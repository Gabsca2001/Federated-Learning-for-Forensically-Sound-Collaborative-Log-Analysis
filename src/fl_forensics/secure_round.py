"""M5 attestation-gated, TPM-signed secure federated round protocol."""

from __future__ import annotations

import copy
import math
import secrets
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable

from .canonical import digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .crypto import (
    DigestSigner,
    SoftwareECDSASigner,
    load_public_key,
    public_key_id,
    verify_digest_signature,
)
from .federated_model import (
    architecture_record,
    arrays_from_export,
    build_model,
    delta_l2,
    dependencies,
    export_state,
    fedavg,
    load_ndarrays,
    seed_everything,
    train_local,
)
from .models import SignatureBlock
from .preprocessing import derived_json_bytes
from .secure_round_models import (
    CheckpointInput,
    ContributionDecision,
    ContributionDecisionCore,
    RoundClientContract,
    SecureCheck,
    SecureCheckpoint,
    SecureCheckpointCore,
    SecureRoundContext,
    SecureRoundContextCore,
    UpdateBundle,
    UpdateBundleCore,
    tensor_schema,
)
from .storage import atomic_json, atomic_write, load_json, write_json_once, write_once
from .tpm_adapter import ESK_HANDLE, TPM2ToolsSigner
from .trust import verify_enrollment_record, verify_result_signature
from .trust_models import AttestationResultV2, EnrollmentRecord, RevocationRecord


GENESIS_DIGEST = "0" * 64
EXPECTED_CLIENTS = [f"client{index:02d}" for index in range(1, 16)]


class SecureRoundError(ValueError):
    """Raised when an M5 protocol invariant cannot be satisfied."""


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _signature(signer: DigestSigner, digest: str, trust_level: str) -> SignatureBlock:
    return SignatureBlock(
        key_id=signer.key_id,
        value_b64=signer.sign_digest(digest),
        trust_level=trust_level,
    )


def _coordinator_signer(workspace: Path, *, create: bool) -> SoftwareECDSASigner:
    private_path = workspace / "authority" / "round-coordinator.private.pem"
    public_path = workspace / "authority" / "round-coordinator.public.pem"
    if private_path.is_file():
        return SoftwareECDSASigner.load(private_path)
    if not create:
        raise SecureRoundError("missing M5 round coordinator private key")
    signer = SoftwareECDSASigner.generate()
    atomic_write(private_path, signer.private_pem())
    private_path.chmod(0o600)
    atomic_write(public_path, signer.public_pem())
    return signer


def _coordinator_public_key(workspace: Path) -> Any:
    candidate = workspace / "public" / "round-coordinator.public.pem"
    if not candidate.is_file():
        candidate = workspace / "authority" / "round-coordinator.public.pem"
    return load_public_key(candidate.read_bytes())


def _verify_signed(value: Any, public_key: Any) -> bool:
    digest = digest_object(value.core.model_dump(mode="json"))
    identity_fields = {
        SecureRoundContext: ("context_id", "round-context-"),
        UpdateBundle: ("bundle_id", "update-bundle-"),
        ContributionDecision: ("decision_id", "contribution-"),
        SecureCheckpoint: ("checkpoint_id", "secure-checkpoint-"),
    }
    identity = identity_fields.get(type(value))
    identity_valid = identity is not None and getattr(value, identity[0]) == (
        f"{identity[1]}{digest[:24]}"
    )
    return (
        digest == value.core_digest
        and identity_valid
        and value.signature.key_id == public_key_id(public_key)
        and verify_digest_signature(public_key, digest, value.signature.value_b64)
    )


def _normalized_relative(value: str) -> Path:
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise SecureRoundError(f"unsafe registry path: {value}")
    return path


def _enrollment(
    trust_workspace: Path, client_id: str, authority_key: Any | None = None
) -> EnrollmentRecord:
    index = load_json(trust_workspace / "registry" / "index.json")
    entry = index.get("enrollments", {}).get(client_id)
    if entry is None:
        raise SecureRoundError(f"client is not enrolled: {client_id}")
    record = EnrollmentRecord.model_validate(
        load_json(trust_workspace / _normalized_relative(str(entry["record_path"])))
    )
    key = authority_key or load_public_key(
        (trust_workspace / "authority" / "enrollment-authority.public.pem").read_bytes()
    )
    if not verify_enrollment_record(record, key):
        raise SecureRoundError(f"invalid enrollment authority signature: {client_id}")
    return record


def _revoked(
    trust_workspace: Path,
    enrollment: EnrollmentRecord,
    authority_key: Any,
    *,
    at: datetime | None = None,
) -> bool:
    root = trust_workspace / "registry" / "revocations"
    for path in sorted(root.glob("*.json")) if root.is_dir() else []:
        record = RevocationRecord.model_validate(load_json(path))
        digest = digest_object(record.core.model_dump(mode="json"))
        valid = (
            digest == record.core_digest
            and record.signature.key_id == public_key_id(authority_key)
            and verify_digest_signature(
                authority_key, digest, record.signature.value_b64
            )
        )
        if not valid:
            raise SecureRoundError(f"invalid revocation record signature: {path.name}")
        effective = at is None or _parse_time(record.core.revoked_at) <= at
        if record.core.enrollment_id == enrollment.core.enrollment_id and effective:
            return True
    return False


def _current_attestation(
    trust_workspace: Path,
    client_id: str,
    enrollment: EnrollmentRecord,
    *,
    now: datetime,
) -> tuple[AttestationResultV2, Path]:
    candidates: list[tuple[datetime, AttestationResultV2, Path]] = []
    for path in (trust_workspace / "results").glob("attestation-*.json"):
        result = AttestationResultV2.model_validate(load_json(path))
        if result.core.client_id == client_id:
            candidates.append((_parse_time(result.core.evaluated_at), result, path))
    if not candidates:
        raise SecureRoundError(f"missing attestation result: {client_id}")
    _evaluated, result, path = max(candidates, key=lambda item: item[0])
    if not verify_result_signature(trust_workspace, result):
        raise SecureRoundError(f"invalid attestation verifier signature: {client_id}")
    if result.core.status not in {"passed", "passed_with_warning"}:
        raise SecureRoundError(f"attestation did not pass for {client_id}: {result.core.status}")
    if result.core.enrollment_id != enrollment.core.enrollment_id:
        raise SecureRoundError(f"attestation/enrollment mismatch: {client_id}")
    if result.core.node_id != enrollment.core.node_id:
        raise SecureRoundError(f"attestation/node mismatch: {client_id}")
    if result.core.transport_peer_fingerprint != enrollment.core.tls_certificate_sha256:
        raise SecureRoundError(f"attestation/mTLS binding mismatch: {client_id}")
    if result.signature.trust_level != enrollment.core.trust_level:
        raise SecureRoundError(f"attestation trust-level mismatch: {client_id}")
    if _parse_time(result.core.expires_at) <= now:
        raise SecureRoundError(f"attestation is expired: {client_id}")
    return result, path


def _new_model(manifest: dict[str, Any], config: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    np, torch, *_rest = dependencies()
    model_config = config["model"]
    training = config["training"]
    seed_everything(int(training["seed"]), torch=torch, np=np)
    architecture = architecture_record(
        input_features=len(manifest["feature_names"]),
        class_count=len(manifest["class_names"]),
        hidden_layers=[int(value) for value in model_config["hidden_layers"]],
        embedding_size=int(model_config["embedding_size"]),
        dropout=float(model_config["dropout"]),
    )
    model = build_model(
        input_features=architecture["input_features"],
        class_count=architecture["classification_head_outputs"],
        hidden_layers=architecture["encoder_hidden_layers"],
        embedding_size=architecture["embedding_size"],
        dropout=architecture["dropout"],
        torch=torch,
    )
    return model, architecture


def initialize_secure_round(
    *,
    workspace: Path,
    trust_workspace: Path,
    partition_manifest_path: Path,
    config_path: Path,
    secure_config_path: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create a signed round context after validating all 15 M4 attestations."""

    now = now or datetime.now(UTC)
    if workspace.exists():
        protected = [path for path in workspace.iterdir() if path.name != "submissions"]
        submissions = workspace / "submissions"
        submitted_files = list(submissions.rglob("*")) if submissions.is_dir() else []
        if protected or any(path.is_file() for path in submitted_files):
            raise FileExistsError(f"M5 workspace must be new and empty: {workspace}")
    manifest = load_json(partition_manifest_path)
    config, config_digest = load_yaml(config_path)
    secure_config, _secure_digest = load_yaml(secure_config_path)
    records = manifest.get("clients", [])
    declared_clients = [item["client_id"] for item in records]
    if manifest.get("client_count") != 15 or declared_clients != EXPECTED_CLIENTS:
        raise SecureRoundError("M5 requires the complete ordered 15-client partition")
    training = config["training"]
    secure_policy = secure_config["secure_round"]
    if (
        int(secure_policy["required_clients"]) != 15
        or str(secure_policy["aggregation"]) != "FedAvg"
    ):
        raise SecureRoundError("M5 policy must require 15-client FedAvg")
    if str(training["aggregator"]) != "fedavg" or str(training["optimizer"]) != "adam":
        raise SecureRoundError("M5 implementation currently requires FedAvg with Adam")
    if str(config["model"]["activation"]) != "relu":
        raise SecureRoundError("M5 implementation currently requires ReLU")
    if manifest.get("partition_config_sha256") != config_digest:
        raise SecureRoundError("partition manifest was created from a different federation config")
    if manifest.get("class_weighting") != training.get("class_weighting"):
        raise SecureRoundError("partition/training class-weighting contract mismatch")
    if (
        int(training["minimum_fit_clients"]) != 15
        or float(training["participation_fraction"]) != 1.0
    ):
        raise SecureRoundError("M5 clean round requires all 15 clients")

    authority_key = load_public_key(
        (trust_workspace / "authority" / "enrollment-authority.public.pem").read_bytes()
    )
    attested: dict[str, tuple[EnrollmentRecord, AttestationResultV2, Path]] = {}
    expiry_values: list[datetime] = []
    for client_id in EXPECTED_CLIENTS:
        enrollment = _enrollment(trust_workspace, client_id, authority_key)
        enrollment_valid = (
            _parse_time(enrollment.core.valid_from)
            <= now
            < _parse_time(enrollment.core.valid_until)
        )
        if (
            enrollment.core.status != "active"
            or not enrollment_valid
            or _revoked(trust_workspace, enrollment, authority_key, at=now)
        ):
            raise SecureRoundError(f"enrollment is not active: {client_id}")
        result, result_path = _current_attestation(
            trust_workspace, client_id, enrollment, now=now
        )
        attested[client_id] = (enrollment, result, result_path)
        expiry_values.append(_parse_time(result.core.expires_at))

    requested_lifetime = int(secure_config["secure_round"]["context_lifetime_seconds"])
    minimum_remaining = int(
        secure_config["secure_round"]["minimum_attestation_remaining_seconds"]
    )
    expires = min(now + timedelta(seconds=requested_lifetime), min(expiry_values))
    if expires <= now + timedelta(seconds=minimum_remaining):
        raise SecureRoundError("attestations expire too soon for an M5 round; issue fresh quotes")

    signer = _coordinator_signer(workspace, create=True)
    public = workspace / "public"
    public.mkdir(parents=True, exist_ok=True)
    write_once(public / "round-coordinator.public.pem", signer.public_pem())
    write_once(public / "partition-manifest.json", partition_manifest_path.read_bytes())
    write_once(public / "federation.yaml", config_path.read_bytes())

    model, architecture = _new_model(manifest, config)
    base_export = export_state(
        model, architecture=architecture, class_names=list(manifest["class_names"])
    )
    base_bytes = derived_json_bytes(base_export)
    base_digest = sha256_bytes(base_bytes)
    write_once(public / "base-model.json", base_bytes)

    client_contracts: list[RoundClientContract] = []
    public_clients: list[dict[str, Any]] = []
    for record in records:
        client_id = str(record["client_id"])
        enrollment, result, result_path = attested[client_id]
        contract = RoundClientContract(
            client_id=client_id,
            node_id=enrollment.core.node_id,
            enrollment_id=enrollment.core.enrollment_id,
            attestation_result_id=result.result_id,
            attestation_result_sha256=sha256_file(result_path),
            snapshot_sha256=str(record["dataset_sha256"]),
            snapshot_manifest_sha256=str(record["manifest_sha256"]),
            train_row_count=int(record["train_row_count"]),
        )
        client_contracts.append(contract)
        public_clients.append(contract.model_dump(mode="json"))

    training_contract = {
        "schema_version": "1.0",
        "artifact_type": "secure_training_contract",
        "feature_names": manifest["feature_names"],
        "class_names": manifest["class_names"],
        "global_class_weights": manifest["global_class_weights"],
        "architecture": architecture,
        "optimizer": str(training["optimizer"]),
        "class_weighting": str(training["class_weighting"]),
        "clients": public_clients,
    }
    contract_bytes = derived_json_bytes(training_contract)
    contract_digest = sha256_bytes(contract_bytes)
    write_once(public / "training-contract.json", contract_bytes)

    context_core = SecureRoundContextCore(
        campaign_id=f"campaign-{secrets.token_hex(12)}",
        round_number=1,
        previous_checkpoint_sha256=GENESIS_DIGEST,
        base_model_sha256=base_digest,
        training_contract_sha256=contract_digest,
        partition_manifest_sha256=sha256_file(partition_manifest_path),
        federation_config_sha256=config_digest,
        seed=int(training["seed"]),
        local_epochs=int(training["local_epochs"]),
        batch_size=int(training["batch_size"]),
        learning_rate_decimal=str(Decimal(str(training["learning_rate"]))),
        required_client_count=15,
        clients=client_contracts,
        issued_at=_utc(now),
        expires_at=_utc(expires),
    )
    digest = digest_object(context_core.model_dump(mode="json"))
    context = SecureRoundContext(
        context_id=f"round-context-{digest[:24]}",
        core=context_core,
        core_digest=digest,
        signature=_signature(signer, digest, "software-development"),
    )
    write_json_once(public / "round-context.json", context.model_dump(mode="json"))
    atomic_json(
        workspace / "state.json",
        {
            "schema_version": "1.0",
            "campaign_id": context.core.campaign_id,
            "context_id": context.context_id,
            "slots": {},
        },
    )
    return {
        "status": "prepared",
        "campaign_id": context.core.campaign_id,
        "context_id": context.context_id,
        "client_count": 15,
        "attested_count": 15,
        "base_model_sha256": base_digest,
        "expires_at": context.core.expires_at,
        "workspace": str(workspace),
    }


def _load_context(public_workspace: Path) -> SecureRoundContext:
    context = SecureRoundContext.model_validate(
        load_json(public_workspace / "round-context.json")
    )
    if not _verify_signed(context, _coordinator_public_key(public_workspace.parent)):
        raise SecureRoundError("invalid coordinator signature on round context")
    return context


def _model_from_export(value: dict[str, Any], *, torch: Any, np: Any) -> Any:
    architecture = value["architecture"]
    model = build_model(
        input_features=int(architecture["input_features"]),
        class_count=int(architecture["classification_head_outputs"]),
        hidden_layers=[int(item) for item in architecture["encoder_hidden_layers"]],
        embedding_size=int(architecture["embedding_size"]),
        dropout=float(architecture["dropout"]),
        torch=torch,
    )
    load_ndarrays(model, arrays_from_export(value, np=np), torch=torch, np=np)
    return model


def create_secure_update(
    *,
    public_workspace: Path,
    client_dataset_path: Path,
    client_manifest_path: Path,
    node_workspace: Path,
    submission_workspace: Path,
    tcti: str,
    client_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Train one isolated client and sign its immutable Update Bundle with its ESK."""

    bundle_path = submission_workspace / "bundle.json"
    if bundle_path.is_file():
        bundle = UpdateBundle.model_validate(load_json(bundle_path))
        context = _load_context(public_workspace)
        public_key = load_public_key(
            (node_workspace / "tpm-objects" / "esk.public.pem").read_bytes()
        )
        update_path = submission_workspace / "update.json"
        metrics_path = submission_workspace / "metrics.json"
        valid_retry = (
            bundle.core.client_id == client_id
            and bundle.core.context_id == context.context_id
            and _verify_signed(bundle, public_key)
            and update_path.is_file()
            and metrics_path.is_file()
            and sha256_file(update_path) == bundle.core.update_sha256
            and sha256_file(metrics_path) == bundle.core.metrics_sha256
        )
        if not valid_retry:
            raise SecureRoundError("existing submission is not a valid idempotent retry")
        return {
            "status": "submitted",
            "client_id": bundle.core.client_id,
            "bundle_id": bundle.bundle_id,
            "idempotent": True,
            "submission": str(submission_workspace),
        }
    now = now or datetime.now(UTC)
    context = _load_context(public_workspace)
    if not (_parse_time(context.core.issued_at) <= now < _parse_time(context.core.expires_at)):
        raise SecureRoundError("round context is not currently valid")
    contract_path = public_workspace / "training-contract.json"
    base_path = public_workspace / "base-model.json"
    if sha256_file(contract_path) != context.core.training_contract_sha256:
        raise SecureRoundError("training contract digest mismatch")
    if sha256_file(base_path) != context.core.base_model_sha256:
        raise SecureRoundError("base model digest mismatch")
    contracts = {item.client_id: item for item in context.core.clients}
    expected = contracts.get(client_id)
    if expected is None:
        raise SecureRoundError(f"client is absent from round context: {client_id}")
    if sha256_file(client_dataset_path) != expected.snapshot_sha256:
        raise SecureRoundError("client snapshot digest mismatch")
    if sha256_file(client_manifest_path) != expected.snapshot_manifest_sha256:
        raise SecureRoundError("client snapshot manifest digest mismatch")
    snapshot = load_json(client_dataset_path)
    snapshot_manifest = load_json(client_manifest_path)
    rows = snapshot["rows"]["train"]
    if snapshot.get("client_id") != client_id or snapshot_manifest.get("client_id") != client_id:
        raise SecureRoundError("snapshot/client identity mismatch")
    if len(rows) != expected.train_row_count:
        raise SecureRoundError("snapshot training row count mismatch")

    training_contract = load_json(contract_path)
    base_export = load_json(base_path)
    (
        np,
        torch,
        _flwr,
        _sklearn,
        _aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependencies()
    model = _model_from_export(base_export, torch=torch, np=np)
    metrics = train_local(
        model=model,
        rows=rows,
        class_names=list(training_contract["class_names"]),
        class_weights={
            key: float(value)
            for key, value in training_contract["global_class_weights"].items()
        },
        epochs=context.core.local_epochs,
        batch_size=context.core.batch_size,
        learning_rate=float(context.core.learning_rate_decimal),
        seed=(
            context.core.seed
            + context.core.round_number * 10_000
            + int(snapshot_manifest["partition_id"])
        ),
        device_name="cpu",
        torch=torch,
        np=np,
        validation_rows=snapshot["rows"].get("validation", []),
        evaluation_functions=(
            accuracy_score,
            confusion_matrix,
            precision_recall_fscore_support,
        ),
        record_history=True,
    )
    updated_export = export_state(
        model,
        architecture=base_export["architecture"],
        class_names=list(base_export["class_names"]),
    )
    metrics["update_delta_l2"] = delta_l2(
        arrays_from_export(base_export, np=np),
        arrays_from_export(updated_export, np=np),
        np=np,
    )
    update_bytes = derived_json_bytes(updated_export)
    metrics_artifact = {
        "schema_version": "2.0",
        "artifact_type": "secure_local_training_metrics",
        "client_id": client_id,
        "context_id": context.context_id,
        **metrics,
    }
    metrics_bytes = derived_json_bytes(metrics_artifact)
    schema_digest = digest_object(tensor_schema(updated_export))
    signer = TPM2ToolsSigner(
        key_context=ESK_HANDLE,
        public_key_pem=(node_workspace / "tpm-objects" / "esk.public.pem").read_bytes(),
        tcti=tcti,
    )
    core = UpdateBundleCore(
        campaign_id=context.core.campaign_id,
        context_id=context.context_id,
        context_digest=context.core_digest,
        round_number=context.core.round_number,
        client_id=client_id,
        node_id=expected.node_id,
        enrollment_id=expected.enrollment_id,
        attestation_result_id=expected.attestation_result_id,
        attestation_result_sha256=expected.attestation_result_sha256,
        base_model_sha256=context.core.base_model_sha256,
        snapshot_sha256=expected.snapshot_sha256,
        update_sha256=sha256_bytes(update_bytes),
        metrics_sha256=sha256_bytes(metrics_bytes),
        tensor_schema_sha256=schema_digest,
        num_examples=len(rows),
        generated_at=_utc(now),
    )
    digest = digest_object(core.model_dump(mode="json"))
    bundle = UpdateBundle(
        bundle_id=f"update-bundle-{digest[:24]}",
        core=core,
        core_digest=digest,
        signature=_signature(
            signer,
            digest,
            str(load_json(node_workspace / "provisioning_summary.json")["trust_level"]),
        ),
    )
    write_once(submission_workspace / "update.json", update_bytes)
    write_once(submission_workspace / "metrics.json", metrics_bytes)
    write_json_once(bundle_path, bundle.model_dump(mode="json"))
    return {
        "status": "submitted",
        "client_id": client_id,
        "bundle_id": bundle.bundle_id,
        "idempotent": False,
        "num_examples": len(rows),
        "submission": str(submission_workspace),
    }


def _check(name: str, operation: Callable[[], tuple[bool, str]]) -> SecureCheck:
    try:
        passed, detail = operation()
        return SecureCheck(name=name, passed=bool(passed), detail=str(detail))
    except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        return SecureCheck(name=name, passed=False, detail=str(exc))


def _tensor_validation(update: dict[str, Any], base: dict[str, Any]) -> tuple[bool, str]:
    def value_shape(value: Any) -> list[int] | None:
        if not isinstance(value, list):
            return []
        child_shapes = [value_shape(item) for item in value]
        if any(shape is None for shape in child_shapes):
            return None
        if child_shapes and any(shape != child_shapes[0] for shape in child_shapes[1:]):
            return None
        return [len(value), *(child_shapes[0] if child_shapes else [])]

    if update.get("artifact_type") != "pytorch_model_state":
        return False, "unexpected update artifact type"
    if update.get("architecture") != base.get("architecture"):
        return False, "architecture differs from base model"
    if update.get("class_names") != base.get("class_names"):
        return False, "class order differs from base model"
    if tensor_schema(update) != tensor_schema(base):
        return False, "tensor names, shapes, or dtypes differ from base model"
    for parameter in update.get("parameters", []):
        if value_shape(parameter.get("values")) != parameter.get("shape"):
            return False, f"tensor {parameter.get('name')} values do not match declared shape"
        stack = [parameter.get("values")]
        while stack:
            value = stack.pop()
            if isinstance(value, list):
                stack.extend(value)
            elif (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
            ):
                return False, f"tensor {parameter.get('name')} contains a non-finite value"
    return True, "architecture, class order, tensor schema, and finite values verified"


def _admission_checks(
    *,
    bundle: UpdateBundle,
    submission: Path,
    context: SecureRoundContext,
    base: dict[str, Any],
    trust_workspace: Path,
    now: datetime,
    expected_client_id: str | None = None,
) -> list[SecureCheck]:
    contracts = {item.client_id: item for item in context.core.clients}
    expected = contracts.get(bundle.core.client_id)
    authority_key = load_public_key(
        (trust_workspace / "authority" / "enrollment-authority.public.pem").read_bytes()
    )

    def context_check() -> tuple[bool, str]:
        generated = _parse_time(bundle.core.generated_at)
        matched = (
            bundle.core.campaign_id == context.core.campaign_id
            and bundle.core.context_id == context.context_id
            and bundle.core.context_digest == context.core_digest
            and bundle.core.round_number == context.core.round_number
            and bundle.core.base_model_sha256 == context.core.base_model_sha256
            and _parse_time(context.core.issued_at)
            <= generated
            < _parse_time(context.core.expires_at)
            and generated <= now
        )
        return matched, "round, campaign, context, base model, and generation-time binding"

    def client_check() -> tuple[bool, str]:
        if expected is None:
            return False, "client is not contracted for this round"
        matched = (
            (expected_client_id is None or bundle.core.client_id == expected_client_id)
            and bundle.core.node_id == expected.node_id
            and bundle.core.enrollment_id == expected.enrollment_id
            and bundle.core.snapshot_sha256 == expected.snapshot_sha256
            and bundle.core.num_examples == expected.train_row_count
        )
        return matched, "client, node, enrollment, snapshot, and row count binding"

    enrollment: EnrollmentRecord | None = None
    try:
        enrollment = _enrollment(trust_workspace, bundle.core.client_id, authority_key)
    except (OSError, ValueError):
        enrollment = None

    def enrollment_check() -> tuple[bool, str]:
        if enrollment is None:
            return False, "valid signed enrollment record not found"
        active = (
            enrollment.core.status == "active"
            and _parse_time(enrollment.core.valid_from)
            <= now
            < _parse_time(enrollment.core.valid_until)
            and not _revoked(trust_workspace, enrollment, authority_key, at=now)
        )
        return active, "enrollment authority signature and revocation state"

    def bundle_signature_check() -> tuple[bool, str]:
        if enrollment is None:
            return False, "cannot resolve enrolled ESK"
        key = load_public_key(enrollment.core.esk_public_key_pem.encode("utf-8"))
        valid = (
            bundle.signature.key_id == enrollment.core.esk_key_id
            and bundle.signature.trust_level == enrollment.core.trust_level
            and _verify_signed(bundle, key)
        )
        return valid, "TPM ESK signature and enrolled key identity"

    def attestation_check() -> tuple[bool, str]:
        if expected is None or enrollment is None:
            return False, "missing round client contract"
        path = trust_workspace / "results" / f"{bundle.core.attestation_result_id}.json"
        if not path.is_file():
            return False, "referenced attestation result is missing"
        result = AttestationResultV2.model_validate(load_json(path))
        valid = (
            sha256_file(path) == bundle.core.attestation_result_sha256
            and result.result_id == expected.attestation_result_id
            and sha256_file(path) == expected.attestation_result_sha256
            and verify_result_signature(trust_workspace, result)
            and result.core.status in {"passed", "passed_with_warning"}
            and result.core.client_id == bundle.core.client_id
            and result.core.node_id == bundle.core.node_id
            and result.core.enrollment_id == bundle.core.enrollment_id
            and result.signature.trust_level == enrollment.core.trust_level
            and _parse_time(result.core.expires_at) > now
        )
        return valid, "signed, passed, fresh attestation and identity binding"

    update_path = submission / "update.json"
    metrics_path = submission / "metrics.json"

    def artifact_check() -> tuple[bool, str]:
        valid = (
            update_path.is_file()
            and metrics_path.is_file()
            and sha256_file(update_path) == bundle.core.update_sha256
            and sha256_file(metrics_path) == bundle.core.metrics_sha256
        )
        return valid, "update and metrics content digests"

    def tensor_check() -> tuple[bool, str]:
        if not update_path.is_file():
            return False, "update artifact is missing"
        update = load_json(update_path)
        valid, detail = _tensor_validation(update, base)
        if valid and digest_object(tensor_schema(update)) != bundle.core.tensor_schema_sha256:
            return False, "bundle tensor schema digest mismatch"
        return valid, detail

    return [
        _check("round_context_binding", context_check),
        _check("client_contract_binding", client_check),
        _check("active_enrollment", enrollment_check),
        _check("tpm_esk_signature", bundle_signature_check),
        _check("fresh_attestation", attestation_check),
        _check("artifact_digests", artifact_check),
        _check("tensor_structure", tensor_check),
    ]


def _sign_decision(
    *,
    signer: SoftwareECDSASigner,
    context: SecureRoundContext,
    bundle: UpdateBundle,
    bundle_sha256: str,
    checks: list[SecureCheck],
    now: datetime,
) -> ContributionDecision:
    status = "accepted" if all(check.passed for check in checks) else "quarantined"
    core = ContributionDecisionCore(
        campaign_id=context.core.campaign_id,
        context_id=context.context_id,
        round_number=context.core.round_number,
        client_id=bundle.core.client_id,
        bundle_id=bundle.bundle_id,
        bundle_sha256=bundle_sha256,
        status=status,
        checks=checks,
        decided_at=_utc(now),
    )
    digest = digest_object(core.model_dump(mode="json"))
    return ContributionDecision(
        decision_id=f"contribution-{digest[:24]}",
        core=core,
        core_digest=digest,
        signature=_signature(signer, digest, "software-development"),
    )


def _sign_malformed_decision(
    *,
    signer: SoftwareECDSASigner,
    context: SecureRoundContext,
    client_id: str,
    bundle_sha256: str,
    detail: str,
    now: datetime,
) -> ContributionDecision:
    core = ContributionDecisionCore(
        campaign_id=context.core.campaign_id,
        context_id=context.context_id,
        round_number=context.core.round_number,
        client_id=client_id,
        bundle_id=f"malformed-bundle-{bundle_sha256[:24]}",
        bundle_sha256=bundle_sha256,
        status="quarantined",
        checks=[SecureCheck(name="bundle_schema", passed=False, detail=detail)],
        decided_at=_utc(now),
    )
    digest = digest_object(core.model_dump(mode="json"))
    return ContributionDecision(
        decision_id=f"contribution-{digest[:24]}",
        core=core,
        core_digest=digest,
        signature=_signature(signer, digest, "software-development"),
    )


def admit_and_aggregate(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Admit signed bundles, enforce replay slots, and create a signed FedAvg checkpoint."""

    now = now or datetime.now(UTC)
    context = _load_context(workspace / "public")
    if not (_parse_time(context.core.issued_at) <= now < _parse_time(context.core.expires_at)):
        raise SecureRoundError("round context expired before admission completed")
    context_clients = [item.client_id for item in context.core.clients]
    if (
        context.core.required_client_count != len(EXPECTED_CLIENTS)
        or context_clients != EXPECTED_CLIENTS
    ):
        raise SecureRoundError("signed context does not contain the required 15 clients")
    signer = _coordinator_signer(workspace, create=False)
    base_path = workspace / "public" / "base-model.json"
    contract_path = workspace / "public" / "training-contract.json"
    if sha256_file(base_path) != context.core.base_model_sha256:
        raise SecureRoundError("base model changed after the round context was signed")
    if sha256_file(contract_path) != context.core.training_contract_sha256:
        raise SecureRoundError("training contract changed after the round context was signed")
    base = load_json(base_path)
    state_path = workspace / "state.json"
    state = load_json(state_path)
    if (
        state.get("campaign_id") != context.core.campaign_id
        or state.get("context_id") != context.context_id
    ):
        raise SecureRoundError("secure-round replay state/context mismatch")
    decisions: list[ContributionDecision] = []
    decision_paths: list[Path] = []
    client_ids = context_clients
    for client_id in client_ids:
        submission = submissions_root / client_id
        bundle_path = submission / "bundle.json"
        if not bundle_path.is_file():
            continue
        bundle_sha = sha256_file(bundle_path)
        slot = f"{context.core.campaign_id}:{context.core.round_number}:{client_id}"
        consumed = state["slots"].get(slot)
        try:
            bundle = UpdateBundle.model_validate(load_json(bundle_path))
        except (OSError, TypeError, ValueError) as exc:
            if consumed is not None and consumed["bundle_sha256"] == bundle_sha:
                existing_path = workspace / str(consumed["decision_path"])
                decisions.append(ContributionDecision.model_validate(load_json(existing_path)))
                decision_paths.append(existing_path)
                continue
            decision = _sign_malformed_decision(
                signer=signer,
                context=context,
                client_id=client_id,
                bundle_sha256=bundle_sha,
                detail=str(exc),
                now=now,
            )
            path = workspace / "quarantine" / f"{decision.decision_id}.json"
            write_json_once(path, decision.model_dump(mode="json"))
            if consumed is None:
                state["slots"][slot] = {
                    "bundle_sha256": bundle_sha,
                    "decision_path": str(path.relative_to(workspace)),
                }
                atomic_json(state_path, state)
            decisions.append(decision)
            decision_paths.append(path)
            continue
        if consumed is not None:
            existing_path = workspace / str(consumed["decision_path"])
            existing = ContributionDecision.model_validate(load_json(existing_path))
            if consumed["bundle_sha256"] == bundle_sha:
                decisions.append(existing)
                decision_paths.append(existing_path)
                continue
            checks = [
                SecureCheck(
                    name="replay_slot",
                    passed=False,
                    detail="round/client slot already contains a different bundle",
                )
            ]
            decision = _sign_decision(
                signer=signer,
                context=context,
                bundle=bundle,
                bundle_sha256=bundle_sha,
                checks=checks,
                now=now,
            )
            path = workspace / "quarantine" / f"{decision.decision_id}.json"
            write_json_once(path, decision.model_dump(mode="json"))
            decisions.append(decision)
            decision_paths.append(path)
            continue
        checks = _admission_checks(
            bundle=bundle,
            submission=submission,
            context=context,
            base=base,
            trust_workspace=trust_workspace,
            now=now,
            expected_client_id=client_id,
        )
        decision = _sign_decision(
            signer=signer,
            context=context,
            bundle=bundle,
            bundle_sha256=bundle_sha,
            checks=checks,
            now=now,
        )
        path = workspace / "decisions" / f"{client_id}.json"
        write_json_once(path, decision.model_dump(mode="json"))
        state["slots"][slot] = {
            "bundle_sha256": bundle_sha,
            "decision_path": str(path.relative_to(workspace)),
        }
        atomic_json(state_path, state)
        decisions.append(decision)
        decision_paths.append(path)

    accepted = [item for item in decisions if item.core.status == "accepted"]
    quarantined = [item for item in decisions if item.core.status == "quarantined"]
    if len(accepted) != context.core.required_client_count or quarantined:
        return {
            "status": "failed",
            "client_count": len(decisions),
            "accepted_count": len(accepted),
            "quarantined_count": len(quarantined),
            "missing_count": context.core.required_client_count - len(decisions),
            "checkpoint_created": False,
            "workspace": str(workspace),
        }

    checkpoint_path = workspace / "checkpoint" / "manifest.json"
    if checkpoint_path.is_file():
        existing = SecureCheckpoint.model_validate(load_json(checkpoint_path))
        existing_inputs = {item.client_id: item for item in existing.core.accepted_inputs}
        retry_matches = (
            _verify_signed(existing, signer.private_key.public_key())
            and existing.core.context_digest == context.core_digest
            and set(existing_inputs) == set(client_ids)
        )
        for decision, decision_path in zip(decisions, decision_paths, strict=True):
            item = existing_inputs.get(decision.core.client_id)
            bundle_path = submissions_root / decision.core.client_id / "bundle.json"
            retry_matches = retry_matches and item is not None and (
                item.decision_sha256 == sha256_file(decision_path)
                and item.bundle_sha256 == sha256_file(bundle_path)
            )
        model_path = workspace / "checkpoint" / "global-model.json"
        retry_matches = retry_matches and model_path.is_file() and (
            sha256_file(model_path) == existing.core.global_model_sha256
        )
        if not retry_matches:
            raise SecureRoundError(
                "existing checkpoint does not match the idempotent accepted inputs"
            )
        return {
            "status": "aggregated",
            "accepted_count": existing.core.accepted_count,
            "quarantined_count": existing.core.quarantined_count,
            "checkpoint_id": existing.checkpoint_id,
            "global_model_sha256": existing.core.global_model_sha256,
            "idempotent": True,
            "workspace": str(workspace),
        }

    np, _torch, _flwr, _sklearn, aggregate, *_metrics = dependencies()
    updates: list[tuple[list[Any], int]] = []
    inputs: list[CheckpointInput] = []
    by_client = {
        item.core.client_id: (item, path)
        for item, path in zip(decisions, decision_paths, strict=True)
    }
    for client_id in client_ids:
        decision, decision_path = by_client[client_id]
        submission = submissions_root / client_id
        bundle_path = submission / "bundle.json"
        bundle = UpdateBundle.model_validate(load_json(bundle_path))
        update = load_json(submission / "update.json")
        updates.append((arrays_from_export(update, np=np), bundle.core.num_examples))
        inputs.append(
            CheckpointInput(
                client_id=client_id,
                decision_id=decision.decision_id,
                decision_sha256=sha256_file(decision_path),
                bundle_id=bundle.bundle_id,
                bundle_sha256=sha256_file(bundle_path),
                update_sha256=bundle.core.update_sha256,
                num_examples=bundle.core.num_examples,
            )
        )
    averaged = fedavg(updates, aggregate=aggregate)
    global_model = copy.deepcopy(base)
    for parameter, array in zip(global_model["parameters"], averaged, strict=True):
        parameter["values"] = np.asarray(array, dtype=np.dtype(parameter["dtype"])).tolist()
    model_bytes = derived_json_bytes(global_model)
    model_digest = sha256_bytes(model_bytes)
    write_once(workspace / "checkpoint" / "global-model.json", model_bytes)
    core = SecureCheckpointCore(
        campaign_id=context.core.campaign_id,
        context_id=context.context_id,
        context_digest=context.core_digest,
        round_number=context.core.round_number,
        previous_checkpoint_sha256=context.core.previous_checkpoint_sha256,
        base_model_sha256=context.core.base_model_sha256,
        required_client_count=context.core.required_client_count,
        accepted_count=len(inputs),
        quarantined_count=0,
        total_examples=sum(item.num_examples for item in inputs),
        accepted_inputs=inputs,
        quarantined_decision_sha256=[],
        global_model_sha256=model_digest,
        created_at=_utc(now),
    )
    digest = digest_object(core.model_dump(mode="json"))
    checkpoint = SecureCheckpoint(
        checkpoint_id=f"secure-checkpoint-{digest[:24]}",
        core=core,
        core_digest=digest,
        signature=_signature(signer, digest, "software-development"),
    )
    write_json_once(checkpoint_path, checkpoint.model_dump(mode="json"))
    return {
        "status": "aggregated",
        "accepted_count": len(inputs),
        "quarantined_count": 0,
        "checkpoint_id": checkpoint.checkpoint_id,
        "global_model_sha256": model_digest,
        "idempotent": False,
        "workspace": str(workspace),
    }


def verify_secure_round(
    *, workspace: Path, trust_workspace: Path, submissions_root: Path
) -> dict[str, Any]:
    """Independently verify every input and recompute the exact FedAvg checkpoint."""

    errors: list[str] = []
    try:
        context = _load_context(workspace / "public")
        public_key = _coordinator_public_key(workspace)
        if (
            context.core.required_client_count != len(EXPECTED_CLIENTS)
            or [item.client_id for item in context.core.clients] != EXPECTED_CLIENTS
        ):
            errors.append("signed context does not contain the required 15 clients")
        checkpoint = SecureCheckpoint.model_validate(
            load_json(workspace / "checkpoint" / "manifest.json")
        )
        if not _verify_signed(checkpoint, public_key):
            errors.append("invalid coordinator signature on checkpoint")
        if checkpoint.core.context_digest != context.core_digest:
            errors.append("checkpoint context digest mismatch")
        checkpoint_binding = (
            checkpoint.core.campaign_id == context.core.campaign_id
            and checkpoint.core.context_id == context.context_id
            and checkpoint.core.round_number == context.core.round_number
            and checkpoint.core.previous_checkpoint_sha256
            == context.core.previous_checkpoint_sha256
            and checkpoint.core.base_model_sha256 == context.core.base_model_sha256
            and checkpoint.core.required_client_count == context.core.required_client_count
        )
        if not checkpoint_binding:
            errors.append("checkpoint round/base/campaign binding mismatch")
        if sha256_file(workspace / "public" / "base-model.json") != (
            context.core.base_model_sha256
        ):
            errors.append("public base model digest mismatch")
        if sha256_file(workspace / "public" / "training-contract.json") != (
            context.core.training_contract_sha256
        ):
            errors.append("public training contract digest mismatch")
        if sha256_file(workspace / "public" / "partition-manifest.json") != (
            context.core.partition_manifest_sha256
        ):
            errors.append("public partition manifest digest mismatch")
        if sha256_file(workspace / "public" / "federation.yaml") != (
            context.core.federation_config_sha256
        ):
            errors.append("public federation configuration digest mismatch")
        if (
            checkpoint.core.accepted_count != len(EXPECTED_CLIENTS)
            or len(checkpoint.core.accepted_inputs) != len(EXPECTED_CLIENTS)
        ):
            errors.append("checkpoint does not contain every required accepted input")
        if (
            checkpoint.core.quarantined_count != 0
            or checkpoint.core.quarantined_decision_sha256
        ):
            errors.append("checkpoint contains quarantined contributions")
        input_client_ids = [item.client_id for item in checkpoint.core.accepted_inputs]
        if (
            input_client_ids != EXPECTED_CLIENTS
            or len(set(input_client_ids)) != len(EXPECTED_CLIENTS)
        ):
            errors.append("checkpoint client inputs are incomplete, duplicated, or unordered")
        base = load_json(workspace / "public" / "base-model.json")
        np, _torch, _flwr, _sklearn, aggregate, *_metrics = dependencies()
        updates: list[tuple[list[Any], int]] = []
        for item in checkpoint.core.accepted_inputs:
            decision_path = workspace / "decisions" / f"{item.client_id}.json"
            bundle_path = submissions_root / item.client_id / "bundle.json"
            update_path = submissions_root / item.client_id / "update.json"
            decision = ContributionDecision.model_validate(load_json(decision_path))
            bundle = UpdateBundle.model_validate(load_json(bundle_path))
            enrollment = _enrollment(trust_workspace, item.client_id)
            esk_key = load_public_key(enrollment.core.esk_public_key_pem.encode("utf-8"))
            if not _verify_signed(decision, public_key) or decision.core.status != "accepted":
                errors.append(f"invalid accepted decision: {item.client_id}")
            if (
                decision.core.campaign_id != context.core.campaign_id
                or decision.core.context_id != context.context_id
                or decision.core.round_number != context.core.round_number
            ):
                errors.append(f"decision context binding mismatch: {item.client_id}")
            decision_time = _parse_time(decision.core.decided_at)
            if not (
                _parse_time(context.core.issued_at)
                <= decision_time
                < _parse_time(context.core.expires_at)
            ):
                errors.append(f"decision outside context lifetime: {item.client_id}")
            if sha256_file(decision_path) != item.decision_sha256:
                errors.append(f"decision digest mismatch: {item.client_id}")
            if sha256_file(bundle_path) != item.bundle_sha256:
                errors.append(f"bundle digest mismatch: {item.client_id}")
            if not _verify_signed(bundle, esk_key):
                errors.append(f"invalid ESK bundle signature: {item.client_id}")
            if (
                decision.core.client_id != item.client_id
                or decision.core.bundle_id != item.bundle_id
                or decision.core.bundle_sha256 != item.bundle_sha256
                or bundle.core.client_id != item.client_id
                or bundle.core.update_sha256 != item.update_sha256
                or bundle.core.num_examples != item.num_examples
            ):
                errors.append(f"checkpoint input binding mismatch: {item.client_id}")
            if sha256_file(update_path) != item.update_sha256:
                errors.append(f"update digest mismatch: {item.client_id}")
            update = load_json(update_path)
            valid, detail = _tensor_validation(update, base)
            if not valid:
                errors.append(f"invalid tensor update {item.client_id}: {detail}")
            independent_checks = _admission_checks(
                bundle=bundle,
                submission=submissions_root / item.client_id,
                context=context,
                base=base,
                trust_workspace=trust_workspace,
                now=decision_time,
                expected_client_id=item.client_id,
            )
            failed_checks = [check.name for check in independent_checks if not check.passed]
            if failed_checks:
                errors.append(
                    f"independent admission failed {item.client_id}: {failed_checks}"
                )
            updates.append((arrays_from_export(update, np=np), item.num_examples))
        averaged = fedavg(updates, aggregate=aggregate) if updates else []
        if checkpoint.core.total_examples != sum(
            item.num_examples for item in checkpoint.core.accepted_inputs
        ):
            errors.append("checkpoint total example count mismatch")
        recomputed = copy.deepcopy(base)
        for parameter, array in zip(recomputed["parameters"], averaged, strict=True):
            parameter["values"] = np.asarray(
                array, dtype=np.dtype(parameter["dtype"])
            ).tolist()
        recomputed_digest = sha256_bytes(derived_json_bytes(recomputed))
        stored_model_path = workspace / "checkpoint" / "global-model.json"
        stored_digest = sha256_file(stored_model_path)
        matches = (
            recomputed_digest == checkpoint.core.global_model_sha256 == stored_digest
        )
        if not matches:
            errors.append("stored checkpoint differs from independently recomputed FedAvg")
        if not (
            _parse_time(context.core.issued_at)
            <= _parse_time(checkpoint.core.created_at)
            < _parse_time(context.core.expires_at)
        ):
            errors.append("checkpoint was created outside the signed context lifetime")
    except (FileNotFoundError, KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
        matches = False
        checkpoint = None
    accepted_count = checkpoint.core.accepted_count if checkpoint is not None else 0
    return {
        "status": (
            "verified"
            if not errors and accepted_count == len(EXPECTED_CLIENTS) and matches
            else "failed"
        ),
        "workspace": str(workspace),
        "accepted_count": accepted_count,
        "matches_reference_checkpoint": matches,
        "error_count": len(errors),
        "errors": errors,
    }
