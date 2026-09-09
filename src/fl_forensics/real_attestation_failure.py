"""Live M4/M6 experiment using an authentic non-conforming TPM Quote.

Every client first passes the attestation bound into the signed round context.
After local training, the selected client extends a measured PCR and obtains a
fresh verifier-signed ``failed_measurement`` result.  Its already computed
update is retained as an experimental probe and its ESK re-signs the bundle so
that M5/M6 must evaluate the real post-training result before FedAvg.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .crypto import DigestSigner, load_public_key
from .preprocessing import derived_json_bytes
from .real_attestation_failure_models import (
    RealAttestationFailureContract,
    RealAttestationFailureContractCore,
)
from .secure_round_models import UpdateBundle, UpdateBundleCore
from .storage import atomic_json, load_json, write_once
from .tpm_adapter import ESK_HANDLE, TPM2ToolsSigner, verify_tpm2_quote
from .trust import verify_enrollment_record, verify_result_signature
from .trust_models import AttestationResultV2, EnrollmentRecord, QuoteEvidence


class RealAttestationFailureError(RuntimeError):
    """Raised when live attestation-failure evidence is incomplete or changed."""


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _artifact_digest(value: Any) -> str:
    return sha256_bytes(derived_json_bytes(value))


def _implementation_sha256() -> str:
    root = Path(__file__).resolve().parent
    return digest_object(
        {
            name: sha256_file(root / name)
            for name in (
                "real_attestation_failure.py",
                "real_attestation_failure_models.py",
                "in_round_admission.py",
                "secure_round.py",
                "tpm_adapter.py",
            )
        }
    )


def build_real_attestation_failure_contract(
    *, config_path: Path, client_ids: list[str]
) -> RealAttestationFailureContract:
    config, config_sha256 = load_yaml(config_path)
    if config.get("schema_version") != "1.0":
        raise RealAttestationFailureError("unsupported real-attestation schema")
    experiment = config.get("experiment")
    if not isinstance(experiment, dict):
        raise RealAttestationFailureError("real-attestation experiment section is missing")
    ordered_clients = sorted(set(client_ids))
    if ordered_clients != client_ids or not client_ids:
        raise RealAttestationFailureError(
            "client identifiers must be present, sorted, and unique"
        )
    target = str(experiment.get("target_client_id", ""))
    if target not in client_ids:
        raise RealAttestationFailureError(
            f"real-attestation target is not a contracted client: {target}"
        )
    active_rounds = [int(item) for item in experiment.get("active_rounds", [])]
    core = RealAttestationFailureContractCore(
        experiment_id=str(experiment["id"]),
        config_sha256=config_sha256,
        client_ids=client_ids,
        target_client_id=target,
        active_rounds=active_rounds,
        phase=str(experiment.get("phase", "")),
        pcr_bank=str(experiment.get("pcr_bank", "sha256")),
        pcr_index=int(experiment["pcr_index"]),
        measurement_sha256=str(experiment["measurement_sha256"]),
        expected_initial_statuses=sorted(
            str(item) for item in experiment.get("expected_initial_statuses", [])
        ),
        expected_post_status=str(experiment.get("expected_post_status", "")),
        quote_format=str(experiment.get("quote_format", "")),
        local_update_is_probe_only=bool(
            experiment.get("local_update_is_probe_only", False)
        ),
        evaluation_labels_used_for_admission=bool(
            experiment.get("evaluation_labels_used_for_admission", True)
        ),
        implementation_sha256=_implementation_sha256(),
    )
    digest = _artifact_digest(core.model_dump(mode="json"))
    return RealAttestationFailureContract(
        contract_id=f"m4-m6-real-attestation-failure-contract-{digest[:24]}",
        core=core,
        core_digest=digest,
    )


def install_real_attestation_failure_contract(
    *, public_workspace: Path, config_path: Path, client_ids: list[str]
) -> tuple[RealAttestationFailureContract, dict[str, Any]]:
    contract = build_real_attestation_failure_contract(
        config_path=config_path, client_ids=client_ids
    )
    config_target = public_workspace / "real-attestation-failure.yaml"
    contract_target = public_workspace / "real-attestation-failure-contract.json"
    write_once(config_target, config_path.read_bytes())
    write_once(contract_target, derived_json_bytes(contract.model_dump(mode="json")))
    return contract, {
        "mode": "real-post-training-tpm-quote-appraisal",
        "config_path": config_target.name,
        "config_sha256": sha256_file(config_target),
        "contract_path": contract_target.name,
        "contract_sha256": sha256_file(contract_target),
        "contract_id": contract.contract_id,
    }


def load_bound_real_attestation_failure_contract(
    public_workspace: Path,
) -> RealAttestationFailureContract | None:
    training = load_json(public_workspace / "training-contract.json")
    binding = training.get("m4_m6_real_attestation_failure")
    if binding is None:
        return None
    if not isinstance(binding, dict):
        raise RealAttestationFailureError("invalid real-attestation binding")
    if (
        binding.get("config_path") != "real-attestation-failure.yaml"
        or binding.get("contract_path") != "real-attestation-failure-contract.json"
    ):
        raise RealAttestationFailureError("unsafe real-attestation public path")
    config_path = public_workspace / str(binding["config_path"])
    contract_path = public_workspace / str(binding["contract_path"])
    if sha256_file(config_path) != binding.get("config_sha256"):
        raise RealAttestationFailureError("bound real-attestation config changed")
    if sha256_file(contract_path) != binding.get("contract_sha256"):
        raise RealAttestationFailureError("bound real-attestation contract changed")
    client_ids = [str(item["client_id"]) for item in training.get("clients", [])]
    expected = build_real_attestation_failure_contract(
        config_path=config_path, client_ids=client_ids
    )
    observed = RealAttestationFailureContract.model_validate(load_json(contract_path))
    if observed.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise RealAttestationFailureError(
            "bound real-attestation contract does not recompute"
        )
    if observed.contract_id != binding.get("contract_id"):
        raise RealAttestationFailureError(
            "bound real-attestation contract id mismatch"
        )
    return observed


def active_target_for_round(public_workspace: Path, round_number: int) -> str | None:
    contract = load_bound_real_attestation_failure_contract(public_workspace)
    if contract is None or round_number not in contract.core.active_rounds:
        return None
    return contract.core.target_client_id


def refresh_update_bundle_attestation(
    *,
    public_workspace: Path,
    node_workspace: Path,
    submission_workspace: Path,
    attestation_result_path: Path,
    client_id: str,
    tcti: str,
    now: datetime | None = None,
    signer: DigestSigner | None = None,
) -> dict[str, Any]:
    """Re-sign an existing update against the bound post-training appraisal."""

    from .secure_round import _load_context, _verify_signed

    now = now or datetime.now(UTC)
    context = _load_context(public_workspace)
    contract = load_bound_real_attestation_failure_contract(public_workspace)
    if contract is None:
        raise RealAttestationFailureError("round has no real-attestation contract")
    if context.core.round_number not in contract.core.active_rounds:
        raise RealAttestationFailureError("real-attestation experiment is inactive")
    if client_id != contract.core.target_client_id:
        raise RealAttestationFailureError("only the contracted target may rebind")
    if not (
        _parse_time(context.core.issued_at) <= now < _parse_time(context.core.expires_at)
    ):
        raise RealAttestationFailureError("round context is not currently valid")

    bundle_path = submission_workspace / "bundle.json"
    original_path = submission_workspace / "pre-reattestation-bundle.json"
    bundle = UpdateBundle.model_validate(load_json(bundle_path))
    public_key = load_public_key(
        (node_workspace / "tpm-objects" / "esk.public.pem").read_bytes()
    )
    if not _verify_signed(bundle, public_key) or bundle.core.client_id != client_id:
        raise RealAttestationFailureError("existing Update Bundle is not a valid ESK probe")
    for path, expected_sha256 in (
        (submission_workspace / "update.json", bundle.core.update_sha256),
        (submission_workspace / "metrics.json", bundle.core.metrics_sha256),
    ):
        if not path.is_file() or sha256_file(path) != expected_sha256:
            raise RealAttestationFailureError(
                f"existing probe artifact changed: {path.name}"
            )

    result = AttestationResultV2.model_validate(load_json(attestation_result_path))
    expected_client = next(
        item for item in context.core.clients if item.client_id == client_id
    )
    result_valid = (
        result.core.client_id == client_id
        and result.core.node_id == expected_client.node_id
        and result.core.enrollment_id == expected_client.enrollment_id
        and result.core.status == contract.core.expected_post_status
        and _parse_time(bundle.core.generated_at) <= _parse_time(result.core.evaluated_at)
        and _parse_time(result.core.evaluated_at) <= now
        and _parse_time(result.core.expires_at) > now
    )
    if not result_valid:
        raise RealAttestationFailureError(
            "post-training attestation does not match the bound failure contract"
        )

    result_sha256 = sha256_file(attestation_result_path)
    if bundle.core.attestation_result_id == result.result_id:
        if bundle.core.attestation_result_sha256 != result_sha256:
            raise RealAttestationFailureError("idempotent result digest changed")
        return {
            "status": "rebound_post_training_attestation",
            "client_id": client_id,
            "attestation_result_id": result.result_id,
            "bundle_id": bundle.bundle_id,
            "idempotent": True,
            "submission": str(submission_workspace),
        }

    write_once(original_path, bundle_path.read_bytes())
    core = UpdateBundleCore.model_validate(
        {
            **bundle.core.model_dump(mode="json"),
            "attestation_result_id": result.result_id,
            "attestation_result_sha256": result_sha256,
            "generated_at": _utc(now),
        }
    )
    digest = digest_object(core.model_dump(mode="json"))
    active_signer = signer or TPM2ToolsSigner(
        key_context=ESK_HANDLE,
        public_key_pem=(node_workspace / "tpm-objects" / "esk.public.pem").read_bytes(),
        tcti=tcti,
    )
    refreshed = UpdateBundle(
        bundle_id=f"update-bundle-{digest[:24]}",
        core=core,
        core_digest=digest,
        signature={
            "key_id": active_signer.key_id,
            "value_b64": active_signer.sign_digest(digest),
            "trust_level": bundle.signature.trust_level,
        },
    )
    atomic_json(bundle_path, refreshed.model_dump(mode="json"))
    return {
        "status": "rebound_post_training_attestation",
        "client_id": client_id,
        "attestation_result_id": result.result_id,
        "original_bundle_id": bundle.bundle_id,
        "bundle_id": refreshed.bundle_id,
        "update_sha256": refreshed.core.update_sha256,
        "idempotent": False,
        "submission": str(submission_workspace),
    }


def _enrollment(trust_workspace: Path, client_id: str) -> EnrollmentRecord:
    index = load_json(trust_workspace / "registry" / "index.json")
    entry = index["enrollments"].get(client_id)
    if entry is None:
        raise RealAttestationFailureError("target enrollment is missing")
    path = Path(str(entry["record_path"]).replace("\\", "/"))
    record = EnrollmentRecord.model_validate(load_json(trust_workspace / path))
    authority = load_public_key(
        (trust_workspace / "authority" / "enrollment-authority.public.pem").read_bytes()
    )
    if not verify_enrollment_record(record, authority):
        raise RealAttestationFailureError("target enrollment signature is invalid")
    return record


def _quote_matches_result(
    *, evidence: QuoteEvidence, result: AttestationResultV2
) -> bool:
    return digest_object(evidence.model_dump(mode="json")) == result.core.quote_evidence_digest


def verify_real_attestation_failure_round(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
) -> dict[str, Any]:
    """Verify Quote authenticity, chronology, quarantine, and FedAvg exclusion."""

    from .in_round_admission_models import (
        InRoundContributionDecision,
        InRoundSecureCheckpoint,
    )
    from .secure_round import _admission_checks, _load_context, _verify_signed

    errors: list[str] = []
    target: str | None = None
    result_id: str | None = None
    decision_id: str | None = None
    try:
        public = workspace / "public"
        context = _load_context(public)
        contract = load_bound_real_attestation_failure_contract(public)
        if contract is None:
            raise RealAttestationFailureError("round has no real-attestation contract")
        if context.core.round_number not in contract.core.active_rounds:
            raise RealAttestationFailureError("round is not active in the experiment")
        target = contract.core.target_client_id
        expected = next(item for item in context.core.clients if item.client_id == target)
        initial_path = trust_workspace / "results" / f"{expected.attestation_result_id}.json"
        initial = AttestationResultV2.model_validate(load_json(initial_path))
        if (
            initial.core.status not in contract.core.expected_initial_statuses
            or not verify_result_signature(trust_workspace, initial)
            or sha256_file(initial_path) != expected.attestation_result_sha256
        ):
            errors.append("initial training-authorizing attestation is not verified-passed")

        submission = submissions_root / target
        original = UpdateBundle.model_validate(
            load_json(submission / "pre-reattestation-bundle.json")
        )
        final = UpdateBundle.model_validate(load_json(submission / "bundle.json"))
        result_path = trust_workspace / "results" / f"{final.core.attestation_result_id}.json"
        result = AttestationResultV2.model_validate(load_json(result_path))
        result_id = result.result_id
        enrollment = _enrollment(trust_workspace, target)
        target_public_key = load_public_key(
            enrollment.core.esk_public_key_pem.encode("utf-8")
        )
        if not _verify_signed(original, target_public_key):
            errors.append("pre-reattestation Update Bundle ESK signature is invalid")
        if not _verify_signed(final, target_public_key):
            errors.append("post-reattestation Update Bundle ESK signature is invalid")
        if (
            original.core.attestation_result_id != expected.attestation_result_id
            or original.core.update_sha256 != final.core.update_sha256
            or original.core.metrics_sha256 != final.core.metrics_sha256
        ):
            errors.append("post-training rebind changed the probe or its initial evidence")
        if (
            result.core.status != contract.core.expected_post_status
            or not verify_result_signature(trust_workspace, result)
            or sha256_file(result_path) != final.core.attestation_result_sha256
        ):
            errors.append("post-training failed_measurement result is invalid")
        chronology = (
            _parse_time(context.core.issued_at)
            <= _parse_time(original.core.generated_at)
            <= _parse_time(result.core.evaluated_at)
            <= _parse_time(final.core.generated_at)
            < _parse_time(context.core.expires_at)
        )
        if not chronology:
            errors.append("training, re-attestation, and bundle chronology is invalid")

        evidence = QuoteEvidence.model_validate(
            load_json(workspace / "real-attestation-evidence" / "quote-evidence.json")
        )
        mutation = load_json(
            workspace / "real-attestation-evidence" / "pcr-mutation.json"
        )
        if (
            evidence.core.client_id != target
            or evidence.core.quote_format != contract.core.quote_format
            or not _quote_matches_result(evidence=evidence, result=result)
            or mutation.get("client_id") != target
            or mutation.get("pcr_index") != contract.core.pcr_index
            or mutation.get("measurement_sha256") != contract.core.measurement_sha256
            or evidence.core.observed_pcr_values.get(str(contract.core.pcr_index))
            != mutation.get("after_sha256")
        ):
            errors.append("preserved PCR mutation/Quote evidence binding is invalid")
        quote_valid, _detail = verify_tpm2_quote(
            evidence, enrollment, evidence.core.observed_pcr_values
        )
        if not quote_valid:
            errors.append("post-training Quote is not authentically signed by the enrolled AK")

        checks = _admission_checks(
            bundle=final,
            submission=submission,
            context=context,
            base=load_json(public / "base-model.json"),
            trust_workspace=trust_workspace,
            now=_parse_time(final.core.generated_at),
            post_training_attestation_client_id=target,
        )
        failed_checks = [item.name for item in checks if not item.passed]
        if failed_checks != ["fresh_attestation"]:
            errors.append(
                f"real failure did not isolate the fresh_attestation gate: {failed_checks}"
            )

        decision_path = workspace / "in-round-decisions" / f"{target}.json"
        decision = InRoundContributionDecision.model_validate(load_json(decision_path))
        decision_id = decision.decision_id
        checkpoint = InRoundSecureCheckpoint.model_validate(
            load_json(workspace / "checkpoint" / "manifest.json")
        )
        accepted_clients = {item.client_id for item in checkpoint.core.accepted_inputs}
        if (
            decision.core.final_status != "trust_quarantined"
            or decision.core.trust.raw_status != "failed_measurement"
            or decision.core.statistics is not None
            or target in accepted_clients
            or checkpoint.core.quarantined_count < 1
        ):
            errors.append("failed TPM client was not quarantined before FedAvg")
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        RuntimeError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "target_client_id": target,
        "post_attestation_result_id": result_id,
        "decision_id": decision_id,
        "authentic_quote_verified": not errors,
        "failed_measurement_verified": not errors,
        "fedavg_exclusion_verified": not errors,
        "error_count": len(errors),
        "errors": errors,
    }
