"""M4 enrollment, nonce challenge, attestation appraisal, and revocation protocol."""

from __future__ import annotations

import base64
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric import ec

from .attestation import create_attestation_result_v2, verify_attestation_signature
from .canonical import canonical_json_bytes, digest_object, sha256_bytes
from .config import load_yaml
from .crypto import (
    DigestSigner,
    SoftwareECDSASigner,
    load_public_key,
    public_key_id,
    verify_digest_signature,
)
from .mtls import (
    certificate_sha256,
    create_client_csr,
    exercise_mtls_handshake,
    initialize_private_pki,
    issue_client_certificate,
    load_certificate,
    verify_client_certificate_binding,
)
from .storage import atomic_json, atomic_write, load_json, utc_now, write_json_once
from .trust_models import (
    AttestationChallenge,
    AttestationChallengeCore,
    AttestationResultCoreV2,
    AttestationResultV2,
    EnrollmentRecord,
    EnrollmentRecordCore,
    EnrollmentRequest,
    EnrollmentRequestCore,
    MeasurementEvent,
    MeasurementLog,
    QuoteEvidence,
    QuoteEvidenceCore,
    RevocationRecord,
    RevocationRecordCore,
)


ZERO_SHA256 = "0" * 64
QuoteVerifier = Callable[[QuoteEvidence, EnrollmentRecord, dict[str, str]], tuple[bool, str]]


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _private_key_bytes(signer: SoftwareECDSASigner) -> bytes:
    return signer.private_pem()


def _write_signer(root: Path, name: str, signer: SoftwareECDSASigner) -> None:
    private_path = root / "authority" / f"{name}.private.pem"
    public_path = root / "authority" / f"{name}.public.pem"
    atomic_write(private_path, _private_key_bytes(signer))
    private_path.chmod(0o600)
    atomic_write(public_path, signer.public_pem())


def _load_signer(root: Path, name: str) -> SoftwareECDSASigner:
    return SoftwareECDSASigner.load(root / "authority" / f"{name}.private.pem")


def build_measurement_log(project_root: Path, trust_config: dict[str, Any]) -> MeasurementLog:
    events: list[MeasurementEvent] = []
    for sequence, item in enumerate(trust_config["measurements"]):
        path = project_root / str(item["path"])
        if not path.is_file():
            raise FileNotFoundError(f"measurement input is missing: {path}")
        events.append(
            MeasurementEvent(
                sequence_number=sequence,
                pcr_index=int(item["pcr_index"]),
                component_id=str(item["component_id"]),
                component_version=str(item["component_version"]),
                source_path=str(item["path"]),
                measurement_sha256=sha256_bytes(path.read_bytes()),
            )
        )
    return MeasurementLog(events=events)


def replay_pcrs(log: MeasurementLog, selection: list[int]) -> dict[str, str]:
    values = {str(index): bytes(32) for index in selection}
    expected_sequence = list(range(len(log.events)))
    if [item.sequence_number for item in log.events] != expected_sequence:
        raise ValueError("measurement event sequence is not contiguous")
    for event in log.events:
        key = str(event.pcr_index)
        if key not in values:
            raise ValueError(f"measurement targets unselected PCR {event.pcr_index}")
        values[key] = bytes.fromhex(
            sha256_bytes(values[key] + bytes.fromhex(event.measurement_sha256))
        )
    return {key: value.hex() for key, value in values.items()}


def initialize_trust_workspace(
    *,
    workspace: Path,
    project_root: Path,
    trust_config_path: Path,
    clients_config_path: Path,
) -> dict[str, Any]:
    manifest_path = workspace / "manifest.json"
    if manifest_path.exists():
        manifest = load_json(manifest_path)
        return {
            "status": "existing",
            "workspace": str(workspace),
            "client_count": manifest["client_count"],
            "baseline_id": manifest["baseline_id"],
            "manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
        }
    if workspace.exists() and any(workspace.iterdir()):
        raise RuntimeError("M4 trust workspace is non-empty but has no manifest")

    trust_config, trust_digest = load_yaml(trust_config_path)
    clients_config, clients_digest = load_yaml(clients_config_path)
    clients = clients_config["clients"]
    if len(clients) != 15:
        raise ValueError("M4 requires exactly 15 client/TPM pairs")

    authority_signer = SoftwareECDSASigner.generate()
    verifier_signer = SoftwareECDSASigner.generate()
    _write_signer(workspace, "enrollment-authority", authority_signer)
    _write_signer(workspace, "attestation-verifier", verifier_signer)
    pki = initialize_private_pki(
        workspace, lifetime_days=int(trust_config["mtls"]["ca_lifetime_days"])
    )

    measurement_log = build_measurement_log(project_root, trust_config)
    selection = [int(value) for value in trust_config["attestation"]["pcr_selection"]]
    expected_pcrs = replay_pcrs(measurement_log, selection)
    write_json_once(
        workspace / "baseline" / "measurement_log.json",
        measurement_log.model_dump(mode="json"),
    )
    baseline = {
        "schema_version": "1.0",
        "artifact_type": "reference_integrity_baseline",
        "baseline_id": trust_config["attestation"]["baseline_id"],
        "baseline_version": trust_config["attestation"]["baseline_version"],
        "pcr_bank": "sha256",
        "pcr_selection": selection,
        "measurement_log_digest": digest_object(measurement_log.model_dump(mode="json")),
        "expected_pcr_values": expected_pcrs,
    }
    write_json_once(workspace / "baseline" / "baseline.json", baseline)

    manifest = {
        "schema_version": "1.0",
        "artifact_type": "m4_trust_workspace_manifest",
        "created_at": utc_now(),
        "client_count": 15,
        "clients_config_digest": clients_digest,
        "trust_config_digest": trust_digest,
        "policy_id": trust_config["attestation"]["policy_id"],
        "policy_version": trust_config["attestation"]["policy_version"],
        "attestation_result_lifetime_seconds": int(
            trust_config["attestation"]["result_lifetime_seconds"]
        ),
        "baseline_id": baseline["baseline_id"],
        "baseline_version": baseline["baseline_version"],
        "baseline_digest": digest_object(baseline),
        "enrollment_authority_key_id": authority_signer.key_id,
        "attestation_verifier_key_id": verifier_signer.key_id,
        **pki,
    }
    write_json_once(manifest_path, manifest)
    atomic_json(workspace / "registry" / "index.json", {"enrollments": {}})
    atomic_json(workspace / "state" / "challenges.json", {"issued": {}, "consumed": {}})
    return {
        "status": "initialized",
        "workspace": str(workspace),
        "client_count": 15,
        "baseline_id": baseline["baseline_id"],
        "manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
    }


def create_enrollment_request(
    *,
    node_workspace: Path,
    client_id: str,
    node_id: str,
    tpm_instance_id: str,
    trust_level: str,
    ek_public_bytes: bytes,
    ak_public_pem: bytes,
    esk_public_pem: bytes,
    esk_signer: DigestSigner,
    measurement_log: MeasurementLog,
    requested_at: str | None = None,
) -> EnrollmentRequest:
    ak_public = load_public_key(ak_public_pem)
    esk_public = load_public_key(esk_public_pem)
    if public_key_id(ak_public) == public_key_id(esk_public):
        raise ValueError("AK and ESK must be different keys")
    if esk_signer.key_id != public_key_id(esk_public):
        raise ValueError("ESK signer does not match the declared public key")
    csr_pem, tls_public_digest = create_client_csr(
        node_workspace, client_id=client_id, node_id=node_id
    )
    basis = {
        "client_id": client_id,
        "node_id": node_id,
        "tpm_instance_id": tpm_instance_id,
        "trust_level": trust_level,
        "ek_public_sha256": sha256_bytes(ek_public_bytes),
        "ak_key_id": public_key_id(ak_public),
        "ak_public_key_pem": ak_public_pem.decode(),
        "esk_key_id": public_key_id(esk_public),
        "esk_public_key_pem": esk_public_pem.decode(),
        "tls_csr_pem": csr_pem,
        "tls_public_key_sha256": tls_public_digest,
        "measurement_log_digest": digest_object(measurement_log.model_dump(mode="json")),
        "requested_at": requested_at or utc_now(),
    }
    core = EnrollmentRequestCore(
        request_id=f"enrollment-request-{digest_object(basis)[:24]}", **basis
    )
    core_digest = digest_object(core.model_dump(mode="json"))
    request = EnrollmentRequest(
        core=core,
        core_digest=core_digest,
        signature={
            "key_id": esk_signer.key_id,
            "value_b64": esk_signer.sign_digest(core_digest),
            "trust_level": trust_level,
        },
    )
    write_json_once(
        node_workspace / "enrollment" / f"{core.request_id}.json",
        request.model_dump(mode="json"),
    )
    atomic_json(
        node_workspace / "enrollment_request.json", request.model_dump(mode="json")
    )
    return request


def verify_enrollment_request(request: EnrollmentRequest) -> tuple[bool, list[str]]:
    errors: list[str] = []
    actual_digest = digest_object(request.core.model_dump(mode="json"))
    if actual_digest != request.core_digest:
        errors.append("enrollment request core digest is invalid")
    try:
        esk_key = load_public_key(request.core.esk_public_key_pem.encode())
        if request.core.esk_key_id != public_key_id(esk_key):
            errors.append("enrollment ESK identifier is invalid")
        elif request.signature.key_id != request.core.esk_key_id or not verify_digest_signature(
            esk_key, request.core_digest, request.signature.value_b64
        ):
            errors.append("enrollment request ESK signature is invalid")
        ak_key = load_public_key(request.core.ak_public_key_pem.encode())
        if request.core.ak_key_id != public_key_id(ak_key):
            errors.append("enrollment AK identifier is invalid")
        if request.core.ak_key_id == request.core.esk_key_id:
            errors.append("AK and ESK roles reuse the same key")
    except ValueError as exc:
        errors.append(f"invalid enrollment public key: {exc}")
    return not errors, errors


def _sign_enrollment_record(
    core: EnrollmentRecordCore, signer: SoftwareECDSASigner
) -> EnrollmentRecord:
    core_digest = digest_object(core.model_dump(mode="json"))
    return EnrollmentRecord(
        core=core,
        core_digest=core_digest,
        signature={
            "key_id": signer.key_id,
            "value_b64": signer.sign_digest(core_digest),
            "trust_level": "software-development",
        },
    )


def enroll_nodes(
    *,
    workspace: Path,
    node_root: Path,
    trust_config_path: Path,
    clients_config_path: Path,
    require_all: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    trust_config, _ = load_yaml(trust_config_path)
    clients_config, _ = load_yaml(clients_config_path)
    expected = {item["client_id"]: item for item in clients_config["clients"]}
    authority = _load_signer(workspace, "enrollment-authority")
    baseline = load_json(workspace / "baseline" / "baseline.json")
    index_path = workspace / "registry" / "index.json"
    index = load_json(index_path)
    now = now or datetime.now(UTC)
    enrolled: list[str] = []
    errors: list[str] = []

    for client_id, pair in expected.items():
        node_workspace = node_root / client_id
        request_path = node_workspace / "enrollment_request.json"
        if not request_path.exists():
            if require_all:
                errors.append(f"{client_id}: enrollment request is missing")
            continue
        request = EnrollmentRequest.model_validate(load_json(request_path))
        valid, request_errors = verify_enrollment_request(request)
        if not valid:
            errors.extend(f"{client_id}: {item}" for item in request_errors)
            continue
        core = request.core
        if (
            core.client_id != client_id
            or core.node_id != pair["node_id"]
            or core.tpm_instance_id != pair["tpm"]
        ):
            errors.append(f"{client_id}: request does not match the declared client/node/TPM pair")
            continue
        if core.trust_level not in {"swtpm", "tpm2"}:
            errors.append(f"{client_id}: development software identity cannot be enrolled for M4")
            continue
        measurement_log = MeasurementLog.model_validate(
            load_json(node_workspace / "measurement_log.json")
        )
        measured_digest = digest_object(measurement_log.model_dump(mode="json"))
        if measured_digest != core.measurement_log_digest:
            errors.append(f"{client_id}: request does not bind the preserved measurement log")
            continue
        if measured_digest != baseline["measurement_log_digest"]:
            errors.append(f"{client_id}: measured components do not match the approved baseline")
            continue

        certificate = issue_client_certificate(
            workspace=workspace,
            node_workspace=node_workspace,
            csr_pem=core.tls_csr_pem,
            client_id=client_id,
            node_id=core.node_id,
            lifetime_days=int(trust_config["mtls"]["client_certificate_lifetime_days"]),
        )
        valid_from = now - timedelta(minutes=5)
        valid_until = now + timedelta(days=int(trust_config["enrollment"]["lifetime_days"]))
        record_basis = {
            "request_id": core.request_id,
            "client_id": client_id,
            "node_id": core.node_id,
            "organization_id": trust_config["enrollment"]["organization_id"],
            "tpm_instance_id": core.tpm_instance_id,
            "trust_level": core.trust_level,
            "ek_public_sha256": core.ek_public_sha256,
            "ek_credential_status": (
                "emulator-logical-identity" if core.trust_level == "swtpm" else "manual-approval"
            ),
            "ak_key_id": core.ak_key_id,
            "ak_public_key_pem": core.ak_public_key_pem,
            "esk_key_id": core.esk_key_id,
            "esk_public_key_pem": core.esk_public_key_pem,
            "tls_certificate_sha256": certificate_sha256(certificate),
            "pcr_bank": "sha256",
            "pcr_selection": baseline["pcr_selection"],
            "policy_id": trust_config["attestation"]["policy_id"],
            "policy_version": trust_config["attestation"]["policy_version"],
            "baseline_id": baseline["baseline_id"],
            "baseline_version": baseline["baseline_version"],
            "baseline_measurement_log_digest": baseline["measurement_log_digest"],
            "expected_pcr_values": baseline["expected_pcr_values"],
            "status": "active",
            "valid_from": valid_from.isoformat().replace("+00:00", "Z"),
            "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
            "issued_at": now.isoformat().replace("+00:00", "Z"),
        }
        enrollment_id = f"enrollment-{digest_object(record_basis)[:24]}"
        record = _sign_enrollment_record(
            EnrollmentRecordCore(enrollment_id=enrollment_id, **record_basis), authority
        )
        record_path = workspace / "registry" / "enrollments" / f"{enrollment_id}.json"
        write_json_once(record_path, record.model_dump(mode="json"))
        atomic_json(node_workspace / "enrollment_record.json", record.model_dump(mode="json"))
        index["enrollments"][client_id] = {
            "enrollment_id": enrollment_id,
            "record_path": record_path.relative_to(workspace).as_posix(),
            "record_digest": digest_object(record.model_dump(mode="json")),
        }
        enrolled.append(client_id)

    if errors:
        return {
            "status": "failed",
            "workspace": str(workspace),
            "enrolled_count": len(enrolled),
            "errors": errors,
        }
    atomic_json(index_path, index)
    return {
        "status": "enrolled",
        "workspace": str(workspace),
        "enrolled_count": len(enrolled),
        "clients": enrolled,
    }


def verify_enrollment_record(
    record: EnrollmentRecord, authority_public_key: ec.EllipticCurvePublicKey
) -> bool:
    digest = digest_object(record.core.model_dump(mode="json"))
    return (
        digest == record.core_digest
        and record.signature.key_id == public_key_id(authority_public_key)
        and verify_digest_signature(
            authority_public_key, record.core_digest, record.signature.value_b64
        )
    )


def _sign_challenge(
    core: AttestationChallengeCore, signer: SoftwareECDSASigner
) -> AttestationChallenge:
    digest = digest_object(core.model_dump(mode="json"))
    return AttestationChallenge(
        core=core,
        core_digest=digest,
        signature={
            "key_id": signer.key_id,
            "value_b64": signer.sign_digest(digest),
            "trust_level": "software-development",
        },
    )


def issue_challenges(
    *,
    workspace: Path,
    node_root: Path,
    trust_config_path: Path,
    client_ids: list[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    config, _ = load_yaml(trust_config_path)
    index = load_json(workspace / "registry" / "index.json")
    state_path = workspace / "state" / "challenges.json"
    state = load_json(state_path)
    signer = _load_signer(workspace, "attestation-verifier")
    now = now or datetime.now(UTC)
    expires = now + timedelta(seconds=int(config["attestation"]["challenge_lifetime_seconds"]))
    selected = client_ids or sorted(index["enrollments"])
    issued: list[str] = []
    for client_id in selected:
        entry = index["enrollments"].get(client_id)
        if entry is None:
            raise ValueError(f"client is not enrolled: {client_id}")
        # record = EnrollmentRecord.model_validate(load_json(workspace / entry["record_path"]))
        record_path = Path(
            str(entry["record_path"]).replace("\\", "/")
        )
        record = EnrollmentRecord.model_validate(
            load_json(workspace / record_path)
        )
        core = AttestationChallengeCore(
            challenge_id=f"challenge-{secrets.token_hex(12)}",
            enrollment_id=record.core.enrollment_id,
            client_id=record.core.client_id,
            node_id=record.core.node_id,
            nonce=secrets.token_hex(32),
            pcr_selection=record.core.pcr_selection,
            policy_id=record.core.policy_id,
            policy_version=record.core.policy_version,
            baseline_id=record.core.baseline_id,
            baseline_version=record.core.baseline_version,
            issued_at=now.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
        )
        challenge = _sign_challenge(core, signer)
        immutable_path = workspace / "challenges" / f"{core.challenge_id}.json"
        write_json_once(immutable_path, challenge.model_dump(mode="json"))
        atomic_json(
            node_root / client_id / "challenge.json", challenge.model_dump(mode="json")
        )
        state["issued"][core.challenge_id] = {
            "client_id": client_id,
            "challenge_digest": digest_object(challenge.model_dump(mode="json")),
            "path": str(immutable_path.relative_to(workspace)),
        }
        issued.append(core.challenge_id)
    atomic_json(state_path, state)
    return {
        "status": "issued",
        "workspace": str(workspace),
        "challenge_count": len(issued),
        "challenge_ids": issued,
    }


def create_software_quote_evidence(
    *,
    node_workspace: Path,
    ak_signer: DigestSigner,
    generated_at: str | None = None,
) -> QuoteEvidence:
    challenge = AttestationChallenge.model_validate(load_json(node_workspace / "challenge.json"))
    record = EnrollmentRecord.model_validate(load_json(node_workspace / "enrollment_record.json"))
    log = MeasurementLog.model_validate(load_json(node_workspace / "measurement_log.json"))
    observed = replay_pcrs(log, challenge.core.pcr_selection)
    message = {
        "magic": "TPM_GENERATED_VALUE",
        "type": "TPM_ST_ATTEST_QUOTE",
        "challenge_id": challenge.core.challenge_id,
        "nonce": challenge.core.nonce,
        "pcr_bank": challenge.core.pcr_bank,
        "pcr_selection": challenge.core.pcr_selection,
        "pcr_values": observed,
        "measurement_log_digest": digest_object(log.model_dump(mode="json")),
        "ak_key_id": ak_signer.key_id,
    }
    message_bytes = canonical_json_bytes(message)
    signature = ak_signer.sign_digest(sha256_bytes(message_bytes))
    basis = {
        "enrollment_id": record.core.enrollment_id,
        "challenge_id": challenge.core.challenge_id,
        "client_id": record.core.client_id,
        "node_id": record.core.node_id,
        "ak_key_id": ak_signer.key_id,
        "quote_format": "software-jcs-v1",
        "nonce": challenge.core.nonce,
        "pcr_bank": "sha256",
        "pcr_selection": challenge.core.pcr_selection,
        "observed_pcr_values": observed,
        "measurement_log_digest": digest_object(log.model_dump(mode="json")),
        "quote_message_b64": base64.b64encode(message_bytes).decode(),
        "quote_signature_b64": signature,
        "generated_at": generated_at or utc_now(),
    }
    core = QuoteEvidenceCore(evidence_id=f"quote-{digest_object(basis)[:24]}", **basis)
    evidence = QuoteEvidence(
        core=core, core_digest=digest_object(core.model_dump(mode="json"))
    )
    write_json_once(
        node_workspace / "quotes" / f"{core.evidence_id}.json",
        evidence.model_dump(mode="json"),
    )
    atomic_json(node_workspace / "quote_evidence.json", evidence.model_dump(mode="json"))
    return evidence


def verify_software_quote(
    evidence: QuoteEvidence,
    record: EnrollmentRecord,
    expected_pcrs: dict[str, str],
) -> tuple[bool, str]:
    try:
        message_bytes = base64.b64decode(evidence.core.quote_message_b64, validate=True)
        message = json.loads(message_bytes)
        ak = load_public_key(record.core.ak_public_key_pem.encode())
        signature_valid = verify_digest_signature(
            ak, sha256_bytes(message_bytes), evidence.core.quote_signature_b64
        )
        fields_valid = (
            message.get("magic") == "TPM_GENERATED_VALUE"
            and message.get("type") == "TPM_ST_ATTEST_QUOTE"
            and message.get("challenge_id") == evidence.core.challenge_id
            and message.get("nonce") == evidence.core.nonce
            and message.get("pcr_selection") == evidence.core.pcr_selection
            and message.get("pcr_values") == expected_pcrs
            and message.get("ak_key_id") == record.core.ak_key_id
        )
        return (
            signature_valid and fields_valid,
            "software protocol quote signature and expected PCR values verified"
            if signature_valid and fields_valid
            else "software protocol quote signature or fields are invalid",
        )
    except (ValueError, json.JSONDecodeError) as exc:
        return False, f"software protocol quote cannot be decoded: {exc}"


def _revoked(workspace: Path, enrollment_id: str) -> bool:
    directory = workspace / "registry" / "revocations"
    if not directory.exists():
        return False
    authority = load_public_key(
        (workspace / "authority" / "enrollment-authority.public.pem").read_bytes()
    )
    for path in directory.glob("*.json"):
        record = RevocationRecord.model_validate(load_json(path))
        digest = digest_object(record.core.model_dump(mode="json"))
        if not (
            digest == record.core_digest
            and record.signature.key_id == public_key_id(authority)
            and verify_digest_signature(
                authority, record.core_digest, record.signature.value_b64
            )
        ):
            raise ValueError(f"revocation record is invalid: {path.name}")
        if record.core.enrollment_id == enrollment_id:
            return True
    return False


def verify_quote_evidence(
    *,
    workspace: Path,
    node_workspace: Path,
    quote_verifier: QuoteVerifier,
    now: datetime | None = None,
) -> tuple[AttestationResultV2, bool]:
    evidence = QuoteEvidence.model_validate(load_json(node_workspace / "quote_evidence.json"))
    challenge_path = workspace / "challenges" / f"{evidence.core.challenge_id}.json"
    challenge = AttestationChallenge.model_validate(load_json(challenge_path))
    index = load_json(workspace / "registry" / "index.json")
    enrollment_entry = index["enrollments"].get(evidence.core.client_id)
    if enrollment_entry is None:
        raise ValueError("quote client has no enrollment record")
    record_path = Path(
        str(enrollment_entry["record_path"]).replace("\\", "/")
    )
    record = EnrollmentRecord.model_validate(
        load_json(workspace / record_path)
    )
    authority_key = load_public_key(
        (workspace / "authority" / "enrollment-authority.public.pem").read_bytes()
    )
    verifier_key = load_public_key(
        (workspace / "authority" / "attestation-verifier.public.pem").read_bytes()
    )
    verifier_signer = _load_signer(workspace, "attestation-verifier")
    ca_certificate = load_certificate(workspace / "pki" / "ca.certificate.pem")
    client_certificate = load_certificate(node_workspace / "tls" / "client.certificate.pem")
    now = now or datetime.now(UTC)
    reasons: list[str] = []
    identity_failed = False
    measurement_failed = False
    stale = False
    unavailable = False

    if not verify_enrollment_record(record, authority_key):
        identity_failed = True
        reasons.append("enrollment record signature or digest is invalid")
    try:
        if _revoked(workspace, record.core.enrollment_id):
            identity_failed = True
            reasons.append("enrollment identity is revoked")
    except ValueError as exc:
        identity_failed = True
        reasons.append(str(exc))
    if not (_parse_utc(record.core.valid_from) <= now <= _parse_utc(record.core.valid_until)):
        identity_failed = True
        reasons.append("enrollment identity is outside its validity period")
    identity_binding = (
        evidence.core.client_id == record.core.client_id == challenge.core.client_id
        and evidence.core.node_id == record.core.node_id == challenge.core.node_id
        and evidence.core.enrollment_id == record.core.enrollment_id == challenge.core.enrollment_id
        and evidence.core.ak_key_id == record.core.ak_key_id
    )
    if not identity_binding:
        identity_failed = True
        reasons.append("quote, challenge, enrollment, or AK identity binding is inconsistent")

    cert_valid, cert_detail = verify_client_certificate_binding(
        certificate=client_certificate,
        ca_certificate=ca_certificate,
        client_id=record.core.client_id,
        expected_fingerprint=record.core.tls_certificate_sha256,
        at_time=now,
    )
    if not cert_valid:
        identity_failed = True
        reasons.append(cert_detail)

    challenge_digest = digest_object(challenge.core.model_dump(mode="json"))
    challenge_signature_valid = (
        challenge_digest == challenge.core_digest
        and challenge.signature.key_id == public_key_id(verifier_key)
        and verify_digest_signature(
            verifier_key, challenge.core_digest, challenge.signature.value_b64
        )
    )
    if not challenge_signature_valid:
        identity_failed = True
        reasons.append("attestation challenge signature or digest is invalid")
    if now > _parse_utc(challenge.core.expires_at):
        stale = True
        reasons.append("attestation challenge has expired")
    if evidence.core.nonce != challenge.core.nonce:
        stale = True
        reasons.append("quote nonce does not match the issued challenge")
    if evidence.core.pcr_selection != challenge.core.pcr_selection:
        measurement_failed = True
        reasons.append("quote PCR selection does not match the challenge")

    actual_evidence_core_digest = digest_object(evidence.core.model_dump(mode="json"))
    if actual_evidence_core_digest != evidence.core_digest:
        measurement_failed = True
        reasons.append("quote evidence wrapper digest is invalid")
    measurement_log = MeasurementLog.model_validate(
        load_json(node_workspace / "measurement_log.json")
    )
    measurement_digest = digest_object(measurement_log.model_dump(mode="json"))
    if (
        evidence.core.measurement_log_digest != measurement_digest
        or measurement_digest != record.core.baseline_measurement_log_digest
    ):
        measurement_failed = True
        reasons.append("measurement log does not match the enrolled baseline")
    try:
        replayed = replay_pcrs(measurement_log, record.core.pcr_selection)
        if replayed != record.core.expected_pcr_values:
            measurement_failed = True
            reasons.append("measurement log replay does not produce the enrolled PCR baseline")
    except ValueError as exc:
        measurement_failed = True
        reasons.append(str(exc))

    state_path = workspace / "state" / "challenges.json"
    state = load_json(state_path)
    evidence_digest = digest_object(evidence.model_dump(mode="json"))
    consumed = state["consumed"].get(challenge.core.challenge_id)
    if consumed:
        if consumed["evidence_digest"] == evidence_digest:
            existing = AttestationResultV2.model_validate(
                load_json(workspace / consumed["result_path"])
            )
            return existing, True
        stale = True
        reasons.append("challenge nonce has already been consumed by different evidence")

    try:
        quote_valid, quote_detail = quote_verifier(
            evidence, record, record.core.expected_pcr_values
        )
        if not quote_valid:
            measurement_failed = True
            reasons.append(quote_detail)
    except (OSError, RuntimeError, ValueError) as exc:
        unavailable = True
        reasons.append(f"quote verification unavailable: {exc}")

    if identity_failed:
        status = "failed_identity"
    elif stale:
        status = "stale"
    elif unavailable:
        status = "unavailable"
    elif measurement_failed:
        status = "failed_measurement"
    else:
        status = "passed"
        reasons.append("AK signature, nonce, PCR baseline, enrollment, and mTLS binding verified")
    lifetime = int(load_json(workspace / "manifest.json")["attestation_result_lifetime_seconds"])
    result_core = AttestationResultCoreV2(
        node_id=record.core.node_id,
        client_id=record.core.client_id,
        enrollment_id=record.core.enrollment_id,
        challenge_id=challenge.core.challenge_id,
        ak_key_id=record.core.ak_key_id,
        status=status,
        nonce=challenge.core.nonce,
        pcr_selection=record.core.pcr_selection,
        quote_digest=sha256_bytes(base64.b64decode(evidence.core.quote_message_b64)),
        quote_evidence_digest=evidence_digest,
        measurement_log_digest=measurement_digest,
        transport_peer_fingerprint=certificate_sha256(client_certificate),
        policy_id=record.core.policy_id,
        policy_version=record.core.policy_version,
        baseline_id=record.core.baseline_id,
        baseline_version=record.core.baseline_version,
        evaluated_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=(now + timedelta(seconds=lifetime)).isoformat().replace("+00:00", "Z"),
        reasons=reasons,
    )
    result = create_attestation_result_v2(
        result_core, verifier_signer, trust_level=record.core.trust_level
    )
    result_path = workspace / "results" / f"{result.result_id}.json"
    write_json_once(result_path, result.model_dump(mode="json"))
    state["consumed"][challenge.core.challenge_id] = {
        "evidence_digest": evidence_digest,
        "result_path": str(result_path.relative_to(workspace)),
        "status": status,
    }
    atomic_json(state_path, state)
    return result, False


def verify_attestation_campaign(
    *,
    workspace: Path,
    node_root: Path,
    quote_verifier: QuoteVerifier,
) -> dict[str, Any]:
    index = load_json(workspace / "registry" / "index.json")
    results: list[dict[str, Any]] = []
    for client_id in sorted(index["enrollments"]):
        node_workspace = node_root / client_id
        if not (node_workspace / "quote_evidence.json").exists():
            results.append(
                {"client_id": client_id, "status": "unavailable", "idempotent": False}
            )
            continue
        result, idempotent = verify_quote_evidence(
            workspace=workspace,
            node_workspace=node_workspace,
            quote_verifier=quote_verifier,
        )
        results.append(
            {
                "client_id": client_id,
                "status": result.core.status,
                "result_id": result.result_id,
                "idempotent": idempotent,
            }
        )
    passed = sum(item["status"] in {"passed", "passed_with_warning"} for item in results)
    return {
        "status": "verified" if passed == len(results) and len(results) == 15 else "failed",
        "workspace": str(workspace),
        "client_count": len(results),
        "passed_count": passed,
        "failed_count": len(results) - passed,
        "results": results,
    }


def revoke_enrollment(
    *, workspace: Path, client_id: str, reason: str, revoked_at: str | None = None
) -> RevocationRecord:
    index = load_json(workspace / "registry" / "index.json")
    entry = index["enrollments"].get(client_id)
    if entry is None:
        raise ValueError(f"client is not enrolled: {client_id}")
    enrollment = EnrollmentRecord.model_validate(load_json(workspace / entry["record_path"]))
    basis = {
        "enrollment_id": enrollment.core.enrollment_id,
        "client_id": client_id,
        "node_id": enrollment.core.node_id,
        "reason": reason,
        "revoked_at": revoked_at or utc_now(),
    }
    core = RevocationRecordCore(
        revocation_id=f"revocation-{digest_object(basis)[:24]}", **basis
    )
    signer = _load_signer(workspace, "enrollment-authority")
    core_digest = digest_object(core.model_dump(mode="json"))
    record = RevocationRecord(
        core=core,
        core_digest=core_digest,
        signature={
            "key_id": signer.key_id,
            "value_b64": signer.sign_digest(core_digest),
            "trust_level": "software-development",
        },
    )
    write_json_once(
        workspace / "registry" / "revocations" / f"{core.revocation_id}.json",
        record.model_dump(mode="json"),
    )
    return record


def test_mtls_bindings(*, workspace: Path, node_root: Path) -> dict[str, Any]:
    index = load_json(workspace / "registry" / "index.json")
    results: list[dict[str, Any]] = []
    for client_id in sorted(index["enrollments"]):
        record = EnrollmentRecord.model_validate(
            load_json(workspace / index["enrollments"][client_id]["record_path"])
        )
        outcome = exercise_mtls_handshake(
            workspace=workspace,
            node_workspace=node_root / client_id,
            claimed_client_id=client_id,
            expected_fingerprint=record.core.tls_certificate_sha256,
        )
        results.append({"client_id": client_id, **outcome})
    passed = sum(item.get("binding_valid") for item in results)
    return {
        "status": "verified" if passed == len(results) and len(results) == 15 else "failed",
        "client_count": len(results),
        "passed_count": passed,
        "results": results,
    }


def verify_result_signature(workspace: Path, result: AttestationResultV2) -> bool:
    key = load_public_key(
        (workspace / "authority" / "attestation-verifier.public.pem").read_bytes()
    )
    return verify_attestation_signature(result, key)
