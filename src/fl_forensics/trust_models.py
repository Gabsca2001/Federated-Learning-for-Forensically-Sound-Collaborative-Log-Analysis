"""Versioned M4 trust, enrollment, and attestation artifacts."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc


KEY_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
NONCE_PATTERN = r"^[0-9a-f]{64}$"


class MeasurementEvent(StrictModel):
    sequence_number: int = Field(ge=0)
    pcr_index: int = Field(ge=0, le=23)
    component_id: str
    component_version: str
    source_path: str
    measurement_sha256: str = Field(pattern=HEX_256_PATTERN)


class MeasurementLog(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["measurement_event_log"] = "measurement_event_log"
    pcr_bank: Literal["sha256"] = "sha256"
    events: list[MeasurementEvent]


class EnrollmentRequestCore(StrictModel):
    request_id: str
    client_id: str
    node_id: str
    tpm_instance_id: str
    trust_level: Literal["software-development", "swtpm", "tpm2"]
    ek_public_sha256: str = Field(pattern=HEX_256_PATTERN)
    ak_key_id: str = Field(pattern=KEY_ID_PATTERN)
    ak_public_key_pem: str
    esk_key_id: str = Field(pattern=KEY_ID_PATTERN)
    esk_public_key_pem: str
    tls_csr_pem: str
    tls_public_key_sha256: str = Field(pattern=HEX_256_PATTERN)
    measurement_log_digest: str = Field(pattern=HEX_256_PATTERN)
    requested_at: str

    _requested_utc = field_validator("requested_at")(_require_utc)


class EnrollmentRequest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["enrollment_request"] = "enrollment_request"
    core: EnrollmentRequestCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class EnrollmentRecordCore(StrictModel):
    enrollment_id: str
    request_id: str
    client_id: str
    node_id: str
    organization_id: str
    tpm_instance_id: str
    trust_level: Literal["swtpm", "tpm2"]
    ek_public_sha256: str = Field(pattern=HEX_256_PATTERN)
    ek_credential_status: Literal[
        "emulator-logical-identity", "manufacturer-certificate", "manual-approval"
    ]
    ak_key_id: str = Field(pattern=KEY_ID_PATTERN)
    ak_public_key_pem: str
    esk_key_id: str = Field(pattern=KEY_ID_PATTERN)
    esk_public_key_pem: str
    tls_certificate_sha256: str = Field(pattern=HEX_256_PATTERN)
    pcr_bank: Literal["sha256"] = "sha256"
    pcr_selection: list[int]
    policy_id: str
    policy_version: str
    baseline_id: str
    baseline_version: str
    baseline_measurement_log_digest: str = Field(pattern=HEX_256_PATTERN)
    expected_pcr_values: dict[str, str]
    status: Literal["active", "revoked"] = "active"
    valid_from: str
    valid_until: str
    issued_at: str

    _valid_from_utc = field_validator("valid_from")(_require_utc)
    _valid_until_utc = field_validator("valid_until")(_require_utc)
    _issued_utc = field_validator("issued_at")(_require_utc)


class EnrollmentRecord(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["enrollment_record"] = "enrollment_record"
    core: EnrollmentRecordCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class RevocationRecordCore(StrictModel):
    revocation_id: str
    enrollment_id: str
    client_id: str
    node_id: str
    reason: str
    revoked_at: str

    _revoked_utc = field_validator("revoked_at")(_require_utc)


class RevocationRecord(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["enrollment_revocation"] = "enrollment_revocation"
    core: RevocationRecordCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class AttestationChallengeCore(StrictModel):
    challenge_id: str
    enrollment_id: str
    client_id: str
    node_id: str
    nonce: str = Field(pattern=NONCE_PATTERN)
    pcr_bank: Literal["sha256"] = "sha256"
    pcr_selection: list[int]
    policy_id: str
    policy_version: str
    baseline_id: str
    baseline_version: str
    issued_at: str
    expires_at: str

    _issued_utc = field_validator("issued_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)


class AttestationChallenge(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["attestation_challenge"] = "attestation_challenge"
    core: AttestationChallengeCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class QuoteEvidenceCore(StrictModel):
    evidence_id: str
    enrollment_id: str
    challenge_id: str
    client_id: str
    node_id: str
    ak_key_id: str = Field(pattern=KEY_ID_PATTERN)
    quote_format: Literal["software-jcs-v1", "tpm2-tools-tpms-attest"]
    nonce: str = Field(pattern=NONCE_PATTERN)
    pcr_bank: Literal["sha256"] = "sha256"
    pcr_selection: list[int]
    observed_pcr_values: dict[str, str]
    measurement_log_digest: str = Field(pattern=HEX_256_PATTERN)
    quote_message_b64: str
    quote_signature_b64: str
    generated_at: str

    _generated_utc = field_validator("generated_at")(_require_utc)


class QuoteEvidence(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["tpm_quote_evidence"] = "tpm_quote_evidence"
    core: QuoteEvidenceCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)


class AttestationResultCoreV2(StrictModel):
    node_id: str
    client_id: str
    enrollment_id: str
    challenge_id: str
    ak_key_id: str = Field(pattern=KEY_ID_PATTERN)
    status: Literal[
        "passed",
        "passed_with_warning",
        "failed_identity",
        "failed_measurement",
        "stale",
        "unavailable",
    ]
    nonce: str = Field(pattern=NONCE_PATTERN)
    pcr_bank: Literal["sha256"] = "sha256"
    pcr_selection: list[int]
    quote_digest: str = Field(pattern=HEX_256_PATTERN)
    quote_evidence_digest: str = Field(pattern=HEX_256_PATTERN)
    measurement_log_digest: str = Field(pattern=HEX_256_PATTERN)
    transport_peer_fingerprint: str = Field(pattern=HEX_256_PATTERN)
    policy_id: str
    policy_version: str
    baseline_id: str
    baseline_version: str
    evaluated_at: str
    expires_at: str
    reasons: list[str] = Field(default_factory=list)

    _evaluated_utc = field_validator("evaluated_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)


class AttestationResultV2(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    artifact_type: Literal["attestation_result"] = "attestation_result"
    result_id: str
    core: AttestationResultCoreV2
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock
