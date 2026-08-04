"""Versioned artifact models for the phase-1 evidence path."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


HEX_256_PATTERN = r"^[0-9a-f]{64}$"


def _require_utc(value: str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SignatureBlock(StrictModel):
    algorithm: Literal["ECDSA-P256-SHA256"] = "ECDSA-P256-SHA256"
    key_id: str
    value_b64: str
    trust_level: Literal["software-development", "swtpm", "tpm2"]


class DigestRef(StrictModel):
    artifact_id: str
    digest: str = Field(pattern=HEX_256_PATTERN)


class AttestationResultCore(StrictModel):
    node_id: str
    client_id: str
    status: Literal[
        "passed",
        "passed_with_warning",
        "failed_identity",
        "failed_measurement",
        "stale",
        "unavailable",
    ]
    nonce: str
    pcr_selection: list[int]
    quote_digest: str = Field(pattern=HEX_256_PATTERN)
    measurement_log_digest: str = Field(pattern=HEX_256_PATTERN)
    policy_id: str
    policy_version: str
    baseline_id: str
    baseline_version: str
    evaluated_at: str
    expires_at: str
    reasons: list[str] = Field(default_factory=list)

    _evaluated_utc = field_validator("evaluated_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)


class AttestationResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["attestation_result"] = "attestation_result"
    result_id: str
    core: AttestationResultCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class BatchManifestCore(StrictModel):
    batch_id: str
    node_id: str
    client_id: str
    acquisition_session_id: str
    sequence_number: int = Field(ge=0)
    source_type: Literal["zeek-jsonl"]
    source_name: str
    observed_start: str
    observed_end: str
    acquired_at: str
    record_count: int = Field(ge=0)
    content_filename: str
    content_size_bytes: int = Field(ge=0)
    content_sha256: str = Field(pattern=HEX_256_PATTERN)
    previous_chain_hash: str = Field(pattern=HEX_256_PATTERN)
    collector_id: str
    collector_version: str
    collector_digest: str = Field(pattern=HEX_256_PATTERN)
    configuration_digest: str = Field(pattern=HEX_256_PATTERN)
    attestation_id: str
    attestation_digest: str = Field(pattern=HEX_256_PATTERN)
    hash_algorithm: Literal["SHA-256"] = "SHA-256"
    chain_encoding: Literal["binary-digests"] = "binary-digests"

    _observed_start_utc = field_validator("observed_start")(_require_utc)
    _observed_end_utc = field_validator("observed_end")(_require_utc)
    _acquired_utc = field_validator("acquired_at")(_require_utc)


class BatchManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["batch_bundle_manifest"] = "batch_bundle_manifest"
    core: BatchManifestCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    chain_hash: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class CheckResult(StrictModel):
    name: str
    passed: bool
    detail: str


class AdmissionDecision(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["batch_admission_decision"] = "batch_admission_decision"
    decision_id: str
    batch_id: str
    status: Literal["accepted", "quarantined"]
    manifest_digest: str = Field(pattern=HEX_256_PATTERN)
    content_digest: str = Field(pattern=HEX_256_PATTERN)
    policy_id: str
    policy_version: str
    decided_at: str
    checks: list[CheckResult]

    _decided_utc = field_validator("decided_at")(_require_utc)


class ReceiptCore(StrictModel):
    receipt_id: str
    batch_id: str
    chain_hash: str = Field(pattern=HEX_256_PATTERN)
    decision_id: str
    admission_status: Literal["accepted", "quarantined"]
    repository_id: str
    received_at: str
    policy_id: str
    policy_version: str

    _received_utc = field_validator("received_at")(_require_utc)


class SignedReceipt(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["repository_receipt"] = "repository_receipt"
    core: ReceiptCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class IdentityRecord(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    client_id: str
    node_id: str
    evidence_key_id: str
    evidence_public_key_pem: str
    status: Literal["active", "revoked"] = "active"
    valid_from: str
    valid_until: str

    _valid_from_utc = field_validator("valid_from")(_require_utc)
    _valid_until_utc = field_validator("valid_until")(_require_utc)


class SnapshotManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["dataset_snapshot_manifest"] = "dataset_snapshot_manifest"
    snapshot_id: str
    client_id: str
    input_batches: list[DigestRef]
    input_decisions: list[DigestRef]
    source_dataset: str
    source_dataset_version: str
    preprocessing_schema: str
    preprocessing_config_digest: str = Field(pattern=HEX_256_PATTERN)
    code_version: str
    seed: int
    feature_names: list[str]
    class_counts: dict[str, int]
    split_counts: dict[str, int]
    discarded_records: dict[str, int]
    dataset_digest: str = Field(pattern=HEX_256_PATTERN)
    lineage_digest: str = Field(pattern=HEX_256_PATTERN)
    built_at: str

    _built_utc = field_validator("built_at")(_require_utc)


class CustodyEventCore(StrictModel):
    sequence_number: int = Field(ge=0)
    previous_event_hash: str = Field(pattern=HEX_256_PATTERN)
    action: str
    actor: str
    object_refs: list[DigestRef]
    outcome: str
    occurred_at: str
    details: dict[str, Any] = Field(default_factory=dict)

    _occurred_utc = field_validator("occurred_at")(_require_utc)


class CustodyEvent(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["custody_event"] = "custody_event"
    core: CustodyEventCore
    event_hash: str = Field(pattern=HEX_256_PATTERN)

