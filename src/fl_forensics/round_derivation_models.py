"""Strict, versioned artifacts for a receipt-bound FedAvg derivation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc


class RoundDerivationBindingCore(StrictModel):
    domain: Literal["fl-round-derivation-binding-v1"] = "fl-round-derivation-binding-v1"
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    input_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    receipt_core_digests: list[str]
    blocked_client_ids: list[str]
    intake_policy: Literal["reject_before_scoring_v1"] = "reject_before_scoring_v1"
    evidence_profile: Literal["provided_client_evidence"] = "provided_client_evidence"
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)


class RoundDerivationBinding(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["round_derivation_binding"] = "round_derivation_binding"
    binding_id: str
    core: RoundDerivationBindingCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class RoundScoringStateCore(StrictModel):
    domain: Literal["fl-round-scoring-state-v1"] = "fl-round-scoring-state-v1"
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    admission_contract_sha256: str = Field(pattern=HEX_256_PATTERN)
    validation_split_sha256: str = Field(pattern=HEX_256_PATTERN)
    trust_eligible_client_ids: list[str]
    scored_client_ids: list[str]
    ordered_bundle_sha256: list[str]
    computation_status: Literal["computed", "skipped_insufficient_candidates"]
    disagreement_contract_sha256: str | None = None
    numerical_state: dict[str, Any]


class RoundScoringState(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["round_scoring_state"] = "round_scoring_state"
    scoring_id: str
    core: RoundScoringStateCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class SubmissionFinalDisposition(StrictModel):
    submission_id: str
    client_id: str
    bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    kind: Literal["runtime_admission", "protocol_rejection"]
    intake_outcome: str
    decision_sha256: str | None = None
    trust_decision_sha256: str | None = None
    final_status: str
    mandatory_gate_passed: bool
    participated_in_scoring: bool
    policy_factor_decimal: str
    effective_weight_decimal: str
    alpha_numerator: str | None
    alpha_denominator: str | None
    runtime_weight_hex: str | None
    semantic_state: Literal["not_reviewed"] = "not_reviewed"


class DerivationNode(StrictModel):
    node_id: str
    kind: str
    sha256: str = Field(pattern=HEX_256_PATTERN)
    availability: Literal["available", "commitment_only"] = "available"


class DerivationEdge(StrictModel):
    source: str
    target: str
    kind: Literal["num", "dec", "audit"]


class RoundDerivationManifestCore(StrictModel):
    domain: Literal["fl-round-derivation-v1"] = "fl-round-derivation-v1"
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    input_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    binding_sha256: str = Field(pattern=HEX_256_PATTERN)
    scoring_state_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_sha256: str | None
    round_status: Literal["aggregated", "failed_without_checkpoint"]
    protocol_rejected_client_ids: list[str]
    missing_client_ids: list[str]
    dispositions: list[SubmissionFinalDisposition]
    total_effective_weight_decimal: str
    aggregation_order: list[str]
    backend_profile: dict[str, str]
    nodes: list[DerivationNode]
    edges: list[DerivationEdge]
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    created_at: str

    _created_utc = field_validator("created_at")(_require_utc)


class RoundDerivationManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["round_derivation_manifest"] = "round_derivation_manifest"
    manifest_id: str
    core: RoundDerivationManifestCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock
