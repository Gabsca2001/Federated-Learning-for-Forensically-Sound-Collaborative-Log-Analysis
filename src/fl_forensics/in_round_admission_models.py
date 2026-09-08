"""Strict artifacts for admission enforced inside an attested FL round."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from .composite_admission_models import (
    AdmissionPolicyDecision,
    IndicatorReference,
    PolicyThresholds,
    StatisticalSignal,
    TrustSignal,
)
from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc
from .secure_round_models import SecureCheck


class InRoundAdmissionContractCore(StrictModel):
    policy_id: str
    primary_policy: Literal["gated_composite"] = "gated_composite"
    policy_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    calibration_source_admission_sha256: str = Field(pattern=HEX_256_PATTERN)
    calibration_semantics: Literal["verified-clean-development-reference"] = (
        "verified-clean-development-reference"
    )
    indicator_references: list[IndicatorReference]
    indicator_weights: dict[str, float]
    robust_z_cap: float = Field(gt=0.0)
    passed_with_warning_risk: float = Field(ge=0.0, le=1.0)
    thresholds: PolicyThresholds
    accepted_downweight_factor: float = Field(gt=0.0, lt=1.0)
    minimum_contributors: int = Field(gt=0)
    validation_metric: Literal["macro_f1_all_model_classes"] = (
        "macro_f1_all_model_classes"
    )
    validation_split_sha256: str = Field(pattern=HEX_256_PATTERN)
    validation_row_count: int = Field(gt=0)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)


class InRoundAdmissionContract(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["in_round_admission_contract"] = (
        "in_round_admission_contract"
    )
    contract_id: str
    core: InRoundAdmissionContractCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)


InRoundDecisionStatus = Literal[
    "accepted",
    "accepted_downweighted",
    "trust_quarantined",
    "integrity_quarantined",
    "statistically_quarantined",
]


class InRoundContributionDecisionCore(StrictModel):
    campaign_id: str
    context_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    contract_id: str
    contract_digest: str = Field(pattern=HEX_256_PATTERN)
    round_number: int = Field(gt=0)
    client_id: str
    bundle_id: str
    bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    update_sha256: str | None = Field(default=None, pattern=HEX_256_PATTERN)
    trust_decision_id: str
    trust_decision_sha256: str = Field(pattern=HEX_256_PATTERN)
    m5_checks: list[SecureCheck]
    trust: TrustSignal
    statistics: StatisticalSignal | None
    policy_decisions: list[AdmissionPolicyDecision]
    primary_decision: AdmissionPolicyDecision | None
    final_status: InRoundDecisionStatus
    num_examples: int = Field(ge=0)
    effective_weight_decimal: str
    reasons: list[str]
    decided_at: str

    _decided_utc = field_validator("decided_at")(_require_utc)


class InRoundContributionDecision(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["in_round_contribution_decision"] = (
        "in_round_contribution_decision"
    )
    decision_id: str
    core: InRoundContributionDecisionCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class InRoundCheckpointInput(StrictModel):
    client_id: str
    decision_id: str
    decision_sha256: str = Field(pattern=HEX_256_PATTERN)
    trust_decision_id: str
    trust_decision_sha256: str = Field(pattern=HEX_256_PATTERN)
    bundle_id: str
    bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    update_sha256: str = Field(pattern=HEX_256_PATTERN)
    num_examples: int = Field(gt=0)
    effective_weight_decimal: str
    status: Literal["accepted", "accepted_downweighted"]


class InRoundSecureCheckpointCore(StrictModel):
    campaign_id: str
    context_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    round_number: int = Field(gt=0)
    previous_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    aggregation_strategy: Literal["FedAvg-gated-composite"] = (
        "FedAvg-gated-composite"
    )
    required_client_count: int = Field(gt=0)
    minimum_contributors: int = Field(gt=0)
    evaluated_count: int = Field(ge=0)
    trust_accepted_count: int = Field(ge=0)
    accepted_count: int = Field(ge=0)
    downweighted_count: int = Field(ge=0)
    quarantined_count: int = Field(ge=0)
    missing_client_ids: list[str]
    total_examples: int = Field(ge=0)
    total_effective_weight_decimal: str
    accepted_inputs: list[InRoundCheckpointInput]
    quarantined_decision_sha256: list[str]
    admission_contract_id: str
    admission_contract_sha256: str = Field(pattern=HEX_256_PATTERN)
    policy_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    validation_split_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    global_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    created_at: str

    _created_utc = field_validator("created_at")(_require_utc)


class InRoundSecureCheckpoint(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["in_round_secure_global_checkpoint"] = (
        "in_round_secure_global_checkpoint"
    )
    checkpoint_id: str
    core: InRoundSecureCheckpointCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock
