"""Strict schemas for joint TPM/statistical contribution admission."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .models import StrictModel

IndicatorDirection = Literal["higher", "lower"]
PolicyName = Literal[
    "tpm_only",
    "statistics_only",
    "sequential",
    "gated_composite",
]
DecisionStatus = Literal[
    "accepted",
    "accepted_downweighted",
    "trust_quarantined",
    "statistically_quarantined",
]


class IndicatorReference(StrictModel):
    """Clean calibration reference for one server-visible update indicator."""

    name: str
    direction: IndicatorDirection
    median: float
    mad: float = Field(ge=0.0)
    sample_count: int = Field(gt=0)


class IndicatorContribution(StrictModel):
    """Exact contribution of one indicator to the statistical risk."""

    name: str
    direction: IndicatorDirection
    raw_value: float
    reference_median: float
    reference_mad: float = Field(ge=0.0)
    adverse_deviation: float = Field(ge=0.0)
    robust_z: float = Field(ge=0.0)
    component_risk: float = Field(ge=0.0, le=1.0)
    normalized_weight: float = Field(gt=0.0, le=1.0)
    weighted_contribution: float = Field(ge=0.0, le=1.0)


class StatisticalSignal(StrictModel):
    """Deterministic statistical risk for one client update."""

    client_id: str
    risk: float = Field(ge=0.0, le=1.0)
    components: list[IndicatorContribution]


class TrustSignal(StrictModel):
    """TPM/M5 trust result kept separate from the statistical signal."""

    raw_status: str
    admissible: bool
    risk: float = Field(ge=0.0, le=1.0)
    evaluated_checks: list[str]
    failed_checks: list[str]
    reasons: list[str]


class PolicyThresholds(StrictModel):
    """Policy thresholds calibrated only from clean reference signals."""

    calibration_method: Literal["clean-reference"] = "clean-reference"
    clean_sample_count: int = Field(gt=0)
    statistical_threshold: float = Field(ge=0.0, le=1.0)
    composite_downweight_threshold: float = Field(ge=0.0, le=1.0)
    composite_threshold: float = Field(ge=0.0, le=1.0)
    trust_weight: float = Field(ge=0.0, le=1.0)


class AdmissionPolicyDecision(StrictModel):
    """One policy outcome over the same immutable trust/statistical signals."""

    policy: PolicyName
    status: DecisionStatus
    contributes: bool
    score: float = Field(ge=0.0, le=1.0)
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    reasons: list[str]


class CompositeAdmissionClientRecord(StrictModel):
    """Signals, decisions, and immutable lineage for one candidate update."""

    client_id: str
    evaluation_label: Literal["normal", "anomalous"]
    source_bundle_id: str
    source_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_update_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_update_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_update_binding: Literal[
        "source-bundle-signed", "controlled-derived-not-resigned"
    ]
    attestation_result_id: str
    attestation_result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trust: TrustSignal
    statistics: StatisticalSignal
    decisions: list[AdmissionPolicyDecision]


class ControlledDisagreementCase(StrictModel):
    """One cell in the controlled trust/statistics disagreement matrix."""

    case_id: str
    source_client_id: str
    condition: Literal[
        "trust_admissible_statistics_normal",
        "trust_admissible_statistics_anomalous",
        "trust_inadmissible_statistics_normal",
        "trust_inadmissible_statistics_anomalous",
    ]
    trust_intervention: Literal["none", "controlled_failed_check"]
    evidence_semantics: Literal[
        "observed verified M4/M5 trust with verified M6 statistics",
        "verified M6 statistics with a controlled counterfactual M4/M5 trust failure",
    ]
    policy_evaluation_only: Literal[True] = True
    security_label: Literal["safe", "unsafe"]
    trust: TrustSignal
    statistics: StatisticalSignal
    decisions: list[AdmissionPolicyDecision]


class ControlledMatrixSelection(StrictModel):
    """Declared source clients and intervention used by the 2x2 matrix."""

    normal_client_id: str
    anomalous_client_id: str
    controlled_failed_check: str


class PolicyEvaluation(StrictModel):
    """Post-decision confusion counts; labels never enter scoring or calibration."""

    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    false_negative: int = Field(ge=0)


class CompositeAdmissionArtifact(StrictModel):
    """Digest-linked pilot over one clean and one candidate M6 population."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_joint_trust_statistical_admission"] = (
        "m6_joint_trust_statistical_admission"
    )
    code_version: str
    experiment_id: str
    campaign_id: str
    round_number: int = Field(gt=0)
    context_id: str
    candidate_attack: str
    attacker_ids: list[str]
    evaluation_labels_used_for_scoring: Literal[False] = False
    candidate_binding_semantics: Literal[
        "controlled M6 derivation from verified M5 identities; attacked candidate bytes "
        "are not covered by the original M5 bundle signatures"
    ]
    source_round_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_round_checkpoint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    clean_frozen_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    clean_comparison_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_frozen_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_comparison_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    partition_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    composite_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byzantine_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    indicator_references: list[IndicatorReference]
    thresholds: PolicyThresholds
    clients: list[CompositeAdmissionClientRecord]
    quadrant_counts: dict[str, int]
    policy_status_counts: dict[str, dict[str, int]]
    policy_evaluation: dict[str, PolicyEvaluation]
    controlled_matrix_selection: ControlledMatrixSelection
    controlled_disagreement_cases: list[ControlledDisagreementCase]
    controlled_policy_evaluation: dict[str, PolicyEvaluation]
