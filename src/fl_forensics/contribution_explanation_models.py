"""Strict schemas for forensic explanations of contribution decisions."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .composite_admission_models import IndicatorContribution, TrustSignal
from .models import StrictModel

HEX_256_PATTERN = r"^[0-9a-f]{64}$"


class PolicyDecisionExplanation(StrictModel):
    """Threshold-local explanation for one admission policy decision."""

    policy: Literal["tpm_only", "statistics_only", "sequential", "gated_composite"]
    status: Literal[
        "accepted",
        "accepted_downweighted",
        "trust_quarantined",
        "statistically_quarantined",
    ]
    contributes: bool
    score: float = Field(ge=0.0, le=1.0)
    quarantine_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    signed_margin_to_quarantine: float | None = None
    downweight_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    signed_margin_to_downweight: float | None = None
    hard_trust_veto_applied: bool
    reasons: list[str]


class TensorDeviationDriver(StrictModel):
    """Contribution of one named parameter tensor to update deviation."""

    tensor_name: str
    parameter_count: int = Field(gt=0)
    update_l2: float = Field(ge=0.0)
    median_distance_l2: float = Field(ge=0.0)
    squared_median_distance_fraction: float = Field(ge=0.0, le=1.0)
    median_absolute_standardized_deviation: float = Field(ge=0.0)


class ContributionDecisionExplanation(StrictModel):
    """Auditable explanation of one contribution's policy outcome."""

    client_id: str
    candidate_update_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    trust: TrustSignal
    statistical_risk: float = Field(ge=0.0, le=1.0)
    statistical_quarantine_threshold: float = Field(ge=0.0, le=1.0)
    statistical_signed_margin_to_quarantine: float
    primary_policy: Literal["gated_composite"] = "gated_composite"
    primary_status: Literal[
        "accepted",
        "accepted_downweighted",
        "trust_quarantined",
        "statistically_quarantined",
    ]
    ranked_statistical_components: list[IndicatorContribution]
    policy_explanations: list[PolicyDecisionExplanation]
    top_tensor_drivers: list[TensorDeviationDriver]
    attack_labels_used_for_explanation: Literal[False] = False
    summary: str


class AggregationClientTrace(StrictModel):
    """Aggregator-specific treatment of one frozen contribution."""

    client_id: str
    clip_scale: float | None = Field(default=None, gt=0.0, le=1.0)
    fedavg_weight_fraction: float | None = Field(default=None, gt=0.0, le=1.0)
    krum_score: float | None = Field(default=None, ge=0.0)
    krum_rank: int | None = Field(default=None, gt=0)
    selected: bool | None = None
    bulyan_candidate_selected: bool | None = None
    retained_coordinate_count: int | None = Field(default=None, ge=0)
    retained_coordinate_fraction: float | None = Field(default=None, ge=0.0, le=1.0)
    distance_to_aggregate_l2: float | None = Field(default=None, ge=0.0)


class AggregationProfileTrace(StrictModel):
    """Complete deterministic trace for one aggregation mechanism."""

    profile_id: Literal[
        "l2_clipping",
        "fedavg",
        "coordinate_median",
        "trimmed_mean",
        "multikrum",
        "bulyan",
    ]
    decision_semantics: str
    coordinate_count: int = Field(gt=0)
    selected_client_ids: list[str] | None = None
    trace_reproduces_aggregate: Literal[True] = True
    clients: list[AggregationClientTrace]


class ContributionExplanationsPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_contribution_decision_explanations"] = (
        "m6_contribution_decision_explanations"
    )
    explanations: list[ContributionDecisionExplanation]


class AggregationTracesPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_robust_aggregation_decision_traces"] = (
        "m6_robust_aggregation_decision_traces"
    )
    profiles: list[AggregationProfileTrace]


class ContributionExplanationSource(StrictModel):
    experiment_id: str
    campaign_id: str
    round_number: int = Field(gt=0)
    candidate_attack: str
    admission_sha256: str = Field(pattern=HEX_256_PATTERN)
    candidate_frozen_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    candidate_comparison_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_round_context_sha256: str = Field(pattern=HEX_256_PATTERN)
    partition_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)


class ContributionExplanationGate(StrictModel):
    source_admission_verified: Literal[True] = True
    source_m4_m5_m6_transitively_verified: Literal[True] = True
    complete_client_coverage: Literal[True] = True
    aggregation_traces_reproduce_implementation: Literal[True] = True
    attack_labels_used_for_explanations: Literal[False] = False
    primary_evidence: Literal[False] = False
    explanation_count: int = Field(gt=0)
    aggregation_profile_count: int = Field(gt=0)
    invariant_violation_count: Literal[0] = 0
    reportable: Literal[True] = True


class ContributionExplanationCore(StrictModel):
    code_version: str
    implementation_sha256: dict[str, str]
    explanation_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    composite_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    byzantine_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    source: ContributionExplanationSource
    explanations_sha256: str = Field(pattern=HEX_256_PATTERN)
    aggregation_traces_sha256: str = Field(pattern=HEX_256_PATTERN)
    gate: ContributionExplanationGate


class ContributionExplanationManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_contribution_explanation_bundle_manifest"] = (
        "m6_contribution_explanation_bundle_manifest"
    )
    explanation_bundle_id: str
    core: ContributionExplanationCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    interpretation_boundary: Literal[
        "update-policy-interpretation-not-primary-log-evidence-or-proof-of-intent"
    ] = "update-policy-interpretation-not-primary-log-evidence-or-proof-of-intent"
    integrity_assurance: Literal["content-addressed-unanchored"] = (
        "content-addressed-unanchored"
    )

    @model_validator(mode="after")
    def _implementation_digest_set(self) -> ContributionExplanationManifest:
        required = {
            "byzantine",
            "composite_admission",
            "contribution_explanation",
            "contribution_explanation_models",
        }
        if set(self.core.implementation_sha256) != required:
            raise ValueError("contribution explanation implementation digest set is incomplete")
        if any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in self.core.implementation_sha256.values()
        ):
            raise ValueError("invalid contribution explanation implementation digest")
        return self
