"""Strict schemas for explanations of live M6 contribution decisions."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .composite_admission_models import IndicatorContribution, TrustSignal
from .contribution_explanation_models import TensorDeviationDriver
from .in_round_admission_models import InRoundDecisionStatus
from .models import HEX_256_PATTERN, StrictModel
from .secure_round_models import SecureCheck


class LivePolicyDecisionExplanation(StrictModel):
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


class LiveAggregationTreatment(StrictModel):
    nominal_weight_decimal: str
    effective_weight_decimal: str
    retained_weight_fraction: float = Field(ge=0.0, le=1.0)
    included_in_checkpoint: bool
    update_l2: float = Field(ge=0.0)
    cosine_to_effective_aggregate: float = Field(ge=-1.0, le=1.0)
    admitted_aggregate_influence_l2: float = Field(ge=0.0)
    full_weight_counterfactual_aggregate_shift_l2: float = Field(ge=0.0)


class LiveDecisionCounterfactual(StrictModel):
    trust_remediation_required: bool
    composite_reduction_for_nonzero_weight: float | None = Field(default=None, ge=0.0)
    composite_reduction_for_full_weight: float | None = Field(default=None, ge=0.0)
    statistical_reduction_for_nonzero_weight: float | None = Field(default=None, ge=0.0)
    statistical_reduction_for_full_weight: float | None = Field(default=None, ge=0.0)
    fixed_context: list[str]
    interpretation: str


class LiveContributionDecisionExplanation(StrictModel):
    round_number: int = Field(gt=0)
    client_id: str
    source_decision_id: str
    source_decision_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_bundle_id: str
    source_bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_update_sha256: str = Field(pattern=HEX_256_PATTERN)
    final_status: InRoundDecisionStatus
    m5_checks: list[SecureCheck]
    trust: TrustSignal
    statistical_risk: float | None = Field(default=None, ge=0.0, le=1.0)
    statistical_quarantine_threshold: float = Field(ge=0.0, le=1.0)
    composite_score: float | None = Field(default=None, ge=0.0, le=1.0)
    composite_downweight_threshold: float = Field(ge=0.0, le=1.0)
    composite_quarantine_threshold: float = Field(ge=0.0, le=1.0)
    signed_headroom_to_quarantine: float | None = None
    signed_headroom_to_full_acceptance: float | None = None
    policy_explanations: list[LivePolicyDecisionExplanation]
    ranked_statistical_components: list[IndicatorContribution]
    top_tensor_drivers: list[TensorDeviationDriver]
    statistical_risk_rank_in_round: int | None = Field(default=None, gt=0)
    peer_count: int = Field(gt=0)
    prior_downweight_count: int = Field(ge=0)
    prior_quarantine_count: int = Field(ge=0)
    aggregation_treatment: LiveAggregationTreatment
    counterfactual: LiveDecisionCounterfactual
    validation_base_minus_client_macro_f1: float | None = None
    test_data_used_for_explanation: Literal[False] = False
    attack_labels_used_for_explanation: Literal[False] = False
    narrative: list[str]


class LiveContributionExplanationsPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_live_contribution_decision_explanations"] = (
        "m6_live_contribution_decision_explanations"
    )
    explanations: list[LiveContributionDecisionExplanation]

    @model_validator(mode="after")
    def _canonical_slots(self) -> LiveContributionExplanationsPayload:
        slots = [(item.round_number, item.client_id) for item in self.explanations]
        if slots != sorted(slots) or len(slots) != len(set(slots)):
            raise ValueError("live explanation slots are not unique and canonical")
        return self


class LiveRoundExplanationIndex(StrictModel):
    round_number: int = Field(gt=0)
    explanation_count: int = Field(gt=0)
    accepted_count: int = Field(ge=0)
    downweighted_count: int = Field(ge=0)
    trust_quarantined_count: int = Field(ge=0)
    statistically_quarantined_count: int = Field(ge=0)
    mean_statistical_risk: float = Field(ge=0.0, le=1.0)
    maximum_statistical_risk: float = Field(ge=0.0, le=1.0)


class LiveClientExplanationIndex(StrictModel):
    client_id: str
    explanation_count: int = Field(gt=0)
    accepted_count: int = Field(ge=0)
    downweighted_count: int = Field(ge=0)
    trust_quarantined_count: int = Field(ge=0)
    statistically_quarantined_count: int = Field(ge=0)
    mean_statistical_risk: float = Field(ge=0.0, le=1.0)
    maximum_statistical_risk: float = Field(ge=0.0, le=1.0)


class LiveContributionExplanationIndex(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_live_contribution_explanation_index"] = (
        "m6_live_contribution_explanation_index"
    )
    rounds: list[LiveRoundExplanationIndex]
    clients: list[LiveClientExplanationIndex]


class LiveContributionExplanationSource(StrictModel):
    experiment_id: str
    campaign_id: str
    round_count: int = Field(gt=0)
    client_count: int = Field(gt=0)
    campaign_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    selected_evaluation_sha256: str = Field(pattern=HEX_256_PATTERN)
    partition_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    server_evaluation_sha256: str = Field(pattern=HEX_256_PATTERN)
    decision_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    update_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    disagreement_contract_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)


class LiveContributionExplanationGate(StrictModel):
    source_campaign_verified: Literal[True] = True
    source_disagreement_rounds_verified: Literal[True] = True
    complete_round_client_coverage: Literal[True] = True
    signed_decisions_bound: Literal[True] = True
    update_tensors_recomputed: Literal[True] = True
    aggregation_treatments_recomputed: Literal[True] = True
    test_data_used_for_explanations: Literal[False] = False
    attack_labels_used_for_explanations: Literal[False] = False
    explanation_count: int = Field(gt=0)
    round_count: int = Field(gt=0)
    client_count: int = Field(gt=0)
    accepted_count: int = Field(ge=0)
    downweighted_count: int = Field(ge=0)
    trust_quarantined_count: int = Field(ge=0)
    statistically_quarantined_count: int = Field(ge=0)
    invariant_violation_count: Literal[0] = 0
    reportable: Literal[True] = True


class LiveContributionExplanationCore(StrictModel):
    experiment_id: str
    code_version: str
    implementation_sha256: dict[str, str]
    explanation_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    source: LiveContributionExplanationSource
    explanations_sha256: str = Field(pattern=HEX_256_PATTERN)
    index_sha256: str = Field(pattern=HEX_256_PATTERN)
    gate: LiveContributionExplanationGate


class LiveContributionExplanationManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_live_contribution_explanation_bundle_manifest"] = (
        "m6_live_contribution_explanation_bundle_manifest"
    )
    explanation_bundle_id: str
    core: LiveContributionExplanationCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    interpretation_boundary: Literal[
        "training-decision-mechanism-explanation-not-proof-of-malicious-intent"
    ] = "training-decision-mechanism-explanation-not-proof-of-malicious-intent"
    integrity_assurance: Literal["content-addressed-unanchored"] = (
        "content-addressed-unanchored"
    )

    @model_validator(mode="after")
    def _implementation_digest_set(self) -> LiveContributionExplanationManifest:
        required = {
            "contribution_explanation",
            "disagreement_experiment",
            "in_round_admission",
            "live_contribution_explanation",
            "live_contribution_explanation_models",
        }
        if set(self.core.implementation_sha256) != required:
            raise ValueError("live explanation implementation digest set is incomplete")
        return self
