"""Strict models for the live M6 trust/statistics disagreement experiment."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .models import HEX_256_PATTERN, StrictModel

DisagreementCondition = Literal[
    "trust_admissible_statistics_normal",
    "trust_admissible_statistics_anomalous",
    "trust_inadmissible_statistics_normal",
    "trust_inadmissible_statistics_anomalous",
]


class ControlledTrustIntervention(StrictModel):
    type: Literal["controlled_failed_check"] = "controlled_failed_check"
    failed_check: Literal[
        "active_enrollment", "tpm_esk_signature", "fresh_attestation"
    ]
    reason: str


class ControlledUpdateIntervention(StrictModel):
    type: Literal["sign_flip_amplification"] = "sign_flip_amplification"
    scale: float = Field(gt=1.0)
    preserve_clean_update: Literal[True] = True


class DisagreementExperimentContractCore(StrictModel):
    experiment_id: str
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    client_ids: list[str]
    assignments: dict[str, DisagreementCondition]
    background_condition: Literal["trust_admissible_statistics_normal"] = (
        "trust_admissible_statistics_normal"
    )
    active_rounds: Literal["all"] = "all"
    trust_intervention: ControlledTrustIntervention
    update_intervention: ControlledUpdateIntervention
    require_observed_attestation_pass: Literal[True] = True
    evaluation_labels_used_for_scoring: Literal[False] = False
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)


class DisagreementExperimentContract(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_live_disagreement_contract"] = (
        "m6_live_disagreement_contract"
    )
    contract_id: str
    core: DisagreementExperimentContractCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)


class DisagreementSubmissionRecord(StrictModel):
    """Experiment facts embedded in the TPM-signed metrics artifact."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m6_live_disagreement_submission_record"] = (
        "m6_live_disagreement_submission_record"
    )
    experiment_id: str
    contract_id: str
    contract_digest: str = Field(pattern=HEX_256_PATTERN)
    round_number: int = Field(gt=0)
    client_id: str
    condition: DisagreementCondition
    security_label: Literal["safe", "unsafe"]
    controlled_trust_failure: bool
    update_intervention_applied: bool
    update_intervention_type: Literal["none", "sign_flip_amplification"]
    update_intervention_scale: float | None = Field(default=None, gt=1.0)
    clean_update_sha256: str = Field(pattern=HEX_256_PATTERN)
    candidate_update_sha256: str = Field(pattern=HEX_256_PATTERN)
    clean_update_path: Literal["clean-update.json"] | None = None
    observed_attestation_required_to_pass: Literal[True] = True
    evaluation_label_used_for_scoring: Literal[False] = False
