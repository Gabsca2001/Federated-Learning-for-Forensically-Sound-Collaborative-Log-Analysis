"""Strict schemas for M8.5 v2 in-round campaign accounting."""

from __future__ import annotations

from collections import Counter
from decimal import Decimal, InvalidOperation
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .campaign_accounting_models import (
    ADMISSION_CHECK_NAMES,
    CampaignTrustAccounting,
)
from .canonical import digest_object
from .disagreement_experiment_models import DisagreementCondition
from .in_round_admission_models import InRoundDecisionStatus
from .models import HEX_256_PATTERN, StrictModel, _require_utc

IN_ROUND_ACCOUNTING_PROFILE = (
    "recovery-tar-offline-in-round-disagreement-accounting-v2"
)
IN_ROUND_ACCOUNTING_STATE = (
    "merkle-committed-time-anchored-recovery-exported-"
    "in-round-campaign-accounted-not-finally-verified"
)
POLICY_NAMES = ("tpm_only", "statistics_only", "sequential", "gated_composite")
CONTRIBUTING_STATUSES = ("accepted", "accepted_downweighted")


def _decimal(value: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("invalid effective-weight decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("effective weight must be finite and non-negative")
    return parsed


class InRoundContributionAccount(StrictModel):
    round_number: int = Field(gt=0)
    client_id: str
    node_id: str
    enrollment_id: str
    attestation_result_id: str
    attestation_result_sha256: str = Field(pattern=HEX_256_PATTERN)
    challenge_id: str
    context_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    bundle_id: str
    bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    trust_decision_id: str
    trust_decision_sha256: str = Field(pattern=HEX_256_PATTERN)
    in_round_decision_id: str
    in_round_decision_sha256: str = Field(pattern=HEX_256_PATTERN)
    snapshot_sha256: str = Field(pattern=HEX_256_PATTERN)
    snapshot_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    update_sha256: str = Field(pattern=HEX_256_PATTERN)
    metrics_sha256: str = Field(pattern=HEX_256_PATTERN)
    tensor_schema_sha256: str = Field(pattern=HEX_256_PATTERN)
    num_examples: int = Field(gt=0)
    effective_weight_decimal: str
    generated_at: str
    trust_decided_at: str
    in_round_decided_at: str
    observed_admission_checks: list[str]
    observed_all_checks_passed: Literal[True] = True
    primary_policy: Literal["gated_composite"] = "gated_composite"
    final_status: InRoundDecisionStatus
    contributes: bool
    downweighted: bool
    policy_statuses: dict[str, InRoundDecisionStatus]
    disagreement_condition: DisagreementCondition
    controlled_assignment: bool
    security_label: Literal["safe", "unsafe"]
    controlled_trust_failure: bool
    update_intervention_applied: bool
    clean_update_sha256: str = Field(pattern=HEX_256_PATTERN)
    candidate_update_sha256: str = Field(pattern=HEX_256_PATTERN)
    intervention_recomputed: Literal[True] = True

    _generated_utc = field_validator("generated_at")(_require_utc)
    _trust_decided_utc = field_validator("trust_decided_at")(_require_utc)
    _in_round_decided_utc = field_validator("in_round_decided_at")(_require_utc)

    @field_validator("observed_admission_checks")
    @classmethod
    def _exact_checks(cls, value: list[str]) -> list[str]:
        if value != list(ADMISSION_CHECK_NAMES):
            raise ValueError("observed M5 admission checks are incomplete or unordered")
        return value

    @model_validator(mode="after")
    def _treatment_consistent(self) -> InRoundContributionAccount:
        if set(self.policy_statuses) != set(POLICY_NAMES):
            raise ValueError("in-round policy status set is incomplete")
        contributing = self.final_status in CONTRIBUTING_STATUSES
        if (
            self.policy_statuses["gated_composite"] != self.final_status
            or self.contributes != contributing
            or self.downweighted != (self.final_status == "accepted_downweighted")
        ):
            raise ValueError("primary policy treatment is inconsistent")
        weight = _decimal(self.effective_weight_decimal)
        if (contributing and weight <= 0) or (not contributing and weight != 0):
            raise ValueError("effective weight differs from the final treatment")
        if self.update_sha256 != self.candidate_update_sha256:
            raise ValueError("signed update differs from the accounted candidate update")
        expected_condition = (
            "trust_inadmissible" if self.controlled_trust_failure else "trust_admissible"
        ) + (
            "_statistics_anomalous"
            if self.update_intervention_applied
            else "_statistics_normal"
        )
        if (
            self.disagreement_condition != expected_condition
            or self.security_label
            != (
                "unsafe"
                if self.controlled_trust_failure or self.update_intervention_applied
                else "safe"
            )
        ):
            raise ValueError("disagreement treatment and security label are inconsistent")
        if not self.controlled_assignment and (
            self.disagreement_condition
            != "trust_admissible_statistics_normal"
            or self.security_label != "safe"
        ):
            raise ValueError("background contribution contains a controlled treatment")
        return self


class InRoundRoundAccount(StrictModel):
    round_number: int = Field(gt=0)
    context_id: str
    context_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_id: str
    checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    previous_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    global_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    required_client_count: int = Field(gt=0)
    submitted_count: int = Field(gt=0)
    observed_trust_accepted_count: int = Field(gt=0)
    fully_accepted_count: int = Field(ge=0)
    downweighted_count: int = Field(ge=0)
    contributing_count: int = Field(gt=0)
    quarantined_count: int = Field(ge=0)
    missing_count: Literal[0] = 0
    submitted_example_count: int = Field(gt=0)
    contributing_example_count: int = Field(gt=0)
    total_effective_weight_decimal: str
    unique_attestation_count: int = Field(gt=0)
    contribution_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_chain_valid: Literal[True] = True

    @model_validator(mode="after")
    def _counts_consistent(self) -> InRoundRoundAccount:
        if (
            self.observed_trust_accepted_count != self.submitted_count
            or self.fully_accepted_count + self.downweighted_count
            != self.contributing_count
            or self.contributing_count + self.quarantined_count
            != self.submitted_count
            or _decimal(self.total_effective_weight_decimal) <= 0
        ):
            raise ValueError("in-round round counts are inconsistent")
        return self


class InRoundClientAccount(StrictModel):
    client_id: str
    node_id: str
    enrollment_id: str
    contracted_round_count: int = Field(gt=0)
    submitted_count: int = Field(gt=0)
    observed_trust_accepted_count: int = Field(gt=0)
    fully_accepted_count: int = Field(ge=0)
    downweighted_count: int = Field(ge=0)
    contributing_count: int = Field(ge=0)
    quarantined_count: int = Field(ge=0)
    submitted_example_count: int = Field(gt=0)
    contributing_example_count: int = Field(ge=0)
    attestation_result_ids: list[str]
    challenge_ids: list[str]
    attestation_count: int = Field(gt=0)
    challenge_count: int = Field(gt=0)

    @model_validator(mode="after")
    def _client_counts_consistent(self) -> InRoundClientAccount:
        if (
            self.submitted_count != self.contracted_round_count
            or self.observed_trust_accepted_count != self.submitted_count
            or self.fully_accepted_count + self.downweighted_count
            != self.contributing_count
            or self.contributing_count + self.quarantined_count
            != self.submitted_count
            or self.attestation_result_ids
            != sorted(set(self.attestation_result_ids))
            or self.challenge_ids != sorted(set(self.challenge_ids))
            or self.attestation_count != len(self.attestation_result_ids)
            or self.challenge_count != len(self.challenge_ids)
        ):
            raise ValueError("in-round client account is inconsistent")
        return self


class PolicyOutcomeAccount(StrictModel):
    policy: Literal["tpm_only", "statistics_only", "sequential", "gated_composite"]
    accepted_count: int = Field(ge=0)
    downweighted_count: int = Field(ge=0)
    quarantined_count: int = Field(ge=0)
    controlled_true_positive: int = Field(ge=0)
    controlled_false_positive: int = Field(ge=0)
    controlled_true_negative: int = Field(ge=0)
    controlled_false_negative: int = Field(ge=0)


class InRoundCampaignAccountingCore(StrictModel):
    source_profile: Literal[
        "recovery-tar-offline-in-round-disagreement-accounting-v2"
    ] = IN_ROUND_ACCOUNTING_PROFILE
    source_recovery_id: str
    source_package_id: str
    source_recovery_archive_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_preservation_id: str
    source_merkle_tree_id: str
    source_merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_timestamp_id: str
    source_campaign_id: str
    source_campaign_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_disagreement_experiment_id: str
    source_disagreement_contract_id: str
    source_disagreement_contract_sha256: str = Field(pattern=HEX_256_PATTERN)
    selected_round: int = Field(gt=0)
    selected_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    selected_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    round_count: int = Field(gt=0)
    required_client_count: int = Field(gt=0)
    submission_count: int = Field(gt=0)
    observed_trust_accepted_count: int = Field(gt=0)
    fully_accepted_count: int = Field(ge=0)
    downweighted_count: int = Field(ge=0)
    contributing_count: int = Field(gt=0)
    quarantined_count: int = Field(ge=0)
    missing_count: Literal[0] = 0
    safe_submission_count: int = Field(gt=0)
    unsafe_submission_count: int = Field(gt=0)
    safe_quarantined_count: int = Field(ge=0)
    unsafe_quarantined_count: int = Field(ge=0)
    controlled_trust_failure_count: int = Field(gt=0)
    controlled_update_intervention_count: int = Field(gt=0)
    submitted_example_count: int = Field(gt=0)
    contributing_example_count: int = Field(gt=0)
    observed_admission_check_names: list[str]
    observed_admission_check_count: int = Field(gt=0)
    passed_observed_admission_check_count: int = Field(gt=0)
    unique_bundle_count: int = Field(gt=0)
    unique_trust_decision_count: int = Field(gt=0)
    unique_in_round_decision_count: int = Field(gt=0)
    unique_update_count: int = Field(gt=0)
    contribution_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    trust_accounting: CampaignTrustAccounting
    policy_outcomes: list[PolicyOutcomeAccount]
    rounds: list[InRoundRoundAccount]
    clients: list[InRoundClientAccount]
    contributions: list[InRoundContributionAccount]
    assurance_state: Literal[
        "merkle-committed-time-anchored-recovery-exported-"
        "in-round-campaign-accounted-not-finally-verified"
    ] = IN_ROUND_ACCOUNTING_STATE

    @field_validator("observed_admission_check_names")
    @classmethod
    def _check_profile(cls, value: list[str]) -> list[str]:
        if value != list(ADMISSION_CHECK_NAMES):
            raise ValueError("observed admission-check profile mismatch")
        return value

    @model_validator(mode="after")
    def _accounting_matches_ledger(self) -> InRoundCampaignAccountingCore:
        client_ids = [item.client_id for item in self.clients]
        expected_keys = [
            (round_number, client_id)
            for round_number in range(1, self.round_count + 1)
            for client_id in client_ids
        ]
        if (
            [item.round_number for item in self.rounds]
            != list(range(1, self.round_count + 1))
            or client_ids != sorted(client_ids)
            or len(client_ids) != self.required_client_count
            or [(item.round_number, item.client_id) for item in self.contributions]
            != expected_keys
        ):
            raise ValueError("in-round accounting ledger is incomplete or unordered")
        status_counts = Counter(item.final_status for item in self.contributions)
        safe = [item for item in self.contributions if item.security_label == "safe"]
        unsafe = [item for item in self.contributions if item.security_label == "unsafe"]
        contributing = [item for item in self.contributions if item.contributes]
        if (
            self.submission_count != len(self.contributions)
            or self.observed_trust_accepted_count != self.submission_count
            or self.fully_accepted_count != status_counts["accepted"]
            or self.downweighted_count != status_counts["accepted_downweighted"]
            or self.contributing_count != len(contributing)
            or self.quarantined_count
            != self.submission_count - self.contributing_count
            or self.fully_accepted_count + self.downweighted_count
            != self.contributing_count
            or self.safe_submission_count != len(safe)
            or self.unsafe_submission_count != len(unsafe)
            or self.safe_quarantined_count
            != sum(not item.contributes for item in safe)
            or self.unsafe_quarantined_count
            != sum(not item.contributes for item in unsafe)
            or self.controlled_trust_failure_count
            != sum(item.controlled_trust_failure for item in self.contributions)
            or self.controlled_update_intervention_count
            != sum(item.update_intervention_applied for item in self.contributions)
            or self.submitted_example_count
            != sum(item.num_examples for item in self.contributions)
            or self.contributing_example_count
            != sum(item.num_examples for item in contributing)
        ):
            raise ValueError("in-round campaign totals do not match the ledger")
        check_count = self.submission_count * len(ADMISSION_CHECK_NAMES)
        if (
            self.observed_admission_check_count != check_count
            or self.passed_observed_admission_check_count != check_count
            or self.contribution_inventory_sha256
            != digest_object(
                [item.model_dump(mode="json") for item in self.contributions]
            )
        ):
            raise ValueError("in-round check or inventory totals do not match")
        if (
            self.unique_bundle_count
            != len({item.bundle_id for item in self.contributions})
            or self.unique_trust_decision_count
            != len({item.trust_decision_id for item in self.contributions})
            or self.unique_in_round_decision_count
            != len({item.in_round_decision_id for item in self.contributions})
            or self.unique_update_count
            != len({item.update_sha256 for item in self.contributions})
            or min(
                self.unique_bundle_count,
                self.unique_trust_decision_count,
                self.unique_in_round_decision_count,
                self.unique_update_count,
            )
            != self.submission_count
        ):
            raise ValueError("in-round contribution identities are not unique")
        if [item.policy for item in self.policy_outcomes] != list(POLICY_NAMES):
            raise ValueError("policy accounting is incomplete or unordered")
        controlled = [item for item in self.contributions if item.controlled_assignment]
        controlled_client_ids = {item.client_id for item in controlled}
        if (
            len(controlled_client_ids) != 4
            or len(controlled) != 4 * self.round_count
        ):
            raise ValueError("controlled 2x2 assignment matrix is incomplete")
        for outcome in self.policy_outcomes:
            statuses = Counter(
                item.policy_statuses[outcome.policy] for item in self.contributions
            )
            confusion = Counter()
            for contribution in controlled:
                unsafe = contribution.security_label == "unsafe"
                quarantined = (
                    contribution.policy_statuses[outcome.policy]
                    not in CONTRIBUTING_STATUSES
                )
                label = (
                    "true_positive"
                    if unsafe and quarantined
                    else "false_positive"
                    if not unsafe and quarantined
                    else "true_negative"
                    if not unsafe
                    else "false_negative"
                )
                confusion[label] += 1
            if (
                outcome.accepted_count != statuses["accepted"]
                or outcome.downweighted_count != statuses["accepted_downweighted"]
                or outcome.quarantined_count
                != self.submission_count
                - statuses["accepted"]
                - statuses["accepted_downweighted"]
                or outcome.controlled_true_positive != confusion["true_positive"]
                or outcome.controlled_false_positive != confusion["false_positive"]
                or outcome.controlled_true_negative != confusion["true_negative"]
                or outcome.controlled_false_negative != confusion["false_negative"]
            ):
                raise ValueError("policy outcome differs from the contribution ledger")
        for round_account in self.rounds:
            items = [
                item
                for item in self.contributions
                if item.round_number == round_account.round_number
            ]
            contributing_items = [item for item in items if item.contributes]
            if (
                round_account.submitted_count != len(items)
                or round_account.fully_accepted_count
                != sum(item.final_status == "accepted" for item in items)
                or round_account.downweighted_count
                != sum(item.downweighted for item in items)
                or round_account.contributing_count != len(contributing_items)
                or round_account.quarantined_count
                != sum(not item.contributes for item in items)
                or round_account.submitted_example_count
                != sum(item.num_examples for item in items)
                or round_account.contributing_example_count
                != sum(item.num_examples for item in contributing_items)
                or round_account.contribution_inventory_sha256
                != digest_object([item.model_dump(mode="json") for item in items])
            ):
                raise ValueError("round account differs from its contribution ledger")
        for client_account in self.clients:
            items = [
                item
                for item in self.contributions
                if item.client_id == client_account.client_id
            ]
            contributing_items = [item for item in items if item.contributes]
            if (
                client_account.submitted_count != len(items)
                or client_account.fully_accepted_count
                != sum(item.final_status == "accepted" for item in items)
                or client_account.downweighted_count
                != sum(item.downweighted for item in items)
                or client_account.contributing_count != len(contributing_items)
                or client_account.quarantined_count
                != sum(not item.contributes for item in items)
                or client_account.submitted_example_count
                != sum(item.num_examples for item in items)
                or client_account.contributing_example_count
                != sum(item.num_examples for item in contributing_items)
                or client_account.attestation_result_ids
                != sorted({item.attestation_result_id for item in items})
                or client_account.challenge_ids
                != sorted({item.challenge_id for item in items})
            ):
                raise ValueError("client account differs from its contribution ledger")
        trust = self.trust_accounting
        if (
            trust.enrollment_count != self.required_client_count
            or trust.attestation_usage_count != self.submission_count
            or trust.verified_bundle_signature_count != self.submission_count
            or trust.verified_coordinator_signature_count
            != 1 + (2 * self.round_count) + (2 * self.submission_count)
        ):
            raise ValueError("in-round trust totals do not match the ledger")
        return self


class InRoundCampaignAccountingReport(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    artifact_type: Literal["m8_in_round_campaign_invariant_accounting"] = (
        "m8_in_round_campaign_invariant_accounting"
    )
    accounting_id: str
    core: InRoundCampaignAccountingCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)


class InRoundCampaignAccountingEnvelope(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    artifact_type: Literal["m8_in_round_campaign_invariant_accounting_envelope"] = (
        "m8_in_round_campaign_invariant_accounting_envelope"
    )
    accounting_id: str
    campaign_accounting_sha256: str = Field(pattern=HEX_256_PATTERN)
    contribution_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_recovery_id: str
    source_recovery_archive_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    assurance_state: Literal[
        "merkle-committed-time-anchored-recovery-exported-"
        "in-round-campaign-accounted-not-finally-verified"
    ] = IN_ROUND_ACCOUNTING_STATE
