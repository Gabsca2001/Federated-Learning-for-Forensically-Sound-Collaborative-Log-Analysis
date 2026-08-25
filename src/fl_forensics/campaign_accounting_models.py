"""Strict schemas for M8.5 offline campaign invariant accounting."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from .canonical import digest_object
from .models import HEX_256_PATTERN, StrictModel, _require_utc

ACCOUNTING_STATE = (
    "merkle-committed-time-anchored-recovery-exported-"
    "campaign-accounted-not-finally-verified"
)
ADMISSION_CHECK_NAMES = (
    "round_context_binding",
    "client_contract_binding",
    "active_enrollment",
    "tpm_esk_signature",
    "fresh_attestation",
    "artifact_digests",
    "tensor_structure",
)


class CampaignContributionAccount(StrictModel):
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
    decision_id: str
    decision_sha256: str = Field(pattern=HEX_256_PATTERN)
    snapshot_sha256: str = Field(pattern=HEX_256_PATTERN)
    snapshot_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    update_sha256: str = Field(pattern=HEX_256_PATTERN)
    metrics_sha256: str = Field(pattern=HEX_256_PATTERN)
    tensor_schema_sha256: str = Field(pattern=HEX_256_PATTERN)
    num_examples: int = Field(gt=0)
    generated_at: str
    decided_at: str
    admission_checks: list[str]
    all_checks_passed: Literal[True] = True

    _generated_utc = field_validator("generated_at")(_require_utc)
    _decided_utc = field_validator("decided_at")(_require_utc)

    @field_validator("admission_checks")
    @classmethod
    def _exact_checks(cls, value: list[str]) -> list[str]:
        if value != list(ADMISSION_CHECK_NAMES):
            raise ValueError("contribution admission checks are incomplete or unordered")
        return value


class CampaignRoundAccount(StrictModel):
    round_number: int = Field(gt=0)
    context_id: str
    context_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_id: str
    checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    previous_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    global_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    required_client_count: int = Field(gt=0)
    contribution_count: int = Field(gt=0)
    accepted_count: int = Field(gt=0)
    quarantined_count: Literal[0] = 0
    missing_count: Literal[0] = 0
    total_examples: int = Field(gt=0)
    passed_check_count: int = Field(gt=0)
    unique_attestation_count: int = Field(gt=0)
    contribution_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_chain_valid: Literal[True] = True


class CampaignClientAccount(StrictModel):
    client_id: str
    node_id: str
    enrollment_id: str
    contracted_round_count: int = Field(gt=0)
    submitted_count: int = Field(gt=0)
    accepted_count: int = Field(gt=0)
    quarantined_count: Literal[0] = 0
    total_examples: int = Field(gt=0)
    attestation_result_ids: list[str]
    challenge_ids: list[str]
    attestation_count: int = Field(gt=0)
    challenge_count: int = Field(gt=0)

    @model_validator(mode="after")
    def _identity_sets_match(self) -> CampaignClientAccount:
        if (
            self.attestation_result_ids != sorted(set(self.attestation_result_ids))
            or self.challenge_ids != sorted(set(self.challenge_ids))
            or self.attestation_count != len(self.attestation_result_ids)
            or self.challenge_count != len(self.challenge_ids)
        ):
            raise ValueError("client trust identities are not unique, ordered, and counted")
        return self


class CampaignTrustAccounting(StrictModel):
    enrollment_count: int = Field(gt=0)
    attestation_count: int = Field(gt=0)
    challenge_count: int = Field(gt=0)
    attestation_usage_count: int = Field(gt=0)
    attestations_per_client: int = Field(gt=0)
    rounds_per_attestation: int = Field(gt=0)
    verified_enrollment_signature_count: int = Field(gt=0)
    verified_attestation_signature_count: int = Field(gt=0)
    verified_challenge_signature_count: int = Field(gt=0)
    verified_bundle_signature_count: int = Field(gt=0)
    verified_coordinator_signature_count: int = Field(gt=0)
    trust_binding_valid: Literal[True] = True


class CampaignAccountingCore(StrictModel):
    source_profile: Literal["recovery-tar-offline-campaign-accounting-v1"] = (
        "recovery-tar-offline-campaign-accounting-v1"
    )
    source_recovery_id: str
    source_package_id: str
    source_recovery_archive_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_preservation_id: str
    source_merkle_tree_id: str
    source_merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_timestamp_id: str
    source_campaign_id: str
    source_campaign_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    selected_round: int = Field(gt=0)
    selected_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    selected_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    round_count: int = Field(gt=0)
    required_client_count: int = Field(gt=0)
    contribution_count: int = Field(gt=0)
    accepted_contribution_count: int = Field(gt=0)
    quarantined_contribution_count: Literal[0] = 0
    missing_contribution_count: Literal[0] = 0
    total_example_count: int = Field(gt=0)
    admission_check_names: list[str]
    admission_check_count: int = Field(gt=0)
    passed_admission_check_count: int = Field(gt=0)
    failed_admission_check_count: Literal[0] = 0
    unique_bundle_count: int = Field(gt=0)
    unique_decision_count: int = Field(gt=0)
    unique_update_count: int = Field(gt=0)
    contribution_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    trust_accounting: CampaignTrustAccounting
    rounds: list[CampaignRoundAccount]
    clients: list[CampaignClientAccount]
    contributions: list[CampaignContributionAccount]
    assurance_state: Literal[
        "merkle-committed-time-anchored-recovery-exported-"
        "campaign-accounted-not-finally-verified"
    ] = ACCOUNTING_STATE

    @field_validator("admission_check_names")
    @classmethod
    def _check_profile(cls, value: list[str]) -> list[str]:
        if value != list(ADMISSION_CHECK_NAMES):
            raise ValueError("campaign admission-check profile mismatch")
        return value

    @model_validator(mode="after")
    def _accounting_matches_ledger(self) -> CampaignAccountingCore:
        if [item.round_number for item in self.rounds] != list(
            range(1, self.round_count + 1)
        ):
            raise ValueError("campaign round accounts are incomplete or unordered")
        client_ids = [item.client_id for item in self.clients]
        if client_ids != sorted(client_ids) or len(client_ids) != self.required_client_count:
            raise ValueError("campaign client accounts are incomplete or unordered")
        expected_keys = [
            (round_number, client_id)
            for round_number in range(1, self.round_count + 1)
            for client_id in client_ids
        ]
        observed_keys = [
            (item.round_number, item.client_id) for item in self.contributions
        ]
        if observed_keys != expected_keys:
            raise ValueError("campaign contribution ledger is incomplete or unordered")
        if (
            self.contribution_count != len(self.contributions)
            or self.accepted_contribution_count != self.contribution_count
            or self.total_example_count
            != sum(item.num_examples for item in self.contributions)
        ):
            raise ValueError("campaign contribution totals do not match the ledger")
        expected_check_count = self.contribution_count * len(ADMISSION_CHECK_NAMES)
        if (
            self.admission_check_count != expected_check_count
            or self.passed_admission_check_count != expected_check_count
        ):
            raise ValueError("campaign admission-check totals do not match the ledger")
        if self.contribution_inventory_sha256 != digest_object(
            [item.model_dump(mode="json") for item in self.contributions]
        ):
            raise ValueError("campaign contribution inventory digest mismatch")
        unique_bundle_count = len({item.bundle_id for item in self.contributions})
        unique_decision_count = len({item.decision_id for item in self.contributions})
        unique_update_count = len({item.update_sha256 for item in self.contributions})
        if (
            self.unique_bundle_count != unique_bundle_count
            or self.unique_decision_count != unique_decision_count
            or unique_bundle_count != self.contribution_count
            or unique_decision_count != self.contribution_count
        ):
            raise ValueError("campaign bundle or decision uniqueness mismatch")
        if (
            self.unique_update_count != unique_update_count
            or unique_update_count != self.contribution_count
        ):
            raise ValueError("campaign update uniqueness mismatch")
        enrollment_ids = {item.enrollment_id for item in self.contributions}
        attestation_ids = {item.attestation_result_id for item in self.contributions}
        challenge_ids = {item.challenge_id for item in self.contributions}
        trust = self.trust_accounting
        if (
            trust.enrollment_count != len(enrollment_ids)
            or trust.enrollment_count != self.required_client_count
            or trust.attestation_count != len(attestation_ids)
            or trust.challenge_count != len(challenge_ids)
            or trust.challenge_count != trust.attestation_count
            or trust.attestation_usage_count != self.contribution_count
            or trust.attestations_per_client * self.required_client_count
            != trust.attestation_count
            or trust.rounds_per_attestation * trust.attestation_count
            != self.contribution_count
            or trust.verified_enrollment_signature_count != trust.enrollment_count
            or trust.verified_attestation_signature_count != trust.attestation_count
            or trust.verified_challenge_signature_count != trust.challenge_count
            or trust.verified_bundle_signature_count != self.contribution_count
            or trust.verified_coordinator_signature_count
            != 1 + (2 * self.round_count) + self.contribution_count
        ):
            raise ValueError("campaign trust totals do not match the ledger")
        for round_account in self.rounds:
            items = [
                item
                for item in self.contributions
                if item.round_number == round_account.round_number
            ]
            if (
                round_account.required_client_count != self.required_client_count
                or round_account.contribution_count != len(items)
                or round_account.accepted_count != len(items)
                or round_account.total_examples
                != sum(item.num_examples for item in items)
                or round_account.passed_check_count
                != len(items) * len(ADMISSION_CHECK_NAMES)
                or round_account.unique_attestation_count
                != len({item.attestation_result_id for item in items})
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
            if (
                client_account.contracted_round_count != self.round_count
                or client_account.submitted_count != len(items)
                or client_account.accepted_count != len(items)
                or client_account.total_examples
                != sum(item.num_examples for item in items)
                or client_account.attestation_result_ids
                != sorted({item.attestation_result_id for item in items})
                or client_account.challenge_ids
                != sorted({item.challenge_id for item in items})
            ):
                raise ValueError("client account differs from its contribution ledger")
        return self


class CampaignAccountingReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_campaign_invariant_accounting"] = (
        "m8_campaign_invariant_accounting"
    )
    accounting_id: str
    core: CampaignAccountingCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)


class CampaignAccountingEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_campaign_invariant_accounting_envelope"] = (
        "m8_campaign_invariant_accounting_envelope"
    )
    accounting_id: str
    campaign_accounting_sha256: str = Field(pattern=HEX_256_PATTERN)
    contribution_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_recovery_id: str
    source_recovery_archive_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    assurance_state: Literal[
        "merkle-committed-time-anchored-recovery-exported-"
        "campaign-accounted-not-finally-verified"
    ] = ACCOUNTING_STATE
