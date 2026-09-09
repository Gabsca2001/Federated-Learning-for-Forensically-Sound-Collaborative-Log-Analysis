"""Strict M8.6 receipt for an in-round disagreement campaign."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .final_preservation_models import (
    VERIFIED_STAGES,
    FinalMerkleStage,
    FinalPreservationStage,
    FinalRecoveryStage,
    FinalTimestampStage,
)
from .in_round_campaign_accounting_models import PolicyOutcomeAccount
from .models import HEX_256_PATTERN, StrictModel

IN_ROUND_FINAL_PROFILE = (
    "offline-recovery-and-in-round-campaign-accounting-final-verification-v2"
)
IN_ROUND_FINAL_ASSURANCE_STATE = (
    "merkle-committed-time-anchored-recovery-exported-"
    "in-round-campaign-accounted-finally-verified"
)


class InRoundFinalCampaignAccountingStage(StrictModel):
    accounting_id: str
    campaign_accounting_sha256: str = Field(pattern=HEX_256_PATTERN)
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    contribution_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
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
    enrollment_count: int = Field(gt=0)
    attestation_count: int = Field(gt=0)
    challenge_count: int = Field(gt=0)
    policy_outcomes: list[PolicyOutcomeAccount]
    accounting_recomputed: Literal[True] = True


class InRoundFinalPreservationCore(StrictModel):
    profile: Literal[
        "offline-recovery-and-in-round-campaign-accounting-final-verification-v2"
    ] = IN_ROUND_FINAL_PROFILE
    preservation: FinalPreservationStage
    merkle: FinalMerkleStage
    timestamp: FinalTimestampStage
    recovery: FinalRecoveryStage
    campaign_accounting: InRoundFinalCampaignAccountingStage
    verified_stages: list[str]
    final_lineage_verified: Literal[True] = True
    assurance_state: Literal[
        "merkle-committed-time-anchored-recovery-exported-"
        "in-round-campaign-accounted-finally-verified"
    ] = IN_ROUND_FINAL_ASSURANCE_STATE

    @model_validator(mode="after")
    def _complete_consistent_chain(self) -> InRoundFinalPreservationCore:
        if self.verified_stages != list(VERIFIED_STAGES):
            raise ValueError("final verification stages are incomplete or unordered")
        preservation = self.preservation
        merkle = self.merkle
        timestamp = self.timestamp
        recovery = self.recovery
        accounting = self.campaign_accounting
        if (
            merkle.source_preservation_id != preservation.preservation_id
            or merkle.source_preservation_manifest_sha256
            != preservation.preservation_manifest_sha256
            or merkle.source_inventory_sha256 != preservation.inventory_sha256
            or recovery.source_preservation_id != preservation.preservation_id
            or recovery.source_inventory_sha256 != preservation.inventory_sha256
            or accounting.source_preservation_id != preservation.preservation_id
        ):
            raise ValueError("final preservation lineage mismatch")
        if (
            timestamp.merkle_tree_id != merkle.tree_id
            or timestamp.merkle_root_sha256 != merkle.root_sha256
            or recovery.source_merkle_tree_id != merkle.tree_id
            or recovery.source_merkle_root_sha256 != merkle.root_sha256
            or accounting.source_merkle_tree_id != merkle.tree_id
            or accounting.source_merkle_root_sha256 != merkle.root_sha256
        ):
            raise ValueError("final Merkle lineage mismatch")
        if (
            recovery.source_timestamp_id != timestamp.timestamp_id
            or recovery.source_timestamp_response_sha256
            != timestamp.timestamp_response_sha256
            or accounting.source_timestamp_id != timestamp.timestamp_id
        ):
            raise ValueError("final timestamp lineage mismatch")
        if (
            accounting.source_recovery_id != recovery.recovery_id
            or accounting.source_package_id != recovery.package_id
            or accounting.source_recovery_archive_sha256 != recovery.archive_sha256
        ):
            raise ValueError("final recovery lineage mismatch")
        if (
            preservation.source_campaign_manifest_sha256
            != accounting.source_campaign_manifest_sha256
            or preservation.selected_derivation_round != accounting.selected_round
            or preservation.selected_checkpoint_sha256
            != accounting.selected_checkpoint_sha256
            or preservation.selected_model_sha256 != accounting.selected_model_sha256
        ):
            raise ValueError("final selected derivation lineage mismatch")
        if (
            preservation.artifact_count != recovery.payload_entry_count
            or preservation.external_evidence_binding_count
            != recovery.external_evidence_binding_count
            or merkle.artifact_leaf_count != preservation.artifact_count
            or merkle.external_evidence_leaf_count
            != preservation.external_evidence_binding_count
            or merkle.leaf_count
            != merkle.artifact_leaf_count + merkle.external_evidence_leaf_count
            or recovery.archived_entry_count
            != recovery.payload_entry_count + recovery.assurance_entry_count + 1
        ):
            raise ValueError("final preservation or recovery counts mismatch")
        if (
            preservation.enrollment_count != accounting.enrollment_count
            or preservation.attestation_count != accounting.attestation_count
            or preservation.challenge_count != accounting.challenge_count
            or accounting.submission_count
            != accounting.round_count * accounting.required_client_count
            or accounting.observed_trust_accepted_count != accounting.submission_count
            or accounting.fully_accepted_count + accounting.downweighted_count
            != accounting.contributing_count
            or accounting.contributing_count + accounting.quarantined_count
            != accounting.submission_count
            or accounting.safe_submission_count + accounting.unsafe_submission_count
            != accounting.submission_count
        ):
            raise ValueError("final in-round campaign or trust counts mismatch")
        return self


class InRoundFinalPreservationReceipt(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    artifact_type: Literal["m8_in_round_final_preservation_verification_receipt"] = (
        "m8_in_round_final_preservation_verification_receipt"
    )
    verification_id: str
    core: InRoundFinalPreservationCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    verifier_implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
