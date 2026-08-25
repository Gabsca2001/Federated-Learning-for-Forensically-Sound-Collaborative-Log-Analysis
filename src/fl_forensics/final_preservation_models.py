"""Strict schemas for the M8.6 final offline preservation verification."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .models import HEX_256_PATTERN, StrictModel

FINAL_VERIFICATION_PROFILE = (
    "offline-recovery-and-campaign-accounting-final-verification-v1"
)
FINAL_ASSURANCE_STATE = (
    "merkle-committed-time-anchored-recovery-exported-"
    "campaign-accounted-finally-verified"
)
VERIFIED_STAGES = (
    "m8.1-preservation-inventory",
    "m8.2-merkle-commitment",
    "m8.3-trusted-timestamp",
    "m8.4-offline-recovery",
    "m8.5-campaign-accounting",
)


class FinalPreservationStage(StrictModel):
    preservation_id: str
    preservation_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    artifact_count: int = Field(gt=0)
    external_evidence_binding_count: int = Field(ge=0)
    selected_derivation_round: int = Field(gt=0)
    source_campaign_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    selected_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    selected_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    enrollment_count: int = Field(gt=0)
    attestation_count: int = Field(gt=0)
    challenge_count: int = Field(gt=0)
    private_material_absent: Literal[True] = True
    inventory_reconstructed: Literal[True] = True


class FinalMerkleStage(StrictModel):
    tree_id: str
    merkle_tree_sha256: str = Field(pattern=HEX_256_PATTERN)
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_preservation_id: str
    source_preservation_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    root_sha256: str = Field(pattern=HEX_256_PATTERN)
    artifact_leaf_count: int = Field(gt=0)
    external_evidence_leaf_count: int = Field(ge=0)
    leaf_count: int = Field(gt=0)
    commitment_recomputed: Literal[True] = True


class FinalTimestampStage(StrictModel):
    timestamp_id: str
    timestamp_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    merkle_tree_id: str
    merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    timestamp_response_sha256: str = Field(pattern=HEX_256_PATTERN)
    gen_time: str
    policy_oid: str
    serial_number: str
    offline_signature_verified: Literal[True] = True


class FinalRecoveryStage(StrictModel):
    recovery_id: str
    recovery_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    package_id: str
    package_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    archive_sha256: str = Field(pattern=HEX_256_PATTERN)
    archive_size_bytes: int = Field(gt=0)
    archived_entry_count: int = Field(gt=0)
    payload_entry_count: int = Field(gt=0)
    assurance_entry_count: int = Field(gt=0)
    external_evidence_binding_count: int = Field(ge=0)
    source_preservation_id: str
    source_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_merkle_tree_id: str
    source_merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_timestamp_id: str
    source_timestamp_response_sha256: str = Field(pattern=HEX_256_PATTERN)
    payload_verified: Literal[True] = True


class FinalCampaignAccountingStage(StrictModel):
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
    admission_check_count: int = Field(gt=0)
    passed_admission_check_count: int = Field(gt=0)
    failed_admission_check_count: Literal[0] = 0
    enrollment_count: int = Field(gt=0)
    attestation_count: int = Field(gt=0)
    challenge_count: int = Field(gt=0)
    accounting_recomputed: Literal[True] = True


class FinalPreservationCore(StrictModel):
    profile: Literal[
        "offline-recovery-and-campaign-accounting-final-verification-v1"
    ] = FINAL_VERIFICATION_PROFILE
    preservation: FinalPreservationStage
    merkle: FinalMerkleStage
    timestamp: FinalTimestampStage
    recovery: FinalRecoveryStage
    campaign_accounting: FinalCampaignAccountingStage
    verified_stages: list[str]
    final_lineage_verified: Literal[True] = True
    assurance_state: Literal[
        "merkle-committed-time-anchored-recovery-exported-"
        "campaign-accounted-finally-verified"
    ] = FINAL_ASSURANCE_STATE

    @model_validator(mode="after")
    def _complete_consistent_chain(self) -> FinalPreservationCore:
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
            or preservation.selected_model_sha256
            != accounting.selected_model_sha256
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
            or accounting.contribution_count
            != accounting.round_count * accounting.required_client_count
            or accounting.accepted_contribution_count
            != accounting.contribution_count
            or accounting.admission_check_count
            != accounting.passed_admission_check_count
        ):
            raise ValueError("final campaign or trust counts mismatch")
        return self


class FinalPreservationReceipt(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_final_preservation_verification_receipt"] = (
        "m8_final_preservation_verification_receipt"
    )
    verification_id: str
    core: FinalPreservationCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    verifier_implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
