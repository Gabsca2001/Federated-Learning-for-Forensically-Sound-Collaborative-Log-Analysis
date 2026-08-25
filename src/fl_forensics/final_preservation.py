"""M8.6 fail-closed final verification of the offline preservation chain."""

from __future__ import annotations

import tarfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from .anchor_models import TimestampManifest, TimestampProof
from .campaign_accounting import verify_campaign_accounting
from .campaign_accounting_models import (
    CampaignAccountingEnvelope,
    CampaignAccountingReport,
)
from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .final_preservation_models import (
    FINAL_ASSURANCE_STATE,
    VERIFIED_STAGES,
    FinalCampaignAccountingStage,
    FinalMerkleStage,
    FinalPreservationCore,
    FinalPreservationReceipt,
    FinalPreservationStage,
    FinalRecoveryStage,
    FinalTimestampStage,
)
from .merkle_models import MerkleEnvelope, MerkleTreeManifest
from .models import StrictModel
from .preservation_models import (
    PreservationEnvelope,
    PreservationManifest,
    PreservedArtifact,
)
from .recovery import verify_recovery_export
from .recovery_models import (
    RecoveryEnvelope,
    RecoveryManifest,
    RecoveryPackageInventory,
)

ASSURANCE_JSON_PATHS = (
    "assurance/m8.1/manifest.json",
    "assurance/m8.1/preservation-manifest.json",
    "assurance/m8.2/manifest.json",
    "assurance/m8.2/merkle-tree.json",
    "assurance/m8.3/manifest.json",
    "assurance/m8.3/timestamp-proof.json",
)
MAX_ASSURANCE_JSON_BYTES = 32 * 1024 * 1024
ModelT = TypeVar("ModelT", bound=StrictModel)


class FinalPreservationError(ValueError):
    """Raised when the M8.1--M8.5 final assurance chain is incomplete."""


@dataclass(frozen=True)
class _VerifiedInputs:
    preservation: PreservationManifest
    preservation_bytes: bytes
    preservation_envelope: PreservationEnvelope
    tree: MerkleTreeManifest
    tree_bytes: bytes
    merkle_envelope: MerkleEnvelope
    timestamp: TimestampManifest
    timestamp_bytes: bytes
    timestamp_proof: TimestampProof
    package: RecoveryPackageInventory
    package_bytes: bytes
    recovery: RecoveryManifest
    recovery_bytes: bytes
    recovery_envelope: RecoveryEnvelope
    accounting: CampaignAccountingReport
    accounting_bytes: bytes
    accounting_envelope: CampaignAccountingEnvelope


def _ensure(condition: bool, message: str) -> None:
    if not condition:
        raise FinalPreservationError(message)


def _canonical_model_bytes(
    value: bytes, model_type: type[ModelT], label: str
) -> ModelT:
    model = model_type.model_validate_json(value)
    expected = canonical_json_bytes(model.model_dump(mode="json")) + b"\n"
    if value != expected:
        raise FinalPreservationError(f"non-canonical final source: {label}")
    return model


def _load_canonical_model(
    path: Path, model_type: type[ModelT], label: str
) -> tuple[ModelT, bytes]:
    value = path.read_bytes()
    return _canonical_model_bytes(value, model_type, label), value


def _verify_source_workspaces(
    *, recovery_workspace: Path, accounting_workspace: Path
) -> None:
    recovery_result = verify_recovery_export(workspace=recovery_workspace)
    if not (
        recovery_result.get("status") == "verified"
        and recovery_result.get("error_count") == 0
        and recovery_result.get("offline_payload_verified") is True
        and recovery_result.get("offline_merkle_recomputed") is True
        and recovery_result.get("offline_timestamp_verified") is True
    ):
        raise FinalPreservationError(
            "M8.4 source recovery verification failed: "
            f"{recovery_result.get('errors', [])}"
        )
    accounting_result = verify_campaign_accounting(
        workspace=accounting_workspace,
        recovery_workspace=recovery_workspace,
    )
    if not (
        accounting_result.get("status") == "verified"
        and accounting_result.get("error_count") == 0
        and accounting_result.get("source_recovery_verified") is True
        and accounting_result.get("verification_recomputed_accounting") is True
    ):
        raise FinalPreservationError(
            "M8.5 source campaign-accounting verification failed: "
            f"{accounting_result.get('errors', [])}"
        )


def _read_assurance_json(
    *, archive_path: Path, package: RecoveryPackageInventory
) -> dict[str, bytes]:
    entries = {item.archive_path: item for item in package.core.entries}
    values: dict[str, bytes] = {}
    with tarfile.open(archive_path, mode="r:") as archive:
        members = {item.name: item for item in archive.getmembers()}
        for path in ASSURANCE_JSON_PATHS:
            entry = entries.get(path)
            member = members.get(path)
            if (
                entry is None
                or entry.entry_class != "assurance-artifact"
                or member is None
                or not member.isfile()
            ):
                raise FinalPreservationError(
                    f"required final assurance member is missing: {path}"
                )
            if entry.size_bytes > MAX_ASSURANCE_JSON_BYTES:
                raise FinalPreservationError(
                    f"final assurance JSON exceeds the safe size limit: {path}"
                )
            source = archive.extractfile(member)
            if source is None:
                raise FinalPreservationError(
                    f"required final assurance member is unreadable: {path}"
                )
            value = source.read(MAX_ASSURANCE_JSON_BYTES + 1)
            if (
                len(value) != entry.size_bytes
                or sha256_bytes(value) != entry.sha256
            ):
                raise FinalPreservationError(
                    f"final assurance member differs from inventory: {path}"
                )
            values[path] = value
    return values


def _load_verified_inputs(
    *, recovery_workspace: Path, accounting_workspace: Path
) -> _VerifiedInputs:
    _verify_source_workspaces(
        recovery_workspace=recovery_workspace,
        accounting_workspace=accounting_workspace,
    )
    package, package_bytes = _load_canonical_model(
        recovery_workspace / "package-inventory.json",
        RecoveryPackageInventory,
        "M8.4 package inventory",
    )
    recovery, recovery_bytes = _load_canonical_model(
        recovery_workspace / "recovery-manifest.json",
        RecoveryManifest,
        "M8.4 recovery manifest",
    )
    recovery_envelope, _recovery_envelope_bytes = _load_canonical_model(
        recovery_workspace / "manifest.json",
        RecoveryEnvelope,
        "M8.4 envelope",
    )
    accounting, accounting_bytes = _load_canonical_model(
        accounting_workspace / "campaign-accounting.json",
        CampaignAccountingReport,
        "M8.5 campaign accounting",
    )
    accounting_envelope, _accounting_envelope_bytes = _load_canonical_model(
        accounting_workspace / "manifest.json",
        CampaignAccountingEnvelope,
        "M8.5 envelope",
    )
    assurance = _read_assurance_json(
        archive_path=recovery_workspace / recovery.core.archive_name,
        package=package,
    )
    preservation_bytes = assurance[
        "assurance/m8.1/preservation-manifest.json"
    ]
    preservation = _canonical_model_bytes(
        preservation_bytes,
        PreservationManifest,
        "offline M8.1 preservation manifest",
    )
    preservation_envelope = _canonical_model_bytes(
        assurance["assurance/m8.1/manifest.json"],
        PreservationEnvelope,
        "offline M8.1 envelope",
    )
    tree_bytes = assurance["assurance/m8.2/merkle-tree.json"]
    tree = _canonical_model_bytes(
        tree_bytes,
        MerkleTreeManifest,
        "offline M8.2 Merkle tree",
    )
    merkle_envelope = _canonical_model_bytes(
        assurance["assurance/m8.2/manifest.json"],
        MerkleEnvelope,
        "offline M8.2 envelope",
    )
    timestamp_bytes = assurance["assurance/m8.3/manifest.json"]
    timestamp = _canonical_model_bytes(
        timestamp_bytes,
        TimestampManifest,
        "offline M8.3 timestamp manifest",
    )
    timestamp_proof = _canonical_model_bytes(
        assurance["assurance/m8.3/timestamp-proof.json"],
        TimestampProof,
        "offline M8.3 timestamp proof",
    )
    return _VerifiedInputs(
        preservation=preservation,
        preservation_bytes=preservation_bytes,
        preservation_envelope=preservation_envelope,
        tree=tree,
        tree_bytes=tree_bytes,
        merkle_envelope=merkle_envelope,
        timestamp=timestamp,
        timestamp_bytes=timestamp_bytes,
        timestamp_proof=timestamp_proof,
        package=package,
        package_bytes=package_bytes,
        recovery=recovery,
        recovery_bytes=recovery_bytes,
        recovery_envelope=recovery_envelope,
        accounting=accounting,
        accounting_bytes=accounting_bytes,
        accounting_envelope=accounting_envelope,
    )


def _one_artifact(
    artifacts: list[PreservedArtifact], *, role: str, suffix: str
) -> PreservedArtifact:
    matches = [
        item
        for item in artifacts
        if item.artifact_role == role and item.relative_path.endswith(suffix)
    ]
    if len(matches) != 1:
        raise FinalPreservationError(
            f"final preservation requires one {role} artifact ending in {suffix}"
        )
    return matches[0]


def _validate_outer_bindings(inputs: _VerifiedInputs) -> None:
    preservation_sha256 = sha256_bytes(inputs.preservation_bytes)
    tree_sha256 = sha256_bytes(inputs.tree_bytes)
    recovery_manifest_sha256 = sha256_bytes(inputs.recovery_bytes)
    package_inventory_sha256 = sha256_bytes(inputs.package_bytes)
    accounting_sha256 = sha256_bytes(inputs.accounting_bytes)
    _ensure(
        inputs.preservation_envelope.preservation_id
        == inputs.preservation.preservation_id
        and inputs.preservation_envelope.preservation_manifest_sha256
        == preservation_sha256
        and inputs.preservation_envelope.canonical_core_sha256
        == inputs.preservation.canonical_core_sha256,
        "final M8.1 envelope binding mismatch",
    )
    _ensure(
        inputs.merkle_envelope.tree_id == inputs.tree.tree_id
        and inputs.merkle_envelope.merkle_tree_sha256 == tree_sha256
        and inputs.merkle_envelope.root_sha256 == inputs.tree.core.root_sha256
        and inputs.merkle_envelope.source_preservation_id
        == inputs.preservation.preservation_id,
        "final M8.2 envelope binding mismatch",
    )
    _ensure(
        inputs.recovery_envelope.recovery_id == inputs.recovery.recovery_id
        and inputs.recovery_envelope.recovery_manifest_sha256
        == recovery_manifest_sha256
        and inputs.recovery_envelope.package_id == inputs.package.package_id
        and inputs.recovery_envelope.package_inventory_sha256
        == package_inventory_sha256
        and inputs.recovery_envelope.archive_sha256
        == inputs.recovery.core.archive_sha256,
        "final M8.4 envelope binding mismatch",
    )
    _ensure(
        inputs.accounting_envelope.accounting_id
        == inputs.accounting.accounting_id
        and inputs.accounting_envelope.campaign_accounting_sha256
        == accounting_sha256
        and inputs.accounting_envelope.contribution_inventory_sha256
        == inputs.accounting.core.contribution_inventory_sha256
        and inputs.accounting_envelope.source_recovery_id
        == inputs.recovery.recovery_id,
        "final M8.5 envelope binding mismatch",
    )


def _build_core(inputs: _VerifiedInputs) -> FinalPreservationCore:
    _validate_outer_bindings(inputs)
    preservation = inputs.preservation
    accounting = inputs.accounting
    selected_round = preservation.core.selected_derivation_round
    campaign_manifest = _one_artifact(
        preservation.core.campaign_assurance,
        role="campaign-assurance",
        suffix="/campaign-manifest.json",
    )
    selected_checkpoint = _one_artifact(
        preservation.core.campaign_assurance,
        role="selected-derivation-round",
        suffix=f"/round-{selected_round:03d}/checkpoint/manifest.json",
    )
    selected_model = _one_artifact(
        preservation.core.campaign_assurance,
        role="selected-derivation-round",
        suffix=f"/round-{selected_round:03d}/checkpoint/global-model.json",
    )
    trust_roles = Counter(item.artifact_role for item in preservation.core.trust_assurance)
    private_exclusion = any(
        item.pattern == "*.private.pem" and item.must_not_be_exported
        for item in preservation.core.excluded_material
    )
    private_payload = any(
        item.source_relative_path.endswith(".private.pem")
        for item in inputs.package.core.entries
    )
    _ensure(
        private_exclusion and not private_payload,
        "private cryptographic material is not fail-closed excluded",
    )
    _ensure(
        preservation.core.campaign_rounds
        == list(range(1, accounting.core.round_count + 1)),
        "final campaign round coverage mismatch",
    )
    _ensure(
        inputs.timestamp.core.timestamp_proof_sha256
        == sha256_bytes(
            canonical_json_bytes(inputs.timestamp_proof.model_dump(mode="json"))
            + b"\n"
        )
        and inputs.timestamp.core.merkle_tree_id == inputs.tree.tree_id
        and inputs.timestamp.core.merkle_root_sha256
        == inputs.tree.core.root_sha256,
        "final M8.3 proof binding mismatch",
    )
    core = FinalPreservationCore(
        preservation=FinalPreservationStage(
            preservation_id=preservation.preservation_id,
            preservation_manifest_sha256=sha256_bytes(inputs.preservation_bytes),
            canonical_core_sha256=preservation.canonical_core_sha256,
            inventory_sha256=preservation.core.preservation_state.inventory_sha256,
            implementation_sha256=inputs.preservation_envelope.implementation_sha256,
            config_sha256=inputs.preservation_envelope.config_sha256,
            artifact_count=preservation.core.preservation_state.artifact_count,
            external_evidence_binding_count=len(preservation.core.external_evidence),
            selected_derivation_round=selected_round,
            source_campaign_manifest_sha256=campaign_manifest.sha256,
            selected_checkpoint_sha256=selected_checkpoint.sha256,
            selected_model_sha256=selected_model.sha256,
            enrollment_count=trust_roles["referenced-enrollment-record"],
            attestation_count=trust_roles["referenced-attestation-result"],
            challenge_count=trust_roles["referenced-attestation-challenge"],
        ),
        merkle=FinalMerkleStage(
            tree_id=inputs.tree.tree_id,
            merkle_tree_sha256=sha256_bytes(inputs.tree_bytes),
            canonical_core_sha256=inputs.tree.canonical_core_sha256,
            implementation_sha256=inputs.merkle_envelope.implementation_sha256,
            config_sha256=inputs.merkle_envelope.config_sha256,
            source_preservation_id=inputs.tree.core.source_preservation_id,
            source_preservation_manifest_sha256=(
                inputs.tree.core.source_preservation_manifest_sha256
            ),
            source_inventory_sha256=inputs.tree.core.source_inventory_sha256,
            root_sha256=inputs.tree.core.root_sha256,
            artifact_leaf_count=inputs.tree.core.artifact_leaf_count,
            external_evidence_leaf_count=(
                inputs.tree.core.external_evidence_leaf_count
            ),
            leaf_count=inputs.tree.core.leaf_count,
        ),
        timestamp=FinalTimestampStage(
            timestamp_id=inputs.timestamp.timestamp_id,
            timestamp_manifest_sha256=sha256_bytes(inputs.timestamp_bytes),
            canonical_core_sha256=inputs.timestamp.canonical_core_sha256,
            implementation_sha256=inputs.timestamp.implementation_sha256,
            config_sha256=inputs.timestamp.config_sha256,
            merkle_tree_id=inputs.timestamp.core.merkle_tree_id,
            merkle_root_sha256=inputs.timestamp.core.merkle_root_sha256,
            timestamp_response_sha256=(
                inputs.timestamp.core.timestamp_response_sha256
            ),
            gen_time=inputs.timestamp_proof.gen_time,
            policy_oid=inputs.timestamp_proof.policy_oid,
            serial_number=inputs.timestamp_proof.serial_number,
        ),
        recovery=FinalRecoveryStage(
            recovery_id=inputs.recovery.recovery_id,
            recovery_manifest_sha256=sha256_bytes(inputs.recovery_bytes),
            canonical_core_sha256=inputs.recovery.canonical_core_sha256,
            implementation_sha256=inputs.recovery.implementation_sha256,
            config_sha256=inputs.recovery.config_sha256,
            package_id=inputs.package.package_id,
            package_inventory_sha256=sha256_bytes(inputs.package_bytes),
            archive_sha256=inputs.recovery.core.archive_sha256,
            archive_size_bytes=inputs.recovery.core.archive_size_bytes,
            archived_entry_count=inputs.recovery.core.archived_entry_count,
            payload_entry_count=inputs.recovery.core.payload_entry_count,
            assurance_entry_count=inputs.recovery.core.assurance_entry_count,
            external_evidence_binding_count=(
                inputs.recovery.core.external_evidence_binding_count
            ),
            source_preservation_id=inputs.package.core.source_preservation_id,
            source_inventory_sha256=inputs.package.core.source_inventory_sha256,
            source_merkle_tree_id=inputs.package.core.source_merkle_tree_id,
            source_merkle_root_sha256=(
                inputs.package.core.source_merkle_root_sha256
            ),
            source_timestamp_id=inputs.package.core.source_timestamp_id,
            source_timestamp_response_sha256=(
                inputs.package.core.source_timestamp_response_sha256
            ),
        ),
        campaign_accounting=FinalCampaignAccountingStage(
            accounting_id=accounting.accounting_id,
            campaign_accounting_sha256=sha256_bytes(inputs.accounting_bytes),
            canonical_core_sha256=accounting.canonical_core_sha256,
            implementation_sha256=accounting.implementation_sha256,
            config_sha256=accounting.config_sha256,
            contribution_inventory_sha256=(
                accounting.core.contribution_inventory_sha256
            ),
            source_recovery_id=accounting.core.source_recovery_id,
            source_package_id=accounting.core.source_package_id,
            source_recovery_archive_sha256=(
                accounting.core.source_recovery_archive_sha256
            ),
            source_preservation_id=accounting.core.source_preservation_id,
            source_merkle_tree_id=accounting.core.source_merkle_tree_id,
            source_merkle_root_sha256=accounting.core.source_merkle_root_sha256,
            source_timestamp_id=accounting.core.source_timestamp_id,
            source_campaign_id=accounting.core.source_campaign_id,
            source_campaign_manifest_sha256=(
                accounting.core.source_campaign_manifest_sha256
            ),
            selected_round=accounting.core.selected_round,
            selected_checkpoint_sha256=accounting.core.selected_checkpoint_sha256,
            selected_model_sha256=accounting.core.selected_model_sha256,
            round_count=accounting.core.round_count,
            required_client_count=accounting.core.required_client_count,
            contribution_count=accounting.core.contribution_count,
            accepted_contribution_count=(
                accounting.core.accepted_contribution_count
            ),
            quarantined_contribution_count=(
                accounting.core.quarantined_contribution_count
            ),
            missing_contribution_count=accounting.core.missing_contribution_count,
            total_example_count=accounting.core.total_example_count,
            admission_check_count=accounting.core.admission_check_count,
            passed_admission_check_count=(
                accounting.core.passed_admission_check_count
            ),
            failed_admission_check_count=(
                accounting.core.failed_admission_check_count
            ),
            enrollment_count=accounting.core.trust_accounting.enrollment_count,
            attestation_count=accounting.core.trust_accounting.attestation_count,
            challenge_count=accounting.core.trust_accounting.challenge_count,
        ),
        verified_stages=list(VERIFIED_STAGES),
    )
    _ensure(
        campaign_manifest.sha256
        == accounting.core.source_campaign_manifest_sha256,
        "final campaign manifest digest mismatch",
    )
    return core


def _derive_core(
    *, recovery_workspace: Path, accounting_workspace: Path
) -> FinalPreservationCore:
    inputs = _load_verified_inputs(
        recovery_workspace=recovery_workspace,
        accounting_workspace=accounting_workspace,
    )
    return _build_core(inputs)


def _receipt(core: FinalPreservationCore) -> FinalPreservationReceipt:
    core_digest = digest_object(core.model_dump(mode="json"))
    return FinalPreservationReceipt(
        verification_id=f"m8-final-verification-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
        verifier_implementation_sha256=sha256_file(Path(__file__)),
    )


def verify_final_preservation(
    *, recovery_workspace: Path, accounting_workspace: Path
) -> dict[str, Any]:
    errors: list[str] = []
    receipt: FinalPreservationReceipt | None = None
    try:
        core = _derive_core(
            recovery_workspace=recovery_workspace,
            accounting_workspace=accounting_workspace,
        )
        receipt = _receipt(core)
    except (
        FileNotFoundError,
        FinalPreservationError,
        KeyError,
        OSError,
        tarfile.TarError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    core = receipt.core if receipt is not None else None
    verified = not errors
    return {
        "status": "verified" if verified else "failed",
        "verification_id": receipt.verification_id if receipt else None,
        "canonical_core_sha256": (
            receipt.canonical_core_sha256 if receipt else None
        ),
        "verification_receipt_sha256": (
            sha256_bytes(
                canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
            )
            if receipt
            else None
        ),
        "assurance_state": FINAL_ASSURANCE_STATE if receipt else None,
        "verified_stage_count": len(VERIFIED_STAGES) if receipt else 0,
        "preservation_id": core.preservation.preservation_id if core else None,
        "merkle_tree_id": core.merkle.tree_id if core else None,
        "merkle_root_sha256": core.merkle.root_sha256 if core else None,
        "timestamp_id": core.timestamp.timestamp_id if core else None,
        "timestamp_gen_time": core.timestamp.gen_time if core else None,
        "recovery_id": core.recovery.recovery_id if core else None,
        "package_id": core.recovery.package_id if core else None,
        "accounting_id": (
            core.campaign_accounting.accounting_id if core else None
        ),
        "campaign_id": (
            core.campaign_accounting.source_campaign_id if core else None
        ),
        "round_count": core.campaign_accounting.round_count if core else 0,
        "contribution_count": (
            core.campaign_accounting.contribution_count if core else 0
        ),
        "selected_round": (
            core.campaign_accounting.selected_round if core else None
        ),
        "preservation_inventory_verified": verified,
        "merkle_commitment_verified": verified,
        "trusted_timestamp_verified": verified,
        "recovery_payload_verified": verified,
        "campaign_invariants_verified": verified,
        "final_lineage_verified": verified,
        "offline_inputs_only": verified,
        "error_count": len(errors),
        "errors": errors,
        "recovery_workspace": str(recovery_workspace),
        "accounting_workspace": str(accounting_workspace),
    }
