from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import fl_forensics.final_preservation as final
from fl_forensics.canonical import canonical_json_bytes, digest_object
from fl_forensics.final_preservation import (
    FinalPreservationError,
    _canonical_model_bytes,
    _receipt,
    _verify_source_workspaces,
    verify_final_preservation,
)
from fl_forensics.final_preservation_models import (
    FINAL_ASSURANCE_STATE,
    VERIFIED_STAGES,
    FinalCampaignAccountingStage,
    FinalMerkleStage,
    FinalPreservationCore,
    FinalPreservationStage,
    FinalRecoveryStage,
    FinalTimestampStage,
)
from fl_forensics.recovery_models import RecoveryEnvelope


def _sha(value: str) -> str:
    return value * 64


def _core() -> FinalPreservationCore:
    return FinalPreservationCore(
        preservation=FinalPreservationStage(
            preservation_id="preservation-1",
            preservation_manifest_sha256=_sha("a"),
            canonical_core_sha256=_sha("b"),
            inventory_sha256=_sha("c"),
            implementation_sha256=_sha("d"),
            config_sha256=_sha("e"),
            artifact_count=2,
            external_evidence_binding_count=1,
            selected_derivation_round=1,
            source_campaign_manifest_sha256=_sha("f"),
            selected_checkpoint_sha256=_sha("0"),
            selected_model_sha256=_sha("1"),
            enrollment_count=1,
            attestation_count=1,
            challenge_count=1,
        ),
        merkle=FinalMerkleStage(
            tree_id="tree-1",
            merkle_tree_sha256=_sha("2"),
            canonical_core_sha256=_sha("3"),
            implementation_sha256=_sha("4"),
            config_sha256=_sha("5"),
            source_preservation_id="preservation-1",
            source_preservation_manifest_sha256=_sha("a"),
            source_inventory_sha256=_sha("c"),
            root_sha256=_sha("6"),
            artifact_leaf_count=2,
            external_evidence_leaf_count=1,
            leaf_count=3,
        ),
        timestamp=FinalTimestampStage(
            timestamp_id="timestamp-1",
            timestamp_manifest_sha256=_sha("7"),
            canonical_core_sha256=_sha("8"),
            implementation_sha256=_sha("9"),
            config_sha256=_sha("a"),
            merkle_tree_id="tree-1",
            merkle_root_sha256=_sha("6"),
            timestamp_response_sha256=_sha("b"),
            gen_time="Aug 25 12:00:00 2026 GMT",
            policy_oid="1.2.3",
            serial_number="0x01",
        ),
        recovery=FinalRecoveryStage(
            recovery_id="recovery-1",
            recovery_manifest_sha256=_sha("c"),
            canonical_core_sha256=_sha("d"),
            implementation_sha256=_sha("e"),
            config_sha256=_sha("f"),
            package_id="package-1",
            package_inventory_sha256=_sha("0"),
            archive_sha256=_sha("1"),
            archive_size_bytes=100,
            archived_entry_count=14,
            payload_entry_count=2,
            assurance_entry_count=11,
            external_evidence_binding_count=1,
            source_preservation_id="preservation-1",
            source_inventory_sha256=_sha("c"),
            source_merkle_tree_id="tree-1",
            source_merkle_root_sha256=_sha("6"),
            source_timestamp_id="timestamp-1",
            source_timestamp_response_sha256=_sha("b"),
        ),
        campaign_accounting=FinalCampaignAccountingStage(
            accounting_id="accounting-1",
            campaign_accounting_sha256=_sha("2"),
            canonical_core_sha256=_sha("3"),
            implementation_sha256=_sha("4"),
            config_sha256=_sha("5"),
            contribution_inventory_sha256=_sha("6"),
            source_recovery_id="recovery-1",
            source_package_id="package-1",
            source_recovery_archive_sha256=_sha("1"),
            source_preservation_id="preservation-1",
            source_merkle_tree_id="tree-1",
            source_merkle_root_sha256=_sha("6"),
            source_timestamp_id="timestamp-1",
            source_campaign_id="campaign-1",
            source_campaign_manifest_sha256=_sha("f"),
            selected_round=1,
            selected_checkpoint_sha256=_sha("0"),
            selected_model_sha256=_sha("1"),
            round_count=1,
            required_client_count=1,
            contribution_count=1,
            accepted_contribution_count=1,
            quarantined_contribution_count=0,
            missing_contribution_count=0,
            total_example_count=10,
            admission_check_count=7,
            passed_admission_check_count=7,
            failed_admission_check_count=0,
            enrollment_count=1,
            attestation_count=1,
            challenge_count=1,
        ),
        verified_stages=list(VERIFIED_STAGES),
    )


def _set_nested(value: dict[str, Any], path: str, replacement: Any) -> None:
    parts = path.split(".")
    current = value
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = replacement


def _verified_recovery_result() -> dict[str, Any]:
    return {
        "status": "verified",
        "error_count": 0,
        "errors": [],
        "offline_payload_verified": True,
        "offline_merkle_recomputed": True,
        "offline_timestamp_verified": True,
    }


def _verified_accounting_result() -> dict[str, Any]:
    return {
        "status": "verified",
        "error_count": 0,
        "errors": [],
        "source_recovery_verified": True,
        "verification_recomputed_accounting": True,
    }


def test_final_core_accepts_only_the_complete_ordered_chain() -> None:
    core = _core()
    assert core.assurance_state == FINAL_ASSURANCE_STATE
    assert core.verified_stages == list(VERIFIED_STAGES)
    assert core.recovery.payload_entry_count == core.preservation.artifact_count


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        ("merkle.source_preservation_id", "other", "preservation lineage"),
        ("timestamp.merkle_root_sha256", _sha("7"), "Merkle lineage"),
        (
            "recovery.source_timestamp_response_sha256",
            _sha("c"),
            "timestamp lineage",
        ),
        ("campaign_accounting.source_recovery_id", "other", "recovery lineage"),
        (
            "campaign_accounting.selected_model_sha256",
            _sha("2"),
            "selected derivation lineage",
        ),
        ("recovery.payload_entry_count", 3, "preservation or recovery counts"),
        ("campaign_accounting.attestation_count", 2, "campaign or trust counts"),
    ],
)
def test_final_core_rejects_cross_stage_mismatch(
    path: str, replacement: Any, message: str
) -> None:
    value = _core().model_dump(mode="json")
    _set_nested(value, path, replacement)
    with pytest.raises(ValueError, match=message):
        FinalPreservationCore.model_validate(value)


def test_final_core_rejects_incomplete_stage_list() -> None:
    value = _core().model_dump(mode="json")
    value["verified_stages"] = value["verified_stages"][:-1]
    with pytest.raises(ValueError, match="stages are incomplete"):
        FinalPreservationCore.model_validate(value)


def test_final_receipt_identity_is_deterministic() -> None:
    first = _receipt(_core())
    second = _receipt(_core())
    assert first == second
    assert first.verification_id.startswith("m8-final-verification-")
    assert first.canonical_core_sha256 == digest_object(
        first.core.model_dump(mode="json")
    )


def test_canonical_source_loader_rejects_equivalent_pretty_json() -> None:
    envelope = RecoveryEnvelope(
        recovery_id="recovery-1",
        recovery_manifest_sha256=_sha("a"),
        package_id="package-1",
        package_inventory_sha256=_sha("b"),
        archive_sha256=_sha("c"),
    )
    canonical = canonical_json_bytes(envelope.model_dump(mode="json")) + b"\n"
    assert _canonical_model_bytes(canonical, RecoveryEnvelope, "test") == envelope
    pretty = json.dumps(envelope.model_dump(mode="json"), indent=2).encode() + b"\n"
    with pytest.raises(FinalPreservationError, match="non-canonical"):
        _canonical_model_bytes(pretty, RecoveryEnvelope, "test")


def test_source_gate_requires_both_fail_closed_verifiers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        final, "verify_recovery_export", lambda **_kwargs: _verified_recovery_result()
    )
    monkeypatch.setattr(
        final,
        "verify_campaign_accounting",
        lambda **_kwargs: _verified_accounting_result(),
    )
    _verify_source_workspaces(
        recovery_workspace=tmp_path / "recovery",
        accounting_workspace=tmp_path / "accounting",
    )


def test_source_gate_rejects_failed_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = _verified_recovery_result()
    failed.update(status="failed", error_count=1, errors=["tampered archive"])
    monkeypatch.setattr(final, "verify_recovery_export", lambda **_kwargs: failed)
    with pytest.raises(FinalPreservationError, match="M8.4 source recovery"):
        _verify_source_workspaces(
            recovery_workspace=tmp_path / "recovery",
            accounting_workspace=tmp_path / "accounting",
        )


def test_source_gate_rejects_failed_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = _verified_accounting_result()
    failed.update(status="failed", error_count=1, errors=["tampered accounting"])
    monkeypatch.setattr(
        final, "verify_recovery_export", lambda **_kwargs: _verified_recovery_result()
    )
    monkeypatch.setattr(final, "verify_campaign_accounting", lambda **_kwargs: failed)
    with pytest.raises(FinalPreservationError, match="M8.5 source campaign"):
        _verify_source_workspaces(
            recovery_workspace=tmp_path / "recovery",
            accounting_workspace=tmp_path / "accounting",
        )


def test_public_verifier_returns_deterministic_success_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(final, "_derive_core", lambda **_kwargs: _core())
    first = verify_final_preservation(
        recovery_workspace=tmp_path / "recovery",
        accounting_workspace=tmp_path / "accounting",
    )
    second = verify_final_preservation(
        recovery_workspace=tmp_path / "recovery",
        accounting_workspace=tmp_path / "accounting",
    )
    assert first == second
    assert first["status"] == "verified"
    assert first["verified_stage_count"] == 5
    assert first["final_lineage_verified"] is True
    assert first["error_count"] == 0


def test_public_verifier_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(**_kwargs: Any) -> FinalPreservationCore:
        raise FinalPreservationError("final lineage tampered")

    monkeypatch.setattr(final, "_derive_core", fail)
    result = verify_final_preservation(
        recovery_workspace=tmp_path / "recovery",
        accounting_workspace=tmp_path / "accounting",
    )
    assert result["status"] == "failed"
    assert result["verification_id"] is None
    assert result["verified_stage_count"] == 0
    assert result["offline_inputs_only"] is False
    assert result["errors"] == ["final lineage tampered"]
