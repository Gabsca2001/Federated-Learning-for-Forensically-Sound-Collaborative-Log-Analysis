from __future__ import annotations

import json
from pathlib import Path

import pytest

import fl_forensics.campaign_accounting as accounting
from fl_forensics.campaign_accounting import (
    _envelope,
    _report,
    _safe_relative,
    verify_campaign_accounting,
)
from fl_forensics.campaign_accounting_models import (
    ADMISSION_CHECK_NAMES,
    CampaignAccountingCore,
    CampaignClientAccount,
    CampaignContributionAccount,
    CampaignRoundAccount,
    CampaignTrustAccounting,
)
from fl_forensics.canonical import canonical_json_bytes, digest_object


def _sha(value: str) -> str:
    return value * 64


def _contribution() -> CampaignContributionAccount:
    return CampaignContributionAccount(
        round_number=1,
        client_id="client01",
        node_id="node01",
        enrollment_id="enrollment-1",
        attestation_result_id="attestation-1",
        attestation_result_sha256=_sha("1"),
        challenge_id="challenge-1",
        context_id="context-1",
        context_digest=_sha("2"),
        bundle_id="bundle-1",
        bundle_sha256=_sha("3"),
        decision_id="decision-1",
        decision_sha256=_sha("4"),
        snapshot_sha256=_sha("5"),
        snapshot_manifest_sha256=_sha("6"),
        update_sha256=_sha("7"),
        metrics_sha256=_sha("8"),
        tensor_schema_sha256=_sha("9"),
        num_examples=10,
        generated_at="2026-08-20T10:01:00Z",
        decided_at="2026-08-20T10:02:00Z",
        admission_checks=list(ADMISSION_CHECK_NAMES),
        all_checks_passed=True,
    )


def _core() -> CampaignAccountingCore:
    contribution = _contribution()
    contribution_value = contribution.model_dump(mode="json")
    inventory = digest_object([contribution_value])
    return CampaignAccountingCore(
        source_recovery_id="recovery-1",
        source_package_id="package-1",
        source_recovery_archive_sha256=_sha("a"),
        source_preservation_id="preservation-1",
        source_merkle_tree_id="tree-1",
        source_merkle_root_sha256=_sha("b"),
        source_timestamp_id="timestamp-1",
        source_campaign_id="campaign-1",
        source_campaign_manifest_sha256=_sha("c"),
        selected_round=1,
        selected_checkpoint_sha256=_sha("d"),
        selected_model_sha256=_sha("e"),
        round_count=1,
        required_client_count=1,
        contribution_count=1,
        accepted_contribution_count=1,
        quarantined_contribution_count=0,
        missing_contribution_count=0,
        total_example_count=10,
        admission_check_names=list(ADMISSION_CHECK_NAMES),
        admission_check_count=len(ADMISSION_CHECK_NAMES),
        passed_admission_check_count=len(ADMISSION_CHECK_NAMES),
        failed_admission_check_count=0,
        unique_bundle_count=1,
        unique_decision_count=1,
        unique_update_count=1,
        contribution_inventory_sha256=inventory,
        trust_accounting=CampaignTrustAccounting(
            enrollment_count=1,
            attestation_count=1,
            challenge_count=1,
            attestation_usage_count=1,
            attestations_per_client=1,
            rounds_per_attestation=1,
            verified_enrollment_signature_count=1,
            verified_attestation_signature_count=1,
            verified_challenge_signature_count=1,
            verified_bundle_signature_count=1,
            verified_coordinator_signature_count=4,
            trust_binding_valid=True,
        ),
        rounds=[
            CampaignRoundAccount(
                round_number=1,
                context_id="context-1",
                context_sha256=_sha("f"),
                checkpoint_id="checkpoint-1",
                checkpoint_sha256=_sha("0"),
                previous_checkpoint_sha256=_sha("1"),
                base_model_sha256=_sha("2"),
                global_model_sha256=_sha("3"),
                required_client_count=1,
                contribution_count=1,
                accepted_count=1,
                quarantined_count=0,
                missing_count=0,
                total_examples=10,
                passed_check_count=len(ADMISSION_CHECK_NAMES),
                unique_attestation_count=1,
                contribution_inventory_sha256=inventory,
                checkpoint_chain_valid=True,
            )
        ],
        clients=[
            CampaignClientAccount(
                client_id="client01",
                node_id="node01",
                enrollment_id="enrollment-1",
                contracted_round_count=1,
                submitted_count=1,
                accepted_count=1,
                quarantined_count=0,
                total_examples=10,
                attestation_result_ids=["attestation-1"],
                challenge_ids=["challenge-1"],
                attestation_count=1,
                challenge_count=1,
            )
        ],
        contributions=[contribution],
    )


def _write_workspace(workspace: Path, core: CampaignAccountingCore) -> None:
    report = _report(core=core, config_sha256=_sha("f"))
    report_bytes = canonical_json_bytes(report.model_dump(mode="json")) + b"\n"
    envelope = _envelope(report=report, report_bytes=report_bytes)
    workspace.mkdir()
    (workspace / "campaign-accounting.json").write_bytes(report_bytes)
    (workspace / "manifest.json").write_bytes(
        canonical_json_bytes(envelope.model_dump(mode="json")) + b"\n"
    )


def test_minimal_accounting_core_is_internally_consistent() -> None:
    core = _core()
    assert core.contribution_count == 1
    assert core.contribution_inventory_sha256 == digest_object(
        [core.contributions[0].model_dump(mode="json")]
    )


def test_contribution_rejects_incomplete_admission_checks() -> None:
    value = _contribution().model_dump(mode="json")
    value["admission_checks"] = list(ADMISSION_CHECK_NAMES[:-1])
    with pytest.raises(ValueError, match="admission checks"):
        CampaignContributionAccount.model_validate(value)


def test_core_rejects_duplicate_contribution_slot() -> None:
    value = _core().model_dump(mode="json")
    value["contributions"] = [*value["contributions"], value["contributions"][0]]
    value["contribution_count"] = 2
    value["accepted_contribution_count"] = 2
    value["total_example_count"] = 20
    value["admission_check_count"] = 2 * len(ADMISSION_CHECK_NAMES)
    value["passed_admission_check_count"] = 2 * len(ADMISSION_CHECK_NAMES)
    value["contribution_inventory_sha256"] = digest_object(value["contributions"])
    with pytest.raises(ValueError, match="ledger is incomplete or unordered"):
        CampaignAccountingCore.model_validate(value)


def test_core_rejects_example_total_mismatch() -> None:
    value = _core().model_dump(mode="json")
    value["total_example_count"] = 11
    with pytest.raises(ValueError, match="totals do not match"):
        CampaignAccountingCore.model_validate(value)


@pytest.mark.parametrize(
    ("field", "tampered_value"),
    [
        ("enrollment_count", 2),
        ("attestation_count", 2),
        ("challenge_count", 2),
        ("attestation_usage_count", 2),
        ("verified_bundle_signature_count", 2),
        ("verified_coordinator_signature_count", 5),
    ],
)
def test_core_rejects_trust_total_mismatch(field: str, tampered_value: int) -> None:
    value = _core().model_dump(mode="json")
    value["trust_accounting"][field] = tampered_value
    with pytest.raises(ValueError, match="trust totals do not match"):
        CampaignAccountingCore.model_validate(value)


@pytest.mark.parametrize("value", ["../outside", "/absolute", "./ambiguous", "."])
def test_accounting_source_path_is_fail_closed(value: str) -> None:
    with pytest.raises(ValueError, match="unsafe accounting source path"):
        _safe_relative(value)


def test_report_serialization_is_deterministic() -> None:
    first = _report(core=_core(), config_sha256=_sha("f"))
    second = _report(core=_core(), config_sha256=_sha("f"))
    assert canonical_json_bytes(first.model_dump(mode="json")) == canonical_json_bytes(
        second.model_dump(mode="json")
    )


def test_verifier_accepts_exact_offline_reconstruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = _core()
    workspace = tmp_path / "accounting"
    _write_workspace(workspace, core)
    monkeypatch.setattr(accounting, "_derive_core", lambda **_kwargs: core)
    result = verify_campaign_accounting(
        workspace=workspace,
        recovery_workspace=tmp_path / "recovery",
    )
    assert result["status"] == "verified"
    assert result["verification_recomputed_accounting"] is True


def test_verifier_rejects_manifest_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = _core()
    workspace = tmp_path / "accounting"
    _write_workspace(workspace, core)
    monkeypatch.setattr(accounting, "_derive_core", lambda **_kwargs: core)
    path = workspace / "manifest.json"
    value = json.loads(path.read_bytes())
    value["campaign_accounting_sha256"] = _sha("0")
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    result = verify_campaign_accounting(
        workspace=workspace,
        recovery_workspace=tmp_path / "recovery",
    )
    assert result["status"] == "failed"
    assert result["error_count"] == 1


def test_verifier_rejects_unexpected_workspace_file(tmp_path: Path) -> None:
    workspace = tmp_path / "accounting"
    workspace.mkdir()
    (workspace / "unexpected.json").write_text("{}")
    result = verify_campaign_accounting(
        workspace=workspace,
        recovery_workspace=tmp_path / "recovery",
    )
    assert result["status"] == "failed"
    assert "unexpected or non-regular" in result["errors"][0]
