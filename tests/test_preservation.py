from __future__ import annotations

import json
from pathlib import Path

import pytest

from fl_forensics import preservation
from fl_forensics.canonical import canonical_json_bytes, sha256_bytes
from fl_forensics.preservation import (
    PreservationError,
    _artifact,
    _excluded,
    create_preservation_manifest,
    verify_preservation_manifest,
)
from fl_forensics.preservation_models import PreservationCore, PreservationState


def test_artifact_identity_is_content_and_role_addressed(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_bytes(canonical_json_bytes({"value": 1}) + b"\n")
    first = _artifact(
        path=path,
        root=tmp_path,
        artifact_role="evidence",
        milestone="M2",
        workspace_role="derivation-chain",
        preservation_class="required-causal-artifact",
    )
    second = _artifact(
        path=path,
        root=tmp_path,
        artifact_role="evidence",
        milestone="M2",
        workspace_role="derivation-chain",
        preservation_class="required-causal-artifact",
    )
    assert first == second
    assert first.relative_path == "evidence.json"
    assert first.size_bytes == path.stat().st_size


def test_artifact_fails_closed_when_required_file_is_missing(tmp_path: Path) -> None:
    with pytest.raises(PreservationError, match="required artifact is missing"):
        _artifact(
            path=tmp_path / "missing.json",
            root=tmp_path,
            artifact_role="evidence",
            milestone="M2",
            workspace_role="derivation-chain",
            preservation_class="required-causal-artifact",
        )


@pytest.mark.parametrize(
    "value",
    [
        "authority/key.private.pem",
        "key.private.pem",
        "state/challenges.json",
    ],
)
def test_private_and_mutable_material_is_excluded(value: str) -> None:
    assert _excluded(value, ["*.private.pem", "state/challenges.json"])


def test_campaign_rounds_must_be_exact_and_consecutive() -> None:
    with pytest.raises(ValueError, match="consecutive and one-based"):
        PreservationCore(
            profile=(
                "content-addressed-not-merkle-committed-not-time-anchored-"
                "not-recovery-exported"
            ),
            derivation_chain=[],
            trust_assurance=[],
            campaign_assurance=[],
            external_evidence=[],
            excluded_material=[],
            selected_derivation_round=1,
            campaign_rounds=[1, 3],
            preservation_state=PreservationState(
                artifact_count=1,
                total_size_bytes=1,
                inventory_sha256="0" * 64,
            ),
        )


def test_canonical_model_round_trip_is_byte_stable(tmp_path: Path) -> None:
    value = {"z": 1, "a": ["x", "y"]}
    first = canonical_json_bytes(value) + b"\n"
    path = tmp_path / "manifest.json"
    path.write_bytes(first)
    assert canonical_json_bytes(json.loads(path.read_text())) + b"\n" == first


def _published_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    source = tmp_path / "source.json"
    source.write_bytes(canonical_json_bytes({"evidence": "original"}) + b"\n")
    artifact = _artifact(
        path=source,
        root=tmp_path,
        artifact_role="test-evidence",
        milestone="M2",
        workspace_role="derivation-chain",
        preservation_class="required-causal-artifact",
    )
    inventory = [artifact.model_dump(mode="json")]
    core = PreservationCore(
        derivation_chain=[artifact],
        trust_assurance=[],
        campaign_assurance=[],
        external_evidence=[],
        excluded_material=[],
        selected_derivation_round=1,
        campaign_rounds=[1],
        preservation_state=PreservationState(
            artifact_count=1,
            total_size_bytes=source.stat().st_size,
            inventory_sha256=sha256_bytes(canonical_json_bytes(inventory)),
        ),
    )
    monkeypatch.setattr(
        preservation,
        "_settings",
        lambda _path: (tmp_path, {}, "1" * 64),
    )
    monkeypatch.setattr(preservation, "_build_core", lambda _root, _settings: core)
    workspace = tmp_path / "published"
    create_preservation_manifest(
        output=workspace,
        config_path=tmp_path / "preservation.yaml",
        verify_sources=False,
    )
    return workspace, source


def test_publication_is_byte_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, _source = _published_fixture(tmp_path, monkeypatch)
    second = tmp_path / "published-again"
    create_preservation_manifest(
        output=second,
        config_path=tmp_path / "preservation.yaml",
        verify_sources=False,
    )
    for name in ("preservation-manifest.json", "manifest.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_verifier_rejects_tampered_preservation_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _source = _published_fixture(tmp_path, monkeypatch)
    path = workspace / "preservation-manifest.json"
    value = json.loads(path.read_text())
    value["core"]["selected_derivation_round"] = 2
    path.chmod(0o640)
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    result = verify_preservation_manifest(
        workspace=workspace,
        config_path=tmp_path / "preservation.yaml",
        verify_sources=False,
    )
    assert result["status"] == "failed"
    assert "differs from reconstructed inventory" in result["errors"][0]


def test_verifier_rejects_tampered_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _source = _published_fixture(tmp_path, monkeypatch)
    path = workspace / "manifest.json"
    value = json.loads(path.read_text())
    value["config_sha256"] = "0" * 64
    path.chmod(0o640)
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    result = verify_preservation_manifest(
        workspace=workspace,
        config_path=tmp_path / "preservation.yaml",
        verify_sources=False,
    )
    assert result["status"] == "failed"
    assert "envelope differs from reconstruction" in result["errors"][0]


def test_verifier_rejects_unexpected_workspace_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _source = _published_fixture(tmp_path, monkeypatch)
    (workspace / "unexpected.json").write_text("{}\n")
    result = verify_preservation_manifest(
        workspace=workspace,
        config_path=tmp_path / "preservation.yaml",
        verify_sources=False,
    )
    assert result["status"] == "failed"
    assert result["errors"] == ["unexpected M8.1 workspace artifact set"]


def test_verifier_rejects_changed_source_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, source = _published_fixture(tmp_path, monkeypatch)
    source.write_bytes(canonical_json_bytes({"evidence": "tampered"}) + b"\n")
    result = verify_preservation_manifest(
        workspace=workspace,
        config_path=tmp_path / "preservation.yaml",
        verify_sources=False,
    )
    assert result["status"] == "failed"
    assert result["errors"] == ["preserved artifact mismatch: source.json"]
