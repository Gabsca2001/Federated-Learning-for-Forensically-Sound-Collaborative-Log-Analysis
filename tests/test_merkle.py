from __future__ import annotations

import json
from pathlib import Path

import pytest

from fl_forensics import merkle
from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_bytes
from fl_forensics.merkle import (
    LEAF_PREFIX,
    NODE_PREFIX,
    _build_core,
    _leaf_digest,
    _levels,
    create_merkle_tree,
    verify_merkle_tree,
)
from fl_forensics.merkle_models import MerkleLeafPayload
from fl_forensics.preservation_models import (
    ExternalEvidenceBinding,
    PreservationCore,
    PreservationManifest,
    PreservationState,
    PreservedArtifact,
)


def _artifact(identity: str, path: str, digest: str) -> PreservedArtifact:
    return PreservedArtifact(
        artifact_id=identity,
        artifact_role="test-evidence",
        milestone="M2",
        workspace_role="derivation-chain",
        relative_path=path,
        sha256=digest,
        size_bytes=10,
        preservation_class="required-causal-artifact",
    )


def _source_manifest(*, reverse: bool = False) -> PreservationManifest:
    artifacts = [
        _artifact("artifact-b", "b.json", "b" * 64),
        _artifact("artifact-a", "a.json", "a" * 64),
    ]
    if reverse:
        artifacts.reverse()
    external = ExternalEvidenceBinding(
        relative_path="raw/source.csv",
        sha256="c" * 64,
        size_bytes=25,
        binding_source="artifacts/m2/manifest.json",
    )
    inventory = [item.model_dump(mode="json") for item in artifacts]
    core = PreservationCore(
        derivation_chain=artifacts,
        trust_assurance=[],
        campaign_assurance=[],
        external_evidence=[external],
        excluded_material=[],
        selected_derivation_round=1,
        campaign_rounds=[1],
        preservation_state=PreservationState(
            artifact_count=2,
            total_size_bytes=20,
            inventory_sha256=sha256_bytes(canonical_json_bytes(inventory)),
        ),
    )
    core_digest = digest_object(core.model_dump(mode="json"))
    return PreservationManifest(
        preservation_id=f"m8-preservation-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
    )


def test_leaf_and_parent_hash_use_domain_separation() -> None:
    payload = MerkleLeafPayload(
        leaf_kind="preserved-artifact",
        identity="artifact-a",
        relative_path="a.json",
        content_sha256="a" * 64,
        size_bytes=10,
        source_descriptor_sha256="b" * 64,
    )
    expected_leaf = sha256_bytes(
        LEAF_PREFIX + canonical_json_bytes(payload.model_dump(mode="json"))
    )
    assert _leaf_digest(payload) == expected_leaf
    expected_parent = sha256_bytes(
        NODE_PREFIX + bytes.fromhex(expected_leaf) + bytes.fromhex(expected_leaf)
    )
    assert _levels([expected_leaf]) == [[expected_leaf]]
    assert _levels([expected_leaf, expected_leaf])[-1] == [expected_parent]


def test_odd_level_duplicates_last_digest() -> None:
    leaves = ["1" * 64, "2" * 64, "3" * 64]
    levels = _levels(leaves)
    expected_right = sha256_bytes(
        NODE_PREFIX + bytes.fromhex(leaves[2]) + bytes.fromhex(leaves[2])
    )
    assert levels[1][1] == expected_right
    assert len(levels[-1]) == 1


def test_leaf_order_is_independent_of_source_list_order() -> None:
    first = _build_core(_source_manifest(), "d" * 64)
    second = _build_core(_source_manifest(reverse=True), "d" * 64)
    assert first.root_sha256 == second.root_sha256
    assert first.leaves == second.leaves
    assert [leaf.payload.relative_path for leaf in first.leaves] == [
        "a.json",
        "b.json",
        "raw/source.csv",
    ]


def test_changed_content_digest_changes_root() -> None:
    first = _source_manifest()
    second_artifact = _artifact("artifact-b", "b.json", "f" * 64)
    second_core = first.core.model_copy(
        update={
            "derivation_chain": [second_artifact, first.core.derivation_chain[1]]
        }
    )
    second_digest = digest_object(second_core.model_dump(mode="json"))
    second = PreservationManifest(
        preservation_id=f"m8-preservation-{second_digest[:24]}",
        core=second_core,
        canonical_core_sha256=second_digest,
    )
    assert _build_core(first, "d" * 64).root_sha256 != _build_core(
        second, "d" * 64
    ).root_sha256


def _published_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, PreservationManifest]:
    source = _source_manifest()
    source_path = tmp_path / "preservation-manifest.json"
    source_path.write_bytes(canonical_json_bytes(source.model_dump(mode="json")) + b"\n")
    source_sha256 = sha256_bytes(source_path.read_bytes())
    monkeypatch.setattr(
        merkle,
        "_settings",
        lambda _path: (
            tmp_path,
            {
                "preservation_workspace": "source",
                "preservation_config": "preservation.yaml",
                "odd_node_rule": "duplicate-last",
            },
            "1" * 64,
        ),
    )
    monkeypatch.setattr(
        merkle,
        "_validated_source",
        lambda _root, _settings, verify_source: (
            source,
            source_path,
            source_sha256,
        ),
    )
    workspace = tmp_path / "published"
    create_merkle_tree(
        output=workspace,
        config_path=tmp_path / "merkle.yaml",
        verify_source=False,
    )
    return workspace, source


def test_publication_is_byte_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, _source = _published_fixture(tmp_path, monkeypatch)
    second = tmp_path / "published-again"
    create_merkle_tree(
        output=second,
        config_path=tmp_path / "merkle.yaml",
        verify_source=False,
    )
    for name in ("merkle-tree.json", "manifest.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_verifier_rejects_tampered_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _source = _published_fixture(tmp_path, monkeypatch)
    path = workspace / "merkle-tree.json"
    value = json.loads(path.read_text())
    value["core"]["root_sha256"] = "0" * 64
    value["core"]["levels"][-1] = ["0" * 64]
    path.chmod(0o640)
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    result = verify_merkle_tree(
        workspace=workspace,
        config_path=tmp_path / "merkle.yaml",
        verify_source=False,
    )
    assert result["status"] == "failed"
    assert "differs from reconstructed commitment" in result["errors"][0]


def test_verifier_rejects_tampered_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _source = _published_fixture(tmp_path, monkeypatch)
    path = workspace / "manifest.json"
    value = json.loads(path.read_text())
    value["root_sha256"] = "0" * 64
    path.chmod(0o640)
    path.write_bytes(canonical_json_bytes(value) + b"\n")
    result = verify_merkle_tree(
        workspace=workspace,
        config_path=tmp_path / "merkle.yaml",
        verify_source=False,
    )
    assert result["status"] == "failed"
    assert "envelope differs from reconstruction" in result["errors"][0]


def test_verifier_rejects_unexpected_workspace_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _source = _published_fixture(tmp_path, monkeypatch)
    (workspace / "unexpected.json").write_text("{}\n")
    result = verify_merkle_tree(
        workspace=workspace,
        config_path=tmp_path / "merkle.yaml",
        verify_source=False,
    )
    assert result["status"] == "failed"
    assert result["errors"] == ["unexpected M8.2 workspace artifact set"]


def test_source_verification_failure_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _source = _published_fixture(tmp_path, monkeypatch)

    def reject_source(_root: Path, _settings: dict, *, verify_source: bool):
        raise merkle.MerkleError("source M8.1 verification failed")

    monkeypatch.setattr(merkle, "_validated_source", reject_source)
    result = verify_merkle_tree(
        workspace=workspace,
        config_path=tmp_path / "merkle.yaml",
        verify_source=True,
    )
    assert result["status"] == "failed"
    assert result["errors"] == ["source M8.1 verification failed"]
