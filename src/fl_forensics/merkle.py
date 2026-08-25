"""M8.2 deterministic Merkle-tree creation and verification."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .merkle_models import (
    MERKLE_ALGORITHM,
    MERKLE_STATE,
    MerkleCore,
    MerkleEnvelope,
    MerkleLeaf,
    MerkleLeafPayload,
    MerkleTreeManifest,
)
from .preservation import verify_preservation_manifest
from .preservation_models import PreservationManifest
from .storage import load_json, write_json_once

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class MerkleError(ValueError):
    """Raised when a deterministic Merkle commitment cannot be proven."""


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _settings(config_path: Path) -> tuple[Path, dict[str, Any], str]:
    value, digest = load_yaml(config_path)
    settings = value.get("merkle")
    if not isinstance(settings, dict):
        raise MerkleError("missing Merkle configuration")
    if settings.get("odd_node_rule") != "duplicate-last":
        raise MerkleError("unsupported Merkle odd-node rule")
    return config_path.resolve().parent.parent, settings, digest


def _leaf_digest(payload: MerkleLeafPayload) -> str:
    return sha256_bytes(
        LEAF_PREFIX + canonical_json_bytes(payload.model_dump(mode="json"))
    )


def _parent_digest(left: str, right: str) -> str:
    try:
        left_bytes = bytes.fromhex(left)
        right_bytes = bytes.fromhex(right)
    except ValueError as exc:
        raise MerkleError("Merkle child digest is not hexadecimal") from exc
    if len(left_bytes) != 32 or len(right_bytes) != 32:
        raise MerkleError("Merkle child digest is not SHA-256 sized")
    return sha256_bytes(NODE_PREFIX + left_bytes + right_bytes)


def _levels(leaf_digests: list[str]) -> list[list[str]]:
    if not leaf_digests:
        raise MerkleError("Merkle tree requires at least one leaf")
    levels = [list(leaf_digests)]
    current = list(leaf_digests)
    while len(current) > 1:
        working = current + [current[-1]] if len(current) % 2 else current
        current = [
            _parent_digest(working[index], working[index + 1])
            for index in range(0, len(working), 2)
        ]
        levels.append(current)
    return levels


def _preserved_artifacts(manifest: PreservationManifest) -> list[Any]:
    core = manifest.core
    return core.derivation_chain + core.trust_assurance + core.campaign_assurance


def _build_core(
    manifest: PreservationManifest, preservation_manifest_sha256: str
) -> MerkleCore:
    pending: list[tuple[str, MerkleLeafPayload]] = []
    for artifact in _preserved_artifacts(manifest):
        descriptor = artifact.model_dump(mode="json")
        payload = MerkleLeafPayload(
            leaf_kind="preserved-artifact",
            identity=artifact.artifact_id,
            relative_path=artifact.relative_path,
            content_sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            source_descriptor_sha256=digest_object(descriptor),
        )
        key = f"artifact:{artifact.relative_path}:{artifact.artifact_id}"
        pending.append((key, payload))
    for binding in manifest.core.external_evidence:
        descriptor = binding.model_dump(mode="json")
        descriptor_sha256 = digest_object(descriptor)
        identity = f"external-evidence-{descriptor_sha256[:24]}"
        payload = MerkleLeafPayload(
            leaf_kind="external-evidence-binding",
            identity=identity,
            relative_path=binding.relative_path,
            content_sha256=binding.sha256,
            size_bytes=binding.size_bytes,
            source_descriptor_sha256=descriptor_sha256,
        )
        key = f"external-evidence:{binding.relative_path}:{identity}"
        pending.append((key, payload))
    pending.sort(key=lambda item: item[0])
    keys = [key for key, _payload in pending]
    if len(keys) != len(set(keys)):
        raise MerkleError("Merkle source contains duplicate leaf keys")
    leaves = [
        MerkleLeaf(
            index=index,
            leaf_key=key,
            payload=payload,
            leaf_sha256=_leaf_digest(payload),
        )
        for index, (key, payload) in enumerate(pending)
    ]
    levels = _levels([leaf.leaf_sha256 for leaf in leaves])
    artifact_count = len(_preserved_artifacts(manifest))
    external_count = len(manifest.core.external_evidence)
    return MerkleCore(
        source_preservation_id=manifest.preservation_id,
        source_preservation_manifest_sha256=preservation_manifest_sha256,
        source_preservation_core_sha256=manifest.canonical_core_sha256,
        source_inventory_sha256=manifest.core.preservation_state.inventory_sha256,
        algorithm=MERKLE_ALGORITHM,
        artifact_leaf_count=artifact_count,
        external_evidence_leaf_count=external_count,
        leaf_count=len(leaves),
        level_count=len(levels),
        leaves=leaves,
        levels=levels,
        root_sha256=levels[-1][0],
    )


def _validated_source(
    root: Path, settings: dict[str, Any], *, verify_source: bool
) -> tuple[PreservationManifest, Path, str]:
    workspace = _resolve(root, str(settings["preservation_workspace"]))
    config_path = _resolve(root, str(settings["preservation_config"]))
    if verify_source:
        result = verify_preservation_manifest(
            workspace=workspace,
            config_path=config_path,
        )
        if result.get("status") != "verified":
            raise MerkleError(
                f"source M8.1 verification failed: {result.get('errors', [])}"
            )
    path = workspace / "preservation-manifest.json"
    manifest = PreservationManifest.model_validate(load_json(path))
    expected_core = digest_object(manifest.core.model_dump(mode="json"))
    if manifest.canonical_core_sha256 != expected_core:
        raise MerkleError("source preservation core digest mismatch")
    if manifest.preservation_id != f"m8-preservation-{expected_core[:24]}":
        raise MerkleError("source preservation identity mismatch")
    return manifest, path, sha256_file(path)


def _tree_manifest(
    source: PreservationManifest, source_sha256: str
) -> MerkleTreeManifest:
    core = _build_core(source, source_sha256)
    core_digest = digest_object(core.model_dump(mode="json"))
    return MerkleTreeManifest(
        tree_id=f"m8-merkle-tree-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
        assurance_state=MERKLE_STATE,
    )


def _envelope(
    *, tree: MerkleTreeManifest, tree_bytes: bytes, config_sha256: str
) -> MerkleEnvelope:
    return MerkleEnvelope(
        tree_id=tree.tree_id,
        merkle_tree_sha256=sha256_bytes(tree_bytes),
        canonical_core_sha256=tree.canonical_core_sha256,
        root_sha256=tree.core.root_sha256,
        source_preservation_id=tree.core.source_preservation_id,
        source_preservation_manifest_sha256=(
            tree.core.source_preservation_manifest_sha256
        ),
        implementation_sha256=sha256_file(Path(__file__)),
        config_sha256=config_sha256,
        assurance_state=MERKLE_STATE,
    )


def create_merkle_tree(
    *, output: Path, config_path: Path, verify_source: bool = True
) -> dict[str, Any]:
    root, settings, config_sha256 = _settings(config_path)
    source, _source_path, source_sha256 = _validated_source(
        root, settings, verify_source=verify_source
    )
    tree = _tree_manifest(source, source_sha256)
    tree_bytes = canonical_json_bytes(tree.model_dump(mode="json")) + b"\n"
    envelope = _envelope(
        tree=tree, tree_bytes=tree_bytes, config_sha256=config_sha256
    )
    write_json_once(output / "merkle-tree.json", tree.model_dump(mode="json"))
    write_json_once(output / "manifest.json", envelope.model_dump(mode="json"))
    return {
        "status": "merkle_committed",
        "tree_id": tree.tree_id,
        "root_sha256": tree.core.root_sha256,
        "leaf_count": tree.core.leaf_count,
        "level_count": tree.core.level_count,
        "source_preservation_id": tree.core.source_preservation_id,
        "workspace": str(output),
    }


def verify_merkle_tree(
    *, workspace: Path, config_path: Path, verify_source: bool = True
) -> dict[str, Any]:
    errors: list[str] = []
    tree: MerkleTreeManifest | None = None
    try:
        names = sorted(
            path.relative_to(workspace).as_posix()
            for path in workspace.rglob("*")
            if path.is_file()
        )
        if names != ["manifest.json", "merkle-tree.json"]:
            raise MerkleError("unexpected M8.2 workspace artifact set")
        tree_path = workspace / "merkle-tree.json"
        envelope_path = workspace / "manifest.json"
        tree = MerkleTreeManifest.model_validate(load_json(tree_path))
        MerkleEnvelope.model_validate(load_json(envelope_path))
        root, settings, config_sha256 = _settings(config_path)
        source, _source_path, source_sha256 = _validated_source(
            root, settings, verify_source=verify_source
        )
        expected_tree = _tree_manifest(source, source_sha256)
        expected_tree_bytes = (
            canonical_json_bytes(expected_tree.model_dump(mode="json")) + b"\n"
        )
        expected_envelope = _envelope(
            tree=expected_tree,
            tree_bytes=expected_tree_bytes,
            config_sha256=config_sha256,
        )
        if tree_path.read_bytes() != expected_tree_bytes:
            errors.append("Merkle tree differs from reconstructed commitment")
        expected_envelope_bytes = (
            canonical_json_bytes(expected_envelope.model_dump(mode="json")) + b"\n"
        )
        if envelope_path.read_bytes() != expected_envelope_bytes:
            errors.append("Merkle envelope differs from reconstruction")
    except (KeyError, MerkleError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "tree_id": tree.tree_id if tree else None,
        "root_sha256": tree.core.root_sha256 if tree else None,
        "leaf_count": tree.core.leaf_count if tree else 0,
        "source_recomputed": not errors,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
