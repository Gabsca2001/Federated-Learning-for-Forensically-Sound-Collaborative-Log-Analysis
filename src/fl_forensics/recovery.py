"""M8.4 deterministic recovery export and self-contained offline verifier."""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .anchor_models import TimestampManifest, TimestampManifestCore, TimestampProof
from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .merkle import _tree_manifest
from .merkle_models import MerkleEnvelope, MerkleTreeManifest
from .preservation_models import PreservationEnvelope, PreservationManifest
from .recovery_models import (
    RECOVERY_STATE,
    RecoveryEntry,
    RecoveryEnvelope,
    RecoveryManifest,
    RecoveryManifestCore,
    RecoveryPackageCore,
    RecoveryPackageInventory,
)
from .storage import load_json, write_json_once, write_once
from .timestamp_anchor import _anchor_subject, _proof, verify_timestamp_anchor

ASSURANCE_WORKSPACES = {
    "m8.1": "preservation_workspace",
    "m8.2": "merkle_workspace",
    "m8.3": "timestamp_workspace",
}
EXPECTED_ASSURANCE_PATHS = {
    "assurance/m8.1/manifest.json",
    "assurance/m8.1/preservation-manifest.json",
    "assurance/m8.2/manifest.json",
    "assurance/m8.2/merkle-tree.json",
    "assurance/m8.3/anchor-subject.json",
    "assurance/m8.3/manifest.json",
    "assurance/m8.3/timestamp-proof.json",
    "assurance/m8.3/timestamp-request.tsq",
    "assurance/m8.3/timestamp-response.tsr",
    "assurance/m8.3/trust-store.pem",
    "assurance/m8.3/tsa-certificates.pem",
}
EXPECTED_OUTPUT_FILES = [
    "manifest.json",
    "package-inventory.json",
    "recovery-export.tar",
    "recovery-manifest.json",
]
INTERNAL_INVENTORY_PATH = "package-inventory.json"


class RecoveryError(ValueError):
    """Raised when an offline recovery export cannot be proven."""


class _DigestWriter:
    def __init__(self) -> None:
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        self.digest.update(data)
        self.size += len(data)
        return len(data)


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _settings(config_path: Path) -> tuple[Path, dict[str, Any], str]:
    value, digest = load_yaml(config_path)
    settings = value.get("recovery")
    if not isinstance(settings, dict):
        raise RecoveryError("missing recovery configuration")
    if settings.get("archive_format") != "deterministic-ustar-v1":
        raise RecoveryError("unsupported recovery archive format")
    if settings.get("include_external_evidence_files") is not False:
        raise RecoveryError("M8.4 external evidence files must remain externally bound")
    return config_path.resolve().parent.parent, settings, digest


def _project_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise RecoveryError(f"recovery source is outside project root: {path}") from exc


def _source_entry(
    *, path: Path, root: Path, archive_path: str, entry_class: str
) -> RecoveryEntry:
    if not path.is_file() or path.is_symlink():
        raise RecoveryError(f"recovery source is missing, non-regular, or a symlink: {path}")
    return RecoveryEntry(
        archive_path=archive_path,
        source_relative_path=_project_relative(path, root),
        entry_class=entry_class,
        sha256=sha256_file(path),
        size_bytes=path.stat().st_size,
    )


def _validated_sources(
    root: Path, settings: dict[str, Any], *, verify_source: bool
) -> tuple[PreservationManifest, MerkleTreeManifest, TimestampManifest]:
    timestamp_workspace = _resolve(root, str(settings["timestamp_workspace"]))
    timestamp_config = _resolve(root, str(settings["timestamp_config"]))
    if verify_source:
        result = verify_timestamp_anchor(
            workspace=timestamp_workspace,
            config_path=timestamp_config,
        )
        if result.get("status") != "verified":
            raise RecoveryError(
                f"source M8.3 verification failed: {result.get('errors', [])}"
            )
    preservation = PreservationManifest.model_validate(
        load_json(_resolve(root, str(settings["preservation_workspace"])) / "preservation-manifest.json")
    )
    merkle = MerkleTreeManifest.model_validate(
        load_json(_resolve(root, str(settings["merkle_workspace"])) / "merkle-tree.json")
    )
    timestamp = TimestampManifest.model_validate(
        load_json(timestamp_workspace / "manifest.json")
    )
    return preservation, merkle, timestamp


def _entries(
    *, root: Path, settings: dict[str, Any], preservation: PreservationManifest
) -> tuple[list[RecoveryEntry], dict[str, Path]]:
    entries: list[RecoveryEntry] = []
    sources: dict[str, Path] = {}
    artifacts = (
        preservation.core.derivation_chain
        + preservation.core.trust_assurance
        + preservation.core.campaign_assurance
    )
    for artifact in artifacts:
        source = root / artifact.relative_path
        archive_path = f"payload/{artifact.relative_path}"
        entry = _source_entry(
            path=source,
            root=root,
            archive_path=archive_path,
            entry_class="preserved-payload",
        )
        if entry.sha256 != artifact.sha256 or entry.size_bytes != artifact.size_bytes:
            raise RecoveryError(f"payload differs from M8.1: {artifact.relative_path}")
        entries.append(entry)
        sources[archive_path] = source
    for label, setting_name in ASSURANCE_WORKSPACES.items():
        workspace = _resolve(root, str(settings[setting_name]))
        if not workspace.is_dir():
            raise RecoveryError(f"assurance workspace is missing: {workspace}")
        for source in sorted(path for path in workspace.rglob("*") if path.is_file()):
            relative = source.relative_to(workspace).as_posix()
            archive_path = f"assurance/{label}/{relative}"
            entries.append(
                _source_entry(
                    path=source,
                    root=root,
                    archive_path=archive_path,
                    entry_class="assurance-artifact",
                )
            )
            sources[archive_path] = source
    entries.sort(key=lambda item: item.archive_path)
    paths = [item.archive_path for item in entries]
    if len(paths) != len(set(paths)):
        raise RecoveryError("recovery export contains duplicate archive paths")
    return entries, sources


def _package_inventory(
    *,
    entries: list[RecoveryEntry],
    preservation: PreservationManifest,
    merkle: MerkleTreeManifest,
    timestamp: TimestampManifest,
) -> RecoveryPackageInventory:
    payload = [item for item in entries if item.entry_class == "preserved-payload"]
    assurance = [item for item in entries if item.entry_class == "assurance-artifact"]
    timestamp_response = next(
        item for item in assurance if item.archive_path == "assurance/m8.3/timestamp-response.tsr"
    )
    core = RecoveryPackageCore(
        source_preservation_id=preservation.preservation_id,
        source_inventory_sha256=preservation.core.preservation_state.inventory_sha256,
        source_merkle_tree_id=merkle.tree_id,
        source_merkle_root_sha256=merkle.core.root_sha256,
        source_timestamp_id=timestamp.timestamp_id,
        source_timestamp_response_sha256=timestamp_response.sha256,
        payload_entry_count=len(payload),
        assurance_entry_count=len(assurance),
        entry_count=len(entries),
        payload_size_bytes=sum(item.size_bytes for item in payload),
        assurance_size_bytes=sum(item.size_bytes for item in assurance),
        entries=entries,
        external_evidence=preservation.core.external_evidence,
        external_evidence_files_included=False,
    )
    core_digest = digest_object(core.model_dump(mode="json"))
    return RecoveryPackageInventory(
        package_id=f"m8-recovery-package-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
    )


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mode = 0o440
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.type = tarfile.REGTYPE
    return info


def _write_tar(
    handle: BinaryIO | _DigestWriter,
    *,
    entries: list[RecoveryEntry],
    sources: dict[str, Path],
    inventory_bytes: bytes,
) -> None:
    items = [(item.archive_path, item, None) for item in entries]
    items.append((INTERNAL_INVENTORY_PATH, None, inventory_bytes))
    items.sort(key=lambda item: item[0])
    with tarfile.open(fileobj=handle, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
        for name, entry, inline in items:
            if inline is not None:
                with tempfile.SpooledTemporaryFile() as source:
                    source.write(inline)
                    source.seek(0)
                    archive.addfile(_tar_info(name, len(inline)), source)
                continue
            assert entry is not None
            with sources[entry.archive_path].open("rb") as source:
                archive.addfile(_tar_info(name, entry.size_bytes), source)


def _publish_archive(
    path: Path,
    *,
    entries: list[RecoveryEntry],
    sources: dict[str, Path],
    inventory_bytes: bytes,
) -> tuple[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"recovery archive already exists: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            _write_tar(
                handle,
                entries=entries,
                sources=sources,
                inventory_bytes=inventory_bytes,
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o440)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return sha256_file(path), path.stat().st_size


def _manifest_core(
    *,
    package: RecoveryPackageInventory,
    inventory_bytes: bytes,
    archive_sha256: str,
    archive_size: int,
) -> RecoveryManifestCore:
    return RecoveryManifestCore(
        package_id=package.package_id,
        package_inventory_sha256=sha256_bytes(inventory_bytes),
        archive_sha256=archive_sha256,
        archive_size_bytes=archive_size,
        archived_entry_count=package.core.entry_count + 1,
        payload_entry_count=package.core.payload_entry_count,
        assurance_entry_count=package.core.assurance_entry_count,
        external_evidence_binding_count=len(package.core.external_evidence),
        source_preservation_id=package.core.source_preservation_id,
        source_merkle_tree_id=package.core.source_merkle_tree_id,
        source_merkle_root_sha256=package.core.source_merkle_root_sha256,
        source_timestamp_id=package.core.source_timestamp_id,
        assurance_state=RECOVERY_STATE,
    )


def _manifest(
    *,
    package: RecoveryPackageInventory,
    inventory_bytes: bytes,
    archive_sha256: str,
    archive_size: int,
    config_sha256: str,
) -> RecoveryManifest:
    core = _manifest_core(
        package=package,
        inventory_bytes=inventory_bytes,
        archive_sha256=archive_sha256,
        archive_size=archive_size,
    )
    core_digest = digest_object(core.model_dump(mode="json"))
    return RecoveryManifest(
        recovery_id=f"m8-recovery-export-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
        implementation_sha256=sha256_file(Path(__file__)),
        config_sha256=config_sha256,
    )


def _envelope(
    *, manifest: RecoveryManifest, manifest_bytes: bytes
) -> RecoveryEnvelope:
    return RecoveryEnvelope(
        recovery_id=manifest.recovery_id,
        recovery_manifest_sha256=sha256_bytes(manifest_bytes),
        package_id=manifest.core.package_id,
        package_inventory_sha256=manifest.core.package_inventory_sha256,
        archive_sha256=manifest.core.archive_sha256,
        assurance_state=RECOVERY_STATE,
    )


def create_recovery_export(
    *, output: Path, config_path: Path, verify_source: bool = True
) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"recovery workspace is not empty: {output}")
    root, settings, config_sha256 = _settings(config_path)
    preservation, merkle, timestamp = _validated_sources(
        root, settings, verify_source=verify_source
    )
    entries, sources = _entries(
        root=root, settings=settings, preservation=preservation
    )
    package = _package_inventory(
        entries=entries,
        preservation=preservation,
        merkle=merkle,
        timestamp=timestamp,
    )
    inventory_bytes = canonical_json_bytes(package.model_dump(mode="json")) + b"\n"
    archive_sha256, archive_size = _publish_archive(
        output / "recovery-export.tar",
        entries=entries,
        sources=sources,
        inventory_bytes=inventory_bytes,
    )
    manifest = _manifest(
        package=package,
        inventory_bytes=inventory_bytes,
        archive_sha256=archive_sha256,
        archive_size=archive_size,
        config_sha256=config_sha256,
    )
    manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json")) + b"\n"
    envelope = _envelope(manifest=manifest, manifest_bytes=manifest_bytes)
    write_once(output / "package-inventory.json", inventory_bytes)
    write_once(output / "recovery-manifest.json", manifest_bytes)
    write_json_once(output / "manifest.json", envelope.model_dump(mode="json"))
    return {
        "status": "recovery_exported",
        "recovery_id": manifest.recovery_id,
        "package_id": package.package_id,
        "archive_sha256": archive_sha256,
        "archive_size_bytes": archive_size,
        "payload_entry_count": package.core.payload_entry_count,
        "assurance_entry_count": package.core.assurance_entry_count,
        "external_evidence_binding_count": len(package.core.external_evidence),
        "workspace": str(output),
    }


def _verify_tar(
    archive_path: Path, package: RecoveryPackageInventory, inventory_bytes: bytes
) -> dict[str, bytes]:
    expected = {item.archive_path: item for item in package.core.entries}
    expected_names = sorted([*expected, INTERNAL_INVENTORY_PATH])
    assurance: dict[str, bytes] = {}
    with tarfile.open(archive_path, mode="r:") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if names != expected_names or len(names) != len(set(names)):
            raise RecoveryError("recovery archive member set or order is invalid")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not member.isfile():
                raise RecoveryError(f"unsafe recovery archive member: {member.name}")
            if (
                member.mode != 0o440
                or member.uid != 0
                or member.gid != 0
                or member.mtime != 0
                or member.uname
                or member.gname
            ):
                raise RecoveryError(f"non-canonical recovery header: {member.name}")
            source = archive.extractfile(member)
            if source is None:
                raise RecoveryError(
                    f"recovery archive member is unreadable: {member.name}"
                )
            if member.name == INTERNAL_INVENTORY_PATH:
                value = source.read()
                if value != inventory_bytes:
                    raise RecoveryError("internal package inventory differs from outer copy")
                continue
            entry = expected[member.name]
            digest = hashlib.sha256()
            size = 0
            chunks: list[bytes] | None = (
                [] if member.name.startswith("assurance/") else None
            )
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
                if chunks is not None:
                    chunks.append(chunk)
            if size != entry.size_bytes or digest.hexdigest() != entry.sha256:
                raise RecoveryError(f"recovery member digest mismatch: {member.name}")
            if chunks is not None:
                assurance[member.name] = b"".join(chunks)
    return assurance


def _verify_offline_chain(
    package: RecoveryPackageInventory, assurance: dict[str, bytes]
) -> None:
    if set(assurance) != EXPECTED_ASSURANCE_PATHS:
        raise RecoveryError("offline assurance artifact set is invalid")
    preservation_bytes = assurance["assurance/m8.1/preservation-manifest.json"]
    preservation = PreservationManifest.model_validate(
        json.loads(preservation_bytes)
    )
    canonical_preservation = (
        canonical_json_bytes(preservation.model_dump(mode="json")) + b"\n"
    )
    preservation_core = digest_object(preservation.core.model_dump(mode="json"))
    if (
        preservation_bytes != canonical_preservation
        or preservation.canonical_core_sha256 != preservation_core
        or preservation.preservation_id != f"m8-preservation-{preservation_core[:24]}"
    ):
        raise RecoveryError("offline M8.1 preservation identity is invalid")
    preservation_envelope_bytes = assurance["assurance/m8.1/manifest.json"]
    preservation_envelope = PreservationEnvelope.model_validate(
        json.loads(preservation_envelope_bytes)
    )
    canonical_preservation_envelope = (
        canonical_json_bytes(preservation_envelope.model_dump(mode="json")) + b"\n"
    )
    if (
        preservation_envelope_bytes != canonical_preservation_envelope
        or preservation_envelope.preservation_id != preservation.preservation_id
        or preservation_envelope.preservation_manifest_sha256
        != sha256_bytes(preservation_bytes)
        or preservation_envelope.canonical_core_sha256
        != preservation.canonical_core_sha256
    ):
        raise RecoveryError("offline M8.1 envelope binding is invalid")
    artifacts = (
        preservation.core.derivation_chain
        + preservation.core.trust_assurance
        + preservation.core.campaign_assurance
    )
    expected_payload = {
        f"payload/{item.relative_path}": (
            item.relative_path,
            item.sha256,
            item.size_bytes,
        )
        for item in artifacts
    }
    published_payload = {
        item.archive_path: (item.source_relative_path, item.sha256, item.size_bytes)
        for item in package.core.entries
        if item.entry_class == "preserved-payload"
    }
    if published_payload != expected_payload:
        raise RecoveryError("offline payload inventory differs from M8.1")
    if package.core.external_evidence != preservation.core.external_evidence:
        raise RecoveryError("offline external-evidence bindings differ from M8.1")

    tree_bytes = assurance["assurance/m8.2/merkle-tree.json"]
    tree = MerkleTreeManifest.model_validate(json.loads(tree_bytes))
    expected_tree = _tree_manifest(preservation, sha256_bytes(preservation_bytes))
    expected_tree_bytes = canonical_json_bytes(expected_tree.model_dump(mode="json")) + b"\n"
    if tree_bytes != expected_tree_bytes:
        raise RecoveryError("offline M8.2 tree differs from reconstructed M8.1")
    merkle_envelope_bytes = assurance["assurance/m8.2/manifest.json"]
    merkle_envelope = MerkleEnvelope.model_validate(
        json.loads(merkle_envelope_bytes)
    )
    canonical_merkle_envelope = (
        canonical_json_bytes(merkle_envelope.model_dump(mode="json")) + b"\n"
    )
    if (
        merkle_envelope_bytes != canonical_merkle_envelope
        or merkle_envelope.tree_id != tree.tree_id
        or merkle_envelope.merkle_tree_sha256 != sha256_bytes(tree_bytes)
        or merkle_envelope.canonical_core_sha256 != tree.canonical_core_sha256
        or merkle_envelope.root_sha256 != tree.core.root_sha256
        or merkle_envelope.source_preservation_id != preservation.preservation_id
        or merkle_envelope.source_preservation_manifest_sha256
        != sha256_bytes(preservation_bytes)
    ):
        raise RecoveryError("offline M8.2 envelope binding is invalid")

    anchor_bytes = assurance["assurance/m8.3/anchor-subject.json"]
    expected_anchor = _anchor_subject(tree, sha256_bytes(tree_bytes))
    expected_anchor_bytes = canonical_json_bytes(expected_anchor.model_dump(mode="json")) + b"\n"
    if anchor_bytes != expected_anchor_bytes:
        raise RecoveryError("offline M8.3 anchor subject differs from M8.2")
    proof_bytes = assurance["assurance/m8.3/timestamp-proof.json"]
    stored_proof = TimestampProof.model_validate(json.loads(proof_bytes))
    expected_proof = _proof(
        anchor=expected_anchor,
        subject_bytes=anchor_bytes,
        request_bytes=assurance["assurance/m8.3/timestamp-request.tsq"],
        response_bytes=assurance["assurance/m8.3/timestamp-response.tsr"],
        certificates=assurance["assurance/m8.3/tsa-certificates.pem"],
        trust_store=assurance["assurance/m8.3/trust-store.pem"],
        tsa_url=stored_proof.tsa_url,
    )
    expected_proof_bytes = (
        canonical_json_bytes(expected_proof.model_dump(mode="json")) + b"\n"
    )
    if proof_bytes != expected_proof_bytes:
        raise RecoveryError("offline M8.3 proof differs from RFC 3161 verification")
    timestamp_manifest_bytes = assurance["assurance/m8.3/manifest.json"]
    timestamp_manifest = TimestampManifest.model_validate(
        json.loads(timestamp_manifest_bytes)
    )
    canonical_timestamp_manifest = (
        canonical_json_bytes(timestamp_manifest.model_dump(mode="json")) + b"\n"
    )
    expected_timestamp_core = TimestampManifestCore(
        anchor_id=expected_anchor.anchor_id,
        anchor_subject_sha256=sha256_bytes(anchor_bytes),
        proof_id=expected_proof.proof_id,
        timestamp_proof_sha256=sha256_bytes(proof_bytes),
        timestamp_request_sha256=expected_proof.timestamp_request_sha256,
        timestamp_response_sha256=expected_proof.timestamp_response_sha256,
        tsa_certificates_sha256=expected_proof.tsa_certificates_sha256,
        trust_store_sha256=expected_proof.trust_store_sha256,
        merkle_tree_id=tree.tree_id,
        merkle_root_sha256=tree.core.root_sha256,
        tsa_url=expected_proof.tsa_url,
    )
    timestamp_core = digest_object(timestamp_manifest.core.model_dump(mode="json"))
    if (
        timestamp_manifest_bytes != canonical_timestamp_manifest
        or timestamp_manifest.core != expected_timestamp_core
        or timestamp_manifest.canonical_core_sha256 != timestamp_core
        or timestamp_manifest.timestamp_id != f"m8-timestamp-anchor-{timestamp_core[:24]}"
    ):
        raise RecoveryError("offline M8.3 manifest binding is invalid")
    if (
        package.core.source_preservation_id != preservation.preservation_id
        or package.core.source_inventory_sha256
        != preservation.core.preservation_state.inventory_sha256
        or package.core.source_merkle_tree_id != tree.tree_id
        or package.core.source_merkle_root_sha256 != tree.core.root_sha256
        or package.core.source_timestamp_id != timestamp_manifest.timestamp_id
        or package.core.source_timestamp_response_sha256
        != expected_proof.timestamp_response_sha256
    ):
        raise RecoveryError("recovery package source lineage is invalid")


def verify_recovery_export(*, workspace: Path) -> dict[str, Any]:
    errors: list[str] = []
    manifest: RecoveryManifest | None = None
    package: RecoveryPackageInventory | None = None
    try:
        names = sorted(
            path.relative_to(workspace).as_posix()
            for path in workspace.rglob("*")
            if path.is_file()
        )
        if names != EXPECTED_OUTPUT_FILES:
            raise RecoveryError("unexpected M8.4 workspace artifact set")
        inventory_path = workspace / "package-inventory.json"
        inventory_bytes = inventory_path.read_bytes()
        package = RecoveryPackageInventory.model_validate(load_json(inventory_path))
        canonical_inventory = (
            canonical_json_bytes(package.model_dump(mode="json")) + b"\n"
        )
        package_core = digest_object(package.core.model_dump(mode="json"))
        if (
            inventory_bytes != canonical_inventory
            or package.canonical_core_sha256 != package_core
            or package.package_id != f"m8-recovery-package-{package_core[:24]}"
        ):
            raise RecoveryError("recovery package identity is invalid")
        archive_path = workspace / "recovery-export.tar"
        assurance = _verify_tar(archive_path, package, inventory_bytes)
        _verify_offline_chain(package, assurance)
        manifest_path = workspace / "recovery-manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        manifest = RecoveryManifest.model_validate(load_json(manifest_path))
        expected_core = _manifest_core(
            package=package,
            inventory_bytes=inventory_bytes,
            archive_sha256=sha256_file(archive_path),
            archive_size=archive_path.stat().st_size,
        )
        canonical_manifest = (
            canonical_json_bytes(manifest.model_dump(mode="json")) + b"\n"
        )
        manifest_core = digest_object(manifest.core.model_dump(mode="json"))
        if (
            manifest_bytes != canonical_manifest
            or manifest.core != expected_core
            or manifest.canonical_core_sha256 != manifest_core
            or manifest.recovery_id
            != f"m8-recovery-export-{manifest_core[:24]}"
        ):
            raise RecoveryError("recovery manifest identity or content is invalid")
        envelope_path = workspace / "manifest.json"
        envelope_bytes = envelope_path.read_bytes()
        RecoveryEnvelope.model_validate(load_json(envelope_path))
        expected_envelope = _envelope(
            manifest=manifest,
            manifest_bytes=manifest_bytes,
        )
        if envelope_bytes != (
            canonical_json_bytes(expected_envelope.model_dump(mode="json")) + b"\n"
        ):
            raise RecoveryError("recovery envelope differs from reconstruction")
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        RecoveryError,
        tarfile.TarError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "recovery_id": manifest.recovery_id if manifest else None,
        "package_id": package.package_id if package else None,
        "payload_entry_count": package.core.payload_entry_count if package else 0,
        "assurance_entry_count": package.core.assurance_entry_count if package else 0,
        "offline_payload_verified": not errors,
        "offline_merkle_recomputed": not errors,
        "offline_timestamp_verified": not errors,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
