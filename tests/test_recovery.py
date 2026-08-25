from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_file
from fl_forensics.recovery import RecoveryError, _tar_info, _verify_tar, _write_tar
from fl_forensics.recovery_models import (
    RecoveryEntry,
    RecoveryPackageCore,
    RecoveryPackageInventory,
)


def _entry(path: Path, root: Path, archive_path: str) -> RecoveryEntry:
    return RecoveryEntry(
        archive_path=archive_path,
        source_relative_path=path.relative_to(root).as_posix(),
        entry_class="preserved-payload",
        sha256=sha256_file(path),
        size_bytes=path.stat().st_size,
    )


def _fixture(tmp_path: Path) -> tuple[list[RecoveryEntry], dict[str, Path], bytes]:
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    assurance = tmp_path / "assurance.json"
    first.write_bytes(b"alpha\n")
    second.write_bytes(b"beta\n")
    assurance.write_bytes(b"test")
    entries = sorted(
        [
            _entry(first, tmp_path, "payload/a.json"),
            _entry(second, tmp_path, "payload/b.json"),
            RecoveryEntry(
                archive_path="assurance/m8.1/manifest.json",
                source_relative_path="assurance.json",
                entry_class="assurance-artifact",
                sha256=sha256_file(assurance),
                size_bytes=4,
            ),
        ],
        key=lambda item: item.archive_path,
    )
    package_core = RecoveryPackageCore(
        source_preservation_id="preservation",
        source_inventory_sha256="1" * 64,
        source_merkle_tree_id="tree",
        source_merkle_root_sha256="2" * 64,
        source_timestamp_id="timestamp",
        source_timestamp_response_sha256="3" * 64,
        payload_entry_count=2,
        assurance_entry_count=1,
        entry_count=3,
        payload_size_bytes=first.stat().st_size + second.stat().st_size,
        assurance_size_bytes=4,
        entries=entries,
        external_evidence=[],
    )
    digest = digest_object(package_core.model_dump(mode="json"))
    package = RecoveryPackageInventory(
        package_id=f"m8-recovery-package-{digest[:24]}",
        core=package_core,
        canonical_core_sha256=digest,
    )
    inventory = canonical_json_bytes(package.model_dump(mode="json")) + b"\n"
    sources = {
        "payload/a.json": first,
        "payload/b.json": second,
        "assurance/m8.1/manifest.json": assurance,
    }
    return entries, sources, inventory


def test_tar_header_is_canonical() -> None:
    info = _tar_info("payload/a.json", 5)
    assert info.mode == 0o440
    assert info.uid == info.gid == info.mtime == 0
    assert info.uname == info.gname == ""
    assert info.isfile()


def test_tar_is_byte_deterministic(tmp_path: Path) -> None:
    entries, sources, inventory = _fixture(tmp_path)
    first = io.BytesIO()
    second = io.BytesIO()
    _write_tar(first, entries=entries, sources=sources, inventory_bytes=inventory)
    _write_tar(second, entries=entries, sources=sources, inventory_bytes=inventory)
    assert first.getvalue() == second.getvalue()


def test_tar_members_are_ordered_and_regular(tmp_path: Path) -> None:
    entries, sources, inventory = _fixture(tmp_path)
    output = tmp_path / "recovery.tar"
    with output.open("wb") as handle:
        _write_tar(handle, entries=entries, sources=sources, inventory_bytes=inventory)
    with tarfile.open(output, "r:") as archive:
        members = archive.getmembers()
    assert [item.name for item in members] == sorted(
        [item.archive_path for item in entries] + ["package-inventory.json"]
    )
    assert all(item.isfile() for item in members)


def test_archive_verifier_accepts_exact_members(tmp_path: Path) -> None:
    entries, sources, inventory = _fixture(tmp_path)
    output = tmp_path / "recovery.tar"
    with output.open("wb") as handle:
        _write_tar(handle, entries=entries, sources=sources, inventory_bytes=inventory)
    package = RecoveryPackageInventory.model_validate_json(inventory)
    assurance = _verify_tar(output, package, inventory)
    assert assurance == {"assurance/m8.1/manifest.json": b"test"}


def test_archive_verifier_rejects_changed_member(tmp_path: Path) -> None:
    entries, sources, inventory = _fixture(tmp_path)
    sources["payload/a.json"].write_bytes(b"changed\n")
    output = tmp_path / "recovery.tar"
    with output.open("wb") as handle:
        _write_tar(handle, entries=entries, sources=sources, inventory_bytes=inventory)
    package = RecoveryPackageInventory.model_validate_json(inventory)
    with pytest.raises(RecoveryError, match="member digest mismatch"):
        _verify_tar(output, package, inventory)


def test_archive_verifier_rejects_unexpected_member(tmp_path: Path) -> None:
    _entries, _sources, inventory = _fixture(tmp_path)
    output = tmp_path / "recovery.tar"
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(_tar_info("unexpected.json", 0), io.BytesIO())
    package = RecoveryPackageInventory.model_validate_json(inventory)
    with pytest.raises(RecoveryError, match="member set or order"):
        _verify_tar(output, package, inventory)


@pytest.mark.parametrize(
    "path",
    ["../secret.pem", "/absolute/file", "./ambiguous.json"],
)
def test_recovery_entry_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValueError):
        RecoveryEntry(
            archive_path=path,
            source_relative_path="source",
            entry_class="preserved-payload",
            sha256="0" * 64,
            size_bytes=1,
        )


def test_recovery_entry_rejects_unsafe_source_path() -> None:
    with pytest.raises(ValueError):
        RecoveryEntry(
            archive_path="payload/safe.json",
            source_relative_path="../outside.json",
            entry_class="preserved-payload",
            sha256="0" * 64,
            size_bytes=1,
        )


def test_archive_verifier_rejects_noncanonical_owner(tmp_path: Path) -> None:
    entries, sources, inventory = _fixture(tmp_path)
    values = {
        entry.archive_path: sources[entry.archive_path].read_bytes()
        for entry in entries
    }
    values["package-inventory.json"] = inventory
    output = tmp_path / "recovery.tar"
    with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(values):
            value = values[name]
            info = _tar_info(name, len(value))
            if name == "payload/a.json":
                info.uname = "owner"
            archive.addfile(info, io.BytesIO(value))
    package = RecoveryPackageInventory.model_validate_json(inventory)
    with pytest.raises(RecoveryError, match="non-canonical recovery header"):
        _verify_tar(output, package, inventory)
