"""Strict schemas for the M8.4 deterministic offline recovery export."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .models import HEX_256_PATTERN, StrictModel
from .preservation_models import ExternalEvidenceBinding

RECOVERY_STATE = "merkle-committed-time-anchored-recovery-exported"


class RecoveryEntry(StrictModel):
    archive_path: str
    source_relative_path: str
    entry_class: Literal["preserved-payload", "assurance-artifact"]
    sha256: str = Field(pattern=HEX_256_PATTERN)
    size_bytes: int = Field(ge=0)
    required: Literal[True] = True

    @field_validator("archive_path", "source_relative_path")
    @classmethod
    def _safe_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or value != path.as_posix():
            raise ValueError("recovery path is unsafe or non-canonical")
        if not value or value.startswith("./"):
            raise ValueError("recovery path is empty or ambiguous")
        return value


class RecoveryPackageCore(StrictModel):
    archive_format: Literal["deterministic-ustar-v1"] = "deterministic-ustar-v1"
    entry_order: Literal["archive-path-lexicographic"] = "archive-path-lexicographic"
    normalized_file_mode_octal: Literal["0440"] = "0440"
    normalized_uid: Literal[0] = 0
    normalized_gid: Literal[0] = 0
    normalized_mtime: Literal[0] = 0
    source_preservation_id: str
    source_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_merkle_tree_id: str
    source_merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_timestamp_id: str
    source_timestamp_response_sha256: str = Field(pattern=HEX_256_PATTERN)
    payload_entry_count: int = Field(gt=0)
    assurance_entry_count: int = Field(gt=0)
    entry_count: int = Field(gt=0)
    payload_size_bytes: int = Field(gt=0)
    assurance_size_bytes: int = Field(gt=0)
    entries: list[RecoveryEntry]
    external_evidence: list[ExternalEvidenceBinding]
    external_evidence_files_included: Literal[False] = False

    @model_validator(mode="after")
    def _counts_and_order_match(self) -> RecoveryPackageCore:
        if self.entry_count != len(self.entries):
            raise ValueError("recovery entry count mismatch")
        payload = [item for item in self.entries if item.entry_class == "preserved-payload"]
        assurance = [item for item in self.entries if item.entry_class == "assurance-artifact"]
        if self.payload_entry_count != len(payload):
            raise ValueError("recovery payload count mismatch")
        if self.assurance_entry_count != len(assurance):
            raise ValueError("recovery assurance count mismatch")
        if self.payload_size_bytes != sum(item.size_bytes for item in payload):
            raise ValueError("recovery payload size mismatch")
        if self.assurance_size_bytes != sum(item.size_bytes for item in assurance):
            raise ValueError("recovery assurance size mismatch")
        paths = [item.archive_path for item in self.entries]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("recovery entries are not unique and ordered")
        return self


class RecoveryPackageInventory(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_recovery_package_inventory"] = (
        "m8_recovery_package_inventory"
    )
    package_id: str
    core: RecoveryPackageCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)


class RecoveryManifestCore(StrictModel):
    package_id: str
    package_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    archive_name: Literal["recovery-export.tar"] = "recovery-export.tar"
    archive_sha256: str = Field(pattern=HEX_256_PATTERN)
    archive_size_bytes: int = Field(gt=0)
    archived_entry_count: int = Field(gt=0)
    payload_entry_count: int = Field(gt=0)
    assurance_entry_count: int = Field(gt=0)
    external_evidence_binding_count: int = Field(ge=0)
    source_preservation_id: str
    source_merkle_tree_id: str
    source_merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_timestamp_id: str
    assurance_state: Literal[
        "merkle-committed-time-anchored-recovery-exported"
    ] = RECOVERY_STATE


class RecoveryManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_recovery_export_manifest"] = (
        "m8_recovery_export_manifest"
    )
    recovery_id: str
    core: RecoveryManifestCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)


class RecoveryEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_recovery_export_envelope"] = (
        "m8_recovery_export_envelope"
    )
    recovery_id: str
    recovery_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    package_id: str
    package_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    archive_sha256: str = Field(pattern=HEX_256_PATTERN)
    assurance_state: Literal[
        "merkle-committed-time-anchored-recovery-exported"
    ] = RECOVERY_STATE
