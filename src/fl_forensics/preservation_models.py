"""Strict schemas for the M8.1 content-addressed preservation inventory."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, StrictModel

PRESERVATION_PROFILE = (
    "content-addressed-not-merkle-committed-not-time-anchored-"
    "not-recovery-exported"
)


class PreservedArtifact(StrictModel):
    artifact_id: str
    artifact_role: str
    milestone: str
    workspace_role: str
    relative_path: str
    sha256: str = Field(pattern=HEX_256_PATTERN)
    size_bytes: int = Field(ge=0)
    preservation_class: str
    required: bool = True
    upstream_dependencies: list[str] = Field(default_factory=list)
    source_verification: dict[str, Any] = Field(default_factory=dict)
    campaign_references: list[str] = Field(default_factory=list)


class ExternalEvidenceBinding(StrictModel):
    relative_path: str
    sha256: str = Field(pattern=HEX_256_PATTERN)
    size_bytes: int = Field(gt=0)
    binding_source: str


class ExcludedMaterial(StrictModel):
    pattern: str
    reason: str
    must_not_be_exported: Literal[True] = True


class PreservationState(StrictModel):
    inventory_algorithm: Literal["lexicographic-relative-path-sha256-v1"] = (
        "lexicographic-relative-path-sha256-v1"
    )
    artifact_count: int = Field(gt=0)
    total_size_bytes: int = Field(gt=0)
    inventory_sha256: str = Field(pattern=HEX_256_PATTERN)


class PreservationCore(StrictModel):
    profile: Literal[
        "content-addressed-not-merkle-committed-not-time-anchored-not-recovery-exported"
    ] = PRESERVATION_PROFILE
    derivation_chain: list[PreservedArtifact]
    trust_assurance: list[PreservedArtifact]
    campaign_assurance: list[PreservedArtifact]
    external_evidence: list[ExternalEvidenceBinding]
    excluded_material: list[ExcludedMaterial]
    selected_derivation_round: int = Field(gt=0)
    campaign_rounds: list[int]
    preservation_state: PreservationState

    @field_validator("campaign_rounds")
    @classmethod
    def _ordered_rounds(cls, value: list[int]) -> list[int]:
        if value != list(range(1, len(value) + 1)):
            raise ValueError("campaign rounds must be consecutive and one-based")
        return value


class PreservationManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_preservation_manifest"] = "m8_preservation_manifest"
    preservation_id: str
    core: PreservationCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    integrity_assurance: Literal["content-addressed-unanchored"] = (
        "content-addressed-unanchored"
    )


class PreservationEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_preservation_envelope"] = "m8_preservation_envelope"
    preservation_id: str
    preservation_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    preservation_state: Literal[
        "content-addressed-not-merkle-committed-not-time-anchored-not-recovery-exported"
    ] = PRESERVATION_PROFILE
