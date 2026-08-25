"""Strict schemas for the M8.2 deterministic Merkle commitment."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from .models import HEX_256_PATTERN, StrictModel

MERKLE_ALGORITHM = "sha256-domain-separated-binary-duplicate-last-v1"
MERKLE_STATE = "merkle-committed-not-time-anchored-not-recovery-exported"


class MerkleLeafPayload(StrictModel):
    leaf_kind: Literal["preserved-artifact", "external-evidence-binding"]
    identity: str
    relative_path: str
    content_sha256: str = Field(pattern=HEX_256_PATTERN)
    size_bytes: int = Field(ge=0)
    source_descriptor_sha256: str = Field(pattern=HEX_256_PATTERN)


class MerkleLeaf(StrictModel):
    index: int = Field(ge=0)
    leaf_key: str
    payload: MerkleLeafPayload
    leaf_sha256: str = Field(pattern=HEX_256_PATTERN)


class MerkleCore(StrictModel):
    source_preservation_id: str
    source_preservation_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_preservation_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    algorithm: Literal[
        "sha256-domain-separated-binary-duplicate-last-v1"
    ] = MERKLE_ALGORITHM
    leaf_domain_prefix_hex: Literal["00"] = "00"
    node_domain_prefix_hex: Literal["01"] = "01"
    leaf_order: Literal["leaf-key-lexicographic-v1"] = "leaf-key-lexicographic-v1"
    odd_node_rule: Literal["duplicate-last"] = "duplicate-last"
    artifact_leaf_count: int = Field(gt=0)
    external_evidence_leaf_count: int = Field(ge=0)
    leaf_count: int = Field(gt=0)
    level_count: int = Field(gt=0)
    leaves: list[MerkleLeaf]
    levels: list[list[str]]
    root_sha256: str = Field(pattern=HEX_256_PATTERN)

    @field_validator("levels")
    @classmethod
    def _valid_level_digests(cls, value: list[list[str]]) -> list[list[str]]:
        if not value or any(not level for level in value):
            raise ValueError("Merkle levels must be non-empty")
        import re

        if any(
            re.fullmatch(HEX_256_PATTERN, digest) is None
            for level in value
            for digest in level
        ):
            raise ValueError("Merkle level contains an invalid digest")
        return value

    @model_validator(mode="after")
    def _counts_and_order_match(self) -> MerkleCore:
        if self.leaf_count != len(self.leaves):
            raise ValueError("Merkle leaf count mismatch")
        if self.leaf_count != (
            self.artifact_leaf_count + self.external_evidence_leaf_count
        ):
            raise ValueError("Merkle leaf class counts mismatch")
        if self.level_count != len(self.levels):
            raise ValueError("Merkle level count mismatch")
        if [leaf.index for leaf in self.leaves] != list(range(self.leaf_count)):
            raise ValueError("Merkle leaf indexes are not consecutive")
        keys = [leaf.leaf_key for leaf in self.leaves]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("Merkle leaf keys are not unique and ordered")
        if self.levels[0] != [leaf.leaf_sha256 for leaf in self.leaves]:
            raise ValueError("Merkle first level differs from leaf digests")
        if self.levels[-1] != [self.root_sha256]:
            raise ValueError("Merkle final level differs from root")
        return self


class MerkleTreeManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_deterministic_merkle_tree"] = (
        "m8_deterministic_merkle_tree"
    )
    tree_id: str
    core: MerkleCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    assurance_state: Literal[
        "merkle-committed-not-time-anchored-not-recovery-exported"
    ] = MERKLE_STATE


class MerkleEnvelope(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_merkle_envelope"] = "m8_merkle_envelope"
    tree_id: str
    merkle_tree_sha256: str = Field(pattern=HEX_256_PATTERN)
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    root_sha256: str = Field(pattern=HEX_256_PATTERN)
    source_preservation_id: str
    source_preservation_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    assurance_state: Literal[
        "merkle-committed-not-time-anchored-not-recovery-exported"
    ] = MERKLE_STATE
