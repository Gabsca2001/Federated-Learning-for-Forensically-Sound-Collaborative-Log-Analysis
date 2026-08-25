"""Strict schemas for the M8.3 RFC 3161 trusted-time anchor."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .models import HEX_256_PATTERN, StrictModel

TIMESTAMP_STATE = "merkle-committed-time-anchored-not-recovery-exported"


class AnchorSubjectCore(StrictModel):
    merkle_tree_id: str
    merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    merkle_tree_sha256: str = Field(pattern=HEX_256_PATTERN)
    merkle_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    merkle_leaf_count: int = Field(gt=0)
    source_preservation_id: str
    source_preservation_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    commitment_algorithm: Literal[
        "sha256-domain-separated-binary-duplicate-last-v1"
    ]


class AnchorSubject(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_timestamp_anchor_subject"] = (
        "m8_timestamp_anchor_subject"
    )
    anchor_id: str
    core: AnchorSubjectCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    requested_protocol: Literal["RFC3161"] = "RFC3161"
    requested_hash_algorithm: Literal["sha256"] = "sha256"


class TimestampProof(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_rfc3161_timestamp_proof"] = (
        "m8_rfc3161_timestamp_proof"
    )
    proof_id: str
    anchor_id: str
    tsa_url: str
    protocol: Literal["RFC3161"] = "RFC3161"
    hash_algorithm: Literal["sha256"] = "sha256"
    message_imprint_sha256: str = Field(pattern=HEX_256_PATTERN)
    anchor_subject_sha256: str = Field(pattern=HEX_256_PATTERN)
    timestamp_request_sha256: str = Field(pattern=HEX_256_PATTERN)
    timestamp_response_sha256: str = Field(pattern=HEX_256_PATTERN)
    tsa_certificates_sha256: str = Field(pattern=HEX_256_PATTERN)
    trust_store_sha256: str = Field(pattern=HEX_256_PATTERN)
    policy_oid: str
    serial_number: str
    gen_time: str
    tsa_name: str
    nonce_present: Literal[True] = True
    openssl_verification: Literal["Verification: OK"] = "Verification: OK"


class TimestampManifestCore(StrictModel):
    anchor_id: str
    anchor_subject_sha256: str = Field(pattern=HEX_256_PATTERN)
    proof_id: str
    timestamp_proof_sha256: str = Field(pattern=HEX_256_PATTERN)
    timestamp_request_sha256: str = Field(pattern=HEX_256_PATTERN)
    timestamp_response_sha256: str = Field(pattern=HEX_256_PATTERN)
    tsa_certificates_sha256: str = Field(pattern=HEX_256_PATTERN)
    trust_store_sha256: str = Field(pattern=HEX_256_PATTERN)
    merkle_tree_id: str
    merkle_root_sha256: str = Field(pattern=HEX_256_PATTERN)
    tsa_url: str
    protocol: Literal["RFC3161"] = "RFC3161"
    assurance_state: Literal[
        "merkle-committed-time-anchored-not-recovery-exported"
    ] = TIMESTAMP_STATE


class TimestampManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m8_timestamp_anchor_manifest"] = (
        "m8_timestamp_anchor_manifest"
    )
    timestamp_id: str
    core: TimestampManifestCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
