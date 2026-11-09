"""A signed snapshot of the supplied multiround evidence graph."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc


class CampaignGraphNode(StrictModel):
    node_id: str
    kind: str
    sha256: str = Field(pattern=HEX_256_PATTERN)
    availability: Literal["available", "commitment_only", "missing"]
    contexts: list[str]


class CampaignGraphEdge(StrictModel):
    source: str
    target: str
    kind: Literal["num", "dec", "audit"]


class CampaignRoundReference(StrictModel):
    manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    context_sha256: str = Field(pattern=HEX_256_PATTERN)
    campaign_id: str
    round_number: int = Field(gt=0)
    previous_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_sha256: str | None
    global_model_sha256: str | None
    submissions: dict[str, str]


class CampaignProductReference(StrictModel):
    manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    kind: Literal["prediction", "explanation", "attack_mapping", "investigation_report"]
    context_digest: str = Field(pattern=HEX_256_PATTERN)


class CampaignDerivationCore(StrictModel):
    domain: Literal["fl-campaign-derivation-v1"] = "fl-campaign-derivation-v1"
    evidence_scope: Literal["provided_pinned_manifests"] = "provided_pinned_manifests"
    rounds: list[CampaignRoundReference] = Field(min_length=1)
    products: list[CampaignProductReference]
    nodes: list[CampaignGraphNode]
    edges: list[CampaignGraphEdge]
    producer_implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    created_at: str

    _created_utc = field_validator("created_at")(_require_utc)


class CampaignDerivationManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["campaign_derivation_manifest"] = "campaign_derivation_manifest"
    manifest_id: str
    core: CampaignDerivationCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock
