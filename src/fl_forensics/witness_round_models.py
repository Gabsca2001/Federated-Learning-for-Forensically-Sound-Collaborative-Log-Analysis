"""Signed linkage of a closed v2 witness set to an actual M5 round."""

from typing import Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc


class WitnessRoundCore(StrictModel):
    domain: Literal["fl-witness-live-round-v1"] = "fl-witness-live-round-v1"
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    policy_digest: str = Field(pattern=HEX_256_PATTERN)
    closure_digest: str = Field(pattern=HEX_256_PATTERN)
    inventory_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    global_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    started_at: str
    completed_at: str

    _started_utc = field_validator("started_at")(_require_utc)
    _completed_utc = field_validator("completed_at")(_require_utc)


class WitnessRoundReceipt(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["witness_live_round_receipt"] = "witness_live_round_receipt"
    core: WitnessRoundCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock
