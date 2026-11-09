"""Signed client commitments and intake accounting, distinct from admission."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc


class SubmissionReceiptCore(StrictModel):
    domain: Literal["fl-submission-receipt-v1"] = "fl-submission-receipt-v1"
    submission_id: str
    campaign_id: str
    context_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    round_number: int = Field(gt=0)
    client_id: str
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    previous_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    bundle_id: str
    bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    bundle_core_digest: str = Field(pattern=HEX_256_PATTERN)
    signing_trust_level: Literal["software-development", "swtpm", "tpm2"]
    submitted_at: str

    _submitted_utc = field_validator("submitted_at")(_require_utc)


class SubmissionReceipt(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["submission_receipt"] = "submission_receipt"
    receipt_id: str
    core: SubmissionReceiptCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class SubmissionIntakeEntry(StrictModel):
    submission_id: str
    client_id: str
    bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    bundle_core_digest: str = Field(pattern=HEX_256_PATTERN)
    receipt_core_digests: list[str]
    outcome: Literal[
        "ready_for_admission",
        "rejected_missing_payload",
        "rejected_invalid_payload",
        "rejected_conflict",
    ]
    reasons: list[str]


class RoundInputInventoryCore(StrictModel):
    domain: Literal["fl-round-input-inventory-v1"] = "fl-round-input-inventory-v1"
    evidence_profile: Literal["provided_client_evidence"] = "provided_client_evidence"
    campaign_id: str
    context_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    round_number: int = Field(gt=0)
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    previous_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    expected_client_ids: list[str]
    missing_client_ids: list[str]
    entries: list[SubmissionIntakeEntry]
    closed_at: str

    _closed_utc = field_validator("closed_at")(_require_utc)


class RoundInputInventory(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["round_input_inventory"] = "round_input_inventory"
    inventory_id: str
    core: RoundInputInventoryCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock
