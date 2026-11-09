"""Attributed semantic reviews, independent of historical operational decisions."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc


class ReviewEvidenceRef(StrictModel):
    sha256: str = Field(pattern=HEX_256_PATTERN)
    description: str = Field(min_length=1)

    @field_validator("description")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence description must not be blank")
        return value


class ReviewLedgerCore(StrictModel):
    domain: Literal["fl-semantic-review-ledger-v1"] = "fl-semantic-review-ledger-v1"
    signing_profile: Literal["software-development"] = "software-development"
    manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    authorized_reviewers: dict[str, str]
    created_at: str

    _created_utc = field_validator("created_at")(_require_utc)


class ReviewLedger(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["semantic_review_ledger"] = "semantic_review_ledger"
    ledger_id: str
    core: ReviewLedgerCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class ReviewRecordCore(StrictModel):
    domain: Literal["fl-semantic-review-record-v1"] = "fl-semantic-review-record-v1"
    signing_profile: Literal["software-development"] = "software-development"
    ledger_id: str
    sequence: int = Field(gt=0)
    subject_revision: int = Field(gt=0)
    submission_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    disposition_sha256: str = Field(pattern=HEX_256_PATTERN)
    decision_sha256: str | None = None
    checkpoint_sha256: str | None = None
    previous_record_sha256: str = Field(pattern=HEX_256_PATTERN)
    previous_subject_record_sha256: str | None = None
    operation_id: str = Field(min_length=1, max_length=256)
    reviewer_id: str = Field(min_length=1)
    label: Literal["not_reviewed", "benign", "suspicious", "malicious", "inconclusive"]
    reason: str = Field(min_length=1)
    evidence_refs: list[ReviewEvidenceRef] = Field(min_length=1)
    created_at: str

    _created_utc = field_validator("created_at")(_require_utc)

    @field_validator("operation_id", "reviewer_id", "reason")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("review fields must not be blank")
        return value


class ReviewRecord(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["semantic_review_record"] = "semantic_review_record"
    review_id: str
    core: ReviewRecordCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class ReviewHead(StrictModel):
    ledger_id: str
    genesis_sha256: str = Field(pattern=HEX_256_PATTERN)
    sequence: int = Field(ge=0)
    last_record_sha256: str = Field(pattern=HEX_256_PATTERN)
