"""Versioned, strict commitments for the independent registration profile."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc
from .secure_round_models import SecureRoundContext
from .submission_evidence_models import SubmissionReceipt


class WitnessPolicyCore(StrictModel):
    domain: Literal["fl-independent-witness-policy-v1"] = "fl-independent-witness-policy-v1"
    witness_key_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    coordinator_key_id: str
    client_key_ids: dict[str, str]
    client_signing_trust_levels: dict[str, Literal["software-development", "swtpm", "tpm2"]]
    tsa_trust_store_sha256: str = Field(pattern=HEX_256_PATTERN)
    tsa_policy_oid: str
    maximum_accuracy_microseconds: int = Field(gt=0, le=60_000_000)
    registration_rule: Literal["issued_at<=lower_and_upper<expires_at"] = (
        "issued_at<=lower_and_upper<expires_at"
    )


class WitnessPhasePolicyCore(WitnessPolicyCore):
    """Opt-in v2: a signed registration cutoff inside the live round window."""

    domain: Literal["fl-independent-witness-policy-v2"] = "fl-independent-witness-policy-v2"
    registration_rule: Literal["issued_at<=lower_and_upper<registration_deadline<expires_at"] = (
        "issued_at<=lower_and_upper<registration_deadline<expires_at"
    )
    registration_deadline: str

    _deadline_utc = field_validator("registration_deadline")(_require_utc)


class WitnessPolicy(StrictModel):
    core: WitnessPolicyCore | WitnessPhasePolicyCore = Field(discriminator="domain")
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class TimestampEvidence(StrictModel):
    protocol: Literal["RFC3161"] = "RFC3161"
    request_b64: str
    response_b64: str


class RegistrationSubject(StrictModel):
    domain: Literal["fl-witness-registration-subject-v1"] = "fl-witness-registration-subject-v1"
    policy_digest: str = Field(pattern=HEX_256_PATTERN)
    sequence: int = Field(gt=0)
    previous_digest: str = Field(pattern=HEX_256_PATTERN)
    receipt_core_digest: str = Field(pattern=HEX_256_PATTERN)
    receipt_sha256: str = Field(pattern=HEX_256_PATTERN)
    submission_id: str


class RegistrationCore(StrictModel):
    domain: Literal["fl-witness-registration-v1"] = "fl-witness-registration-v1"
    subject: RegistrationSubject
    timestamp_digest: str = Field(pattern=HEX_256_PATTERN)
    eligibility: Literal["eligible", "late", "ambiguous", "before_open"]


class WitnessRegistration(StrictModel):
    core: RegistrationCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock
    receipt: SubmissionReceipt
    timestamp: TimestampEvidence


class ClosureSubject(StrictModel):
    domain: Literal["fl-witness-closure-subject-v1"] = "fl-witness-closure-subject-v1"
    policy_digest: str = Field(pattern=HEX_256_PATTERN)
    entry_count: int = Field(ge=0)
    head_digest: str = Field(pattern=HEX_256_PATTERN)
    eligible_receipt_digests: list[str]


class ClosureCore(StrictModel):
    domain: Literal["fl-witness-closure-v1"] = "fl-witness-closure-v1"
    subject: ClosureSubject
    timestamp_digest: str = Field(pattern=HEX_256_PATTERN)


class WitnessClosure(StrictModel):
    core: ClosureCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock
    timestamp: TimestampEvidence


class WitnessSnapshot(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["independent_witness_snapshot"] = "independent_witness_snapshot"
    context: SecureRoundContext
    policy: WitnessPolicy
    registrations: list[WitnessRegistration]
    closure: WitnessClosure
