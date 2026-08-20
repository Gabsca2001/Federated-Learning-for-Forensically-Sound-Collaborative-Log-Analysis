"""Strict signed-artifact schemas for the M5 secure round protocol."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc


class RoundClientContract(StrictModel):
    client_id: str
    node_id: str
    enrollment_id: str
    attestation_result_id: str
    attestation_result_sha256: str = Field(pattern=HEX_256_PATTERN)
    snapshot_sha256: str = Field(pattern=HEX_256_PATTERN)
    snapshot_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    train_row_count: int = Field(gt=0)


class SecureRoundContextCore(StrictModel):
    campaign_id: str
    round_number: int = Field(gt=0)
    previous_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    training_contract_sha256: str = Field(pattern=HEX_256_PATTERN)
    partition_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    federation_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    aggregation_strategy: Literal["FedAvg"] = "FedAvg"
    seed: int
    local_epochs: int = Field(gt=0)
    batch_size: int = Field(gt=0)
    learning_rate_decimal: str
    required_client_count: int = Field(gt=0)
    clients: list[RoundClientContract]
    issued_at: str
    expires_at: str

    _issued_utc = field_validator("issued_at")(_require_utc)
    _expires_utc = field_validator("expires_at")(_require_utc)


class SecureRoundContext(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["secure_round_context"] = "secure_round_context"
    context_id: str
    core: SecureRoundContextCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class UpdateBundleCore(StrictModel):
    campaign_id: str
    context_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    round_number: int = Field(gt=0)
    client_id: str
    node_id: str
    enrollment_id: str
    attestation_result_id: str
    attestation_result_sha256: str = Field(pattern=HEX_256_PATTERN)
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    snapshot_sha256: str = Field(pattern=HEX_256_PATTERN)
    update_sha256: str = Field(pattern=HEX_256_PATTERN)
    metrics_sha256: str = Field(pattern=HEX_256_PATTERN)
    tensor_schema_sha256: str = Field(pattern=HEX_256_PATTERN)
    num_examples: int = Field(gt=0)
    generated_at: str

    _generated_utc = field_validator("generated_at")(_require_utc)


class UpdateBundle(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["secure_update_bundle"] = "secure_update_bundle"
    bundle_id: str
    core: UpdateBundleCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class SecureCheck(StrictModel):
    name: str
    passed: bool
    detail: str


class ContributionDecisionCore(StrictModel):
    campaign_id: str
    context_id: str
    round_number: int = Field(gt=0)
    client_id: str
    bundle_id: str
    bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    status: Literal["accepted", "quarantined"]
    checks: list[SecureCheck]
    decided_at: str

    _decided_utc = field_validator("decided_at")(_require_utc)


class ContributionDecision(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["secure_contribution_decision"] = (
        "secure_contribution_decision"
    )
    decision_id: str
    core: ContributionDecisionCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


class CheckpointInput(StrictModel):
    client_id: str
    decision_id: str
    decision_sha256: str = Field(pattern=HEX_256_PATTERN)
    bundle_id: str
    bundle_sha256: str = Field(pattern=HEX_256_PATTERN)
    update_sha256: str = Field(pattern=HEX_256_PATTERN)
    num_examples: int = Field(gt=0)


class SecureCheckpointCore(StrictModel):
    campaign_id: str
    context_id: str
    context_digest: str = Field(pattern=HEX_256_PATTERN)
    round_number: int = Field(gt=0)
    previous_checkpoint_sha256: str = Field(pattern=HEX_256_PATTERN)
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    aggregation_strategy: Literal["FedAvg"] = "FedAvg"
    required_client_count: int = Field(gt=0)
    accepted_count: int = Field(ge=0)
    quarantined_count: int = Field(ge=0)
    total_examples: int = Field(ge=0)
    accepted_inputs: list[CheckpointInput]
    quarantined_decision_sha256: list[str]
    global_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    created_at: str

    _created_utc = field_validator("created_at")(_require_utc)


class SecureCheckpoint(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["secure_global_checkpoint"] = "secure_global_checkpoint"
    checkpoint_id: str
    core: SecureCheckpointCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


def tensor_schema(model_export: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the signed structural contract without including tensor values."""

    return [
        {
            "name": str(parameter["name"]),
            "shape": [int(value) for value in parameter["shape"]],
            "dtype": str(parameter["dtype"]),
        }
        for parameter in model_export["parameters"]
    ]
