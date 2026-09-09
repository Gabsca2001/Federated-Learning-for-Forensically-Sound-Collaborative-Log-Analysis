"""Strict contracts for the live real-attestation failure experiment."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from .models import HEX_256_PATTERN, StrictModel


class RealAttestationFailureContractCore(StrictModel):
    experiment_id: str
    config_sha256: str = Field(pattern=HEX_256_PATTERN)
    client_ids: list[str]
    target_client_id: str
    active_rounds: list[int]
    phase: Literal["post_local_training_pre_aggregation"] = (
        "post_local_training_pre_aggregation"
    )
    pcr_bank: Literal["sha256"] = "sha256"
    pcr_index: int = Field(ge=0, le=23)
    measurement_sha256: str = Field(pattern=HEX_256_PATTERN)
    expected_initial_statuses: list[Literal["passed", "passed_with_warning"]]
    expected_post_status: Literal["failed_measurement"] = "failed_measurement"
    quote_format: Literal["tpm2-tools-tpms-attest"] = "tpm2-tools-tpms-attest"
    local_update_is_probe_only: Literal[True] = True
    evaluation_labels_used_for_admission: Literal[False] = False
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)

    @field_validator("client_ids")
    @classmethod
    def _unique_clients(cls, value: list[str]) -> list[str]:
        if not value or value != sorted(set(value)):
            raise ValueError("client_ids must be a non-empty sorted unique list")
        return value

    @field_validator("active_rounds")
    @classmethod
    def _unique_positive_rounds(cls, value: list[int]) -> list[int]:
        if not value or any(item < 1 for item in value) or value != sorted(set(value)):
            raise ValueError("active_rounds must be a non-empty sorted unique list")
        return value

    @field_validator("expected_initial_statuses")
    @classmethod
    def _initial_statuses(cls, value: list[str]) -> list[str]:
        if not value or value != sorted(set(value)):
            raise ValueError(
                "expected_initial_statuses must be a non-empty sorted unique list"
            )
        return value


class RealAttestationFailureContract(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m4_m6_real_attestation_failure_contract"] = (
        "m4_m6_real_attestation_failure_contract"
    )
    contract_id: str
    core: RealAttestationFailureContractCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
