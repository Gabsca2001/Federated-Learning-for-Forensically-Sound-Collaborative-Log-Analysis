"""Explicit trusted verification context shared by campaign and M7 consumers.

The caller supplies this profile through a trusted configuration. Reading pins
from the round being verified is never a substitute. Legacy layouts remain
unchanged; witnessed layouts require the complete phase verifier.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from .crypto import load_public_key
from .models import HEX_256_PATTERN, StrictModel
from .storage import load_json
from .submission_witness_cli import _keys
from .witness_models import WitnessRegistration, WitnessSnapshot


class WitnessRoundReference(StrictModel):
    snapshot: str
    expected_policy_digest: str = Field(pattern=HEX_256_PATTERN)
    expected_closure_digest: str = Field(pattern=HEX_256_PATTERN)
    witness_public_key: str
    coordinator_public_key: str
    client_keys: str
    tsa_trust_store: str
    acknowledgements: list[str] = Field(default_factory=list)


class CheckpointVerificationProfile(StrictModel):
    profile: Literal["closed-witness-live-round-v1"]
    rounds: dict[str, WitnessRoundReference] = Field(min_length=1)


def witnessed_layout(workspace: Path) -> bool:
    return (workspace / "witness-round").exists()


def verification_arguments(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    from .config import load_yaml

    value, _digest = load_yaml(path)
    profile = CheckpointVerificationProfile.model_validate(value)
    return {
        "verification_profile": profile.model_dump(mode="json"),
        "profile_root": path.resolve().parent,
    }


def witness_proof(reference: WitnessRoundReference, root: Path) -> dict[str, Any]:
    def path(value: str) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else root / candidate

    return {
        "snapshot": WitnessSnapshot.model_validate(load_json(path(reference.snapshot))),
        "expected_policy_digest": reference.expected_policy_digest,
        "expected_closure_digest": reference.expected_closure_digest,
        "witness_public_key": load_public_key(path(reference.witness_public_key).read_bytes()),
        "coordinator_public_key": load_public_key(
            path(reference.coordinator_public_key).read_bytes()
        ),
        "client_public_keys": _keys(path(reference.client_keys)),
        "trust_store": path(reference.tsa_trust_store).read_bytes(),
        "retained_acknowledgements": [
            WitnessRegistration.model_validate(load_json(path(value)))
            for value in reference.acknowledgements
        ],
    }


def verify_witness_checkpoint(
    *,
    workspace: Path,
    trust_workspace: Path,
    validation_split_path: Path,
    verification_profile: dict[str, Any] | None,
    profile_root: Path | None,
) -> dict[str, Any]:
    from .witness_round import verify_witnessed_round

    if verification_profile is None or profile_root is None:
        raise ValueError("witnessed checkpoint requires an explicit trusted verification profile")
    profile = CheckpointVerificationProfile.model_validate(verification_profile)
    number = str(load_json(workspace / "public/round-context.json")["core"]["round_number"])
    if number not in profile.rounds:
        raise ValueError("trusted witness profile does not cover this round")
    if not witnessed_layout(workspace):
        raise ValueError("configured witness evidence is missing; legacy fallback is forbidden")
    report = verify_witnessed_round(
        workspace=workspace,
        trust_workspace=trust_workspace,
        validation_split_path=validation_split_path,
        **witness_proof(profile.rounds[number], profile_root),
    )
    if report["status"] != "verified_witness_round":
        return {"status": "failed", "errors": report["errors"], "witness_verification": report}
    return {
        **report["round_verification"],
        "verification_scope": "closed_witness_live_checkpoint",
        "deadline_verified": True,
        "phase_order_verified": True,
        "witness_verification": report,
    }
