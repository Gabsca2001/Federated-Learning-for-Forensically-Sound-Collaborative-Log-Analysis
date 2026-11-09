"""Opt-in closed-witness intake followed by actual M5 admission and verification.

Client registration runs through the separately authenticated witness-submit
adapter. This coordinator adapter never opens container networking or accepts
a caller-supplied admission time. Completion times are coordinator clock claims,
not RFC3161 timestamps. A completed witness-round receipt is required for this
profile; a standalone M5 checkpoint does not establish the phase contract.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import sha256_file
from .crypto import public_key_id
from .in_round_admission import admit_and_aggregate_in_round, verify_in_round_secure_round
from .secure_round import _coordinator_public_key, _coordinator_signer, _load_context
from .storage import load_json, write_json_once, write_once
from .submission_evidence import _time, build_round_input_inventory
from .submission_evidence_models import RoundInputInventory
from .submission_witness import (
    WitnessError,
    _bytes,
    _signed,
    _verify_signed,
    registration_cutoff,
    verify_witness_inventory,
    verify_witness_snapshot,
)
from .witness_models import WitnessPhasePolicyCore, WitnessSnapshot
from .witness_round_models import WitnessRoundCore, WitnessRoundReceipt
from .witness_time import verify_timestamp


def _now() -> datetime:
    return datetime.now(UTC)


def _authenticate(workspace: Path, proof: dict[str, Any]) -> tuple[WitnessSnapshot, Any]:
    snapshot = WitnessSnapshot.model_validate_json(proof["snapshot"].model_dump_json())
    if not isinstance(snapshot.policy.core, WitnessPhasePolicyCore):
        raise WitnessError("live admission requires the separately pinned v2 registration policy")
    check = verify_witness_snapshot(**proof)
    if not check["registration_set_verified"]:
        raise WitnessError(f"invalid witness closure: {check['errors']}")
    context = _load_context(workspace / "public")
    if context != snapshot.context or public_key_id(
        _coordinator_public_key(workspace)
    ) != public_key_id(proof["coordinator_public_key"]):
        raise WitnessError("witness context or coordinator differs from live round")
    interval = verify_timestamp(
        _bytes(snapshot.closure.core.subject),
        snapshot.closure.timestamp,
        policy=snapshot.policy,
        trust_store=proof["trust_store"],
    )
    return snapshot, interval


def _phase(
    snapshot: WitnessSnapshot, interval: Any, started: datetime, completed: datetime
) -> None:
    cutoff = registration_cutoff(snapshot.policy, snapshot.context)
    if (
        not cutoff
        <= interval.lower
        <= interval.upper
        <= started
        <= completed
        < _time(snapshot.context.core.expires_at)
    ):
        raise WitnessError("closure/admission/completion falls outside the live phase window")


def _paths(snapshot: WitnessSnapshot, root: Path) -> dict[str, Path]:
    paths = {}
    for entry in snapshot.registrations:
        receipt = entry.receipt
        if entry.core.eligibility != "eligible":
            continue
        client = receipt.core.client_id
        if Path(client).name != client or client in {".", ".."}:
            raise WitnessError("unsafe client identifier for submission adapter")
        path = root / client / "bundle.json"
        if path.is_file():
            paths[receipt.core.bundle_sha256] = path
    return paths


def _intake(workspace: Path, proof: dict[str, Any]) -> dict[str, Any]:
    root = workspace / "witness-round"
    snapshot = proof["snapshot"]
    return verify_witness_inventory(
        inventory=RoundInputInventory.model_validate(load_json(root / "inventory.json")),
        bundle_paths=_paths(snapshot, root / "submissions"),
        **proof,
    )


def _round_check(workspace: Path, trust_workspace: Path, validation_split_path: Path):
    root = workspace / "witness-round"
    return verify_in_round_secure_round(
        workspace=workspace,
        trust_workspace=trust_workspace,
        submissions_root=root / "submissions",
        validation_split_path=validation_split_path,
        client_receipts=root / "receipts",
        require_derivation=True,
    )


def admit_witnessed_round(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
    validation_split_path: Path,
    coordinator_workspace: Path | None = None,
    **proof: Any,
) -> dict[str, Any]:
    """Admit only ready payloads from the externally pinned eligible set."""
    root = workspace / "witness-round"
    if (root / "receipt.json").exists():
        report = verify_witnessed_round(
            workspace=workspace,
            trust_workspace=trust_workspace,
            validation_split_path=validation_split_path,
            **proof,
        )
        if report["status"] != "verified_witness_round":
            raise WitnessError(f"existing witness round is invalid: {report['errors']}")
        return {**report, "idempotent": True}
    snapshot, interval = _authenticate(workspace, proof)
    started = _now()
    _phase(snapshot, interval, started, started)
    if (workspace / "checkpoint/manifest.json").exists():
        raise WitnessError("cannot attach a witness closure to a pre-existing checkpoint")
    receipts = [e.receipt for e in snapshot.registrations if e.core.eligibility == "eligible"]
    source_paths = _paths(snapshot, submissions_root)
    signer = _coordinator_signer(
        workspace, create=False, coordinator_workspace=coordinator_workspace
    )
    inventory = build_round_input_inventory(
        context=snapshot.context,
        receipts=receipts,
        bundle_paths=source_paths,
        client_public_keys=proof["client_public_keys"],
        coordinator_signer=signer,
        coordinator_public_key=proof["coordinator_public_key"],
        closed_at=started,
    )
    intake = verify_witness_inventory(inventory=inventory, bundle_paths=source_paths, **proof)
    if intake["status"] != "verified_eligible_intake":
        raise WitnessError(f"ineligible or empty intake: {intake['errors']}")
    # Freeze evidence offered for eligible receipts, including negative intake.
    # The existing derivation gate blocks every non-ready client before scoring.
    # Unregistered and late receipts never introduce payloads into this directory.
    write_json_once(root / "snapshot.json", snapshot.model_dump(mode="json"))
    write_json_once(root / "inventory.json", inventory.model_dump(mode="json"))
    for receipt in receipts:
        write_json_once(
            root / "receipts" / f"{receipt.receipt_id}.json", receipt.model_dump(mode="json")
        )
    for client_id, source in {
        entry.client_id: source_paths[entry.bundle_sha256].parent
        for entry in inventory.core.entries
        if entry.bundle_sha256 in source_paths
    }.items():
        for name in ("bundle.json", "update.json", "metrics.json"):
            if (source / name).is_file():
                write_once(root / "submissions" / client_id / name, (source / name).read_bytes())
    # Recompute after copying; a source mutation cannot silently enter admission.
    frozen_intake = _intake(workspace, proof)
    if frozen_intake["status"] != "verified_eligible_intake":
        raise WitnessError(f"frozen intake differs: {frozen_intake['errors']}")
    _phase(snapshot, interval, started, _now())
    result = admit_and_aggregate_in_round(
        workspace=workspace,
        trust_workspace=trust_workspace,
        submissions_root=root / "submissions",
        validation_split_path=validation_split_path,
        coordinator_workspace=coordinator_workspace,
        input_inventory_path=root / "inventory.json",
        client_receipts=root / "receipts",
    )
    # A late computation gets no completed witness receipt, even if M5 emitted
    # intermediate evidence. This adapter never backdates or extends a context.
    _phase(snapshot, interval, started, _now())
    check = _round_check(workspace, trust_workspace, validation_split_path)
    if check["status"] != "verified" or not check.get("admission_decisions_verified"):
        raise WitnessError(f"M5 decisions do not reconstruct: {check.get('errors')}")
    if result["status"] != "aggregated":
        return {
            "status": "failed_witness_round",
            "coverage_verified": True,
            "checkpoint_created": False,
            "round_result": result,
            "round_verification": check,
        }
    if not check.get("coefficients_verified"):
        raise WitnessError("M5 effective coefficients do not reconstruct")
    completed = _now()
    _phase(snapshot, interval, started, completed)
    core = WitnessRoundCore(
        context_digest=snapshot.context.core_digest,
        policy_digest=snapshot.policy.core_digest,
        closure_digest=snapshot.closure.core_digest,
        inventory_sha256=sha256_file(root / "inventory.json"),
        checkpoint_sha256=sha256_file(workspace / "checkpoint/manifest.json"),
        global_model_sha256=sha256_file(workspace / "checkpoint/global-model.json"),
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
    )
    receipt = WitnessRoundReceipt(**_signed(core, signer))
    write_json_once(root / "receipt.json", receipt.model_dump(mode="json"))
    return verify_witnessed_round(
        workspace=workspace,
        trust_workspace=trust_workspace,
        validation_split_path=validation_split_path,
        **proof,
    )


def verify_witnessed_round(
    *,
    workspace: Path,
    trust_workspace: Path,
    validation_split_path: Path,
    **proof: Any,
) -> dict[str, Any]:
    """Offline revalidation of phase bindings, every intake and actual M5 weights."""
    report = {
        "status": "invalid",
        "evidence_profile": "witness_live_round_v1",
        "registration_set_verified": False,
        "deadline_verified": False,
        "coverage_verified": False,
        "phase_order_verified": False,
        "admission_decisions_verified": False,
        "coefficients_verified": False,
        "delivery_verified": False,
        "errors": [],
        "limitations": [
            "Witness/TSA independence remains a deployment assumption.",
            "Admission/completion times are coordinator clock claims, not TSA stamps.",
            "A local receipt witness does not prove independent administrative control.",
            "The supplied enrollment authority and current source/runtime remain trusted.",
        ],
    }
    try:
        snapshot, interval = _authenticate(workspace, proof)
        root = workspace / "witness-round"
        if WitnessSnapshot.model_validate(load_json(root / "snapshot.json")) != snapshot:
            raise WitnessError("stored snapshot differs from externally pinned evidence")
        receipt = WitnessRoundReceipt.model_validate(load_json(root / "receipt.json"))
        _verify_signed(receipt, proof["coordinator_public_key"])
        core = receipt.core
        if (
            core.context_digest != snapshot.context.core_digest
            or core.policy_digest != snapshot.policy.core_digest
            or core.closure_digest != snapshot.closure.core_digest
            or core.inventory_sha256 != sha256_file(root / "inventory.json")
            or core.checkpoint_sha256 != sha256_file(workspace / "checkpoint/manifest.json")
            or core.global_model_sha256 != sha256_file(workspace / "checkpoint/global-model.json")
        ):
            raise WitnessError("witness/intake/checkpoint commitment mismatch")
        _phase(snapshot, interval, _time(core.started_at), _time(core.completed_at))
        intake = _intake(workspace, proof)
        if intake["status"] != "verified_eligible_intake":
            raise WitnessError(f"invalid final intake: {intake['errors']}")
        expected_paths = {
            e.client_id
            for e in RoundInputInventory.model_validate(
                load_json(root / "inventory.json")
            ).core.entries
            if e.outcome == "ready_for_admission"
        }
        actual_paths = {p.parent.name for p in (root / "submissions").glob("*/bundle.json")}
        eligible_clients = {
            e.receipt.core.client_id
            for e in snapshot.registrations
            if e.core.eligibility == "eligible"
        }
        if not expected_paths <= actual_paths <= eligible_clients:
            raise WitnessError(
                "admission directory contains missing ready or non-eligible payloads"
            )
        checkpoint = load_json(workspace / "checkpoint/manifest.json")
        if (
            not _time(core.started_at)
            <= _time(checkpoint["core"]["created_at"])
            <= _time(core.completed_at)
        ):
            raise WitnessError("checkpoint was not created during the witnessed admission phase")
        check = _round_check(workspace, trust_workspace, validation_split_path)
        if check["status"] != "verified" or not all(
            check.get(k) for k in ("admission_decisions_verified", "coefficients_verified")
        ):
            raise WitnessError(f"M5 reconstruction failed: {check.get('errors')}")
        report.update(
            status="verified_witness_round",
            registration_set_verified=True,
            deadline_verified=True,
            coverage_verified=True,
            phase_order_verified=True,
            admission_decisions_verified=True,
            coefficients_verified=True,
            eligible_receipt_count=intake["eligible_receipt_count"],
            ready_payload_count=len(expected_paths),
            closure_digest=core.closure_digest,
            checkpoint_sha256=core.checkpoint_sha256,
            global_model_sha256=core.global_model_sha256,
            started_at=core.started_at,
            completed_at=core.completed_at,
            intake_verification=intake,
            round_verification=check,
        )
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as exc:
        report["errors"].append(str(exc))
    return report


def add_round_commands(subparsers: Any) -> None:
    for name in ("witness-round-admit", "witness-round-verify"):
        command = subparsers.add_parser(name, help="opt-in closed-witness M5 phase contract")
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--trust-workspace", type=Path, required=True)
        command.add_argument("--validation-split", type=Path, required=True)
        command.add_argument("--snapshot", type=Path, required=True)
        command.add_argument("--expected-policy-digest", required=True)
        command.add_argument("--expected-closure-digest", required=True)
        command.add_argument("--witness-public-key", type=Path, required=True)
        command.add_argument("--coordinator-public-key", type=Path, required=True)
        command.add_argument("--client-keys", type=Path, required=True)
        command.add_argument("--tsa-trust-store", type=Path, required=True)
        command.add_argument("--acknowledgement", type=Path, action="append", default=[])
        if name == "witness-round-admit":
            command.add_argument("--submissions-root", type=Path, required=True)
            command.add_argument("--coordinator-workspace", type=Path)


def run_round_command(arguments: Any) -> tuple[dict[str, Any], int]:
    from .crypto import load_public_key
    from .submission_witness_cli import _keys
    from .witness_models import WitnessRegistration

    proof = {
        "snapshot": WitnessSnapshot.model_validate(load_json(arguments.snapshot)),
        "expected_policy_digest": arguments.expected_policy_digest,
        "expected_closure_digest": arguments.expected_closure_digest,
        "witness_public_key": load_public_key(arguments.witness_public_key.read_bytes()),
        "coordinator_public_key": load_public_key(arguments.coordinator_public_key.read_bytes()),
        "client_public_keys": _keys(arguments.client_keys),
        "trust_store": arguments.tsa_trust_store.read_bytes(),
        "retained_acknowledgements": [
            WitnessRegistration.model_validate(load_json(p)) for p in arguments.acknowledgement
        ],
    }
    common = dict(
        workspace=arguments.workspace,
        trust_workspace=arguments.trust_workspace,
        validation_split_path=arguments.validation_split,
        **proof,
    )
    if arguments.command == "witness-round-admit":
        result = admit_witnessed_round(
            submissions_root=arguments.submissions_root,
            coordinator_workspace=arguments.coordinator_workspace,
            **common,
        )
    else:
        result = verify_witnessed_round(**common)
    return result, int(result["status"] != "verified_witness_round")
