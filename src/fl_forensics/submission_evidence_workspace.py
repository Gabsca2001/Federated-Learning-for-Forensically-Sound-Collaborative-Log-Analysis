"""Filesystem/CLI adapters using the existing pinned enrollment authority."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import sha256_file
from .crypto import load_public_key, public_key_id
from .secure_round import _coordinator_public_key, _coordinator_signer, _enrollment, _load_context
from .storage import load_json, write_json_once
from .submission_evidence import (
    SubmissionEvidenceError,
    build_round_input_inventory,
    verify_submission_coverage,
)
from .submission_evidence_models import RoundInputInventory, SubmissionReceipt


def _inputs(
    *, workspace: Path, trust_workspace: Path, client_receipts: Path, submissions_root: Path
) -> dict[str, Any]:
    context = _load_context(workspace / "public")
    if not client_receipts.is_dir():
        raise SubmissionEvidenceError("client receipt directory is unavailable")
    client_keys = {}
    client_levels = {}
    for contract in context.core.clients:
        record = _enrollment(trust_workspace, contract.client_id)
        if (
            record.core.enrollment_id != contract.enrollment_id
            or record.core.node_id != contract.node_id
        ):
            raise SubmissionEvidenceError("enrollment differs from authenticated round contract")
        client_keys[contract.client_id] = load_public_key(
            record.core.esk_public_key_pem.encode("utf-8")
        )
        if public_key_id(client_keys[contract.client_id]) != record.core.esk_key_id:
            raise SubmissionEvidenceError("enrollment key identifier mismatch")
        client_levels[contract.client_id] = record.core.trust_level
    receipts = []
    for path in sorted(client_receipts.rglob("*.json")):
        receipt = SubmissionReceipt.model_validate(load_json(path))
        if receipt.core.context_digest != context.core_digest:
            raise SubmissionEvidenceError("receipt belongs to another context; use per-round evidence")
        if (
            receipt.core.client_id not in client_keys
            or receipt.core.signing_trust_level != client_levels[receipt.core.client_id]
        ):
            raise SubmissionEvidenceError("receipt client or signing level differs from enrollment")
        receipts.append(receipt)
    bundle_paths = {}
    for contract in context.core.clients:
        path = submissions_root / contract.client_id / "bundle.json"
        if path.is_file():
            bundle_paths[sha256_file(path)] = path
    # Route a changed bundle to integrity checking rather than hiding it as absent.
    for receipt in receipts:
        path = submissions_root / receipt.core.client_id / "bundle.json"
        if path.is_file():
            bundle_paths.setdefault(receipt.core.bundle_sha256, path)
    return {
        "context": context,
        "evidence_receipts": receipts,
        "bundle_paths": bundle_paths,
        "client_public_keys": client_keys,
        "coordinator_public_key": _coordinator_public_key(workspace),
        "evidence_source": str(client_receipts.resolve()),
    }


def create_submission_inventory_workspace(
    *,
    workspace: Path,
    trust_workspace: Path,
    client_receipts: Path,
    submissions_root: Path,
    inventory_path: Path,
    coordinator_workspace: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    inputs = _inputs(
        workspace=workspace,
        trust_workspace=trust_workspace,
        client_receipts=client_receipts,
        submissions_root=submissions_root,
    )
    if inventory_path.is_file():
        inventory = RoundInputInventory.model_validate(load_json(inventory_path))
    else:
        inventory = build_round_input_inventory(
            context=inputs["context"],
            receipts=inputs["evidence_receipts"],
            bundle_paths=inputs["bundle_paths"],
            client_public_keys=inputs["client_public_keys"],
            coordinator_signer=_coordinator_signer(
                workspace, create=False, coordinator_workspace=coordinator_workspace
            ),
            coordinator_public_key=inputs["coordinator_public_key"],
            closed_at=now or datetime.now(UTC),
        )
        write_json_once(inventory_path, inventory.model_dump(mode="json"))
    report = verify_submission_coverage(inventory=inventory, **inputs)
    report["inventory_path"] = str(inventory_path)
    report["inventory_id"] = inventory.inventory_id
    return report


def verify_submission_inventory_workspace(
    *,
    workspace: Path,
    trust_workspace: Path,
    client_receipts: Path,
    submissions_root: Path,
    inventory_path: Path,
) -> dict[str, Any]:
    try:
        inputs = _inputs(
            workspace=workspace,
            trust_workspace=trust_workspace,
            client_receipts=client_receipts,
            submissions_root=submissions_root,
        )
        inventory = RoundInputInventory.model_validate(load_json(inventory_path))
        return verify_submission_coverage(inventory=inventory, **inputs)
    except (OSError, ValueError, TypeError) as exc:
        return {
            "status": "invalid",
            "evidence_profile": "provided_client_evidence",
            "verification_scope": "submission_intake_only",
            "coverage_verified": False,
            "deadline_verified": False,
            "admission_decisions_verified": False,
            "errors": [str(exc)],
            "property_statuses": {
                "coverage": "failed", "admission_decisions": "not_checked",
                "deadline": "not_checked", "delivery": "not_checked",
            },
        }
