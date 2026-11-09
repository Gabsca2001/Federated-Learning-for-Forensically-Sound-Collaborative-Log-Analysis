"""CLI adapters with explicitly supplied authority, reviewer keys and head pins."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes
from .crypto import SoftwareECDSASigner, load_public_key
from .review_ledger import (
    ReviewLedgerError,
    append_review,
    initialize_review_ledger,
    verify_review_ledger,
)
from .review_ledger_models import ReviewHead
from .storage import load_json, write_once


def add_review_commands(subparsers: Any) -> None:
    for name in ("review-init", "review-append", "review-verify"):
        command = subparsers.add_parser(
            name, help="attributed semantic reviews; preserve historical decisions"
        )
        command.add_argument("--ledger", type=Path, required=True)
        command.add_argument("--round-workspace", type=Path, required=True)
        command.add_argument("--coordinator-public-key", type=Path, required=True)
        command.add_argument("--reviewer-keys", type=Path, required=True)
        command.add_argument("--export-head", type=Path)
        if name == "review-init":
            command.add_argument("--authority-private-key", type=Path, required=True)
            command.add_argument("--manifest-sha256", required=True)
        else:
            command.add_argument("--authority-public-key", type=Path, required=True)
            command.add_argument("--expected-head", type=Path, required=name == "review-append")
        if name == "review-append":
            command.add_argument("--operation-id", required=True)
            command.add_argument("--submission-id", required=True)
            command.add_argument("--reviewer-id", required=True)
            command.add_argument("--reviewer-private-key", type=Path, required=True)
            command.add_argument(
                "--label",
                choices=("not_reviewed", "benign", "suspicious", "malicious", "inconclusive"),
                required=True,
            )
            command.add_argument("--reason", required=True)
            command.add_argument("--evidence", type=Path, required=True)
        if name == "review-verify":
            command.add_argument("--require-tip-anchor", action="store_true")


def _export(path: Path | None, head: dict[str, Any], ledger: Path) -> None:
    if path is not None:
        if path.resolve().is_relative_to(ledger.resolve()):
            raise ReviewLedgerError("export the trusted head outside the mutable ledger")
        write_once(path, canonical_json_bytes(head) + b"\n")


def run_review_command(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    try:
        if arguments.export_head is not None and arguments.export_head.resolve().is_relative_to(
            arguments.ledger.resolve()
        ):
            raise ReviewLedgerError("export the trusted head outside the mutable ledger")
        roster = load_json(arguments.reviewer_keys)
        if not isinstance(roster, dict) or not roster:
            raise ReviewLedgerError("reviewer registry must map named authors to public PEM paths")
        keys = {}
        for reviewer_id, value in roster.items():
            path = Path(value)
            if not path.is_absolute():
                path = arguments.reviewer_keys.parent / path
            keys[reviewer_id] = load_public_key(path.read_bytes())
        coordinator = load_public_key(arguments.coordinator_public_key.read_bytes())
        common = {
            "ledger_workspace": arguments.ledger,
            "round_workspace": arguments.round_workspace,
            "coordinator_public_key": coordinator,
        }
        if arguments.command == "review-init":
            head = initialize_review_ledger(
                **common,
                expected_manifest_sha256=arguments.manifest_sha256,
                authority_signer=SoftwareECDSASigner.load(arguments.authority_private_key),
                authorized_reviewers=keys,
            )
            result = {"status": "initialized", "head": head.model_dump(mode="json")}
        else:
            authority = load_public_key(arguments.authority_public_key.read_bytes())
            expected = (
                ReviewHead.model_validate(load_json(arguments.expected_head))
                if arguments.expected_head
                else None
            )
            if arguments.command == "review-append":
                appended = append_review(
                    **common,
                    authority_public_key=authority,
                    reviewer_public_keys=keys,
                    expected_previous_head=expected,
                    operation_id=arguments.operation_id,
                    submission_id=arguments.submission_id,
                    label=arguments.label,
                    reason=arguments.reason,
                    evidence_refs=load_json(arguments.evidence),
                    reviewer_id=arguments.reviewer_id,
                    signer=SoftwareECDSASigner.load(arguments.reviewer_private_key),
                )
                result = {
                    "status": "appended",
                    "idempotent": appended["idempotent"],
                    "record": appended["record"].model_dump(mode="json"),
                    "head": appended["head"].model_dump(mode="json"),
                    "lineage_indexed": appended["lineage_indexed"],
                }
            else:
                result = verify_review_ledger(
                    **common,
                    authority_public_key=authority,
                    reviewer_public_keys=keys,
                    expected_head=expected,
                    require_tip_anchor=arguments.require_tip_anchor,
                )
        if result["status"] != "failed":
            try:
                _export(arguments.export_head, result["head"], arguments.ledger)
                result["head_exported"] = arguments.export_head is not None
            except (OSError, ValueError) as exc:
                result["head_exported"] = False
                result["head_export_error"] = str(exc)
                # Preserve the committed operation result; the separate export failed.
                return result, 1
        return result, 1 if result["status"] == "failed" else 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        return {"status": "failed", "errors": [str(exc)]}, 1
