"""Client receipts and coverage relative to explicitly supplied evidence.

Trusted keys/context are supplied by the caller, never taken from a submission.
This module neither witnesses delivery/time nor performs training admission.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, digest_object, sha256_file
from .crypto import DigestSigner, public_key_id, verify_digest_signature
from .models import SignatureBlock
from .secure_round_models import SecureRoundContext, UpdateBundle
from .storage import load_json, write_once
from .submission_evidence_models import (
    RoundInputInventory,
    RoundInputInventoryCore,
    SubmissionIntakeEntry,
    SubmissionReceipt,
    SubmissionReceiptCore,
)


class SubmissionEvidenceError(ValueError):
    """Invalid evidence or inconsistent immutable client copies."""


def _time(value: str) -> datetime:
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() is None:
        raise SubmissionEvidenceError("timestamp must include a UTC offset")
    return result


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SubmissionEvidenceError("timestamp must include a UTC offset")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _signature(signer: DigestSigner, digest: str, trust_level: str) -> SignatureBlock:
    return SignatureBlock(
        key_id=signer.key_id, value_b64=signer.sign_digest(digest), trust_level=trust_level
    )


def _signed_valid(value: Any, key: Any, id_field: str, prefix: str) -> bool:
    digest = digest_object(value.core.model_dump(mode="json"))
    return (
        digest == value.core_digest
        and getattr(value, id_field) == prefix + digest
        and value.signature.key_id == public_key_id(key)
        and verify_digest_signature(key, digest, value.signature.value_b64)
    )


def _context_valid(context: SecureRoundContext, key: Any) -> bool:
    # Reuse the existing secure-round signature/identifier contract.
    from .secure_round import _verify_signed

    clients = [item.client_id for item in context.core.clients]
    return (
        _verify_signed(context, key)
        and len(clients) == len(set(clients)) == context.core.required_client_count
        and _time(context.core.issued_at) < _time(context.core.expires_at)
    )


def submission_identity(
    context: SecureRoundContext, client_id: str, bundle_sha256: str
) -> str:
    return "submission-" + digest_object(
        {
            "domain": "fl-submission-identity-v1",
            "campaign_id": context.core.campaign_id,
            "context_digest": context.core_digest,
            "client_id": client_id,
            "bundle_sha256": bundle_sha256,
        }
    )


def _bundle_matches(bundle: UpdateBundle, context: SecureRoundContext, key: Any) -> bool:
    from .secure_round import _verify_signed

    expected = next(
        (item for item in context.core.clients if item.client_id == bundle.core.client_id),
        None,
    )
    return (
        expected is not None
        and _verify_signed(bundle, key)
        and bundle.core.campaign_id == context.core.campaign_id
        and bundle.core.context_id == context.context_id
        and bundle.core.context_digest == context.core_digest
        and bundle.core.round_number == context.core.round_number
        and bundle.core.base_model_sha256 == context.core.base_model_sha256
        and bundle.core.node_id == expected.node_id
        and bundle.core.enrollment_id == expected.enrollment_id
        and bundle.core.snapshot_sha256 == expected.snapshot_sha256
        and bundle.core.num_examples == expected.train_row_count
    )


def verify_submission_receipt(
    receipt: SubmissionReceipt, *, context: SecureRoundContext, client_public_key: Any
) -> bool:
    """Verify a client claim; context authentication is the caller's precondition."""
    try:
        core = receipt.core
        return (
            receipt.schema_version == "1.0"
            and receipt.artifact_type == "submission_receipt"
            and core.domain == "fl-submission-receipt-v1"
            and receipt.signature.trust_level == core.signing_trust_level
            and _signed_valid(receipt, client_public_key, "receipt_id", "submission-receipt-")
            and core.submission_id == submission_identity(context, core.client_id, core.bundle_sha256)
            and core.campaign_id == context.core.campaign_id
            and core.context_id == context.context_id
            and core.context_digest == context.core_digest
            and core.round_number == context.core.round_number
            and core.base_model_sha256 == context.core.base_model_sha256
            and core.previous_checkpoint_sha256 == context.core.previous_checkpoint_sha256
            and core.client_id in {item.client_id for item in context.core.clients}
            and _time(context.core.issued_at) <= _time(core.submitted_at)
            < _time(context.core.expires_at)
        )
    except (ValueError, TypeError, AttributeError):
        return False


def create_submission_receipt(
    *,
    bundle_path: Path,
    context: SecureRoundContext,
    signer: DigestSigner,
    client_public_key: Any,
    trust_level: str,
    submitted_at: datetime | None = None,
) -> SubmissionReceipt:
    """Create a signed claim after validating the bundle against the pinned key."""
    bundle = UpdateBundle.model_validate(load_json(bundle_path))
    if not _bundle_matches(bundle, context, client_public_key):
        raise SubmissionEvidenceError("bundle does not match context or trusted client key")
    if signer.key_id != public_key_id(client_public_key):
        raise SubmissionEvidenceError("receipt signer does not match trusted client key")
    if trust_level != bundle.signature.trust_level:
        raise SubmissionEvidenceError("receipt and bundle trust levels differ")
    bundle_hash = sha256_file(bundle_path)
    core = SubmissionReceiptCore(
        submission_id=submission_identity(context, bundle.core.client_id, bundle_hash),
        campaign_id=context.core.campaign_id,
        context_id=context.context_id,
        context_digest=context.core_digest,
        round_number=context.core.round_number,
        client_id=bundle.core.client_id,
        base_model_sha256=context.core.base_model_sha256,
        previous_checkpoint_sha256=context.core.previous_checkpoint_sha256,
        bundle_id=bundle.bundle_id,
        bundle_sha256=bundle_hash,
        bundle_core_digest=bundle.core_digest,
        signing_trust_level=trust_level,
        submitted_at=_utc(submitted_at or datetime.now(UTC)),
    )
    digest = digest_object(core.model_dump(mode="json"))
    receipt = SubmissionReceipt(
        receipt_id="submission-receipt-" + digest,
        core=core,
        core_digest=digest,
        signature=_signature(signer, digest, trust_level),
    )
    if not verify_submission_receipt(receipt, context=context, client_public_key=client_public_key):
        raise SubmissionEvidenceError("receipt contains an invalid client time claim")
    return receipt


def ensure_submission_receipt(
    *,
    bundle_path: Path,
    context: SecureRoundContext,
    signer: DigestSigner,
    client_public_key: Any,
    trust_level: str,
    client_receipt_root: Path,
    submitted_at: datetime | None = None,
) -> SubmissionReceipt:
    """Reuse signed bytes on retry, recovering either missing copy from the other."""
    bundle = UpdateBundle.model_validate(load_json(bundle_path))
    if not _bundle_matches(bundle, context, client_public_key):
        raise SubmissionEvidenceError("bundle does not match trusted context/client")
    if client_receipt_root.resolve().is_relative_to(bundle_path.parent.resolve()):
        raise SubmissionEvidenceError("client evidence must be outside the submission directory")
    identity = submission_identity(context, bundle.core.client_id, sha256_file(bundle_path))
    paths = [bundle_path.parent / "submission-receipt.json", client_receipt_root / f"{identity}.json"]
    existing = [path.read_bytes() for path in paths if path.is_file()]
    if existing:
        if any(value != existing[0] for value in existing):
            raise SubmissionEvidenceError("immutable receipt copies disagree")
        receipt = SubmissionReceipt.model_validate_json(existing[0])
        if (
            not verify_submission_receipt(
                receipt, context=context, client_public_key=client_public_key
            )
            or receipt.core.submission_id != identity
            or receipt.core.bundle_core_digest != bundle.core_digest
            or receipt.core.bundle_id != bundle.bundle_id
            or receipt.signature.trust_level != bundle.signature.trust_level
        ):
            raise SubmissionEvidenceError("existing receipt does not match bundle/context")
        data = existing[0]
    else:
        receipt = create_submission_receipt(
            bundle_path=bundle_path,
            context=context,
            signer=signer,
            client_public_key=client_public_key,
            trust_level=trust_level,
            submitted_at=submitted_at,
        )
        data = canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
    for path in paths:
        write_once(path, data)
    return receipt


def _intake_entries(
    *,
    receipts: Sequence[SubmissionReceipt],
    context: SecureRoundContext,
    bundle_paths: Mapping[str, Path],
    client_public_keys: Mapping[str, Any],
) -> list[SubmissionIntakeEntry]:
    groups: dict[str, list[SubmissionReceipt]] = defaultdict(list)
    client_submissions: dict[str, set[str]] = defaultdict(set)
    for receipt in receipts:
        key = client_public_keys.get(receipt.core.client_id)
        if key is None or not verify_submission_receipt(
            receipt, context=context, client_public_key=key
        ):
            raise SubmissionEvidenceError("invalid receipt or missing trusted client key")
        groups[receipt.core.submission_id].append(receipt)
        client_submissions[receipt.core.client_id].add(receipt.core.submission_id)
    entries = []
    for identity, copies in sorted(groups.items()):
        core = copies[0].core
        if any(
            item.core.bundle_core_digest != core.bundle_core_digest
            or item.core.bundle_id != core.bundle_id
            for item in copies
        ):
            raise SubmissionEvidenceError("conflicting claims about the same bundle bytes")
        outcome = "ready_for_admission"
        reasons = []
        if len(client_submissions[core.client_id]) > 1:
            outcome = "rejected_conflict"
            reasons = ["multiple_bundle_hashes_for_client_context"]
        else:
            path = bundle_paths.get(core.bundle_sha256)
            if path is None or not path.is_file():
                outcome = "rejected_missing_payload"
                reasons = ["bundle_unavailable"]
            else:
                try:
                    bundle = UpdateBundle.model_validate(load_json(path))
                    valid = (
                        sha256_file(path) == core.bundle_sha256
                        and bundle.core_digest == core.bundle_core_digest
                        and bundle.bundle_id == core.bundle_id
                        and bundle.core.client_id == core.client_id
                        and _bundle_matches(bundle, context, client_public_keys[core.client_id])
                    )
                    if not valid:
                        outcome = "rejected_invalid_payload"
                        reasons = ["bundle_integrity_or_context_mismatch"]
                    else:
                        for name, expected in (
                            ("update.json", bundle.core.update_sha256),
                            ("metrics.json", bundle.core.metrics_sha256),
                        ):
                            payload = path.parent / name
                            if not payload.is_file():
                                outcome = "rejected_missing_payload"
                                reasons = [f"{name}_unavailable"]
                                break
                            if sha256_file(payload) != expected:
                                outcome = "rejected_invalid_payload"
                                reasons = [f"{name}_digest_mismatch"]
                                break
                except (OSError, ValueError, TypeError):
                    outcome = "rejected_invalid_payload"
                    reasons = ["unreadable_or_invalid_bundle"]
        entries.append(
            SubmissionIntakeEntry(
                submission_id=identity,
                client_id=core.client_id,
                bundle_sha256=core.bundle_sha256,
                bundle_core_digest=core.bundle_core_digest,
                receipt_core_digests=sorted({item.core_digest for item in copies}),
                outcome=outcome,
                reasons=reasons,
            )
        )
    return entries


def _inventory_core(
    *, context: SecureRoundContext, entries: list[SubmissionIntakeEntry], closed_at: str
) -> RoundInputInventoryCore:
    expected = sorted(item.client_id for item in context.core.clients)
    seen = {entry.client_id for entry in entries}
    return RoundInputInventoryCore(
        campaign_id=context.core.campaign_id,
        context_id=context.context_id,
        context_digest=context.core_digest,
        round_number=context.core.round_number,
        base_model_sha256=context.core.base_model_sha256,
        previous_checkpoint_sha256=context.core.previous_checkpoint_sha256,
        expected_client_ids=expected,
        missing_client_ids=sorted(set(expected) - seen),
        entries=entries,
        closed_at=closed_at,
    )


def build_round_input_inventory(
    *,
    context: SecureRoundContext,
    receipts: Sequence[SubmissionReceipt],
    bundle_paths: Mapping[str, Path],
    client_public_keys: Mapping[str, Any],
    coordinator_signer: DigestSigner,
    coordinator_public_key: Any,
    closed_at: datetime,
) -> RoundInputInventory:
    """Sign observed intake outcomes, not final statistical admission decisions."""
    if not _context_valid(context, coordinator_public_key):
        raise SubmissionEvidenceError("invalid authenticated round context")
    if coordinator_signer.key_id != public_key_id(coordinator_public_key):
        raise SubmissionEvidenceError("wrong coordinator signer")
    closed = _utc(closed_at)
    if _time(closed) < _time(context.core.issued_at):
        raise SubmissionEvidenceError("inventory closes before round context issuance")
    entries = _intake_entries(
        receipts=receipts,
        context=context,
        bundle_paths=bundle_paths,
        client_public_keys=client_public_keys,
    )
    core = _inventory_core(context=context, entries=entries, closed_at=closed)
    digest = digest_object(core.model_dump(mode="json"))
    return RoundInputInventory(
        inventory_id="round-input-inventory-" + digest,
        core=core,
        core_digest=digest,
        signature=_signature(coordinator_signer, digest, "software-development"),
    )


def verify_submission_coverage(
    *,
    inventory: RoundInputInventory,
    context: SecureRoundContext,
    evidence_receipts: Sequence[SubmissionReceipt],
    bundle_paths: Mapping[str, Path],
    client_public_keys: Mapping[str, Any],
    coordinator_public_key: Any,
    evidence_source: str,
) -> dict[str, Any]:
    """Recompute coverage from external T; never certify delivery or admission."""
    report: dict[str, Any] = {
        "status": "invalid",
        "evidence_profile": "provided_client_evidence",
        "verification_scope": "submission_intake_only",
        "evidence_source": evidence_source,
        "coverage_verified": False,
        "deadline_verified": False,
        "admission_decisions_verified": False,
        "delivery_verified": False,
        "inventory_fully_recomputed": False,
        "intake_outcomes_verified": False,
        "unverified_outcome_submission_ids": [],
        "additional_inventory_submission_ids": [],
        "missing_submission_ids": [],
        "errors": [],
        "property_statuses": {
            "coverage": "not_checked", "intake_outcomes": "not_checked",
            "admission_decisions": "not_checked", "deadline": "not_checked",
            "delivery": "not_checked",
        },
        "limitations": [
            "Coverage is relative to the supplied client evidence set, not all submissions.",
            "Client timestamps do not prove delivery or registration before a deadline.",
            "Intake outcomes do not verify trust/statistical admission or a checkpoint.",
            "Signing trust levels are client claims; this API does not verify TPM attestation.",
        ],
    }
    errors = report["errors"]
    try:
        if not evidence_source.strip():
            raise SubmissionEvidenceError("evidence source must be declared")
        if not _context_valid(context, coordinator_public_key):
            raise SubmissionEvidenceError("invalid authenticated round context")
        if (
            inventory.schema_version != "1.0"
            or inventory.artifact_type != "round_input_inventory"
            or inventory.core.domain != "fl-round-input-inventory-v1"
            or inventory.core.evidence_profile != "provided_client_evidence"
            or inventory.signature.trust_level != "software-development"
            or not _signed_valid(
                inventory, coordinator_public_key, "inventory_id", "round-input-inventory-"
            )
        ):
            raise SubmissionEvidenceError("invalid inventory signature or signed domain")
        if _time(inventory.core.closed_at) < _time(context.core.issued_at):
            raise SubmissionEvidenceError("inventory closes before round context issuance")
        actual_ids = [entry.submission_id for entry in inventory.core.entries]
        if actual_ids != sorted(set(actual_ids)):
            raise SubmissionEvidenceError("inventory submissions must be unique and ordered")
        if inventory.core != _inventory_core(
            context=context, entries=inventory.core.entries, closed_at=inventory.core.closed_at
        ):
            raise SubmissionEvidenceError("inventory context or client accounting mismatch")
        known_clients = set(inventory.core.expected_client_ids)
        client_ids: dict[str, set[str]] = defaultdict(set)
        for entry in inventory.core.entries:
            if (
                entry.client_id not in known_clients
                or entry.submission_id != submission_identity(
                    context, entry.client_id, entry.bundle_sha256
                )
                or not entry.receipt_core_digests
                or entry.receipt_core_digests != sorted(set(entry.receipt_core_digests))
            ):
                raise SubmissionEvidenceError("invalid inventory entry identity or receipt references")
            client_ids[entry.client_id].add(entry.submission_id)
        for receipt in evidence_receipts:
            client_ids[receipt.core.client_id].add(receipt.core.submission_id)
        entries = _intake_entries(
            receipts=evidence_receipts,
            context=context,
            bundle_paths=bundle_paths,
            client_public_keys=client_public_keys,
        )
        actual = {entry.submission_id: entry for entry in inventory.core.entries}
        evidence_ids = {entry.submission_id for entry in entries}
        report["missing_submission_ids"] = sorted(
            evidence_ids - set(actual)
        )
        report["additional_inventory_submission_ids"] = sorted(set(actual) - evidence_ids)
        for entry in entries:
            observed = actual.get(entry.submission_id)
            metadata = {"receipt_core_digests", "outcome", "reasons"}
            if (
                observed is None
                or observed.model_dump(exclude=metadata) != entry.model_dump(exclude=metadata)
                or not set(entry.receipt_core_digests).issubset(observed.receipt_core_digests)
            ):
                errors.append(f"missing or inconsistent intake outcome: {entry.submission_id}")
            elif (observed.outcome, observed.reasons) != (entry.outcome, entry.reasons):
                if (
                    observed.outcome == "rejected_conflict"
                    and entry.outcome != "rejected_conflict"
                    and len(client_ids[entry.client_id]) > 1
                ):
                    report["unverified_outcome_submission_ids"].append(entry.submission_id)
                else:
                    errors.append(f"incorrect intake outcome: {entry.submission_id}")
        report["evidence_submission_count"] = len(entries)
        report["conflicting_submission_ids"] = [
            entry.submission_id for entry in entries if entry.outcome == "rejected_conflict"
        ]
        if not errors:
            if entries:
                report["status"] = "verified_for_evidence_set"
                report["coverage_verified"] = True
                report["intake_outcomes_verified"] = not report["unverified_outcome_submission_ids"]
                report["inventory_fully_recomputed"] = (
                    not report["additional_inventory_submission_ids"]
                    and all(actual[entry.submission_id] == entry for entry in entries)
                )
                if not report["inventory_fully_recomputed"]:
                    report["limitations"].append(
                        "Inventory entries outside the supplied evidence are not client-authenticated."
                    )
                if report["unverified_outcome_submission_ids"]:
                    report["limitations"].append(
                        "A conflict claimed only by the coordinator is not proven client equivocation."
                    )
            else:
                report["status"] = "insufficient_evidence"
                report["limitations"].append("An empty evidence set cannot establish coverage.")
    except (ValueError, TypeError, AttributeError, OSError) as exc:
        errors.append(str(exc))
    report["property_statuses"]["coverage"] = (
        "failed" if errors else "verified" if report["coverage_verified"] else "insufficient_evidence"
    )
    report["property_statuses"]["intake_outcomes"] = (
        "verified" if report["intake_outcomes_verified"] else "insufficient_evidence"
    )
    return report
