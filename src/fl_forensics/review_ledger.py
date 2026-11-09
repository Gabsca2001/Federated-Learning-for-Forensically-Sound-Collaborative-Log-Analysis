"""Append-only attributed reviews with explicit trusted-prefix/tip checks.

The ledger authenticates historical artifacts, not a new numerical execution.
No head read solely from this mutable filesystem is an independent anchor.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .crypto import DigestSigner, SoftwareECDSASigner, public_key_id, verify_digest_signature
from .in_round_admission import verify_in_round_signature
from .in_round_admission_models import InRoundContributionDecision, InRoundSecureCheckpoint
from .models import SignatureBlock
from .review_ledger_models import (
    ReviewEvidenceRef,
    ReviewHead,
    ReviewLedger,
    ReviewLedgerCore,
    ReviewRecord,
    ReviewRecordCore,
)
from .round_derivation import _verify_signature
from .round_derivation_models import (
    RoundDerivationBinding,
    RoundDerivationManifest,
    RoundScoringState,
)
from .secure_round import _verify_signed
from .secure_round_models import ContributionDecision, SecureRoundContext
from .storage import write_json_once
from .submission_evidence import _signed_valid
from .submission_evidence_models import RoundInputInventory


class ReviewLedgerError(ValueError):
    """Untrusted review input, changed history or stale append precondition."""


def _bytes(value: Any) -> bytes:
    return canonical_json_bytes(value.model_dump(mode="json")) + b"\n"


def _utc(value: datetime | None) -> str:
    value = value or datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReviewLedgerError("review time must include an offset")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sign(model: Any, core: Any, id_field: str, prefix: str, signer: DigestSigner) -> Any:
    digest = digest_object(core.model_dump(mode="json"))
    return model(
        **{
            id_field: prefix + digest,
            "core": core,
            "core_digest": digest,
            "signature": SignatureBlock(
                key_id=signer.key_id,
                value_b64=signer.sign_digest(digest),
                trust_level="software-development",
            ),
        }
    )


def _verify(value: Any, key: Any, id_field: str, prefix: str) -> None:
    digest = digest_object(value.core.model_dump(mode="json"))
    if not (
        value.core.signing_profile == value.signature.trust_level == "software-development"
        and value.core_digest == digest
        and getattr(value, id_field) == prefix + digest
        and value.signature.key_id == public_key_id(key)
        and verify_digest_signature(key, digest, value.signature.value_b64)
    ):
        raise ReviewLedgerError(f"invalid signed review artifact: {id_field}")


def _path(root: Path, *parts: str) -> Path:
    path = root.joinpath(*parts)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ReviewLedgerError("historical artifact path escapes its workspace")
    return path


def authenticate_review_subject(
    *, round_workspace: Path, trusted_coordinator_key: Any, expected_manifest_sha256: str
) -> dict[str, Any]:
    """Check signed historical references without invoking the current round verifier."""
    try:
        manifest_path = _path(round_workspace, "derivation", "manifest.json")
        manifest_data = manifest_path.read_bytes()
        if sha256_bytes(manifest_data) != expected_manifest_sha256:
            raise ReviewLedgerError("historical manifest differs from the pinned digest")
        manifest = RoundDerivationManifest.model_validate_json(manifest_data)
        _verify_signature(manifest, trusted_coordinator_key, "manifest_id", "round-derivation-")
        context = SecureRoundContext.model_validate_json(
            _path(round_workspace, "public", "round-context.json").read_bytes()
        )
        if not _verify_signed(context, trusted_coordinator_key):
            raise ReviewLedgerError("historical context signature is invalid")
        if context.core_digest != manifest.core.context_digest:
            raise ReviewLedgerError("historical context differs from the manifest")
        for name, expected in (
            ("base-model.json", context.core.base_model_sha256),
            ("training-contract.json", context.core.training_contract_sha256),
            ("partition-manifest.json", context.core.partition_manifest_sha256),
            ("federation.yaml", context.core.federation_config_sha256),
        ):
            if sha256_file(_path(round_workspace, "public", name)) != expected:
                raise ReviewLedgerError(f"changed historical public artifact: {name}")
        for name, expected, model, id_field, prefix in (
            (
                "binding.json",
                manifest.core.binding_sha256,
                RoundDerivationBinding,
                "binding_id",
                "round-binding-",
            ),
            (
                "scoring-state.json",
                manifest.core.scoring_state_sha256,
                RoundScoringState,
                "scoring_id",
                "round-scoring-",
            ),
        ):
            path = _path(round_workspace, "derivation", name)
            artifact_data = path.read_bytes()
            if sha256_bytes(artifact_data) != expected:
                raise ReviewLedgerError(f"changed historical artifact: {name}")
            artifact = model.model_validate_json(artifact_data)
            _verify_signature(artifact, trusted_coordinator_key, id_field, prefix)
            if artifact.core.context_digest != context.core_digest:
                raise ReviewLedgerError("historical artifact context mismatch")
            inventory_hash = (
                artifact.core.input_inventory_sha256
                if name == "binding.json"
                else artifact.core.inventory_sha256
            )
            if inventory_hash != manifest.core.input_inventory_sha256:
                raise ReviewLedgerError("historical artifact refers to a different inventory")
        inventory_path = _path(round_workspace, "derivation", "input-inventory.json")
        inventory_data = inventory_path.read_bytes()
        if sha256_bytes(inventory_data) != manifest.core.input_inventory_sha256:
            raise ReviewLedgerError("changed historical inventory")
        inventory = RoundInputInventory.model_validate_json(inventory_data)
        if (
            not _signed_valid(
                inventory, trusted_coordinator_key, "inventory_id", "round-input-inventory-"
            )
            or inventory.core.context_digest != context.core_digest
        ):
            raise ReviewLedgerError("invalid historical inventory signature/context")
        checkpoint_path = _path(round_workspace, "checkpoint", "manifest.json")
        if manifest.core.checkpoint_sha256 is not None:
            checkpoint_data = checkpoint_path.read_bytes()
            if sha256_bytes(checkpoint_data) != manifest.core.checkpoint_sha256:
                raise ReviewLedgerError("changed historical checkpoint")
            checkpoint = InRoundSecureCheckpoint.model_validate_json(checkpoint_data)
            if not verify_in_round_signature(checkpoint, trusted_coordinator_key):
                raise ReviewLedgerError("invalid historical checkpoint signature")
            if checkpoint.core.context_digest != context.core_digest:
                raise ReviewLedgerError("historical checkpoint context mismatch")
            if (
                sha256_file(_path(round_workspace, "checkpoint", "global-model.json"))
                != checkpoint.core.global_model_sha256
            ):
                raise ReviewLedgerError("changed historical model bytes")
        elif manifest.core.round_status != "failed_without_checkpoint" or checkpoint_path.exists():
            raise ReviewLedgerError("inconsistent historical failed-round artifacts")
        known_clients = {client.client_id for client in context.core.clients}
        subjects = {}
        for item in manifest.core.dispositions:
            if item.submission_id in subjects or item.client_id not in known_clients:
                raise ReviewLedgerError("duplicate or unknown historical submission")
            if item.kind == "runtime_admission":
                decision_path = _path(
                    round_workspace, "in-round-decisions", f"{item.client_id}.json"
                )
                trust_path = _path(round_workspace, "decisions", f"{item.client_id}.json")
                decision_data = decision_path.read_bytes()
                trust_data = trust_path.read_bytes()
                if (
                    sha256_bytes(decision_data) != item.decision_sha256
                    or sha256_bytes(trust_data) != item.trust_decision_sha256
                ):
                    raise ReviewLedgerError("changed historical decision bytes")
                decision = InRoundContributionDecision.model_validate_json(decision_data)
                trust = ContributionDecision.model_validate_json(trust_data)
                if not verify_in_round_signature(
                    decision, trusted_coordinator_key
                ) or not _verify_signed(trust, trusted_coordinator_key):
                    raise ReviewLedgerError("invalid historical decision signature")
                if (
                    decision.core.context_digest != context.core_digest
                    or decision.core.client_id != item.client_id
                    or decision.core.bundle_sha256 != item.bundle_sha256
                    or trust.core.bundle_sha256 != item.bundle_sha256
                    or trust.core.context_id != context.context_id
                    or trust.core.campaign_id != context.core.campaign_id
                    or trust.core.round_number != context.core.round_number
                    or trust.core.client_id != item.client_id
                    or decision.core.trust_decision_sha256 != item.trust_decision_sha256
                ):
                    raise ReviewLedgerError("historical decision refers to another subject")
            elif item.decision_sha256 is not None or item.trust_decision_sha256 is not None:
                raise ReviewLedgerError("protocol rejection claims a fictitious runtime decision")
            subjects[item.submission_id] = {
                "submission_id": item.submission_id,
                "client_id": item.client_id,
                "disposition_sha256": digest_object(item.model_dump(mode="json")),
                "decision_sha256": item.decision_sha256,
                "checkpoint_sha256": manifest.core.checkpoint_sha256,
            }
        return {
            "historical_artifacts_authenticated": True,
            "historical_round_recomputed": False,
            "manifest_sha256": expected_manifest_sha256,
            "context_digest": context.core_digest,
            "subjects": subjects,
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ReviewLedgerError(str(exc)) from exc


@contextmanager
def _exclusive(ledger_workspace: Path) -> Iterator[None]:
    """Serialize cooperative writers/readers; do not break another process's lock."""
    ledger_workspace.mkdir(parents=True, exist_ok=True)
    path = ledger_workspace / ".append.lock"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ReviewLedgerError("review ledger is busy; retry with the expected head") from exc
    try:
        yield
    finally:
        os.close(descriptor)
        path.unlink()


def _read_history(
    *,
    ledger_workspace: Path,
    round_workspace: Path,
    coordinator_public_key: Any,
    authority_public_key: Any,
    reviewer_public_keys: Mapping[str, Any],
) -> dict[str, Any]:
    genesis_path = ledger_workspace / "ledger.json"
    genesis_data = genesis_path.read_bytes()
    genesis = ReviewLedger.model_validate_json(genesis_data)
    if genesis_data != _bytes(genesis):
        raise ReviewLedgerError("review genesis has noncanonical bytes")
    _verify(genesis, authority_public_key, "ledger_id", "review-ledger-")
    if not genesis.core.authorized_reviewers:
        raise ReviewLedgerError("review ledger has no authorized reviewers")
    for reviewer, key_id in genesis.core.authorized_reviewers.items():
        if (
            reviewer not in reviewer_public_keys
            or public_key_id(reviewer_public_keys[reviewer]) != key_id
        ):
            raise ReviewLedgerError("missing or changed pinned reviewer key")
    subject = authenticate_review_subject(
        round_workspace=round_workspace,
        trusted_coordinator_key=coordinator_public_key,
        expected_manifest_sha256=genesis.core.manifest_sha256,
    )
    if subject["context_digest"] != genesis.core.context_digest:
        raise ReviewLedgerError("ledger and historical context differ")
    genesis_hash = sha256_bytes(genesis_data)
    head = ReviewHead(
        ledger_id=genesis.ledger_id,
        genesis_sha256=genesis_hash,
        sequence=0,
        last_record_sha256=genesis_hash,
    )
    heads, records, latest, operations = [head], [], {}, {}
    data = (ledger_workspace / "review-ledger.jsonl").read_bytes()
    for line in data.splitlines(keepends=True):
        record = ReviewRecord.model_validate_json(line)
        if line != _bytes(record):
            raise ReviewLedgerError("review ledger has noncanonical or incomplete lines")
        core = record.core
        if core.reviewer_id not in genesis.core.authorized_reviewers:
            raise ReviewLedgerError("review author is not authorized by the ledger")
        _verify(record, reviewer_public_keys[core.reviewer_id], "review_id", "review-")
        expected_subject = subject["subjects"].get(core.submission_id)
        if expected_subject is None or any(
            getattr(core, name) != expected_subject[name]
            for name in ("disposition_sha256", "decision_sha256", "checkpoint_sha256")
        ):
            raise ReviewLedgerError("review refers to a different historical subject")
        previous = latest.get(core.submission_id)
        if (
            core.ledger_id != genesis.ledger_id
            or core.context_digest != subject["context_digest"]
            or core.manifest_sha256 != subject["manifest_sha256"]
            or core.sequence != head.sequence + 1
            or core.previous_record_sha256 != head.last_record_sha256
            or core.subject_revision != (previous["revision"] + 1 if previous else 1)
            or core.previous_subject_record_sha256
            != (previous["record_sha256"] if previous else None)
            or core.operation_id in operations
        ):
            raise ReviewLedgerError("broken review history or duplicate operation")
        record_hash = sha256_bytes(line)
        head = ReviewHead(
            ledger_id=genesis.ledger_id,
            genesis_sha256=genesis_hash,
            sequence=core.sequence,
            last_record_sha256=record_hash,
        )
        latest[core.submission_id] = {
            "label": core.label,
            "revision": core.subject_revision,
            "reviewer_id": core.reviewer_id,
            "review_id": record.review_id,
            "record_sha256": record_hash,
            "created_at": core.created_at,
        }
        heads.append(head)
        records.append(record)
        operations[core.operation_id] = record
    return {
        "genesis": genesis,
        "subject": subject,
        "heads": heads,
        "head": head,
        "records": records,
        "latest": latest,
        "operations": operations,
    }


def initialize_review_ledger(
    *,
    ledger_workspace: Path,
    round_workspace: Path,
    expected_manifest_sha256: str,
    coordinator_public_key: Any,
    authority_signer: SoftwareECDSASigner,
    authorized_reviewers: Mapping[str, Any],
    created_at: datetime | None = None,
) -> ReviewHead:
    if ledger_workspace.resolve().is_relative_to(round_workspace.resolve()):
        raise ReviewLedgerError("keep semantic reviews outside the historical round workspace")
    if not authorized_reviewers or any(not name.strip() for name in authorized_reviewers):
        raise ReviewLedgerError("named authorized reviewers are required")
    subject = authenticate_review_subject(
        round_workspace=round_workspace,
        trusted_coordinator_key=coordinator_public_key,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    with _exclusive(ledger_workspace):
        genesis_path = ledger_workspace / "ledger.json"
        if not genesis_path.exists():
            log = ledger_workspace / "review-ledger.jsonl"
            try:
                descriptor = os.open(log, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
            except FileExistsError:
                if log.read_bytes():
                    raise ReviewLedgerError(
                        "nonempty review log without authenticated genesis"
                    ) from None
            core = ReviewLedgerCore(
                manifest_sha256=expected_manifest_sha256,
                context_digest=subject["context_digest"],
                authorized_reviewers={
                    name: public_key_id(key) for name, key in sorted(authorized_reviewers.items())
                },
                created_at=_utc(created_at),
            )
            genesis = _sign(ReviewLedger, core, "ledger_id", "review-ledger-", authority_signer)
            _verify(
                genesis, authority_signer.private_key.public_key(), "ledger_id", "review-ledger-"
            )
            write_json_once(genesis_path, genesis.model_dump(mode="json"))
        state = _read_history(
            ledger_workspace=ledger_workspace,
            round_workspace=round_workspace,
            coordinator_public_key=coordinator_public_key,
            authority_public_key=authority_signer.private_key.public_key(),
            reviewer_public_keys=authorized_reviewers,
        )
        if state["genesis"].core.manifest_sha256 != expected_manifest_sha256 or (
            state["genesis"].core.authorized_reviewers
            != {name: public_key_id(key) for name, key in authorized_reviewers.items()}
        ):
            raise ReviewLedgerError("existing ledger has a different subject or reviewer roster")
        if created_at is not None and state["genesis"].core.created_at != _utc(created_at):
            raise ReviewLedgerError("existing ledger has a different creation-time claim")
        return state["head"]


def _index(ledger_workspace: Path, record: ReviewRecord, record_hash: str) -> dict[str, Any]:
    from .lineage import LineageStore

    try:
        LineageStore(ledger_workspace / "lineage").record_review_path(
            manifest_sha256=record.core.manifest_sha256,
            context_digest=record.core.context_digest,
            submission_id=record.core.submission_id,
            disposition_sha256=record.core.disposition_sha256,
            review_id=record.review_id,
            review_record_sha256=record_hash,
            previous_review_record_sha256=record.core.previous_subject_record_sha256,
        )
        return {"lineage_indexed": True}
    except (OSError, ValueError) as exc:
        # The primary signed history is committed; a rebuildable index is not its authority.
        return {"lineage_indexed": False, "lineage_index_error": str(exc)}


def append_review(
    *,
    ledger_workspace: Path,
    round_workspace: Path,
    coordinator_public_key: Any,
    authority_public_key: Any,
    reviewer_public_keys: Mapping[str, Any],
    expected_previous_head: ReviewHead,
    operation_id: str,
    submission_id: str,
    label: str,
    reason: str,
    evidence_refs: list[dict[str, str]],
    reviewer_id: str,
    signer: DigestSigner,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    try:
        if ledger_workspace.resolve().is_relative_to(round_workspace.resolve()):
            raise ReviewLedgerError("keep semantic reviews outside the historical round workspace")
        with _exclusive(ledger_workspace):
            state = _read_history(
                ledger_workspace=ledger_workspace,
                round_workspace=round_workspace,
                coordinator_public_key=coordinator_public_key,
                authority_public_key=authority_public_key,
                reviewer_public_keys=reviewer_public_keys,
            )
            if reviewer_id not in state["genesis"].core.authorized_reviewers or (
                signer.key_id != public_key_id(reviewer_public_keys[reviewer_id])
            ):
                raise ReviewLedgerError("review signer is not the authorized author")
            target = state["subject"]["subjects"].get(submission_id)
            if target is None:
                raise ReviewLedgerError("unknown historical submission")
            existing = state["operations"].get(operation_id)
            requested = {
                "submission_id": submission_id,
                "label": label,
                "reason": reason,
                "evidence_refs": [ReviewEvidenceRef.model_validate(item) for item in evidence_refs],
                "reviewer_id": reviewer_id,
                "operation_id": operation_id,
            }
            if existing is not None:
                if (
                    any(getattr(existing.core, name) != value for name, value in requested.items())
                    or (created_at is not None and existing.core.created_at != _utc(created_at))
                    or expected_previous_head != state["heads"][existing.core.sequence - 1]
                ):
                    raise ReviewLedgerError(
                        "operation id was already used with different review data"
                    )
                indexed = _index(
                    ledger_workspace,
                    existing,
                    state["heads"][existing.core.sequence].last_record_sha256,
                )
                return {"record": existing, "head": state["head"], "idempotent": True, **indexed}
            if expected_previous_head != state["head"]:
                raise ReviewLedgerError("stale expected review head")
            previous = state["latest"].get(submission_id)
            core = ReviewRecordCore(
                ledger_id=state["genesis"].ledger_id,
                sequence=state["head"].sequence + 1,
                subject_revision=previous["revision"] + 1 if previous else 1,
                context_digest=state["subject"]["context_digest"],
                manifest_sha256=state["subject"]["manifest_sha256"],
                disposition_sha256=target["disposition_sha256"],
                decision_sha256=target["decision_sha256"],
                checkpoint_sha256=target["checkpoint_sha256"],
                previous_record_sha256=state["head"].last_record_sha256,
                previous_subject_record_sha256=previous["record_sha256"] if previous else None,
                created_at=_utc(created_at),
                **requested,
            )
            record = _sign(ReviewRecord, core, "review_id", "review-", signer)
            _verify(record, reviewer_public_keys[reviewer_id], "review_id", "review-")
            data = _bytes(record)
            with (ledger_workspace / "review-ledger.jsonl").open("ab") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            head = ReviewHead(
                ledger_id=state["genesis"].ledger_id,
                genesis_sha256=state["head"].genesis_sha256,
                sequence=core.sequence,
                last_record_sha256=sha256_bytes(data),
            )
            indexed = _index(ledger_workspace, record, head.last_record_sha256)
            return {"record": record, "head": head, "idempotent": False, **indexed}
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ReviewLedgerError(str(exc)) from exc


def verify_review_ledger(
    *,
    ledger_workspace: Path,
    round_workspace: Path,
    coordinator_public_key: Any,
    authority_public_key: Any,
    reviewer_public_keys: Mapping[str, Any],
    expected_head: ReviewHead | None = None,
    require_tip_anchor: bool = False,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "status": "failed",
        "chain_verified": False,
        "historical_artifacts_authenticated": False,
        "historical_round_recomputed": False,
        "anchor_status": "unanchored",
        "rollback_protection_verified": False,
        "anchored_sequence": None,
        "current_tip_anchored": False,
        "head": None,
        "semantic_states": {},
        "errors": [],
        "semantic_projection_rule": "latest attributed judgment per submission, not consensus or truth",
        "evidence_payloads_verified": False,
        "review_timestamps_attested": False,
        "limitations": [
            "A valid attributed judgment is not ground truth or a causal finding.",
            "Without a trusted external head, an internally valid rollback/fork may be invisible.",
            "Historical numerical execution requires its preserved source release and environment.",
        ],
    }
    try:
        # Read one presented JSONL snapshot; verification also works on read-only exports.
        # A concurrent/interrupted partial row fails closed and can be retried.
        state = _read_history(
            ledger_workspace=ledger_workspace,
            round_workspace=round_workspace,
            coordinator_public_key=coordinator_public_key,
            authority_public_key=authority_public_key,
            reviewer_public_keys=reviewer_public_keys,
        )
        report.update(
            {
                "chain_verified": True,
                "historical_artifacts_authenticated": True,
                "head": state["head"].model_dump(mode="json"),
            }
        )
        if expected_head is not None:
            expected_head = ReviewHead.model_validate(expected_head)
            if expected_head.sequence >= len(state["heads"]) or (
                state["heads"][expected_head.sequence] != expected_head
            ):
                raise ReviewLedgerError("history does not contain the trusted head")
            report["anchor_status"] = (
                "trusted_tip" if expected_head == state["head"] else "trusted_prefix"
            )
            report["rollback_protection_verified"] = True
            report["anchored_sequence"] = expected_head.sequence
            report["current_tip_anchored"] = expected_head == state["head"]
        if require_tip_anchor and report["anchor_status"] != "trusted_tip":
            raise ReviewLedgerError("a trusted anchor of the current tip is required")
        report["semantic_states"] = {
            submission: state["latest"].get(
                submission,
                {
                    "label": "not_reviewed",
                    "revision": 0,
                    "reviewer_id": None,
                },
            )
            for submission in state["subject"]["subjects"]
        }
        report["status"] = "verified"
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        report["errors"].append(str(exc))
    return report
