"""Independent receipt registration, transactional append-only log and closure.

This opt-in profile preserves the existing provided-client-evidence contract.
The independent witness and pinned TSA are trusted for honest operation; a
single signed chain does not eliminate witness equivocation or prove delivery
to the training coordinator. Public verification needs external policy/head pins.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, digest_object, sha256_bytes
from .crypto import DigestSigner, public_key_id
from .submission_evidence import (
    SubmissionEvidenceError,
    _context_valid,
    _signature,
    _signed_valid,
    _time,
    verify_submission_coverage,
    verify_submission_receipt,
)
from .submission_evidence_models import RoundInputInventory, SubmissionReceipt
from .witness_models import (
    ClosureCore,
    ClosureSubject,
    RegistrationCore,
    RegistrationSubject,
    WitnessClosure,
    WitnessPhasePolicyCore,
    WitnessPolicy,
    WitnessPolicyCore,
    WitnessRegistration,
    WitnessSnapshot,
)
from .witness_time import TimeInterval, TimestampProvider, verify_timestamp


class WitnessError(SubmissionEvidenceError):
    """Fail-closed witness protocol error."""


def _bytes(value: Any) -> bytes:
    return canonical_json_bytes(value.model_dump(mode="json"))


def _signed(core: Any, signer: DigestSigner) -> dict[str, Any]:
    digest = digest_object(core.model_dump(mode="json"))
    return {
        "core": core,
        "core_digest": digest,
        "signature": _signature(signer, digest, "software-development"),
    }


def _verify_signed(value: Any, key: Any) -> None:
    # Revalidation catches mutable model_copy artifacts as well as on-disk input.
    value = type(value).model_validate_json(value.model_dump_json())
    if value.signature.trust_level != "software-development" or not _signed_valid(
        value, key, "core_digest", ""
    ):
        raise WitnessError("invalid witness signature or core digest")


def create_witness_policy(
    *,
    context: Any,
    coordinator_public_key: Any,
    client_public_keys: Mapping[str, Any],
    signer: DigestSigner,
    trust_store: bytes,
    tsa_policy_oid: str,
    maximum_accuracy_microseconds: int = 1_000_000,
    client_signing_trust_levels: Mapping[str, str] | None = None,
    registration_deadline: str | None = None,
) -> WitnessPolicy:
    core_type = WitnessPolicyCore if registration_deadline is None else WitnessPhasePolicyCore
    extra = (
        {} if registration_deadline is None else {"registration_deadline": registration_deadline}
    )
    core = core_type(
        **extra,
        witness_key_id=signer.key_id,
        context_digest=context.core_digest,
        coordinator_key_id=public_key_id(coordinator_public_key),
        client_key_ids={k: public_key_id(v) for k, v in sorted(client_public_keys.items())},
        client_signing_trust_levels=dict(client_signing_trust_levels)
        if client_signing_trust_levels is not None
        else {k: "software-development" for k in client_public_keys},
        tsa_trust_store_sha256=sha256_bytes(trust_store),
        tsa_policy_oid=tsa_policy_oid,
        maximum_accuracy_microseconds=maximum_accuracy_microseconds,
    )
    policy = WitnessPolicy(**_signed(core, signer))
    # The public key is supplied separately to verification; initialization
    # still checks key separation and a complete authenticated client contract.
    if not _context_valid(context, coordinator_public_key):
        raise WitnessError("invalid authenticated round context")
    expected = {c.client_id for c in context.core.clients}
    if set(client_public_keys) != expected:
        raise WitnessError("client key set differs from round contract")
    if set(core.client_signing_trust_levels) != expected:
        raise WitnessError("client signing-level set differs from round contract")
    if signer.key_id in {core.coordinator_key_id, *core.client_key_ids.values()}:
        raise WitnessError("witness must use a separate signing key")
    registration_cutoff(policy, context)
    return policy


def verify_policy(
    *,
    policy: WitnessPolicy,
    context: Any,
    expected_policy_digest: str,
    witness_public_key: Any,
    coordinator_public_key: Any,
    client_public_keys: Mapping[str, Any],
    trust_store: bytes,
) -> None:
    _verify_signed(policy, witness_public_key)
    if policy.core_digest != expected_policy_digest:
        raise WitnessError("policy differs from external pin")
    core = policy.core
    if (
        not _context_valid(context, coordinator_public_key)
        or core.context_digest != context.core_digest
        or core.coordinator_key_id != public_key_id(coordinator_public_key)
        or core.witness_key_id != public_key_id(witness_public_key)
        or core.client_key_ids != {k: public_key_id(v) for k, v in client_public_keys.items()}
        or set(client_public_keys) != {c.client_id for c in context.core.clients}
        or set(core.client_signing_trust_levels) != set(client_public_keys)
        or core.tsa_trust_store_sha256 != sha256_bytes(trust_store)
        or core.witness_key_id in {core.coordinator_key_id, *core.client_key_ids.values()}
    ):
        raise WitnessError("policy/context/authority binding mismatch")
    registration_cutoff(policy, context)


def registration_cutoff(policy: WitnessPolicy, context: Any) -> datetime:
    """Resolve authenticated cutoff semantics; v1 always retains context expiry."""
    expires = _time(context.core.expires_at)
    if isinstance(policy.core, WitnessPhasePolicyCore):
        deadline = _time(policy.core.registration_deadline)
        if not _time(context.core.issued_at) < deadline < expires:
            raise WitnessError("registration deadline must be strictly inside context validity")
        return deadline
    return expires


def _eligibility(interval: TimeInterval, context: Any, policy: WitnessPolicy) -> str:
    issued, deadline = _time(context.core.issued_at), registration_cutoff(policy, context)
    if interval.upper < issued:
        return "before_open"
    if interval.lower >= deadline:
        return "late"
    if issued <= interval.lower and interval.upper < deadline:
        return "eligible"
    return "ambiguous"


def verify_registration(
    entry: WitnessRegistration,
    *,
    policy: WitnessPolicy,
    context: Any,
    witness_public_key: Any,
    client_public_keys: Mapping[str, Any],
    trust_store: bytes,
) -> TimeInterval:
    entry = WitnessRegistration.model_validate_json(entry.model_dump_json())
    _verify_signed(entry, witness_public_key)
    subject, receipt = entry.core.subject, entry.receipt
    key = client_public_keys.get(receipt.core.client_id)
    if (
        key is None
        or not verify_submission_receipt(receipt, context=context, client_public_key=key)
        or receipt.core.signing_trust_level
        != policy.core.client_signing_trust_levels.get(receipt.core.client_id)
        or subject.policy_digest != policy.core_digest
        or subject.receipt_core_digest != receipt.core_digest
        or subject.receipt_sha256 != sha256_bytes(_bytes(receipt))
        or subject.submission_id != receipt.core.submission_id
        or entry.core.timestamp_digest != digest_object(entry.timestamp.model_dump(mode="json"))
    ):
        raise WitnessError("invalid registration receipt/context/timestamp binding")
    interval = verify_timestamp(
        _bytes(subject), entry.timestamp, policy=policy, trust_store=trust_store
    )
    if entry.core.eligibility != _eligibility(interval, context, policy):
        raise WitnessError("incorrect deadline eligibility")
    return interval


def _verify_chain(
    entries: Sequence[WitnessRegistration],
    *,
    policy: WitnessPolicy,
    context: Any,
    witness_public_key: Any,
    client_public_keys: Mapping[str, Any],
    trust_store: bytes,
) -> tuple[list[SubmissionReceipt], str, datetime | None]:
    previous = policy.core_digest
    seen: set[str] = set()
    eligible = []
    last_lower = None
    for sequence, entry in enumerate(entries, 1):
        subject = entry.core.subject
        if (
            subject.sequence != sequence
            or subject.previous_digest != previous
            or subject.receipt_core_digest in seen
        ):
            raise WitnessError("noncontiguous/reordered/duplicate witness log")
        interval = verify_registration(
            entry,
            policy=policy,
            context=context,
            witness_public_key=witness_public_key,
            client_public_keys=client_public_keys,
            trust_store=trust_store,
        )
        if last_lower is not None and interval.lower < last_lower:
            raise WitnessError("TSA time moved backwards")
        last_lower = interval.lower
        previous = entry.core_digest
        seen.add(subject.receipt_core_digest)
        if entry.core.eligibility == "eligible":
            eligible.append(entry.receipt)
    return eligible, previous, last_lower


def verify_witness_snapshot(
    *,
    snapshot: WitnessSnapshot,
    expected_policy_digest: str,
    expected_closure_digest: str,
    witness_public_key: Any,
    coordinator_public_key: Any,
    client_public_keys: Mapping[str, Any],
    trust_store: bytes,
    retained_acknowledgements: Sequence[WitnessRegistration] = (),
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "status": "invalid",
        "evidence_profile": "independent_witness_rfc3161_v1",
        "registration_set_verified": False,
        "deadline_verified": False,
        "coverage_verified": False,
        "delivery_verified": False,
        "admission_decisions_verified": False,
        "errors": [],
        "limitations": [
            "Witness honesty, independent administration and TSA time accuracy are assumptions.",
            "External policy and final closure pins must be obtained outside the coordinator.",
            "A single witness does not prevent split views without exchanged retained heads.",
            "Registration is not delivery to the coordinator or final training admission.",
            "Eligibility uses a conservative full accuracy interval, not client timestamps.",
        ],
    }
    try:
        snapshot = WitnessSnapshot.model_validate_json(snapshot.model_dump_json())
        if isinstance(snapshot.policy.core, WitnessPhasePolicyCore):
            report["evidence_profile"] = "independent_witness_rfc3161_v2"
        verify_policy(
            policy=snapshot.policy,
            context=snapshot.context,
            expected_policy_digest=expected_policy_digest,
            witness_public_key=witness_public_key,
            coordinator_public_key=coordinator_public_key,
            client_public_keys=client_public_keys,
            trust_store=trust_store,
        )
        eligible, head, last_lower = _verify_chain(
            snapshot.registrations,
            policy=snapshot.policy,
            context=snapshot.context,
            witness_public_key=witness_public_key,
            client_public_keys=client_public_keys,
            trust_store=trust_store,
        )
        closure = snapshot.closure
        _verify_signed(closure, witness_public_key)
        expected_subject = ClosureSubject(
            policy_digest=snapshot.policy.core_digest,
            entry_count=len(snapshot.registrations),
            head_digest=head,
            eligible_receipt_digests=sorted(r.core_digest for r in eligible),
        )
        if (
            not expected_closure_digest
            or closure.core_digest != expected_closure_digest
            or closure.core.subject != expected_subject
            or closure.core.timestamp_digest
            != digest_object(closure.timestamp.model_dump(mode="json"))
        ):
            raise WitnessError("closure differs from complete log or external head pin")
        interval = verify_timestamp(
            _bytes(closure.core.subject),
            closure.timestamp,
            policy=snapshot.policy,
            trust_store=trust_store,
        )
        if interval.lower < registration_cutoff(snapshot.policy, snapshot.context) or (
            last_lower is not None and interval.lower < last_lower
        ):
            raise WitnessError("closure is not proven after the registration deadline")
        by_sequence = {e.core.subject.sequence: e for e in snapshot.registrations}
        for ack in retained_acknowledgements:
            verify_registration(
                ack,
                policy=snapshot.policy,
                context=snapshot.context,
                witness_public_key=witness_public_key,
                client_public_keys=client_public_keys,
                trust_store=trust_store,
            )
            stored = by_sequence.get(ack.core.subject.sequence)
            if stored is None or stored.core_digest != ack.core_digest:
                raise WitnessError("retained client acknowledgement exposes omission or fork")
        report.update(
            status="verified_registration_set",
            registration_set_verified=True,
            deadline_verified=True,
            registered_receipt_count=len(snapshot.registrations),
            eligible_receipt_count=len(eligible),
            eligible_submission_ids=sorted({r.core.submission_id for r in eligible}),
            excluded_receipt_counts={
                status: sum(e.core.eligibility == status for e in snapshot.registrations)
                for status in ("late", "ambiguous", "before_open")
            },
            closure_digest=closure.core_digest,
            retained_acknowledgement_count=len(retained_acknowledgements),
        )
    except (ValueError, TypeError, AttributeError, OSError) as exc:
        report["errors"].append(str(exc))
    return report


def verify_witness_inventory(
    *,
    inventory: RoundInputInventory,
    bundle_paths: Mapping[str, Path],
    **verification: Any,
) -> dict[str, Any]:
    report = verify_witness_snapshot(**verification)
    if not report["registration_set_verified"]:
        return report
    snapshot = verification["snapshot"]
    eligible = [r.receipt for r in snapshot.registrations if r.core.eligibility == "eligible"]
    intake = verify_submission_coverage(
        inventory=inventory,
        context=snapshot.context,
        evidence_receipts=eligible,
        bundle_paths=bundle_paths,
        client_public_keys=verification["client_public_keys"],
        coordinator_public_key=verification["coordinator_public_key"],
        evidence_source="externally-pinned-independent-witness-closure",
    )
    report["intake_verification"] = intake
    report["coverage_verified"] = bool(
        intake["coverage_verified"] and intake["inventory_fully_recomputed"]
    )
    report["errors"].extend(intake["errors"])
    if intake["additional_inventory_submission_ids"]:
        report["errors"].append("inventory contains submissions outside the eligible witness set")
    report["status"] = (
        "verified_eligible_intake"
        if report["coverage_verified"]
        else "invalid_inventory"
        if report["errors"]
        else "insufficient_evidence"
    )
    return report


class WitnessStore:
    """One context per SQLite database; commits are serialized and crash-atomic.

    SQLite triggers prevent accidental update/delete through this API's schema.
    They do not constrain a malicious administrator. Clients retain signed
    acknowledgements; verifiers retain final closure commitments externally.
    """

    def __init__(
        self,
        *,
        database: Path,
        policy: WitnessPolicy,
        context: Any,
        expected_policy_digest: str,
        signer: DigestSigner,
        witness_public_key: Any,
        coordinator_public_key: Any,
        client_public_keys: Mapping[str, Any],
        trust_store: bytes,
        timestamp_provider: TimestampProvider,
    ) -> None:
        verify_policy(
            policy=policy,
            context=context,
            expected_policy_digest=expected_policy_digest,
            witness_public_key=witness_public_key,
            coordinator_public_key=coordinator_public_key,
            client_public_keys=client_public_keys,
            trust_store=trust_store,
        )
        if signer.key_id != policy.core.witness_key_id:
            raise WitnessError("wrong witness signer")
        self.database, self.policy, self.context, self.signer = database, policy, context, signer
        self.witness_public_key, self.coordinator_public_key = (
            witness_public_key,
            coordinator_public_key,
        )
        self.client_public_keys, self.trust_store = client_public_keys, trust_store
        self.timestamp_provider = timestamp_provider
        database.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create keeps the private journal private from its first byte.
        if not database.exists():
            import os

            try:
                fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        with self._connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS registrations (
                    sequence INTEGER PRIMARY KEY, receipt_digest TEXT UNIQUE NOT NULL, artifact TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS closure (id INTEGER PRIMARY KEY CHECK(id=1), artifact TEXT NOT NULL);
            """)
            for table in ("policy", "registrations", "closure"):
                for action in ("UPDATE", "DELETE"):
                    connection.execute(
                        f"CREATE TRIGGER IF NOT EXISTS {table}_{action.lower()} "
                        f"BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT, 'append-only'); END"
                    )
            connection.execute("INSERT OR IGNORE INTO policy VALUES (1, ?)", (policy.core_digest,))
            if connection.execute("SELECT digest FROM policy").fetchone()[0] != policy.core_digest:
                raise WitnessError("existing database belongs to another policy")

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database, timeout=30)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                yield connection
        finally:
            connection.close()

    def _entries(self, connection: sqlite3.Connection) -> list[WitnessRegistration]:
        return [
            WitnessRegistration.model_validate_json(row[0])
            for row in connection.execute("SELECT artifact FROM registrations ORDER BY sequence")
        ]

    def _chain(self, entries: Sequence[WitnessRegistration]):
        return _verify_chain(
            entries,
            policy=self.policy,
            context=self.context,
            witness_public_key=self.witness_public_key,
            client_public_keys=self.client_public_keys,
            trust_store=self.trust_store,
        )

    def register(self, receipt: SubmissionReceipt) -> WitnessRegistration:
        receipt = SubmissionReceipt.model_validate_json(receipt.model_dump_json())
        key = self.client_public_keys.get(receipt.core.client_id)
        if (
            key is None
            or not verify_submission_receipt(receipt, context=self.context, client_public_key=key)
            or receipt.core.signing_trust_level
            != self.policy.core.client_signing_trust_levels.get(receipt.core.client_id)
        ):
            raise WitnessError("invalid authenticated client receipt")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            entries = self._entries(connection)
            _, previous, last_lower = self._chain(entries)
            for entry in entries:
                if entry.receipt.core_digest == receipt.core_digest:
                    return entry  # Immutable idempotent acknowledgement, including after closure.
            if connection.execute("SELECT 1 FROM closure").fetchone():
                raise WitnessError("witness round is closed")
            subject = RegistrationSubject(
                policy_digest=self.policy.core_digest,
                sequence=len(entries) + 1,
                previous_digest=previous,
                receipt_core_digest=receipt.core_digest,
                receipt_sha256=sha256_bytes(_bytes(receipt)),
                submission_id=receipt.core.submission_id,
            )
            timestamp = self.timestamp_provider.stamp(_bytes(subject))
            interval = verify_timestamp(
                _bytes(subject), timestamp, policy=self.policy, trust_store=self.trust_store
            )
            if last_lower is not None and interval.lower < last_lower:
                raise WitnessError("TSA time moved backwards")
            core = RegistrationCore(
                subject=subject,
                timestamp_digest=digest_object(timestamp.model_dump(mode="json")),
                eligibility=_eligibility(interval, self.context, self.policy),
            )
            entry = WitnessRegistration(
                **_signed(core, self.signer), receipt=receipt, timestamp=timestamp
            )
            connection.execute(
                "INSERT INTO registrations VALUES (?, ?, ?)",
                (subject.sequence, receipt.core_digest, entry.model_dump_json()),
            )
            return entry  # The context manager commits before returning the acknowledgement.

    def close(self) -> WitnessSnapshot:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            entries = self._entries(connection)
            eligible, head, last_lower = self._chain(entries)
            row = connection.execute("SELECT artifact FROM closure").fetchone()
            if row:
                closure = WitnessClosure.model_validate_json(row[0])
            else:
                subject = ClosureSubject(
                    policy_digest=self.policy.core_digest,
                    entry_count=len(entries),
                    head_digest=head,
                    eligible_receipt_digests=sorted(r.core_digest for r in eligible),
                )
                timestamp = self.timestamp_provider.stamp(_bytes(subject))
                interval = verify_timestamp(
                    _bytes(subject), timestamp, policy=self.policy, trust_store=self.trust_store
                )
                if interval.lower < registration_cutoff(self.policy, self.context) or (
                    last_lower is not None and interval.lower < last_lower
                ):
                    raise WitnessError("closure is not proven after the registration deadline")
                core = ClosureCore(
                    subject=subject,
                    timestamp_digest=digest_object(timestamp.model_dump(mode="json")),
                )
                closure = WitnessClosure(**_signed(core, self.signer), timestamp=timestamp)
                connection.execute(
                    "INSERT INTO closure VALUES (1, ?)", (closure.model_dump_json(),)
                )
            snapshot = WitnessSnapshot(
                context=self.context, policy=self.policy, registrations=entries, closure=closure
            )
            report = verify_witness_snapshot(
                snapshot=snapshot,
                expected_policy_digest=self.policy.core_digest,
                expected_closure_digest=closure.core_digest,
                witness_public_key=self.witness_public_key,
                coordinator_public_key=self.coordinator_public_key,
                client_public_keys=self.client_public_keys,
                trust_store=self.trust_store,
            )
            if not report["registration_set_verified"]:
                raise WitnessError(str(report["errors"]))
            return snapshot

    def snapshot(self) -> WitnessSnapshot:
        # A read transaction prevents concurrent closure from exposing a torn view.
        with self._connection() as connection:
            connection.execute("BEGIN")
            row = connection.execute("SELECT artifact FROM closure").fetchone()
            if row is None:
                raise WitnessError("no final closure exists")
            return WitnessSnapshot(
                context=self.context,
                policy=self.policy,
                registrations=self._entries(connection),
                closure=WitnessClosure.model_validate_json(row[0]),
            )
