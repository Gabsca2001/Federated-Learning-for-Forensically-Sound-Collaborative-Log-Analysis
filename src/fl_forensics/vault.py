"""Content-addressed evidence storage and chained custody events."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import GENESIS_CHAIN_HASH, digest_object, sha256_bytes
from .models import (
    AdmissionDecision,
    AttestationResult,
    BatchManifest,
    CustodyEvent,
    CustodyEventCore,
    DigestRef,
    SignedReceipt,
)
from .storage import atomic_json, load_json, utc_now, write_json_once, write_once


@dataclass(frozen=True)
class ExistingSubmission:
    chain_hash: str
    decision: AdmissionDecision
    receipt: SignedReceipt | None


class EvidenceVault:
    """Prototype vault whose indexes are reconstructible from protected records."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.objects = root / "objects" / "sha256"
        self.records = root / "records"
        self.custody = root / "custody" / "events"
        self.state_path = root / "operational" / "index.json"
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            atomic_json(
                self.state_path,
                {
                    "schema_version": "1.0",
                    "positions": {},
                    "clients": {},
                    "sessions": {},
                    "custody_head": GENESIS_CHAIN_HASH,
                    "custody_sequence": 0,
                },
            )

    def _state(self) -> dict[str, Any]:
        return load_json(self.state_path)

    @staticmethod
    def position_key(client_id: str, session_id: str, sequence_number: int) -> str:
        return f"{client_id}|{session_id}|{sequence_number}"

    def put_object(self, data: bytes) -> str:
        digest = sha256_bytes(data)
        path = self.objects / digest[:2] / digest[2:]
        write_once(path, data)
        return digest

    def object_bytes(self, digest: str) -> bytes:
        return (self.objects / digest[:2] / digest[2:]).read_bytes()

    def existing_submission(self, manifest: BatchManifest) -> ExistingSubmission | None:
        state = self._state()
        key = self.position_key(
            manifest.core.client_id,
            manifest.core.acquisition_session_id,
            manifest.core.sequence_number,
        )
        entry = state["positions"].get(key)
        if entry is None:
            return None
        record = load_json(self.root / entry["decision_path"])
        decision = AdmissionDecision.model_validate(record["decision"])
        receipt_path = entry.get("receipt_path")
        receipt = (
            SignedReceipt.model_validate(load_json(self.root / receipt_path))
            if receipt_path
            else None
        )
        return ExistingSubmission(entry["chain_hash"], decision, receipt)

    def expected_continuity(self, manifest: BatchManifest) -> tuple[bool, str]:
        state = self._state()
        client_id = manifest.core.client_id
        session_id = manifest.core.acquisition_session_id
        sequence = manifest.core.sequence_number
        session = state["sessions"].get(f"{client_id}|{session_id}")
        client = state["clients"].get(client_id)

        if session is None:
            if sequence != 0:
                return False, "new session must start at sequence 0"
            expected_previous = client["chain_hash"] if client else GENESIS_CHAIN_HASH
        else:
            if sequence != session["sequence_number"] + 1:
                return False, f"expected sequence {session['sequence_number'] + 1}"
            expected_previous = session["chain_hash"]

        if manifest.core.previous_chain_hash != expected_previous:
            return False, f"expected predecessor {expected_previous}"
        return True, "sequence and predecessor are continuous"

    def persist_submission(
        self,
        *,
        raw: bytes,
        manifest: BatchManifest,
        attestation: AttestationResult,
        decision: AdmissionDecision,
    ) -> dict[str, str]:
        raw_digest = self.put_object(raw)
        manifest_bytes = (
            __import__("json")
            .dumps(
                manifest.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            .encode("utf-8")
            + b"\n"
        )
        attestation_bytes = (
            __import__("json")
            .dumps(
                attestation.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            .encode("utf-8")
            + b"\n"
        )
        manifest_object_digest = self.put_object(manifest_bytes)
        attestation_object_digest = self.put_object(attestation_bytes)
        decision_dict = decision.model_dump(mode="json")
        decision_digest = digest_object(decision_dict)

        category = "accepted" if decision.status == "accepted" else "quarantine"
        record_path = (
            self.records
            / category
            / f"{manifest.core.batch_id}-{manifest.chain_hash[:16]}.json"
        )
        write_json_once(
            record_path,
            {
                "schema_version": "1.0",
                "batch_id": manifest.core.batch_id,
                "chain_hash": manifest.chain_hash,
                "raw_object": raw_digest,
                "manifest_object": manifest_object_digest,
                "attestation_object": attestation_object_digest,
                "decision": decision_dict,
                "decision_digest": decision_digest,
            },
        )

        state = self._state()
        key = self.position_key(
            manifest.core.client_id,
            manifest.core.acquisition_session_id,
            manifest.core.sequence_number,
        )
        relative_record_path = str(record_path.relative_to(self.root))
        if key not in state["positions"]:
            state["positions"][key] = {
                "chain_hash": manifest.chain_hash,
                "decision_id": decision.decision_id,
                "decision_path": relative_record_path,
                "receipt_path": None,
            }
        if decision.status == "accepted":
            state["sessions"][
                f"{manifest.core.client_id}|{manifest.core.acquisition_session_id}"
            ] = {
                "sequence_number": manifest.core.sequence_number,
                "chain_hash": manifest.chain_hash,
            }
            state["clients"][manifest.core.client_id] = {
                "session_id": manifest.core.acquisition_session_id,
                "sequence_number": manifest.core.sequence_number,
                "chain_hash": manifest.chain_hash,
            }
        atomic_json(self.state_path, state)
        self.append_custody_event(
            action="preserve_batch",
            actor="evidence-vault",
            object_refs=[
                DigestRef(artifact_id=manifest.core.batch_id, digest=raw_digest),
                DigestRef(artifact_id=decision.decision_id, digest=decision_digest),
            ],
            outcome=decision.status,
            details={
                "record_path": relative_record_path,
                "manifest_digest": manifest_object_digest,
            },
        )
        return {
            "raw_digest": raw_digest,
            "manifest_object_digest": manifest_object_digest,
            "attestation_object_digest": attestation_object_digest,
            "decision_digest": decision_digest,
            "record_path": relative_record_path,
        }

    def persist_receipt(self, manifest: BatchManifest, receipt: SignedReceipt) -> Path:
        path = self.records / "receipts" / f"{receipt.core.receipt_id}.json"
        write_json_once(path, receipt.model_dump(mode="json"))
        state = self._state()
        key = self.position_key(
            manifest.core.client_id,
            manifest.core.acquisition_session_id,
            manifest.core.sequence_number,
        )
        position = state["positions"].get(key)
        if position and position.get("decision_id") == receipt.core.decision_id:
            position["receipt_path"] = str(path.relative_to(self.root))
        atomic_json(self.state_path, state)
        self.append_custody_event(
            action="issue_receipt",
            actor=receipt.core.repository_id,
            object_refs=[DigestRef(artifact_id=receipt.core.receipt_id, digest=receipt.core_digest)],
            outcome=receipt.core.admission_status,
            details={"batch_id": manifest.core.batch_id},
        )
        return path

    def append_custody_event(
        self,
        *,
        action: str,
        actor: str,
        object_refs: list[DigestRef],
        outcome: str,
        details: dict[str, Any],
    ) -> CustodyEvent:
        state = self._state()
        sequence = int(state["custody_sequence"])
        core = CustodyEventCore(
            sequence_number=sequence,
            previous_event_hash=state["custody_head"],
            action=action,
            actor=actor,
            object_refs=object_refs,
            outcome=outcome,
            occurred_at=utc_now(),
            details=details,
        )
        event_hash = digest_object(core.model_dump(mode="json"))
        event = CustodyEvent(core=core, event_hash=event_hash)
        path = self.custody / f"{sequence:012d}-{event_hash}.json"
        write_json_once(path, event.model_dump(mode="json"))
        state["custody_sequence"] = sequence + 1
        state["custody_head"] = event_hash
        atomic_json(self.state_path, state)
        return event

    def verify_integrity(self) -> list[str]:
        errors: list[str] = []
        for path in sorted(self.objects.glob("*/*")):
            expected = path.parent.name + path.name
            actual = sha256_bytes(path.read_bytes())
            if actual != expected:
                errors.append(f"object digest mismatch: {path}")

        expected_previous = GENESIS_CHAIN_HASH
        expected_sequence = 0
        for path in sorted(self.custody.glob("*.json")):
            event = CustodyEvent.model_validate(load_json(path))
            if event.core.sequence_number != expected_sequence:
                errors.append(f"custody sequence discontinuity: {path}")
            if event.core.previous_event_hash != expected_previous:
                errors.append(f"custody predecessor mismatch: {path}")
            actual = digest_object(event.core.model_dump(mode="json"))
            if actual != event.event_hash:
                errors.append(f"custody event digest mismatch: {path}")
            expected_previous = event.event_hash
            expected_sequence += 1
        return errors
