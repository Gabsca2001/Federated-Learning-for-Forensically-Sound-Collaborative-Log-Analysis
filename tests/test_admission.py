from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fl_forensics.acquisition import build_batch
from fl_forensics.admission import AdmissionController
from fl_forensics.attestation import create_attestation_result, create_development_attestation
from fl_forensics.canonical import sha256_bytes
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.models import AttestationResultCore, IdentityRecord
from fl_forensics.vault import EvidenceVault


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "zeek_conn.jsonl"


class AdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evidence_signer = SoftwareECDSASigner.generate()
        self.verifier_signer = SoftwareECDSASigner.generate()
        self.repository_signer = SoftwareECDSASigner.generate()
        now = datetime.now(UTC)
        self.identity = IdentityRecord(
            client_id="client01",
            node_id="node01",
            evidence_key_id=self.evidence_signer.key_id,
            evidence_public_key_pem=self.evidence_signer.public_pem().decode(),
            valid_from=(now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            valid_until=(now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        )

    def _attestation(self):
        return create_development_attestation(
            node_id="node01",
            client_id="client01",
            signer=self.verifier_signer,
            quote_digest=sha256_bytes(b"quote"),
            measurement_log_digest=sha256_bytes(b"measurements"),
            nonce="nonce-1",
        )

    def _controller(self, root: Path, identity: IdentityRecord | None = None):
        return AdmissionController(
            identities={"client01": identity or self.identity},
            verifier_public_key=load_public_key(self.verifier_signer.public_pem()),
            repository_signer=self.repository_signer,
            vault=EvidenceVault(root / "vault"),
        )

    def _batch(self, root: Path, attestation, input_path: Path = FIXTURE):
        return build_batch(
            input_path=input_path,
            queue_root=root / "queue",
            node_id="node01",
            client_id="client01",
            session_id="session-a",
            sequence_number=0,
            attestation=attestation,
            signer=self.evidence_signer,
            configuration_digest=sha256_bytes(b"config"),
        )

    def test_content_tampering_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attestation = self._attestation()
            batch = self._batch(root, attestation)
            outcome = self._controller(root).process(
                raw=batch.raw + b"{}\n",
                manifest=batch.manifest,
                attestation=attestation,
            )
            self.assertEqual(outcome.decision.status, "quarantined")
            failed = {item.name for item in outcome.decision.checks if not item.passed}
            self.assertIn("content_digest", failed)

    def test_expired_attestation_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            now = datetime.now(UTC)
            core = AttestationResultCore(
                node_id="node01",
                client_id="client01",
                status="passed",
                nonce="expired-nonce",
                pcr_selection=[0, 2, 4, 7, 10],
                quote_digest=sha256_bytes(b"quote"),
                measurement_log_digest=sha256_bytes(b"measurements"),
                policy_id="test",
                policy_version="1",
                baseline_id="test",
                baseline_version="1",
                evaluated_at=(now - timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
                expires_at=(now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            )
            attestation = create_attestation_result(core, self.verifier_signer)
            batch = self._batch(root, attestation)
            outcome = self._controller(root).process(
                raw=batch.raw,
                manifest=batch.manifest,
                attestation=attestation,
                now=now,
            )
            self.assertEqual(outcome.decision.status, "quarantined")
            failed = {item.name for item in outcome.decision.checks if not item.passed}
            self.assertIn("attestation_freshness", failed)

    def test_wrong_node_binding_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrong_identity = self.identity.model_copy(update={"node_id": "node99"})
            attestation = self._attestation()
            batch = self._batch(root, attestation)
            outcome = self._controller(root, wrong_identity).process(
                raw=batch.raw,
                manifest=batch.manifest,
                attestation=attestation,
            )
            self.assertEqual(outcome.decision.status, "quarantined")
            failed = {item.name for item in outcome.decision.checks if not item.passed}
            self.assertIn("client_node_binding", failed)

    def test_same_position_with_different_commitment_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            attestation = self._attestation()
            first = self._batch(root / "first", attestation)
            controller = self._controller(root)
            first_outcome = controller.process(
                raw=first.raw,
                manifest=first.manifest,
                attestation=attestation,
            )
            self.assertEqual(first_outcome.decision.status, "accepted")

            changed_input = root / "changed.jsonl"
            changed_input.write_bytes(FIXTURE.read_bytes() + FIXTURE.read_bytes().splitlines()[0] + b"\n")
            second = self._batch(root / "second", attestation, changed_input)
            second_outcome = controller.process(
                raw=second.raw,
                manifest=second.manifest,
                attestation=attestation,
            )
            self.assertEqual(second_outcome.decision.status, "quarantined")
            failed = {item.name for item in second_outcome.decision.checks if not item.passed}
            self.assertIn("session_sequence_continuity", failed)


if __name__ == "__main__":
    unittest.main()

