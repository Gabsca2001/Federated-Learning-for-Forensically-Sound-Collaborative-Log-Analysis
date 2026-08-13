from __future__ import annotations

import stat
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fl_forensics.acquisition import build_batch
from fl_forensics.admission import AdmissionController
from fl_forensics.canonical import digest_object
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.mtls import exercise_mtls_handshake
from fl_forensics.models import IdentityRecord
from fl_forensics.storage import atomic_json, load_json, write_json_once
from fl_forensics.trust import (
    create_enrollment_request,
    create_software_quote_evidence,
    enroll_nodes,
    initialize_trust_workspace,
    issue_challenges,
    revoke_enrollment,
    verify_quote_evidence,
    verify_result_signature,
    verify_software_quote,
)
from fl_forensics.trust_models import MeasurementLog, QuoteEvidence
from fl_forensics.vault import EvidenceVault


ROOT = Path(__file__).resolve().parents[1]
TRUST_CONFIG = ROOT / "configs" / "trust.yaml"
CLIENTS_CONFIG = ROOT / "configs" / "clients.yaml"


class TrustProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        temporary_root = Path(self.temporary.name)
        self.workspace = temporary_root / "trust"
        self.node_root = temporary_root / "nodes"
        self.node = self.node_root / "client01"
        initialize_trust_workspace(
            workspace=self.workspace,
            project_root=ROOT,
            trust_config_path=TRUST_CONFIG,
            clients_config_path=CLIENTS_CONFIG,
        )
        config = load_json(self.workspace / "baseline" / "measurement_log.json")
        self.measurement_log = MeasurementLog.model_validate(config)
        write_json_once(
            self.node / "measurement_log.json", self.measurement_log.model_dump(mode="json")
        )
        self.ak = SoftwareECDSASigner.generate()
        self.esk = SoftwareECDSASigner.generate()
        create_enrollment_request(
            node_workspace=self.node,
            client_id="client01",
            node_id="node01",
            tpm_instance_id="tpm01",
            trust_level="swtpm",
            ek_public_bytes=b"logical-swtpm-ek-01",
            ak_public_pem=self.ak.public_pem(),
            esk_public_pem=self.esk.public_pem(),
            esk_signer=self.esk,
            measurement_log=self.measurement_log,
        )
        outcome = enroll_nodes(
            workspace=self.workspace,
            node_root=self.node_root,
            trust_config_path=TRUST_CONFIG,
            clients_config_path=CLIENTS_CONFIG,
            require_all=False,
        )
        self.assertEqual(outcome["status"], "enrolled")
        issue_challenges(
            workspace=self.workspace,
            node_root=self.node_root,
            trust_config_path=TRUST_CONFIG,
            client_ids=["client01"],
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _quote(self, signer: SoftwareECDSASigner | None = None) -> QuoteEvidence:
        return create_software_quote_evidence(
            node_workspace=self.node, ak_signer=signer or self.ak
        )

    def _verify(self):
        return verify_quote_evidence(
            workspace=self.workspace,
            node_workspace=self.node,
            quote_verifier=verify_software_quote,
        )

    def _tamper_measurement_log(self, log: MeasurementLog) -> None:
        """Simulate an attacker bypassing the write-once file permission.

        ``write_json_once`` creates protected artifacts as read-only.  POSIX can
        replace such a file when its parent directory is writable, whereas
        Windows rejects ``os.replace`` until the read-only attribute is cleared.
        The permission change is therefore an explicit part of this adversarial
        test, not a relaxation of the production persistence primitive.
        """

        path = self.node / "measurement_log.json"
        path.chmod(path.stat().st_mode | stat.S_IWUSR)
        atomic_json(path, log.model_dump(mode="json"))

    def test_nominal_quote_is_passed_signed_and_idempotent(self) -> None:
        self._quote()
        result, replay = self._verify()
        self.assertEqual(result.core.status, "passed")
        self.assertFalse(replay)
        self.assertTrue(verify_result_signature(self.workspace, result))
        same, replay = self._verify()
        self.assertTrue(replay)
        self.assertEqual(same.result_id, result.result_id)

    def test_nonce_replay_with_changed_wrapper_is_stale(self) -> None:
        evidence = self._quote()
        first, _ = self._verify()
        self.assertEqual(first.core.status, "passed")
        changed_core = evidence.core.model_copy(
            update={"generated_at": "2030-01-01T00:00:00Z", "evidence_id": "quote-replay"}
        )
        changed = QuoteEvidence(
            core=changed_core,
            core_digest=digest_object(changed_core.model_dump(mode="json")),
        )
        atomic_json(self.node / "quote_evidence.json", changed.model_dump(mode="json"))
        replay_result, idempotent = self._verify()
        self.assertFalse(idempotent)
        self.assertEqual(replay_result.core.status, "stale")
        self.assertTrue(
            any("already been consumed" in reason for reason in replay_result.core.reasons)
        )

    def test_altered_measurement_is_rejected(self) -> None:
        first = self.measurement_log.events[0]
        altered = first.model_copy(update={"measurement_sha256": "f" * 64})
        log = MeasurementLog(events=[altered, *self.measurement_log.events[1:]])
        self._tamper_measurement_log(log)
        self._quote()
        result, _ = self._verify()
        self.assertEqual(result.core.status, "failed_measurement")
        self.assertTrue(any("baseline" in reason for reason in result.core.reasons))

    def test_failed_measurement_attestation_quarantines_the_batch(self) -> None:
        first = self.measurement_log.events[0]
        altered = first.model_copy(update={"measurement_sha256": "e" * 64})
        log = MeasurementLog(events=[altered, *self.measurement_log.events[1:]])
        self._tamper_measurement_log(log)
        self._quote()
        result, _ = self._verify()
        self.assertEqual(result.core.status, "failed_measurement")

        now = datetime.now(UTC)
        identity = IdentityRecord(
            client_id="client01",
            node_id="node01",
            evidence_key_id=self.esk.key_id,
            evidence_public_key_pem=self.esk.public_pem().decode(),
            valid_from=(now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            valid_until=(now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        )
        batch = build_batch(
            input_path=ROOT / "tests" / "fixtures" / "zeek_conn.jsonl",
            queue_root=Path(self.temporary.name) / "queue",
            node_id="node01",
            client_id="client01",
            session_id="m4-negative",
            sequence_number=0,
            attestation=result,
            signer=self.esk,
            configuration_digest="0" * 64,
            trust_level="swtpm",
        )
        controller = AdmissionController(
            identities={"client01": identity},
            verifier_public_key=load_public_key(
                (self.workspace / "authority" / "attestation-verifier.public.pem").read_bytes()
            ),
            repository_signer=SoftwareECDSASigner.generate(),
            vault=EvidenceVault(Path(self.temporary.name) / "vault"),
            required_attestation_trust_levels={"swtpm", "tpm2"},
        )
        outcome = controller.process(
            raw=batch.raw,
            manifest=batch.manifest,
            attestation=result,
            now=now,
        )
        self.assertEqual(outcome.decision.status, "quarantined")
        failed = {item.name for item in outcome.decision.checks if not item.passed}
        self.assertIn("attestation_status", failed)

    def test_revoked_enrollment_is_rejected(self) -> None:
        self._quote()
        revoke_enrollment(
            workspace=self.workspace,
            client_id="client01",
            reason="negative acceptance test",
        )
        result, _ = self._verify()
        self.assertEqual(result.core.status, "failed_identity")
        self.assertTrue(any("revoked" in reason for reason in result.core.reasons))

    def test_wrong_ak_pair_is_rejected(self) -> None:
        self._quote(SoftwareECDSASigner.generate())
        result, _ = self._verify()
        self.assertEqual(result.core.status, "failed_identity")
        self.assertTrue(any("AK identity binding" in reason for reason in result.core.reasons))

    def test_mtls_handshake_binds_the_claimed_client(self) -> None:
        record = load_json(self.node / "enrollment_record.json")
        fingerprint = record["core"]["tls_certificate_sha256"]
        accepted = exercise_mtls_handshake(
            workspace=self.workspace,
            node_workspace=self.node,
            claimed_client_id="client01",
            expected_fingerprint=fingerprint,
        )
        self.assertTrue(accepted["binding_valid"])
        self.assertEqual(accepted["tls_version"], "TLSv1.3")
        wrong_pair = exercise_mtls_handshake(
            workspace=self.workspace,
            node_workspace=self.node,
            claimed_client_id="client02",
            expected_fingerprint=fingerprint,
        )
        self.assertFalse(wrong_pair["binding_valid"])

    def test_enrollment_rejects_ak_esk_key_reuse(self) -> None:
        second_node = self.node_root / "reuse"
        write_json_once(
            second_node / "measurement_log.json",
            self.measurement_log.model_dump(mode="json"),
        )
        with self.assertRaisesRegex(ValueError, "different keys"):
            create_enrollment_request(
                node_workspace=second_node,
                client_id="client01",
                node_id="node01",
                tpm_instance_id="tpm01",
                trust_level="swtpm",
                ek_public_bytes=b"ek",
                ak_public_pem=self.ak.public_pem(),
                esk_public_pem=self.ak.public_pem(),
                esk_signer=self.ak,
                measurement_log=self.measurement_log,
            )


if __name__ == "__main__":
    unittest.main()
