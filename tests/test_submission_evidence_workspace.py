from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import test_real_attestation_failure as reattestation_tests
import test_secure_round as secure_round_tests

from fl_forensics.canonical import digest_object
from fl_forensics.cli import build_parser, main
from fl_forensics.crypto import load_public_key
from fl_forensics.real_attestation_failure import (
    RealAttestationFailureError,
    refresh_update_bundle_attestation,
)
from fl_forensics.secure_round import create_secure_update
from fl_forensics.storage import atomic_json, load_json, write_once
from fl_forensics.submission_evidence import ensure_submission_receipt
from fl_forensics.submission_evidence_models import RoundInputInventory
from fl_forensics.submission_evidence_workspace import (
    create_submission_inventory_workspace,
    verify_submission_inventory_workspace,
)


class SubmissionEvidenceWorkspaceTests(unittest.TestCase):
    """Adapters against an enrolled secure-round fixture; TPM calls are mocked."""

    def setUp(self) -> None:
        # Import the module, not its TestCase class, to avoid collecting its suite twice.
        self.fixture = secure_round_tests.SecureRoundAdmissionTests(
            "test_nominal_bundle_passes_every_admission_check"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.workspace = self.fixture._aggregation_workspace()
        self.root = Path(self.fixture.temporary.name)
        self.client_receipts = self.root / "independent-client-copies"
        self.inventory_path = self.workspace / "input-inventory.json"
        write_once(
            self.fixture.node / "tpm-objects" / "esk.public.pem",
            self.fixture.esk.public_pem(),
        )
        self.receipt_result = self._create_receipt()

    def _create_receipt(self):
        with (
            patch("fl_forensics.secure_round.TPM2ToolsSigner", return_value=self.fixture.esk),
            patch(
                "fl_forensics.secure_round.train_local",
                side_effect=AssertionError("receipt retry unexpectedly trained a model"),
            ),
        ):
            return create_secure_update(
                public_workspace=self.workspace / "public",
                client_dataset_path=self.root / "not-read-dataset.json",
                client_manifest_path=self.root / "not-read-manifest.json",
                node_workspace=self.fixture.node,
                submission_workspace=self.fixture.submission,
                tcti="test-mock-only",
                client_id="client01",
                now=self.fixture.now,
                client_receipt_root=self.client_receipts,
            )

    def _options(self):
        return {
            "workspace": self.workspace,
            "trust_workspace": self.fixture.trust,
            "client_receipts": self.client_receipts,
            "submissions_root": self.fixture.submissions_root,
            "inventory_path": self.inventory_path,
        }

    def _create_inventory(self):
        return create_submission_inventory_workspace(**self._options(), now=self.fixture.now)

    def _verify_inventory(self):
        return verify_submission_inventory_workspace(**self._options())

    @staticmethod
    def _remove(path: Path) -> None:
        path.chmod(0o600)
        path.unlink()

    def test_secure_update_retry_creates_two_receipt_copies_without_training(self) -> None:
        self.assertTrue(self.receipt_result["idempotent"])
        client_path = Path(self.receipt_result["client_receipt"])
        submission_path = self.fixture.submission / "submission-receipt.json"
        self.assertTrue(client_path.is_file())
        self.assertEqual(client_path.read_bytes(), submission_path.read_bytes())
        original_bytes = client_path.read_bytes()
        repeated = self._create_receipt()
        self.assertEqual(repeated["receipt_id"], self.receipt_result["receipt_id"])
        self.assertEqual(client_path.read_bytes(), original_bytes)

    def test_inventory_adapter_roundtrip_uses_enrollment_keys(self) -> None:
        created = self._create_inventory()
        self.assertEqual(created["status"], "verified_for_evidence_set")
        verified = self._verify_inventory()
        self.assertTrue(verified["coverage_verified"])
        self.assertTrue(verified["inventory_fully_recomputed"])
        self.assertFalse(verified["deadline_verified"])
        self.assertFalse(verified["admission_decisions_verified"])
        first_bytes = self.inventory_path.read_bytes()
        repeated = self._create_inventory()
        self.assertEqual(repeated["inventory_id"], created["inventory_id"])
        self.assertEqual(self.inventory_path.read_bytes(), first_bytes)

    def test_missing_payload_is_recorded_while_client_evidence_survives(self) -> None:
        self._remove(self.fixture.submission / "bundle.json")
        created = self._create_inventory()
        inventory = RoundInputInventory.model_validate(load_json(self.inventory_path))
        self.assertEqual(created["status"], "verified_for_evidence_set")
        self.assertEqual(inventory.core.entries[0].outcome, "rejected_missing_payload")
        self.assertTrue(self._verify_inventory()["coverage_verified"])

    def test_signed_self_consistent_omission_is_detected_using_client_copies(self) -> None:
        self._create_inventory()
        inventory = RoundInputInventory.model_validate(load_json(self.inventory_path))
        core = inventory.core.model_copy(
            update={"entries": [], "missing_client_ids": inventory.core.expected_client_ids}
        )
        digest = digest_object(core.model_dump(mode="json"))
        forged = inventory.model_copy(
            update={
                "core": core,
                "core_digest": digest,
                "inventory_id": inventory.inventory_id.replace(inventory.core_digest, digest),
                "signature": inventory.signature.model_copy(
                    update={"value_b64": self.fixture.coordinator.sign_digest(digest)}
                ),
            }
        )
        atomic_json(self.inventory_path, forged.model_dump(mode="json"))
        self._remove(self.fixture.submission / "bundle.json")
        verified = self._verify_inventory()
        self.assertEqual(verified["status"], "invalid")
        self.assertFalse(verified["coverage_verified"])
        self.assertIn(
            self.receipt_result["submission_id"], verified["missing_submission_ids"]
        )

    def test_tampered_enrollment_authority_signature_is_rejected(self) -> None:
        self._create_inventory()
        index = load_json(self.fixture.trust / "registry" / "index.json")
        record_path = (
            self.fixture.trust / index["enrollments"]["client01"]["record_path"]
        )
        enrollment = load_json(record_path)
        enrollment["signature"]["value_b64"] = "AAAA"
        atomic_json(record_path, enrollment)
        verified = self._verify_inventory()
        self.assertEqual(verified["status"], "invalid")
        self.assertFalse(verified["coverage_verified"])

    def test_client_cli_parser_exposes_receipt_root(self) -> None:
        arguments = build_parser().parse_args(
            [
                "m5-client-update",
                "--public-workspace", str(self.workspace / "public"),
                "--client-dataset", str(self.root / "dataset.json"),
                "--client-manifest", str(self.root / "manifest.json"),
                "--node-workspace", str(self.fixture.node),
                "--submission-workspace", str(self.fixture.submission),
                "--client-id", "client01",
                "--tcti", "test-mock-only",
                "--client-receipt-root", str(self.client_receipts),
            ]
        )
        self.assertEqual(arguments.client_receipt_root, self.client_receipts)

    def test_inventory_verify_cli_reports_conditional_coverage_as_json(self) -> None:
        self._create_inventory()
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(
                [
                    "m5-input-inventory-verify",
                    "--workspace", str(self.workspace),
                    "--trust-workspace", str(self.fixture.trust),
                    "--client-receipts", str(self.client_receipts),
                    "--submissions", str(self.fixture.submissions_root),
                    "--inventory", str(self.inventory_path),
                ]
            )
        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["status"], "verified_for_evidence_set")
        self.assertFalse(report["deadline_verified"])
        self.assertFalse(report["admission_decisions_verified"])


class ReceiptedBundleReattestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = reattestation_tests.RealPostTrainingReattestationTests(
            "test_real_failed_result_is_rebound_and_only_trust_gate_fails"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def test_rebinding_cannot_rewrite_a_bundle_with_a_client_receipt(self) -> None:
        bundle_path = self.fixture.submission / "bundle.json"
        bundle = load_json(bundle_path)
        client_root = Path(self.fixture.temporary.name) / "separate-client-receipts"
        receipt = ensure_submission_receipt(
            bundle_path=bundle_path,
            context=self.fixture.context,
            signer=self.fixture.esk,
            client_public_key=load_public_key(self.fixture.esk.public_pem()),
            trust_level=bundle["signature"]["trust_level"],
            client_receipt_root=client_root,
            submitted_at=self.fixture.now,
        )
        receipt_path = self.fixture.submission / "submission-receipt.json"
        client_path = client_root / f"{receipt.core.submission_id}.json"
        bundle_before = bundle_path.read_bytes()
        receipt_before = receipt_path.read_bytes()
        client_before = client_path.read_bytes()

        with self.assertRaisesRegex(RealAttestationFailureError, "cannot rebind"):
            refresh_update_bundle_attestation(
                public_workspace=self.fixture.public,
                node_workspace=self.fixture.node,
                submission_workspace=self.fixture.submission,
                attestation_result_path=self.fixture.failed_path,
                client_id="client01",
                tcti="unused-in-software-test",
                now=self.fixture.now,
                signer=self.fixture.esk,
            )

        self.assertEqual(bundle_path.read_bytes(), bundle_before)
        self.assertEqual(receipt_path.read_bytes(), receipt_before)
        self.assertEqual(client_path.read_bytes(), client_before)
        self.assertFalse((self.fixture.submission / "pre-reattestation-bundle.json").exists())


if __name__ == "__main__":
    unittest.main()
