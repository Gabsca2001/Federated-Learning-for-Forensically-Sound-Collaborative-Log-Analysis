from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from fl_forensics.canonical import digest_object, sha256_file
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.secure_round_models import (
    RoundClientContract,
    SecureRoundContext,
    SecureRoundContextCore,
    UpdateBundle,
    UpdateBundleCore,
    tensor_schema,
)
from fl_forensics.storage import atomic_json, write_json_once
from fl_forensics.submission_evidence import (
    SubmissionEvidenceError,
    build_round_input_inventory,
    create_submission_receipt,
    ensure_submission_receipt,
    verify_submission_coverage,
    verify_submission_receipt,
)


class SubmissionEvidenceTests(unittest.TestCase):
    """Cryptographic protocol tests; no model training or synthetic TPM claim."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = datetime(2026, 11, 2, 10, 0, tzinfo=UTC)
        self.coordinator = SoftwareECDSASigner.generate()
        self.coordinator_key = load_public_key(self.coordinator.public_pem())
        self.signers = {
            client_id: SoftwareECDSASigner.generate()
            for client_id in ("client01", "client02")
        }
        self.client_keys = {
            client_id: load_public_key(signer.public_pem())
            for client_id, signer in self.signers.items()
        }
        self.context = self._context()
        self.bundle_paths: dict[str, Path] = {}
        self.bundles: dict[str, UpdateBundle] = {}
        self.paths: dict[str, Path] = {}
        self.receipts = []
        for client_id in self.signers:
            path, bundle = self._bundle(client_id)
            self.paths[client_id] = path
            self.bundles[client_id] = bundle
            self.receipts.append(self._receipt(path, client_id))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _context(self, *, round_number: int = 1) -> SecureRoundContext:
        clients = [
            RoundClientContract(
                client_id=client_id,
                node_id=f"node-{client_id}",
                enrollment_id=f"enrollment-{client_id}",
                attestation_result_id=f"attestation-{client_id}",
                attestation_result_sha256="1" * 64,
                snapshot_sha256="2" * 64,
                snapshot_manifest_sha256="3" * 64,
                train_row_count=3,
            )
            for client_id in self.signers
        ]
        core = SecureRoundContextCore(
            campaign_id="submission-evidence-campaign",
            round_number=round_number,
            previous_checkpoint_sha256="0" * 64,
            base_model_sha256="4" * 64,
            training_contract_sha256="5" * 64,
            partition_manifest_sha256="6" * 64,
            federation_config_sha256="7" * 64,
            seed=341593,
            local_epochs=1,
            batch_size=4,
            learning_rate_decimal="0.001",
            required_client_count=len(clients),
            clients=clients,
            issued_at=(self.now - timedelta(minutes=5)).isoformat(),
            expires_at=(self.now + timedelta(minutes=5)).isoformat(),
        )
        digest = digest_object(core.model_dump(mode="json"))
        return SecureRoundContext(
            context_id=f"round-context-{digest[:24]}",
            core=core,
            core_digest=digest,
            signature=self._signature(self.coordinator, digest),
        )

    @staticmethod
    def _signature(signer: SoftwareECDSASigner, digest: str) -> dict[str, str]:
        return {
            "key_id": signer.key_id,
            "value_b64": signer.sign_digest(digest),
            "trust_level": "software-development",
        }

    def _bundle(self, client_id: str, *, variant: int = 0) -> tuple[Path, UpdateBundle]:
        directory = self.root / "payloads" / f"{client_id}-{variant}"
        model = {
            "parameters": [
                {"name": "weight", "shape": [1], "dtype": "float32", "values": [variant]}
            ]
        }
        write_json_once(directory / "update.json", model)
        write_json_once(directory / "metrics.json", {"num_examples": 3})
        contract = next(
            item for item in self.context.core.clients if item.client_id == client_id
        )
        core = UpdateBundleCore(
            campaign_id=self.context.core.campaign_id,
            context_id=self.context.context_id,
            context_digest=self.context.core_digest,
            round_number=self.context.core.round_number,
            client_id=client_id,
            node_id=contract.node_id,
            enrollment_id=contract.enrollment_id,
            attestation_result_id=contract.attestation_result_id,
            attestation_result_sha256=contract.attestation_result_sha256,
            base_model_sha256=self.context.core.base_model_sha256,
            snapshot_sha256=contract.snapshot_sha256,
            update_sha256=sha256_file(directory / "update.json"),
            metrics_sha256=sha256_file(directory / "metrics.json"),
            tensor_schema_sha256=digest_object(tensor_schema(model)),
            num_examples=3,
            generated_at=self.now.isoformat(),
        )
        digest = digest_object(core.model_dump(mode="json"))
        bundle = UpdateBundle(
            bundle_id=f"update-bundle-{digest[:24]}",
            core=core,
            core_digest=digest,
            signature=self._signature(self.signers[client_id], digest),
        )
        path = directory / "bundle.json"
        write_json_once(path, bundle.model_dump(mode="json"))
        self.bundle_paths[sha256_file(path)] = path
        return path, bundle

    def _receipt(self, path: Path, client_id: str):
        return create_submission_receipt(
            bundle_path=path,
            context=self.context,
            signer=self.signers[client_id],
            client_public_key=self.client_keys[client_id],
            trust_level="software-development",
            submitted_at=self.now,
        )

    def _inventory(self, *, receipts=None, bundle_paths=None):
        return build_round_input_inventory(
            context=self.context,
            receipts=self.receipts if receipts is None else receipts,
            bundle_paths=self.bundle_paths if bundle_paths is None else bundle_paths,
            client_public_keys=self.client_keys,
            coordinator_signer=self.coordinator,
            coordinator_public_key=self.coordinator_key,
            closed_at=self.now + timedelta(minutes=1),
        )

    def _verify(self, inventory, *, receipts=None, bundle_paths=None, client_keys=None):
        return verify_submission_coverage(
            inventory=inventory,
            context=self.context,
            evidence_receipts=self.receipts if receipts is None else receipts,
            bundle_paths=self.bundle_paths if bundle_paths is None else bundle_paths,
            client_public_keys=self.client_keys if client_keys is None else client_keys,
            coordinator_public_key=self.coordinator_key,
            evidence_source="independently-presented-client-copies",
        )

    def _resign(self, inventory, *, entries):
        """A malicious coordinator can sign a newly self-consistent inventory."""
        missing_clients = sorted(
            set(inventory.core.expected_client_ids) - {entry.client_id for entry in entries}
        )
        core = inventory.core.model_copy(
            update={"entries": entries, "missing_client_ids": missing_clients}
        )
        digest = digest_object(core.model_dump(mode="json"))
        identifier = inventory.inventory_id.replace(inventory.core_digest, digest)
        return inventory.model_copy(
            update={
                "core": core,
                "core_digest": digest,
                "inventory_id": identifier,
                "signature": inventory.signature.model_copy(
                    update={"value_b64": self.coordinator.sign_digest(digest)}
                ),
            }
        )

    def _resign_receipt(self, receipt, *, updates):
        core = receipt.core.model_copy(update=updates)
        digest = digest_object(core.model_dump(mode="json"))
        signer = self.signers[receipt.core.client_id]
        return receipt.model_copy(
            update={
                "core": core,
                "core_digest": digest,
                "receipt_id": receipt.receipt_id.replace(receipt.core_digest, digest),
                "signature": receipt.signature.model_copy(
                    update={"value_b64": signer.sign_digest(digest)}
                ),
            }
        )

    def test_valid_two_client_inventory_has_only_conditional_coverage(self) -> None:
        inventory = self._inventory()
        self.assertEqual(len(inventory.core.entries), 2)
        self.assertEqual(
            {entry.outcome for entry in inventory.core.entries}, {"ready_for_admission"}
        )
        report = self._verify(inventory)
        self.assertEqual(report["status"], "verified_for_evidence_set")
        self.assertTrue(report["coverage_verified"])
        self.assertFalse(report["deadline_verified"])
        self.assertFalse(report["admission_decisions_verified"])
        self.assertEqual(report["missing_submission_ids"], [])

    def test_client_signature_does_not_attest_delivery_deadline(self) -> None:
        receipt = self.receipts[0]
        self.assertTrue(
            verify_submission_receipt(
                receipt, context=self.context, client_public_key=self.client_keys["client01"]
            )
        )
        report = self._verify(self._inventory())
        self.assertFalse(report["deadline_verified"])

    def test_builder_requires_authentic_coordinator_context(self) -> None:
        self.assertEqual(len(self._inventory().core.entries), 2)
        altered_context = self.context.model_copy(
            update={
                "signature": self.context.signature.model_copy(update={"value_b64": "AAAA"})
            }
        )
        with self.assertRaises(SubmissionEvidenceError):
            build_round_input_inventory(
                context=altered_context,
                receipts=self.receipts,
                bundle_paths=self.bundle_paths,
                client_public_keys=self.client_keys,
                coordinator_signer=self.coordinator,
                coordinator_public_key=self.coordinator_key,
                closed_at=self.now + timedelta(minutes=1),
            )

    def test_valid_client_signature_cannot_make_outside_window_time_eligible(self) -> None:
        receipt = self.receipts[0]
        for timestamp in (
            self.context.core.expires_at,
            (self.now - timedelta(minutes=6)).isoformat(),
        ):
            with self.subTest(timestamp=timestamp):
                signed_claim = self._resign_receipt(receipt, updates={"submitted_at": timestamp})
                self.assertFalse(
                    verify_submission_receipt(
                        signed_claim,
                        context=self.context,
                        client_public_key=self.client_keys["client01"],
                    )
                )

    def test_wrong_domain_is_rejected_even_with_valid_client_signature(self) -> None:
        signed_other_protocol = self._resign_receipt(
            self.receipts[0], updates={"domain": "other-protocol-v1"}
        )
        self.assertFalse(
            verify_submission_receipt(
                signed_other_protocol,
                context=self.context,
                client_public_key=self.client_keys["client01"],
            )
        )

    def test_signed_receipt_binds_bundle_context_and_both_checkpoint_references(self) -> None:
        receipt = self.receipts[0]
        self.assertEqual(receipt.core.bundle_sha256, sha256_file(self.paths["client01"]))
        self.assertEqual(receipt.core.bundle_core_digest, self.bundles["client01"].core_digest)
        self.assertEqual(receipt.core.context_digest, self.context.core_digest)
        self.assertEqual(receipt.core.base_model_sha256, self.context.core.base_model_sha256)
        self.assertEqual(
            receipt.core.previous_checkpoint_sha256,
            self.context.core.previous_checkpoint_sha256,
        )
        self.assertTrue(receipt.core.domain)

    def test_omission_survives_coordinator_resigning_inventory(self) -> None:
        inventory = self._inventory()
        omitted = inventory.core.entries[-1]
        forged = self._resign(inventory, entries=list(inventory.core.entries[:-1]))
        remaining_paths = {
            key: path for key, path in self.bundle_paths.items() if key != omitted.bundle_sha256
        }
        report = self._verify(forged, bundle_paths=remaining_paths)
        self.assertEqual(report["status"], "invalid")
        self.assertFalse(report["coverage_verified"])
        self.assertIn(omitted.submission_id, report["missing_submission_ids"])

    def test_unchanged_count_does_not_hide_replacement_by_other_bundle(self) -> None:
        path, _bundle = self._bundle("client01", variant=1)
        replacement = self._receipt(path, "client01")
        substituted_inventory = self._inventory(receipts=[replacement, self.receipts[1]])
        report = self._verify(substituted_inventory)
        self.assertEqual(len(substituted_inventory.core.entries), 2)
        self.assertEqual(report["status"], "invalid")
        self.assertFalse(report["coverage_verified"])
        self.assertIn(self.receipts[0].core.submission_id, report["missing_submission_ids"])

    def test_duplicate_evidence_does_not_duplicate_submission(self) -> None:
        receipts = [self.receipts[0], self.receipts[1], self.receipts[0]]
        inventory = self._inventory(receipts=receipts)
        self.assertEqual(len(inventory.core.entries), 2)
        self.assertEqual(
            self._verify(inventory, receipts=receipts)["status"], "verified_for_evidence_set"
        )

    def test_different_submissions_for_same_slot_are_both_rejected_as_conflict(self) -> None:
        path, _bundle = self._bundle("client01", variant=1)
        conflict_receipt = self._receipt(path, "client01")
        evidence = [*self.receipts, conflict_receipt]
        inventory = self._inventory(receipts=evidence)
        conflicts = [entry for entry in inventory.core.entries if entry.client_id == "client01"]
        self.assertEqual(len(conflicts), 2)
        self.assertEqual({entry.outcome for entry in conflicts}, {"rejected_conflict"})
        self.assertEqual(
            self._verify(inventory, receipts=evidence)["status"], "verified_for_evidence_set"
        )

    def test_missing_payload_is_explicit_negative_outcome_without_losing_coverage(self) -> None:
        missing_hash = self.receipts[0].core.bundle_sha256
        available = {key: path for key, path in self.bundle_paths.items() if key != missing_hash}
        inventory = self._inventory(bundle_paths=available)
        entry = next(item for item in inventory.core.entries if item.client_id == "client01")
        self.assertEqual(entry.outcome, "rejected_missing_payload")
        report = self._verify(inventory, bundle_paths=available)
        self.assertTrue(report["coverage_verified"])
        self.assertFalse(report["admission_decisions_verified"])

    def test_inventory_cannot_claim_available_payload_that_is_now_missing(self) -> None:
        inventory = self._inventory()
        missing_hash = self.receipts[0].core.bundle_sha256
        available = {key: path for key, path in self.bundle_paths.items() if key != missing_hash}
        self.assertEqual(self._verify(inventory, bundle_paths=available)["status"], "invalid")

    def test_changed_update_is_not_ready_for_admission(self) -> None:
        atomic_json(self.paths["client01"].parent / "update.json", {"tampered": True})
        inventory = self._inventory()
        entry = next(item for item in inventory.core.entries if item.client_id == "client01")
        self.assertEqual(entry.outcome, "rejected_invalid_payload")

    def test_changed_metrics_is_not_ready_for_admission(self) -> None:
        atomic_json(self.paths["client01"].parent / "metrics.json", {"num_examples": 100000})
        inventory = self._inventory()
        entry = next(item for item in inventory.core.entries if item.client_id == "client01")
        self.assertEqual(entry.outcome, "rejected_invalid_payload")

    def test_receipt_rejects_wrong_pinned_client_key(self) -> None:
        self.assertFalse(
            verify_submission_receipt(
                self.receipts[0],
                context=self.context,
                client_public_key=self.client_keys["client02"],
            )
        )
        wrong_keys = dict(self.client_keys, client01=self.client_keys["client02"])
        self.assertEqual(
            self._verify(self._inventory(), client_keys=wrong_keys)["status"], "invalid"
        )

    def test_receipt_rejects_changed_key_identifier_even_with_original_signature(self) -> None:
        receipt = self.receipts[0]
        altered = receipt.model_copy(
            update={
                "signature": receipt.signature.model_copy(
                    update={"key_id": self.signers["client02"].key_id}
                )
            }
        )
        self.assertFalse(
            verify_submission_receipt(
                altered, context=self.context, client_public_key=self.client_keys["client01"]
            )
        )

    def test_outer_trust_label_cannot_override_signed_trust_level(self) -> None:
        receipt = self.receipts[0]
        self.assertEqual(receipt.core.signing_trust_level, "software-development")
        altered = receipt.model_copy(
            update={"signature": receipt.signature.model_copy(update={"trust_level": "tpm2"})}
        )
        self.assertFalse(
            verify_submission_receipt(
                altered, context=self.context, client_public_key=self.client_keys["client01"]
            )
        )

    def test_receipt_rejects_changed_client_identity(self) -> None:
        receipt = self.receipts[0]
        altered = receipt.model_copy(
            update={"core": receipt.core.model_copy(update={"client_id": "client02"})}
        )
        self.assertFalse(
            verify_submission_receipt(
                altered, context=self.context, client_public_key=self.client_keys["client01"]
            )
        )

    def test_receipt_rejects_signature_tampering(self) -> None:
        receipt = self.receipts[0]
        altered = receipt.model_copy(
            update={"signature": receipt.signature.model_copy(update={"value_b64": "AAAA"})}
        )
        self.assertFalse(
            verify_submission_receipt(
                altered, context=self.context, client_public_key=self.client_keys["client01"]
            )
        )
        self.assertEqual(
            self._verify(self._inventory(), receipts=[altered, self.receipts[1]])["status"],
            "invalid",
        )

    def test_receipt_cannot_be_replayed_in_another_authenticated_round(self) -> None:
        self.assertFalse(
            verify_submission_receipt(
                self.receipts[0],
                context=self._context(round_number=2),
                client_public_key=self.client_keys["client01"],
            )
        )

    def test_receipt_rejects_checkpoint_tampering(self) -> None:
        receipt = self.receipts[0]
        altered = receipt.model_copy(
            update={"core": receipt.core.model_copy(update={"base_model_sha256": "f" * 64})}
        )
        self.assertFalse(
            verify_submission_receipt(
                altered, context=self.context, client_public_key=self.client_keys["client01"]
            )
        )

    def test_inventory_rejects_invalid_coordinator_signature(self) -> None:
        inventory = self._inventory()
        altered = inventory.model_copy(
            update={"signature": inventory.signature.model_copy(update={"value_b64": "AAAA"})}
        )
        self.assertEqual(self._verify(altered)["status"], "invalid")

    def test_empty_evidence_set_never_certifies_global_completeness(self) -> None:
        inventory = self._inventory(receipts=[])
        report = self._verify(inventory, receipts=[])
        self.assertEqual(report["status"], "insufficient_evidence")
        self.assertFalse(report["coverage_verified"])
        self.assertFalse(report["deadline_verified"])

    def test_presented_subset_does_not_invalidate_other_inventory_submissions(self) -> None:
        inventory = self._inventory()
        presented = self.receipts[0]
        other = self.receipts[1]
        report = self._verify(inventory, receipts=[presented])
        self.assertEqual(report["status"], "verified_for_evidence_set")
        self.assertTrue(report["coverage_verified"])
        self.assertFalse(report["inventory_fully_recomputed"])
        self.assertIn(
            other.core.submission_id, report["additional_inventory_submission_ids"]
        )
        self.assertNotIn(
            presented.core.submission_id, report["additional_inventory_submission_ids"]
        )
        self.assertFalse(report["deadline_verified"])
        self.assertFalse(report["admission_decisions_verified"])

    def test_partial_evidence_covers_submission_without_proving_claimed_conflict(self) -> None:
        path, _bundle = self._bundle("client01", variant=1)
        conflicting = self._receipt(path, "client01")
        inventory = self._inventory(receipts=[*self.receipts, conflicting])
        presented = self.receipts[0]
        report = self._verify(inventory, receipts=[presented])
        self.assertEqual(report["status"], "verified_for_evidence_set")
        self.assertTrue(report["coverage_verified"])
        self.assertFalse(report["intake_outcomes_verified"])
        self.assertFalse(report["inventory_fully_recomputed"])
        self.assertIn(
            presented.core.submission_id, report["unverified_outcome_submission_ids"]
        )

    def test_ensure_receipt_reuses_existing_signature_and_restores_client_copy(self) -> None:
        client_root = self.root / "client01-private-receipts"
        options = {
            "bundle_path": self.paths["client01"],
            "context": self.context,
            "signer": self.signers["client01"],
            "client_public_key": self.client_keys["client01"],
            "trust_level": "software-development",
            "client_receipt_root": client_root,
            "submitted_at": self.now,
        }
        receipt = ensure_submission_receipt(**options)
        submission_copy = self.paths["client01"].parent / "submission-receipt.json"
        client_copy = client_root / f"{receipt.core.submission_id}.json"
        initial_bytes = submission_copy.read_bytes()
        self.assertEqual(client_copy.read_bytes(), initial_bytes)
        client_copy.chmod(0o600)
        client_copy.unlink()
        with patch.object(
            SoftwareECDSASigner, "sign_digest", side_effect=AssertionError("retry re-signed")
        ):
            retried = ensure_submission_receipt(**options)
        self.assertEqual(retried.receipt_id, receipt.receipt_id)
        self.assertEqual(submission_copy.read_bytes(), initial_bytes)
        self.assertEqual(client_copy.read_bytes(), initial_bytes)

    def test_ensure_receipt_restores_submission_copy_from_client_evidence(self) -> None:
        client_root = self.root / "client01-private-receipts"
        options = {
            "bundle_path": self.paths["client01"],
            "context": self.context,
            "signer": self.signers["client01"],
            "client_public_key": self.client_keys["client01"],
            "trust_level": "software-development",
            "client_receipt_root": client_root,
            "submitted_at": self.now,
        }
        receipt = ensure_submission_receipt(**options)
        submission_copy = self.paths["client01"].parent / "submission-receipt.json"
        client_copy = client_root / f"{receipt.core.submission_id}.json"
        initial_bytes = client_copy.read_bytes()
        submission_copy.chmod(0o600)
        submission_copy.unlink()
        with patch.object(
            SoftwareECDSASigner, "sign_digest", side_effect=AssertionError("retry re-signed")
        ):
            retried = ensure_submission_receipt(**options)
        self.assertEqual(retried.receipt_id, receipt.receipt_id)
        self.assertEqual(submission_copy.read_bytes(), initial_bytes)

    def test_ensure_receipt_does_not_overwrite_a_divergent_client_copy(self) -> None:
        client_root = self.root / "client01-private-receipts"
        options = {
            "bundle_path": self.paths["client01"],
            "context": self.context,
            "signer": self.signers["client01"],
            "client_public_key": self.client_keys["client01"],
            "trust_level": "software-development",
            "client_receipt_root": client_root,
            "submitted_at": self.now,
        }
        receipt = ensure_submission_receipt(**options)
        client_copy = client_root / f"{receipt.core.submission_id}.json"
        bad_value = receipt.model_dump(mode="json")
        bad_value["signature"]["value_b64"] = "AAAA"
        atomic_json(client_copy, bad_value)
        bad_bytes = client_copy.read_bytes()
        with self.assertRaises((SubmissionEvidenceError, FileExistsError)):
            ensure_submission_receipt(**options)
        self.assertEqual(client_copy.read_bytes(), bad_bytes)


if __name__ == "__main__":
    unittest.main()
