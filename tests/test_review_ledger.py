from __future__ import annotations

import copy
import io
import json
import shutil
import stat
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import test_round_derivation as round_tests

from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_file
from fl_forensics.cli import main
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.review_ledger import (
    ReviewLedgerError,
    append_review,
    authenticate_review_subject,
    initialize_review_ledger,
    verify_review_ledger,
)
from fl_forensics.storage import load_json


class ReviewLedgerTests(unittest.TestCase):
    """Signed semantic revisions over a preserved round, without new training."""

    def setUp(self) -> None:
        self.fixture = round_tests.RoundDerivationTests(
            "test_nominal_derivation_binds_receipts_decisions_scoring_and_checkpoint"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture._prepare()
        self.fixture._run()
        self.workspace = self.fixture.workspace
        self.ledger = self.fixture.root / "separate-review-ledger"
        self.manifest = self.workspace / "derivation" / "manifest.json"
        self.manifest_hash = sha256_file(self.manifest)
        dispositions = load_json(self.manifest)["core"]["dispositions"]
        self.subject = dispositions[0]["submission_id"]
        self.other_subject = dispositions[1]["submission_id"]
        self.authority = SoftwareECDSASigner.generate()
        self.authority_key = load_public_key(self.authority.public_pem())
        self.signers = {name: SoftwareECDSASigner.generate() for name in ("analyst-a", "analyst-b")}
        self.keys = {
            name: load_public_key(signer.public_pem()) for name, signer in self.signers.items()
        }
        self.coordinator_key = load_public_key(self.fixture.fixture.coordinator.public_pem())
        self.now = self.fixture.now
        self.evidence = [
            {
                "sha256": sha256_file(self.fixture.validation_path),
                "description": "Controlled validation evidence, not an independent truth label",
            }
        ]
        self.historical_hashes = self._hashes(self.workspace)
        self.genesis_head = initialize_review_ledger(
            ledger_workspace=self.ledger,
            round_workspace=self.workspace,
            expected_manifest_sha256=self.manifest_hash,
            coordinator_public_key=self.coordinator_key,
            authority_signer=self.authority,
            authorized_reviewers=self.keys,
            created_at=self.now,
        )

    @staticmethod
    def _hashes(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): sha256_file(path)
            for path in root.rglob("*")
            if path.is_file()
        }

    def _options(self, *, ledger: Path | None = None) -> dict:
        return {
            "ledger_workspace": ledger or self.ledger,
            "round_workspace": self.workspace,
            "coordinator_public_key": self.coordinator_key,
            "authority_public_key": self.authority_key,
            "reviewer_public_keys": self.keys,
        }

    def _append(
        self,
        *,
        previous=None,
        operation="operation-1",
        subject=None,
        label="suspicious",
        reason="Investigative concern requiring an attributed review",
        reviewer="analyst-a",
        ledger: Path | None = None,
        **overrides,
    ):
        options = {
            **self._options(ledger=ledger),
            "expected_previous_head": previous or self.genesis_head,
            "operation_id": operation,
            "submission_id": subject or self.subject,
            "label": label,
            "reason": reason,
            "evidence_refs": self.evidence,
            "reviewer_id": reviewer,
            "signer": self.signers[reviewer],
            "created_at": self.now,
            **overrides,
        }
        return append_review(**options)

    def _verify(self, **overrides):
        return verify_review_ledger(**{**self._options(), **overrides})

    @property
    def record_path(self) -> Path:
        return self.ledger / "review-ledger.jsonl"

    def _lines(self) -> list[bytes]:
        return self.record_path.read_bytes().splitlines(keepends=True)

    @staticmethod
    def _replace(path: Path, data: bytes) -> None:
        path.chmod(path.stat().st_mode | stat.S_IWUSR)
        path.write_bytes(data)

    def _write_records(self, records: list[dict]) -> None:
        self._replace(
            self.record_path,
            b"".join(canonical_json_bytes(record) + b"\n" for record in records),
        )

    @staticmethod
    def _resign(record: dict, signer: SoftwareECDSASigner) -> dict:
        result = copy.deepcopy(record)
        old_digest = result["core_digest"]
        digest = digest_object(result["core"])
        # The test does not depend on the chosen human-readable envelope ID prefix.
        for key, value in result.items():
            if key != "core_digest" and isinstance(value, str) and value.endswith(old_digest):
                result[key] = value[: -len(old_digest)] + digest
        result["core_digest"] = digest
        result["signature"]["key_id"] = signer.key_id
        result["signature"]["value_b64"] = signer.sign_digest(digest)
        return result

    def test_subject_authentication_does_not_claim_new_numerical_recomputation(self) -> None:
        with (
            patch(
                "fl_forensics.in_round_admission.verify_in_round_secure_round",
                side_effect=AssertionError("review re-ran current round verification"),
            ),
            patch(
                "fl_forensics.round_derivation.implementation_sha256",
                side_effect=AssertionError("review demanded the current implementation hash"),
            ),
        ):
            report = authenticate_review_subject(
                round_workspace=self.workspace,
                trusted_coordinator_key=self.coordinator_key,
                expected_manifest_sha256=self.manifest_hash,
            )
        self.assertTrue(report["historical_artifacts_authenticated"])
        self.assertFalse(report["historical_round_recomputed"])
        self.assertEqual(report["manifest_sha256"], self.manifest_hash)
        self.assertIn(self.subject, report["subjects"])
        self.assertTrue(report["subjects"][self.subject]["disposition_sha256"])

    def test_two_disagreeing_reviews_preserve_all_historical_bytes(self) -> None:
        first = self._append(label="benign")
        second = self._append(
            previous=first["head"],
            operation="operation-2",
            label="malicious",
            reviewer="analyst-b",
            reason="New evidence changes this analyst's assessment",
        )
        report = self._verify(expected_head=second["head"], require_tip_anchor=True)
        self.assertEqual(report["status"], "verified", report)
        self.assertTrue(report["historical_artifacts_authenticated"])
        self.assertFalse(report["historical_round_recomputed"])
        state = report["semantic_states"][self.subject]
        self.assertEqual(state["label"], "malicious")
        self.assertEqual(state["revision"], 2)
        self.assertEqual(state["reviewer_id"], "analyst-b")
        self.assertEqual(len(self._lines()), 2)
        self.assertEqual(self._hashes(self.workspace), self.historical_hashes)
        for disposition in load_json(self.manifest)["core"]["dispositions"]:
            self.assertEqual(disposition["semantic_state"], "not_reviewed")

    def test_revisions_are_scoped_to_submission_not_all_clients_or_rounds(self) -> None:
        first = self._append(label="suspicious")
        second = self._append(
            previous=first["head"],
            operation="operation-2",
            subject=self.other_subject,
            label="benign",
        )
        report = self._verify(expected_head=second["head"])
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(report["semantic_states"][self.subject]["revision"], 1)
        self.assertEqual(report["semantic_states"][self.other_subject]["revision"], 1)
        self.assertEqual(report["semantic_states"][self.subject]["label"], "suspicious")
        self.assertEqual(report["semantic_states"][self.other_subject]["label"], "benign")

    def test_unanchored_chain_makes_no_rollback_guarantee(self) -> None:
        self._append()
        report = self._verify()
        self.assertEqual(report["status"], "verified", report)
        self.assertTrue(report["chain_verified"])
        self.assertEqual(report["anchor_status"], "unanchored")
        self.assertFalse(report["rollback_protection_verified"])

    def test_external_tip_anchor_verifies_the_presented_tip(self) -> None:
        appended = self._append()
        report = self._verify(expected_head=appended["head"], require_tip_anchor=True)
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(report["anchor_status"], "trusted_tip")
        self.assertTrue(report["rollback_protection_verified"])

    def test_old_anchor_verifies_only_the_prefix(self) -> None:
        first = self._append()
        self._append(previous=first["head"], operation="operation-2", label="inconclusive")
        report = self._verify(expected_head=first["head"])
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(report["anchor_status"], "trusted_prefix")
        self.assertTrue(report["rollback_protection_verified"])
        self.assertEqual(
            self._verify(expected_head=first["head"], require_tip_anchor=True)["status"],
            "failed",
        )

    def test_requiring_tip_without_external_anchor_fails(self) -> None:
        self._append()
        self.assertEqual(self._verify(require_tip_anchor=True)["status"], "failed")

    def test_retry_reuses_record_bytes_without_signing_or_appending(self) -> None:
        first = self._append()
        before = self.record_path.read_bytes()
        with patch.object(
            SoftwareECDSASigner, "sign_digest", side_effect=AssertionError("retry re-signed")
        ):
            retried = self._append()
        self.assertTrue(retried["idempotent"])
        self.assertEqual(retried["head"], first["head"])
        self.assertEqual(self.record_path.read_bytes(), before)
        self.assertEqual(len(self._lines()), 1)

    def test_reused_operation_id_with_changed_review_fails(self) -> None:
        self._append()
        before = self.record_path.read_bytes()
        with self.assertRaises(ReviewLedgerError):
            self._append(label="benign")
        self.assertEqual(self.record_path.read_bytes(), before)

    def test_stale_expected_tip_cannot_create_another_append(self) -> None:
        self._append()
        before = self.record_path.read_bytes()
        with self.assertRaises(ReviewLedgerError):
            self._append(operation="operation-2")
        self.assertEqual(self.record_path.read_bytes(), before)

    def test_two_concurrent_appends_with_one_expected_tip_have_one_winner(self) -> None:
        def attempt(index):
            try:
                return self._append(operation=f"concurrent-{index}")
            except ReviewLedgerError:
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt, range(2)))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(self._lines()), 1)
        self.assertEqual(
            self._verify(expected_head=winners[0]["head"], require_tip_anchor=True)["status"],
            "verified",
        )

    def test_unknown_author_with_own_valid_key_is_not_self_authorized(self) -> None:
        outsider = SoftwareECDSASigner.generate()
        outsiders = {**self.keys, "outsider": load_public_key(outsider.public_pem())}
        with self.assertRaises(ReviewLedgerError):
            append_review(
                **{**self._options(), "reviewer_public_keys": outsiders},
                expected_previous_head=self.genesis_head,
                operation_id="outsider-operation",
                submission_id=self.subject,
                label="malicious",
                reason="An unauthorized signer cannot make this an authorized review",
                evidence_refs=self.evidence,
                reviewer_id="outsider",
                signer=outsider,
                created_at=self.now,
            )
        self.assertEqual(self.record_path.read_bytes(), b"")

    def test_author_id_cannot_be_signed_with_another_author_key(self) -> None:
        with self.assertRaises(ReviewLedgerError):
            self._append(signer=self.signers["analyst-b"])
        self.assertEqual(self.record_path.read_bytes(), b"")

    def test_verifier_requires_the_pinned_reviewer_key(self) -> None:
        appended = self._append()
        wrong_keys = {
            **self.keys,
            "analyst-a": load_public_key(SoftwareECDSASigner.generate().public_pem()),
        }
        report = self._verify(reviewer_public_keys=wrong_keys, expected_head=appended["head"])
        self.assertEqual(report["status"], "failed")

    def test_unknown_submission_cannot_be_reviewed(self) -> None:
        with self.assertRaises(ReviewLedgerError):
            self._append(subject="submission-" + "f" * 64)
        self.assertEqual(self.record_path.read_bytes(), b"")

    def test_reason_evidence_and_semantic_label_are_required(self) -> None:
        for overrides in (
            {"reason": ""},
            {"reason": "   "},
            {"evidence_refs": []},
            {"evidence_refs": [{"sha256": "not-a-hash", "description": "bad reference"}]},
            {"label": "accepted"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises((ReviewLedgerError, ValueError)):
                    self._append(**overrides)
                self.assertEqual(self.record_path.read_bytes(), b"")

    def test_wrong_manifest_pin_is_rejected(self) -> None:
        with self.assertRaises(ReviewLedgerError):
            authenticate_review_subject(
                round_workspace=self.workspace,
                trusted_coordinator_key=self.coordinator_key,
                expected_manifest_sha256="f" * 64,
            )

    def test_historical_checkpoint_byte_change_is_detected(self) -> None:
        self._append()
        path = self.workspace / "checkpoint" / "global-model.json"
        self._replace(path, path.read_bytes() + b" ")
        report = self._verify()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["historical_artifacts_authenticated"])

    def test_tampered_record_signature_is_rejected(self) -> None:
        appended = self._append()
        record = json.loads(self._lines()[0])
        record["signature"]["value_b64"] = "AAAA"
        self._write_records([record])
        self.assertEqual(self._verify(expected_head=appended["head"])["status"], "failed")

    def test_record_removal_breaks_the_chain(self) -> None:
        first = self._append()
        second = self._append(previous=first["head"], operation="operation-2")
        self._replace(self.record_path, self._lines()[1])
        self.assertEqual(self._verify(expected_head=second["head"])["status"], "failed")

    def test_truncation_is_detected_against_the_external_tip(self) -> None:
        first = self._append()
        second = self._append(previous=first["head"], operation="operation-2")
        self._replace(self.record_path, self._lines()[0])
        self.assertEqual(self._verify(expected_head=second["head"])["status"], "failed")

    def test_authorized_resigned_alternative_history_is_detected_by_external_head(self) -> None:
        first = self._append()
        second = self._append(previous=first["head"], operation="operation-2", label="malicious")
        records = [json.loads(line) for line in self._lines()]
        records[-1]["core"]["label"] = "inconclusive"
        records[-1] = self._resign(records[-1], self.signers["analyst-a"])
        self._write_records(records)
        self.assertEqual(self._verify(expected_head=second["head"])["status"], "failed")

    def test_valid_fork_cannot_replace_the_branch_named_by_a_trusted_head(self) -> None:
        first = self._append()
        fork = self.fixture.root / "forked-review-ledger"
        shutil.copytree(self.ledger, fork)
        second = self._append(previous=first["head"], operation="operation-2", label="benign")
        alternate = self._append(
            previous=first["head"], operation="fork-operation-2", label="malicious", ledger=fork
        )
        self.assertNotEqual(second["head"], alternate["head"])
        report = self._verify(ledger_workspace=fork, expected_head=second["head"])
        self.assertEqual(report["status"], "failed")
        unanchored = self._verify(ledger_workspace=fork)
        self.assertEqual(unanchored["status"], "verified", unanchored)
        self.assertFalse(unanchored["rollback_protection_verified"])

    def test_head_from_another_ledger_is_rejected(self) -> None:
        other = self.fixture.root / "other-review-ledger"
        other_head = initialize_review_ledger(
            ledger_workspace=other,
            round_workspace=self.workspace,
            expected_manifest_sha256=self.manifest_hash,
            coordinator_public_key=self.coordinator_key,
            authority_signer=self.authority,
            authorized_reviewers=self.keys,
            created_at=self.now + timedelta(seconds=1),
        )
        self.assertEqual(self._verify(expected_head=other_head)["status"], "failed")

    def test_bad_signer_cannot_persist_an_invalid_review(self) -> None:
        authorized_key_id = self.signers["analyst-a"].key_id

        class InvalidSigner:
            key_id = authorized_key_id

            @staticmethod
            def sign_digest(digest):
                del digest
                return "AAAA"

        before = self.record_path.read_bytes()
        with self.assertRaises(ReviewLedgerError):
            self._append(signer=InvalidSigner())
        self.assertEqual(self.record_path.read_bytes(), before)

    def test_invalid_genesis_signature_is_not_persisted(self) -> None:
        ledger = self.fixture.root / "invalid-genesis-ledger"
        with (
            patch.object(SoftwareECDSASigner, "sign_digest", return_value="AAAA"),
            self.assertRaises(ReviewLedgerError),
        ):
            initialize_review_ledger(
                ledger_workspace=ledger,
                round_workspace=self.workspace,
                expected_manifest_sha256=self.manifest_hash,
                coordinator_public_key=self.coordinator_key,
                authority_signer=self.authority,
                authorized_reviewers=self.keys,
                created_at=self.now,
            )
        self.assertFalse((ledger / "ledger.json").exists())
        if (ledger / "review-ledger.jsonl").exists():
            self.assertEqual((ledger / "review-ledger.jsonl").read_bytes(), b"")

    def test_public_verification_is_read_only_and_does_not_take_write_lock(self) -> None:
        appended = self._append()
        before = self._hashes(self.ledger)
        with patch(
            "fl_forensics.review_ledger._exclusive",
            side_effect=AssertionError("public verification attempted a write lock"),
        ):
            report = self._verify(expected_head=appended["head"], require_tip_anchor=True)
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(self._hashes(self.ledger), before)

    def test_relocated_ledger_cannot_append_inside_historical_workspace(self) -> None:
        relocated = self.workspace / "relocated-review-ledger"
        shutil.copytree(self.ledger, relocated)
        before = (relocated / "review-ledger.jsonl").read_bytes()
        with self.assertRaises(ReviewLedgerError):
            self._append(ledger=relocated)
        self.assertEqual((relocated / "review-ledger.jsonl").read_bytes(), before)

    def test_committed_review_survives_index_failure_and_retry_rebuilds_index(self) -> None:
        with patch(
            "fl_forensics.lineage.LineageStore.record_review_path",
            side_effect=OSError("controlled derived-index failure"),
        ):
            committed = self._append()
        self.assertFalse(committed["lineage_indexed"])
        self.assertIn("controlled derived-index failure", committed["lineage_index_error"])
        before = self.record_path.read_bytes()
        self.assertEqual(len(self._lines()), 1)
        report = self._verify(expected_head=committed["head"], require_tip_anchor=True)
        self.assertEqual(report["status"], "verified", report)
        with patch.object(
            SoftwareECDSASigner, "sign_digest", side_effect=AssertionError("retry re-signed")
        ):
            recovered = self._append()
        self.assertTrue(recovered["idempotent"])
        self.assertTrue(recovered["lineage_indexed"])
        self.assertEqual(recovered["head"], committed["head"])
        self.assertEqual(self.record_path.read_bytes(), before)

    def test_cli_init_append_and_verify_use_external_keys_and_head(self) -> None:
        inputs = self.fixture.root / "cli-review-inputs"
        inputs.mkdir()
        ledger = self.fixture.root / "cli-review-ledger"
        coordinator_path = inputs / "coordinator.public.pem"
        authority_private = inputs / "authority.private.pem"
        authority_public = inputs / "authority.public.pem"
        reviewer_private = inputs / "analyst-a.private.pem"
        roster_path = inputs / "reviewers.json"
        evidence_path = inputs / "evidence.json"
        head_zero = inputs / "head-0.json"
        head_one = inputs / "head-1.json"
        coordinator_path.write_bytes(self.fixture.fixture.coordinator.public_pem())
        authority_private.write_bytes(self.authority.private_pem())
        authority_public.write_bytes(self.authority.public_pem())
        reviewer_private.write_bytes(self.signers["analyst-a"].private_pem())
        for reviewer_id, signer in self.signers.items():
            (inputs / f"{reviewer_id}.public.pem").write_bytes(signer.public_pem())
        roster_path.write_text(
            json.dumps({name: f"{name}.public.pem" for name in self.signers}), encoding="utf-8"
        )
        evidence_path.write_text(json.dumps(self.evidence), encoding="utf-8")
        common = [
            "--ledger",
            str(ledger),
            "--round-workspace",
            str(self.workspace),
            "--coordinator-public-key",
            str(coordinator_path),
            "--reviewer-keys",
            str(roster_path),
        ]

        def invoke(command, arguments):
            output = io.StringIO()
            with redirect_stdout(output):
                code = main([command, *common, *arguments])
            result = json.loads(output.getvalue())
            self.assertEqual(code, 0, result)
            return result

        initialized = invoke(
            "review-init",
            [
                "--manifest-sha256",
                self.manifest_hash,
                "--authority-private-key",
                str(authority_private),
                "--export-head",
                str(head_zero),
            ],
        )
        self.assertEqual(initialized["status"], "initialized")
        append_arguments = [
            "--authority-public-key",
            str(authority_public),
            "--expected-head",
            str(head_zero),
            "--operation-id",
            "cli-review-operation",
            "--submission-id",
            self.subject,
            "--reviewer-id",
            "analyst-a",
            "--reviewer-private-key",
            str(reviewer_private),
            "--label",
            "suspicious",
            "--reason",
            "CLI roundtrip over signed historical evidence",
            "--evidence",
            str(evidence_path),
            "--export-head",
            str(head_one),
        ]
        unsafe_export = list(append_arguments)
        unsafe_export[unsafe_export.index("--export-head") + 1] = str(ledger / "head.json")
        before_failed_cli = (ledger / "review-ledger.jsonl").read_bytes()
        rejected_output = io.StringIO()
        with redirect_stdout(rejected_output):
            rejected_code = main(["review-append", *common, *unsafe_export])
        rejected = json.loads(rejected_output.getvalue())
        self.assertEqual(rejected_code, 1)
        self.assertEqual(rejected["status"], "failed")
        self.assertEqual((ledger / "review-ledger.jsonl").read_bytes(), before_failed_cli)
        self.assertFalse((ledger / "head.json").exists())
        appended = invoke("review-append", append_arguments)
        self.assertEqual(appended["status"], "appended")
        first_bytes = (ledger / "review-ledger.jsonl").read_bytes()
        retry = invoke("review-append", append_arguments)
        self.assertTrue(retry["idempotent"])
        self.assertEqual((ledger / "review-ledger.jsonl").read_bytes(), first_bytes)
        report = invoke(
            "review-verify",
            [
                "--authority-public-key",
                str(authority_public),
                "--expected-head",
                str(head_one),
                "--require-tip-anchor",
            ],
        )
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(report["anchor_status"], "trusted_tip")
        self.assertFalse(report["historical_round_recomputed"])
        self.assertEqual(report["semantic_states"][self.subject]["label"], "suspicious")
        self.assertEqual(self._hashes(self.workspace), self.historical_hashes)

    def test_manifest_pin_and_parsing_use_one_identical_byte_snapshot(self) -> None:
        original = load_json(self.manifest)
        original_disposition = next(
            item
            for item in original["core"]["dispositions"]
            if item["submission_id"] == self.subject
        )
        original_disposition_hash = digest_object(original_disposition)
        alternate = copy.deepcopy(original)
        alternate_disposition = next(
            item
            for item in alternate["core"]["dispositions"]
            if item["submission_id"] == self.subject
        )
        alternate_disposition.update({"alpha_numerator": "3", "alpha_denominator": "4"})
        alternate_disposition_hash = digest_object(alternate_disposition)
        digest = digest_object(alternate["core"])
        alternate["core_digest"] = digest
        alternate["manifest_id"] = "round-derivation-" + digest
        alternate["signature"]["value_b64"] = self.fixture.fixture.coordinator.sign_digest(digest)
        self.assertNotEqual(original_disposition_hash, alternate_disposition_hash)
        before = self.manifest.read_bytes()

        def changed_second_read(path):
            if Path(path).resolve() == self.manifest.resolve():
                return alternate
            return load_json(path)

        # Old hash-then-load code accepted B after hashing A. Authentication must
        # derive both commitment and interpretation from the same pinned bytes.
        with patch(
            "fl_forensics.review_ledger.load_json",
            side_effect=changed_second_read,
            create=True,
        ):
            report = authenticate_review_subject(
                round_workspace=self.workspace,
                trusted_coordinator_key=self.coordinator_key,
                expected_manifest_sha256=self.manifest_hash,
            )
        self.assertTrue(report["historical_artifacts_authenticated"])
        self.assertEqual(
            report["subjects"][self.subject]["disposition_sha256"],
            original_disposition_hash,
        )
        self.assertNotEqual(
            report["subjects"][self.subject]["disposition_sha256"],
            alternate_disposition_hash,
        )
        self.assertEqual(self.manifest.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
