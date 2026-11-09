from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_dataset24 as csv_tests
import test_dataset24_parquet as parquet_tests

from fl_forensics.canonical import sha256_file
from fl_forensics.cli import main
from fl_forensics.config import load_yaml
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.ingestion_coverage import (
    RecordCoverageCore,
    RecordCoverageError,
    RecordCoverageManifest,
    RecordInventory,
    RecordInventoryCore,
    create_ingestion_coverage,
    verify_ingestion_coverage,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import _signed

ROOT = Path(__file__).resolve().parents[1]


class IngestionCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "coverage"
        self.source = self.root / "source.jsonl"
        self.signer = SoftwareECDSASigner.generate()
        self.config = load_yaml(ROOT / "configs/base.yaml")[0]["preprocessing"]
        event = {"ts": 1000, "capture_id": "same", "label": "benign", "uid": "duplicate"}
        self.source.write_bytes(
            derived_json_bytes(event)
            + derived_json_bytes(event)
            + b'\n{invalid}\n{}\n{"ts":-1,"label":"benign"}\n{"ts":1}\n'
            + b'{"ts":1,"label":"benign","_source_records":0}\n'
        )

    def _create(self, **changes):
        arguments = {
            "output": self.output,
            "source": self.source,
            "profile": "zeek-jsonl-v1",
            "expected_source_sha256": sha256_file(self.source),
            "preprocessing_config": self.config,
            "signer": self.signer,
            "authority_public_key": self.signer.private_key.public_key(),
        }
        result = create_ingestion_coverage(**{**arguments, **changes})
        self.inventory_pin = result["inventory_sha256"]
        self.manifest_pin = result["manifest_sha256"]
        return result

    def _verify(self, **changes):
        return verify_ingestion_coverage(
            **{
                "workspace": self.output,
                "expected_inventory_sha256": self.inventory_pin,
                "expected_manifest_sha256": self.manifest_pin,
                "authority_public_key": self.signer.private_key.public_key(),
                **changes,
            }
        )

    @staticmethod
    def _replace(path, data):
        path.unlink(missing_ok=True)
        path.write_bytes(data)

    def _resign_manifest(self, update):
        path = self.output / "manifest.json"
        core = json.loads(path.read_bytes())["core"]
        update(core)
        manifest = _signed(
            RecordCoverageManifest,
            RecordCoverageCore.model_validate(core),
            "manifest_id",
            "record-coverage-",
            self.signer,
        )
        self._replace(path, derived_json_bytes(manifest.model_dump(mode="json")))
        self.manifest_pin = sha256_file(path)

    def test_every_occurrence_has_derived_or_motivated_discard_outcome(self):
        result = self._create()
        self.assertEqual(result["record_count"], 8)
        self.assertEqual(
            result["outcome_counts"],
            {
                "derived": 2,
                "blank_line": 1,
                "invalid_json": 1,
                "missing_timestamp": 1,
                "invalid_timestamp": 1,
                "missing_label": 1,
                "invalid_source_lineage": 1,
            },
        )
        outcomes = [
            json.loads(line)
            for line in (self.output / "record-outcomes.jsonl").read_bytes().splitlines()
        ]
        self.assertNotEqual(outcomes[0]["record_id"], outcomes[1]["record_id"])
        self.assertNotEqual(outcomes[0]["event_id"], outcomes[1]["event_id"])
        self.assertEqual(outcomes[0]["window_id"], outcomes[1]["window_id"])
        self.assertEqual(self._verify()["status"], "verified")

    def test_inventory_is_written_before_transformation(self):
        import fl_forensics.ingestion_coverage as coverage

        original = coverage._derive

        def derive(*args):
            self.assertTrue((self.output / "input-inventory.json").is_file())
            self.assertFalse((self.output / "manifest.json").exists())
            return original(*args)

        with patch.object(coverage, "_derive", side_effect=derive):
            self._create()

    def test_no_input_outcome_or_snapshot_is_rewritten_on_verification(self):
        self._create()
        before = {
            path.relative_to(self.output): path.read_bytes()
            for path in self.output.rglob("*")
            if path.is_file()
        }
        self.assertEqual(self._verify()["status"], "verified")
        self.assertEqual(
            before,
            {
                path.relative_to(self.output): path.read_bytes()
                for path in self.output.rglob("*")
                if path.is_file()
            },
        )
        with self.assertRaisesRegex(RecordCoverageError, "never overwrite"):
            self._create()

    def test_wrong_source_anchor_rejected_before_derivation(self):
        with self.assertRaisesRegex(RecordCoverageError, "anchor"):
            self._create(expected_source_sha256="0" * 64)
        self.assertFalse((self.output / "snapshot").exists())

    def test_source_mutation_missing_file_and_extra_source_are_rejected(self):
        self._create()
        raw = self.output / "inputs/input.jsonl"
        original = raw.read_bytes()
        raw.write_bytes(b"changed")
        self.assertEqual(self._verify()["status"], "failed")
        raw.unlink()
        self.assertEqual(self._verify()["status"], "failed")
        raw.write_bytes(original)
        (self.output / "inputs/extra").write_bytes(b"extra")
        self.assertEqual(self._verify()["status"], "failed")

    def test_signed_omission_duplication_wrong_reference_and_false_discard_are_rejected(self):
        self._create()
        outcomes_path = self.output / "record-outcomes.jsonl"
        original_outcomes = outcomes_path.read_bytes()
        original_manifest = (self.output / "manifest.json").read_bytes()
        lines = original_outcomes.splitlines()
        false_discard = json.loads(lines[0])
        false_discard.update(
            status="discarded", reason="invalid_json", window_id=None, event_id=None
        )
        wrong_ref = json.loads(lines[0])
        wrong_ref["window_id"] = "invented-window"
        cases = [
            lines[1:],
            [lines[0], *lines],
            [derived_json_bytes(false_discard).strip(), *lines[1:]],
            [derived_json_bytes(wrong_ref).strip(), *lines[1:]],
        ]
        for values in cases:
            with self.subTest(values=values[:1]):
                self._replace(self.output / "manifest.json", original_manifest)
                outcomes_path.write_bytes(b"\n".join(values) + b"\n")
                self._resign_manifest(
                    lambda core: core.update(outcomes_sha256=sha256_file(outcomes_path))
                )
                result = self._verify()
                self.assertEqual(result["status"], "failed")
                self.assertIn("outcomes", " ".join(result["errors"]))

    def test_coordinated_inventory_and_outcome_omission_fails_against_raw_source(self):
        self._create()
        records = self.output / "source-records.jsonl"
        records.write_bytes(b"\n".join(records.read_bytes().splitlines()[1:]) + b"\n")
        path = self.output / "input-inventory.json"
        core = json.loads(path.read_bytes())["core"]
        core.update(record_count=7, records_sha256=sha256_file(records))
        new_inventory = _signed(
            RecordInventory,
            RecordInventoryCore.model_validate(core),
            "inventory_id",
            "record-inventory-",
            self.signer,
        )
        self._replace(path, derived_json_bytes(new_inventory.model_dump(mode="json")))
        self.inventory_pin = sha256_file(path)
        self._resign_manifest(lambda value: value.update(inventory_sha256=self.inventory_pin))
        result = self._verify()
        self.assertEqual(result["status"], "failed")
        self.assertIn("complete committed input", " ".join(result["errors"]))

    def test_signed_changed_derived_payload_still_has_to_reproduce(self):
        self._create()
        dataset = self.output / "snapshot/dataset.json"
        self._replace(dataset, derived_json_bytes({"rows": []}))
        self._resign_manifest(
            lambda core: core["snapshot_artifacts"].update({"dataset.json": sha256_file(dataset)})
        )
        result = self._verify()
        self.assertEqual(result["status"], "failed")
        self.assertIn("does not reproduce", " ".join(result["errors"]))

    def test_no_downgrade_if_coverage_or_snapshot_evidence_is_missing(self):
        self._create()
        for name in (
            "source-records.jsonl",
            "record-outcomes.jsonl",
            "snapshot/lineage.json",
            "input-inventory.json",
            "manifest.json",
        ):
            with self.subTest(name=name):
                path = self.output / name
                data = path.read_bytes()
                path.unlink()
                self.assertEqual(self._verify()["status"], "failed")
                path.write_bytes(data)

    def test_wrong_pins_keys_policy_and_source_release_fail(self):
        self._create()
        self.assertEqual(self._verify(expected_inventory_sha256="0" * 64)["status"], "failed")
        self.assertEqual(self._verify(expected_manifest_sha256="0" * 64)["status"], "failed")
        self.assertEqual(
            self._verify(
                authority_public_key=SoftwareECDSASigner.generate().private_key.public_key()
            )["status"],
            "failed",
        )
        self._resign_manifest(lambda core: core.update(implementation_sha256="0" * 64))
        self.assertEqual(self._verify()["status"], "failed")
        self._replace(self.output / "preprocessing-config.json", b"{}")
        self.assertEqual(self._verify()["status"], "failed")

    def test_empty_inventory_has_no_nontrivial_coverage_claim(self):
        self.source.write_bytes(b"")
        self._create()
        result = self._verify()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["record_count"], 0)
        self.assertFalse(result["nontrivial_coverage_verified"])
        self.assertFalse(result["capture_completeness_verified"])
        self.assertFalse(result["independent_timestamp_verified"])

    def test_csv_many_to_one_consolidation_keeps_each_source_occurrence(self):
        source = self.root / "csv"
        csv_tests._build_fixture(source)
        result = self._create(
            source=source,
            profile="data24-csv-v1",
            expected_source_sha256=sha256_file(source / "download_manifest.json"),
        )
        self.assertEqual(result["record_count"], 9)
        outcomes = [
            json.loads(line)
            for line in (self.output / "record-outcomes.jsonl").read_bytes().splitlines()
        ]
        self.assertEqual(len({row["event_id"] for row in outcomes}), 8)
        self.assertEqual(self._verify()["status"], "verified")

    def test_parquet_many_to_one_consolidation_and_training_sampling(self):
        source = self.root / "parquet"
        relative, pinned = parquet_tests._build_fixture(source)
        from fl_forensics.dataset24_parquet import PINNED_PARQUET_FILES

        config = copy.deepcopy(self.config)
        config["training_sampling"] = {
            "enabled": True,
            "method": "deterministic-hash-ranking-within-class",
            "seed": 341593,
            "majority_labels": ["benign", "reconnaissance"],
            "majority_fraction": "0.5",
            "minority_fraction": "1.0",
        }
        with patch.dict(PINNED_PARQUET_FILES, {relative: pinned}, clear=True):
            result = self._create(
                source=source,
                profile="data24-parquet-v1",
                expected_source_sha256=sha256_file(source / "download_manifest.json"),
                preprocessing_config=config,
            )
            self.assertEqual(result["record_count"], 11)
            self.assertGreater(result["outcome_counts"]["training_window_not_selected"], 0)
            self.assertEqual(self._verify()["status"], "verified")

    def test_cli_create_verify_and_failure_exit_codes(self):
        import contextlib
        import io

        public = self.root / "authority.pem"
        private = self.root / "authority.private.pem"
        public.write_bytes(self.signer.public_pem())
        private.write_bytes(self.signer.private_pem())
        common = ["--workspace", str(self.output), "--authority-public-key", str(public)]
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(
                [
                    "ingestion-create",
                    *common,
                    "--authority-private-key",
                    str(private),
                    "--source",
                    str(self.source),
                    "--profile",
                    "zeek-jsonl-v1",
                    "--expected-source-sha256",
                    sha256_file(self.source),
                    "--config",
                    str(ROOT / "configs/base.yaml"),
                ]
            )
        self.assertEqual(code, 0)
        args = [
            "ingestion-verify",
            *common,
            "--expected-inventory-sha256",
            sha256_file(self.output / "input-inventory.json"),
            "--expected-manifest-sha256",
            sha256_file(self.output / "manifest.json"),
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(args), 0)
            (self.output / "record-outcomes.jsonl").unlink()
            self.assertEqual(main(args), 1)
