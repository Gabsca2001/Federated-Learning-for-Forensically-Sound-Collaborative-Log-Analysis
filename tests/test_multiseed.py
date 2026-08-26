from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from fl_forensics.canonical import sha256_file
from fl_forensics.multiseed import (
    MultiSeedError,
    create_multiseed_summary,
    describe,
    load_multiseed_contract,
    verify_multiseed_summary,
)
from fl_forensics.preprocessing import derived_json_bytes


class MultiSeedTests(unittest.TestCase):
    def _contract(self, root: Path) -> Path:
        path = root / "multiseed.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "schema_version": "1.0",
                    "experiment_id": "test-multiseed",
                    "base_federation_config": "configs/federation.yaml",
                    "seeds": [11, 523],
                    "modes": ["iid", "non-iid"],
                    "execution": {"device": "cpu"},
                    "statistics": {
                        "primary_metric": "macro_f1_all_model_classes",
                        "primary_split": "test",
                        "standard_deviation": "sample",
                        "confidence_interval": "student-t-95-percent",
                        "pairing": "by-seed",
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return path

    def _fake_runs(self, root: Path) -> tuple[Path, Path]:
        runs = root / "runs"
        dataset = root / "m2"
        dataset.mkdir()
        (dataset / "manifest.json").write_text("{}", encoding="utf-8")
        class_names = ["benign", "attack"]
        for seed_index, seed in enumerate((11, 523)):
            config = {
                "partitioning": {"seed": seed},
                "training": {"seed": seed},
            }
            config_path = runs / "configs" / f"federation-seed-{seed}.yaml"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                yaml.safe_dump(config, sort_keys=False), encoding="utf-8"
            )
            for mode_index, mode in enumerate(("iid", "non-iid")):
                base = runs / f"seed-{seed}" / mode
                partition = base / "partition"
                run = base / "run"
                partition.mkdir(parents=True)
                run.mkdir(parents=True)
                partition_manifest = {
                    "class_names": class_names,
                    "partition_mode": mode,
                }
                (partition / "manifest.json").write_bytes(
                    derived_json_bytes(partition_manifest)
                )
                offset = seed_index * 0.01 + mode_index * 0.02
                split = lambda value: {
                    "accuracy": value + 0.01,
                    "balanced_accuracy_observed_classes": value + 0.005,
                    "macro_f1_all_model_classes": value,
                    "per_class": {
                        "benign": {"f1": value + 0.02},
                        "attack": {"f1": value - 0.02},
                    },
                }
                metrics = {
                    "partition_mode": mode,
                    "selected": {
                        "round": 2 + mode_index,
                        "validation": split(0.80 + offset),
                        "test": split(0.75 + offset),
                        "temporal_holdout": {
                            "accuracy": 0.98 - offset,
                        },
                        "operational_metrics": {
                            "temporal_holdout_benign_false_alarms": {
                                "false_alarm_rate": 0.02 + offset,
                            }
                        },
                    },
                }
                (run / "metrics.json").write_bytes(derived_json_bytes(metrics))
                manifest = {
                    "partition_mode": mode,
                    "training": {"seed": seed},
                    "federation_config_sha256": sha256_file(config_path),
                    "partition_manifest_sha256": sha256_file(
                        partition / "manifest.json"
                    ),
                    "metrics_sha256": sha256_file(run / "metrics.json"),
                    "selected_round": 2 + mode_index,
                    "selection_policy": {
                        "metric": "macro_f1_all_model_classes",
                        "mode": "maximize",
                        "split": "validation",
                        "test_policy": "selected-checkpoint-only",
                        "tie_breaker": "earliest_round",
                    },
                }
                (run / "manifest.json").write_bytes(derived_json_bytes(manifest))
        return runs, dataset

    def test_describe_uses_sample_standard_deviation_and_student_t(self) -> None:
        result = describe([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertEqual(result["count"], 5)
        self.assertEqual(result["mean"], 3.0)
        self.assertAlmostEqual(result["sample_standard_deviation"], 1.5811388300841898)
        self.assertLess(result["confidence_interval_95_lower"], 3.0)
        self.assertGreater(result["confidence_interval_95_upper"], 3.0)

    def test_contract_rejects_duplicate_or_unsorted_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._contract(root)
            value = yaml.safe_load(path.read_text())
            value["seeds"] = [523, 11, 523]
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(MultiSeedError, "unique and sorted"):
                load_multiseed_contract(path)

    def test_contract_rejects_overlapping_partition_retry_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = self._contract(root)
            value = yaml.safe_load(path.read_text())
            value["seeds"] = [11, 522]
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(MultiSeedError, "at least 512"):
                load_multiseed_contract(path)

    def test_summary_is_recomputed_from_verified_paired_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._contract(root)
            runs, dataset = self._fake_runs(root)
            output = root / "summary"
            verified = {"status": "verified", "errors": []}
            with patch(
                "fl_forensics.multiseed.verify_partitions", return_value=verified
            ), patch(
                "fl_forensics.multiseed.verify_federated_baseline",
                return_value=verified,
            ):
                result = create_multiseed_summary(
                    runs_workspace=runs,
                    dataset_workspace=dataset,
                    output=output,
                    config_path=config,
                )
                self.assertEqual(result["run_count"], 4)
                summary = json.loads((output / "summary.json").read_text())
                self.assertEqual(summary["seed_count"], 2)
                self.assertAlmostEqual(
                    summary["mode_summaries"]["iid"]["test_macro_f1"]["mean"],
                    0.755,
                )
                self.assertAlmostEqual(
                    summary["paired_comparison"][
                        "test_macro_f1_non_iid_minus_iid"
                    ]["mean"],
                    0.02,
                )
                verification = verify_multiseed_summary(
                    runs_workspace=runs,
                    dataset_workspace=dataset,
                    workspace=output,
                    config_path=config,
                )
                self.assertEqual(verification["status"], "verified")

                metrics = runs / "seed-11" / "iid" / "run" / "metrics.json"
                metrics.write_bytes(metrics.read_bytes() + b" ")
                tampered = verify_multiseed_summary(
                    runs_workspace=runs,
                    dataset_workspace=dataset,
                    workspace=output,
                    config_path=config,
                )
                self.assertEqual(tampered["status"], "failed")
                self.assertIn("metrics digest mismatch", tampered["errors"][0])


if __name__ == "__main__":
    unittest.main()
