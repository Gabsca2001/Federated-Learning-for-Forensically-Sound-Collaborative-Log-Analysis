from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.reporting import generate_m3_report


CLASSES = ["benign", "discovery", "multi_tactic"]


def _evaluation(scale: float = 1.0) -> dict[str, object]:
    return {
        "row_count": 12,
        "observed_labels": CLASSES,
        "observed_class_count": 3,
        "loss": 0.4,
        "accuracy": 0.75,
        "balanced_accuracy_observed_classes": 0.75,
        "macro_precision_all_model_classes": 0.72 * scale,
        "macro_recall_all_model_classes": 0.71 * scale,
        "macro_f1_all_model_classes": 0.70 * scale,
        "per_class": {
            "benign": {"precision": 0.8, "recall": 0.9, "f1": 0.85, "support": 5},
            "discovery": {"precision": 0.7, "recall": 0.6, "f1": 0.65, "support": 4},
            "multi_tactic": {"precision": 0.5, "recall": 0.67, "f1": 0.57, "support": 3},
        },
        "confusion_matrix": {
            "labels": CLASSES,
            "values": [[4, 1, 0], [1, 2, 1], [0, 1, 2]],
        },
    }


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(derived_json_bytes(value))


def _build_workspace(root: Path) -> tuple[Path, Path]:
    workspace = root / "m3"
    rounds = []
    for number, factor in ((1, 0.9), (2, 1.0), (3, 0.98)):
        rounds.append(
            {
                "round": number,
                "global_model_sha256": f"model-{number}",
                "weighted_training_loss": 1.0 / number,
                "validation": _evaluation(factor),
            }
        )
    selected = {
        "round": 2,
        "model_sha256": "model-2",
        "validation": rounds[1]["validation"],
        "test": _evaluation(1.0),
        "temporal_holdout": _evaluation(0.5),
    }
    metrics = {
        "schema_version": "2.0",
        "artifact_type": "m3_fedavg_metrics",
        "dataset": "UWF-ZeekData24",
        "partition_mode": "iid",
        "rounds": rounds,
        "final": rounds[-1],
        "selected": selected,
        "interpretation_constraints": [],
    }
    clients = [
        {
            "client_id": f"client{number:02d}",
            "global_test": {
                **_evaluation(0.8 + number / 100),
                "macro_f1_all_model_classes": 0.60 + number / 100,
            },
        }
        for number in range(1, 4)
    ]
    comparison = {
        "schema_version": "2.0",
        "artifact_type": "m3_local_fedavg_comparison",
        "fedavg_selected": selected,
        "selected_global_client_validation": [
            {
                "client_id": f"client{number:02d}",
                "validation": {
                    **_evaluation(0.8 + number / 100),
                    "macro_f1_all_model_classes": 0.60 + number / 100,
                },
            }
            for number in range(1, 4)
        ],
        "local_only_clients": clients,
        "local_only_summary": {
            "global_test_macro_f1": {
                "client_count": 3,
                "mean": 0.62,
                "population_stddev": 0.01,
                "minimum": 0.61,
                "maximum": 0.63,
            }
        },
    }
    _write(workspace / "metrics.json", metrics)
    _write(workspace / "comparison.json", comparison)
    _write(
        workspace / "manifest.json",
        {
            "schema_version": "2.0",
            "artifact_type": "m3_fedavg_run_manifest",
            "dataset": "UWF-ZeekData24",
            "partition_mode": "iid",
            "metrics_sha256": sha256_file(workspace / "metrics.json"),
            "comparison_sha256": sha256_file(workspace / "comparison.json"),
        },
    )

    central = root / "central"
    _write(
        central / "metrics.json",
        {
            "schema_version": "1.0",
            "artifact_type": "centralized_baseline_metrics",
            "dataset": "UWF-ZeekData24",
            "metrics": {"test": _evaluation(1.02)},
        },
    )
    _write(
        central / "manifest.json",
        {
            "schema_version": "1.0",
            "dataset": "UWF-ZeekData24",
            "metrics_sha256": sha256_file(central / "metrics.json"),
        },
    )
    return workspace, central


class ReportingTests(unittest.TestCase):
    def test_report_is_complete_and_repeatable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace, central = _build_workspace(Path(temporary))
            first = generate_m3_report(
                workspace=workspace, central_workspace=central
            )
            first_summary_digest = sha256_file(workspace / "reports" / "summary.json")
            second = generate_m3_report(
                workspace=workspace, central_workspace=central
            )
            self.assertEqual(first["status"], "reported")
            self.assertEqual(first["figure_count"], 8)
            self.assertEqual(first["best_validation_round"], 2)
            self.assertEqual(first["selected_round"], 2)
            self.assertEqual(first_summary_digest, second["summary_sha256"])
            summary = json.loads((workspace / "reports" / "summary.json").read_text())
            self.assertEqual(len(summary["figures"]), 8)
            self.assertEqual(summary["metrics"]["selected_round"], 2)
            for figure in summary["figures"]:
                path = workspace / "reports" / figure["path"]
                self.assertTrue(path.is_file())
                self.assertEqual(sha256_file(path), figure["sha256"])

    def test_metrics_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace, _central = _build_workspace(Path(temporary))
            with (workspace / "metrics.json").open("ab") as stream:
                stream.write(b" ")
            with self.assertRaisesRegex(ValueError, "metrics digest"):
                generate_m3_report(workspace=workspace)


if __name__ == "__main__":
    unittest.main()
