from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m2_error_analysis_script", ROOT / "scripts" / "m2_error_analysis.py"
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load scripts/m2_error_analysis.py")
M2_ERROR_ANALYSIS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M2_ERROR_ANALYSIS)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _synthetic_inputs(root: Path) -> tuple[Path, Path]:
    dataset_workspace = root / "dataset"
    diagnostics_workspace = root / "diagnostics"
    dataset_workspace.mkdir()
    diagnostics_workspace.mkdir()

    definitions = [
        ("r-correct-1", "capture-a", "reconnaissance", [0.0, 0.1, 0.0], 1),
        ("r-correct-2", "capture-a", "reconnaissance", [0.2, 0.0, 0.1], 8),
        ("r-error", "capture-b", "reconnaissance", [1.8, 2.0, 0.2], 12),
        ("m-correct-1", "capture-b", "multi_tactic", [2.0, 2.1, 0.0], 30),
        ("m-correct-2", "capture-b", "multi_tactic", [2.2, 1.9, 0.1], 120),
        ("m-error", "capture-a", "multi_tactic", [0.1, 0.2, 0.0], 4),
        ("e-correct-1", "capture-c", "exfiltration", [4.0, 0.1, 3.9], 1),
        ("e-correct-2", "capture-c", "exfiltration", [3.9, 0.0, 4.1], 6),
        ("e-error", "capture-c", "exfiltration", [2.1, 2.0, 0.0], 25),
    ]
    rows = []
    for index, (window_id, capture_id, label, features, event_count) in enumerate(
        definitions
    ):
        rows.append(
            {
                "window_id": window_id,
                "capture_id": capture_id,
                "features": features,
                "label": label,
                "observed_labels": [label],
                "source_event_ids": [
                    f"{window_id}-event-{event}" for event in range(event_count)
                ],
                "split": "test",
                "window_start_epoch": index * 60,
                "window_end_epoch": (index + 1) * 60,
            }
        )
    _write_json(
        dataset_workspace / "dataset.json",
        {
            "dataset": "UWF-ZeekData24",
            "feature_names": ["feature_a", "feature_b", "feature_c"],
            "rows": rows,
        },
    )
    _write_json(
        dataset_workspace / "scaler.json",
        {"mean": [1.0, 1.0, 1.0], "scale": [1.0, 1.0, 1.0]},
    )

    by_id = {row["window_id"]: row for row in rows}
    errors = [
        ("r-error", "multi_tactic", 0.70),
        ("m-error", "reconnaissance", 0.60),
        ("e-error", "multi_tactic", 0.80),
    ]
    records = []
    for window_id, predicted_label, margin in errors:
        row = by_id[window_id]
        records.append(
            {
                "selection_epoch": 7,
                "split": "test",
                "window_id": window_id,
                "capture_id": row["capture_id"],
                "true_label": row["label"],
                "predicted_label": predicted_label,
                "confidence_margin": margin,
                "observed_labels": row["observed_labels"],
                "source_event_count": len(row["source_event_ids"]),
            }
        )
    errors_path = diagnostics_workspace / "misclassified_windows.jsonl"
    errors_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    error_summary_path = diagnostics_workspace / "misclassification_summary.json"
    _write_json(
        error_summary_path,
        {
            "selection_epoch": 7,
            "error_count": len(records),
            "splits": {
                "test": {
                    "row_count": len(rows),
                    "error_count": len(records),
                    "error_rate": len(records) / len(rows),
                }
            },
        },
    )
    _write_json(
        diagnostics_workspace / "summary.json",
        {
            "dataset": "UWF-ZeekData24",
            "evaluated_model": "best-validation-weighted-log-loss-checkpoint",
            "selected_checkpoint_epoch": 7,
            "artifact_sha256": {
                "misclassified_windows.jsonl": _sha256(errors_path),
                "misclassification_summary.json": _sha256(error_summary_path),
            },
        },
    )
    return dataset_workspace, diagnostics_workspace


@unittest.skipUnless(
    all(
        importlib.util.find_spec(name)
        for name in ("matplotlib", "numpy", "sklearn")
    ),
    "optional M2 analysis dependencies are not installed",
)
class M2ErrorAnalysisTests(unittest.TestCase):
    def test_analysis_is_traceable_and_generates_explanatory_plots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dataset_workspace, diagnostics_workspace = _synthetic_inputs(root)
            output = root / "analysis"
            with patch(
                "fl_forensics.dataset24.verify_workspace",
                return_value={"status": "verified", "errors": []},
            ):
                summary = M2_ERROR_ANALYSIS.run_error_analysis(
                    dataset_workspace=dataset_workspace,
                    diagnostics_workspace=diagnostics_workspace,
                    output=output,
                    split="test",
                )

            self.assertEqual(summary["error_count"], 3)
            self.assertEqual(
                summary["dominant_bidirectional_pair"],
                ["multi_tactic", "reconnaissance"],
            )
            self.assertFalse(summary["observed_labels_used_as_features"])
            self.assertEqual(summary["pca"]["status"], "analyzed")
            self.assertEqual(len(summary["pca"]["explained_variance_ratio"]), 2)

            required_plots = {
                "capture_error_rates.png",
                "event_bucket_error_rates.png",
                "transition_counts.png",
                "error_confidence_margins.png",
                "feature_profile_main_transition.png",
                "feature_confusion_heatmap.png",
                "pca_main_confusion.png",
            }
            self.assertTrue(required_plots.issubset(summary["artifact_sha256"]))
            for name in required_plots:
                self.assertTrue((output / name).is_file())
                self.assertEqual(len(summary["artifact_sha256"][name]), 64)

            feature_analysis = json.loads(
                (output / "feature_transition_analysis.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(feature_analysis["observed_labels_used_as_features"])
            self.assertEqual(feature_analysis["transitions"][0]["status"], "analyzed")

    def test_tampered_diagnostic_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dataset_workspace, diagnostics_workspace = _synthetic_inputs(root)
            with (diagnostics_workspace / "misclassified_windows.jsonl").open(
                "a", encoding="utf-8"
            ) as stream:
                stream.write("{}\n")
            with patch(
                "fl_forensics.dataset24.verify_workspace",
                return_value={"status": "verified", "errors": []},
            ):
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    M2_ERROR_ANALYSIS.run_error_analysis(
                        dataset_workspace=dataset_workspace,
                        diagnostics_workspace=diagnostics_workspace,
                        output=root / "analysis",
                        split="test",
                    )


if __name__ == "__main__":
    unittest.main()
