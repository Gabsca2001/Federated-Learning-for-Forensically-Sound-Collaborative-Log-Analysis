from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m2_diagnostics_script", ROOT / "scripts" / "m2_diagnostics.py"
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load scripts/m2_diagnostics.py")
M2_DIAGNOSTICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M2_DIAGNOSTICS)


class _FakeModel:
    def __init__(self, np: object) -> None:
        self.classes_ = np.asarray(["benign", "exfiltration"], dtype=str)

    def predict(self, _features: object) -> object:
        import numpy as np

        return np.asarray(["exfiltration", "exfiltration"], dtype=str)

    def predict_proba(self, _features: object) -> object:
        import numpy as np

        return np.asarray([[0.2, 0.8], [0.1, 0.9]], dtype=float)


class M2DiagnosticHelperTests(unittest.TestCase):
    @unittest.skipUnless(
        importlib.util.find_spec("numpy"),
        "optional M2 numerical dependencies are not installed",
    )
    def test_misclassification_export_preserves_traceability(self) -> None:
        import numpy as np

        rows = [
            {
                "window_id": "window-1",
                "capture_id": "capture-1",
                "features": [1.5, 2.5],
                "observed_labels": ["benign"],
                "source_event_ids": ["event-1", "event-2"],
            },
            {
                "window_id": "window-2",
                "capture_id": "capture-1",
                "features": [3.5, 4.5],
                "observed_labels": ["exfiltration"],
                "source_event_ids": ["event-3"],
            },
        ]
        records = M2_DIAGNOSTICS._misclassification_records(
            model=_FakeModel(np),
            split="validation",
            rows=rows,
            features=np.zeros((2, 2), dtype=float),
            labels=np.asarray(["benign", "exfiltration"], dtype=str),
            feature_names=["feature_a", "feature_b"],
            selected_epoch=7,
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["window_id"], "window-1")
        self.assertEqual(record["source_event_ids"], ["event-1", "event-2"])
        self.assertEqual(record["feature_values"], {"feature_a": 1.5, "feature_b": 2.5})
        self.assertEqual(record["true_label"], "benign")
        self.assertEqual(record["predicted_label"], "exfiltration")
        self.assertAlmostEqual(record["confidence_margin"], 0.6)


@unittest.skipUnless(
    all(
        importlib.util.find_spec(name)
        for name in ("matplotlib", "numpy", "sklearn")
    ),
    "optional M2 diagnostic dependencies are not installed",
)
class M2DiagnosticIntegrationTests(unittest.TestCase):
    def test_best_validation_loss_checkpoint_is_exported_and_evaluated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dataset_workspace = root / "dataset"
            dataset_workspace.mkdir()
            rows = []
            split_sizes = {"train": 8, "validation": 4, "test": 4}
            for split, size in split_sizes.items():
                for index in range(size):
                    label = "benign" if index % 2 == 0 else "exfiltration"
                    rows.append(
                        {
                            "window_id": f"{split}-window-{index}",
                            "capture_id": f"{split}-capture",
                            "features": [0.0, 0.0],
                            "label": label,
                            "observed_labels": [label],
                            "source_event_ids": [f"{split}-event-{index}"],
                            "split": split,
                            "window_start_epoch": index * 60,
                            "window_end_epoch": (index + 1) * 60,
                        }
                    )
            rows.append(
                {
                    "window_id": "holdout-window-0",
                    "capture_id": "holdout-capture",
                    "features": [0.0, 0.0],
                    "label": "benign",
                    "observed_labels": ["benign"],
                    "source_event_ids": ["holdout-event-0"],
                    "split": "temporal_holdout",
                    "window_start_epoch": 0,
                    "window_end_epoch": 60,
                }
            )
            (dataset_workspace / "dataset.json").write_text(
                json.dumps(
                    {
                        "dataset": "UWF-ZeekData24",
                        "feature_names": ["feature_a", "feature_b"],
                        "rows": rows,
                    }
                ),
                encoding="utf-8",
            )
            (dataset_workspace / "scaler.json").write_text(
                json.dumps({"mean": [0.0, 0.0], "scale": [1.0, 1.0]}),
                encoding="utf-8",
            )
            config_path = root / "config.yaml"
            config_path.write_text(
                """
experiment:
  seed: 123
model:
  hidden_layers: [4]
  embedding_size: 2
  activation: relu
  regularization_alpha: 0.0001
  max_iterations: 3
  class_weighting: none
federation:
  batch_size: 4
  learning_rate: 0.001
""".lstrip(),
                encoding="utf-8",
            )
            output = root / "diagnostics"
            with patch(
                "fl_forensics.dataset24.verify_workspace",
                return_value={"status": "verified", "errors": []},
            ):
                summary = M2_DIAGNOSTICS.run_diagnostics(
                    dataset_workspace=dataset_workspace,
                    config_path=config_path,
                    output=output,
                    epochs=3,
                    include_test=True,
                    class_weighting="none",
                    seed_override=123,
                )

            history = json.loads(
                (output / "training_history.json").read_text(encoding="utf-8")
            )["epochs"]
            expected_epoch = min(
                history,
                key=lambda item: item["validation_weighted_log_loss"],
            )["epoch"]
            self.assertEqual(summary["selected_checkpoint_epoch"], expected_epoch)
            self.assertEqual(
                summary["evaluated_model"],
                "best-validation-weighted-log-loss-checkpoint",
            )
            self.assertEqual(len(summary["selected_checkpoint_model_sha256"]), 64)
            self.assertEqual(
                summary["artifact_sha256"]["best_checkpoint_model.json"],
                summary["selected_checkpoint_model_sha256"],
            )
            self.assertEqual(
                summary["artifact_sha256"]["checkpoint_metrics.json"],
                summary["artifact_sha256"]["final_metrics.json"],
            )

            checkpoint = json.loads(
                (output / "best_checkpoint_model.json").read_text(encoding="utf-8")
            )
            self.assertEqual(checkpoint["selection"]["epoch"], expected_epoch)
            self.assertFalse(checkpoint["selection"]["test_observed_during_selection"])
            self.assertEqual(
                (output / "checkpoint_metrics.json").read_bytes(),
                (output / "final_metrics.json").read_bytes(),
            )

            errors = [
                json.loads(line)
                for line in (output / "misclassified_windows.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            error_summary = json.loads(
                (output / "misclassification_summary.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertGreater(len(errors), 0)
            self.assertEqual(error_summary["error_count"], len(errors))
            self.assertIn("test", error_summary["splits"])
            self.assertIn("class_probabilities", errors[0])


if __name__ == "__main__":
    unittest.main()
