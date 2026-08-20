from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m5_local_diagnostics_script", ROOT / "scripts" / "m5_local_diagnostics.py"
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load scripts/m5_local_diagnostics.py")
M5_DIAGNOSTICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M5_DIAGNOSTICS)


@unittest.skipUnless(
    all(importlib.util.find_spec(name) for name in ("matplotlib", "numpy")),
    "optional reporting dependencies are not installed",
)
class M5LocalDiagnosticTests(unittest.TestCase):
    def _workspace(self, root: Path) -> Path:
        workspace = root / "campaign"
        labels = ["benign", "attack"]
        for index in range(1, 3):
            client_id = f"client{index:02d}"
            history = []
            for epoch in range(1, 3):
                split_metrics = {
                    "row_count": 4,
                    "observed_labels": labels,
                    "observed_class_count": 2,
                    "loss": 0.8 - epoch * 0.1 + index * 0.01,
                    "accuracy": 0.5 + epoch * 0.1,
                    "balanced_accuracy_observed_classes": 0.5 + epoch * 0.1,
                    "macro_precision_all_model_classes": 0.5 + epoch * 0.1,
                    "macro_recall_all_model_classes": 0.5 + epoch * 0.1,
                    "macro_f1_all_model_classes": 0.5 + epoch * 0.1,
                    "per_class": {
                        "benign": {
                            "precision": 0.6,
                            "recall": 0.5,
                            "f1": 0.55,
                            "support": 2,
                        },
                        "attack": {
                            "precision": 0.7,
                            "recall": 0.5,
                            "f1": 0.58,
                            "support": 2,
                        },
                    },
                    "confusion_matrix": {
                        "labels": labels,
                        "values": [[1, 1], [1, 1]],
                    },
                }
                history.append(
                    {
                        "epoch": epoch,
                        "optimizer_train_loss": split_metrics["loss"],
                        "train": split_metrics,
                        "validation": split_metrics,
                    }
                )
            metrics = {
                "schema_version": "2.0",
                "artifact_type": "secure_local_training_metrics",
                "client_id": client_id,
                "context_id": "round-context-test",
                "train_loss": 0.75,
                "num_examples": 4,
                "validation_num_examples": 4,
                "optimizer_steps": 2,
                "epochs": 2,
                "history": history,
                "final": {
                    "train": history[-1]["train"],
                    "validation": history[-1]["validation"],
                },
                "update_delta_l2": 0.1 * index,
            }
            submission = workspace / "submissions" / client_id
            submission.mkdir(parents=True)
            metrics_path = submission / "metrics.json"
            metrics_path.write_bytes(derived_json_bytes(metrics))
            bundle = {
                "core": {
                    "client_id": client_id,
                    "metrics_sha256": sha256_file(metrics_path),
                }
            }
            (submission / "bundle.json").write_bytes(derived_json_bytes(bundle))
            decision = {
                "core": {
                    "client_id": client_id,
                    "status": "accepted",
                    "checks": [{"name": "test", "passed": True, "detail": "ok"}],
                }
            }
            decision_path = workspace / "decisions" / f"{client_id}.json"
            decision_path.parent.mkdir(parents=True, exist_ok=True)
            decision_path.write_bytes(derived_json_bytes(decision))
        return workspace

    def test_report_uses_digest_bound_local_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self._workspace(root)
            output = root / "report"
            with patch.object(
                M5_DIAGNOSTICS,
                "verify_secure_round",
                return_value={
                    "status": "verified",
                    "accepted_count": 15,
                    "matches_reference_checkpoint": True,
                    "error_count": 0,
                    "errors": [],
                },
            ):
                result = M5_DIAGNOSTICS.generate_report(
                    workspace=workspace,
                    trust_workspace=root / "trust",
                    output=output,
                )

            self.assertEqual(result["status"], "reported")
            self.assertEqual(result["client_count"], 2)
            self.assertEqual(result["epochs"], 2)
            self.assertEqual(result["figure_count"], 5)
            summary = json.loads((output / "summary.json").read_text())
            self.assertFalse(summary["test_data_observed"])
            self.assertEqual(len(summary["clients"]), 2)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(
                manifest["artifacts"]["summary.json"],
                sha256_file(output / "summary.json"),
            )
            self.assertTrue((output / "local-loss-curves.png").is_file())
            self.assertTrue(
                (output / "local-validation-confusion-matrices.png").is_file()
            )

    def test_metrics_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self._workspace(root)
            metrics_path = workspace / "submissions" / "client01" / "metrics.json"
            with metrics_path.open("ab") as stream:
                stream.write(b"\n")
            with patch.object(
                M5_DIAGNOSTICS,
                "verify_secure_round",
                return_value={
                    "status": "verified",
                    "accepted_count": 15,
                    "matches_reference_checkpoint": True,
                    "error_count": 0,
                    "errors": [],
                },
            ), self.assertRaisesRegex(ValueError, "signed metrics digest mismatch"):
                M5_DIAGNOSTICS.generate_report(
                    workspace=workspace,
                    trust_workspace=root / "trust",
                    output=root / "report",
                )

    def test_failed_secure_round_verification_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self._workspace(root)
            with patch.object(
                M5_DIAGNOSTICS,
                "verify_secure_round",
                return_value={"status": "failed", "errors": ["invalid signature"]},
            ), self.assertRaisesRegex(ValueError, "must verify"):
                M5_DIAGNOSTICS.generate_report(
                    workspace=workspace,
                    trust_workspace=root / "trust",
                    output=root / "report",
                )


if __name__ == "__main__":
    unittest.main()
