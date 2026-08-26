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
    "m5_campaign_report_script", ROOT / "scripts" / "m5_campaign_report.py"
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("unable to load scripts/m5_campaign_report.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class M5CampaignReportTests(unittest.TestCase):
    @staticmethod
    def _evaluation(score: float) -> dict:
        return {
            "row_count": 4,
            "loss": 1.0 - score,
            "macro_f1_all_model_classes": score,
            "per_class": {
                "benign": {"f1": score, "support": 2},
                "attack": {"f1": max(0.0, score - 0.1), "support": 2},
            },
            "confusion_matrix": {
                "labels": ["benign", "attack"],
                "values": [[2, 0], [1, 1]],
            },
        }

    def _workspace(self, root: Path) -> Path:
        workspace = root / "campaign"
        references = []
        for round_number, global_score in ((1, 0.60), (2, 0.75)):
            validation = {
                "schema_version": "1.0",
                "artifact_type": "secure_round_validation_metrics",
                "round_number": round_number,
                "validation": self._evaluation(global_score),
            }
            validation_path = workspace / "evaluation" / f"round-{round_number:03d}-validation.json"
            validation_path.parent.mkdir(parents=True, exist_ok=True)
            validation_path.write_bytes(derived_json_bytes(validation))
            references.append(
                {
                    "round_number": round_number,
                    "validation_metrics_sha256": sha256_file(validation_path),
                }
            )
            for client_index in range(1, 3):
                client_id = f"client{client_index:02d}"
                history = []
                for epoch in range(1, 3):
                    train_score = 0.4 + 0.1 * round_number + 0.02 * epoch
                    validation_score = train_score - 0.03
                    history.append(
                        {
                            "epoch": epoch,
                            "optimizer_train_loss": 1.0 - train_score,
                            "train": self._evaluation(train_score),
                            "validation": self._evaluation(validation_score),
                        }
                    )
                metrics = {
                    "schema_version": "2.0",
                    "client_id": client_id,
                    "epochs": 2,
                    "history": history,
                    "update_delta_l2": round_number * client_index * 0.1,
                }
                submission = (
                    workspace / "rounds" / f"round-{round_number:03d}" / "submissions" / client_id
                )
                submission.mkdir(parents=True, exist_ok=True)
                metrics_path = submission / "metrics.json"
                metrics_path.write_bytes(derived_json_bytes(metrics))
                bundle = {
                    "core": {
                        "client_id": client_id,
                        "metrics_sha256": sha256_file(metrics_path),
                    }
                }
                (submission / "bundle.json").write_bytes(derived_json_bytes(bundle))
        final = {
            "selected_round": 2,
            "metrics": {
                split: self._evaluation(score)
                for split, score in (
                    ("validation", 0.75),
                    ("test", 0.73),
                    ("temporal_holdout", 0.90),
                )
            },
            "selected_global_client_test": [
                {
                    "client_id": f"client{client_index:02d}",
                    "test": self._evaluation(0.70 + client_index / 100),
                }
                for client_index in range(1, 3)
            ],
        }
        (workspace / "evaluation" / "selected-checkpoint-evaluation.json").write_bytes(
            derived_json_bytes(final)
        )
        manifest = {
            "core": {
                "round_count": 2,
                "required_client_count": 2,
                "total_accepted_contributions": 4,
                "selected_round": 2,
                "rounds": references,
            }
        }
        (workspace / "campaign-manifest.json").write_bytes(derived_json_bytes(manifest))
        return workspace

    def test_verified_campaign_generates_learning_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self._workspace(root)
            output = root / "report"
            with patch.object(
                REPORT,
                "verify_secure_campaign",
                return_value={
                    "status": "verified",
                    "round_count": 2,
                    "accepted_contribution_count": 4,
                    "errors": [],
                },
            ):
                result = REPORT.generate_report(
                    workspace=workspace,
                    trust_workspace=root / "trust",
                    partition_manifest_path=root / "partition.json",
                    server_evaluation_path=root / "evaluation.json",
                    output=output,
                )
            self.assertEqual(result["status"], "reported")
            self.assertEqual(result["selected_round"], 2)
            self.assertEqual(result["figure_count"], 10)
            self.assertEqual(result["client_confusion_matrix_figure_count"], 2)
            self.assertEqual(result["confusion_matrices"]["test"]["values"], [[2, 0], [1, 1]])
            self.assertTrue((output / "global-validation-by-round.png").is_file())
            self.assertTrue((output / "selected-validation-test-confusion-absolute.png").is_file())
            self.assertTrue((output / "per-client-confusion" / "client01.png").is_file())
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["accepted_contribution_count"], 4)
            self.assertEqual(
                set(summary["confusion_matrices"]),
                {"validation", "test", "temporal_holdout"},
            )
            report_manifest = json.loads((output / "manifest.json").read_text())
            self.assertIn("per-client-confusion/client01.png", report_manifest["artifacts"])
            self.assertEqual(
                summary["test_selection_policy"],
                "validation-only selection; selected checkpoint test once",
            )

    def test_unsigned_metrics_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self._workspace(root)
            path = workspace / "rounds" / "round-001" / "submissions" / "client01" / "metrics.json"
            with path.open("ab") as stream:
                stream.write(b"\n")
            with (
                patch.object(
                    REPORT,
                    "verify_secure_campaign",
                    return_value={"status": "verified", "errors": []},
                ),
                self.assertRaisesRegex(ValueError, "signed metrics mismatch"),
            ):
                REPORT.generate_report(
                    workspace=workspace,
                    trust_workspace=root / "trust",
                    partition_manifest_path=root / "partition.json",
                    server_evaluation_path=root / "evaluation.json",
                    output=root / "report",
                )


if __name__ == "__main__":
    unittest.main()
