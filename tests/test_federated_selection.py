from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fl_forensics.federated_training import (
    _benign_false_alarm_summary,
    _load_client_local_tests,
    _load_server_split,
    _select_validation_checkpoint,
)


class FederatedCheckpointSelectionTests(unittest.TestCase):
    def test_highest_validation_macro_f1_is_selected(self) -> None:
        rounds = [
            {
                "round": 1,
                "validation": {"macro_f1_all_model_classes": 0.81},
            },
            {
                "round": 2,
                "validation": {"macro_f1_all_model_classes": 0.88},
            },
            {
                "round": 3,
                "validation": {"macro_f1_all_model_classes": 0.84},
            },
        ]

        self.assertEqual(_select_validation_checkpoint(rounds)["round"], 2)

    def test_equal_validation_scores_choose_the_earliest_round(self) -> None:
        rounds = [
            {
                "round": 4,
                "validation": {"macro_f1_all_model_classes": 0.91},
            },
            {
                "round": 7,
                "validation": {"macro_f1_all_model_classes": 0.91},
            },
        ]

        self.assertEqual(_select_validation_checkpoint(rounds)["round"], 4)

    def test_benign_false_alarm_rate_uses_the_benign_matrix_row(self) -> None:
        evaluation = {
            "confusion_matrix": {
                "labels": ["attack", "benign", "other"],
                "values": [[5, 0, 0], [2, 96, 2], [0, 0, 4]],
            }
        }

        result = _benign_false_alarm_summary(evaluation)

        self.assertEqual(result["actual_benign_count"], 100)
        self.assertEqual(result["false_alarm_count"], 4)
        self.assertAlmostEqual(result["false_alarm_rate"], 0.04)

    def test_local_tests_are_loaded_from_separate_evaluation_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            relative = Path("evaluation/clients/client01/test.json")
            target = workspace / relative
            target.parent.mkdir(parents=True)
            target.write_text(
                json.dumps(
                    {
                        "client_id": "client01",
                        "rows": {"test": [{"window_id": "test-1"}]},
                    }
                ),
                encoding="utf-8",
            )
            manifest = {
                "clients": [
                    {
                        "client_id": "client01",
                        "local_test_path": relative.as_posix(),
                    }
                ]
            }

            loaded = _load_client_local_tests(workspace, manifest)

            self.assertEqual(loaded[0][1]["rows"]["test"][0]["window_id"], "test-1")

    def test_validation_can_be_loaded_without_opening_a_test_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            relative = Path("server/splits/validation.json")
            target = workspace / relative
            target.parent.mkdir(parents=True)
            target.write_text(
                json.dumps(
                    {
                        "split": "validation",
                        "rows": {"validation": [{"window_id": "validation-1"}]},
                    }
                ),
                encoding="utf-8",
            )
            manifest = {
                "server_evaluation_splits": {
                    "validation": {"path": relative.as_posix()},
                    "test": {"path": "server/splits/missing-test.json"},
                    "temporal_holdout": {"path": "server/splits/missing-holdout.json"},
                }
            }

            rows = _load_server_split(workspace, manifest, "validation")

            self.assertEqual(rows, [{"window_id": "validation-1"}])

    def test_server_split_path_traversal_is_rejected(self) -> None:
        manifest = {
            "server_evaluation_splits": {
                "test": {"path": "server/splits/../../clients/client01/dataset.json"}
            }
        }

        with self.assertRaisesRegex(ValueError, "escapes split boundary"):
            _load_server_split(Path("workspace"), manifest, "test")


if __name__ == "__main__":
    unittest.main()
