from __future__ import annotations

import unittest

from fl_forensics.federated_training import (
    _benign_false_alarm_summary,
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


if __name__ == "__main__":
    unittest.main()
