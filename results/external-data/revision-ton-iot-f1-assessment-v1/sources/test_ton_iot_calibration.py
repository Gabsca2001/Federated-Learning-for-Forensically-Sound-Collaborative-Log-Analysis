import unittest

import numpy as np

from fl_forensics.ton_iot_calibration import fit_macro_threshold, metrics


class CalibrationTests(unittest.TestCase):
    def test_macro_objective_matches_exhaustive_validation_search(self):
        y = np.array([0, 0, 0, 1, 1, 1])
        score = np.array([0.1, 0.4, 0.5, 0.3, 0.7, 0.9])
        result = fit_macro_threshold(y, score)
        candidates = [metrics(y, score, t) for t in [-1, *np.unique(score)]]
        best = max(
            candidates,
            key=lambda r: (r["macro_f1"], -r["confusion_matrix"]["values"][0][1], r["threshold"]),
        )
        self.assertEqual(result["threshold"], best["threshold"])
        self.assertEqual(result["validation"]["macro_f1"], best["macro_f1"])

    def test_equal_scores_are_not_split_using_ground_truth(self):
        result = fit_macro_threshold([0, 1], [0.7, 0.7])
        matrix = result["validation"]["confusion_matrix"]["values"]
        self.assertIn(matrix, ([[1, 0], [1, 0]], [[0, 1], [0, 1]]))

    def test_high_attack_f1_does_not_hide_benign_failure(self):
        result = metrics([0] * 30 + [1] * 688, [1.0] * 718)
        self.assertGreater(result["attack_f1"], 0.97)
        self.assertEqual(result["benign_f1"], 0)
        self.assertLess(result["macro_f1"], 0.5)
        self.assertFalse(result["f1_goal_met"])

    def test_threshold_is_fitted_only_to_supplied_validation(self):
        fit = fit_macro_threshold([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
        expected = fit["threshold"]
        metrics([1, 0], [0.01, 0.99], expected)
        self.assertEqual(fit["threshold"], expected)
        self.assertEqual(fit["fit_scope"], "Corrected validation only")

    def test_bad_scores_labels_or_single_class_are_rejected(self):
        for labels, score in [
            ([0, 1], [0.1, float("nan")]),
            ([0, 1], [-0.1, 0.2]),
            ([0, 1], [0.1, 1.1]),
            ([0, 0], [0.1, 0.2]),
            ([0.5, 1], [0.1, 0.2]),
        ]:
            with self.assertRaises(ValueError):
                fit_macro_threshold(labels, score)

    def test_strict_threshold_rule_handles_zero_and_one(self):
        result = fit_macro_threshold([0, 1], [0.0, 1.0])
        self.assertEqual(result["validation"]["macro_f1"], 1)
        self.assertEqual(
            metrics([0, 1], [0.0, 1.0], result["threshold"])["confusion_matrix"]["values"],
            [[1, 0], [0, 1]],
        )
