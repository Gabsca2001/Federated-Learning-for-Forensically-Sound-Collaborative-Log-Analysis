import unittest

import numpy as np

from fl_forensics.ton_iot_margin import center_validation_plateau


class MarginTests(unittest.TestCase):
    def test_centers_gap_and_keeps_all_validation_decisions(self):
        score = np.array([0.1, 0.2, 0.8, 0.9])
        fitted = center_validation_plateau(score, 0.2)
        self.assertEqual(fitted["threshold"], 0.5)
        np.testing.assert_array_equal(score > 0.2, score > fitted["threshold"])

    def test_equal_scores_cannot_be_split(self):
        score = np.array([0.2, 0.2, 0.8, 0.8])
        fitted = center_validation_plateau(score, 0.2)
        np.testing.assert_array_equal(score > 0.2, score > fitted["threshold"])

    def test_adjacent_float32_scores_use_float64_comparison(self):
        low = np.float32(0.5)
        high = np.nextafter(low, np.float32(1.0))
        fitted = center_validation_plateau(np.array([low, high]), float(low))
        self.assertGreater(fitted["threshold"], float(low))
        self.assertLess(fitted["threshold"], float(high))
        np.testing.assert_array_equal(
            np.array([low, high], dtype=np.float64) > fitted["threshold"], [False, True]
        )

    def test_one_sided_predictions_keep_threshold(self):
        self.assertFalse(center_validation_plateau([0.8, 0.9], 0.2)["changed"])
        self.assertFalse(center_validation_plateau([0.1, 0.2], 0.9)["changed"])

    def test_invalid_scores_and_thresholds_are_rejected(self):
        for score, threshold in [
            ([], 0),
            ([float("nan")], 0.5),
            ([1.1], 0.5),
            ([[0.2]], 0.5),
            ([0.2], float("nan")),
        ]:
            with self.assertRaises(ValueError):
                center_validation_plateau(score, threshold)
