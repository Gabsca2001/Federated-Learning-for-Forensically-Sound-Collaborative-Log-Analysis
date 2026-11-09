import unittest

import numpy as np

from fl_forensics.ton_iot_novelty import (
    anomaly_flags,
    calibrate_benign_threshold,
    combine_flags,
    minute_alert_support,
)


class NoveltyRulesTests(unittest.TestCase):
    def test_finite_calibration_budget_uses_integer_false_alert_count(self):
        fitted = calibrate_benign_threshold(np.arange(101), 0.01)
        self.assertEqual(fitted["allowed_false_alerts"], 1)
        self.assertEqual(fitted["observed_false_alerts"], 1)
        self.assertLessEqual(fitted["observed_false_positive_rate"], 0.01)

    def test_tied_scores_cannot_be_split_to_meet_a_budget(self):
        fitted = calibrate_benign_threshold([0, 1, 1, 1], 0.5)
        self.assertEqual(fitted["threshold"], 1)
        self.assertEqual(fitted["observed_false_alerts"], 0)

    def test_zero_budget_is_calibration_maximum(self):
        fitted = calibrate_benign_threshold([-3, -1, 2], 0)
        self.assertEqual(fitted["threshold"], 2)
        self.assertEqual(fitted["observed_false_alerts"], 0)

    def test_invalid_calibration_inputs_are_rejected(self):
        for scores, budget in [([], 0.01), ([np.nan], 0.01), ([1], 1), ([1], -0.1), ([[1]], 0.01)]:
            with self.assertRaises(ValueError):
                calibrate_benign_threshold(scores, budget)

    def test_strict_comparison_preserves_float32_boundary(self):
        low = np.float32(0.5)
        high = np.nextafter(low, np.float32(1))
        middle = (float(low) + float(high)) / 2
        np.testing.assert_array_equal(anomaly_flags([low, high], middle), [False, True])

    def test_combination_is_or_and_rejects_probability_vectors(self):
        np.testing.assert_array_equal(combine_flags([0, 1, 0], [1, 0, 0]), [True, True, False])
        with self.assertRaises(ValueError):
            combine_flags([0.1], [1])

    def test_benign_alert_does_not_count_as_detection_of_attacked_host(self):
        result = minute_alert_support([1, 1], [1, 0], [0, 1])
        self.assertTrue(result["any_alert"][0])
        self.assertFalse(result["attacked_host_alert"][0])
        self.assertTrue(result["benign_host_only_coincidence"][0])

    def test_supported_detection_and_normal_minute_false_alert_are_distinct(self):
        result = minute_alert_support([1, 1, 2], [1, 0, 0], [1, 0, 1])
        np.testing.assert_array_equal(result["attacked_host_alert"], [True, False])
        np.testing.assert_array_equal(result["any_alert"], [True, True])
        np.testing.assert_array_equal(result["benign_host_only_coincidence"], [False, False])
