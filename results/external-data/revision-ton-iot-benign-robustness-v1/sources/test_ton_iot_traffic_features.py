import unittest

import numpy as np

from fl_forensics.ton_iot_traffic_features import apply_standard, derive_features, fit_standard


class TrafficFeaturesTests(unittest.TestCase):
    def sample(self):
        x = np.zeros((2, 25))
        x[:, 0] = [2, 4]
        x[:, 1:3] = [[1, 2], [2, 4]]
        x[:, 3:6] = [1, 2, 3]
        x[:, 6:10] = [[100, 200, 10, 20], [200, 400, 20, 40]]
        x[:, 10] = 1
        return x

    def test_rates_remove_uniform_count_and_volume_scaling(self):
        rates, names = derive_features(self.sample(), "rates")
        self.assertEqual(rates.shape, (2, 26))
        self.assertEqual(len(set(names)), 26)
        np.testing.assert_array_equal(rates[0], rates[1])

    def test_zero_packet_denominators_remain_finite(self):
        x = self.sample()
        x[:, 8:10] = 0
        values, _ = derive_features(x, "rates")
        self.assertTrue(np.isfinite(values).all())

    def test_augmented_retains_volume_and_has_distinct_schema(self):
        values, names = derive_features(self.sample(), "augmented")
        self.assertEqual(values.shape, (2, 33))
        self.assertEqual(len(set(names)), 33)
        self.assertNotEqual(values[0, 0], values[1, 0])

    def test_scaler_is_fitted_only_on_training(self):
        train, _ = derive_features(self.sample(), "fractions")
        spec = fit_standard(train)
        original = dict(spec)
        test = np.full((1, 15), 1000.0)
        transformed = apply_standard(test, spec)
        self.assertEqual(spec, original)
        self.assertTrue(np.isfinite(transformed).all())

    def test_invalid_windows_are_rejected(self):
        for x in [
            np.zeros((1, 25)),
            np.full((1, 25), -1.0),
            np.full((1, 25), np.nan),
            np.ones((1, 24)),
        ]:
            with self.assertRaises(ValueError):
                derive_features(x, "rates")
