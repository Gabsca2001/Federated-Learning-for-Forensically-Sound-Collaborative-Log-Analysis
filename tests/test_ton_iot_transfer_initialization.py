import unittest

import numpy as np

from fl_forensics.robust_preprocessing import apply_feature_transform, fit_feature_transform
from fl_forensics.ton_iot_transfer_initialization import initialize_target_encoder


class TransferInitializationTests(unittest.TestCase):
    def models(self):
        encoder = [
            np.ones((4, 3)),
            np.ones(4),
            np.ones((3, 4)),
            np.ones(3),
            np.ones((2, 3)),
            np.ones(2),
        ]
        source = [v.copy() for v in encoder] + [np.ones((6, 2)), np.ones(6)]
        target = [np.zeros_like(v) for v in encoder] + [np.full((2, 2), 7.0), np.full(2, 8.0)]
        return source, target

    def test_source_encoder_and_new_binary_head_remain_separate(self):
        source, target = self.models()
        result = initialize_target_encoder(source, target)
        for expected, actual in zip(source[:6], result[:6]):
            np.testing.assert_array_equal(expected, actual)
        for expected, actual in zip(target[-2:], result[-2:]):
            np.testing.assert_array_equal(expected, actual)

    def test_initialization_does_not_alias_or_modify_original_artifacts(self):
        source, target = self.models()
        result = initialize_target_encoder(source, target)
        result[0][0, 0] = 99
        result[-1][0] = 99
        self.assertEqual(source[0][0, 0], 1)
        self.assertEqual(target[-1][0], 8)

    def test_incompatible_or_nonfinite_source_models_are_rejected(self):
        source, target = self.models()
        source[0] = np.ones((5, 3))
        with self.assertRaises(ValueError):
            initialize_target_encoder(source, target)
        source, target = self.models()
        source[0][0, 0] = np.nan
        with self.assertRaises(ValueError):
            initialize_target_encoder(source, target)

    def test_reusing_six_source_labels_as_target_classes_is_rejected(self):
        source, _ = self.models()
        with self.assertRaises(ValueError):
            initialize_target_encoder(source, source)

    def test_winsor_bounds_use_training_and_leave_proportions_unclipped(self):
        names = ["connection_count", "state_sf_fraction"]
        train = np.array([[1, 0.1], [2, 0.2], [3, 0.3], [1000, 0.4]])
        spec = fit_feature_transform(
            train_features=train,
            feature_names=names,
            mode="log1p-winsor",
            lower_quantile=0.001,
            upper_quantile=0.999,
        )
        original = dict(spec["winsorization"]["upper_bounds_after_log1p"])
        test = np.array([[1e12, 0.9]])
        actual = apply_feature_transform(features=test, feature_names=names, specification=spec)
        self.assertEqual(spec["winsorization"]["upper_bounds_after_log1p"], original)
        self.assertNotIn("state_sf_fraction", original)
        expected = (0.9 - train[:, 1].mean()) / train[:, 1].std()
        self.assertAlmostEqual(actual[0, 1], expected)
