import datetime as dt
import tempfile
import unittest
from pathlib import Path

import numpy as np

from fl_forensics.preprocessing import FEATURE_NAMES
from fl_forensics.ton_iot_retraining import (
    TEST_START,
    VALIDATION_START,
    binary_metrics,
    fit_transform,
    iid_partitions,
    select_round,
    split_rows,
    tensor_digest,
    transform,
    verify_checkpoint,
    wilson_interval,
)


class TargetRetrainingTests(unittest.TestCase):
    def row(self, start, label):
        return {
            "window_start_epoch": start,
            "window_end_epoch": start + 60,
            "label": label,
            "capture_id": dt.datetime.fromtimestamp(start, dt.UTC).date().isoformat(),
            "features": [1.0] * 25,
        }

    def rows(self):
        return [
            self.row(VALIDATION_START - 7200, "benign"),
            self.row(VALIDATION_START - 7140, "attack"),
            self.row(VALIDATION_START, "benign"),
            self.row(VALIDATION_START + 60, "attack"),
            self.row(TEST_START, "benign"),
            self.row(TEST_START + 60, "attack"),
        ]

    def test_temporal_isolation_and_hour_purge(self):
        rows = self.rows() + [
            self.row(VALIDATION_START - 60, "attack"),
            self.row(TEST_START - 60, "attack"),
        ]
        groups = split_rows(rows)
        self.assertEqual(
            {k: len(v) for k, v in groups.items()},
            {"train": 2, "validation": 2, "test": 2, "embargo": 2},
        )
        self.assertLessEqual(
            max(r["window_end_epoch"] for r in groups["train"]), VALIDATION_START - 3600
        )
        self.assertLessEqual(
            max(r["window_end_epoch"] for r in groups["validation"]), TEST_START - 3600
        )

    def test_missing_class_or_repeated_window_fails(self):
        with self.assertRaises(ValueError):
            split_rows(self.rows() + [self.rows()[0]])
        with self.assertRaises(ValueError):
            split_rows([r for r in self.rows() if r["label"] == "attack"])

    def test_target_transform_fits_training_only(self):
        train = np.tile(np.array([1.0, 3.0])[:, None], (1, 25))
        source = {"feature_names": FEATURE_NAMES, "mean": [100.0] * 25, "scale": [2.0] * 25}
        spec = fit_transform(train, "target-standard", source)
        self.assertEqual(spec["training_row_count"], 2)
        self.assertTrue(np.allclose(spec["mean_after_transform"], 2))
        self.assertTrue(np.allclose(transform(np.full((1, 25), 1000000.0), spec), 999998))
        self.assertTrue(np.allclose(spec["mean_after_transform"], 2))
        self.assertEqual(
            fit_transform(train, "source-standard", source)["mean_after_transform"], [100.0] * 25
        )

    def test_logarithm_applies_to_existing_ten_heavy_tailed_features(self):
        spec = fit_transform(np.ones((2, 25)), "target-log1p", {})
        self.assertEqual(spec["log1p_features"], FEATURE_NAMES[:10])

    def test_partitions_cover_training_once_and_preserve_determinism(self):
        labels = np.arange(900) % 2
        a = iid_partitions(labels)
        b = iid_partitions(labels)
        self.assertEqual(a, b)
        self.assertEqual(sorted(i for group in a for i in group), list(range(900)))
        self.assertTrue(all(len(group) >= 32 for group in a))

    def test_selection_uses_validation_and_earliest_tie(self):
        records = [
            {"round": 1, "validation_macro_f1": 0.7, "test_accuracy": 1.0},
            {"round": 2, "validation_macro_f1": 0.8, "test_accuracy": 0.0},
            {"round": 3, "validation_macro_f1": 0.8, "test_accuracy": 1.0},
        ]
        self.assertEqual(select_round(records)["round"], 2)
        with self.assertRaises(ValueError):
            select_round([{"round": 1, "validation_macro_f1": float("nan")}])

    def test_tensor_tampering_is_detected(self):
        arrays = [np.ones((2, 3), dtype="float32"), np.zeros(2, dtype="float32")]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "model.npz"
            np.savez_compressed(path, p00=arrays[0], p01=arrays[1])
            self.assertEqual(len(verify_checkpoint(path, tensor_digest(arrays))), 2)
            arrays[0][0, 0] = 2
            with self.assertRaises(ValueError):
                verify_checkpoint(path, tensor_digest(arrays))

    def test_zero_false_positives_in_thirty_is_not_a_tight_guarantee(self):
        low, high = wilson_interval(0, 30)
        self.assertAlmostEqual(low, 0)
        self.assertGreater(high, 0.11)
        result = binary_metrics([0] * 30 + [1] * 10, [0] * 30 + [1] * 10)
        self.assertEqual(result["false_positive_rate"], 0)
        self.assertGreater(result["false_positive_rate_wilson95"][1], 0.11)


if __name__ == "__main__":
    unittest.main()
