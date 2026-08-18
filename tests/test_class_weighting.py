from __future__ import annotations

import unittest
from math import sqrt

from fl_forensics.class_weighting import compute_class_weights


class ClassWeightingTests(unittest.TestCase):
    def test_balanced_weights_use_training_counts(self) -> None:
        weights = compute_class_weights(
            ["majority", "majority", "majority", "majority", "rare"],
            strategy="balanced",
        )
        self.assertAlmostEqual(weights["majority"], 0.625)
        self.assertAlmostEqual(weights["rare"], 2.5)

    def test_sqrt_balanced_reduces_extreme_weights(self) -> None:
        weights = compute_class_weights(
            ["majority", "majority", "majority", "majority", "rare"],
            strategy="sqrt-balanced",
        )
        self.assertAlmostEqual(weights["majority"], sqrt(0.625))
        self.assertAlmostEqual(weights["rare"], sqrt(2.5))

    def test_federated_alias_has_the_same_semantics(self) -> None:
        labels = ["majority", "majority", "rare"]
        self.assertEqual(
            compute_class_weights(labels, strategy="global-sqrt-balanced-training-only"),
            compute_class_weights(labels, strategy="sqrt-balanced"),
        )

    def test_none_produces_uniform_weights(self) -> None:
        self.assertEqual(
            compute_class_weights(["a", "a", "b"], strategy="none"),
            {"a": 1.0, "b": 1.0},
        )

    def test_unknown_strategy_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported class-weighting strategy"):
            compute_class_weights(["a"], strategy="unknown")


if __name__ == "__main__":
    unittest.main()
