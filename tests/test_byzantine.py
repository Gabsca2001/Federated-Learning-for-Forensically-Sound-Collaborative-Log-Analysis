from __future__ import annotations

import unittest

import numpy as np

from fl_forensics.byzantine import (
    ByzantineConfigurationError,
    aggregate_deltas,
    apply_delta,
    attack_delta,
    backdoor_rows,
    clip_delta_l2,
    colluding_deltas,
    delta_l2,
    label_flip_rows,
    model_replacement_delta,
    poison_prototypes,
    update_indicators,
)


def delta(value: float) -> list[np.ndarray]:
    return [
        np.asarray([value, value + 1.0], dtype=np.float32),
        np.asarray([[value]], dtype=np.float32),
    ]


class ByzantineAttackTests(unittest.TestCase):
    def test_model_attacks_are_deterministic_and_preserve_structure(self) -> None:
        original = delta(1.0)
        first = attack_delta(original, attack="gaussian_noise", seed=7, scale=2.0)
        second = attack_delta(original, attack="gaussian_noise", seed=7, scale=2.0)
        for left, right, reference in zip(first, second, original, strict=True):
            np.testing.assert_array_equal(left, right)
            self.assertEqual(left.shape, reference.shape)
            self.assertEqual(left.dtype, reference.dtype)
        flipped = attack_delta(original, attack="sign_flip", seed=0, scale=3.0)
        np.testing.assert_allclose(flipped[0], -3.0 * original[0])
        amplified = attack_delta(
            original, attack="update_amplification", seed=0, scale=15.0
        )
        np.testing.assert_allclose(amplified[1], 15.0 * original[1])

    def test_model_replacement_scales_an_explicit_malicious_target(self) -> None:
        base = delta(1.0)
        malicious = delta(-2.0)
        replacement = model_replacement_delta(base, malicious, scale=4.0)
        submitted = apply_delta(base, replacement)
        for actual, base_tensor, malicious_tensor in zip(
            submitted, base, malicious, strict=True
        ):
            expected = base_tensor + 4.0 * (malicious_tensor - base_tensor)
            np.testing.assert_allclose(actual, expected)

    def test_label_flip_and_backdoor_do_not_mutate_clean_rows(self) -> None:
        rows = [
            {"window_id": "a", "label": "reconnaissance", "features": [1.0, 2.0]},
            {"window_id": "b", "label": "benign", "features": [3.0, 4.0]},
        ]
        flipped, changed = label_flip_rows(
            rows, source_label="reconnaissance", target_label="benign"
        )
        self.assertEqual(changed, 1)
        self.assertEqual(flipped[0]["label"], "benign")
        self.assertEqual(rows[0]["label"], "reconnaissance")
        poisoned, selected = backdoor_rows(
            rows,
            target_label="benign",
            feature_indices=[0],
            trigger_value=99.0,
            fraction=0.5,
            seed=9,
        )
        self.assertEqual(len(selected), 1)
        self.assertEqual(sum(item["features"][0] == 99.0 for item in poisoned), 1)
        self.assertEqual(rows[0]["features"], [1.0, 2.0])

    def test_prototype_poisoning_and_collusion_are_explicit(self) -> None:
        prototypes = {
            "benign": np.asarray([0.0, 0.0], dtype=np.float32),
            "reconnaissance": np.asarray([2.0, 4.0], dtype=np.float32),
        }
        poisoned = poison_prototypes(
            prototypes,
            source_class="reconnaissance",
            target_class="benign",
            scale=1.5,
        )
        np.testing.assert_allclose(poisoned["reconnaissance"], [-1.0, -2.0])
        coordinated = colluding_deltas(delta(2.0), client_count=3, scale=4.0)
        self.assertEqual(len(coordinated), 3)
        for item in coordinated[1:]:
            np.testing.assert_array_equal(item[0], coordinated[0][0])


class RobustAggregationTests(unittest.TestCase):
    def test_clipping_enforces_the_exact_l2_bound(self) -> None:
        clipped, scale = clip_delta_l2(
            [np.asarray([3.0, 4.0], dtype=np.float32)], max_norm=2.5
        )
        self.assertAlmostEqual(scale, 0.5)
        self.assertAlmostEqual(delta_l2(clipped), 2.5, places=6)

    def test_all_aggregators_consume_the_same_frozen_deltas(self) -> None:
        clean = [delta(value) for value in (0.0, 0.1, -0.1, 0.2, -0.2, 0.05, -0.05)]
        poisoned = [*clean, delta(100.0)]
        original = [[tensor.copy() for tensor in item] for item in poisoned]
        fedavg = aggregate_deltas(
            poisoned, strategy="fedavg", f=1, weights=[1] * len(poisoned)
        )
        median = aggregate_deltas(poisoned, strategy="coordinate_median", f=1)
        trimmed = aggregate_deltas(poisoned, strategy="trimmed_mean", f=1)
        multikrum = aggregate_deltas(
            poisoned, strategy="multikrum", f=1, multikrum_m=4
        )
        bulyan = aggregate_deltas(poisoned, strategy="bulyan", f=1)
        self.assertGreater(delta_l2(fedavg), 10.0)
        for robust in (median, trimmed, multikrum, bulyan):
            self.assertLess(delta_l2(robust), 3.0)
        for before, after in zip(original, poisoned, strict=True):
            for expected, actual in zip(before, after, strict=True):
                np.testing.assert_array_equal(expected, actual)

    def test_invalid_n_f_bounds_halt_explicitly(self) -> None:
        five = [delta(float(index)) for index in range(5)]
        with self.assertRaisesRegex(ByzantineConfigurationError, "Krum requires"):
            aggregate_deltas(five, strategy="multikrum", f=2)
        with self.assertRaisesRegex(ByzantineConfigurationError, "Bulyan requires"):
            aggregate_deltas(five, strategy="bulyan", f=1)
        with self.assertRaisesRegex(ByzantineConfigurationError, "trimmed mean requires"):
            aggregate_deltas(five, strategy="trimmed_mean", f=3)

    def test_indicators_surface_a_large_opposite_update(self) -> None:
        records = update_indicators(
            [delta(0.0), delta(0.1), delta(-0.1), delta(50.0)],
            client_ids=["a", "b", "c", "attacker"],
        )
        by_client = {item["client_id"]: item for item in records}
        self.assertGreater(
            by_client["attacker"]["coordinate_median_distance"],
            by_client["a"]["coordinate_median_distance"],
        )
        self.assertGreater(by_client["attacker"]["relative_norm"], 10.0)


if __name__ == "__main__":
    unittest.main()
