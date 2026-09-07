from __future__ import annotations

import unittest

import numpy as np

from fl_forensics.contribution_explanation import (
    ContributionExplanationError,
    tensor_deviation_drivers,
    trace_aggregation_profiles,
)


def delta(value: float) -> list[np.ndarray]:
    return [
        np.asarray([value, value * 0.5], dtype=np.float64),
        np.asarray([[value * 0.25]], dtype=np.float64),
    ]


class AggregationTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client_ids = [f"client{index:02d}" for index in range(1, 8)]
        self.deltas = [delta(value) for value in (0.00, 0.01, 0.02, 0.03, 0.04, 0.05, 10.0)]
        self.weights = [10, 11, 12, 13, 14, 15, 16]

    def test_all_traces_are_deterministic_and_cover_the_same_clients(self) -> None:
        first = trace_aggregation_profiles(
            self.deltas,
            client_ids=self.client_ids,
            weights=self.weights,
            f=1,
            clip_threshold=1.0,
        )
        second = trace_aggregation_profiles(
            self.deltas,
            client_ids=self.client_ids,
            weights=self.weights,
            f=1,
            clip_threshold=1.0,
        )
        self.assertEqual(first, second)
        self.assertEqual(
            [item.profile_id for item in first],
            [
                "l2_clipping",
                "fedavg",
                "coordinate_median",
                "trimmed_mean",
                "multikrum",
                "bulyan",
            ],
        )
        for profile in first:
            self.assertEqual(
                [item.client_id for item in profile.clients], self.client_ids
            )
            self.assertTrue(profile.trace_reproduces_aggregate)

    def test_outlier_is_clipped_and_excluded_by_client_selecting_defenses(self) -> None:
        profiles = {
            item.profile_id: item
            for item in trace_aggregation_profiles(
                self.deltas,
                client_ids=self.client_ids,
                weights=self.weights,
                f=1,
                clip_threshold=1.0,
            )
        }
        clipping = {item.client_id: item for item in profiles["l2_clipping"].clients}
        self.assertLess(clipping["client07"].clip_scale, 1.0)
        multikrum = {item.client_id: item for item in profiles["multikrum"].clients}
        self.assertFalse(multikrum["client07"].selected)
        self.assertEqual(multikrum["client07"].krum_rank, 7)
        bulyan = {item.client_id: item for item in profiles["bulyan"].clients}
        self.assertFalse(bulyan["client07"].bulyan_candidate_selected)
        trimmed = {item.client_id: item for item in profiles["trimmed_mean"].clients}
        self.assertEqual(trimmed["client07"].retained_coordinate_count, 0)
        self.assertEqual(trimmed["client07"].retained_coordinate_fraction, 0.0)

    def test_stored_clipping_scale_mismatch_fails_closed(self) -> None:
        expected = {client_id: 1.0 for client_id in self.client_ids}
        with self.assertRaisesRegex(ContributionExplanationError, "clipping trace"):
            trace_aggregation_profiles(
                self.deltas,
                client_ids=self.client_ids,
                weights=self.weights,
                f=1,
                clip_threshold=1.0,
                expected_clip_scales=expected,
            )

    def test_invalid_client_alignment_fails_closed(self) -> None:
        with self.assertRaisesRegex(ContributionExplanationError, "client IDs"):
            trace_aggregation_profiles(
                self.deltas,
                client_ids=self.client_ids[:-1],
                weights=self.weights,
                f=1,
                clip_threshold=1.0,
            )


class TensorDriverTests(unittest.TestCase):
    def test_tensor_drivers_rank_squared_median_distance(self) -> None:
        client_ids = ["client01", "client02", "client03"]
        deltas = [
            [np.zeros(2), np.zeros(4)],
            [np.ones(2) * 0.1, np.ones(4) * 0.1],
            [np.ones(2) * 5.0, np.ones(4) * 0.2],
        ]
        drivers = tensor_deviation_drivers(
            deltas,
            client_ids=client_ids,
            tensor_names=["large-shift", "small-shift"],
            top_k=2,
        )
        self.assertEqual(drivers["client03"][0].tensor_name, "large-shift")
        self.assertGreater(
            drivers["client03"][0].squared_median_distance_fraction,
            drivers["client03"][1].squared_median_distance_fraction,
        )
        self.assertAlmostEqual(
            sum(
                item.squared_median_distance_fraction
                for item in drivers["client03"]
            ),
            1.0,
        )

    def test_invalid_tensor_names_fail_closed(self) -> None:
        with self.assertRaisesRegex(ContributionExplanationError, "tensor names"):
            tensor_deviation_drivers(
                [delta(0.0), delta(0.1)],
                client_ids=["client01", "client02"],
                tensor_names=["only-one"],
                top_k=1,
            )


if __name__ == "__main__":
    unittest.main()
