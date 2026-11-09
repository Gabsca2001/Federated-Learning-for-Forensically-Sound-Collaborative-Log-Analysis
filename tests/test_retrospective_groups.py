import copy
import unittest

import numpy as np

from fl_forensics.retrospective_groups import (
    INDICATORS,
    calibrate_groups,
    detect_groups,
    pair_descriptors,
)


def campaign(seed=3):
    rng = np.random.default_rng(seed)
    return [
        {
            "round_number": number,
            "client_ids": list("abcde"),
            "deltas": [[rng.normal(size=3) for _ in range(4)] for _ in range(5)],
            "indicators": [
                {"client_id": client, **dict(zip(INDICATORS, rng.normal(size=5), strict=True))}
                for client in "abcde"
            ],
        }
        for number in range(1, 7)
    ]


class GroupTests(unittest.TestCase):
    def test_shared_update_translation_does_not_create_similarity(self):
        source = campaign()
        shifted = copy.deepcopy(source)
        for record in shifted:
            record["deltas"] = [[tensor + 100 for tensor in delta] for delta in record["deltas"]]
        first, second = pair_descriptors(source), pair_descriptors(shifted)
        for a, b in zip(first, second, strict=True):
            self.assertAlmostEqual(a["score"], b["score"], places=12)

    def test_calibration_does_not_read_candidate_campaign(self):
        clean = [campaign(1), campaign(2)]
        before = copy.deepcopy(clean)
        calibration = calibrate_groups(clean)
        self.assertFalse(calibration["attack_identities_used"])
        self.assertEqual(calibration["complete_clean_pair_count"], 20)
        self.assertEqual(calibration, calibrate_groups(clean))
        for old, new in zip(before, clean, strict=True):
            self.assertTrue(np.array_equal(old[0]["deltas"][0], new[0]["deltas"][0]))

    def test_identical_varying_pair_is_detected_without_truth_ids(self):
        candidate = campaign(20)
        for record in candidate:
            record["deltas"][1] = copy.deepcopy(record["deltas"][0])
            record["indicators"][1] = {**record["indicators"][0], "client_id": "b"}
        result = detect_groups(candidate, calibrate_groups([campaign(1), campaign(2)]))
        self.assertTrue(any({"a", "b"} <= set(group) for group in result["candidate_groups"]))
        self.assertFalse(result["intentional_collusion_proved"])

    def test_constant_zero_vectors_are_undefined_not_perfectly_similar(self):
        source = campaign()
        for record in source:
            record["deltas"] = [[np.zeros(3) for _ in range(4)] for _ in range(5)]
            for item in record["indicators"]:
                item.update({name: 1.0 for name in INDICATORS})
        self.assertTrue(all(pair["score"] is None for pair in pair_descriptors(source)))
        with self.assertRaisesRegex(ValueError, "no fully defined"):
            calibrate_groups([source])

    def test_label_informed_calibration_is_rejected(self):
        calibration = calibrate_groups([campaign()])
        calibration["attack_identities_used"] = True
        with self.assertRaises(ValueError):
            detect_groups(campaign(), calibration)

    def test_population_schema_and_nonfinite_series_fail(self):
        for mutate in (
            lambda records: records[1]["client_ids"].reverse(),
            lambda records: records[1]["deltas"][0].append(np.ones(1)),
            lambda records: records[1]["indicators"][0].update(relative_norm=float("nan")),
        ):
            records = campaign()
            mutate(records)
            with self.assertRaises(ValueError):
                pair_descriptors(records)

    def test_short_and_unordered_trajectories_fail(self):
        with self.assertRaises(ValueError):
            pair_descriptors(campaign()[:2])
        with self.assertRaises(ValueError):
            pair_descriptors(list(reversed(campaign())))
