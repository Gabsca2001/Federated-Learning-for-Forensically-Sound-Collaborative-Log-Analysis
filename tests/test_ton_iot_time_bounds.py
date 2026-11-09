import unittest

from fl_forensics.ton_iot_time_bounds import indices_observed_by, observation_end_upper_bound


class ObservationBoundTests(unittest.TestCase):
    def row(self, start, duration):
        values = [0.0] * 25
        values[5] = duration
        return {"window_start_epoch": start, "window_end_epoch": start + 60, "features": values}

    def test_long_connection_is_not_admitted_by_start_time_alone(self):
        rows = [self.row(0, 2), self.row(0, 86400)]
        self.assertEqual(indices_observed_by(rows, 3600), [0])

    def test_rounding_guard_and_window_end_are_included(self):
        row = self.row(0, 10)
        self.assertEqual(observation_end_upper_bound(row), 71)
        self.assertEqual(indices_observed_by([row], 70), [])
        self.assertEqual(indices_observed_by([row], 71), [0])

    def test_invalid_duration_or_window_fails(self):
        for duration in (-1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                observation_end_upper_bound(self.row(0, duration))
        row = self.row(0, 0)
        row["window_end_epoch"] = 59
        with self.assertRaises(ValueError):
            observation_end_upper_bound(row)

    def test_source_count_changes_do_not_change_the_time_bound(self):
        a = self.row(1000, 120)
        b = self.row(1000, 120)
        a["features"][0] = 100
        b["features"][0] = 20
        self.assertEqual(observation_end_upper_bound(a), observation_end_upper_bound(b))
