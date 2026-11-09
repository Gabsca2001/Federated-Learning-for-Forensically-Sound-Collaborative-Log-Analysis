import hashlib
import struct
import unittest

import numpy as np

from fl_forensics.ton_iot_host_windows import (
    HostAccumulator,
    canonical_host,
    exact_integer_sum,
    host_window_id,
    pool_host_scores,
)
from fl_forensics.ton_iot_windows import WindowAccumulator


class HostWindowsTests(unittest.TestCase):
    def rows(self):
        return [
            {
                "dst_ip": "192.168.1." + str(i % 3 + 1),
                "dst_port": i % 4,
                "proto": ("TCP" if i % 2 else "-"),
                "service": ("http" if i % 2 else "dns"),
                "conn_state": "SF",
                "duration": (i + 1) / 3,
                "src_bytes": i * 10,
                "dst_bytes": i * 20,
                "src_pkts": i + 1,
                "dst_pkts": i + 2,
                "label": i % 2,
                "type": ("ddos" if i % 2 else "normal"),
            }
            for i in range(19)
        ]

    def test_batched_aggregation_matches_rowwise_reference_across_files(self):
        rows = self.rows()
        plain = WindowAccumulator()
        batched = HostAccumulator()
        for lo, hi, source in [(0, 7, "Network_dataset_1.csv"), (7, 19, "Network_dataset_2.csv")]:
            for i in range(lo, hi):
                plain.add({k: str(v) for k, v in rows[i].items()}, ordinal=i, source_name=source)
            batched.add_block(
                {k: np.asarray([row[k] for row in rows[lo:hi]]) for k in rows[0]},
                np.arange(lo, hi),
                source,
            )
        self.assertEqual(
            plain.finish(100, profile="occurrence"), batched.finish(100, profile="occurrence")
        )

    def test_host_ids_distinguish_hosts_and_canonicalize_ipv6(self):
        self.assertNotEqual(host_window_id("192.168.1.1", 100), host_window_id("192.168.1.2", 100))
        self.assertEqual(host_window_id("2001:0DB8::1", 100), host_window_id("2001:db8::1", 100))
        self.assertEqual(canonical_host(" 192.168.1.1 "), "192.168.1.1")

    def test_ordinals_cannot_be_reused_or_reordered(self):
        row = self.rows()[0]
        columns = {k: np.asarray([v]) for k, v in row.items()}
        acc = HostAccumulator()
        acc.add_block(columns, [10], "Network_dataset_1.csv")
        with self.assertRaises(ValueError):
            acc.add_block(columns, [10], "Network_dataset_1.csv")
        with self.assertRaises(ValueError):
            acc.add_block(columns, [9], "Network_dataset_1.csv")

    def test_digest_commits_original_occurrence_order(self):
        rows = self.rows()
        acc = HostAccumulator()
        ordinals = np.arange(100, 119)
        acc.add_block(
            {k: np.asarray([r[k] for r in rows]) for k in rows[0]},
            ordinals,
            "Network_dataset_1.csv",
        )
        self.assertEqual(
            acc.occurrence_digest.hexdigest(),
            hashlib.sha256(b"".join(struct.pack(">Q", int(i)) for i in ordinals)).hexdigest(),
        )

    def test_integer_totals_do_not_overflow_int64(self):
        values = np.full(2048, 2**53, dtype=np.int64)
        self.assertEqual(exact_integer_sum(values), 2048 * 2**53)

    def test_pooling_is_any_host_alert_on_the_same_minute(self):
        b, s, y = pool_host_scores([2, 1, 2, 1], [0.1, 0.2, 0.9, 0.3], [0, 0, 1, 0])
        np.testing.assert_array_equal(b, [1, 2])
        np.testing.assert_array_equal(s, [0.3, 0.9])
        np.testing.assert_array_equal(y, [0, 1])

    def test_malformed_pool_inputs_are_rejected(self):
        for b, s, y in [
            ([], [], []),
            ([1], [np.nan], [0]),
            ([1, 2], [0.2], [0, 1]),
            ([1], [0.5], [2]),
        ]:
            with self.assertRaises(ValueError):
                pool_host_scores(b, s, y)
