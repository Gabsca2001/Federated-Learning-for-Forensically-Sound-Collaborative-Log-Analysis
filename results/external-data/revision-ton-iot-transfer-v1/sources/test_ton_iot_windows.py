import hashlib
import unittest

import numpy as np

from fl_forensics.preprocessing import build_window_row
from fl_forensics.ton_iot import normalize_network_record
from fl_forensics.ton_iot_windows import (
    WindowAccumulator,
    duplicate_projection,
    fold_duplicate_index,
)


class WindowTests(unittest.TestCase):
    def row(self, **kw):
        return dict(
            ts="1560000000.125",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            dst_port="80",
            duration="1.25",
            src_bytes="50",
            dst_bytes="40",
            src_pkts="3",
            dst_pkts="2",
            proto="tcp",
            service="http",
            conn_state="SF",
            label="0",
            type="normal",
            **kw,
        )

    def test_streamed_features_are_identical_to_existing_function(self):
        rng = np.random.default_rng(341593)
        rows = []
        for n in range(151):
            row = self.row()
            row.update(
                duration=str(float(rng.exponential(2))),
                dst_port=str(n % 9),
                dst_ip=f"192.168.1.{n % 13 + 1}",
                proto=["tcp", "udp", "icmp", "other"][n % 4],
                service=["http", "dns", "ssl", "ssh", "-"][n % 5],
                conn_state=["SF", "S0", "REJ", "RSTO", "RSTR", "OTH"][n % 6],
                label=str(n % 2),
                type="normal" if n % 2 == 0 else "ddos",
            )
            rows.append(row)
        acc = WindowAccumulator()
        events = []
        for n, row in enumerate(rows):
            acc.add(row, ordinal=n, source_name="Network_dataset_1.csv")
            events.append(
                normalize_network_record(
                    row,
                    source_sha256="a" * 64,
                    source_name="Network_dataset_1.csv",
                    record_number=n + 1,
                )
            )
        expected, _ = build_window_row(
            events=events,
            capture_id="2019-06-08",
            bucket=26000000,
            window_seconds=60,
            client_id="test",
            benign_labels={"benign"},
            mixed_attack_label=None,
            split_seed=0,
            split_percentages={"train": 0, "validation": 0, "test": 100},
        )
        self.assertEqual(
            acc.finish(26000000, profile="occurrence")["features"], expected["features"]
        )
        self.assertEqual(acc.finish(26000000, profile="occurrence")["label"], expected["label"])

    def test_file_fragments_are_merged_without_losing_occurrences(self):
        acc = WindowAccumulator()
        for n in range(2):
            acc.add(self.row(), ordinal=n, source_name=f"Network_dataset_{n + 1}.csv")
        result = acc.finish(26000000, profile="occurrence")
        self.assertEqual(result["features"][0], 2)
        self.assertEqual(len(result["source_file_counts"]), 2)

    def test_projection_ignores_only_uid_and_labels(self):
        row = self.row()
        fields = list(row)
        digest = duplicate_projection(row, fields)
        changed = {**row, "uid": "id", "label": "1", "type": "ddos"}
        self.assertEqual(digest, duplicate_projection(changed, fields + ["uid"]))
        self.assertNotEqual(digest, duplicate_projection({**row, "src_pkts": "4"}, fields))
        self.assertNotEqual(digest, duplicate_projection({**row, "ts": "1560000001"}, fields))

    def test_length_prefix_prevents_delimiter_ambiguity(self):
        self.assertNotEqual(
            duplicate_projection({"a": "a,b", "b": "c"}, ["a", "b"]),
            duplicate_projection({"a": "a", "b": "b,c"}, ["a", "b"]),
        )

    def test_chunk_boundaries_retain_earliest_and_union_labels(self):
        dtype = np.dtype([("digest", "S32"), ("ordinal", "<u4"), ("label", "u1"), ("kind", "<u2")])
        values = [
            (hashlib.sha256(b"a").digest(), 4, 1, 1),
            (hashlib.sha256(b"b").digest(), 1, 1, 1),
            (hashlib.sha256(b"a").digest(), 2, 2, 2),
            (hashlib.sha256(b"a").digest(), 0, 1, 1),
            (hashlib.sha256(b"c").digest(), 3, 2, 2),
        ]
        for size in (1, 2, 3, 50):
            with self.subTest(chunk_size=size):
                records = np.array(values, dtype=dtype)
                keep = np.zeros(5, dtype="u1")
                result = fold_duplicate_index(records, keep, chunk_size=size)
                self.assertEqual(keep.tolist(), [2, 1, 0, 2, 0])
                self.assertEqual(result["projection_groups"], 3)
                self.assertEqual(result["excess_occurrences"], 2)
                self.assertEqual(result["conflicting_binary_groups"], 1)
                self.assertEqual(result["conflicting_type_groups"], 1)


if __name__ == "__main__":
    unittest.main()
