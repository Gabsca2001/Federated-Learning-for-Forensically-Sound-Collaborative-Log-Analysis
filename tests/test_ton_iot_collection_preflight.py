import csv
import hashlib
import importlib.util
import io
import unittest
from pathlib import Path

script = Path(__file__).with_name("revision_ton_iot_collection_preflight.py")
if not script.exists():
    script = Path(__file__).parents[1] / "scripts/revision_ton_iot_collection_preflight.py"
spec = importlib.util.spec_from_file_location("collection_preflight", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
REQUIRED, scan_stream = module.REQUIRED, module.scan_stream


class CollectionPreflightTests(unittest.TestCase):
    def setUp(self):
        self.row = {
            "ts": "1560000000.125",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "dst_port": "80",
            "duration": "1.5",
            "src_bytes": "50",
            "dst_bytes": "40",
            "src_pkts": "3",
            "dst_pkts": "2",
            "proto": "tcp",
            "service": "http",
            "conn_state": "SF",
            "label": "0",
            "type": "normal",
        }

    def scan(self, rows, fields=None, **kwargs):
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=fields or list(self.row))
        writer.writeheader()
        writer.writerows(rows)
        payload = b"\xef\xbb\xbf" + stream.getvalue().encode()
        report = scan_stream(io.BytesIO(payload), name="test.csv", **kwargs)
        self.assertEqual(report["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(report["scanned_bytes"], len(payload))
        return report

    def test_bom_and_original_bytes_are_accounted_for(self):
        result = self.scan([self.row])
        self.assertEqual(result["rows"], 1)
        self.assertEqual(result["strict_fully_observed_valid_rows"], 1)

    def test_uid_and_reordered_columns_preserve_field_meanings(self):
        result = self.scan(
            [{**self.row, "uid": "connection-id"}], fields=["uid"] + list(reversed(self.row))
        )
        self.assertEqual(result["strict_fully_observed_valid_rows"], 1)
        self.assertEqual(result["binary_label_counts"], {"0": 1})

    def test_missing_measurements_are_not_zero_imputed(self):
        result = self.scan([{**self.row, "duration": "-", "src_bytes": "", "service": "-"}])
        self.assertEqual(result["missing_values"], {"duration": 1, "src_bytes": 1, "service": 1})
        self.assertEqual(result["strict_fully_observed_valid_rows"], 0)
        self.assertEqual(result["usable_rows_under_explicit_category_policy"], 0)

    def test_unknown_service_is_retained_as_an_explicit_other_category(self):
        result = self.scan([{**self.row, "service": "-"}])
        self.assertEqual(result["strict_fully_observed_valid_rows"], 0)
        self.assertEqual(result["usable_rows_under_explicit_category_policy"], 1)
        self.assertEqual(result["rejected_measurement_rows"], 0)

    def test_one_occurrence_with_two_bad_fields_is_rejected_only_once(self):
        result = self.scan([{**self.row, "src_ip": "0", "src_bytes": "0.0.0.0"}])
        self.assertEqual(result["rejected_measurement_rows"], 1)
        self.assertEqual(
            result["rejected_occurrences_first10000"],
            [{"record_number": 1, "reasons": ["invalid_src_bytes", "invalid_src_ip"]}],
        )

    def test_bad_ip_count_port_and_binary_label_are_visible(self):
        result = self.scan(
            [{**self.row, "dst_ip": "bad", "src_pkts": "2.5", "dst_port": "65536", "label": "2"}]
        )
        self.assertEqual(set(result["invalid_values"]), {"dst_ip", "src_pkts", "dst_port", "label"})

    def test_negative_and_nonfinite_values_fail(self):
        result = self.scan([{**self.row, "duration": "-1", "src_bytes": "inf", "dst_pkts": "NaN"}])
        self.assertEqual(result["invalid_values"], {"duration": 1, "src_bytes": 1})
        self.assertEqual(result["missing_values"], {"dst_pkts": 1})

    def test_label_type_conflicts_are_not_forced_into_a_class(self):
        result = self.scan([{**self.row, "label": "1"}])
        self.assertEqual(result["label_type_conflicts"], 1)
        self.assertEqual(result["strict_fully_observed_valid_rows"], 0)

    def test_shared_minute_across_files_and_mixed_labels(self):
        files, labels = {}, {}
        self.scan([self.row], minute_files=files, minute_labels=labels, file_bit=1)
        self.scan(
            [{**self.row, "label": "1", "type": "ddos"}],
            minute_files=files,
            minute_labels=labels,
            file_bit=2,
        )
        self.assertEqual(list(files.values()), [3])
        self.assertEqual(list(labels.values()), [3])

    def test_missing_or_duplicate_headers_are_rejected(self):
        for header in [list(REQUIRED)[:-1], list(REQUIRED) + ["ts"]]:
            with self.assertRaises(ValueError):
                scan_stream(io.BytesIO((",".join(header) + "\n").encode()), name="bad.csv")

    def test_short_and_wide_rows_do_not_disappear(self):
        header = ",".join(self.row)
        payload = (header + "\n" + "a,b\n" + ",".join(self.row.values()) + ",extra\n").encode()
        result = scan_stream(io.BytesIO(payload), name="bad-width.csv")
        self.assertEqual(result["rows"], 2)
        self.assertEqual(result["invalid_values"], {"row_width": 2})

    def test_backward_timestamps_remain_visible(self):
        result = self.scan([self.row, {**self.row, "ts": "1560000000.0"}])
        self.assertEqual(result["timestamp_regressions_within_file"], 1)
        self.assertEqual(result["timestamp_range_seconds"], [1560000000.0, 1560000000.125])


if __name__ == "__main__":
    unittest.main()
