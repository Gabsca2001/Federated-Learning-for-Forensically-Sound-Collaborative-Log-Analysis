import csv
import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "ton_preflight", Path(__file__).parents[1] / "scripts/revision_ton_iot_preflight.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ToNPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "network.csv"
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
        }

    def write(self, rows):
        with self.path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def test_valid_columns_do_not_certify_sampled_window_counts(self):
        self.write([self.row, {**self.row, "label": "1"}])
        result = module.audit(self.path, release_scope="selected-train-test")
        self.assertTrue(result["required_field_coverage_supported_under_declared_mapping"])
        self.assertTrue(result["selected_release_count_distortion_risk"])
        self.assertFalse(result["dataset_compatibility_verified"])
        self.assertFalse(result["complete_window_coverage_established"])

    def test_missing_packets_are_not_silently_filled_with_zero(self):
        row = dict(self.row)
        del row["src_pkts"]
        self.write([row])
        result = module.audit(self.path)
        self.assertIn("originator_packets", result["missing_required_columns"])
        self.assertFalse(result["required_field_coverage_supported_under_declared_mapping"])

    def test_malformed_counts_labels_and_addresses_fail_coverage(self):
        self.write([{**self.row, "src_pkts": "-", "dst_ip": "not-an-ip", "label": "2"}])
        result = module.audit(self.path)
        self.assertEqual(result["fully_valid_rows"], 0)
        self.assertEqual(
            set(result["invalid_values_by_field"]),
            {"originator_packets", "destination_ip", "binary_label"},
        )

    def test_timestamp_units_are_explicit_and_bad_mapping_rejected(self):
        self.write([{**self.row, "ts": "1560000000125"}])
        result = module.audit(self.path, timestamp_unit="milliseconds")
        self.assertEqual(result["timestamp_range_epoch_seconds"], ["1560000000.125"] * 2)
        with self.assertRaises(ValueError):
            module.audit(self.path, columns={"timestamp": "ts"})
