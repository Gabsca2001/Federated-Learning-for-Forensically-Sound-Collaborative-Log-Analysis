import unittest

from fl_forensics.preprocessing import FEATURE_NAMES, build_window_row
from fl_forensics.ton_iot import ToNIoTRecordError, normalize_network_record


class ToNIoTMappingTests(unittest.TestCase):
    def setUp(self):
        self.row = {
            "ts": "1560000000.125",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "dst_port": "80",
            "duration": "1",
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

    def event(self, row=None, **kwargs):
        return normalize_network_record(
            self.row if row is None else row,
            source_sha256="a" * 64,
            source_name=kwargs.get("source_name", "Network_dataset_1.csv"),
            record_number=kwargs.get("record_number", 1),
        )

    def test_all_25_features_match_existing_window_implementation(self):
        a = self.event()
        b = self.event(
            {
                **self.row,
                "src_ip": "192.168.1.3",
                "dst_ip": "192.168.1.4",
                "dst_port": "53",
                "duration": "3",
                "src_bytes": "70",
                "dst_bytes": "80",
                "src_pkts": "5",
                "dst_pkts": "4",
                "proto": "udp",
                "service": "dns",
                "conn_state": "S0",
                "label": "1",
                "type": "ddos",
            },
            record_number=2,
        )
        row, _ = build_window_row(
            events=[a, b],
            capture_id=a["capture_id"],
            bucket=int(a["timestamp"] // 60),
            window_seconds=60,
            client_id="toniot",
            benign_labels={"benign"},
            mixed_attack_label=None,
            split_seed=0,
            split_percentages={"train": 0, "validation": 0, "test": 100},
        )
        self.assertEqual(len(FEATURE_NAMES), 25)
        self.assertEqual(
            row["features"],
            [
                2.0,
                2.0,
                2.0,
                2.0,
                1.0,
                3.0,
                120.0,
                120.0,
                8.0,
                6.0,
                0.5,
                0.5,
                0.0,
                0.0,
                0.5,
                0.5,
                0.0,
                0.0,
                0.0,
                0.5,
                0.5,
                0.0,
                0.0,
                0.0,
                0.0,
            ],
        )
        self.assertEqual(row["label"], "attack")
        self.assertEqual(a["capture_id"], b["capture_id"])

    def test_missing_service_is_other_and_numeric_missing_is_rejected(self):
        self.assertEqual(self.event({**self.row, "service": "-"})["service"], "missing")
        for field in ("duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts"):
            with self.assertRaises(ToNIoTRecordError):
                self.event({**self.row, field: "-"})

    def test_each_category_activates_only_its_named_feature(self):
        groups = {
            "proto": ("protocol", ("tcp", "udp", "icmp", "unknown")),
            "service": ("service", ("dns", "http", "ssl", "ssh", "-")),
            "conn_state": ("state", ("SF", "S0", "REJ", "RSTO", "RSTR", "OTH")),
        }
        for field, (prefix, values) in groups.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    event = self.event({**self.row, field: value})
                    row, _ = build_window_row(
                        events=[event],
                        capture_id=event["capture_id"],
                        bucket=int(event["timestamp"] // 60),
                        window_seconds=60,
                        client_id="toniot",
                        benign_labels={"benign"},
                        mixed_attack_label=None,
                        split_seed=0,
                        split_percentages={"train": 0, "validation": 0, "test": 100},
                    )
                    expected = "other" if value in ("unknown", "-", "OTH") else value.lower()
                    for name, coefficient in zip(FEATURE_NAMES, row["features"], strict=True):
                        if name.startswith(prefix + "_"):
                            self.assertEqual(
                                coefficient, float(name == f"{prefix}_{expected}_fraction")
                            )

    def test_source_ipv6_and_uid_are_preserved(self):
        result = self.event({**self.row, "src_ip": "::", "dst_ip": "ff02::2", "uid": "connection"})
        self.assertEqual(result["originator_host"], "::")
        self.assertEqual(result["uid"], "connection")
        self.assertEqual(self.event()["uid"], "")

    def test_observed_source_corruption_is_not_silently_repaired(self):
        for changes in (
            {"src_ip": "0"},
            {"src_bytes": "0.0.0.0"},
            {"src_pkts": "1.5"},
            {"duration": "-1"},
            {"dst_port": "65536"},
            {"src_bytes": "inf"},
        ):
            with self.assertRaises(ToNIoTRecordError):
                self.event({**self.row, **changes})

    def test_source_ids_do_not_claim_distinct_connections(self):
        a, b = self.event(), self.event(record_number=2)
        self.assertNotEqual(a["event_id"], b["event_id"])
        self.assertEqual(a["source_occurrence"]["record_number"], 1)
        self.assertIn("occurrence", a["identity_scope"])

    def test_file_boundaries_do_not_change_capture_group(self):
        self.assertEqual(
            self.event()["capture_id"],
            self.event(source_name="Network_dataset_2.csv")["capture_id"],
        )
        self.assertNotEqual(
            self.event()["event_id"], self.event(source_name="Network_dataset_2.csv")["event_id"]
        )

    def test_binary_truth_is_not_forced_into_mitre_classes(self):
        result = self.event({**self.row, "label": "1", "type": "new_attack"})
        self.assertEqual(result["label"], "attack")
        self.assertEqual(result["source_attack_type"], "new_attack")
        for changes in ({"label": "2"}, {"label": "1", "type": "normal"}, {"type": "ddos"}):
            with self.assertRaises(ToNIoTRecordError):
                self.event({**self.row, **changes})

    def test_zero_destination_port_follows_existing_feature_contract(self):
        self.assertEqual(self.event({**self.row, "dst_port": "0"})["responder_port"], 0)

    def test_invalid_timestamp_unit_is_not_guessed(self):
        with self.assertRaises(ToNIoTRecordError):
            self.event({**self.row, "ts": "1560000000125"})


if __name__ == "__main__":
    unittest.main()
