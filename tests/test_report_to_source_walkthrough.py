import importlib.util
import tempfile
import unittest
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from fl_forensics.dataset24 import EXPECTED_COLUMNS, _full_row_digest, _identity_digest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "report_to_source_walkthrough.py"
spec = importlib.util.spec_from_file_location("report_to_source_walkthrough", SCRIPT)
walk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(walk)


def _row(i, state="S0", dst="10.0.0.1", port="80", ob="", rb=""):
    row = {c: "" for c in EXPECTED_COLUMNS}
    row.update(
        conn_state=state, src_ip_zeek="10.0.0.9", dest_ip_zeek=dst, dest_port_zeek=port,
        orig_bytes=ob, resp_bytes=rb, duration="0.001", proto="tcp", datetime=f"2024-03-22T23:23:{30 + i:02d}Z",
        label_tactic="none", uid=f"C{i}",
    )
    return row


class DigestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "sample.parquet"
        rows = [_row(i, dst=f"10.0.0.{i}") for i in range(5)]
        pq.write_table(pa.table({c: [r[c] for r in rows] for c in EXPECTED_COLUMNS}), self.path)
        self.rows = rows

    def tearDown(self):
        self.tmp.cleanup()

    def test_reader_is_one_based_and_digests_recompute(self):
        got = walk.read_rows(self.path, [1, 4])
        self.assertEqual(got[1]["dest_ip_zeek"], "10.0.0.0")
        self.assertEqual(got[4]["dest_ip_zeek"], "10.0.0.3")
        ref = {"row_number": 4, "source_record_sha256": _full_row_digest(self.rows[3], EXPECTED_COLUMNS)}
        result = walk.check_record(got[4], ref, _identity_digest(self.rows[3], EXPECTED_COLUMNS))
        self.assertTrue(result["source_record_match"])
        self.assertTrue(result["source_identity_match"])

    def test_mismatched_record_digest_raises(self):
        got = walk.read_rows(self.path, [2])
        ref = {"row_number": 2, "source_record_sha256": _full_row_digest(self.rows[0], EXPECTED_COLUMNS)}
        with self.assertRaises(walk.DigestMismatch):
            walk.check_record(got[2], ref, None)

    def test_single_changed_field_breaks_digest(self):
        got = walk.read_rows(self.path, [1])[1]
        ref = {"row_number": 1, "source_record_sha256": _full_row_digest(got, EXPECTED_COLUMNS)}
        tampered = dict(got, orig_bytes="1")
        with self.assertRaises(walk.DigestMismatch):
            walk.check_record(tampered, ref, None)

    def test_mismatched_identity_digest_raises(self):
        got = walk.read_rows(self.path, [1])[1]
        ref = {"row_number": 1, "source_record_sha256": _full_row_digest(got, EXPECTED_COLUMNS)}
        with self.assertRaises(walk.DigestMismatch):
            walk.check_record(got, ref, "0" * 64)

    def test_file_digest_mismatch_raises(self):
        with self.assertRaises(walk.DigestMismatch):
            walk.verify_file(self.path, sha256="0" * 64, label="sample")

    def test_missing_row_is_an_error(self):
        with self.assertRaises(ValueError):
            walk.read_rows(self.path, [99])


class CriteriaTests(unittest.TestCase):
    def test_probe_pattern_is_supported(self):
        recs = [{k: v for k, v in _row(i, state="REJ" if i % 2 else "S0", dst=f"10.0.0.{i}", ob="0", rb="0").items()} for i in range(6)]
        self.assertEqual(walk.evaluate(walk.summarize(recs), True)["verdict"], "supported")

    def test_established_payload_is_contested(self):
        recs = [_row(i, state="SF", ob="500", rb="900") for i in range(6)]
        self.assertEqual(walk.evaluate(walk.summarize(recs), True)["verdict"], "contested")

    def test_missing_byte_fields_are_inconclusive(self):
        recs = [_row(i, state="S0", dst=f"10.0.0.{i}") for i in range(6)]
        self.assertEqual(walk.evaluate(walk.summarize(recs), True)["verdict"], "inconclusive")

    def test_broken_chain_is_inconclusive(self):
        recs = [_row(i, dst=f"10.0.0.{i}") for i in range(6)]
        self.assertEqual(walk.evaluate(walk.summarize(recs), False)["verdict"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
