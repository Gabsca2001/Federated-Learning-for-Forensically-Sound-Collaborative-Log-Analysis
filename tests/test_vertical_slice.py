from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fl_forensics.demo import run_demo
from fl_forensics.verification import verify_workspace


ROOT = Path(__file__).resolve().parents[1]


class VerticalSliceTests(unittest.TestCase):
    def test_demo_is_accepted_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "run"
            summary = run_demo(
                input_path=ROOT / "tests" / "fixtures" / "zeek_conn.jsonl",
                output=workspace,
                config_path=ROOT / "configs" / "base.yaml",
            )
            self.assertEqual(summary["admission_status"], "accepted")
            self.assertEqual(summary["feature_count"], 25)
            self.assertEqual(summary["window_count"], 3)
            verification = verify_workspace(workspace)
            self.assertEqual(verification["status"], "verified", verification["errors"])

    def test_tampered_queue_copy_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "run"
            summary = run_demo(
                input_path=ROOT / "tests" / "fixtures" / "zeek_conn.jsonl",
                output=workspace,
                config_path=ROOT / "configs" / "base.yaml",
            )
            batch_directory = workspace / summary["paths"]["batch_directory"]
            manifest = json.loads((batch_directory / "manifest.json").read_text())
            raw_path = batch_directory / manifest["core"]["content_filename"]
            raw_path.chmod(0o600)
            raw_path.write_bytes(raw_path.read_bytes() + b"\n{}\n")
            verification = verify_workspace(workspace)
            self.assertEqual(verification["status"], "failed")
            self.assertIn(
                "queued raw batch digest does not match manifest", verification["errors"]
            )


if __name__ == "__main__":
    unittest.main()

