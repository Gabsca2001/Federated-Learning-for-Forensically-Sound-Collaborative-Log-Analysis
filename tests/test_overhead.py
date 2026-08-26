from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

import yaml

from fl_forensics.overhead import (
    OverheadBenchmarkError,
    create_overhead_benchmark,
    load_overhead_contract,
    verify_overhead_benchmark,
)


class OverheadBenchmarkTests(unittest.TestCase):
    def _config(self, root: Path) -> Path:
        path = root / "configs" / "overhead.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(
            yaml.safe_dump(
                {
                    "schema_version": "1.0",
                    "benchmark_id": "test-overhead",
                    "profile": "offline-verifier-latency-v1",
                    "project_root": "..",
                    "inputs": {},
                    "stages": [
                        {
                            "stage_id": "m4-software-ecdsa-sign-verify",
                            "warmup_runs": 0,
                            "repetitions": 2,
                            "operations_per_sample": 4,
                            "expected": {
                                "status": "verified",
                                "operation_count": 4,
                            },
                        }
                    ],
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return path

    def test_receipt_is_created_and_independently_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            output = root / "artifacts" / "overhead"
            result = create_overhead_benchmark(output=output, config_path=config)
            self.assertEqual(result["status"], "benchmarked")
            self.assertEqual(result["stage_count"], 1)
            self.assertEqual(result["measured_sample_count"], 2)

            verification = verify_overhead_benchmark(
                workspace=output,
                config_path=config,
            )
            self.assertEqual(verification["status"], "verified")
            self.assertTrue(verification["statistics_recomputed"])
            self.assertTrue(verification["implementation_binding_verified"])

            summary = json.loads((output / "summary.json").read_text())
            stage = summary["stages"][0]
            self.assertEqual(stage["operations_per_sample"], 4)
            self.assertEqual(stage["wall_time_ns"]["count"], 2)
            self.assertGreaterEqual(stage["median_wall_time_ms"], 0.0)

    def test_tampered_samples_fail_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            output = root / "artifacts" / "overhead"
            create_overhead_benchmark(output=output, config_path=config)
            path = output / "samples.json"
            value = json.loads(path.read_text())
            value["samples"][0]["wall_time_ns"] += 1
            path.chmod(path.stat().st_mode | stat.S_IWUSR)
            path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
            result = verify_overhead_benchmark(
                workspace=output,
                config_path=config,
            )
            self.assertEqual(result["status"], "failed")
            self.assertGreater(result["error_count"], 0)

    def test_configuration_change_breaks_the_receipt_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            output = root / "artifacts" / "overhead"
            create_overhead_benchmark(output=output, config_path=config)
            value = yaml.safe_load(config.read_text())
            value["benchmark_id"] = "changed-overhead"
            config.write_text(yaml.safe_dump(value), encoding="utf-8")
            result = verify_overhead_benchmark(
                workspace=output,
                config_path=config,
            )
            self.assertEqual(result["status"], "failed")
            self.assertIn("manifest", " ".join(result["errors"]))

    def test_contract_rejects_unknown_or_reordered_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            value = yaml.safe_load(config.read_text())
            value["stages"][0]["stage_id"] = "unknown-stage"
            config.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(OverheadBenchmarkError, "unknown"):
                load_overhead_contract(config)

    def test_output_workspace_is_write_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root)
            output = root / "artifacts" / "overhead"
            create_overhead_benchmark(output=output, config_path=config)
            with self.assertRaisesRegex(OverheadBenchmarkError, "new or empty"):
                create_overhead_benchmark(output=output, config_path=config)


if __name__ == "__main__":
    unittest.main()
