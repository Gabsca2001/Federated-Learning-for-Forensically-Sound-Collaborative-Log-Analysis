from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.prototype_sensitivity_reporting import (
    PrototypeSensitivityReportingError,
    generate_prototype_sensitivity_report,
    verify_prototype_sensitivity_report,
)
from fl_forensics.storage import load_json, write_once

ROOT = Path(__file__).resolve().parents[1]


class PrototypeSensitivityReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.campaign = root / "campaign"
        self.report = root / "report"
        self.config_path = ROOT / "configs" / "byzantine-prototype-sensitivity.yaml"
        self._write_campaign()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _strategy(*, robust: bool, f: int, scale: float) -> dict[str, object]:
        recall_delta = 0.0 if robust else -(f * scale) / 20.0
        macro_delta = 0.0 if robust else (f - scale) / 100.0
        return {
            "aggregation_strategy": (
                "coordinate_median" if robust else "support_weighted_mean"
            ),
            "source_prototype_shift_l2": (
                0.05 if robust else float(f * scale)
            ),
            "validation_macro_f1_delta": macro_delta,
            "test_macro_f1_delta": macro_delta,
            "validation_source_recall_delta": recall_delta,
            "test_source_recall_delta": recall_delta,
            "test_source_misclassification_rate_delta": -recall_delta,
            "test_targeted_attack_success_rate_delta": 0.0,
            "clean_test_macro_f1": 0.76,
            "attacked_test_macro_f1": 0.76 + macro_delta,
            "clean_test_source_recall": 0.99,
            "attacked_test_source_recall": 0.99 + recall_delta,
            "attacked_test_targeted_attack_success_rate": 0.0,
            "attacked_test_other_class_misclassification_rate": (
                0.01 - recall_delta
            ),
        }

    def _write_campaign(self) -> None:
        cells = [
            (1, 1.5),
            (2, 1.5),
            (3, 0.5),
            (3, 1.0),
            (3, 1.5),
            (3, 2.0),
        ]
        scenarios = []
        for f, scale in cells:
            scenarios.append(
                {
                    "scenario_id": f"f{f}-scale-{str(scale).replace('.', 'p')}",
                    "f": f,
                    "scale": scale,
                    "attacker_ids": [f"client{index:02d}" for index in range(1, f + 1)],
                    "primary_anchor": f == 3 and scale == 1.5,
                    "baseline": self._strategy(robust=False, f=f, scale=scale),
                    "robust": self._strategy(robust=True, f=f, scale=scale),
                }
            )
        sensitivity = {
            "schema_version": "1.0",
            "artifact_type": "m6_prototype_poisoning_sensitivity",
            "analysis_type": "exploratory-one-factor-at-a-time",
            "campaign_config_sha256": "a" * 64,
            "scenario_count": 6,
            "primary_scenario_id": "f3-scale-1p5",
            "report_every_scenario": True,
            "test_based_selection_permitted": False,
            "selection_performed": False,
            "test_data_accessed": True,
            "scenarios": scenarios,
        }
        write_once(
            self.campaign / "sensitivity.json", derived_json_bytes(sensitivity)
        )
        manifest = {
            "artifact_type": "m6_prototype_poisoning_sensitivity_manifest",
            "sensitivity_sha256": sha256_file(
                self.campaign / "sensitivity.json"
            ),
        }
        write_once(self.campaign / "manifest.json", derived_json_bytes(manifest))

    @staticmethod
    def _verified_source(**_kwargs: object) -> dict[str, object]:
        return {"status": "verified", "errors": []}

    def _generate(self) -> dict[str, object]:
        with patch(
            "fl_forensics.prototype_sensitivity_reporting.verify_prototype_sensitivity",
            side_effect=self._verified_source,
        ):
            return generate_prototype_sensitivity_report(
                source_round_workspace=Path("source"),
                trust_workspace=Path("trust"),
                partition_workspace=Path("partition"),
                sensitivity_workspace=self.campaign,
                output=self.report,
                config_path=self.config_path,
            )

    def _verify(self) -> dict[str, object]:
        with patch(
            "fl_forensics.prototype_sensitivity_reporting.verify_prototype_sensitivity",
            side_effect=self._verified_source,
        ):
            return verify_prototype_sensitivity_report(
                source_round_workspace=Path("source"),
                trust_workspace=Path("trust"),
                partition_workspace=Path("partition"),
                sensitivity_workspace=self.campaign,
                report_workspace=self.report,
                config_path=self.config_path,
            )

    def test_report_is_complete_repeatable_and_does_not_select(self) -> None:
        result = self._generate()
        self.assertEqual(result["scenario_count"], 6)
        self.assertEqual(result["row_count"], 12)
        self.assertEqual(result["figure_count"], 6)
        report = load_json(self.report / "report.json")
        self.assertFalse(report["selection_performed"])
        self.assertFalse(report["test_based_selection_permitted"])
        self.assertTrue(
            report["observations"]["descriptive_extrema_not_selection"]
        )
        self.assertEqual(len(report["artifacts"]), 8)
        self.assertEqual(
            len((self.report / "sensitivity.csv").read_text().splitlines()), 13
        )
        verification = self._verify()
        self.assertEqual(verification["status"], "verified")
        self.assertTrue(verification["source_recomputed"])

    def test_report_tampering_and_post_test_selection_are_rejected(self) -> None:
        self._generate()
        table = self.report / "sensitivity.csv"
        table.chmod(0o640)
        table.write_bytes(table.read_bytes() + b"tampered\n")
        verification = self._verify()
        self.assertEqual(verification["status"], "failed")
        self.assertTrue(
            any("sensitivity.csv" in error for error in verification["errors"])
        )

        sensitivity_path = self.campaign / "sensitivity.json"
        sensitivity = load_json(sensitivity_path)
        sensitivity["selection_performed"] = True
        sensitivity_path.chmod(0o640)
        sensitivity_path.write_bytes(derived_json_bytes(sensitivity))
        with self.assertRaises(PrototypeSensitivityReportingError):
            self._generate()


if __name__ == "__main__":
    unittest.main()
