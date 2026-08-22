from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fl_forensics.config import load_yaml
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.prototype_sensitivity import (
    PrototypeSensitivityError,
    _campaign_plan,
    _effective_config,
    _strategy_record,
    plan_prototype_sensitivity,
    run_prototype_sensitivity,
)
from fl_forensics.storage import load_json, write_once

ROOT = Path(__file__).resolve().parents[1]


class PrototypeSensitivityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config, self.config_digest = load_yaml(
            ROOT / "configs" / "byzantine-prototype-sensitivity.yaml"
        )

    def test_one_factor_design_has_six_cells_and_nested_attackers(self) -> None:
        plan = _campaign_plan(self.config)
        self.assertEqual(
            [(item["f"], item["scale"]) for item in plan],
            [
                (1, 1.5),
                (2, 1.5),
                (3, 0.5),
                (3, 1.0),
                (3, 1.5),
                (3, 2.0),
            ],
        )
        self.assertEqual(plan[0]["attacker_ids"], ["client02"])
        self.assertEqual(plan[1]["attacker_ids"], ["client02", "client05"])
        self.assertEqual(
            plan[-1]["attacker_ids"], ["client02", "client05", "client14"]
        )
        primary = [item for item in plan if item["primary_anchor"]]
        self.assertEqual([item["scenario_id"] for item in primary], ["f3-scale-1p5"])
        public_plan = plan_prototype_sensitivity(
            config_path=ROOT / "configs" / "byzantine-prototype-sensitivity.yaml"
        )
        self.assertEqual(public_plan["scenario_count"], 6)
        self.assertEqual(public_plan["scenarios"], plan)
        self.assertFalse(public_plan["test_data_accessed"])
        self.assertFalse(public_plan["selection_performed"])

    def test_effective_config_binds_campaign_and_disables_selection(self) -> None:
        scenario = _campaign_plan(self.config)[0]
        effective = _effective_config(
            self.config,
            campaign_config_sha256=self.config_digest,
            scenario=scenario,
        )
        self.assertNotIn("sensitivity", effective)
        self.assertEqual(effective["attack"]["scale"], 1.5)
        binding = effective["experiment"]["sensitivity"]
        self.assertEqual(binding["campaign_config_sha256"], self.config_digest)
        self.assertFalse(binding["test_based_selection_permitted"])

        invalid = copy.deepcopy(self.config)
        invalid["sensitivity"]["test_based_selection_permitted"] = True
        with self.assertRaises(PrototypeSensitivityError):
            _campaign_plan(invalid)

    def test_strategy_record_preserves_targeted_and_untargeted_impact(self) -> None:
        strategy = "support_weighted_mean"
        comparison = {
            "attack_effects": [
                {
                    "aggregation_strategy": strategy,
                    "source_prototype_shift_l2": 5.0,
                    "validation_macro_f1_delta": 0.01,
                    "test_macro_f1_delta": 0.02,
                    "validation_source_recall_delta": -0.15,
                    "test_source_recall_delta": -0.2,
                    "test_source_misclassification_rate_delta": 0.2,
                    "test_attack_success_rate_delta": 0.0,
                }
            ],
            "outcomes": [
                {
                    "condition": "clean",
                    "aggregation_strategy": strategy,
                    "metrics": {
                        "test": {"macro_f1_all_model_classes": 0.75}
                    },
                    "source_class_integrity": {
                        "test": {
                            "source_recall": 1.0,
                            "targeted_attack_success_rate": 0.0,
                            "other_class_misclassification_rate": 0.0,
                        }
                    },
                },
                {
                    "condition": "attacked",
                    "aggregation_strategy": strategy,
                    "metrics": {
                        "test": {"macro_f1_all_model_classes": 0.77}
                    },
                    "source_class_integrity": {
                        "test": {
                            "source_recall": 0.8,
                            "targeted_attack_success_rate": 0.0,
                            "other_class_misclassification_rate": 0.2,
                        }
                    },
                },
            ],
        }
        record = _strategy_record(comparison, strategy=strategy)
        self.assertEqual(record["test_source_recall_delta"], -0.2)
        self.assertEqual(record["attacked_test_targeted_attack_success_rate"], 0.0)
        self.assertEqual(
            record["attacked_test_other_class_misclassification_rate"], 0.2
        )

    @staticmethod
    def _fake_comparison() -> dict[str, object]:
        outcomes = []
        effects = []
        for strategy in ("support_weighted_mean", "coordinate_median"):
            for condition, recall in (("clean", 1.0), ("attacked", 0.8)):
                outcomes.append(
                    {
                        "condition": condition,
                        "aggregation_strategy": strategy,
                        "metrics": {
                            "test": {"macro_f1_all_model_classes": 0.75}
                        },
                        "source_class_integrity": {
                            "test": {
                                "source_recall": recall,
                                "targeted_attack_success_rate": 0.0,
                                "other_class_misclassification_rate": 1.0 - recall,
                            }
                        },
                    }
                )
            effects.append(
                {
                    "aggregation_strategy": strategy,
                    "source_prototype_shift_l2": 1.0,
                    "validation_macro_f1_delta": 0.0,
                    "test_macro_f1_delta": 0.0,
                    "validation_source_recall_delta": -0.2,
                    "test_source_recall_delta": -0.2,
                    "test_source_misclassification_rate_delta": 0.2,
                    "test_attack_success_rate_delta": 0.0,
                }
            )
        return {
            "schema_version": "1.1",
            "outcomes": outcomes,
            "attack_effects": effects,
        }

    def test_runner_preserves_every_cell_without_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "campaign"

            def fake_freeze(**kwargs: object) -> dict[str, object]:
                frozen = Path(kwargs["output"])
                write_once(
                    frozen / "manifest.json",
                    derived_json_bytes({"artifact_type": "test-frozen"}),
                )
                return {"status": "frozen"}

            def fake_compare(**kwargs: object) -> dict[str, object]:
                comparison_output = Path(kwargs["output"])
                write_once(
                    comparison_output / "comparison.json",
                    derived_json_bytes(self._fake_comparison()),
                )
                return {"status": "compared"}

            with (
                patch(
                    "fl_forensics.prototype_sensitivity.freeze_prototype_scenario",
                    side_effect=fake_freeze,
                ) as freeze_mock,
                patch(
                    "fl_forensics.prototype_sensitivity.run_prototype_comparison",
                    side_effect=fake_compare,
                ) as compare_mock,
            ):
                result = run_prototype_sensitivity(
                    source_round_workspace=Path("source"),
                    trust_workspace=Path("trust"),
                    partition_workspace=Path("partition"),
                    output=output,
                    config_path=(
                        ROOT / "configs" / "byzantine-prototype-sensitivity.yaml"
                    ),
                )
            self.assertEqual(result["scenario_count"], 6)
            self.assertEqual(freeze_mock.call_count, 6)
            self.assertEqual(compare_mock.call_count, 6)
            summary = load_json(output / "sensitivity.json")
            self.assertEqual(len(summary["scenarios"]), 6)
            self.assertFalse(summary["selection_performed"])
            self.assertFalse(summary["test_based_selection_permitted"])


if __name__ == "__main__":
    unittest.main()
