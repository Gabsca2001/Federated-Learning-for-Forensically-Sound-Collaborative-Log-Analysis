from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from pydantic import ValidationError

from fl_forensics.in_round_admission import (
    SUPPORTED_LEGACY_IN_ROUND_IMPLEMENTATION_SHA256,
)
from fl_forensics.live_contribution_explanation import (
    LiveContributionExplanationError,
    _counterfactual,
    _settings,
    verify_live_contribution_explanation_bundle,
)
from fl_forensics.live_contribution_explanation_models import (
    LiveContributionDecisionExplanation,
    LiveContributionExplanationsPayload,
)


def decision(*, trust_admissible: bool) -> SimpleNamespace:
    return SimpleNamespace(
        core=SimpleNamespace(
            trust=SimpleNamespace(admissible=trust_admissible),
        )
    )


class LiveCounterfactualTests(unittest.TestCase):
    def test_hard_trust_veto_cannot_be_compensated_by_statistics(self) -> None:
        result = _counterfactual(
            decision(trust_admissible=False),
            composite_score=0.9,
            downweight_threshold=0.4,
            quarantine_threshold=0.7,
            trust_weight=0.35,
        )
        self.assertTrue(result.trust_remediation_required)
        self.assertIsNone(result.composite_reduction_for_nonzero_weight)
        self.assertIsNone(result.statistical_reduction_for_full_weight)
        self.assertIn("no statistical-score reduction", result.interpretation)

    def test_admissible_trust_has_exact_score_level_margins(self) -> None:
        result = _counterfactual(
            decision(trust_admissible=True),
            composite_score=0.8,
            downweight_threshold=0.4,
            quarantine_threshold=0.7,
            trust_weight=0.25,
        )
        self.assertFalse(result.trust_remediation_required)
        self.assertAlmostEqual(result.composite_reduction_for_nonzero_weight, 0.1)
        self.assertAlmostEqual(result.composite_reduction_for_full_weight, 0.4)
        self.assertAlmostEqual(
            result.statistical_reduction_for_nonzero_weight, 0.1 / 0.75
        )
        self.assertAlmostEqual(
            result.statistical_reduction_for_full_weight, 0.4 / 0.75
        )


class LiveExplanationContractTests(unittest.TestCase):
    def test_payload_rejects_noncanonical_or_duplicate_slots(self) -> None:
        later = LiveContributionDecisionExplanation.model_construct(
            round_number=2, client_id="client01"
        )
        earlier = LiveContributionDecisionExplanation.model_construct(
            round_number=1, client_id="client01"
        )
        with self.assertRaisesRegex(ValidationError, "slots"):
            LiveContributionExplanationsPayload(explanations=[later, earlier])
        with self.assertRaisesRegex(ValidationError, "slots"):
            LiveContributionExplanationsPayload(explanations=[earlier, earlier])

    def test_missing_bundle_fails_closed_without_source_recomputation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = verify_live_contribution_explanation_bundle(
                workspace=Path(temporary),
                campaign_workspace=Path("unused-campaign"),
                trust_workspace=Path("unused-trust"),
                partition_workspace=Path("unused-partition"),
                config_path=Path("unused-config"),
            )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_count"], 1)
        self.assertIn("missing live explanation files", result["errors"][0])

    def test_configuration_rejects_unsafe_interpretation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.yaml"
            path.write_text(
                """schema_version: \"1.0\"
experiment:
  id: test-live-explanations
  expected_source_experiment_id: test-source
live_contribution_explanations:
  expected_round_count: 1
  expected_client_count: 1
  primary_policy: gated_composite
  top_tensor_drivers: 1
  require_complete_disagreement_verification: true
  interpretation:
    attack_labels_used: true
    test_data_used: false
    hard_trust_veto_is_explainable_not_compensable: true
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                LiveContributionExplanationError, "unsafe live-explanation policy"
            ):
                _settings(path)

    def test_legacy_implementation_compatibility_is_an_explicit_allowlist(self) -> None:
        self.assertEqual(len(SUPPORTED_LEGACY_IN_ROUND_IMPLEMENTATION_SHA256), 3)
        self.assertNotIn("0" * 64, SUPPORTED_LEGACY_IN_ROUND_IMPLEMENTATION_SHA256)


if __name__ == "__main__":
    unittest.main()
