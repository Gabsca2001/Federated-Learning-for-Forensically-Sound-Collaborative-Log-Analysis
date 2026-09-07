from __future__ import annotations

import unittest

from fl_forensics.composite_admission import (
    CompositeAdmissionError,
    apply_controlled_trust_failure,
    build_indicator_references,
    calibrate_policy_thresholds,
    decide_admission_policies,
    score_statistical_indicators,
    trust_signal_from_checks,
)

DIRECTIONS = {
    "relative_norm": "higher",
    "cosine_to_median": "lower",
    "coordinate_median_distance": "higher",
    "mad_score": "higher",
    "validation_impact": "higher",
}
WEIGHTS = {name: 1.0 for name in DIRECTIONS}


def indicator(client_id: str, offset: float = 0.0) -> dict[str, float | str]:
    return {
        "client_id": client_id,
        "relative_norm": 1.0 + offset,
        "cosine_to_median": 0.98 - offset,
        "coordinate_median_distance": 0.20 + offset,
        "mad_score": 0.10 + offset,
        "validation_impact": 0.01 + offset,
    }


def checks(*, fresh: bool = True) -> list[dict[str, object]]:
    return [
        {"name": "active_enrollment", "passed": True, "detail": "active"},
        {"name": "tpm_esk_signature", "passed": True, "detail": "valid"},
        {
            "name": "fresh_attestation",
            "passed": fresh,
            "detail": "fresh" if fresh else "expired",
        },
    ]


class CompositeAdmissionSignalTests(unittest.TestCase):
    def test_clean_reference_and_outlier_scoring_are_deterministic(self) -> None:
        clean = [
            indicator("client01", -0.02),
            indicator("client02", -0.01),
            indicator("client03", 0.00),
            indicator("client04", 0.01),
            indicator("client05", 0.02),
        ]
        references = build_indicator_references(clean, directions=DIRECTIONS)
        candidates = [indicator("benign", 0.0), indicator("outlier", 5.0)]
        first = score_statistical_indicators(
            candidates,
            references=references,
            weights=WEIGHTS,
            z_cap=3.0,
        )
        second = score_statistical_indicators(
            candidates,
            references=references,
            weights=WEIGHTS,
            z_cap=3.0,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["benign"].risk, 0.0)
        self.assertEqual(first["outlier"].risk, 1.0)
        self.assertEqual(
            [item.name for item in first["outlier"].components], sorted(DIRECTIONS)
        )

    def test_low_cosine_is_treated_as_adverse(self) -> None:
        clean = [indicator(f"client{index:02d}", index / 1000) for index in range(1, 6)]
        references = build_indicator_references(clean, directions=DIRECTIONS)
        candidate = indicator("client99", 0.0)
        candidate["cosine_to_median"] = -0.8
        signal = score_statistical_indicators(
            [candidate], references=references, weights=WEIGHTS
        )["client99"]
        by_name = {item.name: item for item in signal.components}
        self.assertEqual(by_name["cosine_to_median"].component_risk, 1.0)
        self.assertGreater(signal.risk, 0.0)

    def test_invalid_or_duplicate_inputs_fail_closed(self) -> None:
        duplicate = [indicator("client01"), indicator("client01", 0.1)]
        with self.assertRaisesRegex(CompositeAdmissionError, "unique"):
            build_indicator_references(duplicate, directions=DIRECTIONS)
        references = build_indicator_references(
            [indicator("client01"), indicator("client02", 0.1)],
            directions=DIRECTIONS,
        )
        invalid = indicator("client03")
        invalid["relative_norm"] = float("nan")
        with self.assertRaisesRegex(CompositeAdmissionError, "finite"):
            score_statistical_indicators(
                [invalid], references=references, weights=WEIGHTS
            )


class CompositeAdmissionPolicyTests(unittest.TestCase):
    def test_thresholds_are_calibrated_without_candidate_labels(self) -> None:
        clean = [
            self._statistics(risk).model_copy(
                update={"client_id": f"client{index:02d}"}
            )
            for index, risk in enumerate((0.10, 0.20, 0.70), start=1)
        ]
        thresholds = calibrate_policy_thresholds(
            clean,
            trust_weight=0.50,
            statistical_margin=0.05,
            composite_margin=0.025,
            downweight_quantile=0.90,
        )
        self.assertAlmostEqual(thresholds.statistical_threshold, 0.75)
        self.assertAlmostEqual(thresholds.composite_threshold, 0.375)
        self.assertAlmostEqual(thresholds.composite_downweight_threshold, 0.30)
        self.assertEqual(thresholds.clean_sample_count, 3)

    def _statistics(self, risk: float):
        clean = [indicator("client01", -0.01), indicator("client02", 0.01)]
        references = build_indicator_references(clean, directions=DIRECTIONS)
        signal = score_statistical_indicators(
            [indicator("candidate")], references=references, weights=WEIGHTS
        )["candidate"]
        return signal.model_copy(update={"risk": risk})

    def _decide(self, *, trust, risk: float):
        return {
            item.policy: item
            for item in decide_admission_policies(
                trust=trust,
                statistics=self._statistics(risk),
                statistical_threshold=0.60,
                composite_threshold=0.55,
                composite_downweight_threshold=0.35,
                trust_weight=0.50,
            )
        }

    def test_attested_anomalous_update_surfaces_policy_disagreement(self) -> None:
        trust = trust_signal_from_checks(checks(), raw_status="passed")
        decisions = self._decide(trust=trust, risk=0.9)
        self.assertEqual(decisions["tpm_only"].status, "accepted")
        self.assertEqual(
            decisions["statistics_only"].status, "statistically_quarantined"
        )
        self.assertEqual(
            decisions["sequential"].status, "statistically_quarantined"
        )
        self.assertEqual(decisions["gated_composite"].status, "accepted_downweighted")

    def test_unattested_normal_update_cannot_bypass_the_gated_policy(self) -> None:
        trust = trust_signal_from_checks(
            checks(fresh=False), raw_status="failed_measurement"
        )
        decisions = self._decide(trust=trust, risk=0.0)
        self.assertEqual(decisions["statistics_only"].status, "accepted")
        self.assertEqual(decisions["tpm_only"].status, "trust_quarantined")
        self.assertEqual(decisions["sequential"].status, "trust_quarantined")
        self.assertEqual(decisions["gated_composite"].status, "trust_quarantined")
        self.assertIn(
            "hard trust veto",
            " ".join(decisions["gated_composite"].reasons),
        )

    def test_controlled_trust_failure_preserves_observed_signal(self) -> None:
        observed = trust_signal_from_checks(checks(), raw_status="passed")
        controlled = apply_controlled_trust_failure(
            observed,
            failed_check="fresh_attestation",
            reason="controlled stale Quote",
        )
        self.assertTrue(observed.admissible)
        self.assertEqual(observed.failed_checks, [])
        self.assertFalse(controlled.admissible)
        self.assertEqual(controlled.risk, 1.0)
        self.assertEqual(controlled.failed_checks, ["fresh_attestation"])
        with self.assertRaisesRegex(CompositeAdmissionError, "not evaluated"):
            apply_controlled_trust_failure(
                observed,
                failed_check="unknown",
                reason="controlled failure",
            )

    def test_warning_is_preserved_as_nonzero_trust_risk(self) -> None:
        trust = trust_signal_from_checks(
            checks(), raw_status="passed_with_warning", passed_with_warning_risk=0.25
        )
        self.assertTrue(trust.admissible)
        self.assertEqual(trust.risk, 0.25)
        decisions = self._decide(trust=trust, risk=0.5)
        self.assertEqual(decisions["gated_composite"].status, "accepted_downweighted")

    def test_invalid_policy_thresholds_are_rejected(self) -> None:
        trust = trust_signal_from_checks(checks(), raw_status="passed")
        with self.assertRaisesRegex(CompositeAdmissionError, "cannot exceed"):
            decide_admission_policies(
                trust=trust,
                statistics=self._statistics(0.0),
                statistical_threshold=0.60,
                composite_threshold=0.30,
                composite_downweight_threshold=0.40,
                trust_weight=0.50,
            )


if __name__ == "__main__":
    unittest.main()
