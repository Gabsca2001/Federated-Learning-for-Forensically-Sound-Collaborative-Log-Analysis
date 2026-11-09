"""Independent mechanism properties and counterexamples for admission claims."""
from fractions import Fraction
import math
import unittest

from fl_forensics.composite_admission import decide_admission_policies, score_statistical_indicators
from fl_forensics.composite_admission_models import IndicatorReference, StatisticalSignal, TrustSignal


TAU = 0.8183094063145846
DOWN = 0.2748970485340289


def decisions(risk, *, trust_risk=0.0, admissible=True, weight=0.5, limit=TAU/2):
    trust = TrustSignal(raw_status="passed" if admissible else "failed_measurement",
                        admissible=admissible, risk=trust_risk,
                        evaluated_checks=[], failed_checks=[], reasons=[])
    stats = StatisticalSignal(client_id="candidate", risk=risk, components=[])
    return {d.policy: d for d in decide_admission_policies(
        trust=trust, statistics=stats, statistical_threshold=TAU,
        composite_threshold=limit, composite_downweight_threshold=min(DOWN, limit),
        trust_weight=weight)}


class GateMechanismProperties(unittest.TestCase):
    def test_hard_veto_cannot_be_compensated(self):
        for index in range(1001):
            for policy in ("tpm_only", "sequential", "gated_composite"):
                self.assertFalse(decisions(index/1000, admissible=False, trust_risk=1)[policy].contributes)

    def test_actual_scaled_thresholds_have_same_support_including_adjacent_floats(self):
        values = [i/10000 for i in range(10001)]
        values += [math.nextafter(TAU, 0), TAU, math.nextafter(TAU, 1)]
        for risk in values:
            outcomes = decisions(risk)
            self.assertEqual(outcomes["sequential"].contributes, outcomes["gated_composite"].contributes)
        self.assertTrue(decisions(TAU)["sequential"].contributes)
        self.assertFalse(decisions(math.nextafter(TAU, 1))["sequential"].contributes)

    def test_composite_weight_is_irrelevant_when_thresholds_are_scaled_and_trust_zero(self):
        # Binary-exact weights avoid pretending arbitrary real and float boundaries coincide.
        for weight in (0.0, 0.25, 0.5, 0.75):
            for risk in (0.1, 0.6, 0.8, 0.9, 1.0):
                result = decisions(risk, weight=weight, limit=(1-weight)*TAU)
                self.assertEqual(result["sequential"].contributes, result["gated_composite"].contributes)

    def test_admissible_warning_changes_composite_boundary(self):
        result = decisions(0.7, trust_risk=0.25)
        self.assertTrue(result["sequential"].contributes)
        self.assertFalse(result["gated_composite"].contributes)

    def test_degenerate_all_trust_weight_cannot_use_statistics(self):
        self.assertEqual(decisions(0, weight=1, limit=0)["gated_composite"].status,
                         decisions(1, weight=1, limit=0)["gated_composite"].status)

    def test_any_zero_indicator_prevents_statistical_quarantine_under_current_threshold(self):
        refs = {str(i): IndicatorReference(name=str(i), direction="higher", median=0, mad=1, sample_count=15)
                for i in range(5)}
        for zero in range(5):
            row = {"client_id": "candidate", **{str(i): 0 if i == zero else 100 for i in range(5)}}
            stats = score_statistical_indicators([row], references=refs, weights={n: 1 for n in refs})["candidate"]
            self.assertAlmostEqual(stats.risk, 0.8)
            self.assertTrue(decisions(stats.risk)["sequential"].contributes)
            self.assertEqual(decisions(stats.risk)["gated_composite"].status, "accepted_downweighted")

    def test_downweighting_does_not_imply_lower_attacker_share(self):
        # Three equal-sized attackers among 15 clients. Reducing benign masses
        # more strongly can increase adversarial normalized participation.
        original = Fraction(3, 15)
        all_downweighted = (3*Fraction(1, 2))/(15*Fraction(1, 2))
        benign_only_downweighted = Fraction(3)/(3+12*Fraction(1, 2))
        attacker_only_downweighted = (3*Fraction(1, 2))/(12+3*Fraction(1, 2))
        self.assertEqual(all_downweighted, original)
        self.assertGreater(benign_only_downweighted, original)
        self.assertLess(attacker_only_downweighted, original)

    def test_halving_one_nominal_mass_does_not_halve_its_normalized_coefficient(self):
        before = Fraction(1, 15)
        after = Fraction(1, 2)/(14+Fraction(1, 2))
        self.assertEqual(after/before, Fraction(15, 29))
        self.assertNotEqual(after, before/2)


if __name__ == "__main__":
    unittest.main()
