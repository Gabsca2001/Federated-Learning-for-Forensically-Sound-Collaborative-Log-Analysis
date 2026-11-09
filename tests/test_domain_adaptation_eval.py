import importlib.util
import unittest
from pathlib import Path

import numpy as np

_spec = importlib.util.spec_from_file_location(
    "domain_adaptation_eval", Path(__file__).resolve().parents[1] / "scripts/domain_adaptation_eval.py"
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class DomainAdaptationEvalTest(unittest.TestCase):
    def test_auroc_perfect_and_ties(self):
        actual = np.array([True, True, False, False])
        self.assertEqual(mod.auroc(actual, np.array([0.9, 0.8, 0.2, 0.1])), 1.0)
        self.assertEqual(mod.auroc(actual, np.array([0.5, 0.5, 0.5, 0.5])), 0.5)
        self.assertIsNone(mod.auroc(np.array([True, True]), np.array([0.1, 0.2])))

    def test_binary_metrics_counts(self):
        actual = np.array([True, True, False, False])
        predicted = np.array([True, False, True, False])
        m = mod.binary_metrics(actual, predicted, np.array([0.9, 0.1, 0.8, 0.2]))
        self.assertEqual(m["confusion_matrix"]["rows_true_benign_attack"], [[1, 1], [1, 1]])
        self.assertAlmostEqual(m["balanced_accuracy"], 0.5)
        self.assertAlmostEqual(m["false_positive_rate"], 0.5)

    def test_verdict_thresholds(self):
        self.assertEqual(mod.verdict({"balanced_accuracy": 0.75, "false_positive_rate": 0.2}), "improvement")
        self.assertEqual(mod.verdict({"balanced_accuracy": 0.75, "false_positive_rate": 0.4}), "inconclusive")
        self.assertEqual(mod.verdict({"balanced_accuracy": 0.55, "false_positive_rate": 0.1}), "negative")

    def test_baselines_are_earliest_dates(self):
        self.assertEqual(mod.BASELINE_DATES["ton_iot"], ("2019-04-02", "2019-04-03"))
        self.assertEqual(len(mod.BASELINE_DATES["data22"]), 4)


if __name__ == "__main__":
    unittest.main()
