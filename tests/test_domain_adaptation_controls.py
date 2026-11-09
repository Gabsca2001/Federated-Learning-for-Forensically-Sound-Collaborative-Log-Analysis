import importlib.util
import sys
import unittest
from pathlib import Path

import numpy as np

_scripts = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(_scripts))
_spec = importlib.util.spec_from_file_location("domain_adaptation_controls", _scripts / "domain_adaptation_controls.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class ControlsTest(unittest.TestCase):
    def test_knn_excludes_self_for_baseline(self):
        Zb = np.array([[0.0], [1.0], [2.0], [3.0], [4.0], [5.0], [6.0]])
        Z = np.vstack([Zb, [[100.0]]])
        base = np.array([True] * 7 + [False])
        s = mod.nn_scores(Zb, Z, base, k=2)
        self.assertGreater(s[0], 0.0)  # self-distance excluded
        self.assertGreater(s[-1], s[:7].max())

    def test_evaluate_uses_baseline_percentile(self):
        rng = np.random.default_rng(0)
        score = np.concatenate([rng.normal(0, 1, 1000), rng.normal(5, 1, 100), rng.normal(0, 1, 100)])
        base = np.array([True] * 1000 + [False] * 200)
        attack = np.array([False] * 1000 + [True] * 100 + [False] * 100)
        m = mod.evaluate(score, base, attack)
        self.assertAlmostEqual(m["baseline_alert_rate"], 0.01, places=2)
        self.assertGreater(m["attack_recall"], 0.9)


if __name__ == "__main__":
    unittest.main()
