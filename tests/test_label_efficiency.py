import importlib.util
import sys
import unittest
from pathlib import Path

import numpy as np

_scripts = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(_scripts))
_spec = importlib.util.spec_from_file_location("label_efficiency", _scripts / "label_efficiency.py")
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _row(t, types):
    return {"window_start_epoch": t, "source_type_counts": types}


class LabelEfficiencyTest(unittest.TestCase):
    def test_split_is_within_family_chronological_with_purge(self):
        rows = [_row(i * 60, {"normal": 1}) for i in range(100)] + [_row(10_000 + i * 60, {"dos": 1}) for i in range(10)]
        pool, test = mod.split(rows)
        self.assertFalse((pool & test).any())
        ben = np.arange(100)
        first_test = min(rows[i]["window_start_epoch"] for i in ben if test[i])
        self.assertTrue(all(rows[i]["window_start_epoch"] <= first_test - 3600 for i in ben if pool[i]))
        self.assertEqual(int(test[:100].sum()), 30)
        self.assertEqual(int(test[100:].sum()), 3)

    def test_sample_is_balanced_and_deterministic(self):
        y = np.array([0] * 50 + [1] * 50)
        idx = np.arange(100)
        a = mod.sample(idx, y, 16, 0)
        b = mod.sample(idx, y, 16, 0)
        self.assertTrue((a == b).all())
        self.assertEqual(int((y[a] == 0).sum()), 8)
        self.assertEqual(len(mod.sample(idx, y, "all", 0)), 100)

    def test_family_labels(self):
        self.assertEqual(mod.family({"source_type_counts": {"normal": 3}}), "benign")
        self.assertEqual(mod.family({"source_type_counts": {"normal": 1, "dos": 2}}), "dos")
        self.assertEqual(mod.family({"source_type_counts": {"dos": 1, "xss": 1}}), "mixed")


if __name__ == "__main__":
    unittest.main()
