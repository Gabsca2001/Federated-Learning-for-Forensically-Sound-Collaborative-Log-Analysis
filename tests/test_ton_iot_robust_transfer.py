import argparse
import importlib.util
import tempfile
import unittest
from pathlib import Path

import numpy as np

from fl_forensics.preprocessing import FEATURE_NAMES

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ton_iot_robust_transfer.py"
spec = importlib.util.spec_from_file_location("ton_iot_robust_transfer", SCRIPT)
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)


def _baseline():
    return {"mean": [float(i) for i in range(25)], "scale": [float(i + 1) for i in range(25)]}


class AblationTests(unittest.TestCase):
    def test_groups_use_real_feature_names(self):
        for group, removed in rt.ABLATION_GROUPS.items():
            self.assertTrue(set(removed) <= set(FEATURE_NAMES), group)

    def test_ablation_drops_group_and_reuses_training_scaler(self):
        names = list(FEATURE_NAMES)
        raw = np.abs(np.random.default_rng(0).normal(size=(40, 25)))
        spec = rt.fit_ablation(names, "ablate-durations", raw, _baseline())
        kept = [names[i] for i in spec["indices"]]
        self.assertEqual(len(kept), 22)
        self.assertNotIn("duration_mean", kept)
        self.assertEqual(spec["transform"]["mean_after_transform"], [float(i) for i in spec["indices"]])
        out = rt.apply(raw, spec)
        self.assertEqual(out.shape, (40, 22))

    def test_unknown_variant_rejected(self):
        with self.assertRaises(ValueError):
            rt.fit_any(list(FEATURE_NAMES), "nope", np.ones((3, 25)), _baseline())


class SelectionTests(unittest.TestCase):
    def test_ablations_never_selected(self):
        means = {"standard": 0.5, "log1p": 0.6, "ablate-durations": 0.99}
        self.assertEqual(rt.select_variant(means), "log1p")

    def test_tie_break_follows_declared_order(self):
        means = {v: 0.7 for v in rt.PREPROCESSING_VARIANTS}
        self.assertEqual(rt.select_variant(means), rt.PREPROCESSING_VARIANTS[0])

    def test_round_selection_earliest_on_tie(self):
        evals = [(1, {"macro_f1_all_model_classes": 0.4}), (2, {"macro_f1_all_model_classes": 0.8}), (5, {"macro_f1_all_model_classes": 0.8})]
        self.assertEqual(rt.select_round(evals)[0], 2)


class MetricTests(unittest.TestCase):
    def test_binary_metrics_known_confusion(self):
        actual = [0, 0, 0, 1, 1, 1, 1]
        predicted = [1, 1, 0, 1, 1, 1, 0]
        scores = [0.9, 0.8, 0.1, 0.95, 0.85, 0.7, 0.2]
        m = rt.binary_metrics(actual, predicted, scores)
        self.assertEqual(m["confusion_matrix"]["values"], [[1, 2], [1, 3]])
        self.assertAlmostEqual(m["false_positive_rate"], 2 / 3)
        self.assertAlmostEqual(m["attack_recall"], 3 / 4)
        self.assertAlmostEqual(m["balanced_accuracy"], (3 / 4 + 1 / 3) / 2)

    def test_assess_standard_selection_is_negative(self):
        run = lambda v, s, ba, fpr, rec: {"variant": v, "seed": s, "ton_iot": {"occurrence": {"balanced_accuracy": ba, "false_positive_rate": fpr, "attack_recall": rec}}}
        results = {f"standard-{s}": run("standard", s, 0.7, 0.3, 0.8) for s in (1, 2, 3)}
        self.assertEqual(rt.assess("standard", results)["verdict"], "negative")


class BoundaryTests(unittest.TestCase):
    def test_evaluate_refuses_changed_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "protocol.md").write_text("frozen")
            (out / "protocol.sha256").write_text("0" * 64 + "  protocol.md\n")
            with self.assertRaises(ValueError):
                rt.evaluate_phase(argparse.Namespace(output=out))

    def test_evaluate_refuses_changed_selection(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "protocol.md").write_text("frozen")
            (out / "protocol.sha256").write_text(hashlib.sha256(b"frozen").hexdigest() + "  protocol.md\n")
            (out / "selection-before-ton-iot.json").write_text("{}")
            (out / "selection-before-ton-iot.sha256").write_text("1" * 64 + "\n")
            with self.assertRaises(ValueError):
                rt.evaluate_phase(argparse.Namespace(output=out))


if __name__ == "__main__":
    unittest.main()
