from __future__ import annotations

import copy
import unittest

import numpy as np

from fl_forensics.literature_baselines import (
    fedgradtrace_global_gradient,
    flame_aggregate,
    weidetect_aggregate,
)


class LiteratureBaselineTests(unittest.TestCase):
    def test_flame_majority_clustering_clipping_and_seeded_noise(self):
        base = [np.zeros(2, dtype=np.float64)]
        models = [
            [np.asarray(value, dtype=np.float64)]
            for value in ([1.0, 1.0], [1.01, 0.99], [0.99, 1.01], [1.0, 1.02], [-10.0, -10.0])
        ]
        before = copy.deepcopy(models)
        arguments = {
            "base": base,
            "models": models,
            "client_ids": [f"c{i}" for i in range(5)],
            "noise_factor": 0.01,
        }
        first, report = flame_aggregate(**arguments, seed=7)
        self.assertEqual(report["status"], "aggregated", report)
        self.assertNotIn("c4", report["selected_client_ids"])
        self.assertEqual(report["sklearn_min_samples"], 2)
        self.assertEqual(report["equivalent_contrib_min_samples"], 1)
        self.assertGreater(report["noise_sigma"], 0)
        second, _ = flame_aggregate(**arguments, seed=7)
        another, _ = flame_aggregate(**arguments, seed=8)
        self.assertTrue(np.array_equal(first[0], second[0]))
        self.assertFalse(np.array_equal(first[0], another[0]))
        self.assertTrue(
            all(np.array_equal(old[0], new[0]) for old, new in zip(before, models, strict=True))
        )

    def test_zero_noise_is_not_silently_called_full_flame(self):
        with self.assertRaisesRegex(ValueError, "ablation"):
            flame_aggregate(
                base=[np.zeros(1)],
                models=[[np.ones(1)]] * 3,
                client_ids=["a", "b", "c"],
                noise_factor=0,
                seed=1,
            )

    def test_flame_zero_update_sensitivity_is_a_valid_limiting_case(self):
        base = [np.ones(2)]
        result, report = flame_aggregate(
            base=base,
            models=[copy.deepcopy(base) for _ in range(5)],
            client_ids=list("abcde"),
            seed=1,
        )
        self.assertEqual(report["status"], "aggregated", report)
        self.assertEqual(report["noise_sigma"], 0)
        self.assertTrue(np.array_equal(result[0], base[0]))

    def test_weidetect_selects_high_scores_and_uses_uniform_paper_average(self):
        models = [[np.asarray([value], dtype=np.float64)] for value in [1, 2, 9, 0]]
        value, report = weidetect_aggregate(
            models=models,
            client_ids=list("abcd"),
            validation_f1=[0.1, 0.2, 0.9, 0],
            keep_count=2,
            seed=1,
        )
        self.assertEqual(set(report["selected_client_ids"]), {"b", "c"})
        self.assertEqual(value[0][0], 5.5)
        self.assertEqual(report["cdf"][3], 0)
        self.assertIn("fitted", report["fit_status"])

    def test_weidetect_equal_scores_are_declared_degenerate_not_a_successful_fit(self):
        models = [[np.asarray([float(value)])] for value in range(5)]
        arguments = {
            "models": models,
            "client_ids": list("abcde"),
            "validation_f1": [0.5] * 5,
            "keep_count": 3,
            "seed": 42,
        }
        first, report = weidetect_aggregate(**arguments)
        second, retried = weidetect_aggregate(**arguments)
        self.assertIn("degenerate", report["fit_status"])
        self.assertIsNone(report["shape"])
        self.assertEqual(report["selected_client_ids"], retried["selected_client_ids"])
        self.assertTrue(np.array_equal(first[0], second[0]))

    def test_weidetect_invalid_scores_and_unknown_shape_fail(self):
        with self.assertRaises(ValueError):
            weidetect_aggregate(
                models=[[np.ones(1)], [np.ones(1)]],
                client_ids=["a", "b"],
                validation_f1=[float("nan"), 0.5],
                keep_count=1,
                seed=1,
            )

    def test_literal_fedgradtrace_equations_remain_distinct(self):
        arguments = {
            "base": [np.asarray([2.0])],
            "gradients": [[np.asarray([1.0])], [np.asarray([3.0])]],
            "gradient_histories": [np.asarray([[1.0]]), np.asarray([[3.0]])],
            "client_ids": ["a", "b"],
            "sample_counts": [1, 3],
            "learning_rate": 0.1,
        }
        eq2, report2 = fedgradtrace_global_gradient(**arguments, formula="literal_eq2")
        eq3, report3 = fedgradtrace_global_gradient(**arguments, formula="literal_eq3")
        self.assertAlmostEqual(eq2[0][0], 4.3)
        self.assertAlmostEqual(eq3[0][0], 1.75)
        self.assertAlmostEqual(report2["coefficient_sum"], 2.5)
        self.assertAlmostEqual(report3["coefficient_sum"], 1.0)
        self.assertFalse(report3["local_final_updates_used_as_gradient_substitutes"])

    def test_live_gradient_history_cannot_be_replaced_by_unrelated_vectors(self):
        with self.assertRaisesRegex(ValueError, "actual current"):
            fedgradtrace_global_gradient(
                base=[np.asarray([2.0])],
                gradients=[[np.asarray([1.0])]],
                gradient_histories=[np.asarray([[9.0]])],
                client_ids=["a"],
                sample_counts=[2],
                learning_rate=0.1,
                formula="literal_eq3",
            )

    def test_literal_eq3_zero_denominator_is_not_an_invented_average(self):
        with self.assertRaisesRegex(ValueError, "zero trajectory denominator"):
            fedgradtrace_global_gradient(
                base=[np.asarray([2.0])],
                gradients=[[np.asarray([0.0])]],
                gradient_histories=[np.asarray([[0.0]])],
                client_ids=["a"],
                sample_counts=[2],
                learning_rate=0.1,
                formula="literal_eq3",
            )

    def test_tensor_schema_nonfinite_and_duplicate_identity_are_rejected(self):
        for models, ids in (
            ([[np.ones(1)], [np.ones(2)], [np.ones(1)]], list("abc")),
            ([[np.ones(1)]] * 3, ["a", "a", "c"]),
            ([[np.asarray([float("inf")])]] * 3, list("abc")),
        ):
            with self.assertRaises(ValueError):
                flame_aggregate(base=[np.zeros(1)], models=models, client_ids=ids, seed=1)
