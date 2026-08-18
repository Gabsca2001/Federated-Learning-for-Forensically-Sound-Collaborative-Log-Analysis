from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "m2_preprocessing_experiment_script",
    ROOT / "scripts" / "m2_preprocessing_experiment.py",
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import guard
    raise RuntimeError("unable to load scripts/m2_preprocessing_experiment.py")
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


@unittest.skipUnless(
    importlib.util.find_spec("numpy"),
    "optional M2 numerical dependencies are not installed",
)
class RobustFeatureTransformTests(unittest.TestCase):
    def test_log_and_winsor_bounds_are_fitted_on_training_only(self) -> None:
        import numpy as np

        from fl_forensics.robust_preprocessing import (
            apply_feature_transform,
            fit_feature_transform,
        )

        names = ["connection_count", "duration_mean", "state_sf_fraction"]
        train = np.asarray(
            [[1.0, 2.0, 0.1], [2.0, 4.0, 0.2], [3.0, 8.0, 0.3]],
            dtype=float,
        )
        specification = fit_feature_transform(
            train_features=train,
            feature_names=names,
            mode="log1p-winsor",
            lower_quantile=0.0,
            upper_quantile=1.0,
        )
        validation = np.asarray([[1000000.0, 1000000.0, 0.4]], dtype=float)
        transformed = apply_feature_transform(
            features=validation,
            feature_names=names,
            specification=specification,
        )

        self.assertEqual(specification["fitted_on_split"], "train")
        self.assertEqual(
            specification["log1p_features"],
            ["connection_count", "duration_mean"],
        )
        self.assertTrue(specification["winsorization"]["enabled"])
        self.assertTrue(np.isfinite(transformed).all())
        self.assertLess(abs(float(transformed[0, 0])), 2.0)
        self.assertLess(abs(float(transformed[0, 1])), 2.0)

    def test_standard_transform_matches_population_mean_and_scale(self) -> None:
        import numpy as np

        from fl_forensics.robust_preprocessing import (
            apply_feature_transform,
            fit_feature_transform,
        )

        names = ["feature_a", "feature_b"]
        train = np.asarray([[1.0, 5.0], [3.0, 5.0]], dtype=float)
        specification = fit_feature_transform(
            train_features=train, feature_names=names, mode="standard"
        )
        transformed = apply_feature_transform(
            features=train, feature_names=names, specification=specification
        )
        np.testing.assert_allclose(transformed[:, 0], [-1.0, 1.0])
        np.testing.assert_allclose(transformed[:, 1], [0.0, 0.0])
        self.assertEqual(specification["scale_after_transform"], [1.0, 1.0])

    def test_log_transform_rejects_negative_selected_features(self) -> None:
        import numpy as np

        from fl_forensics.robust_preprocessing import fit_feature_transform

        with self.assertRaisesRegex(ValueError, "non-negative"):
            fit_feature_transform(
                train_features=np.asarray([[-1.0], [2.0]], dtype=float),
                feature_names=["duration_mean"],
                mode="log1p",
            )


def _synthetic_workspace(root: Path) -> tuple[Path, Path]:
    import numpy as np

    dataset_workspace = root / "dataset"
    dataset_workspace.mkdir()
    feature_names = [
        "connection_count",
        "duration_mean",
        "state_sf_fraction",
    ]
    rows = []
    sizes = {"train": 16, "validation": 8, "test": 8}
    for split, size in sizes.items():
        for index in range(size):
            is_attack = index % 2 == 1
            label = "reconnaissance" if is_attack else "benign"
            base = 8.0 if is_attack else 1.0
            rows.append(
                {
                    "window_id": f"{split}-{index}",
                    "capture_id": f"{split}-capture",
                    "features": [base + index / 10, base * 2 + index, 0.8 if is_attack else 0.2],
                    "label": label,
                    "source_event_ids": [f"event-{split}-{index}"],
                    "split": split,
                }
            )
    train = np.asarray(
        [row["features"] for row in rows if row["split"] == "train"],
        dtype=float,
    )
    scales = train.std(axis=0, ddof=0)
    scales = np.where(scales == 0.0, 1.0, scales)
    (dataset_workspace / "dataset.json").write_text(
        json.dumps(
            {
                "dataset": "UWF-ZeekData24",
                "feature_names": feature_names,
                "rows": rows,
            }
        ),
        encoding="utf-8",
    )
    (dataset_workspace / "scaler.json").write_text(
        json.dumps(
            {
                "mean": train.mean(axis=0).tolist(),
                "scale": scales.tolist(),
            }
        ),
        encoding="utf-8",
    )
    config_path = root / "config.yaml"
    config_path.write_text(
        """
experiment:
  seed: 1
model:
  hidden_layers: [4]
  embedding_size: 2
  activation: relu
  regularization_alpha: 0.0001
  max_iterations: 2
  class_weighting: sqrt-balanced
federation:
  batch_size: 4
  learning_rate: 0.001
""".lstrip(),
        encoding="utf-8",
    )
    return dataset_workspace, config_path


@unittest.skipUnless(
    all(
        importlib.util.find_spec(name)
        for name in ("matplotlib", "numpy", "sklearn")
    ),
    "optional M2 experiment dependencies are not installed",
)
class PreprocessingExperimentTests(unittest.TestCase):
    def test_validation_selection_and_final_test_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dataset_workspace, config_path = _synthetic_workspace(root)
            validation_output = root / "validation"
            with patch(
                "fl_forensics.dataset24.verify_workspace",
                return_value={"status": "verified", "errors": []},
            ):
                validation_summary = EXPERIMENT.run_validation_experiment(
                    dataset_workspace=dataset_workspace,
                    config_path=config_path,
                    output=validation_output,
                    variants=["standard", "log1p", "log1p-winsor"],
                    seeds=[1, 2],
                    epochs=2,
                    lower_quantile=0.0,
                    upper_quantile=1.0,
                )

            selection = json.loads(
                (validation_output / "selection.json").read_text(encoding="utf-8")
            )
            results = json.loads(
                (validation_output / "validation_results.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(validation_summary["status"], "validation-complete")
            self.assertFalse(selection["test_observed_during_selection"])
            self.assertEqual(len(results["runs"]), 6)
            for run in results["runs"]:
                self.assertNotIn("test", run["metrics"])

            final_output = root / "final"
            with patch(
                "fl_forensics.dataset24.verify_workspace",
                return_value={"status": "verified", "errors": []},
            ):
                final_summary = EXPERIMENT.run_final_test(
                    dataset_workspace=dataset_workspace,
                    config_path=config_path,
                    output=final_output,
                    selection_path=validation_output / "selection.json",
                )
            self.assertEqual(final_summary["status"], "final-test-complete")
            self.assertEqual(
                final_summary["test_evaluated_variants"],
                [selection["selected_variant"]],
            )
            self.assertEqual(final_summary["aggregate"]["run_count"], 2)

    def test_modified_selected_transform_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dataset_workspace, config_path = _synthetic_workspace(root)
            validation_output = root / "validation"
            with patch(
                "fl_forensics.dataset24.verify_workspace",
                return_value={"status": "verified", "errors": []},
            ):
                EXPERIMENT.run_validation_experiment(
                    dataset_workspace=dataset_workspace,
                    config_path=config_path,
                    output=validation_output,
                    variants=["log1p"],
                    seeds=[1],
                    epochs=1,
                    lower_quantile=0.001,
                    upper_quantile=0.999,
                )
            selection_path = validation_output / "selection.json"
            selection = json.loads(selection_path.read_text(encoding="utf-8"))
            selection["selected_transform"]["mean_after_transform"][0] += 1.0
            modified = root / "modified-selection.json"
            modified.write_text(json.dumps(selection), encoding="utf-8")
            with patch(
                "fl_forensics.dataset24.verify_workspace",
                return_value={"status": "verified", "errors": []},
            ):
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    EXPERIMENT.run_final_test(
                        dataset_workspace=dataset_workspace,
                        config_path=config_path,
                        output=root / "final",
                        selection_path=modified,
                    )


if __name__ == "__main__":
    unittest.main()
