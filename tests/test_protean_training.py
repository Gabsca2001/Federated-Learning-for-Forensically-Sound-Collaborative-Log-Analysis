from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from fl_forensics.config import load_yaml
from fl_forensics.federated_model import build_model, dependencies, seed_everything
from fl_forensics.protean_training import (
    PROTEAN_CANDIDATE_SELECTION_POLICY,
    _contains_forbidden_evaluation_split,
    _evaluate_prototype_rows,
    _select_candidate_checkpoint,
)

ROOT = Path(__file__).resolve().parents[1]
NUMERICAL_STACK = all(
    importlib.util.find_spec(name) for name in ("numpy", "sklearn", "torch")
)


class ProteanCandidatePolicyTests(unittest.TestCase):
    def test_config_enforces_validation_only_candidate_selection(self) -> None:
        config, _digest = load_yaml(ROOT / "configs" / "federation-protean.yaml")

        self.assertEqual(
            config["training"]["checkpoint_selection"],
            PROTEAN_CANDIDATE_SELECTION_POLICY,
        )
        lambda_selection = config["protean"]["objective"][
            "prototype_alignment_weight_selection"
        ]
        self.assertEqual(lambda_selection["split"], "validation")
        self.assertEqual(
            lambda_selection["test_policy"],
            "never_used_for_hyperparameter_selection",
        )

    def test_selection_uses_prototype_macro_f1_and_earliest_tie(self) -> None:
        history = [
            {
                "round": 1,
                "validation": {
                    "nearest_global_prototype": {
                        "macro_f1_all_model_classes": 0.7
                    }
                },
            },
            {
                "round": 2,
                "validation": {
                    "nearest_global_prototype": {
                        "macro_f1_all_model_classes": 0.9
                    }
                },
            },
            {
                "round": 3,
                "validation": {
                    "nearest_global_prototype": {
                        "macro_f1_all_model_classes": 0.9
                    }
                },
            },
        ]

        self.assertEqual(_select_candidate_checkpoint(history)["round"], 2)

    def test_forbidden_split_detection_is_recursive(self) -> None:
        self.assertFalse(
            _contains_forbidden_evaluation_split(
                {"validation": {"classification_head": {"accuracy": 1.0}}}
            )
        )
        self.assertTrue(
            _contains_forbidden_evaluation_split(
                {"selected": [{"nested": {"test": {"accuracy": 1.0}}}]}
            )
        )


@unittest.skipUnless(
    NUMERICAL_STACK,
    "optional federated numerical dependencies are not installed",
)
class ProteanCandidateEvaluationTests(unittest.TestCase):
    def test_nearest_prototype_evaluation_has_metrics_without_row_embeddings(self) -> None:
        import numpy as np
        import torch

        seed_everything(17, torch=torch, np=np)
        model = build_model(
            input_features=2,
            class_count=2,
            hidden_layers=[4, 4],
            embedding_size=2,
            dropout=0.0,
            torch=torch,
        )
        with torch.no_grad():
            for parameter in model.parameters():
                parameter.zero_()
            model.encoder[0].weight.copy_(
                torch.tensor(
                    [[1.0, 0.0], [0.0, 1.0], [0.0, 0.0], [0.0, 0.0]]
                )
            )
            model.encoder[2].weight.copy_(
                torch.tensor(
                    [
                        [1.0, 0.0, 0.0, 0.0],
                        [0.0, 1.0, 0.0, 0.0],
                        [0.0, 0.0, 0.0, 0.0],
                        [0.0, 0.0, 0.0, 0.0],
                    ]
                )
            )
            model.encoder[4].weight.copy_(
                torch.tensor([[1.0, 0.0, 0.0, 0.0], [0.0, 1.0, 0.0, 0.0]])
            )
        rows = [
            {"features": [1.0, 0.0], "label": "benign"},
            {"features": [0.0, 1.0], "label": "attack"},
        ]
        result = _evaluate_prototype_rows(
            model=model,
            rows=rows,
            class_names=["benign", "attack"],
            global_prototypes={"benign": [1.0, 0.0], "attack": [0.0, 1.0]},
            batch_size=2,
            dependency_values=dependencies(),
        )

        self.assertEqual(result["accuracy"], 1.0)
        self.assertEqual(result["macro_f1_all_model_classes"], 1.0)
        self.assertIsNone(result["loss"])
        self.assertEqual(result["prototype_distance"]["unavailable_classes"], [])
        self.assertNotIn("row_embeddings", result)


if __name__ == "__main__":
    unittest.main()
