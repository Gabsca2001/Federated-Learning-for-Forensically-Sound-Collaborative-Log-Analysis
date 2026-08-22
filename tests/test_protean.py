from __future__ import annotations

import importlib.util
import unittest

from fl_forensics.federated_model import build_model, model_to_ndarrays, seed_everything
from fl_forensics.protean import (
    aggregate_global_prototypes,
    available_prototype_values,
    extract_local_prototypes,
    nearest_prototype_predictions,
    train_local_protean,
)

NUMERICAL_STACK = all(importlib.util.find_spec(name) for name in ("numpy", "torch"))


@unittest.skipUnless(
    NUMERICAL_STACK,
    "optional federated numerical dependencies are not installed",
)
class ProteanCoreTests(unittest.TestCase):
    @staticmethod
    def _rows() -> list[dict[str, object]]:
        return [
            {
                "window_id": f"row-{index}",
                "features": [float(index % 2), float((index // 2) % 2)],
                "label": "benign" if index < 8 else "attack",
            }
            for index in range(16)
        ]

    @staticmethod
    def _model(*, seed: int, torch: object, np: object) -> object:
        seed_everything(seed, torch=torch, np=np)
        return build_model(
            input_features=2,
            class_count=2,
            hidden_layers=[8, 4],
            embedding_size=2,
            dropout=0.0,
            torch=torch,
        )

    def test_three_term_training_is_deterministic_and_auditable(self) -> None:
        import numpy as np
        import torch

        states = []
        recorded = []
        for _run in range(2):
            model = self._model(seed=77, torch=torch, np=np)
            metrics = train_local_protean(
                model=model,
                rows=self._rows(),
                class_names=["benign", "attack"],
                class_weights={"benign": 1.0, "attack": 1.0},
                global_prototypes={"benign": [0.0, 0.0], "attack": [1.0, 1.0]},
                prototype_alignment_weight=0.05,
                proximal_weight=0.1,
                minimum_local_support=2,
                epochs=2,
                batch_size=4,
                learning_rate=0.01,
                seed=77,
                device_name="cpu",
                torch=torch,
                np=np,
            )
            states.append(model_to_ndarrays(model, np=np))
            recorded.append(metrics)

        self.assertEqual(recorded[0], recorded[1])
        for left, right in zip(states[0], states[1], strict=True):
            self.assertTrue(np.array_equal(left, right))
        metrics = recorded[0]
        self.assertEqual(metrics["num_examples"], 16)
        self.assertEqual(metrics["optimizer_steps"], 8)
        self.assertEqual(metrics["prototype_alignment_weight"], 0.05)
        self.assertEqual(metrics["proximal_weight"], 0.1)
        self.assertGreater(metrics["prototype_aligned_class_terms"], 0)
        self.assertGreater(metrics["prototype_alignment_loss"], 0.0)
        self.assertGreater(metrics["proximal_penalty"], 0.0)
        self.assertFalse(metrics["first_round_without_prototypes"])

    def test_first_round_has_no_prototype_alignment(self) -> None:
        import numpy as np
        import torch

        model = self._model(seed=91, torch=torch, np=np)
        metrics = train_local_protean(
            model=model,
            rows=self._rows(),
            class_names=["benign", "attack"],
            class_weights={"benign": 1.0, "attack": 1.0},
            global_prototypes=None,
            prototype_alignment_weight=1.0,
            proximal_weight=0.1,
            minimum_local_support=2,
            epochs=1,
            batch_size=4,
            learning_rate=0.01,
            seed=91,
            device_name="cpu",
            torch=torch,
            np=np,
        )

        self.assertTrue(metrics["first_round_without_prototypes"])
        self.assertEqual(metrics["received_global_prototype_classes"], [])
        self.assertEqual(metrics["prototype_aligned_class_terms"], 0)
        self.assertEqual(metrics["prototype_alignment_loss"], 0.0)

    def test_extraction_records_support_without_row_embeddings(self) -> None:
        import numpy as np
        import torch

        model = self._model(seed=7, torch=torch, np=np)
        artifact = extract_local_prototypes(
            model=model,
            rows=self._rows(),
            class_names=["benign", "attack"],
            minimum_local_support=5,
            batch_size=4,
            device_name="cpu",
            torch=torch,
            np=np,
        )

        self.assertEqual(artifact["class_support"], {"benign": 8, "attack": 8})
        self.assertEqual(set(artifact["prototypes"]), {"benign", "attack"})
        for prototype in artifact["prototypes"].values():
            self.assertEqual(prototype["support"], 8)
            self.assertEqual(len(prototype["values"]), 2)
        self.assertNotIn("row_embeddings", artifact)

    def test_quorum_aggregates_or_retains_previous_prototype(self) -> None:
        import numpy as np

        submissions = [
            {
                "client_id": "client01",
                "prototypes": {
                    "benign": {"support": 2, "values": [0.0, 0.0]},
                    "attack": {"support": 2, "values": [1.0, 1.0]},
                },
            },
            {
                "client_id": "client02",
                "prototypes": {
                    "benign": {"support": 4, "values": [2.0, 2.0]},
                    "attack": {"support": 2, "values": [2.0, 2.0]},
                },
            },
            {
                "client_id": "client03",
                "prototypes": {
                    "benign": {"support": 6, "values": [4.0, 4.0]},
                },
            },
        ]
        result = aggregate_global_prototypes(
            submissions=submissions,
            class_names=["benign", "attack", "rare"],
            minimum_local_support=2,
            class_quorum=3,
            method="support_weighted_mean",
            previous_global_prototypes={"attack": [7.0, 7.0]},
            np=np,
        )

        benign = result["classes"]["benign"]
        self.assertEqual(benign["status"], "aggregated")
        self.assertEqual(benign["eligible_client_count"], 3)
        self.assertEqual(benign["total_support"], 12)
        self.assertTrue(
            np.allclose(benign["values"], [32.0 / 12.0, 32.0 / 12.0])
        )
        self.assertEqual(result["classes"]["attack"]["status"], "retained_previous")
        self.assertEqual(result["classes"]["attack"]["values"], [7.0, 7.0])
        self.assertEqual(result["classes"]["rare"]["status"], "unavailable")
        self.assertIsNone(result["classes"]["rare"]["values"])
        self.assertEqual(
            available_prototype_values(result)["attack"], [7.0, 7.0]
        )

    def test_coordinate_median_is_not_support_weighted(self) -> None:
        import numpy as np

        result = aggregate_global_prototypes(
            submissions=[
                {
                    "client_id": "client01",
                    "prototypes": {"attack": {"support": 5, "values": [0.0, 9.0]}},
                },
                {
                    "client_id": "client02",
                    "prototypes": {"attack": {"support": 50, "values": [2.0, 3.0]}},
                },
                {
                    "client_id": "client03",
                    "prototypes": {"attack": {"support": 5, "values": [100.0, 1.0]}},
                },
            ],
            class_names=["attack"],
            minimum_local_support=5,
            class_quorum=3,
            method="coordinate_median",
            previous_global_prototypes=None,
            np=np,
        )

        self.assertEqual(result["classes"]["attack"]["values"], [2.0, 3.0])

    def test_nearest_prototype_inference_records_availability_and_margin(self) -> None:
        import numpy as np

        result = nearest_prototype_predictions(
            embeddings=np.asarray([[0.1, 0.1], [9.9, 10.2]], dtype=np.float32),
            class_names=["benign", "attack", "rare"],
            global_prototypes={"benign": [0.0, 0.0], "attack": [10.0, 10.0]},
            np=np,
        )

        self.assertEqual(result["prediction_indices"], [0, 1])
        self.assertEqual(result["available_classes"], ["benign", "attack"])
        self.assertEqual(result["unavailable_classes"], ["rare"])
        self.assertTrue(all(value > 0 for value in result["distance_margins"]))


if __name__ == "__main__":
    unittest.main()
