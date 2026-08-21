from __future__ import annotations

import importlib.util
import unittest

from fl_forensics.federated_model import build_model, seed_everything, train_local


@unittest.skipUnless(
    all(importlib.util.find_spec(name) for name in ("numpy", "sklearn", "torch")),
    "optional federated numerical dependencies are not installed",
)
class FederatedLocalMetricTests(unittest.TestCase):
    def test_local_training_records_epoch_validation_history(self) -> None:
        import numpy as np
        import torch
        from sklearn.metrics import (
            accuracy_score,
            confusion_matrix,
            precision_recall_fscore_support,
        )

        class_names = ["benign", "attack"]
        train_rows = [
            {
                "window_id": f"train-{index}",
                "features": [float(index % 2), float((index + 1) % 2)],
                "label": class_names[index % 2],
            }
            for index in range(16)
        ]
        validation_rows = [
            {
                "window_id": f"validation-{index}",
                "features": [float(index % 2), float((index + 1) % 2)],
                "label": class_names[index % 2],
            }
            for index in range(8)
        ]
        seed_everything(1234, torch=torch, np=np)
        model = build_model(
            input_features=2,
            class_count=2,
            hidden_layers=[8, 4],
            embedding_size=2,
            dropout=0.0,
            torch=torch,
        )
        metrics = train_local(
            model=model,
            rows=train_rows,
            validation_rows=validation_rows,
            class_names=class_names,
            class_weights={"benign": 1.0, "attack": 1.0},
            epochs=3,
            batch_size=4,
            learning_rate=0.01,
            seed=1234,
            device_name="cpu",
            torch=torch,
            np=np,
            evaluation_functions=(
                accuracy_score,
                confusion_matrix,
                precision_recall_fscore_support,
            ),
            record_history=True,
        )

        self.assertEqual(metrics["epochs"], 3)
        self.assertEqual(metrics["num_examples"], 16)
        self.assertEqual(metrics["validation_num_examples"], 8)
        self.assertEqual([item["epoch"] for item in metrics["history"]], [1, 2, 3])
        for item in metrics["history"]:
            self.assertGreaterEqual(item["optimizer_train_loss"], 0.0)
            for split, expected_rows in (("train", 16), ("validation", 8)):
                evaluation = item[split]
                self.assertEqual(evaluation["row_count"], expected_rows)
                self.assertGreaterEqual(evaluation["loss"], 0.0)
                self.assertEqual(
                    evaluation["confusion_matrix"]["labels"], class_names
                )
                self.assertEqual(
                    sum(sum(row) for row in evaluation["confusion_matrix"]["values"]),
                    expected_rows,
                )
        self.assertEqual(metrics["final"]["train"], metrics["history"][-1]["train"])
        self.assertEqual(
            metrics["final"]["validation"],
            metrics["history"][-1]["validation"],
        )

    def test_history_requires_metric_functions(self) -> None:
        import numpy as np
        import torch

        model = build_model(
            input_features=1,
            class_count=1,
            hidden_layers=[2, 2],
            embedding_size=1,
            dropout=0.0,
            torch=torch,
        )
        with self.assertRaisesRegex(ValueError, "evaluation metric functions"):
            train_local(
                model=model,
                rows=[{"features": [0.0], "label": "benign"}],
                class_names=["benign"],
                class_weights={"benign": 1.0},
                epochs=1,
                batch_size=1,
                learning_rate=0.001,
                seed=7,
                device_name="cpu",
                torch=torch,
                np=np,
                record_history=True,
            )


if __name__ == "__main__":
    unittest.main()
