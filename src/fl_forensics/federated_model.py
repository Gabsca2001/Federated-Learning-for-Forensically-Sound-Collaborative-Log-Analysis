"""Shared PyTorch model and training primitives for Flower and the M3 audit runner."""

from __future__ import annotations

import math
import random
from typing import Any


class FederatedDependencyError(RuntimeError):
    """Raised when the optional M3 numerical stack is unavailable."""


def dependencies() -> tuple[Any, ...]:
    try:
        import flwr
        import numpy as np
        import sklearn
        import torch
        from flwr.server.strategy.aggregate import aggregate
        from sklearn.metrics import (
            accuracy_score,
            confusion_matrix,
            precision_recall_fscore_support,
        )
    except ImportError as exc:
        raise FederatedDependencyError(
            'Milestone 3 requires: python -m pip install -e ".[federated,dev]"'
        ) from exc
    return (
        np,
        torch,
        flwr,
        sklearn,
        aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    )


def seed_everything(seed: int, *, torch: Any, np: Any) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True)


def build_model(
    *,
    input_features: int,
    class_count: int,
    hidden_layers: list[int],
    embedding_size: int,
    dropout: float,
    torch: Any,
) -> Any:
    if len(hidden_layers) != 2:
        raise ValueError("the frozen M3 architecture requires exactly two hidden layers")

    class FederatedMLP(torch.nn.Module):
        def __init__(self) -> None:
            super().__init__()
            modules: list[Any] = [
                torch.nn.Linear(input_features, hidden_layers[0]),
                torch.nn.ReLU(),
            ]
            if dropout > 0:
                modules.append(torch.nn.Dropout(dropout))
            modules.extend(
                [
                    torch.nn.Linear(hidden_layers[0], hidden_layers[1]),
                    torch.nn.ReLU(),
                ]
            )
            if dropout > 0:
                modules.append(torch.nn.Dropout(dropout))
            modules.extend(
                [
                    torch.nn.Linear(hidden_layers[1], embedding_size),
                    torch.nn.ReLU(),
                ]
            )
            self.encoder = torch.nn.Sequential(*modules)
            self.classification_head = torch.nn.Linear(embedding_size, class_count)

        def forward(self, features: Any) -> Any:
            return self.classification_head(self.encoder(features))

    return FederatedMLP()


def architecture_record(
    *,
    input_features: int,
    class_count: int,
    hidden_layers: list[int],
    embedding_size: int,
    dropout: float,
) -> dict[str, Any]:
    return {
        "input_features": input_features,
        "encoder_hidden_layers": hidden_layers,
        "embedding_size": embedding_size,
        "classification_head_outputs": class_count,
        "activation": "relu",
        "dropout": dropout,
        "backend": "PyTorch",
    }


def model_to_ndarrays(model: Any, *, np: Any) -> list[Any]:
    return [
        value.detach().cpu().numpy().astype(np.float32, copy=True)
        for value in model.state_dict().values()
    ]


def load_ndarrays(model: Any, arrays: list[Any], *, torch: Any, np: Any) -> None:
    state = model.state_dict()
    if len(state) != len(arrays):
        raise ValueError("parameter count does not match model state")
    loaded: dict[str, Any] = {}
    for (name, reference), array in zip(state.items(), arrays, strict=True):
        value = np.asarray(array, dtype=np.float32)
        if list(value.shape) != list(reference.shape):
            raise ValueError(f"parameter shape mismatch for {name}")
        loaded[name] = torch.from_numpy(value.copy()).to(dtype=reference.dtype)
    model.load_state_dict(loaded, strict=True)


def export_state(
    model: Any,
    *,
    architecture: dict[str, Any],
    class_names: list[str],
) -> dict[str, Any]:
    parameters = []
    for name, value in model.state_dict().items():
        array = value.detach().cpu().numpy()
        parameters.append(
            {
                "name": name,
                "shape": list(array.shape),
                "dtype": str(array.dtype),
                "values": array.tolist(),
            }
        )
    return {
        "schema_version": "1.0",
        "artifact_type": "pytorch_model_state",
        "architecture": architecture,
        "class_names": class_names,
        "parameters": parameters,
    }


def arrays_from_export(value: dict[str, Any], *, np: Any) -> list[Any]:
    return [
        np.asarray(parameter["values"], dtype=np.dtype(parameter["dtype"]))
        for parameter in value["parameters"]
    ]


def _arrays_from_rows(
    rows: list[dict[str, Any]], *, class_names: list[str], np: Any
) -> tuple[Any, Any]:
    if not rows:
        return (
            np.empty((0, 0), dtype=np.float32),
            np.empty((0,), dtype=np.int64),
        )
    label_indices = {name: index for index, name in enumerate(class_names)}
    features = np.asarray([row["features"] for row in rows], dtype=np.float32)
    labels = np.asarray([label_indices[row["label"]] for row in rows], dtype=np.int64)
    return features, labels


def train_local(
    *,
    model: Any,
    rows: list[dict[str, Any]],
    class_names: list[str],
    class_weights: dict[str, float],
    epochs: int,
    batch_size: int,
    learning_rate: float,
    seed: int,
    device_name: str,
    torch: Any,
    np: Any,
    validation_rows: list[dict[str, Any]] | None = None,
    evaluation_functions: tuple[Any, Any, Any] | None = None,
    record_history: bool = False,
) -> dict[str, Any]:
    if not rows:
        raise ValueError("a client cannot train on an empty snapshot")
    seed_everything(seed, torch=torch, np=np)
    device = torch.device(device_name)
    features, labels = _arrays_from_rows(rows, class_names=class_names, np=np)
    dataset = torch.utils.data.TensorDataset(
        torch.from_numpy(features), torch.from_numpy(labels)
    )
    generator = torch.Generator().manual_seed(seed)
    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=min(batch_size, len(dataset)),
        shuffle=True,
        generator=generator,
        num_workers=0,
    )
    weights = torch.tensor(
        [class_weights[name] for name in class_names], dtype=torch.float32, device=device
    )
    criterion = torch.nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    model.to(device)
    total_loss = 0.0
    total_seen = 0
    history: list[dict[str, Any]] = []
    if record_history and evaluation_functions is None:
        raise ValueError("record_history requires evaluation metric functions")
    for epoch in range(epochs):
        model.train()
        epoch_loss = 0.0
        epoch_seen = 0
        for batch_features, batch_labels in loader:
            batch_features = batch_features.to(device)
            batch_labels = batch_labels.to(device)
            optimizer.zero_grad()
            outputs = model(batch_features)
            loss = criterion(outputs, batch_labels)
            loss.backward()
            optimizer.step()
            count = len(batch_labels)
            weighted_loss = float(loss.detach().cpu().item()) * count
            total_loss += weighted_loss
            total_seen += count
            epoch_loss += weighted_loss
            epoch_seen += count
        if record_history:
            assert evaluation_functions is not None
            accuracy_score, confusion_matrix, precision_recall_fscore_support = (
                evaluation_functions
            )
            train_evaluation = evaluate_rows(
                model=model,
                rows=rows,
                class_names=class_names,
                batch_size=batch_size,
                torch=torch,
                np=np,
                accuracy_score=accuracy_score,
                confusion_matrix=confusion_matrix,
                precision_recall_fscore_support=precision_recall_fscore_support,
                device_name=device_name,
                move_to_cpu_after=False,
            )
            validation_evaluation = evaluate_rows(
                model=model,
                rows=validation_rows or [],
                class_names=class_names,
                batch_size=batch_size,
                torch=torch,
                np=np,
                accuracy_score=accuracy_score,
                confusion_matrix=confusion_matrix,
                precision_recall_fscore_support=precision_recall_fscore_support,
                device_name=device_name,
                move_to_cpu_after=False,
            )
            history.append(
                {
                    "epoch": epoch + 1,
                    "optimizer_train_loss": epoch_loss / epoch_seen,
                    "train": train_evaluation,
                    "validation": validation_evaluation,
                }
            )
    model.to("cpu")
    result = {
        "train_loss": total_loss / total_seen,
        "num_examples": len(dataset),
        "optimizer_steps": epochs * len(loader),
        "epochs": epochs,
    }
    if record_history:
        result.update(
            {
                "validation_num_examples": len(validation_rows or []),
                "history": history,
                "final": {
                    "train": history[-1]["train"],
                    "validation": history[-1]["validation"],
                },
            }
        )
    return result


def evaluate_rows(
    *,
    model: Any,
    rows: list[dict[str, Any]],
    class_names: list[str],
    batch_size: int,
    torch: Any,
    np: Any,
    accuracy_score: Any,
    confusion_matrix: Any,
    precision_recall_fscore_support: Any,
    device_name: str = "cpu",
    move_to_cpu_after: bool = True,
) -> dict[str, Any]:
    if not rows:
        return {
            "row_count": 0,
            "observed_labels": [],
            "observed_class_count": 0,
            "loss": None,
            "accuracy": None,
            "balanced_accuracy_observed_classes": None,
            "macro_precision_all_model_classes": None,
            "macro_recall_all_model_classes": None,
            "macro_f1_all_model_classes": None,
            "per_class": {},
            "confusion_matrix": {"labels": class_names, "values": []},
        }
    features, labels = _arrays_from_rows(rows, class_names=class_names, np=np)
    dataset = torch.utils.data.TensorDataset(
        torch.from_numpy(features), torch.from_numpy(labels)
    )
    loader = torch.utils.data.DataLoader(
        dataset, batch_size=min(batch_size, len(dataset)), shuffle=False, num_workers=0
    )
    device = torch.device(device_name)
    model.to(device)
    model.eval()
    criterion = torch.nn.CrossEntropyLoss(reduction="sum").to(device)
    predictions: list[int] = []
    total_loss = 0.0
    with torch.no_grad():
        for batch_features, batch_labels in loader:
            batch_features = batch_features.to(device)
            batch_labels = batch_labels.to(device)
            outputs = model(batch_features)
            total_loss += float(criterion(outputs, batch_labels).item())
            predictions.extend(outputs.argmax(dim=1).cpu().tolist())
    if move_to_cpu_after:
        model.to("cpu")
    prediction_array = np.asarray(predictions, dtype=np.int64)
    label_ids = list(range(len(class_names)))
    precision, recall, f1, support = precision_recall_fscore_support(
        labels, prediction_array, labels=label_ids, zero_division=0
    )
    observed_ids = sorted(set(labels.tolist()))
    observed_labels = [class_names[index] for index in observed_ids]
    return {
        "row_count": len(labels),
        "observed_labels": observed_labels,
        "observed_class_count": len(observed_labels),
        "loss": total_loss / len(labels),
        "accuracy": float(accuracy_score(labels, prediction_array)),
        "balanced_accuracy_observed_classes": float(recall[support > 0].mean()),
        "macro_precision_all_model_classes": float(precision.mean()),
        "macro_recall_all_model_classes": float(recall.mean()),
        "macro_f1_all_model_classes": float(f1.mean()),
        "per_class": {
            name: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, name in enumerate(class_names)
        },
        "confusion_matrix": {
            "labels": class_names,
            "values": confusion_matrix(labels, prediction_array, labels=label_ids)
            .astype(int)
            .tolist(),
        },
    }


def fedavg(updates: list[tuple[list[Any], int]], *, aggregate: Any) -> list[Any]:
    if not updates or any(weight <= 0 for _arrays, weight in updates):
        raise ValueError("FedAvg requires non-empty positive-weight client updates")
    return aggregate(updates)


def delta_l2(base: list[Any], updated: list[Any], *, np: Any) -> float:
    if len(base) != len(updated):
        raise ValueError("cannot compare model states with different parameter counts")
    squared = math.fsum(
        float(np.square(new.astype(np.float64) - old.astype(np.float64)).sum())
        for old, new in zip(base, updated, strict=True)
    )
    return math.sqrt(squared)
