"""Centralized MLP encoder/classification-head baseline for Milestone 2."""

from __future__ import annotations

import json
import warnings
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_bytes, sha256_file
from .config import load_yaml
from .dataset24 import DATASET_NAME, verify_workspace
from .preprocessing import derived_json_bytes
from .storage import write_once


class BaselineDependencyError(RuntimeError):
    """Raised when the optional M2 numerical dependencies are unavailable."""


def _dependencies() -> tuple[Any, ...]:
    try:
        import numpy as np
        import sklearn
        from sklearn.exceptions import ConvergenceWarning
        from sklearn.metrics import (
            accuracy_score,
            confusion_matrix,
            precision_recall_fscore_support,
        )
        from sklearn.neural_network import MLPClassifier
        from sklearn.utils.class_weight import compute_sample_weight
    except ImportError as exc:
        raise BaselineDependencyError(
            'Milestone 2 requires: python -m pip install -e ".[m2]"'
        ) from exc
    return (
        np,
        sklearn,
        ConvergenceWarning,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        MLPClassifier,
        compute_sample_weight,
    )


def _evaluate(
    *,
    model: Any,
    features: Any,
    labels: Any,
    class_names: list[str],
    metrics_functions: tuple[Any, ...],
) -> dict[str, Any]:
    (
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = metrics_functions
    predictions = model.predict(features)
    precision, recall, f1, support = precision_recall_fscore_support(
        labels,
        predictions,
        labels=class_names,
        zero_division=0,
    )
    observed = sorted({str(item) for item in labels.tolist()})
    return {
        "row_count": len(labels),
        "observed_labels": observed,
        "observed_class_count": len(observed),
        "accuracy": float(accuracy_score(labels, predictions)),
        "balanced_accuracy_observed_classes": float(recall[support > 0].mean()),
        "macro_precision_all_model_classes": float(precision.mean()),
        "macro_recall_all_model_classes": float(recall.mean()),
        "macro_f1_all_model_classes": float(f1.mean()),
        "per_class": {
            class_name: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, class_name in enumerate(class_names)
        },
        "confusion_matrix": {
            "labels": class_names,
            "values": confusion_matrix(
                labels, predictions, labels=class_names
            ).astype(int).tolist(),
        },
    }


def _model_export(model: Any, architecture: dict[str, Any], sklearn_version: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "backend": "scikit-learn",
        "backend_version": sklearn_version,
        "architecture": architecture,
        "classes": [str(item) for item in model.classes_.tolist()],
        "coefficient_shapes": [list(value.shape) for value in model.coefs_],
        "intercept_shapes": [list(value.shape) for value in model.intercepts_],
        "coefficients": [value.tolist() for value in model.coefs_],
        "intercepts": [value.tolist() for value in model.intercepts_],
        "iterations": int(model.n_iter_),
        "final_loss": float(model.loss_),
        "loss_curve": [float(value) for value in model.loss_curve_],
    }


def train_central_baseline(
    *, workspace: Path, output: Path, config_path: Path
) -> dict[str, Any]:
    verification = verify_workspace(workspace)
    if verification["status"] != "verified":
        raise ValueError(f"M2 workspace verification failed: {verification['errors']}")

    (
        np,
        sklearn,
        ConvergenceWarning,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
        MLPClassifier,
        compute_sample_weight,
    ) = _dependencies()
    config, _config_source_digest = load_yaml(config_path)
    model_config = config["model"]
    federation_config = config["federation"]
    dataset = json.loads((workspace / "dataset.json").read_text(encoding="utf-8"))
    scaler = json.loads((workspace / "scaler.json").read_text(encoding="utf-8"))
    dataset_manifest = json.loads(
        (workspace / "manifest.json").read_text(encoding="utf-8")
    )
    if dataset.get("dataset") != DATASET_NAME:
        raise ValueError("central baseline accepts only UWF-ZeekData24 M2 snapshots")

    rows = dataset["rows"]
    split_rows: dict[str, list[dict[str, Any]]] = {
        split: [row for row in rows if row["split"] == split]
        for split in ("train", "validation", "test", "temporal_holdout")
    }
    for required in ("train", "validation", "test"):
        if not split_rows[required]:
            raise ValueError(f"required split is empty: {required}")

    means = np.asarray(scaler["mean"], dtype=np.float64)
    scales = np.asarray(scaler["scale"], dtype=np.float64)

    def arrays(items: list[dict[str, Any]]) -> tuple[Any, Any]:
        features = np.asarray([item["features"] for item in items], dtype=np.float64)
        labels = np.asarray([item["label"] for item in items], dtype=str)
        return (features - means) / scales, labels

    train_features, train_labels = arrays(split_rows["train"])
    all_training_classes = sorted({str(item) for item in train_labels.tolist()})
    for split in ("validation", "test", "temporal_holdout"):
        unknown = sorted(
            {row["label"] for row in split_rows[split]} - set(all_training_classes)
        )
        if unknown:
            raise ValueError(f"{split} contains labels absent from training: {unknown}")

    hidden_layers = tuple(int(item) for item in model_config["hidden_layers"])
    embedding_size = int(model_config["embedding_size"])
    architecture = {
        "input_features": len(dataset["feature_names"]),
        "encoder_hidden_layers": list(hidden_layers),
        "embedding_size": embedding_size,
        "classification_head_outputs": len(all_training_classes),
        "activation": str(model_config["activation"]),
        "dropout": 0.0,
        "note": "The sklearn M2 baseline has no dropout; the federated PyTorch profile is M3.",
    }
    model = MLPClassifier(
        hidden_layer_sizes=hidden_layers + (embedding_size,),
        activation=str(model_config["activation"]),
        solver="adam",
        alpha=float(model_config["regularization_alpha"]),
        batch_size=min(int(federation_config["batch_size"]), len(train_features)),
        learning_rate_init=float(federation_config["learning_rate"]),
        max_iter=int(model_config["max_iterations"]),
        random_state=int(config["experiment"]["seed"]),
        shuffle=True,
        early_stopping=False,
    )
    sample_weights = compute_sample_weight(class_weight="balanced", y=train_labels)
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=ConvergenceWarning)
        model.fit(train_features, train_labels, sample_weight=sample_weights)

    metrics_functions = (
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    )
    metrics: dict[str, Any] = {}
    for split, items in split_rows.items():
        if not items:
            continue
        features, labels = arrays(items)
        metrics[split] = _evaluate(
            model=model,
            features=features,
            labels=labels,
            class_names=all_training_classes,
            metrics_functions=metrics_functions,
        )

    model_export = _model_export(model, architecture, sklearn.__version__)
    model_bytes = derived_json_bytes(model_export)
    metrics_artifact = {
        "schema_version": "1.0",
        "artifact_type": "centralized_baseline_metrics",
        "dataset": DATASET_NAME,
        "dataset_sha256": dataset_manifest["artifacts"]["dataset.json"],
        "model_classes": all_training_classes,
        "training_class_counts": dict(sorted(Counter(train_labels.tolist()).items())),
        "class_weighting": "balanced sample weights computed from training only",
        "metrics": metrics,
        "interpretation_constraints": [
            "The temporal_holdout split is benign-only in the published Data24 CSV release.",
            (
                "Macro metrics for temporal_holdout include zero-support model classes and must "
                "not be interpreted as a full multiclass test."
            ),
            "The dataset has a documented acquisition-time/class confound and cross-label records.",
        ],
    }
    metrics_bytes = derived_json_bytes(metrics_artifact)
    training_manifest = {
        "schema_version": "1.0",
        "artifact_type": "centralized_baseline_manifest",
        "dataset": DATASET_NAME,
        "code_version": __version__,
        "implementation_sha256": sha256_file(Path(__file__)),
        "config_sha256": _config_source_digest,
        "input_m2_manifest_sha256": sha256_file(workspace / "manifest.json"),
        "input_dataset_sha256": sha256_file(workspace / "dataset.json"),
        "input_scaler_sha256": sha256_file(workspace / "scaler.json"),
        "model_sha256": sha256_bytes(model_bytes),
        "metrics_sha256": sha256_bytes(metrics_bytes),
        "seed": int(config["experiment"]["seed"]),
        "iterations": int(model.n_iter_),
    }
    manifest_bytes = derived_json_bytes(training_manifest)
    write_once(output / "model.json", model_bytes)
    write_once(output / "metrics.json", metrics_bytes)
    write_once(output / "manifest.json", manifest_bytes)

    return {
        "status": "trained",
        "dataset": DATASET_NAME,
        "output": str(output),
        "model_sha256": training_manifest["model_sha256"],
        "iterations": int(model.n_iter_),
        "classes": all_training_classes,
        "validation_macro_f1": metrics["validation"]["macro_f1_all_model_classes"],
        "test_macro_f1": metrics["test"]["macro_f1_all_model_classes"],
        "temporal_holdout_observed_labels": metrics.get("temporal_holdout", {}).get(
            "observed_labels", []
        ),
    }


def verify_central_baseline(*, workspace: Path, dataset_workspace: Path) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = workspace / "manifest.json"
    if not manifest_path.is_file():
        return {
            "status": "failed",
            "workspace": str(workspace),
            "error_count": 1,
            "errors": ["missing centralized baseline manifest.json"],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("dataset") != DATASET_NAME:
        errors.append("baseline manifest dataset is not UWF-ZeekData24")
    output_refs = {
        "model.json": manifest.get("model_sha256"),
        "metrics.json": manifest.get("metrics_sha256"),
    }
    for name, expected in output_refs.items():
        path = workspace / name
        if not path.is_file():
            errors.append(f"missing centralized baseline artifact: {name}")
        elif not expected or sha256_file(path) != expected:
            errors.append(f"centralized baseline digest mismatch: {name}")

    input_refs = {
        "manifest.json": manifest.get("input_m2_manifest_sha256"),
        "dataset.json": manifest.get("input_dataset_sha256"),
        "scaler.json": manifest.get("input_scaler_sha256"),
    }
    for name, expected in input_refs.items():
        path = dataset_workspace / name
        if not path.is_file():
            errors.append(f"missing referenced M2 input: {name}")
        elif not expected or sha256_file(path) != expected:
            errors.append(f"referenced M2 input digest mismatch: {name}")

    return {
        "status": "verified" if not errors else "failed",
        "dataset": manifest.get("dataset"),
        "workspace": str(workspace),
        "dataset_workspace": str(dataset_workspace),
        "model_sha256": manifest.get("model_sha256"),
        "metrics_sha256": manifest.get("metrics_sha256"),
        "error_count": len(errors),
        "errors": errors,
    }
