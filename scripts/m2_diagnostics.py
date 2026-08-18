"""Diagnostic training run and plots for the Milestone 2 centralized MLP.

This script intentionally writes to a separate output directory and does not
replace the verified M2 baseline artifacts. During training it observes only
the train and validation splits. It retains the checkpoint with minimum
validation weighted log-loss, exports traceable misclassifications, and only
then evaluates test and temporal holdout when explicitly requested.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any


def _dependencies() -> tuple[Any, ...]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        import sklearn
        from sklearn.metrics import (
            accuracy_score,
            confusion_matrix,
            log_loss,
            precision_recall_fscore_support,
        )
        from sklearn.neural_network import MLPClassifier
        from sklearn.utils.class_weight import compute_sample_weight
    except ImportError as exc:
        raise RuntimeError(
            'M2 diagnostics require: python -m pip install -e ".[m2,reporting]"'
        ) from exc
    return (
        plt,
        np,
        sklearn,
        accuracy_score,
        confusion_matrix,
        log_loss,
        precision_recall_fscore_support,
        MLPClassifier,
        compute_sample_weight,
    )


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(
                json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
            )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _checkpoint_model_export(
    *,
    model: Any,
    sklearn_version: str,
    architecture: dict[str, Any],
    selected_epoch: int,
    validation_weighted_log_loss: float,
    seed: int,
    class_weighting: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_type": "m2_diagnostic_checkpoint",
        "backend": "scikit-learn",
        "backend_version": sklearn_version,
        "architecture": architecture,
        "selection": {
            "metric": "validation_weighted_log_loss",
            "mode": "minimum",
            "epoch": selected_epoch,
            "value": validation_weighted_log_loss,
            "test_observed_during_selection": False,
        },
        "training": {
            "seed": seed,
            "class_weighting": class_weighting,
        },
        "classes": [str(item) for item in model.classes_.tolist()],
        "coefficient_shapes": [list(value.shape) for value in model.coefs_],
        "intercept_shapes": [list(value.shape) for value in model.intercepts_],
        "coefficients": [value.tolist() for value in model.coefs_],
        "intercepts": [value.tolist() for value in model.intercepts_],
        "optimizer_training_loss": float(model.loss_),
    }


def _misclassification_records(
    *,
    model: Any,
    split: str,
    rows: list[dict[str, Any]],
    features: Any,
    labels: Any,
    feature_names: list[str],
    selected_epoch: int,
) -> list[dict[str, Any]]:
    predictions = model.predict(features)
    probabilities = model.predict_proba(features)
    probability_classes = [str(item) for item in model.classes_.tolist()]
    records: list[dict[str, Any]] = []
    for row_index, (row, true_label, predicted_label, probability_values) in enumerate(
        zip(rows, labels, predictions, probabilities, strict=True)
    ):
        true_name = str(true_label)
        predicted_name = str(predicted_label)
        if true_name == predicted_name:
            continue
        probability_by_class = {
            class_name: float(probability_values[index])
            for index, class_name in enumerate(probability_classes)
        }
        source_event_ids = [str(item) for item in row.get("source_event_ids", [])]
        feature_values = {
            feature_name: float(value)
            for feature_name, value in zip(
                feature_names, row["features"], strict=True
            )
        }
        predicted_probability = probability_by_class[predicted_name]
        true_probability = probability_by_class[true_name]
        records.append(
            {
                "schema_version": "1.0",
                "artifact_type": "m2_diagnostic_misclassification",
                "selection_epoch": selected_epoch,
                "split": split,
                "split_row_index": row_index,
                "window_id": row.get("window_id"),
                "capture_id": row.get("capture_id"),
                "window_start_epoch": row.get("window_start_epoch"),
                "window_end_epoch": row.get("window_end_epoch"),
                "true_label": true_name,
                "predicted_label": predicted_name,
                "predicted_probability": predicted_probability,
                "true_label_probability": true_probability,
                "confidence_margin": predicted_probability - true_probability,
                "class_probabilities": probability_by_class,
                "feature_values": feature_values,
                "observed_labels": [
                    str(item) for item in row.get("observed_labels", [])
                ],
                "source_event_count": len(source_event_ids),
                "source_event_ids": source_event_ids,
            }
        )
    return records


def _misclassification_summary(
    *,
    records: list[dict[str, Any]],
    evaluated_row_counts: dict[str, int],
    selected_epoch: int,
) -> dict[str, Any]:
    splits: dict[str, Any] = {}
    for split, row_count in evaluated_row_counts.items():
        split_records = [record for record in records if record["split"] == split]
        transitions = Counter(
            (record["true_label"], record["predicted_label"])
            for record in split_records
        )
        splits[split] = {
            "row_count": row_count,
            "error_count": len(split_records),
            "error_rate": len(split_records) / row_count if row_count else 0.0,
            "transitions": [
                {
                    "true_label": true_label,
                    "predicted_label": predicted_label,
                    "count": count,
                }
                for (true_label, predicted_label), count in sorted(
                    transitions.items()
                )
            ],
        }
    return {
        "schema_version": "1.0",
        "artifact_type": "m2_diagnostic_misclassification_summary",
        "evaluated_model": "best-validation-weighted-log-loss-checkpoint",
        "selection_epoch": selected_epoch,
        "error_count": len(records),
        "splits": splits,
    }


def _macro_f1(
    labels: Any,
    predictions: Any,
    class_names: list[str],
    precision_recall_fscore_support: Any,
) -> float:
    _precision, _recall, f1, _support = precision_recall_fscore_support(
        labels,
        predictions,
        labels=class_names,
        zero_division=0,
    )
    return float(f1.mean())


def _evaluate_split(
    *,
    model: Any,
    features: Any,
    labels: Any,
    class_names: list[str],
    class_weights: dict[str, float],
    accuracy_score: Any,
    confusion_matrix: Any,
    log_loss: Any,
    precision_recall_fscore_support: Any,
    compute_sample_weight: Any,
) -> dict[str, Any]:
    predictions = model.predict(features)
    probabilities = model.predict_proba(features)
    sample_weights = compute_sample_weight(class_weight=class_weights, y=labels)
    precision, recall, f1, support = precision_recall_fscore_support(
        labels,
        predictions,
        labels=class_names,
        zero_division=0,
    )
    return {
        "row_count": int(len(labels)),
        "accuracy": float(accuracy_score(labels, predictions)),
        "log_loss_unweighted": float(
            log_loss(labels, probabilities, labels=class_names)
        ),
        "log_loss_weighted_training_policy": float(
            log_loss(
                labels,
                probabilities,
                labels=class_names,
                sample_weight=sample_weights,
            )
        ),
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
        "confusion_matrix": confusion_matrix(
            labels, predictions, labels=class_names
        ).astype(int).tolist(),
    }


def _plot_learning_curves(
    *,
    plt: Any,
    history: list[dict[str, Any]],
    selected_epoch: int,
    output: Path,
) -> None:
    epochs = [item["epoch"] for item in history]
    figure, axes = plt.subplots(1, 2, figsize=(14, 5))

    axes[0].plot(
        epochs,
        [item["train_weighted_log_loss"] for item in history],
        label="Train",
        linewidth=2,
    )
    axes[0].plot(
        epochs,
        [item["validation_weighted_log_loss"] for item in history],
        label="Validation",
        linewidth=2,
    )
    axes[0].set_title("Weighted log-loss")
    axes[0].set_xlabel("Epoch")
    axes[0].set_ylabel("Log-loss")
    axes[0].grid(alpha=0.25)
    axes[0].axvline(
        selected_epoch,
        color="black",
        linestyle="--",
        linewidth=1.5,
        label=f"Selected checkpoint ({selected_epoch})",
    )
    axes[0].legend()

    axes[1].plot(
        epochs,
        [item["train_macro_f1"] for item in history],
        label="Train",
        linewidth=2,
    )
    axes[1].plot(
        epochs,
        [item["validation_macro_f1"] for item in history],
        label="Validation",
        linewidth=2,
    )
    axes[1].set_title("Macro-F1")
    axes[1].set_xlabel("Epoch")
    axes[1].set_ylabel("Macro-F1")
    axes[1].set_ylim(0.0, 1.0)
    axes[1].grid(alpha=0.25)
    axes[1].axvline(
        selected_epoch,
        color="black",
        linestyle="--",
        linewidth=1.5,
        label=f"Selected checkpoint ({selected_epoch})",
    )
    axes[1].legend()

    figure.suptitle("M2 learning curves — train vs validation")
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_confusion_matrices(
    *,
    plt: Any,
    np: Any,
    metrics: dict[str, Any],
    class_names: list[str],
    output: Path,
    normalized: bool,
) -> None:
    splits = [name for name in ("train", "validation", "test") if name in metrics]
    figure, axes = plt.subplots(1, len(splits), figsize=(7 * len(splits), 6))
    if len(splits) == 1:
        axes = [axes]
    for axis, split in zip(axes, splits, strict=True):
        matrix = np.asarray(metrics[split]["confusion_matrix"], dtype=np.float64)
        if normalized:
            row_totals = matrix.sum(axis=1, keepdims=True)
            matrix = np.divide(
                matrix,
                row_totals,
                out=np.zeros_like(matrix),
                where=row_totals != 0,
            )
        image = axis.imshow(matrix, cmap="Blues", vmin=0.0)
        axis.set_title(f"{split.replace('_', ' ').title()}")
        axis.set_xlabel("Predicted")
        axis.set_ylabel("True")
        axis.set_xticks(range(len(class_names)), class_names, rotation=45, ha="right")
        axis.set_yticks(range(len(class_names)), class_names)
        threshold = float(matrix.max()) / 2 if matrix.size else 0.0
        for row in range(matrix.shape[0]):
            for column in range(matrix.shape[1]):
                value = matrix[row, column]
                label = f"{value:.2f}" if normalized else str(int(value))
                axis.text(
                    column,
                    row,
                    label,
                    ha="center",
                    va="center",
                    fontsize=8,
                    color="white" if value > threshold else "black",
                )
        figure.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    kind = "Row-normalized" if normalized else "Absolute"
    figure.suptitle(f"M2 confusion matrices — {kind}")
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_per_class_f1(
    *,
    plt: Any,
    np: Any,
    metrics: dict[str, Any],
    class_names: list[str],
    output: Path,
) -> None:
    splits = [name for name in ("train", "validation", "test") if name in metrics]
    positions = np.arange(len(class_names), dtype=np.float64)
    width = 0.8 / len(splits)
    figure, axis = plt.subplots(figsize=(13, 6))
    for index, split in enumerate(splits):
        values = [metrics[split]["per_class"][name]["f1"] for name in class_names]
        offset = (index - (len(splits) - 1) / 2) * width
        axis.bar(positions + offset, values, width=width, label=split.title())
    axis.set_title("Per-class F1")
    axis.set_ylabel("F1")
    axis.set_ylim(0.0, 1.0)
    axis.set_xticks(positions, class_names, rotation=30, ha="right")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_class_support(
    *,
    plt: Any,
    np: Any,
    metrics: dict[str, Any],
    class_names: list[str],
    output: Path,
) -> None:
    splits = [name for name in ("train", "validation", "test") if name in metrics]
    positions = np.arange(len(class_names), dtype=np.float64)
    width = 0.8 / len(splits)
    figure, axis = plt.subplots(figsize=(13, 6))
    for index, split in enumerate(splits):
        values = [
            metrics[split]["per_class"][name]["support"] for name in class_names
        ]
        offset = (index - (len(splits) - 1) / 2) * width
        axis.bar(positions + offset, values, width=width, label=split.title())
    axis.set_title("Class support by split — logarithmic scale")
    axis.set_ylabel("Rows/windows")
    axis.set_yscale("log")
    axis.set_xticks(positions, class_names, rotation=30, ha="right")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def run_diagnostics(
    *,
    dataset_workspace: Path,
    config_path: Path,
    output: Path,
    epochs: int | None,
    include_test: bool,
    class_weighting: str | None,
    seed_override: int | None,
) -> dict[str, Any]:
    from fl_forensics.class_weighting import compute_class_weights
    from fl_forensics.config import load_yaml
    from fl_forensics.dataset24 import DATASET_NAME, verify_workspace

    (
        plt,
        np,
        sklearn,
        accuracy_score,
        confusion_matrix,
        log_loss,
        precision_recall_fscore_support,
        MLPClassifier,
        compute_sample_weight,
    ) = _dependencies()

    verification = verify_workspace(dataset_workspace)
    if verification["status"] != "verified":
        raise ValueError(f"M2 workspace verification failed: {verification['errors']}")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"diagnostic output is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    config, config_digest = load_yaml(config_path)
    model_config = config["model"]
    federation_config = config["federation"]
    dataset = json.loads(
        (dataset_workspace / "dataset.json").read_text(encoding="utf-8")
    )
    scaler = json.loads(
        (dataset_workspace / "scaler.json").read_text(encoding="utf-8")
    )
    if dataset.get("dataset") != DATASET_NAME:
        raise ValueError("diagnostics accept only UWF-ZeekData24 M2 snapshots")

    split_rows = {
        split: [row for row in dataset["rows"] if row["split"] == split]
        for split in ("train", "validation", "test", "temporal_holdout")
    }
    means = np.asarray(scaler["mean"], dtype=np.float64)
    scales = np.asarray(scaler["scale"], dtype=np.float64)

    def arrays(items: list[dict[str, Any]]) -> tuple[Any, Any]:
        features = np.asarray([item["features"] for item in items], dtype=np.float64)
        labels = np.asarray([item["label"] for item in items], dtype=str)
        return (features - means) / scales, labels

    split_arrays = {
        split: arrays(items) for split, items in split_rows.items() if items
    }
    train_features, train_labels = split_arrays["train"]
    validation_features, validation_labels = split_arrays["validation"]
    class_names = sorted({str(label) for label in train_labels.tolist()})
    class_array = np.asarray(class_names, dtype=str)
    weighting_strategy = class_weighting or str(model_config["class_weighting"])
    class_weights = compute_class_weights(
        train_labels.tolist(), strategy=weighting_strategy
    )
    train_weights = compute_sample_weight(
        class_weight=class_weights, y=train_labels
    )
    validation_weights = compute_sample_weight(
        class_weight=class_weights, y=validation_labels
    )

    epoch_count = int(epochs or model_config["max_iterations"])
    if epoch_count < 1:
        raise ValueError("epochs must be positive")
    seed = int(
        seed_override
        if seed_override is not None
        else config["experiment"]["seed"]
    )
    hidden_layers = tuple(int(item) for item in model_config["hidden_layers"])
    embedding_size = int(model_config["embedding_size"])
    architecture = {
        "input_features": len(dataset["feature_names"]),
        "encoder_hidden_layers": list(hidden_layers),
        "embedding_size": embedding_size,
        "classification_head_outputs": len(class_names),
        "activation": str(model_config["activation"]),
        "dropout": 0.0,
    }
    model = MLPClassifier(
        hidden_layer_sizes=hidden_layers + (embedding_size,),
        activation=str(model_config["activation"]),
        solver="adam",
        alpha=float(model_config["regularization_alpha"]),
        batch_size=min(int(federation_config["batch_size"]), len(train_features)),
        learning_rate_init=float(federation_config["learning_rate"]),
        max_iter=1,
        random_state=np.random.RandomState(seed),
        shuffle=True,
        early_stopping=False,
    )

    history: list[dict[str, Any]] = []
    best_checkpoint_model: Any | None = None
    best_checkpoint_row: dict[str, Any] | None = None
    for epoch in range(1, epoch_count + 1):
        model.partial_fit(
            train_features,
            train_labels,
            classes=class_array,
            sample_weight=train_weights,
        )
        train_probabilities = model.predict_proba(train_features)
        validation_probabilities = model.predict_proba(validation_features)
        train_predictions = model.predict(train_features)
        validation_predictions = model.predict(validation_features)
        epoch_record = {
            "epoch": epoch,
            "optimizer_training_loss": float(model.loss_),
            "train_weighted_log_loss": float(
                log_loss(
                    train_labels,
                    train_probabilities,
                    labels=class_names,
                    sample_weight=train_weights,
                )
            ),
            "validation_weighted_log_loss": float(
                log_loss(
                    validation_labels,
                    validation_probabilities,
                    labels=class_names,
                    sample_weight=validation_weights,
                )
            ),
            "train_unweighted_log_loss": float(
                log_loss(train_labels, train_probabilities, labels=class_names)
            ),
            "validation_unweighted_log_loss": float(
                log_loss(
                    validation_labels,
                    validation_probabilities,
                    labels=class_names,
                )
            ),
            "train_macro_f1": _macro_f1(
                train_labels,
                train_predictions,
                class_names,
                precision_recall_fscore_support,
            ),
            "validation_macro_f1": _macro_f1(
                validation_labels,
                validation_predictions,
                class_names,
                precision_recall_fscore_support,
            ),
            "train_accuracy": float(
                accuracy_score(train_labels, train_predictions)
            ),
            "validation_accuracy": float(
                accuracy_score(validation_labels, validation_predictions)
            ),
        }
        history.append(epoch_record)
        if (
            best_checkpoint_row is None
            or epoch_record["validation_weighted_log_loss"]
            < best_checkpoint_row["validation_weighted_log_loss"]
        ):
            best_checkpoint_row = dict(epoch_record)
            best_checkpoint_model = deepcopy(model)
        print(
            f"epoch={epoch:03d}/{epoch_count:03d} "
            f"train_loss={history[-1]['train_weighted_log_loss']:.6f} "
            f"val_loss={history[-1]['validation_weighted_log_loss']:.6f} "
            f"train_macro_f1={history[-1]['train_macro_f1']:.6f} "
            f"val_macro_f1={history[-1]['validation_macro_f1']:.6f}",
            flush=True,
        )

    if best_checkpoint_model is None or best_checkpoint_row is None:
        raise RuntimeError("diagnostic training did not produce a checkpoint")

    # Test and temporal holdout remain sealed unless explicitly requested for a
    # final candidate. They are never observed during epoch-by-epoch training.
    evaluation_splits = ["train", "validation"]
    if include_test:
        evaluation_splits.extend(["test", "temporal_holdout"])
    checkpoint_metrics = {
        split: _evaluate_split(
            model=best_checkpoint_model,
            features=features,
            labels=labels,
            class_names=class_names,
            class_weights=class_weights,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            log_loss=log_loss,
            precision_recall_fscore_support=precision_recall_fscore_support,
            compute_sample_weight=compute_sample_weight,
        )
        for split in evaluation_splits
        for features, labels in [split_arrays[split]]
    }
    best_loss_row = best_checkpoint_row
    best_f1_row = max(history, key=lambda item: item["validation_macro_f1"])
    final_row = history[-1]
    possible_overfit = (
        final_row["validation_weighted_log_loss"]
        > best_loss_row["validation_weighted_log_loss"] * 1.05
        and final_row["train_weighted_log_loss"]
        < best_loss_row["train_weighted_log_loss"]
    )

    checkpoint_export = _checkpoint_model_export(
        model=best_checkpoint_model,
        sklearn_version=sklearn.__version__,
        architecture=architecture,
        selected_epoch=int(best_loss_row["epoch"]),
        validation_weighted_log_loss=float(
            best_loss_row["validation_weighted_log_loss"]
        ),
        seed=seed,
        class_weighting=weighting_strategy,
    )
    checkpoint_path = output / "best_checkpoint_model.json"
    _write_json(checkpoint_path, checkpoint_export)
    checkpoint_sha256 = _sha256_file(checkpoint_path)

    misclassification_records: list[dict[str, Any]] = []
    for split in evaluation_splits:
        features, labels = split_arrays[split]
        misclassification_records.extend(
            _misclassification_records(
                model=best_checkpoint_model,
                split=split,
                rows=split_rows[split],
                features=features,
                labels=labels,
                feature_names=[str(item) for item in dataset["feature_names"]],
                selected_epoch=int(best_loss_row["epoch"]),
            )
        )
    error_summary = _misclassification_summary(
        records=misclassification_records,
        evaluated_row_counts={
            split: int(checkpoint_metrics[split]["row_count"])
            for split in evaluation_splits
        },
        selected_epoch=int(best_loss_row["epoch"]),
    )

    artifact_values = {
        "training_history.json": {"epochs": history},
        "checkpoint_metrics.json": checkpoint_metrics,
        # Backward-compatible name used by the existing aggregation notebooks.
        "final_metrics.json": checkpoint_metrics,
        "misclassification_summary.json": error_summary,
    }
    for name, value in artifact_values.items():
        _write_json(output / name, value)
    _write_jsonl(output / "misclassified_windows.jsonl", misclassification_records)
    artifact_hashes = {
        name: _sha256_file(output / name)
        for name in (
            "best_checkpoint_model.json",
            "training_history.json",
            "checkpoint_metrics.json",
            "final_metrics.json",
            "misclassified_windows.jsonl",
            "misclassification_summary.json",
        )
    }

    summary = {
        "dataset": DATASET_NAME,
        "sklearn_version": sklearn.__version__,
        "config_sha256": config_digest,
        "seed": seed,
        "epochs": epoch_count,
        "class_weighting": weighting_strategy,
        "class_weights": class_weights,
        "best_epoch_by_validation_weighted_log_loss": best_loss_row["epoch"],
        "best_validation_weighted_log_loss": best_loss_row[
            "validation_weighted_log_loss"
        ],
        "best_epoch_by_validation_macro_f1": best_f1_row["epoch"],
        "best_validation_macro_f1": best_f1_row["validation_macro_f1"],
        "evaluated_model": "best-validation-weighted-log-loss-checkpoint",
        "selected_checkpoint_epoch": best_loss_row["epoch"],
        "selected_checkpoint_model_path": checkpoint_path.name,
        "selected_checkpoint_model_sha256": checkpoint_sha256,
        "checkpoint_train_macro_f1": checkpoint_metrics["train"][
            "macro_f1_all_model_classes"
        ],
        "checkpoint_validation_macro_f1": checkpoint_metrics["validation"][
            "macro_f1_all_model_classes"
        ],
        "final_train_weighted_log_loss": final_row["train_weighted_log_loss"],
        "final_validation_weighted_log_loss": final_row[
            "validation_weighted_log_loss"
        ],
        "final_train_macro_f1": final_row["train_macro_f1"],
        "final_validation_macro_f1": final_row["validation_macro_f1"],
        "possible_overfit_signal": possible_overfit,
        "test_evaluated": include_test,
        "misclassification_error_count": len(misclassification_records),
        "misclassification_artifacts": {
            "records": "misclassified_windows.jsonl",
            "summary": "misclassification_summary.json",
        },
        "artifact_sha256": artifact_hashes,
        "selection_policy": (
            "minimum validation weighted log-loss checkpoint selected before "
            "test and temporal holdout are evaluated once"
            if include_test
            else "minimum validation weighted log-loss checkpoint; test and "
            "temporal holdout remain sealed"
        ),
        "limitations": [
            "The validation split contains extremely low support for exfiltration.",
            "A single run cannot establish stability; repeat with multiple fixed seeds.",
            "partial_fit monitoring is a separate diagnostic training protocol.",
        ],
    }

    _write_json(output / "summary.json", summary)
    _plot_learning_curves(
        plt=plt,
        history=history,
        selected_epoch=int(best_loss_row["epoch"]),
        output=output / "learning_curves.png",
    )
    _plot_confusion_matrices(
        plt=plt,
        np=np,
        metrics=checkpoint_metrics,
        class_names=class_names,
        output=output / "confusion_matrices_absolute.png",
        normalized=False,
    )
    _plot_confusion_matrices(
        plt=plt,
        np=np,
        metrics=checkpoint_metrics,
        class_names=class_names,
        output=output / "confusion_matrices_normalized.png",
        normalized=True,
    )
    _plot_per_class_f1(
        plt=plt,
        np=np,
        metrics=checkpoint_metrics,
        class_names=class_names,
        output=output / "per_class_f1.png",
    )
    _plot_class_support(
        plt=plt,
        np=np,
        metrics=checkpoint_metrics,
        class_names=class_names,
        output=output / "class_support.png",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset-workspace", type=Path, default=Path("artifacts/m2-data24")
    )
    parser.add_argument("--config", type=Path, default=Path("configs/base.yaml"))
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/m2-diagnostics-sqrt")
    )
    parser.add_argument("--epochs", type=int)
    parser.add_argument(
        "--seed",
        type=int,
        help="Override experiment.seed without modifying the YAML configuration.",
    )
    parser.add_argument(
        "--class-weighting",
        choices=("balanced", "sqrt-balanced", "none"),
        help="Override model.class_weighting for a controlled comparison.",
    )
    parser.add_argument(
        "--include-test",
        action="store_true",
        help=(
            "Evaluate test and temporal holdout once, after selecting the best "
            "validation-loss checkpoint."
        ),
    )
    arguments = parser.parse_args()
    summary = run_diagnostics(
        dataset_workspace=arguments.dataset_workspace,
        config_path=arguments.config,
        output=arguments.output,
        epochs=arguments.epochs,
        include_test=arguments.include_test,
        class_weighting=arguments.class_weighting,
        seed_override=arguments.seed,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
