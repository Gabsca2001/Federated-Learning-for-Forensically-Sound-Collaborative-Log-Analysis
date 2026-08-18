"""Controlled multi-seed comparison of robust M2 feature preprocessing.

Validation mode compares preprocessing variants without evaluating test.
Final-test mode accepts only the variant frozen in a validation selection
artifact, retrains the predeclared seeds, and evaluates test once per seed.
The verified M2 baseline workspace is never modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from statistics import mean, stdev
from typing import Any


DEFAULT_SEEDS = (341593, 341594, 341595, 341596, 341597)
DEFAULT_VARIANTS = ("standard", "log1p", "log1p-winsor")


def _dependencies() -> tuple[Any, ...]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        from sklearn.metrics import (
            accuracy_score,
            log_loss,
            precision_recall_fscore_support,
        )
        from sklearn.neural_network import MLPClassifier
        from sklearn.utils.class_weight import compute_sample_weight
    except ImportError as exc:
        raise RuntimeError(
            'M2 preprocessing experiments require: pip install -e ".[m2,reporting]"'
        ) from exc
    return (
        plt,
        np,
        accuracy_score,
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _object_sha256(value: Any) -> str:
    raw = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sample_standard_deviation(values: list[float]) -> float:
    return stdev(values) if len(values) > 1 else 0.0


def _macro_f1(
    labels: Any,
    predictions: Any,
    class_names: list[str],
    precision_recall_fscore_support: Any,
) -> float:
    _precision, _recall, f1, _support = precision_recall_fscore_support(
        labels, predictions, labels=class_names, zero_division=0
    )
    return float(f1.mean())


def _evaluate(
    *,
    model: Any,
    features: Any,
    labels: Any,
    class_names: list[str],
    class_weights: dict[str, float],
    accuracy_score: Any,
    log_loss: Any,
    precision_recall_fscore_support: Any,
    compute_sample_weight: Any,
) -> dict[str, Any]:
    predictions = model.predict(features)
    probabilities = model.predict_proba(features)
    weights = compute_sample_weight(class_weight=class_weights, y=labels)
    precision, recall, f1, support = precision_recall_fscore_support(
        labels, predictions, labels=class_names, zero_division=0
    )
    return {
        "row_count": int(len(labels)),
        "accuracy": float(accuracy_score(labels, predictions)),
        "macro_f1_all_model_classes": float(f1.mean()),
        "weighted_log_loss_training_policy": float(
            log_loss(
                labels,
                probabilities,
                labels=class_names,
                sample_weight=weights,
            )
        ),
        "unweighted_log_loss": float(
            log_loss(labels, probabilities, labels=class_names)
        ),
        "per_class": {
            class_name: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, class_name in enumerate(class_names)
        },
    }


def _train_run(
    *,
    np: Any,
    train_features: Any,
    train_labels: Any,
    validation_features: Any,
    validation_labels: Any,
    test_features: Any | None,
    test_labels: Any | None,
    class_names: list[str],
    class_weights: dict[str, float],
    model_config: dict[str, Any],
    federation_config: dict[str, Any],
    seed: int,
    epochs: int,
    dependencies: tuple[Any, ...],
) -> tuple[dict[str, Any], Any]:
    (
        _plt,
        _np,
        accuracy_score,
        log_loss,
        precision_recall_fscore_support,
        MLPClassifier,
        compute_sample_weight,
    ) = dependencies
    train_weights = compute_sample_weight(
        class_weight=class_weights, y=train_labels
    )
    validation_weights = compute_sample_weight(
        class_weight=class_weights, y=validation_labels
    )
    hidden_layers = tuple(int(item) for item in model_config["hidden_layers"])
    embedding_size = int(model_config["embedding_size"])
    model = MLPClassifier(
        hidden_layer_sizes=hidden_layers + (embedding_size,),
        activation=str(model_config["activation"]),
        solver="adam",
        alpha=float(model_config["regularization_alpha"]),
        batch_size=min(
            int(federation_config["batch_size"]), len(train_features)
        ),
        learning_rate_init=float(federation_config["learning_rate"]),
        max_iter=1,
        random_state=np.random.RandomState(seed),
        shuffle=True,
        early_stopping=False,
    )
    class_array = np.asarray(class_names, dtype=str)
    history: list[dict[str, Any]] = []
    best_model: Any | None = None
    best_row: dict[str, Any] | None = None
    for epoch in range(1, epochs + 1):
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
        row = {
            "epoch": epoch,
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
        }
        history.append(row)
        if (
            best_row is None
            or row["validation_weighted_log_loss"]
            < best_row["validation_weighted_log_loss"]
        ):
            best_row = dict(row)
            best_model = deepcopy(model)
    if best_model is None or best_row is None:
        raise RuntimeError("training did not produce a validation checkpoint")

    metrics = {
        "train": _evaluate(
            model=best_model,
            features=train_features,
            labels=train_labels,
            class_names=class_names,
            class_weights=class_weights,
            accuracy_score=accuracy_score,
            log_loss=log_loss,
            precision_recall_fscore_support=precision_recall_fscore_support,
            compute_sample_weight=compute_sample_weight,
        ),
        "validation": _evaluate(
            model=best_model,
            features=validation_features,
            labels=validation_labels,
            class_names=class_names,
            class_weights=class_weights,
            accuracy_score=accuracy_score,
            log_loss=log_loss,
            precision_recall_fscore_support=precision_recall_fscore_support,
            compute_sample_weight=compute_sample_weight,
        ),
    }
    if (test_features is None) != (test_labels is None):
        raise ValueError("test features and labels must be provided together")
    if test_features is not None and test_labels is not None:
        metrics["test"] = _evaluate(
            model=best_model,
            features=test_features,
            labels=test_labels,
            class_names=class_names,
            class_weights=class_weights,
            accuracy_score=accuracy_score,
            log_loss=log_loss,
            precision_recall_fscore_support=precision_recall_fscore_support,
            compute_sample_weight=compute_sample_weight,
        )
    return (
        {
            "seed": seed,
            "selected_epoch": int(best_row["epoch"]),
            "selection_metric": "minimum validation weighted log-loss",
            "history": history,
            "metrics": metrics,
        },
        best_model,
    )


def _load_experiment(
    *, dataset_workspace: Path, config_path: Path, include_test: bool
) -> dict[str, Any]:
    from fl_forensics.config import load_yaml
    from fl_forensics.dataset24 import DATASET_NAME, verify_workspace

    verification = verify_workspace(dataset_workspace)
    if verification["status"] != "verified":
        raise ValueError(f"M2 workspace verification failed: {verification['errors']}")
    config, config_digest = load_yaml(config_path)
    dataset = json.loads(
        (dataset_workspace / "dataset.json").read_text(encoding="utf-8")
    )
    if dataset.get("dataset") != DATASET_NAME:
        raise ValueError("experiment accepts only UWF-ZeekData24 M2 snapshots")
    required = ["train", "validation"]
    if include_test:
        required.append("test")
    split_rows = {
        split: [row for row in dataset["rows"] if row["split"] == split]
        for split in required
    }
    for split, rows in split_rows.items():
        if not rows:
            raise ValueError(f"required split is empty: {split}")
    training_classes = sorted(
        {str(row["label"]) for row in split_rows["train"]}
    )
    for split in required[1:]:
        unknown = sorted(
            {str(row["label"]) for row in split_rows[split]}
            - set(training_classes)
        )
        if unknown:
            raise ValueError(f"{split} contains labels absent from train: {unknown}")
    return {
        "config": config,
        "config_sha256": config_digest,
        "dataset": dataset,
        "dataset_sha256": _sha256_file(dataset_workspace / "dataset.json"),
        "scaler": json.loads(
            (dataset_workspace / "scaler.json").read_text(encoding="utf-8")
        ),
        "split_rows": split_rows,
        "class_names": training_classes,
    }


def _raw_arrays(
    *, np: Any, rows: list[dict[str, Any]]
) -> tuple[Any, Any]:
    return (
        np.asarray([row["features"] for row in rows], dtype=np.float64),
        np.asarray([row["label"] for row in rows], dtype=str),
    )


def _fit_transforms(
    *,
    raw_train_features: Any,
    feature_names: list[str],
    variants: list[str],
    lower_quantile: float,
    upper_quantile: float,
    baseline_scaler: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    from fl_forensics.robust_preprocessing import fit_feature_transform

    specifications = {
        variant: fit_feature_transform(
            train_features=raw_train_features,
            feature_names=feature_names,
            mode=variant,
            lower_quantile=lower_quantile,
            upper_quantile=upper_quantile,
        )
        for variant in variants
    }
    standard = specifications.get("standard")
    if standard is not None:
        if baseline_scaler.get("fitted_on_split") not in {None, "train"}:
            raise ValueError("M2 scaler was not fitted on the training split")
        scaler_names = baseline_scaler.get("feature_names")
        if scaler_names is not None and scaler_names != feature_names:
            raise ValueError("M2 scaler feature schema differs from the dataset")
        if len(baseline_scaler["mean"]) != len(feature_names):
            raise ValueError("M2 scaler mean has the wrong dimension")
        if len(baseline_scaler["scale"]) != len(feature_names):
            raise ValueError("M2 scaler scale has the wrong dimension")
        standard["mean_after_transform"] = [
            float(value) for value in baseline_scaler["mean"]
        ]
        standard["scale_after_transform"] = [
            float(value) for value in baseline_scaler["scale"]
        ]
        standard["parameter_source"] = "verified M2 scaler.json"
    return specifications


def _aggregate_validation(
    results: list[dict[str, Any]], variants: list[str]
) -> list[dict[str, Any]]:
    aggregates = []
    for variant in variants:
        local = [item for item in results if item["variant"] == variant]
        f1_values = [
            float(item["metrics"]["validation"]["macro_f1_all_model_classes"])
            for item in local
        ]
        loss_values = [
            float(
                item["metrics"]["validation"][
                    "weighted_log_loss_training_policy"
                ]
            )
            for item in local
        ]
        epochs = [int(item["selected_epoch"]) for item in local]
        aggregates.append(
            {
                "variant": variant,
                "run_count": len(local),
                "validation_macro_f1_mean": mean(f1_values),
                "validation_macro_f1_sample_std": _sample_standard_deviation(
                    f1_values
                ),
                "validation_weighted_log_loss_mean": mean(loss_values),
                "validation_weighted_log_loss_sample_std": (
                    _sample_standard_deviation(loss_values)
                ),
                "selected_epoch_mean": mean(epochs),
                "selected_epochs": epochs,
            }
        )
    return aggregates


def _select_variant(aggregates: list[dict[str, Any]]) -> dict[str, Any]:
    if not aggregates:
        raise ValueError("no validation aggregates are available")
    return sorted(
        aggregates,
        key=lambda item: (
            -item["validation_macro_f1_mean"],
            item["validation_weighted_log_loss_mean"],
            item["variant"],
        ),
    )[0]


def _plot_validation_summary(
    *, plt: Any, np: Any, aggregates: list[dict[str, Any]], output: Path
) -> None:
    names = [item["variant"] for item in aggregates]
    positions = np.arange(len(names), dtype=np.float64)
    figure, axes = plt.subplots(1, 2, figsize=(13, 5.5))
    axes[0].bar(
        positions,
        [item["validation_macro_f1_mean"] for item in aggregates],
        yerr=[item["validation_macro_f1_sample_std"] for item in aggregates],
        capsize=5,
        color="#2563eb",
    )
    axes[0].set_title("Validation macro-F1 across fixed seeds")
    axes[0].set_ylabel("Macro-F1 (mean ± sample SD)")
    axes[0].set_ylim(0.0, 1.0)
    axes[0].set_xticks(positions, names, rotation=20, ha="right")
    axes[0].grid(axis="y", alpha=0.25)
    axes[1].bar(
        positions,
        [item["validation_weighted_log_loss_mean"] for item in aggregates],
        yerr=[
            item["validation_weighted_log_loss_sample_std"]
            for item in aggregates
        ],
        capsize=5,
        color="#7c3aed",
    )
    axes[1].set_title("Validation weighted log-loss")
    axes[1].set_ylabel("Loss (mean ± sample SD; lower is better)")
    axes[1].set_xticks(positions, names, rotation=20, ha="right")
    axes[1].grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_validation_curves(
    *,
    plt: Any,
    np: Any,
    results: list[dict[str, Any]],
    variants: list[str],
    output: Path,
) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(14, 5.5))
    for variant in variants:
        local = [item for item in results if item["variant"] == variant]
        epochs = [row["epoch"] for row in local[0]["history"]]
        f1_matrix = np.asarray(
            [
                [row["validation_macro_f1"] for row in item["history"]]
                for item in local
            ],
            dtype=np.float64,
        )
        loss_matrix = np.asarray(
            [
                [row["validation_weighted_log_loss"] for row in item["history"]]
                for item in local
            ],
            dtype=np.float64,
        )
        f1_mean = f1_matrix.mean(axis=0)
        f1_std = f1_matrix.std(axis=0, ddof=1) if len(local) > 1 else 0.0
        loss_mean = loss_matrix.mean(axis=0)
        loss_std = loss_matrix.std(axis=0, ddof=1) if len(local) > 1 else 0.0
        axes[0].plot(epochs, f1_mean, label=variant)
        axes[0].fill_between(epochs, f1_mean - f1_std, f1_mean + f1_std, alpha=0.14)
        axes[1].plot(epochs, loss_mean, label=variant)
        axes[1].fill_between(
            epochs, loss_mean - loss_std, loss_mean + loss_std, alpha=0.14
        )
    axes[0].set_title("Validation macro-F1 by epoch")
    axes[0].set_xlabel("Epoch")
    axes[0].set_ylabel("Macro-F1 (mean ± sample SD)")
    axes[0].set_ylim(0.0, 1.0)
    axes[1].set_title("Validation weighted log-loss by epoch")
    axes[1].set_xlabel("Epoch")
    axes[1].set_ylabel("Weighted log-loss")
    for axis in axes:
        axis.grid(alpha=0.22)
        axis.legend()
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def run_validation_experiment(
    *,
    dataset_workspace: Path,
    config_path: Path,
    output: Path,
    variants: list[str],
    seeds: list[int],
    epochs: int | None,
    lower_quantile: float,
    upper_quantile: float,
) -> dict[str, Any]:
    from fl_forensics.class_weighting import compute_class_weights
    from fl_forensics.robust_preprocessing import (
        TRANSFORM_MODES,
        apply_feature_transform,
    )

    dependencies = _dependencies()
    plt, np = dependencies[:2]
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"experiment output is not empty: {output}")
    if not variants or len(set(variants)) != len(variants):
        raise ValueError("variants must be a non-empty unique list")
    unknown_variants = sorted(set(variants) - set(TRANSFORM_MODES))
    if unknown_variants:
        raise ValueError(f"unsupported variants: {unknown_variants}")
    if not seeds or len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be a non-empty unique list")

    context = _load_experiment(
        dataset_workspace=dataset_workspace,
        config_path=config_path,
        include_test=False,
    )
    config = context["config"]
    model_config = config["model"]
    federation_config = config["federation"]
    epoch_count = int(epochs or model_config["max_iterations"])
    if epoch_count < 1:
        raise ValueError("epochs must be positive")
    feature_names = [str(name) for name in context["dataset"]["feature_names"]]
    raw_train, train_labels = _raw_arrays(
        np=np, rows=context["split_rows"]["train"]
    )
    raw_validation, validation_labels = _raw_arrays(
        np=np, rows=context["split_rows"]["validation"]
    )
    specifications = _fit_transforms(
        raw_train_features=raw_train,
        feature_names=feature_names,
        variants=variants,
        lower_quantile=lower_quantile,
        upper_quantile=upper_quantile,
        baseline_scaler=context["scaler"],
    )
    class_weights = compute_class_weights(
        train_labels.tolist(), strategy=str(model_config["class_weighting"])
    )
    output.mkdir(parents=True, exist_ok=True)
    transforms_dir = output / "transforms"
    transforms_dir.mkdir()
    for variant, specification in specifications.items():
        _write_json(transforms_dir / f"{variant}.json", specification)

    results: list[dict[str, Any]] = []
    for variant in variants:
        specification = specifications[variant]
        train_features = apply_feature_transform(
            features=raw_train,
            feature_names=feature_names,
            specification=specification,
        )
        validation_features = apply_feature_transform(
            features=raw_validation,
            feature_names=feature_names,
            specification=specification,
        )
        for seed in seeds:
            print(f"validation variant={variant} seed={seed}", flush=True)
            run, _model = _train_run(
                np=np,
                train_features=train_features,
                train_labels=train_labels,
                validation_features=validation_features,
                validation_labels=validation_labels,
                test_features=None,
                test_labels=None,
                class_names=context["class_names"],
                class_weights=class_weights,
                model_config=model_config,
                federation_config=federation_config,
                seed=seed,
                epochs=epoch_count,
                dependencies=dependencies,
            )
            run["variant"] = variant
            results.append(run)

    aggregates = _aggregate_validation(results, variants)
    selected = _select_variant(aggregates)
    selected_mode = str(selected["variant"])
    selection = {
        "schema_version": "1.0",
        "artifact_type": "m2_preprocessing_validation_selection",
        "dataset": context["dataset"]["dataset"],
        "dataset_sha256": context["dataset_sha256"],
        "config_sha256": context["config_sha256"],
        "seeds": seeds,
        "epochs": epoch_count,
        "variants": variants,
        "class_weighting": str(model_config["class_weighting"]),
        "selection_policy": (
            "maximize mean validation macro-F1 across predeclared seeds; "
            "tie-break by minimum mean validation weighted log-loss"
        ),
        "selected_variant": selected_mode,
        "selected_validation_aggregate": selected,
        "selected_transform": specifications[selected_mode],
        "selected_transform_sha256": _object_sha256(
            specifications[selected_mode]
        ),
        "test_observed_during_selection": False,
        "exploratory_disclosure": (
            "The preprocessing hypothesis was motivated by an earlier test-error "
            "audit; variant and epoch selection in this experiment use validation only."
        ),
    }
    _write_json(output / "validation_results.json", {"runs": results})
    _write_json(output / "validation_aggregates.json", {"variants": aggregates})
    _write_json(output / "selection.json", selection)
    _plot_validation_summary(
        plt=plt,
        np=np,
        aggregates=aggregates,
        output=output / "validation_variant_comparison.png",
    )
    _plot_validation_curves(
        plt=plt,
        np=np,
        results=results,
        variants=variants,
        output=output / "validation_learning_curves.png",
    )
    artifact_names = sorted(
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file()
    )
    summary = {
        "status": "validation-complete",
        "dataset": context["dataset"]["dataset"],
        "selected_variant": selected_mode,
        "test_evaluated": False,
        "seed_count": len(seeds),
        "variant_count": len(variants),
        "output": str(output),
        "artifact_sha256": {
            name: _sha256_file(output / name) for name in artifact_names
        },
    }
    _write_json(output / "summary.json", summary)
    return summary


def _aggregate_test(
    results: list[dict[str, Any]], class_names: list[str]
) -> dict[str, Any]:
    f1_values = [
        float(item["metrics"]["test"]["macro_f1_all_model_classes"])
        for item in results
    ]
    accuracy_values = [
        float(item["metrics"]["test"]["accuracy"]) for item in results
    ]
    loss_values = [
        float(
            item["metrics"]["test"]["weighted_log_loss_training_policy"]
        )
        for item in results
    ]
    return {
        "run_count": len(results),
        "test_macro_f1_mean": mean(f1_values),
        "test_macro_f1_sample_std": _sample_standard_deviation(f1_values),
        "test_accuracy_mean": mean(accuracy_values),
        "test_accuracy_sample_std": _sample_standard_deviation(accuracy_values),
        "test_weighted_log_loss_mean": mean(loss_values),
        "test_weighted_log_loss_sample_std": _sample_standard_deviation(
            loss_values
        ),
        "per_class_f1": {
            class_name: {
                "mean": mean(
                    [
                        float(item["metrics"]["test"]["per_class"][class_name]["f1"])
                        for item in results
                    ]
                ),
                "sample_std": _sample_standard_deviation(
                    [
                        float(item["metrics"]["test"]["per_class"][class_name]["f1"])
                        for item in results
                    ]
                ),
            }
            for class_name in class_names
        },
    }


def _plot_test_per_class(
    *, plt: Any, np: Any, aggregate: dict[str, Any], output: Path
) -> None:
    values = aggregate["per_class_f1"]
    names = list(values)
    positions = np.arange(len(names), dtype=np.float64)
    figure, axis = plt.subplots(figsize=(11, 6))
    axis.bar(
        positions,
        [values[name]["mean"] for name in names],
        yerr=[values[name]["sample_std"] for name in names],
        capsize=5,
        color="#2563eb",
    )
    axis.set_title("Frozen preprocessing — test per-class F1 across fixed seeds")
    axis.set_ylabel("F1 (mean ± sample SD)")
    axis.set_ylim(0.0, 1.0)
    axis.set_xticks(positions, names, rotation=30, ha="right")
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def run_final_test(
    *,
    dataset_workspace: Path,
    config_path: Path,
    output: Path,
    selection_path: Path,
) -> dict[str, Any]:
    from fl_forensics.class_weighting import compute_class_weights
    from fl_forensics.robust_preprocessing import apply_feature_transform

    dependencies = _dependencies()
    plt, np = dependencies[:2]
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"final-test output is not empty: {output}")
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    if selection.get("artifact_type") != "m2_preprocessing_validation_selection":
        raise ValueError("selection artifact has the wrong type")
    if selection.get("test_observed_during_selection") is not False:
        raise ValueError("selection artifact does not preserve the test boundary")

    context = _load_experiment(
        dataset_workspace=dataset_workspace,
        config_path=config_path,
        include_test=True,
    )
    if selection.get("dataset_sha256") != context["dataset_sha256"]:
        raise ValueError("selection and dataset SHA-256 values differ")
    if selection.get("config_sha256") != context["config_sha256"]:
        raise ValueError("selection and configuration SHA-256 values differ")
    selected_specification = selection["selected_transform"]
    if _object_sha256(selected_specification) != selection.get(
        "selected_transform_sha256"
    ):
        raise ValueError("selected transform digest mismatch")

    config = context["config"]
    model_config = config["model"]
    federation_config = config["federation"]
    feature_names = [str(name) for name in context["dataset"]["feature_names"]]
    raw_train, train_labels = _raw_arrays(
        np=np, rows=context["split_rows"]["train"]
    )
    raw_validation, validation_labels = _raw_arrays(
        np=np, rows=context["split_rows"]["validation"]
    )
    raw_test, test_labels = _raw_arrays(
        np=np, rows=context["split_rows"]["test"]
    )
    winsor = selected_specification["winsorization"]
    recomputed_specification = _fit_transforms(
        raw_train_features=raw_train,
        feature_names=feature_names,
        variants=[str(selection["selected_variant"])],
        lower_quantile=float(winsor["lower_quantile"]),
        upper_quantile=float(winsor["upper_quantile"]),
        baseline_scaler=context["scaler"],
    )[str(selection["selected_variant"])]
    if _object_sha256(recomputed_specification) != selection.get(
        "selected_transform_sha256"
    ):
        raise ValueError("training-only transform cannot be reproduced")

    train_features = apply_feature_transform(
        features=raw_train,
        feature_names=feature_names,
        specification=recomputed_specification,
    )
    validation_features = apply_feature_transform(
        features=raw_validation,
        feature_names=feature_names,
        specification=recomputed_specification,
    )
    test_features = apply_feature_transform(
        features=raw_test,
        feature_names=feature_names,
        specification=recomputed_specification,
    )
    class_weights = compute_class_weights(
        train_labels.tolist(), strategy=str(model_config["class_weighting"])
    )
    seeds = [int(seed) for seed in selection["seeds"]]
    epoch_count = int(selection["epochs"])
    results: list[dict[str, Any]] = []
    for seed in seeds:
        print(
            f"final-test variant={selection['selected_variant']} seed={seed}",
            flush=True,
        )
        run, _model = _train_run(
            np=np,
            train_features=train_features,
            train_labels=train_labels,
            validation_features=validation_features,
            validation_labels=validation_labels,
            test_features=test_features,
            test_labels=test_labels,
            class_names=context["class_names"],
            class_weights=class_weights,
            model_config=model_config,
            federation_config=federation_config,
            seed=seed,
            epochs=epoch_count,
            dependencies=dependencies,
        )
        run["variant"] = str(selection["selected_variant"])
        results.append(run)
    aggregate = _aggregate_test(results, context["class_names"])
    output.mkdir(parents=True, exist_ok=True)
    _write_json(
        output / "final_test_results.json",
        {
            "selected_variant": selection["selected_variant"],
            "selection_sha256": _sha256_file(selection_path),
            "runs": results,
            "aggregate": aggregate,
        },
    )
    _plot_test_per_class(
        plt=plt,
        np=np,
        aggregate=aggregate,
        output=output / "test_per_class_f1.png",
    )
    artifact_names = sorted(path.name for path in output.iterdir() if path.is_file())
    summary = {
        "status": "final-test-complete",
        "dataset": context["dataset"]["dataset"],
        "selected_variant": selection["selected_variant"],
        "test_evaluated": True,
        "test_evaluated_variants": [selection["selected_variant"]],
        "seed_count": len(seeds),
        "aggregate": aggregate,
        "output": str(output),
        "artifact_sha256": {
            name: _sha256_file(output / name) for name in artifact_names
        },
    }
    _write_json(output / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("validation", "final-test"), required=True)
    parser.add_argument(
        "--dataset-workspace",
        type=Path,
        default=Path("artifacts/m2-data24-parquet"),
    )
    parser.add_argument("--config", type=Path, default=Path("configs/base.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--variants", nargs="+", default=list(DEFAULT_VARIANTS)
    )
    parser.add_argument("--seeds", nargs="+", type=int, default=list(DEFAULT_SEEDS))
    parser.add_argument("--epochs", type=int)
    parser.add_argument("--lower-quantile", type=float, default=0.001)
    parser.add_argument("--upper-quantile", type=float, default=0.999)
    parser.add_argument("--selection", type=Path)
    arguments = parser.parse_args()
    if arguments.phase == "validation":
        if arguments.selection is not None:
            parser.error("--selection is valid only for --phase final-test")
        summary = run_validation_experiment(
            dataset_workspace=arguments.dataset_workspace,
            config_path=arguments.config,
            output=arguments.output,
            variants=[str(item) for item in arguments.variants],
            seeds=[int(item) for item in arguments.seeds],
            epochs=arguments.epochs,
            lower_quantile=arguments.lower_quantile,
            upper_quantile=arguments.upper_quantile,
        )
    else:
        if arguments.selection is None:
            parser.error("--selection is required for --phase final-test")
        summary = run_final_test(
            dataset_workspace=arguments.dataset_workspace,
            config_path=arguments.config,
            output=arguments.output,
            selection_path=arguments.selection,
        )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
