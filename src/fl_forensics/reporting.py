"""Deterministic visual reports derived from verified M3 metric artifacts."""

from __future__ import annotations

import io
import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_file
from .dataset24 import DATASET_NAME
from .preprocessing import derived_json_bytes
from .storage import write_once


class ReportingDependencyError(RuntimeError):
    """Raised when the optional plotting dependency is unavailable."""


def _plotting_dependencies() -> tuple[Any, Any]:
    cache_root = Path(tempfile.gettempdir()) / "fl-forensics-matplotlib"
    cache_root.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(cache_root))
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise ReportingDependencyError(
            'M3 reporting requires: python -m pip install -e ".[reporting]"'
        ) from exc
    return matplotlib, plt


def _load_json(path: Path, description: str) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"missing {description}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {description}: {path}") from exc
    if not isinstance(value, dict):
        raise TypeError(f"{description} must contain a JSON object: {path}")
    return value


def _validated_m3_sources(
    workspace: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str]]:
    manifest_path = workspace / "manifest.json"
    metrics_path = workspace / "metrics.json"
    comparison_path = workspace / "comparison.json"
    manifest = _load_json(manifest_path, "M3 run manifest")
    metrics = _load_json(metrics_path, "M3 metrics artifact")
    comparison = _load_json(comparison_path, "M3 comparison artifact")
    if manifest.get("dataset") != DATASET_NAME or metrics.get("dataset") != DATASET_NAME:
        raise ValueError("M3 reporting accepts only UWF-ZeekData24 artifacts")
    if metrics.get("partition_mode") != manifest.get("partition_mode"):
        raise ValueError("M3 metrics partition mode does not match the run manifest")
    actual_metrics_digest = sha256_file(metrics_path)
    actual_comparison_digest = sha256_file(comparison_path)
    if actual_metrics_digest != manifest.get("metrics_sha256"):
        raise ValueError("M3 metrics digest does not match the run manifest")
    if actual_comparison_digest != manifest.get("comparison_sha256"):
        raise ValueError("M3 comparison digest does not match the run manifest")
    return (
        manifest,
        metrics,
        comparison,
        {
            "m3_run_manifest_sha256": sha256_file(manifest_path),
            "m3_metrics_sha256": actual_metrics_digest,
            "m3_comparison_sha256": actual_comparison_digest,
        },
    )


def _validated_central_source(workspace: Path) -> tuple[dict[str, Any], dict[str, str]]:
    manifest_path = workspace / "manifest.json"
    metrics_path = workspace / "metrics.json"
    manifest = _load_json(manifest_path, "M2 centralized baseline manifest")
    metrics = _load_json(metrics_path, "M2 centralized baseline metrics")
    if manifest.get("dataset") != DATASET_NAME or metrics.get("dataset") != DATASET_NAME:
        raise ValueError("central comparison accepts only UWF-ZeekData24 artifacts")
    actual_digest = sha256_file(metrics_path)
    if actual_digest != manifest.get("metrics_sha256"):
        raise ValueError("centralized metrics digest does not match its manifest")
    return metrics, {
        "central_manifest_sha256": sha256_file(manifest_path),
        "central_metrics_sha256": actual_digest,
    }


def _metric_percent(value: Any) -> float:
    if value is None:
        raise ValueError("required report metric is null")
    return float(value) * 100.0


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)


def _style_axes(ax: Any, *, grid_axis: str = "y") -> None:
    ax.grid(axis=grid_axis, color="#d8dee9", linewidth=0.8, alpha=0.75)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _figure_bytes(fig: Any, *, plt: Any) -> bytes:
    buffer = io.BytesIO()
    fig.savefig(
        buffer,
        format="png",
        dpi=180,
        bbox_inches="tight",
        facecolor="white",
        metadata={"Software": f"fl-forensics {__version__}"},
    )
    plt.close(fig)
    return buffer.getvalue()


def _write_figure(
    *,
    output: Path,
    filename: str,
    description: str,
    build: Callable[[], Any],
    plt: Any,
) -> dict[str, Any]:
    path = output / filename
    content = _figure_bytes(build(), plt=plt)
    write_once(path, content)
    return {
        "path": filename,
        "description": description,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _matrix_figure(
    *,
    plt: Any,
    labels: list[str],
    values: list[list[float]],
    normalized: bool,
    title: str,
) -> Any:
    if len(values) != len(labels) or any(len(row) != len(labels) for row in values):
        raise ValueError("confusion matrix dimensions do not match its labels")
    fig, ax = plt.subplots(figsize=(9.4, 7.8))
    _draw_matrix_axis(
        fig=fig,
        ax=ax,
        labels=labels,
        values=values,
        normalized=normalized,
        title=title,
    )
    fig.tight_layout()
    return fig


def _draw_matrix_axis(
    *,
    fig: Any,
    ax: Any,
    labels: list[str],
    values: list[list[float]],
    normalized: bool,
    title: str,
) -> None:
    image = ax.imshow(values, cmap="Blues", vmin=0, vmax=1 if normalized else None)
    display_labels = [label.replace("_", " ") for label in labels]
    ax.set_xticks(range(len(labels)), display_labels, rotation=35, ha="right")
    ax.set_yticks(range(len(labels)), display_labels)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("Actual class")
    ax.set_title(title)
    maximum = max((max(row) for row in values), default=0.0)
    threshold = (0.5 if normalized else maximum / 2.0) if maximum else 0.0
    for row_index, row in enumerate(values):
        for column_index, value in enumerate(row):
            text = f"{value * 100:.1f}%" if normalized else f"{int(value)}"
            ax.text(
                column_index,
                row_index,
                text,
                ha="center",
                va="center",
                fontsize=8.5,
                color="white" if value > threshold else "#17202a",
            )
    colorbar = fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    colorbar.set_label("Share of actual class" if normalized else "Window count")


def _matrix_data(
    evaluation: dict[str, Any],
) -> tuple[list[str], list[list[float]], list[list[float]]]:
    matrix = evaluation.get("confusion_matrix")
    if not isinstance(matrix, dict):
        raise TypeError("evaluation contains no confusion matrix")
    labels = [str(label) for label in matrix.get("labels", [])]
    values = [[float(value) for value in row] for row in matrix.get("values", [])]
    if not labels or len(values) != len(labels) or any(len(row) != len(labels) for row in values):
        raise ValueError("confusion matrix dimensions do not match its labels")
    normalized = [[value / sum(row) if sum(row) else 0.0 for value in row] for row in values]
    return labels, values, normalized


def _client_confusion_figure(
    *,
    plt: Any,
    client_id: str,
    selected_evaluation: dict[str, Any],
    local_evaluation: dict[str, Any] | None,
) -> Any:
    evaluations = [("Selected FedAvg", selected_evaluation)]
    if local_evaluation is not None:
        evaluations.append(("Local-only", local_evaluation))
    fig, axes = plt.subplots(
        2,
        len(evaluations),
        figsize=(8.2 * len(evaluations), 12.2),
        squeeze=False,
    )
    expected_labels: list[str] | None = None
    for column, (model_name, evaluation) in enumerate(evaluations):
        labels, absolute, normalized = _matrix_data(evaluation)
        if expected_labels is None:
            expected_labels = labels
        elif labels != expected_labels:
            raise ValueError(f"{client_id} model confusion-matrix labels do not match")
        _draw_matrix_axis(
            fig=fig,
            ax=axes[0][column],
            labels=labels,
            values=absolute,
            normalized=False,
            title=f"{model_name} — absolute counts",
        )
        _draw_matrix_axis(
            fig=fig,
            ax=axes[1][column],
            labels=labels,
            values=normalized,
            normalized=True,
            title=f"{model_name} — row-normalized",
        )
    fig.suptitle(f"{client_id} local test confusion matrices", fontsize=16, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    return fig


def _per_class_figure(*, plt: Any, labels: list[str], per_class: dict[str, Any]) -> Any:
    missing = [label for label in labels if label not in per_class]
    if missing:
        raise ValueError(f"per-class metrics are missing labels: {missing}")
    positions = list(range(len(labels)))
    width = 0.24
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    for offset, key, display in (
        (-width, "precision", "Precision"),
        (0.0, "recall", "Recall"),
        (width, "f1", "F1"),
    ):
        ax.bar(
            [position + offset for position in positions],
            [_metric_percent(per_class[label][key]) for label in labels],
            width=width,
            label=display,
        )
    tick_labels = [
        f"{label.replace('_', ' ')}\n(n={int(per_class[label]['support'])})" for label in labels
    ]
    ax.set_xticks(positions, tick_labels, rotation=25, ha="right")
    ax.set_ylim(0, 100)
    ax.set_ylabel("Score (%)")
    ax.set_title("Test precision, recall, and F1 by class")
    ax.legend(frameon=False, ncol=3)
    _style_axes(ax)
    fig.tight_layout()
    return fig


def _validation_figure(*, plt: Any, rounds: list[dict[str, Any]]) -> Any:
    x_values = [int(item["round"]) for item in rounds]
    y_values = [
        _metric_percent(item["validation"]["macro_f1_all_model_classes"]) for item in rounds
    ]
    if not x_values:
        raise ValueError("M3 metrics contain no rounds")
    best_index = max(range(len(y_values)), key=y_values.__getitem__)
    fig, ax = plt.subplots(figsize=(10.5, 5.5))
    ax.plot(x_values, y_values, linewidth=2.0, marker="o", markersize=3.5)
    ax.scatter([x_values[best_index]], [y_values[best_index]], s=70, zorder=3)
    ax.annotate(
        f"Best: round {x_values[best_index]} ({y_values[best_index]:.2f}%)",
        (x_values[best_index], y_values[best_index]),
        xytext=(8, 10),
        textcoords="offset points",
    )
    ax.set_xlabel("Federated round")
    ax.set_ylabel("Validation macro-F1 (%)")
    ax.set_title("FedAvg validation performance by round")
    ax.set_ylim(0, 100)
    _style_axes(ax)
    fig.tight_layout()
    return fig


def _training_loss_figure(*, plt: Any, rounds: list[dict[str, Any]]) -> Any:
    x_values = [int(item["round"]) for item in rounds]
    y_values = [float(item["weighted_training_loss"]) for item in rounds]
    if not x_values:
        raise ValueError("M3 metrics contain no rounds")
    fig, ax = plt.subplots(figsize=(10.5, 5.5))
    ax.plot(x_values, y_values, linewidth=2.0, marker="o", markersize=3.5)
    ax.set_xlabel("Federated round")
    ax.set_ylabel("Example-weighted local training loss")
    ax.set_title("Training loss by federated round")
    _style_axes(ax)
    fig.tight_layout()
    return fig


def _comparison_figure(
    *,
    plt: Any,
    comparison: dict[str, Any],
    central_test_f1: float | None,
) -> Any:
    local_summary = comparison["local_only_summary"]["global_test_macro_f1"]
    fedavg_checkpoint = comparison.get("fedavg_selected", comparison.get("fedavg_final"))
    if not isinstance(fedavg_checkpoint, dict):
        raise TypeError("comparison artifact contains no FedAvg checkpoint")
    categories = ["Local-only mean", "FedAvg"]
    values = [
        _metric_percent(local_summary["mean"]),
        _metric_percent(fedavg_checkpoint["test"]["macro_f1_all_model_classes"]),
    ]
    errors = [_metric_percent(local_summary["population_stddev"]), 0.0]
    if central_test_f1 is not None:
        categories.append("Centralized")
        values.append(_metric_percent(central_test_f1))
        errors.append(0.0)
    fig, ax = plt.subplots(figsize=(8.8, 5.8))
    bars = ax.bar(categories, values, yerr=errors, capsize=6)
    ax.bar_label(bars, labels=[f"{value:.2f}%" for value in values], padding=4)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Test macro-F1 (%)")
    ax.set_title("Local-only, FedAvg, and centralized comparison")
    fig.text(
        0.5,
        0.015,
        "Local-only error bar: ±1 population standard deviation across clients",
        ha="center",
        fontsize=8.5,
        color="#52606d",
    )
    _style_axes(ax)
    fig.tight_layout(rect=(0, 0.045, 1, 1))
    return fig


def _per_client_figure(*, plt: Any, comparison: dict[str, Any]) -> Any:
    clients = sorted(comparison.get("local_only_clients", []), key=lambda item: item["client_id"])
    if not clients:
        raise ValueError("comparison artifact contains no local-only client results")
    identifiers = [str(item["client_id"]) for item in clients]
    values = [
        _metric_percent(item["global_test"]["macro_f1_all_model_classes"]) for item in clients
    ]
    fedavg_checkpoint = comparison.get("fedavg_selected", comparison.get("fedavg_final"))
    if not isinstance(fedavg_checkpoint, dict):
        raise TypeError("comparison artifact contains no FedAvg checkpoint")
    fedavg = _metric_percent(fedavg_checkpoint["test"]["macro_f1_all_model_classes"])
    fig, ax = plt.subplots(figsize=(10.8, 6.5))
    bars = ax.barh(identifiers, values)
    ax.bar_label(bars, labels=[f"{value:.2f}%" for value in values], padding=4)
    ax.axvline(fedavg, linestyle="--", linewidth=2.0, label=f"FedAvg: {fedavg:.2f}%")
    ax.set_xlim(0, 100)
    ax.set_xlabel("Global test macro-F1 (%)")
    ax.set_ylabel("Local-only client model")
    ax.set_title("Local-only model performance by client")
    ax.legend(frameon=False, loc="lower right")
    _style_axes(ax, grid_axis="x")
    fig.tight_layout()
    return fig


def _selected_global_client_validation_figure(*, plt: Any, comparison: dict[str, Any]) -> Any:
    clients = sorted(
        comparison.get("selected_global_client_validation", []),
        key=lambda item: item["client_id"],
    )
    if not clients:
        raise ValueError("comparison artifact contains no selected-model client validation results")
    identifiers = [str(item["client_id"]) for item in clients]
    values = [_metric_percent(item["validation"]["macro_f1_all_model_classes"]) for item in clients]
    mean_value = sum(values) / len(values)
    fig, ax = plt.subplots(figsize=(10.8, 6.5))
    bars = ax.barh(identifiers, values)
    ax.bar_label(bars, labels=[f"{value:.2f}%" for value in values], padding=4)
    ax.axvline(
        mean_value,
        linestyle="--",
        linewidth=2.0,
        label=f"Client mean: {mean_value:.2f}%",
    )
    ax.set_xlim(0, 100)
    ax.set_xlabel("Client validation macro-F1 (%)")
    ax.set_ylabel("Client snapshot")
    ax.set_title("Selected global model performance by client")
    ax.legend(frameon=False, loc="lower right")
    _style_axes(ax, grid_axis="x")
    fig.tight_layout()
    return fig


def _client_local_test_figure(*, plt: Any, comparison: dict[str, Any]) -> Any:
    global_items = {
        str(item["client_id"]): item["test"]
        for item in comparison.get("selected_global_client_test", [])
        if item.get("test", {}).get("macro_f1_all_model_classes") is not None
    }
    local_items = {
        str(item["client_id"]): item["local_test"]
        for item in comparison.get("local_only_clients", [])
        if "local_test" in item
    }
    identifiers = sorted(global_items)
    if not identifiers:
        raise ValueError("comparison artifact contains no client-local test results")
    positions = list(range(len(identifiers)))
    selected_values = [
        _metric_percent(global_items[client_id]["macro_f1_all_model_classes"])
        for client_id in identifiers
    ]
    has_local_comparison = all(
        client_id in local_items
        and local_items[client_id].get("macro_f1_all_model_classes") is not None
        for client_id in identifiers
    )
    height = 0.38
    fig, ax = plt.subplots(figsize=(11.2, 7.0))
    selected_positions = (
        [position - height / 2 for position in positions] if has_local_comparison else positions
    )
    ax.barh(
        selected_positions,
        selected_values,
        height=height if has_local_comparison else 0.65,
        label="Selected FedAvg",
    )
    if has_local_comparison:
        local_values = [
            _metric_percent(local_items[client_id]["macro_f1_all_model_classes"])
            for client_id in identifiers
        ]
        ax.barh(
            [position + height / 2 for position in positions],
            local_values,
            height=height,
            label="Local-only",
        )
    ax.set_yticks(positions, identifiers)
    ax.set_xlim(0, 100)
    ax.set_xlabel("Client-local test macro-F1 (%)")
    ax.set_ylabel("Evaluation-only client test")
    ax.set_title(
        "Selected global vs local-only model on each client domain"
        if has_local_comparison
        else "Selected global model on each client domain"
    )
    ax.legend(frameon=False, loc="lower right")
    _style_axes(ax, grid_axis="x")
    fig.tight_layout()
    return fig


def generate_m3_report(
    *,
    workspace: Path,
    output: Path | None = None,
    central_workspace: Path | None = None,
) -> dict[str, Any]:
    """Generate immutable plots from digest-validated M3 metric artifacts."""

    manifest, metrics, comparison, source_digests = _validated_m3_sources(workspace)
    central_test_f1 = None
    if central_workspace is not None:
        central_metrics, central_digests = _validated_central_source(central_workspace)
        source_digests.update(central_digests)
        central_test_f1 = float(central_metrics["metrics"]["test"]["macro_f1_all_model_classes"])
    matplotlib, plt = _plotting_dependencies()
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.titleweight": "bold",
            "axes.titlesize": 14,
            "axes.labelsize": 10.5,
            "legend.fontsize": 9.5,
        }
    )
    report_output = output if output is not None else workspace / "reports"
    selected = metrics.get("selected")
    legacy_final_round_protocol = not isinstance(selected, dict)
    evaluated_checkpoint = metrics["final"] if legacy_final_round_protocol else selected
    selected_test = evaluated_checkpoint["test"]
    labels, _test_absolute, _test_normalized = _matrix_data(selected_test)
    rounds = metrics.get("rounds", [])
    figures: list[dict[str, Any]] = []
    global_confusion_matrices: dict[str, dict[str, Any]] = {}
    split_titles = {
        "validation": "Validation",
        "test": "Test",
        "temporal_holdout": "Temporal holdout (benign-only)",
    }
    for split, display_name in split_titles.items():
        evaluation = evaluated_checkpoint.get(split)
        if not isinstance(evaluation, dict) or "confusion_matrix" not in evaluation:
            continue
        split_labels, absolute_values, normalized_values = _matrix_data(evaluation)
        if split_labels != labels:
            raise ValueError(f"selected checkpoint {split} class labels do not match test")
        global_confusion_matrices[split] = evaluation["confusion_matrix"]
        slug = split.replace("_", "-")
        figures.extend(
            [
                _write_figure(
                    output=report_output,
                    filename=f"confusion-matrix-{slug}.png",
                    description=(
                        f"Absolute {display_name.lower()} confusion matrix; "
                        "rows are actual classes."
                    ),
                    build=lambda labels=split_labels, values=absolute_values, name=display_name: (
                        _matrix_figure(
                            plt=plt,
                            labels=labels,
                            values=values,
                            normalized=False,
                            title=f"{name} confusion matrix — absolute counts",
                        )
                    ),
                    plt=plt,
                ),
                _write_figure(
                    output=report_output,
                    filename=f"confusion-matrix-{slug}-normalized.png",
                    description=(
                        f"Row-normalized {display_name.lower()} confusion matrix; "
                        "rows are actual classes."
                    ),
                    build=lambda labels=split_labels, values=normalized_values, name=display_name: (
                        _matrix_figure(
                            plt=plt,
                            labels=labels,
                            values=values,
                            normalized=True,
                            title=f"{name} confusion matrix — row-normalized",
                        )
                    ),
                    plt=plt,
                ),
            ]
        )
    figures.extend(
        [
            _write_figure(
                output=report_output,
                filename="per-class-metrics-test.png",
                description="Test precision, recall, F1, and support by class.",
                build=lambda: _per_class_figure(
                    plt=plt, labels=labels, per_class=selected_test["per_class"]
                ),
                plt=plt,
            ),
            _write_figure(
                output=report_output,
                filename="validation-by-round.png",
                description="Validation macro-F1 over federated rounds.",
                build=lambda: _validation_figure(plt=plt, rounds=rounds),
                plt=plt,
            ),
            _write_figure(
                output=report_output,
                filename="training-loss-by-round.png",
                description="Example-weighted local training loss over federated rounds.",
                build=lambda: _training_loss_figure(plt=plt, rounds=rounds),
                plt=plt,
            ),
        ]
    )
    if comparison.get("local_only_clients"):
        figures.extend(
            [
                _write_figure(
                    output=report_output,
                    filename="local-vs-fedavg.png",
                    description=(
                        "Local-only mean, FedAvg, and optional centralized test macro-F1."
                    ),
                    build=lambda: _comparison_figure(
                        plt=plt,
                        comparison=comparison,
                        central_test_f1=central_test_f1,
                    ),
                    plt=plt,
                ),
                _write_figure(
                    output=report_output,
                    filename="per-client-test-macro-f1.png",
                    description="Global test macro-F1 of each local-only client model.",
                    build=lambda: _per_client_figure(plt=plt, comparison=comparison),
                    plt=plt,
                ),
            ]
        )
    if comparison.get("selected_global_client_validation"):
        figures.append(
            _write_figure(
                output=report_output,
                filename="selected-global-per-client-validation.png",
                description=(
                    "Validation macro-F1 of the selected global model on each client snapshot."
                ),
                build=lambda: _selected_global_client_validation_figure(
                    plt=plt, comparison=comparison
                ),
                plt=plt,
            )
        )
    if any(
        item.get("test", {}).get("macro_f1_all_model_classes") is not None
        for item in comparison.get("selected_global_client_test", [])
    ):
        figures.append(
            _write_figure(
                output=report_output,
                filename="selected-global-vs-local-only-client-test.png",
                description=(
                    "Selected FedAvg and local-only macro-F1 on each separate client test."
                ),
                build=lambda: _client_local_test_figure(plt=plt, comparison=comparison),
                plt=plt,
            )
        )
    selected_client_tests = {
        str(item["client_id"]): item["test"]
        for item in comparison.get("selected_global_client_test", [])
        if isinstance(item.get("test", {}).get("confusion_matrix"), dict)
    }
    local_client_tests = {
        str(item["client_id"]): item["local_test"]
        for item in comparison.get("local_only_clients", [])
        if isinstance(item.get("local_test", {}).get("confusion_matrix"), dict)
    }
    client_confusion_paths: list[str] = []
    for client_id in sorted(selected_client_tests):
        if not client_id or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for character in client_id
        ):
            raise ValueError(f"unsafe client identifier in report: {client_id!r}")
        filename = f"per-client-confusion/{client_id}.png"
        figures.append(
            _write_figure(
                output=report_output,
                filename=filename,
                description=(
                    f"{client_id} local-test confusion matrices for selected FedAvg"
                    + (" and local-only models." if client_id in local_client_tests else ".")
                ),
                build=lambda identifier=client_id: _client_confusion_figure(
                    plt=plt,
                    client_id=identifier,
                    selected_evaluation=selected_client_tests[identifier],
                    local_evaluation=local_client_tests.get(identifier),
                ),
                plt=plt,
            )
        )
        client_confusion_paths.append(filename)
    validation_values = [
        (int(item["round"]), float(item["validation"]["macro_f1_all_model_classes"]))
        for item in rounds
    ]
    if not validation_values:
        raise ValueError("M3 metrics contain no validation history")
    best_validation_round, best_validation_f1 = max(validation_values, key=lambda item: item[1])
    summary = {
        "schema_version": "2.0",
        "artifact_type": "m3_evaluation_report",
        "dataset": DATASET_NAME,
        "partition_mode": manifest["partition_mode"],
        "code_version": __version__,
        "reporting_backend": {
            "name": "matplotlib",
            "version": matplotlib.__version__,
        },
        "source_digests": source_digests,
        "metrics": {
            "final_round": int(metrics["final"]["round"]),
            "final_validation_macro_f1": float(
                metrics["final"]["validation"]["macro_f1_all_model_classes"]
            ),
            "selected_round": int(evaluated_checkpoint["round"]),
            "selected_validation_macro_f1": float(
                evaluated_checkpoint["validation"]["macro_f1_all_model_classes"]
            ),
            "selected_test_macro_f1": float(selected_test["macro_f1_all_model_classes"]),
            "best_validation_round": best_validation_round,
            "best_validation_macro_f1": best_validation_f1,
            "local_only_mean_test_macro_f1": _optional_float(
                comparison.get("local_only_summary", {}).get("global_test_macro_f1", {}).get("mean")
            ),
            "selected_global_client_unweighted_mean_test_macro_f1": (
                comparison.get("selected_global_client_test_summary", {})
                .get("macro_f1_all_model_classes", {})
                .get("mean")
            ),
            "local_only_client_unweighted_mean_local_test_macro_f1": (
                comparison.get("local_only_summary", {}).get("local_test_macro_f1", {}).get("mean")
            ),
            "centralized_test_macro_f1": central_test_f1,
        },
        "operational_metrics": evaluated_checkpoint.get("operational_metrics"),
        "class_labels": labels,
        "confusion_matrices": global_confusion_matrices,
        "confusion_matrix_figures": [
            item["path"] for item in figures if "confusion" in item["path"]
        ],
        "client_confusion_matrix_figures": client_confusion_paths,
        "figures": figures,
        "interpretation_constraints": [
            (
                "This legacy artifact retained the final-round model; the best validation "
                "round is diagnostic only."
                if legacy_final_round_protocol
                else "The reported checkpoint was selected using validation macro-F1 only."
            ),
            "The test split must not be used to select a round or tune hyperparameters.",
            "The temporal holdout is benign-only and is not presented as a multiclass result.",
            "The report is derived from digest-validated metrics and does not re-run inference.",
        ],
    }
    summary_bytes = derived_json_bytes(summary)
    write_once(report_output / "summary.json", summary_bytes)
    return {
        "status": "reported",
        "dataset": DATASET_NAME,
        "partition_mode": manifest["partition_mode"],
        "workspace": str(workspace),
        "output": str(report_output),
        "figure_count": len(figures),
        "best_validation_round": best_validation_round,
        "best_validation_macro_f1": best_validation_f1,
        "selected_round": int(evaluated_checkpoint["round"]),
        "selected_test_macro_f1": float(selected_test["macro_f1_all_model_classes"]),
        "confusion_matrices": global_confusion_matrices,
        "confusion_matrix_figures": [
            item["path"] for item in figures if "confusion" in item["path"]
        ],
        "client_confusion_matrix_figure_count": len(client_confusion_paths),
        "summary_sha256": sha256_file(report_output / "summary.json"),
    }
