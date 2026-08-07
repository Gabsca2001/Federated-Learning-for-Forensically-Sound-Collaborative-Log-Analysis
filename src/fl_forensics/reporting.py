"""Deterministic visual reports derived from verified M3 metric artifacts."""

from __future__ import annotations

import io
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable

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
        raise ValueError(f"{description} must contain a JSON object: {path}")
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
) -> Any:
    if len(values) != len(labels) or any(len(row) != len(labels) for row in values):
        raise ValueError("confusion matrix dimensions do not match its labels")
    fig, ax = plt.subplots(figsize=(9.4, 7.8))
    image = ax.imshow(values, cmap="Blues", vmin=0, vmax=1 if normalized else None)
    display_labels = [label.replace("_", " ") for label in labels]
    ax.set_xticks(range(len(labels)), display_labels, rotation=35, ha="right")
    ax.set_yticks(range(len(labels)), display_labels)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("Actual class")
    ax.set_title(
        "Test confusion matrix — row-normalized"
        if normalized
        else "Test confusion matrix — absolute counts"
    )
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
    fig.tight_layout()
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
        f"{label.replace('_', ' ')}\n(n={int(per_class[label]['support'])})"
        for label in labels
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
        _metric_percent(item["validation"]["macro_f1_all_model_classes"])
        for item in rounds
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
    categories = ["Local-only mean", "FedAvg"]
    values = [
        _metric_percent(local_summary["mean"]),
        _metric_percent(
            comparison["fedavg_final"]["test"]["macro_f1_all_model_classes"]
        ),
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
    clients = sorted(
        comparison.get("local_only_clients", []), key=lambda item: item["client_id"]
    )
    if not clients:
        raise ValueError("comparison artifact contains no local-only client results")
    identifiers = [str(item["client_id"]) for item in clients]
    values = [
        _metric_percent(item["global_test"]["macro_f1_all_model_classes"])
        for item in clients
    ]
    fedavg = _metric_percent(
        comparison["fedavg_final"]["test"]["macro_f1_all_model_classes"]
    )
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
        central_test_f1 = float(
            central_metrics["metrics"]["test"]["macro_f1_all_model_classes"]
        )
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
    final_test = metrics["final"]["test"]
    matrix = final_test["confusion_matrix"]
    labels = [str(label) for label in matrix["labels"]]
    absolute_values = [[float(value) for value in row] for row in matrix["values"]]
    normalized_values = [
        [value / sum(row) if sum(row) else 0.0 for value in row]
        for row in absolute_values
    ]
    rounds = metrics.get("rounds", [])
    figures = [
        _write_figure(
            output=report_output,
            filename="confusion-matrix-test.png",
            description="Absolute test confusion matrix; rows are actual classes.",
            build=lambda: _matrix_figure(
                plt=plt, labels=labels, values=absolute_values, normalized=False
            ),
            plt=plt,
        ),
        _write_figure(
            output=report_output,
            filename="confusion-matrix-test-normalized.png",
            description="Row-normalized test confusion matrix, robust to class imbalance.",
            build=lambda: _matrix_figure(
                plt=plt, labels=labels, values=normalized_values, normalized=True
            ),
            plt=plt,
        ),
        _write_figure(
            output=report_output,
            filename="per-class-metrics-test.png",
            description="Test precision, recall, F1, and support by class.",
            build=lambda: _per_class_figure(
                plt=plt, labels=labels, per_class=final_test["per_class"]
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
        _write_figure(
            output=report_output,
            filename="local-vs-fedavg.png",
            description="Local-only mean, FedAvg, and optional centralized test macro-F1.",
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
    validation_values = [
        (int(item["round"]), float(item["validation"]["macro_f1_all_model_classes"]))
        for item in rounds
    ]
    if not validation_values:
        raise ValueError("M3 metrics contain no validation history")
    best_validation_round, best_validation_f1 = max(
        validation_values, key=lambda item: item[1]
    )
    summary = {
        "schema_version": "1.0",
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
            "final_test_macro_f1": float(final_test["macro_f1_all_model_classes"]),
            "best_validation_round": best_validation_round,
            "best_validation_macro_f1": best_validation_f1,
            "local_only_mean_test_macro_f1": float(
                comparison["local_only_summary"]["global_test_macro_f1"]["mean"]
            ),
            "centralized_test_macro_f1": central_test_f1,
        },
        "class_labels": labels,
        "figures": figures,
        "interpretation_constraints": [
            (
                "The best validation round is diagnostic only; M3 training retained the "
                "final-round model."
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
        "final_test_macro_f1": float(final_test["macro_f1_all_model_classes"]),
        "summary_sha256": sha256_file(report_output / "summary.json"),
    }
