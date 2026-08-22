"""Deterministic validation-only selection and reporting for PROTEAN sweeps."""

from __future__ import annotations

import io
import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_bytes, sha256_file
from .config import load_yaml
from .dataset24 import DATASET_NAME
from .federated_training import SELECTION_METRIC
from .preprocessing import derived_json_bytes
from .protean_training import _contains_forbidden_evaluation_split
from .storage import write_once

CROSS_CANDIDATE_SELECTION_POLICY = {
    "split": "validation",
    "classifier": "nearest_global_prototype",
    "metric": SELECTION_METRIC,
    "mode": "maximize",
    "round_tie_breaker": "earliest_round",
    "candidate_tie_breaker": "smallest_prototype_alignment_weight",
    "test_policy": "locked_until_selection_artifact_is_verified",
}
COLORS = ("#1f77b4", "#ff7f0e", "#2ca02c", "#d62728")


class ProteanReportingDependencyError(RuntimeError):
    """Raised when matplotlib is not available."""


def _plotting_dependencies() -> tuple[Any, Any]:
    cache_root = Path(tempfile.gettempdir()) / "fl-forensics-matplotlib"
    cache_root.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(cache_root))
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise ProteanReportingDependencyError(
            'PROTEAN reporting requires: python -m pip install -e ".[reporting]"'
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


def _validated_candidate(workspace: Path) -> dict[str, Any]:
    manifest_path = workspace / "manifest.json"
    metrics_path = workspace / "metrics.json"
    clients_path = workspace / "selected_client_validation.json"
    manifest = _load_json(manifest_path, "PROTEAN candidate manifest")
    metrics = _load_json(metrics_path, "PROTEAN candidate metrics")
    clients = _load_json(clients_path, "PROTEAN client validation")
    if manifest.get("artifact_type") != "protean_candidate_run_manifest":
        raise ValueError("unexpected PROTEAN candidate manifest type")
    if manifest.get("dataset") != DATASET_NAME or metrics.get("dataset") != DATASET_NAME:
        raise ValueError("PROTEAN reporting accepts only UWF-ZeekData24")
    if sha256_file(metrics_path) != manifest.get("metrics_sha256"):
        raise ValueError("PROTEAN candidate metrics digest mismatch")
    if sha256_file(clients_path) != manifest.get(
        "selected_client_validation_sha256"
    ):
        raise ValueError("PROTEAN client-validation digest mismatch")
    if manifest.get("test_data_accessed") is not False:
        raise ValueError("candidate manifest crossed the test-data barrier")
    if metrics.get("test_data_accessed") is not False:
        raise ValueError("candidate metrics crossed the test-data barrier")
    if _contains_forbidden_evaluation_split(metrics) or _contains_forbidden_evaluation_split(
        clients
    ):
        raise ValueError("candidate contains a forbidden evaluation split")
    selected = metrics.get("selected")
    if not isinstance(selected, dict):
        raise TypeError("candidate contains no selected validation checkpoint")
    prototype_path = workspace / str(selected["global_prototypes_path"])
    prototype_object = _load_json(prototype_path, "selected global prototypes")
    if sha256_file(prototype_path) != selected.get("global_prototypes_sha256"):
        raise ValueError("selected global-prototype digest mismatch")
    rounds = metrics.get("rounds", [])
    if not rounds:
        raise ValueError("candidate contains no round metrics")
    best_head = max(
        rounds,
        key=lambda item: (
            float(item["validation"]["classification_head"][SELECTION_METRIC]),
            -int(item["round"]),
        ),
    )
    return {
        "workspace": workspace,
        "manifest": manifest,
        "metrics": metrics,
        "clients": clients,
        "selected_prototypes": prototype_object,
        "weight": float(manifest["training"]["prototype_alignment_weight"]),
        "selected_prototype_f1": float(
            selected["validation"]["nearest_global_prototype"][SELECTION_METRIC]
        ),
        "selected_head_f1": float(
            selected["validation"]["classification_head"][SELECTION_METRIC]
        ),
        "selected_round": int(selected["round"]),
        "best_head_round": int(best_head["round"]),
        "best_head_f1": float(
            best_head["validation"]["classification_head"][SELECTION_METRIC]
        ),
        "source_digests": {
            "manifest_sha256": sha256_file(manifest_path),
            "metrics_sha256": sha256_file(metrics_path),
            "selected_client_validation_sha256": sha256_file(clients_path),
        },
    }


def _validated_fedavg(workspace: Path) -> dict[str, Any]:
    manifest_path = workspace / "manifest.json"
    comparison_path = workspace / "comparison.json"
    manifest = _load_json(manifest_path, "FedAvg manifest")
    comparison = _load_json(comparison_path, "FedAvg comparison")
    if manifest.get("dataset") != DATASET_NAME:
        raise ValueError("FedAvg validation source is not UWF-ZeekData24")
    if sha256_file(comparison_path) != manifest.get("comparison_sha256"):
        raise ValueError("FedAvg comparison digest mismatch")
    selected = comparison.get("fedavg_selected")
    clients = comparison.get("selected_global_client_validation")
    if not isinstance(selected, dict) or not isinstance(clients, list):
        raise TypeError("FedAvg source lacks selected validation results")
    return {
        "manifest": manifest,
        "comparison": comparison,
        "validation_f1": float(selected["validation"][SELECTION_METRIC]),
        "clients": {str(item["client_id"]): item["validation"] for item in clients},
        "source_digests": {
            "manifest_sha256": sha256_file(manifest_path),
            "comparison_sha256": sha256_file(comparison_path),
        },
        "boundary": (
            "The historical FedAvg artifact predates this sweep and contains a fixed test "
            "evaluation; this report reads only its validation fields and never uses it "
            "for PROTEAN candidate selection."
        ),
    }


def _validate_sweep(
    candidates: list[dict[str, Any]], config_path: Path
) -> tuple[dict[str, Any], str]:
    config, config_digest = load_yaml(config_path)
    expected_weights = sorted(
        float(value)
        for value in config["protean"]["objective"][
            "prototype_alignment_weight_selection"
        ]["candidates"]
    )
    actual_weights = sorted(item["weight"] for item in candidates)
    if actual_weights != expected_weights:
        raise ValueError(
            f"PROTEAN sweep weights mismatch: expected {expected_weights}, got {actual_weights}"
        )
    fields = (
        "partition_manifest_sha256",
        "dataset_manifest_sha256",
        "protean_config_sha256",
        "initial_model_sha256",
        "implementation_files",
    )
    reference = candidates[0]["manifest"]
    for candidate in candidates:
        manifest = candidate["manifest"]
        for field in fields:
            if manifest.get(field) != reference.get(field):
                raise ValueError(f"candidate comparability mismatch: {field}")
        if manifest.get("protean_config_sha256") != config_digest:
            raise ValueError("candidate was not produced with the supplied PROTEAN config")
        training = dict(manifest["training"])
        training.pop("prototype_alignment_weight", None)
        reference_training = dict(reference["training"])
        reference_training.pop("prototype_alignment_weight", None)
        if training != reference_training:
            raise ValueError("candidate training settings are not comparable")
    return config, config_digest


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
    write_once(path, _figure_bytes(build(), plt=plt))
    return {
        "path": filename,
        "description": description,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _performance_figure(
    *, plt: Any, candidates: list[dict[str, Any]], baseline_f1: float
) -> Any:
    fig, axes = plt.subplots(1, 2, figsize=(14.5, 5.4), sharex=True, sharey=True)
    for color, candidate in zip(COLORS, candidates, strict=True):
        rounds = candidate["metrics"]["rounds"]
        x_values = [int(item["round"]) for item in rounds]
        label = f"λ={candidate['weight']:g}"
        axes[0].plot(
            x_values,
            [
                100
                * float(item["validation"]["nearest_global_prototype"][SELECTION_METRIC])
                for item in rounds
            ],
            label=label,
            color=color,
            linewidth=1.8,
        )
        axes[1].plot(
            x_values,
            [
                100
                * float(item["validation"]["classification_head"][SELECTION_METRIC])
                for item in rounds
            ],
            label=label,
            color=color,
            linewidth=1.8,
        )
    axes[1].axhline(
        100 * baseline_f1,
        color="#111827",
        linestyle="--",
        linewidth=1.5,
        label="FedAvg selected validation",
    )
    axes[0].set_title("Nearest global prototype")
    axes[1].set_title("Classification head")
    for ax in axes:
        ax.set_xlabel("Federated round")
        ax.set_ylabel("Validation macro-F1 (%)")
        ax.set_ylim(0, 100)
        _style_axes(ax)
        ax.legend(frameon=False)
    fig.suptitle("PROTEAN validation learning curves", fontweight="bold")
    fig.tight_layout()
    return fig


def _loss_figure(*, plt: Any, candidates: list[dict[str, Any]]) -> Any:
    fig, axes = plt.subplots(2, 2, figsize=(14.5, 9.2), sharex=True)
    definitions = (
        ("objective_loss", "Objective loss", 1.0),
        ("supervised_loss", "Supervised loss", 1.0),
        ("prototype_alignment_loss", "Weighted prototype contribution", None),
        ("proximal_penalty", "Weighted proximal contribution", 0.1),
    )
    for color, candidate in zip(COLORS, candidates, strict=True):
        rounds = candidate["metrics"]["rounds"]
        x_values = [int(item["round"]) for item in rounds]
        for ax, (key, _title, fixed_weight) in zip(
            axes.flat, definitions, strict=True
        ):
            weight = candidate["weight"] if fixed_weight is None else fixed_weight
            ax.plot(
                x_values,
                [float(item["weighted_training"][key]) * weight for item in rounds],
                label=f"λ={candidate['weight']:g}",
                color=color,
                linewidth=1.7,
            )
    for ax, (_key, title, _weight) in zip(axes.flat, definitions, strict=True):
        ax.set_title(title)
        ax.set_xlabel("Federated round")
        _style_axes(ax)
    axes[0, 0].legend(frameon=False)
    fig.suptitle("PROTEAN local objective components", fontweight="bold")
    fig.tight_layout()
    return fig


def _selection_figure(
    *, plt: Any, candidates: list[dict[str, Any]], baseline_f1: float
) -> Any:
    positions = list(range(len(candidates)))
    width = 0.25
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    series = (
        (-width, "selected_prototype_f1", "Nearest prototype — selected"),
        (0.0, "selected_head_f1", "Head at prototype checkpoint"),
        (width, "best_head_f1", "Head — diagnostic maximum"),
    )
    for offset, key, label in series:
        ax.bar(
            [value + offset for value in positions],
            [100 * candidate[key] for candidate in candidates],
            width=width,
            label=label,
        )
    ax.axhline(
        100 * baseline_f1,
        color="#111827",
        linestyle="--",
        linewidth=1.5,
        label="FedAvg selected validation",
    )
    ax.set_xticks(positions, [f"λ={item['weight']:g}" for item in candidates])
    ax.set_ylim(0, 100)
    ax.set_ylabel("Validation macro-F1 (%)")
    ax.set_title("Validation-only candidate comparison")
    ax.legend(frameon=False, ncol=2)
    _style_axes(ax)
    fig.tight_layout()
    return fig


def _normalized_matrix(values: list[list[Any]]) -> list[list[float]]:
    return [
        [float(value) / sum(float(item) for item in row) if sum(row) else 0.0 for value in row]
        for row in values
    ]


def _confusion_figure(*, plt: Any, selected: dict[str, Any]) -> Any:
    validation = selected["metrics"]["selected"]["validation"]
    records = (
        ("nearest_global_prototype", "Nearest prototype"),
        ("classification_head", "Classification head"),
    )
    fig, axes = plt.subplots(2, 2, figsize=(14.5, 12.2))
    for row_index, (key, title) in enumerate(records):
        matrix = validation[key]["confusion_matrix"]
        labels = [str(value).replace("_", " ") for value in matrix["labels"]]
        absolute = [[float(value) for value in row] for row in matrix["values"]]
        normalized = _normalized_matrix(absolute)
        for column_index, (values, suffix, maximum) in enumerate(
            ((absolute, "counts", None), (normalized, "row-normalized", 1.0))
        ):
            ax = axes[row_index, column_index]
            image = ax.imshow(values, cmap="Blues", vmin=0, vmax=maximum)
            ax.set_xticks(range(len(labels)), labels, rotation=35, ha="right")
            ax.set_yticks(range(len(labels)), labels)
            ax.set_xlabel("Predicted")
            ax.set_ylabel("Actual")
            ax.set_title(f"{title} — {suffix}")
            threshold = 0.5 if maximum == 1.0 else max(max(row) for row in values) / 2
            for actual, matrix_row in enumerate(values):
                for predicted, value in enumerate(matrix_row):
                    text = f"{100 * value:.1f}%" if maximum == 1.0 else str(int(value))
                    ax.text(
                        predicted,
                        actual,
                        text,
                        ha="center",
                        va="center",
                        fontsize=7.5,
                        color="white" if value > threshold else "#17202a",
                    )
            fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.suptitle(
        f"Validation confusion matrices — λ={selected['weight']:g}",
        fontweight="bold",
    )
    fig.tight_layout()
    return fig


def _client_analysis(
    selected: dict[str, Any], baseline_clients: dict[str, Any]
) -> list[dict[str, Any]]:
    rows = []
    for client in selected["clients"]["clients"]:
        client_id = str(client["client_id"])
        supports = client["training_class_support"]
        baseline = baseline_clients[client_id]
        for class_name, prototype_record in client["validation"][
            "nearest_global_prototype"
        ]["per_class"].items():
            support = int(supports.get(class_name, 0))
            category = "absent" if support == 0 else ("rare" if support < 5 else "supported")
            prototype_f1 = float(prototype_record["f1"])
            head_f1 = float(
                client["validation"]["classification_head"]["per_class"][class_name]["f1"]
            )
            baseline_f1 = float(baseline["per_class"][class_name]["f1"])
            rows.append(
                {
                    "client_id": client_id,
                    "class_name": class_name,
                    "training_support": support,
                    "support_category": category,
                    "nearest_prototype_f1": prototype_f1,
                    "classification_head_f1": head_f1,
                    "fedavg_f1": baseline_f1,
                    "nearest_prototype_delta_vs_fedavg": prototype_f1 - baseline_f1,
                    "classification_head_delta_vs_fedavg": head_f1 - baseline_f1,
                }
            )
    return rows


def _client_heatmap_figure(
    *, plt: Any, rows: list[dict[str, Any]], class_names: list[str]
) -> Any:
    client_ids = sorted({str(item["client_id"]) for item in rows})
    lookup = {(item["client_id"], item["class_name"]): item for item in rows}
    keys = (
        ("nearest_prototype_delta_vs_fedavg", "Nearest prototype − FedAvg"),
        ("classification_head_delta_vs_fedavg", "Classification head − FedAvg"),
    )
    fig, axes = plt.subplots(1, 2, figsize=(16.5, 8.3), sharey=True)
    for ax, (key, title) in zip(axes, keys, strict=True):
        matrix = [
            [float(lookup[(client_id, class_name)][key]) for class_name in class_names]
            for client_id in client_ids
        ]
        image = ax.imshow(matrix, cmap="RdBu", vmin=-1, vmax=1, aspect="auto")
        ax.set_xticks(
            range(len(class_names)),
            [name.replace("_", " ") for name in class_names],
            rotation=35,
            ha="right",
        )
        ax.set_yticks(range(len(client_ids)), client_ids)
        ax.set_title(title)
        ax.set_xlabel("Class")
        for row_index, client_id in enumerate(client_ids):
            for column_index, class_name in enumerate(class_names):
                record = lookup[(client_id, class_name)]
                marker = "A" if record["support_category"] == "absent" else (
                    "R" if record["support_category"] == "rare" else ""
                )
                ax.text(
                    column_index,
                    row_index,
                    f"{100 * record[key]:+.0f}{marker}",
                    ha="center",
                    va="center",
                    fontsize=6.5,
                )
        fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04, label="F1 delta")
    axes[0].set_ylabel("Client")
    fig.suptitle("Per-client/class validation F1 delta (A=absent, R=rare)", fontweight="bold")
    fig.tight_layout()
    return fig


def _support_figure(*, plt: Any, selected: dict[str, Any]) -> Any:
    classes = selected["selected_prototypes"]["classes"]
    names = list(classes)
    positions = list(range(len(names)))
    fig, axes = plt.subplots(1, 2, figsize=(14.5, 5.7))
    axes[0].bar(positions, [classes[name]["eligible_client_count"] for name in names])
    axes[0].axhline(
        selected["selected_prototypes"]["class_quorum"],
        linestyle="--",
        color="#d62728",
        label="Required quorum",
    )
    axes[0].legend(frameon=False)
    axes[0].set_ylabel("Eligible clients")
    axes[0].set_title("Prototype quorum")
    axes[1].bar(positions, [classes[name]["total_support"] for name in names])
    axes[1].set_ylabel("Training rows")
    axes[1].set_title("Aggregated class support")
    labels = [name.replace("_", " ") for name in names]
    for ax in axes:
        ax.set_xticks(positions, labels, rotation=35, ha="right")
        _style_axes(ax)
    fig.suptitle("Selected global-prototype evidence", fontweight="bold")
    fig.tight_layout()
    return fig


def _communication_figure(*, plt: Any, candidates: list[dict[str, Any]]) -> Any:
    fig, axes = plt.subplots(1, 2, figsize=(14.5, 5.4), sharex=True)
    for color, candidate in zip(COLORS, candidates, strict=True):
        rounds = candidate["metrics"]["rounds"]
        x_values = [int(item["round"]) for item in rounds]
        prototype_bytes = [
            int(item["communication"]["client_upload_prototype_bytes"])
            + int(item["communication"]["server_broadcast_prototype_bytes"])
            for item in rounds
        ]
        total_bytes = [int(item["communication"]["total_bytes"]) for item in rounds]
        axes[0].plot(
            x_values,
            [value / 1024 for value in prototype_bytes],
            color=color,
            label=f"λ={candidate['weight']:g}",
        )
        axes[1].plot(
            x_values,
            [100 * prototype / total for prototype, total in zip(prototype_bytes, total_bytes, strict=True)],
            color=color,
            label=f"λ={candidate['weight']:g}",
        )
    axes[0].set_ylabel("Prototype traffic (KiB)")
    axes[1].set_ylabel("Prototype share of total traffic (%)")
    for ax in axes:
        ax.set_xlabel("Federated round")
        _style_axes(ax)
        ax.legend(frameon=False)
    fig.suptitle("Prototype communication overhead", fontweight="bold")
    fig.tight_layout()
    return fig


def generate_protean_validation_report(
    *,
    candidate_workspaces: list[Path],
    fedavg_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Select the PROTEAN candidate and render validation-only evidence."""

    candidates = sorted(
        [_validated_candidate(path) for path in candidate_workspaces],
        key=lambda item: item["weight"],
    )
    if not candidates:
        raise ValueError("at least one PROTEAN candidate workspace is required")
    _config, config_digest = _validate_sweep(candidates, config_path)
    baseline = _validated_fedavg(fedavg_workspace)
    partition_digest = candidates[0]["manifest"]["partition_manifest_sha256"]
    if baseline["manifest"].get("partition_manifest_sha256") != partition_digest:
        raise ValueError("FedAvg and PROTEAN do not reference the same partition snapshot")
    selected = max(
        candidates,
        key=lambda item: (item["selected_prototype_f1"], -item["weight"]),
    )
    head_diagnostic = max(
        candidates,
        key=lambda item: (item["best_head_f1"], -item["weight"]),
    )
    class_names = list(
        selected["metrics"]["selected"]["validation"]["classification_head"][
            "confusion_matrix"
        ]["labels"]
    )
    client_rows = _client_analysis(selected, baseline["clients"])
    selection = {
        "schema_version": "1.0",
        "artifact_type": "protean_validation_only_selection",
        "dataset": DATASET_NAME,
        "partition_mode": "non-iid",
        "policy": CROSS_CANDIDATE_SELECTION_POLICY,
        "candidates": [
            {
                "prototype_alignment_weight": item["weight"],
                "prototype_selected_round": item["selected_round"],
                "prototype_selected_validation_macro_f1": item[
                    "selected_prototype_f1"
                ],
                "head_macro_f1_at_prototype_checkpoint": item["selected_head_f1"],
                "head_diagnostic_best_round": item["best_head_round"],
                "head_diagnostic_best_validation_macro_f1": item["best_head_f1"],
                "candidate_manifest_sha256": item["source_digests"][
                    "manifest_sha256"
                ],
            }
            for item in candidates
        ],
        "selected": {
            "prototype_alignment_weight": selected["weight"],
            "round": selected["selected_round"],
            "validation_macro_f1": selected["selected_prototype_f1"],
            "candidate_manifest_sha256": selected["source_digests"][
                "manifest_sha256"
            ],
            "model_sha256": selected["metrics"]["selected"]["model_sha256"],
            "global_prototypes_sha256": selected["metrics"]["selected"][
                "global_prototypes_sha256"
            ],
        },
        "head_diagnostic": {
            "not_the_primary_selection": True,
            "prototype_alignment_weight": head_diagnostic["weight"],
            "round": head_diagnostic["best_head_round"],
            "validation_macro_f1": head_diagnostic["best_head_f1"],
        },
        "fedavg_validation_macro_f1": baseline["validation_f1"],
        "test_data_accessed": False,
        "interpretation_constraints": [
            "PROTEAN candidate and round selection use validation only.",
            "The head maximum is diagnostic and does not replace the predeclared selector.",
            baseline["boundary"],
            "No PROTEAN test or temporal-holdout artifact exists at selection time.",
        ],
    }
    if _contains_forbidden_evaluation_split(selection):
        raise ValueError("selection artifact crossed the test-data barrier")
    selection_bytes = derived_json_bytes(selection)
    write_once(output / "selection.json", selection_bytes)

    client_artifact = {
        "schema_version": "1.0",
        "artifact_type": "protean_validation_client_class_analysis",
        "selected_prototype_alignment_weight": selected["weight"],
        "selected_round": selected["selected_round"],
        "rows": client_rows,
        "test_data_accessed": False,
    }
    client_bytes = derived_json_bytes(client_artifact)
    write_once(output / "client_class_validation.json", client_bytes)

    matrix_artifact = {
        "schema_version": "1.0",
        "artifact_type": "protean_selected_validation_confusion_matrices",
        "selected_prototype_alignment_weight": selected["weight"],
        "selected_round": selected["selected_round"],
        "nearest_global_prototype": selected["metrics"]["selected"]["validation"][
            "nearest_global_prototype"
        ]["confusion_matrix"],
        "classification_head": selected["metrics"]["selected"]["validation"][
            "classification_head"
        ]["confusion_matrix"],
        "test_data_accessed": False,
    }
    matrix_bytes = derived_json_bytes(matrix_artifact)
    write_once(output / "confusion_matrices_validation.json", matrix_bytes)

    matplotlib, plt = _plotting_dependencies()
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 9.5,
            "axes.titleweight": "bold",
            "axes.titlesize": 12.5,
            "axes.labelsize": 10,
            "legend.fontsize": 8.5,
        }
    )
    figures = [
        _write_figure(
            output=output,
            filename="validation-learning-curves.png",
            description="Head and nearest-prototype validation macro-F1 by round.",
            build=lambda: _performance_figure(
                plt=plt, candidates=candidates, baseline_f1=baseline["validation_f1"]
            ),
            plt=plt,
        ),
        _write_figure(
            output=output,
            filename="training-objective-curves.png",
            description="Supervised, prototype, proximal, and total objective curves.",
            build=lambda: _loss_figure(plt=plt, candidates=candidates),
            plt=plt,
        ),
        _write_figure(
            output=output,
            filename="validation-candidate-selection.png",
            description="Validation-only comparison used for candidate selection.",
            build=lambda: _selection_figure(
                plt=plt, candidates=candidates, baseline_f1=baseline["validation_f1"]
            ),
            plt=plt,
        ),
        _write_figure(
            output=output,
            filename="confusion-matrices-validation.png",
            description="Absolute and normalized validation confusion matrices.",
            build=lambda: _confusion_figure(plt=plt, selected=selected),
            plt=plt,
        ),
        _write_figure(
            output=output,
            filename="client-class-validation-delta.png",
            description="Per-client/class validation F1 delta against FedAvg.",
            build=lambda: _client_heatmap_figure(
                plt=plt, rows=client_rows, class_names=class_names
            ),
            plt=plt,
        ),
        _write_figure(
            output=output,
            filename="prototype-quorum-support.png",
            description="Selected prototype quorum and training support by class.",
            build=lambda: _support_figure(plt=plt, selected=selected),
            plt=plt,
        ),
        _write_figure(
            output=output,
            filename="prototype-communication-overhead.png",
            description="Prototype communication bytes and total traffic share.",
            build=lambda: _communication_figure(plt=plt, candidates=candidates),
            plt=plt,
        ),
    ]
    summary = {
        "schema_version": "1.0",
        "artifact_type": "protean_validation_report",
        "dataset": DATASET_NAME,
        "partition_mode": "non-iid",
        "code_version": __version__,
        "reporting_backend": {"name": "matplotlib", "version": matplotlib.__version__},
        "selection_sha256": sha256_bytes(selection_bytes),
        "client_class_validation_sha256": sha256_bytes(client_bytes),
        "confusion_matrices_validation_sha256": sha256_bytes(matrix_bytes),
        "protean_config_sha256": config_digest,
        "candidate_sources": [item["source_digests"] for item in candidates],
        "fedavg_source": baseline["source_digests"],
        "figures": figures,
        "selected_prototype_alignment_weight": selected["weight"],
        "selected_round": selected["selected_round"],
        "selected_validation_macro_f1": selected["selected_prototype_f1"],
        "test_data_accessed": False,
        "interpretation_constraints": selection["interpretation_constraints"],
    }
    summary_bytes = derived_json_bytes(summary)
    write_once(output / "summary.json", summary_bytes)
    return {
        "status": "reported_validation_only",
        "output": str(output),
        "candidate_count": len(candidates),
        "figure_count": len(figures),
        "selected_prototype_alignment_weight": selected["weight"],
        "selected_round": selected["selected_round"],
        "selected_validation_macro_f1": selected["selected_prototype_f1"],
        "head_diagnostic_alignment_weight": head_diagnostic["weight"],
        "head_diagnostic_round": head_diagnostic["best_head_round"],
        "head_diagnostic_validation_macro_f1": head_diagnostic["best_head_f1"],
        "test_data_accessed": False,
        "summary_sha256": sha256_file(output / "summary.json"),
    }


def _workspace_file_digests(workspace: Path) -> dict[str, str]:
    return {
        path.relative_to(workspace).as_posix(): sha256_file(path)
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }


def verify_protean_validation_report(
    *,
    candidate_workspaces: list[Path],
    fedavg_workspace: Path,
    workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Rebuild a report and require byte-identical validation-only evidence."""

    errors: list[str] = []
    summary: dict[str, Any] = {}
    try:
        if not workspace.is_dir():
            raise ValueError(f"missing PROTEAN report workspace: {workspace}")
        actual = _workspace_file_digests(workspace)
        with tempfile.TemporaryDirectory(prefix="fl-forensics-protean-report-") as temp:
            expected_workspace = Path(temp) / "report"
            generate_protean_validation_report(
                candidate_workspaces=candidate_workspaces,
                fedavg_workspace=fedavg_workspace,
                output=expected_workspace,
                config_path=config_path,
            )
            expected = _workspace_file_digests(expected_workspace)
        if actual.keys() != expected.keys():
            missing = sorted(expected.keys() - actual.keys())
            unexpected = sorted(actual.keys() - expected.keys())
            if missing:
                errors.append(f"missing report files: {missing}")
            if unexpected:
                errors.append(f"unexpected report files: {unexpected}")
        for relative in sorted(actual.keys() & expected.keys()):
            if actual[relative] != expected[relative]:
                errors.append(f"report digest mismatch: {relative}")
        summary = _load_json(workspace / "summary.json", "PROTEAN report summary")
        if summary.get("test_data_accessed") is not False:
            errors.append("PROTEAN report crossed the test-data barrier")
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        ProteanReportingDependencyError,
    ) as exc:
        errors.append(str(exc))

    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "error_count": len(errors),
        "errors": errors,
        "candidate_count": len(candidate_workspaces),
        "figure_count": len(summary.get("figures", [])),
        "selected_prototype_alignment_weight": summary.get(
            "selected_prototype_alignment_weight"
        ),
        "selected_round": summary.get("selected_round"),
        "test_data_accessed": False,
        "summary_sha256": (
            sha256_file(workspace / "summary.json")
            if (workspace / "summary.json").is_file()
            else None
        ),
    }
