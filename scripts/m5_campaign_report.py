"""Generate digest-linked learning diagnostics for a verified M5 secure campaign."""

from __future__ import annotations

import argparse
import csv
import io
import json
import statistics
from pathlib import Path
from typing import Any

from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_campaign import verify_secure_campaign
from fl_forensics.storage import write_once


def _dependencies() -> tuple[Any, Any]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError as exc:
        raise RuntimeError(
            'M5 campaign reporting requires: python -m pip install -e ".[reporting]"'
        ) from exc
    return plt, np


def _write_figure(*, figure: Any, path: Path, plt: Any) -> None:
    buffer = io.BytesIO()
    figure.savefig(
        buffer,
        format="png",
        dpi=170,
        bbox_inches="tight",
        metadata={"Software": "fl-forensics m5_campaign_report"},
    )
    plt.close(figure)
    write_once(path, buffer.getvalue())


def _load_campaign(workspace: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = json.loads((workspace / "campaign-manifest.json").read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for reference in manifest["core"]["rounds"]:
        round_number = int(reference["round_number"])
        round_root = workspace / "rounds" / f"round-{round_number:03d}"
        validation_path = workspace / "evaluation" / f"round-{round_number:03d}-validation.json"
        if sha256_file(validation_path) != reference["validation_metrics_sha256"]:
            raise ValueError(f"round {round_number} validation digest mismatch")
        global_validation = json.loads(validation_path.read_text(encoding="utf-8"))["validation"]
        for client_index in range(1, int(manifest["core"]["required_client_count"]) + 1):
            client_id = f"client{client_index:02d}"
            submission = round_root / "submissions" / client_id
            metrics_path = submission / "metrics.json"
            bundle_path = submission / "bundle.json"
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            if sha256_file(metrics_path) != bundle["core"]["metrics_sha256"]:
                raise ValueError(f"round {round_number} signed metrics mismatch: {client_id}")
            if metrics.get("schema_version") != "2.0":
                raise ValueError(f"round {round_number} lacks local epoch history: {client_id}")
            for epoch_record in metrics["history"]:
                rows.append(
                    {
                        "round": round_number,
                        "client_id": client_id,
                        "local_epoch": int(epoch_record["epoch"]),
                        "global_local_epoch": (
                            (round_number - 1) * int(metrics["epochs"]) + int(epoch_record["epoch"])
                        ),
                        "train_loss": float(epoch_record["train"]["loss"]),
                        "validation_loss": float(epoch_record["validation"]["loss"]),
                        "train_macro_f1": float(
                            epoch_record["train"]["macro_f1_all_model_classes"]
                        ),
                        "validation_macro_f1": float(
                            epoch_record["validation"]["macro_f1_all_model_classes"]
                        ),
                        "optimizer_train_loss": float(epoch_record["optimizer_train_loss"]),
                        "update_delta_l2": float(metrics["update_delta_l2"]),
                        "global_validation_loss": float(global_validation["loss"]),
                        "global_validation_macro_f1": float(
                            global_validation["macro_f1_all_model_classes"]
                        ),
                        "metrics_sha256": sha256_file(metrics_path),
                        "bundle_sha256": sha256_file(bundle_path),
                    }
                )
    return manifest, rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    write_once(path, stream.getvalue().encode("utf-8"))


def _group_mean(
    rows: list[dict[str, Any]], *, key: str, value: str
) -> tuple[list[int], list[float], list[float]]:
    grouped: dict[int, list[float]] = {}
    for row in rows:
        grouped.setdefault(int(row[key]), []).append(float(row[value]))
    positions = sorted(grouped)
    means = [statistics.fmean(grouped[position]) for position in positions]
    deviations = [
        statistics.pstdev(grouped[position]) if len(grouped[position]) > 1 else 0.0
        for position in positions
    ]
    return positions, means, deviations


def _curve_figure(
    *,
    rows: list[dict[str, Any]],
    key: str,
    series: list[tuple[str, str, str]],
    title: str,
    y_label: str,
    y_limit: tuple[float, float] | None,
    plt: Any,
    np: Any,
) -> Any:
    figure, axis = plt.subplots(figsize=(12, 5.8))
    for field, label, color in series:
        positions, means, deviations = _group_mean(rows, key=key, value=field)
        x = np.asarray(positions)
        mean = np.asarray(means)
        std = np.asarray(deviations)
        axis.plot(x, mean, label=label, color=color, linewidth=2)
        axis.fill_between(x, mean - std, mean + std, color=color, alpha=0.14)
    axis.set_title(title)
    axis.set_xlabel("Secure global/local epoch" if key == "global_local_epoch" else "Round")
    axis.set_ylabel(y_label)
    if y_limit is not None:
        axis.set_ylim(*y_limit)
    axis.grid(alpha=0.25)
    axis.legend()
    return figure


def _global_validation_figure(*, rows: list[dict[str, Any]], plt: Any) -> Any:
    final_epoch_rows: dict[int, dict[str, Any]] = {}
    for row in rows:
        final_epoch_rows[int(row["round"])] = row
    rounds = sorted(final_epoch_rows)
    f1 = [final_epoch_rows[item]["global_validation_macro_f1"] for item in rounds]
    loss = [final_epoch_rows[item]["global_validation_loss"] for item in rounds]
    figure, left = plt.subplots(figsize=(12, 5.8))
    right = left.twinx()
    left.plot(rounds, f1, color="#2ca02c", marker="o", label="Validation macro-F1")
    right.plot(rounds, loss, color="#d62728", marker=".", label="Validation loss")
    left.set_xlabel("Secure round")
    left.set_ylabel("Macro-F1", color="#2ca02c")
    right.set_ylabel("Cross-entropy", color="#d62728")
    left.set_ylim(0.0, 1.0)
    left.grid(alpha=0.25)
    figure.suptitle("M5 secure global checkpoint validation by round")
    lines = left.lines + right.lines
    left.legend(lines, [item.get_label() for item in lines], loc="best")
    return figure


def _heatmap_figure(
    *,
    rows: list[dict[str, Any]],
    field: str,
    title: str,
    color_label: str,
    plt: Any,
    np: Any,
    vmin: float | None = None,
    vmax: float | None = None,
) -> Any:
    final_rows: dict[tuple[int, str], dict[str, Any]] = {}
    for row in rows:
        key = (int(row["round"]), str(row["client_id"]))
        current = final_rows.get(key)
        if current is None or int(row["local_epoch"]) > int(current["local_epoch"]):
            final_rows[key] = row
    rounds = sorted({item[0] for item in final_rows})
    clients = sorted({item[1] for item in final_rows})
    matrix = np.asarray(
        [
            [float(final_rows[(round_number, client)][field]) for client in clients]
            for round_number in rounds
        ]
    )
    figure, axis = plt.subplots(figsize=(13, 9))
    image = axis.imshow(matrix, aspect="auto", cmap="viridis", vmin=vmin, vmax=vmax)
    axis.set_xticks(range(len(clients)), clients, rotation=45, ha="right")
    axis.set_yticks(range(len(rounds)), rounds)
    axis.set_xlabel("Client")
    axis.set_ylabel("Secure round")
    axis.set_title(title)
    figure.colorbar(image, ax=axis, label=color_label)
    return figure


def _selected_confusion_figure(
    *,
    final_evaluation: dict[str, Any],
    normalized: bool,
    plt: Any,
    np: Any,
) -> Any:
    splits = ("validation", "test", "temporal_holdout")
    figure, axes = plt.subplots(1, len(splits), figsize=(20, 6.2), squeeze=False)
    for axis, split in zip(axes[0], splits, strict=True):
        matrix = final_evaluation["metrics"][split]["confusion_matrix"]
        values = np.asarray(matrix["values"], dtype=float)
        if normalized:
            totals = values.sum(axis=1, keepdims=True)
            display_values = np.divide(values, totals, out=np.zeros_like(values), where=totals > 0)
        else:
            display_values = values
        _draw_confusion_axis(
            figure=figure,
            axis=axis,
            labels=[str(item) for item in matrix["labels"]],
            values=display_values,
            normalized=normalized,
            title=(
                "Temporal holdout\n(benign-only)" if split == "temporal_holdout" else split.title()
            ),
        )
    figure.suptitle(
        f"Selected secure checkpoint — round {final_evaluation['selected_round']} — "
        + ("row-normalized" if normalized else "absolute counts")
    )
    figure.tight_layout(rect=(0, 0, 1, 0.92))
    return figure


def _draw_confusion_axis(
    *,
    figure: Any,
    axis: Any,
    labels: list[str],
    values: Any,
    normalized: bool,
    title: str,
) -> None:
    image = axis.imshow(values, vmin=0.0, vmax=1.0 if normalized else None, cmap="Blues")
    display_labels = [label.replace("_", " ") for label in labels]
    axis.set_xticks(range(len(labels)), display_labels, rotation=40, ha="right")
    axis.set_yticks(range(len(labels)), display_labels)
    axis.set_xlabel("Predicted")
    axis.set_ylabel("Actual")
    axis.set_title(title)
    maximum = float(values.max()) if values.size else 0.0
    threshold = (0.5 if normalized else maximum / 2.0) if maximum else 0.0
    for row_index, row in enumerate(values):
        for column_index, value in enumerate(row):
            axis.text(
                column_index,
                row_index,
                f"{float(value) * 100:.1f}%" if normalized else str(int(value)),
                ha="center",
                va="center",
                fontsize=7.5,
                color="white" if float(value) > threshold else "#17202a",
            )
    figure.colorbar(
        image,
        ax=axis,
        fraction=0.046,
        pad=0.04,
        label="Row fraction" if normalized else "Window count",
    )


def _client_confusion_figure(
    *, client_id: str, evaluation: dict[str, Any], plt: Any, np: Any
) -> Any:
    matrix = evaluation["confusion_matrix"]
    labels = [str(item) for item in matrix["labels"]]
    absolute = np.asarray(matrix["values"], dtype=float)
    totals = absolute.sum(axis=1, keepdims=True)
    normalized = np.divide(absolute, totals, out=np.zeros_like(absolute), where=totals > 0)
    figure, axes = plt.subplots(1, 2, figsize=(14, 6.2), squeeze=False)
    _draw_confusion_axis(
        figure=figure,
        axis=axes[0][0],
        labels=labels,
        values=absolute,
        normalized=False,
        title="Absolute counts",
    )
    _draw_confusion_axis(
        figure=figure,
        axis=axes[0][1],
        labels=labels,
        values=normalized,
        normalized=True,
        title="Row-normalized",
    )
    figure.suptitle(f"{client_id} — selected secure checkpoint local test")
    figure.tight_layout(rect=(0, 0, 1, 0.94))
    return figure


def _selected_per_class_figure(*, final_evaluation: dict[str, Any], plt: Any, np: Any) -> Any:
    validation = final_evaluation["metrics"]["validation"]["per_class"]
    test = final_evaluation["metrics"]["test"]["per_class"]
    class_names = list(validation)
    positions = np.arange(len(class_names))
    width = 0.38
    figure, axis = plt.subplots(figsize=(12, 5.8))
    axis.bar(
        positions - width / 2,
        [float(validation[name]["f1"]) for name in class_names],
        width,
        label="Validation",
        color="#2ca02c",
    )
    axis.bar(
        positions + width / 2,
        [float(test[name]["f1"]) for name in class_names],
        width,
        label="Test",
        color="#ff7f0e",
    )
    axis.set_xticks(
        positions,
        [name.replace("_", " ") for name in class_names],
        rotation=35,
        ha="right",
    )
    axis.set_ylim(0.0, 1.0)
    axis.set_ylabel("F1")
    axis.set_title(f"Selected checkpoint per-class F1 — round {final_evaluation['selected_round']}")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    return figure


def generate_report(
    *,
    workspace: Path,
    trust_workspace: Path,
    partition_manifest_path: Path,
    server_evaluation_path: Path,
    output: Path,
) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"M5 campaign report output must be new and empty: {output}")
    verification = verify_secure_campaign(
        workspace=workspace,
        trust_workspace=trust_workspace,
        partition_manifest_path=partition_manifest_path,
        server_evaluation_path=server_evaluation_path,
    )
    if verification["status"] != "verified":
        raise ValueError(f"M5 campaign verification failed: {verification['errors']}")
    output.mkdir(parents=True, exist_ok=True)
    plt, np = _dependencies()
    manifest, rows = _load_campaign(workspace)
    final_evaluation = json.loads(
        (workspace / "evaluation" / "selected-checkpoint-evaluation.json").read_text(
            encoding="utf-8"
        )
    )
    figures = {
        "global-validation-by-round.png": _global_validation_figure(rows=rows, plt=plt),
        "local-train-validation-loss.png": _curve_figure(
            rows=rows,
            key="global_local_epoch",
            series=[
                ("train_loss", "Client train mean", "#1f77b4"),
                ("validation_loss", "Client validation mean", "#d62728"),
            ],
            title="M5 local train/validation loss across secure rounds",
            y_label="Unweighted cross-entropy",
            y_limit=None,
            plt=plt,
            np=np,
        ),
        "local-train-validation-macro-f1.png": _curve_figure(
            rows=rows,
            key="global_local_epoch",
            series=[
                ("train_macro_f1", "Client train mean", "#1f77b4"),
                ("validation_macro_f1", "Client validation mean", "#2ca02c"),
            ],
            title="M5 local train/validation macro-F1 across secure rounds",
            y_label="Macro-F1",
            y_limit=(0.0, 1.0),
            plt=plt,
            np=np,
        ),
        "client-validation-f1-heatmap.png": _heatmap_figure(
            rows=rows,
            field="validation_macro_f1",
            title="Final local validation macro-F1 by round and client",
            color_label="Macro-F1",
            vmin=0.0,
            vmax=1.0,
            plt=plt,
            np=np,
        ),
        "client-update-norm-heatmap.png": _heatmap_figure(
            rows=rows,
            field="update_delta_l2",
            title="Signed client update L2 norm by round",
            color_label="L2 norm",
            plt=plt,
            np=np,
        ),
        "selected-validation-test-confusion.png": _selected_confusion_figure(
            final_evaluation=final_evaluation, normalized=True, plt=plt, np=np
        ),
        "selected-validation-test-confusion-absolute.png": _selected_confusion_figure(
            final_evaluation=final_evaluation, normalized=False, plt=plt, np=np
        ),
        "selected-validation-test-per-class-f1.png": _selected_per_class_figure(
            final_evaluation=final_evaluation, plt=plt, np=np
        ),
    }
    client_confusion_paths: list[str] = []
    selected_client_tests = sorted(
        final_evaluation.get("selected_global_client_test", []),
        key=lambda item: str(item["client_id"]),
    )
    for item in selected_client_tests:
        client_id = str(item["client_id"])
        if not client_id or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for character in client_id
        ):
            raise ValueError(f"unsafe client identifier in report: {client_id!r}")
        filename = f"per-client-confusion/{client_id}.png"
        figures[filename] = _client_confusion_figure(
            client_id=client_id,
            evaluation=item["test"],
            plt=plt,
            np=np,
        )
        client_confusion_paths.append(filename)
    for filename, figure in figures.items():
        _write_figure(figure=figure, path=output / filename, plt=plt)
    _write_csv(output / "round-client-epoch-metrics.csv", rows)
    summary = {
        "schema_version": "1.0",
        "artifact_type": "m5_secure_campaign_report_summary",
        "source_workspace": str(workspace),
        "source_campaign_manifest_sha256": sha256_file(workspace / "campaign-manifest.json"),
        "campaign_verification": verification,
        "round_count": int(manifest["core"]["round_count"]),
        "client_count": int(manifest["core"]["required_client_count"]),
        "accepted_contribution_count": int(manifest["core"]["total_accepted_contributions"]),
        "selected_round": int(manifest["core"]["selected_round"]),
        "selected_metrics": final_evaluation["metrics"],
        "confusion_matrices": {
            split: final_evaluation["metrics"][split]["confusion_matrix"]
            for split in ("validation", "test", "temporal_holdout")
        },
        "confusion_matrix_figures": sorted(name for name in figures if "confusion" in name),
        "client_confusion_matrix_figures": client_confusion_paths,
        "test_selection_policy": "validation-only selection; selected checkpoint test once",
    }
    write_once(output / "summary.json", derived_json_bytes(summary))
    artifact_paths = sorted(path for path in output.rglob("*") if path.is_file())
    report_manifest = {
        "schema_version": "1.0",
        "artifact_type": "m5_secure_campaign_report_manifest",
        "source_campaign_manifest_sha256": summary["source_campaign_manifest_sha256"],
        "artifacts": {
            path.relative_to(output).as_posix(): sha256_file(path) for path in artifact_paths
        },
    }
    write_once(output / "manifest.json", derived_json_bytes(report_manifest))
    return {
        "status": "reported",
        "workspace": str(workspace),
        "output": str(output),
        "round_count": summary["round_count"],
        "client_count": summary["client_count"],
        "selected_round": summary["selected_round"],
        "selected_test_macro_f1": final_evaluation["metrics"]["test"]["macro_f1_all_model_classes"],
        "confusion_matrices": summary["confusion_matrices"],
        "confusion_matrix_figures": summary["confusion_matrix_figures"],
        "client_confusion_matrix_figure_count": len(client_confusion_paths),
        "figure_count": len(figures),
        "manifest_sha256": sha256_file(output / "manifest.json"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, default=Path("artifacts/m5-secure-multiround"))
    parser.add_argument("--trust-workspace", type=Path, default=Path("artifacts/m4-trust"))
    parser.add_argument(
        "--partition-workspace",
        type=Path,
        default=Path("artifacts/m3-data24-parquet-iid"),
    )
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/m5-secure-multiround-report")
    )
    arguments = parser.parse_args()
    result = generate_report(
        workspace=arguments.workspace,
        trust_workspace=arguments.trust_workspace,
        partition_manifest_path=arguments.partition_workspace / "manifest.json",
        server_evaluation_path=(arguments.partition_workspace / "server" / "evaluation.json"),
        output=arguments.output,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
