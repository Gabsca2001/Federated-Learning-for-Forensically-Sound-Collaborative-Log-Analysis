"""Generate local-client diagnostics from accepted M5 signed metric artifacts.

The report is read-only with respect to the secure-round workspace. It never
uses the server test split: local convergence and model-selection diagnostics
are restricted to each client's train and validation snapshots.
"""

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
from fl_forensics.secure_round import verify_secure_round
from fl_forensics.storage import write_once


def _dependencies() -> tuple[Any, Any]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError as exc:
        raise RuntimeError(
            'M5 diagnostics require: python -m pip install -e ".[federated,reporting]"'
        ) from exc
    return plt, np


def _load_records(workspace: Path) -> tuple[list[dict[str, Any]], list[str]]:
    submissions = workspace / "submissions"
    decisions = workspace / "decisions"
    client_directories = sorted(
        path for path in submissions.glob("client[0-9][0-9]") if path.is_dir()
    )
    if not client_directories:
        raise ValueError(f"no M5 client submissions found: {submissions}")

    records: list[dict[str, Any]] = []
    class_names: list[str] | None = None
    for directory in client_directories:
        client_id = directory.name
        metrics_path = directory / "metrics.json"
        bundle_path = directory / "bundle.json"
        decision_path = decisions / f"{client_id}.json"
        for path in (metrics_path, bundle_path, decision_path):
            if not path.is_file():
                raise FileNotFoundError(f"missing accepted M5 artifact: {path}")
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        decision = json.loads(decision_path.read_text(encoding="utf-8"))
        if metrics.get("schema_version") != "2.0":
            raise ValueError(
                f"{client_id} metrics do not contain per-epoch M5 diagnostics"
            )
        if metrics.get("client_id") != client_id:
            raise ValueError(f"metrics/client mismatch: {client_id}")
        if bundle.get("core", {}).get("client_id") != client_id:
            raise ValueError(f"bundle/client mismatch: {client_id}")
        if sha256_file(metrics_path) != bundle["core"].get("metrics_sha256"):
            raise ValueError(f"signed metrics digest mismatch: {client_id}")
        decision_core = decision.get("core", {})
        if decision_core.get("client_id") != client_id:
            raise ValueError(f"decision/client mismatch: {client_id}")
        if decision_core.get("status") != "accepted":
            raise ValueError(f"client contribution was not accepted: {client_id}")
        if not all(bool(item.get("passed")) for item in decision_core.get("checks", [])):
            raise ValueError(f"accepted decision contains a failed check: {client_id}")
        history = metrics.get("history", [])
        if len(history) != int(metrics.get("epochs", 0)) or not history:
            raise ValueError(f"invalid epoch history: {client_id}")
        if [int(item.get("epoch", 0)) for item in history] != list(
            range(1, len(history) + 1)
        ):
            raise ValueError(f"non-contiguous epoch history: {client_id}")
        labels = list(history[-1]["validation"]["confusion_matrix"]["labels"])
        if class_names is None:
            class_names = labels
        elif labels != class_names:
            raise ValueError(f"class order differs across clients: {client_id}")
        records.append(
            {
                "client_id": client_id,
                "metrics": metrics,
                "metrics_sha256": sha256_file(metrics_path),
                "bundle_sha256": sha256_file(bundle_path),
                "decision_sha256": sha256_file(decision_path),
            }
        )
    assert class_names is not None
    return records, class_names


def _distribution(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values),
        "population_stddev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "minimum": min(values),
        "maximum": max(values),
    }


def _write_figure(*, figure: Any, path: Path, plt: Any) -> None:
    buffer = io.BytesIO()
    figure.savefig(
        buffer,
        format="png",
        dpi=170,
        bbox_inches="tight",
        metadata={"Software": "fl-forensics m5_local_diagnostics"},
    )
    plt.close(figure)
    write_once(path, buffer.getvalue())


def _summary_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        metrics = record["metrics"]
        final = metrics["final"]
        rows.append(
            {
                "client_id": record["client_id"],
                "train_rows": int(metrics["num_examples"]),
                "validation_rows": int(metrics["validation_num_examples"]),
                "epochs": int(metrics["epochs"]),
                "optimizer_steps": int(metrics["optimizer_steps"]),
                "optimizer_train_loss_all_epochs": float(metrics["train_loss"]),
                "final_train_loss": float(final["train"]["loss"]),
                "final_validation_loss": float(final["validation"]["loss"]),
                "final_train_macro_f1": float(
                    final["train"]["macro_f1_all_model_classes"]
                ),
                "final_validation_macro_f1": float(
                    final["validation"]["macro_f1_all_model_classes"]
                ),
                "update_delta_l2": float(metrics["update_delta_l2"]),
                "metrics_sha256": record["metrics_sha256"],
                "bundle_sha256": record["bundle_sha256"],
                "decision_sha256": record["decision_sha256"],
            }
        )
    return rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    write_once(path, stream.getvalue().encode("utf-8"))


def _loss_figure(*, records: list[dict[str, Any]], plt: Any, np: Any) -> Any:
    epochs = np.asarray(
        [item["epoch"] for item in records[0]["metrics"]["history"]], dtype=int
    )
    train = np.asarray(
        [
            [item["train"]["loss"] for item in record["metrics"]["history"]]
            for record in records
        ],
        dtype=float,
    )
    validation = np.asarray(
        [
            [item["validation"]["loss"] for item in record["metrics"]["history"]]
            for record in records
        ],
        dtype=float,
    )
    figure, axis = plt.subplots(figsize=(10, 5.5))
    for values in train:
        axis.plot(epochs, values, color="#1f77b4", alpha=0.12, linewidth=1)
    for values in validation:
        axis.plot(epochs, values, color="#d62728", alpha=0.12, linewidth=1)
    for values, color, label in (
        (train, "#1f77b4", "Train mean"),
        (validation, "#d62728", "Validation mean"),
    ):
        mean = values.mean(axis=0)
        std = values.std(axis=0)
        axis.plot(epochs, mean, color=color, linewidth=2.5, marker="o", label=label)
        axis.fill_between(epochs, mean - std, mean + std, color=color, alpha=0.16)
    axis.set_title("M5 local models — evaluation loss by local epoch")
    axis.set_xlabel("Local epoch")
    axis.set_ylabel("Unweighted cross-entropy")
    axis.grid(alpha=0.25)
    axis.legend()
    axis.set_xticks(epochs)
    return figure


def _f1_figure(*, records: list[dict[str, Any]], plt: Any, np: Any) -> Any:
    epochs = np.asarray(
        [item["epoch"] for item in records[0]["metrics"]["history"]], dtype=int
    )
    train = np.asarray(
        [
            [
                item["train"]["macro_f1_all_model_classes"]
                for item in record["metrics"]["history"]
            ]
            for record in records
        ],
        dtype=float,
    )
    validation = np.asarray(
        [
            [
                item["validation"]["macro_f1_all_model_classes"]
                for item in record["metrics"]["history"]
            ]
            for record in records
        ],
        dtype=float,
    )
    figure, axis = plt.subplots(figsize=(10, 5.5))
    for values, color, label in (
        (train, "#1f77b4", "Train mean"),
        (validation, "#2ca02c", "Validation mean"),
    ):
        mean = values.mean(axis=0)
        std = values.std(axis=0)
        axis.plot(epochs, mean, color=color, linewidth=2.5, marker="o", label=label)
        axis.fill_between(epochs, mean - std, mean + std, color=color, alpha=0.16)
    axis.set_title("M5 local models — macro-F1 by local epoch")
    axis.set_xlabel("Local epoch")
    axis.set_ylabel("Macro-F1")
    axis.set_ylim(0.0, 1.0)
    axis.grid(alpha=0.25)
    axis.legend()
    axis.set_xticks(epochs)
    return figure


def _client_f1_figure(*, rows: list[dict[str, Any]], plt: Any, np: Any) -> Any:
    positions = np.arange(len(rows))
    width = 0.38
    figure, axis = plt.subplots(figsize=(13, 5.5))
    axis.bar(
        positions - width / 2,
        [item["final_train_macro_f1"] for item in rows],
        width,
        label="Train",
        color="#1f77b4",
    )
    axis.bar(
        positions + width / 2,
        [item["final_validation_macro_f1"] for item in rows],
        width,
        label="Validation",
        color="#2ca02c",
    )
    axis.set_xticks(positions, [item["client_id"] for item in rows], rotation=45)
    axis.set_ylim(0.0, 1.0)
    axis.set_ylabel("Macro-F1")
    axis.set_title("M5 final local macro-F1 by client")
    axis.grid(axis="y", alpha=0.25)
    axis.legend()
    return figure


def _per_class_figure(
    *, records: list[dict[str, Any]], class_names: list[str], plt: Any, np: Any
) -> Any:
    matrix = np.asarray(
        [
            [
                record["metrics"]["final"]["validation"]["per_class"][name]["f1"]
                for name in class_names
            ]
            for record in records
        ],
        dtype=float,
    )
    figure, axis = plt.subplots(figsize=(11, 7))
    image = axis.imshow(matrix, aspect="auto", vmin=0.0, vmax=1.0, cmap="viridis")
    axis.set_xticks(
        np.arange(len(class_names)),
        [name.replace("_", " ") for name in class_names],
        rotation=35,
        ha="right",
    )
    axis.set_yticks(
        np.arange(len(records)), [record["client_id"] for record in records]
    )
    axis.set_title("Validation F1 per class and client")
    figure.colorbar(image, ax=axis, label="F1")
    return figure


def _confusion_figure(
    *, records: list[dict[str, Any]], class_names: list[str], plt: Any, np: Any
) -> Any:
    columns = 5
    rows = (len(records) + columns - 1) // columns
    figure, axes = plt.subplots(rows, columns, figsize=(18, 3.8 * rows), squeeze=False)
    image = None
    for axis, record in zip(axes.flat, records, strict=False):
        values = np.asarray(
            record["metrics"]["final"]["validation"]["confusion_matrix"]["values"],
            dtype=float,
        )
        totals = values.sum(axis=1, keepdims=True)
        normalized = np.divide(values, totals, out=np.zeros_like(values), where=totals > 0)
        image = axis.imshow(normalized, vmin=0.0, vmax=1.0, cmap="Blues")
        axis.set_title(record["client_id"])
        axis.set_xticks(range(len(class_names)))
        axis.set_yticks(range(len(class_names)))
        axis.set_xticklabels(range(len(class_names)), fontsize=7)
        axis.set_yticklabels(range(len(class_names)), fontsize=7)
        axis.set_xlabel("Predicted class index", fontsize=8)
        axis.set_ylabel("Actual class index", fontsize=8)
    for axis in axes.flat[len(records) :]:
        axis.axis("off")
    if image is not None:
        figure.colorbar(image, ax=axes.ravel().tolist(), shrink=0.75, label="Row fraction")
    figure.suptitle(
        "M5 local validation confusion matrices — row-normalized\n"
        + ", ".join(f"{index}={name}" for index, name in enumerate(class_names)),
        fontsize=12,
    )
    figure.subplots_adjust(top=0.88, wspace=0.38, hspace=0.45)
    return figure


def generate_report(
    *, workspace: Path, trust_workspace: Path, output: Path
) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"M5 diagnostic output must be new and empty: {output}")
    verification = verify_secure_round(
        workspace=workspace,
        trust_workspace=trust_workspace,
        submissions_root=workspace / "submissions",
    )
    if verification["status"] != "verified":
        raise ValueError(
            "M5 secure round must verify before diagnostics are generated: "
            f"{verification['errors']}"
        )
    output.mkdir(parents=True, exist_ok=True)
    plt, np = _dependencies()
    records, class_names = _load_records(workspace)
    rows = _summary_rows(records)

    figures = {
        "local-loss-curves.png": _loss_figure(records=records, plt=plt, np=np),
        "local-macro-f1-curves.png": _f1_figure(records=records, plt=plt, np=np),
        "local-final-macro-f1.png": _client_f1_figure(rows=rows, plt=plt, np=np),
        "local-validation-per-class-f1.png": _per_class_figure(
            records=records, class_names=class_names, plt=plt, np=np
        ),
        "local-validation-confusion-matrices.png": _confusion_figure(
            records=records, class_names=class_names, plt=plt, np=np
        ),
    }
    for name, figure in figures.items():
        _write_figure(figure=figure, path=output / name, plt=plt)
    _write_csv(output / "client-summary.csv", rows)

    validation_f1 = [item["final_validation_macro_f1"] for item in rows]
    validation_loss = [item["final_validation_loss"] for item in rows]
    update_norms = [item["update_delta_l2"] for item in rows]
    summary = {
        "schema_version": "1.0",
        "artifact_type": "m5_local_diagnostic_summary",
        "source_workspace": str(workspace),
        "source_secure_round_verification": verification,
        "client_count": len(records),
        "epochs": int(records[0]["metrics"]["epochs"]),
        "class_names": class_names,
        "test_data_observed": False,
        "final_validation_macro_f1": _distribution(validation_f1),
        "final_validation_loss": _distribution(validation_loss),
        "update_delta_l2": _distribution(update_norms),
        "clients": rows,
        "interpretation": [
            "Curves use client-local train and validation snapshots only.",
            "No server test examples are mounted, evaluated, or used for selection.",
            "Metrics digests are committed by accepted TPM-signed Update Bundles.",
        ],
    }
    write_once(output / "summary.json", derived_json_bytes(summary))
    artifact_names = sorted(path.name for path in output.iterdir() if path.is_file())
    report_manifest = {
        "schema_version": "1.0",
        "artifact_type": "m5_local_diagnostic_report_manifest",
        "source_workspace": str(workspace),
        "artifacts": {
            name: sha256_file(output / name) for name in artifact_names
        },
    }
    write_once(output / "manifest.json", derived_json_bytes(report_manifest))
    return {
        "status": "reported",
        "workspace": str(workspace),
        "output": str(output),
        "client_count": len(records),
        "epochs": summary["epochs"],
        "mean_final_validation_macro_f1": summary["final_validation_macro_f1"][
            "mean"
        ],
        "figure_count": len(figures),
        "manifest_sha256": sha256_file(output / "manifest.json"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m5-secure-round")
    )
    parser.add_argument(
        "--trust-workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/m5-local-diagnostics")
    )
    arguments = parser.parse_args()
    print(
        json.dumps(
            generate_report(
                workspace=arguments.workspace,
                trust_workspace=arguments.trust_workspace,
                output=arguments.output,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
