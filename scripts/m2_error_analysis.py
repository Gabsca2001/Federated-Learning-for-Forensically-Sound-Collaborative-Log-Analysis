"""Explain M2 checkpoint errors without retraining or changing the baseline.

The analyzer consumes a verified M2 dataset snapshot and the traceable
misclassifications exported by ``scripts/m2_diagnostics.py``.  Model features
are standardized with the training-only scaler.  Labels and provenance fields
are used only to group and explain errors, never as predictive inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


EVENT_BUCKETS = ("1", "2-5", "6-20", "21-100", ">100")


def _dependencies() -> tuple[Any, ...]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        from sklearn.decomposition import PCA
    except ImportError as exc:
        raise RuntimeError(
            'M2 error analysis requires: python -m pip install -e ".[m2,reporting]"'
        ) from exc
    return plt, np, PCA


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


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"JSONL record is not an object at {path}:{line_number}")
        records.append(value)
    return records


def _event_bucket(count: int) -> str:
    if count <= 1:
        return "1"
    if count <= 5:
        return "2-5"
    if count <= 20:
        return "6-20"
    if count <= 100:
        return "21-100"
    return ">100"


def _transition_name(true_label: str, predicted_label: str) -> str:
    return f"{true_label} -> {predicted_label}"


def _validate_inputs(
    *,
    dataset_workspace: Path,
    diagnostics_workspace: Path,
    split: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    from fl_forensics.dataset24 import DATASET_NAME, verify_workspace

    verification = verify_workspace(dataset_workspace)
    if verification["status"] != "verified":
        raise ValueError(f"M2 workspace verification failed: {verification['errors']}")

    dataset = json.loads(
        (dataset_workspace / "dataset.json").read_text(encoding="utf-8")
    )
    scaler = json.loads(
        (dataset_workspace / "scaler.json").read_text(encoding="utf-8")
    )
    if dataset.get("dataset") != DATASET_NAME:
        raise ValueError("error analysis accepts only UWF-ZeekData24 snapshots")

    summary_path = diagnostics_workspace / "summary.json"
    if not summary_path.is_file():
        raise ValueError(f"missing diagnostic summary: {summary_path}")
    diagnostic_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if diagnostic_summary.get("evaluated_model") != (
        "best-validation-weighted-log-loss-checkpoint"
    ):
        raise ValueError("diagnostics do not describe the selected checkpoint")

    required = (
        "misclassified_windows.jsonl",
        "misclassification_summary.json",
    )
    artifact_hashes = diagnostic_summary.get("artifact_sha256", {})
    for name in required:
        path = diagnostics_workspace / name
        if not path.is_file():
            raise ValueError(f"missing diagnostic artifact: {name}")
        expected = artifact_hashes.get(name)
        if not expected:
            raise ValueError(f"diagnostic summary has no SHA-256 for: {name}")
        if _sha256_file(path) != expected:
            raise ValueError(f"diagnostic artifact digest mismatch: {name}")

    error_summary = json.loads(
        (diagnostics_workspace / "misclassification_summary.json").read_text(
            encoding="utf-8"
        )
    )
    if split not in error_summary.get("splits", {}):
        raise ValueError(f"split was not evaluated by diagnostics: {split}")

    split_rows = [row for row in dataset.get("rows", []) if row.get("split") == split]
    if not split_rows:
        raise ValueError(f"dataset has no rows for split: {split}")
    split_summary = error_summary["splits"][split]
    if int(split_summary["row_count"]) != len(split_rows):
        raise ValueError("diagnostic and dataset split row counts differ")

    all_errors = _load_jsonl(diagnostics_workspace / required[0])
    errors = [record for record in all_errors if record.get("split") == split]
    if int(split_summary["error_count"]) != len(errors):
        raise ValueError("diagnostic split error count does not match JSONL")

    selected_epoch = int(diagnostic_summary["selected_checkpoint_epoch"])
    rows_by_id = {str(row.get("window_id")): row for row in split_rows}
    if len(rows_by_id) != len(split_rows):
        raise ValueError("dataset split contains duplicate or missing window IDs")
    seen_error_ids: set[str] = set()
    for record in errors:
        window_id = str(record.get("window_id"))
        if window_id in seen_error_ids:
            raise ValueError(f"duplicate misclassification record: {window_id}")
        seen_error_ids.add(window_id)
        row = rows_by_id.get(window_id)
        if row is None:
            raise ValueError(f"misclassified window is absent from dataset: {window_id}")
        if str(record.get("true_label")) != str(row.get("label")):
            raise ValueError(f"true label mismatch for window: {window_id}")
        if record.get("capture_id") != row.get("capture_id"):
            raise ValueError(f"capture mismatch for window: {window_id}")
        if int(record.get("selection_epoch", -1)) != selected_epoch:
            raise ValueError(f"checkpoint epoch mismatch for window: {window_id}")
        if len(row.get("source_event_ids", [])) != int(record["source_event_count"]):
            raise ValueError(f"source-event count mismatch for window: {window_id}")

    return dataset, scaler, diagnostic_summary, split_rows, errors


def _rate_tables(
    *, split_rows: list[dict[str, Any]], errors: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    error_ids = {str(record["window_id"]) for record in errors}
    capture_totals = Counter(str(row.get("capture_id")) for row in split_rows)
    capture_errors = Counter(str(record.get("capture_id")) for record in errors)
    capture_rates = [
        {
            "capture_id": capture_id,
            "row_count": total,
            "error_count": capture_errors[capture_id],
            "error_rate": capture_errors[capture_id] / total,
        }
        for capture_id, total in sorted(capture_totals.items())
    ]

    bucket_totals: Counter[str] = Counter()
    bucket_errors: Counter[str] = Counter()
    for row in split_rows:
        bucket = _event_bucket(len(row.get("source_event_ids", [])))
        bucket_totals[bucket] += 1
        if str(row["window_id"]) in error_ids:
            bucket_errors[bucket] += 1
    bucket_rates = [
        {
            "bucket": bucket,
            "row_count": bucket_totals[bucket],
            "error_count": bucket_errors[bucket],
            "error_rate": (
                bucket_errors[bucket] / bucket_totals[bucket]
                if bucket_totals[bucket]
                else 0.0
            ),
        }
        for bucket in EVENT_BUCKETS
    ]
    return capture_rates, bucket_rates


def _transition_analysis(errors: list[dict[str, Any]]) -> dict[str, Any]:
    transitions = Counter(
        (str(record["true_label"]), str(record["predicted_label"]))
        for record in errors
    )
    observed = Counter(
        (
            str(record["true_label"]),
            str(record["predicted_label"]),
            tuple(sorted(str(item) for item in record.get("observed_labels", []))),
        )
        for record in errors
    )
    pair_counts: Counter[tuple[str, str]] = Counter()
    for (true_label, predicted_label), count in transitions.items():
        pair_counts[tuple(sorted((true_label, predicted_label)))] += count

    ordered = sorted(
        transitions.items(), key=lambda item: (-item[1], item[0][0], item[0][1])
    )
    bidirectional_pairs = {
        pair: count
        for pair, count in pair_counts.items()
        if (pair[0], pair[1]) in transitions and (pair[1], pair[0]) in transitions
    }
    ordered_pairs = sorted(
        bidirectional_pairs.items(), key=lambda item: (-item[1], item[0])
    )
    return {
        "transitions": [
            {
                "true_label": true_label,
                "predicted_label": predicted_label,
                "count": count,
            }
            for (true_label, predicted_label), count in ordered
        ],
        "observed_label_composition": [
            {
                "true_label": true_label,
                "predicted_label": predicted_label,
                "observed_labels": list(observed_labels),
                "count": count,
            }
            for (true_label, predicted_label, observed_labels), count in sorted(
                observed.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "bidirectional_pairs": [
            {"labels": list(pair), "count": count}
            for pair, count in ordered_pairs
        ],
    }


def _ambiguous_feature_groups(
    *, split_rows: list[dict[str, Any]], error_ids: set[str]
) -> dict[str, Any]:
    groups: dict[tuple[float, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in split_rows:
        signature = tuple(round(float(value), 10) for value in row["features"])
        groups[signature].append(row)

    ambiguous: list[dict[str, Any]] = []
    error_count = 0
    row_count = 0
    for rows in groups.values():
        labels = Counter(str(row["label"]) for row in rows)
        if len(labels) < 2:
            continue
        local_errors = sum(str(row["window_id"]) in error_ids for row in rows)
        error_count += local_errors
        row_count += len(rows)
        ambiguous.append(
            {
                "row_count": len(rows),
                "labels": dict(sorted(labels.items())),
                "captures": dict(
                    sorted(Counter(str(row.get("capture_id")) for row in rows).items())
                ),
                "source_event_counts": dict(
                    sorted(
                        Counter(
                            str(len(row.get("source_event_ids", []))) for row in rows
                        ).items()
                    )
                ),
                "error_count": local_errors,
                "example_window_ids": [str(row["window_id"]) for row in rows[:5]],
            }
        )
    ambiguous.sort(key=lambda item: (-item["error_count"], -item["row_count"]))
    return {
        "rounding_decimal_places": 10,
        "ambiguous_group_count": len(ambiguous),
        "ambiguous_row_count": row_count,
        "error_count_in_ambiguous_groups": error_count,
        "groups": ambiguous,
    }


def _feature_transition_analysis(
    *,
    np: Any,
    split_rows: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    feature_names: list[str],
    means: Any,
    scales: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    matrix = np.asarray([row["features"] for row in split_rows], dtype=np.float64)
    standardized = (matrix - means) / scales
    rows_by_id = {
        str(row["window_id"]): (index, row)
        for index, row in enumerate(split_rows)
    }
    error_ids = {str(record["window_id"]) for record in errors}
    correct_indices: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(split_rows):
        if str(row["window_id"]) not in error_ids:
            correct_indices[str(row["label"])].append(index)

    grouped_errors: dict[tuple[str, str], list[int]] = defaultdict(list)
    for record in errors:
        index, _row = rows_by_id[str(record["window_id"])]
        grouped_errors[(str(record["true_label"]), str(record["predicted_label"]))].append(
            index
        )

    transitions: list[dict[str, Any]] = []
    for (true_label, predicted_label), indices in sorted(
        grouped_errors.items(), key=lambda item: (-len(item[1]), item[0])
    ):
        true_indices = correct_indices.get(true_label, [])
        predicted_indices = correct_indices.get(predicted_label, [])
        if not true_indices or not predicted_indices:
            transitions.append(
                {
                    "true_label": true_label,
                    "predicted_label": predicted_label,
                    "error_count": len(indices),
                    "status": "insufficient-correct-reference-rows",
                }
            )
            continue
        error_mean = standardized[indices].mean(axis=0)
        true_mean = standardized[true_indices].mean(axis=0)
        predicted_mean = standardized[predicted_indices].mean(axis=0)
        error_to_true = np.abs(error_mean - true_mean)
        error_to_predicted = np.abs(error_mean - predicted_mean)
        closeness_delta = error_to_true - error_to_predicted
        feature_rows = [
            {
                "feature": feature_name,
                "error_group_mean_z": float(error_mean[index]),
                "correct_true_mean_z": float(true_mean[index]),
                "correct_predicted_mean_z": float(predicted_mean[index]),
                "error_to_true_absolute_distance": float(error_to_true[index]),
                "error_to_predicted_absolute_distance": float(
                    error_to_predicted[index]
                ),
                "closeness_delta": float(closeness_delta[index]),
            }
            for index, feature_name in enumerate(feature_names)
        ]
        feature_rows.sort(key=lambda item: -abs(item["closeness_delta"]))
        transitions.append(
            {
                "true_label": true_label,
                "predicted_label": predicted_label,
                "error_count": len(indices),
                "correct_true_count": len(true_indices),
                "correct_predicted_count": len(predicted_indices),
                "status": "analyzed",
                "mean_euclidean_distance_to_correct_true": float(
                    np.linalg.norm(error_mean - true_mean)
                ),
                "mean_euclidean_distance_to_correct_predicted": float(
                    np.linalg.norm(error_mean - predicted_mean)
                ),
                "features": feature_rows,
            }
        )

    metadata = {
        "standardization": "M2 training-only scaler",
        "interpretation": (
            "Positive closeness_delta means that the error-group feature mean is "
            "closer to correctly classified rows of the predicted class."
        ),
        "observed_labels_used_as_features": False,
        "transitions": transitions,
    }
    return metadata, {"standardized": standardized, "rows_by_id": rows_by_id}


def _pca_analysis(
    *,
    np: Any,
    PCA: Any,
    plt: Any,
    split_rows: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    standardized: Any,
    dominant_pair: list[str],
    output: Path,
) -> dict[str, Any]:
    if len(dominant_pair) != 2:
        return {"status": "unavailable", "reason": "no bidirectional class pair"}
    pair_set = set(dominant_pair)
    indices = [
        index
        for index, row in enumerate(split_rows)
        if str(row["label"]) in pair_set
    ]
    if len(indices) < 3:
        return {"status": "unavailable", "reason": "fewer than three pair rows"}

    pca = PCA(n_components=2)
    projected = pca.fit_transform(standardized[indices])
    error_ids = {str(record["window_id"]) for record in errors}
    colors = ("#2563eb", "#f97316")
    figure, axis = plt.subplots(figsize=(10, 7))
    group_counts: dict[str, int] = {}
    for color, label in zip(colors, dominant_pair, strict=True):
        for is_error, marker, alpha in ((False, "o", 0.38), (True, "X", 0.95)):
            local = [
                position
                for position, row_index in enumerate(indices)
                if str(split_rows[row_index]["label"]) == label
                and (str(split_rows[row_index]["window_id"]) in error_ids) == is_error
            ]
            group_name = f"{label} — {'error' if is_error else 'correct'}"
            group_counts[group_name] = len(local)
            if not local:
                continue
            axis.scatter(
                projected[local, 0],
                projected[local, 1],
                s=52 if is_error else 20,
                marker=marker,
                alpha=alpha,
                color=color,
                label=group_name,
                edgecolors="black" if is_error else "none",
                linewidths=0.5,
            )
    ratios = [float(value) for value in pca.explained_variance_ratio_]
    axis.set_title(
        f"PCA: {dominant_pair[0]} vs {dominant_pair[1]} — correct and errors"
    )
    axis.set_xlabel(f"PC1 ({ratios[0]:.1%} variance)")
    axis.set_ylabel(f"PC2 ({ratios[1]:.1%} variance)")
    axis.grid(alpha=0.2)
    axis.legend(loc="best")
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)
    return {
        "status": "analyzed",
        "labels": dominant_pair,
        "row_count": len(indices),
        "explained_variance_ratio": ratios,
        "explained_variance_ratio_sum": float(sum(ratios)),
        "group_counts": group_counts,
    }


def _plot_capture_rates(
    plt: Any, records: list[dict[str, Any]], split: str, output: Path
) -> None:
    ordered = sorted(records, key=lambda item: (-item["error_rate"], item["capture_id"]))
    figure, axis = plt.subplots(figsize=(10, 6))
    axis.bar(
        [item["capture_id"] for item in ordered],
        [100 * item["error_rate"] for item in ordered],
        color="#2563eb",
    )
    axis.set_title(f"{split.replace('_', ' ').title()} error rate by capture")
    axis.set_ylabel("Error rate (%)")
    axis.tick_params(axis="x", rotation=35)
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_bucket_rates(
    plt: Any, records: list[dict[str, Any]], split: str, output: Path
) -> None:
    figure, axis = plt.subplots(figsize=(9, 6))
    axis.bar(
        [item["bucket"] for item in records],
        [100 * item["error_rate"] for item in records],
        color="#7c3aed",
    )
    axis.set_title(
        f"{split.replace('_', ' ').title()} error rate by source-event count"
    )
    axis.set_xlabel("Events in window")
    axis.set_ylabel("Error rate (%)")
    axis.grid(axis="y", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_transitions(plt: Any, transitions: list[dict[str, Any]], output: Path) -> None:
    ordered = list(reversed(transitions))
    figure, axis = plt.subplots(figsize=(11, max(5, len(ordered) * 0.65)))
    axis.barh(
        [
            _transition_name(item["true_label"], item["predicted_label"])
            for item in ordered
        ],
        [item["count"] for item in ordered],
        color="#dc2626",
    )
    axis.set_title("Misclassification transitions")
    axis.set_xlabel("Error count")
    axis.grid(axis="x", alpha=0.25)
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_confidence_margins(
    plt: Any, errors: list[dict[str, Any]], output: Path
) -> None:
    grouped: dict[tuple[str, str], list[float]] = defaultdict(list)
    for record in errors:
        grouped[(str(record["true_label"]), str(record["predicted_label"]))].append(
            float(record["confidence_margin"])
        )
    ordered = sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))[:3]
    figure, axis = plt.subplots(figsize=(10, 6))
    for (true_label, predicted_label), values in ordered:
        axis.hist(
            values,
            bins=min(12, max(4, len(values))),
            alpha=0.5,
            label=_transition_name(true_label, predicted_label),
        )
    axis.set_title("Confidence margins for the main error transitions")
    axis.set_xlabel("Predicted probability − true-label probability")
    axis.set_ylabel("Errors")
    axis.grid(axis="y", alpha=0.2)
    if ordered:
        axis.legend()
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_feature_profile(
    *, plt: Any, np: Any, transition: dict[str, Any], output: Path
) -> None:
    features = transition["features"][:10]
    features = list(reversed(features))
    positions = np.arange(len(features), dtype=np.float64)
    height = 0.24
    figure, axis = plt.subplots(figsize=(12, 7))
    axis.barh(
        positions - height,
        [item["correct_true_mean_z"] for item in features],
        height=height,
        label=f"correct {transition['true_label']}",
        color="#2563eb",
    )
    axis.barh(
        positions,
        [item["error_group_mean_z"] for item in features],
        height=height,
        label="misclassified group",
        color="#dc2626",
    )
    axis.barh(
        positions + height,
        [item["correct_predicted_mean_z"] for item in features],
        height=height,
        label=f"correct {transition['predicted_label']}",
        color="#f97316",
    )
    axis.set_yticks(positions, [item["feature"] for item in features])
    axis.set_title(
        "Feature profile: "
        + _transition_name(transition["true_label"], transition["predicted_label"])
    )
    axis.set_xlabel("Mean standardized feature value (z)")
    axis.axvline(0.0, color="black", linewidth=0.8)
    axis.grid(axis="x", alpha=0.2)
    axis.legend()
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def _plot_feature_heatmap(
    *, plt: Any, np: Any, transitions: list[dict[str, Any]], output: Path
) -> None:
    analyzed = [item for item in transitions if item.get("status") == "analyzed"]
    if not analyzed:
        return
    feature_names = [item["feature"] for item in analyzed[0]["features"][:12]]
    matrix = np.asarray(
        [
            [
                next(
                    feature["closeness_delta"]
                    for feature in transition["features"]
                    if feature["feature"] == feature_name
                )
                for feature_name in feature_names
            ]
            for transition in analyzed
        ],
        dtype=np.float64,
    )
    limit = max(float(np.abs(matrix).max()), 1e-9)
    figure, axis = plt.subplots(
        figsize=(max(11, len(feature_names) * 0.85), max(5, len(analyzed) * 0.75))
    )
    image = axis.imshow(matrix, cmap="coolwarm", vmin=-limit, vmax=limit, aspect="auto")
    axis.set_xticks(range(len(feature_names)), feature_names, rotation=45, ha="right")
    axis.set_yticks(
        range(len(analyzed)),
        [
            _transition_name(item["true_label"], item["predicted_label"])
            for item in analyzed
        ],
    )
    axis.set_title("Feature closeness for error transitions")
    figure.colorbar(image, ax=axis, label="Closeness delta (+ = predicted class)")
    figure.tight_layout()
    figure.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(figure)


def run_error_analysis(
    *,
    dataset_workspace: Path,
    diagnostics_workspace: Path,
    output: Path,
    split: str,
) -> dict[str, Any]:
    plt, np, PCA = _dependencies()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"error-analysis output is not empty: {output}")

    dataset, scaler, diagnostic_summary, split_rows, errors = _validate_inputs(
        dataset_workspace=dataset_workspace,
        diagnostics_workspace=diagnostics_workspace,
        split=split,
    )
    output.mkdir(parents=True, exist_ok=True)
    feature_names = [str(item) for item in dataset["feature_names"]]
    means = np.asarray(scaler["mean"], dtype=np.float64)
    scales = np.asarray(scaler["scale"], dtype=np.float64)
    if len(feature_names) != len(means) or len(means) != len(scales):
        raise ValueError("feature names and scaler dimensions differ")
    if np.any(scales == 0):
        raise ValueError("scaler contains a zero scale")

    capture_rates, bucket_rates = _rate_tables(
        split_rows=split_rows, errors=errors
    )
    transition_analysis = _transition_analysis(errors)
    error_ids = {str(record["window_id"]) for record in errors}
    ambiguous = _ambiguous_feature_groups(
        split_rows=split_rows, error_ids=error_ids
    )
    feature_analysis, feature_context = _feature_transition_analysis(
        np=np,
        split_rows=split_rows,
        errors=errors,
        feature_names=feature_names,
        means=means,
        scales=scales,
    )

    dominant_transition = (
        transition_analysis["transitions"][0]
        if transition_analysis["transitions"]
        else None
    )
    dominant_pair = (
        transition_analysis["bidirectional_pairs"][0]["labels"]
        if transition_analysis["bidirectional_pairs"]
        else []
    )
    pca = _pca_analysis(
        np=np,
        PCA=PCA,
        plt=plt,
        split_rows=split_rows,
        errors=errors,
        standardized=feature_context["standardized"],
        dominant_pair=dominant_pair,
        output=output / "pca_main_confusion.png",
    )

    values = {
        "capture_error_rates.json": {"split": split, "captures": capture_rates},
        "event_bucket_error_rates.json": {"split": split, "buckets": bucket_rates},
        "transition_analysis.json": transition_analysis,
        "ambiguous_feature_groups.json": ambiguous,
        "feature_transition_analysis.json": feature_analysis,
        "pca_analysis.json": pca,
    }
    for name, value in values.items():
        _write_json(output / name, value)

    _plot_capture_rates(
        plt, capture_rates, split, output / "capture_error_rates.png"
    )
    _plot_bucket_rates(
        plt, bucket_rates, split, output / "event_bucket_error_rates.png"
    )
    _plot_transitions(
        plt, transition_analysis["transitions"], output / "transition_counts.png"
    )
    _plot_confidence_margins(
        plt, errors, output / "error_confidence_margins.png"
    )
    analyzed_transitions = [
        item
        for item in feature_analysis["transitions"]
        if item.get("status") == "analyzed"
    ]
    if analyzed_transitions:
        _plot_feature_profile(
            plt=plt,
            np=np,
            transition=analyzed_transitions[0],
            output=output / "feature_profile_main_transition.png",
        )
        _plot_feature_heatmap(
            plt=plt,
            np=np,
            transitions=feature_analysis["transitions"],
            output=output / "feature_confusion_heatmap.png",
        )

    artifact_names = sorted(path.name for path in output.iterdir() if path.is_file())
    artifact_hashes = {
        name: _sha256_file(output / name) for name in artifact_names
    }
    summary = {
        "schema_version": "1.0",
        "artifact_type": "m2_checkpoint_error_analysis",
        "dataset": dataset["dataset"],
        "split": split,
        "row_count": len(split_rows),
        "error_count": len(errors),
        "error_rate": len(errors) / len(split_rows),
        "selected_checkpoint_epoch": diagnostic_summary[
            "selected_checkpoint_epoch"
        ],
        "dataset_workspace": str(dataset_workspace),
        "diagnostics_workspace": str(diagnostics_workspace),
        "input_sha256": {
            "dataset.json": _sha256_file(dataset_workspace / "dataset.json"),
            "scaler.json": _sha256_file(dataset_workspace / "scaler.json"),
            "diagnostics/summary.json": _sha256_file(
                diagnostics_workspace / "summary.json"
            ),
            "diagnostics/misclassified_windows.jsonl": _sha256_file(
                diagnostics_workspace / "misclassified_windows.jsonl"
            ),
        },
        "dominant_transition": dominant_transition,
        "dominant_bidirectional_pair": dominant_pair,
        "ambiguous_feature_group_count": ambiguous["ambiguous_group_count"],
        "errors_in_ambiguous_feature_groups": ambiguous[
            "error_count_in_ambiguous_groups"
        ],
        "pca": pca,
        "observed_labels_used_as_features": False,
        "artifact_sha256": artifact_hashes,
        "limitations": [
            "PCA is descriptive and is not evidence of causal feature importance.",
            "Feature profiles compare group means and do not measure model gradients.",
            "Exact-feature ambiguity is evaluated after rounding to 10 decimals.",
            "Only errors from the selected diagnostic checkpoint are analyzed.",
        ],
    }
    _write_json(output / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset-workspace",
        type=Path,
        default=Path("artifacts/m2-data24-parquet"),
    )
    parser.add_argument(
        "--diagnostics-workspace",
        type=Path,
        default=Path("artifacts/m2-diagnostics-checkpoint-seed341593"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/m2-error-analysis-seed341593"),
    )
    parser.add_argument("--split", default="test")
    arguments = parser.parse_args()
    summary = run_error_analysis(
        dataset_workspace=arguments.dataset_workspace,
        diagnostics_workspace=arguments.diagnostics_workspace,
        output=arguments.output,
        split=arguments.split,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
