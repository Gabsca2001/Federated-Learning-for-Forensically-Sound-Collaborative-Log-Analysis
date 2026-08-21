"""One-shot final evaluation of endpoints frozen by the PROTEAN pre-test lock."""

from __future__ import annotations

import math
import os
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_bytes, sha256_file
from .dataset24 import DATASET_NAME
from .federated_model import dependencies
from .federated_partitioning import verify_partitions
from .federated_training import (
    SELECTION_METRIC,
    _benign_false_alarm_summary,
    _model_from_export,
)
from .preprocessing import derived_json_bytes
from .protean import available_prototype_values, nearest_prototype_predictions
from .protean_reporting import (
    _figure_bytes,
    _load_json,
    _plotting_dependencies,
    _style_axes,
    _validated_fedavg,
)
from .protean_selection_lock import (
    PRIMARY_ENDPOINT_ID,
    SECONDARY_ENDPOINT_ID,
    verify_protean_selection_lock,
)
from .protean_training import verify_protean_candidate
from .storage import write_once

FINAL_SPLITS = ("test", "temporal_holdout")
MINIMUM_EXPLAINABILITY_GROUP_ROWS = 10
MITRE_TACTIC_MAPPING = {
    "benign": {
        "mitre_tactic_id": None,
        "mitre_tactic_name": None,
        "semantic": "non-malicious observation",
    },
    "credential_access": {
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
    },
    "exfiltration": {
        "mitre_tactic_id": "TA0010",
        "mitre_tactic_name": "Exfiltration",
    },
    "initial_access": {
        "mitre_tactic_id": "TA0001",
        "mitre_tactic_name": "Initial Access",
    },
    "multi_tactic": {
        "mitre_tactic_id": None,
        "mitre_tactic_name": None,
        "semantic": (
            "multiple tactics observed in the same aggregation window; no unique "
            "tactic attribution is asserted"
        ),
    },
    "reconnaissance": {
        "mitre_tactic_id": "TA0043",
        "mitre_tactic_name": "Reconnaissance",
    },
}


def _same_float(left: Any, right: Any) -> bool:
    return math.isclose(float(left), float(right), rel_tol=0.0, abs_tol=1e-12)


def _candidate_sources(candidate_workspaces: list[Path]) -> dict[str, dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    for workspace in candidate_workspaces:
        manifest_path = workspace / "manifest.json"
        manifest = _load_json(manifest_path, "PROTEAN candidate manifest")
        digest = sha256_file(manifest_path)
        if digest in sources:
            raise ValueError("candidate manifest is registered more than once")
        sources[digest] = {"workspace": workspace, "manifest": manifest}
    return sources


def _endpoint_source(
    *, endpoint: dict[str, Any], sources: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    manifest_digest = str(endpoint["candidate_manifest_sha256"])
    if manifest_digest not in sources:
        raise ValueError(
            f"selection lock references an unregistered candidate: {manifest_digest}"
        )
    source = sources[manifest_digest]
    workspace = Path(source["workspace"])
    manifest = source["manifest"]
    if sha256_file(workspace / "metrics.json") != endpoint["candidate_metrics_sha256"]:
        raise ValueError("endpoint candidate metrics digest mismatch")
    if not _same_float(
        manifest["training"]["prototype_alignment_weight"],
        endpoint["prototype_alignment_weight"],
    ):
        raise ValueError("endpoint lambda does not match its candidate manifest")

    round_number = int(endpoint["round"])
    index = _load_json(workspace / "round_index.json", "PROTEAN round index")
    matches = [item for item in index["rounds"] if int(item["round"]) == round_number]
    if len(matches) != 1:
        raise ValueError(f"candidate contains no unique round {round_number}")
    index_entry = matches[0]
    round_path = workspace / str(index_entry["path"])
    if sha256_file(round_path) != index_entry["sha256"]:
        raise ValueError("selected round-record digest mismatch")
    record = _load_json(round_path, "selected PROTEAN round record")
    model_path = workspace / str(record["aggregated_global_model_path"])
    prototype_path = workspace / str(record["aggregated_global_prototypes_path"])
    if sha256_file(model_path) != endpoint["model_sha256"]:
        raise ValueError("selected endpoint model digest mismatch")
    if sha256_file(prototype_path) != endpoint["global_prototypes_sha256"]:
        raise ValueError("selected endpoint prototype digest mismatch")
    return {
        **source,
        "manifest_sha256": manifest_digest,
        "round_record_path": index_entry["path"],
        "round_record_sha256": index_entry["sha256"],
        "model_path": record["aggregated_global_model_path"],
        "model_export": _load_json(model_path, "selected PROTEAN model"),
        "prototype_path": record["aggregated_global_prototypes_path"],
        "prototype_object": _load_json(
            prototype_path, "selected PROTEAN global prototypes"
        ),
    }


def _verified_pretest_inputs(
    *,
    candidate_workspaces: list[Path],
    fedavg_workspace: Path,
    report_workspace: Path,
    selection_lock_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    lock_verification = verify_protean_selection_lock(
        candidate_workspaces=candidate_workspaces,
        fedavg_workspace=fedavg_workspace,
        report_workspace=report_workspace,
        workspace=selection_lock_workspace,
        config_path=config_path,
    )
    if lock_verification["status"] != "verified":
        raise ValueError(
            "PROTEAN selection lock must verify before final data access: "
            f"{lock_verification['errors']}"
        )
    lock_path = selection_lock_workspace / "selection_lock.json"
    lock_manifest_path = selection_lock_workspace / "manifest.json"
    lock = _load_json(lock_path, "PROTEAN selection lock")
    lock_manifest = _load_json(lock_manifest_path, "PROTEAN selection-lock manifest")
    if lock.get("test_gate", {}).get("state") != "locked":
        raise ValueError("PROTEAN test gate is not locked")
    if lock.get("test_data_accessed") is not False:
        raise ValueError("selection lock was not created before test access")

    partition_verification = verify_partitions(
        workspace=partition_workspace, dataset_workspace=dataset_workspace
    )
    if partition_verification["status"] != "verified":
        raise ValueError(
            "PROTEAN partition workspace must verify before final data access: "
            f"{partition_verification['errors']}"
        )
    partition_manifest_path = partition_workspace / "manifest.json"
    dataset_manifest_path = dataset_workspace / "manifest.json"
    if sha256_file(partition_manifest_path) != lock_manifest.get(
        "partition_manifest_sha256"
    ):
        raise ValueError("selection lock and final partition snapshot do not match")
    if sha256_file(dataset_manifest_path) != lock_manifest.get(
        "dataset_manifest_sha256"
    ):
        raise ValueError("selection lock and final dataset snapshot do not match")

    sources = _candidate_sources(candidate_workspaces)
    endpoints = {
        PRIMARY_ENDPOINT_ID: _endpoint_source(
            endpoint=lock["primary_endpoint"], sources=sources
        ),
        SECONDARY_ENDPOINT_ID: _endpoint_source(
            endpoint=lock["secondary_endpoint"], sources=sources
        ),
    }
    verified_manifests: set[str] = set()
    for source in endpoints.values():
        digest = str(source["manifest_sha256"])
        if digest in verified_manifests:
            continue
        result = verify_protean_candidate(
            workspace=Path(source["workspace"]),
            partition_workspace=partition_workspace,
            dataset_workspace=dataset_workspace,
            config_path=config_path,
        )
        if result["status"] != "verified":
            raise ValueError(
                "selected PROTEAN candidate must verify before final data access: "
                f"{result['errors']}"
            )
        verified_manifests.add(digest)

    baseline = _validated_fedavg(fedavg_workspace)
    if baseline["source_digests"] != lock_manifest.get("fedavg_source"):
        raise ValueError("selection lock and FedAvg reference do not match")
    partition_manifest = _load_json(
        partition_manifest_path, "non-IID partition manifest"
    )
    if partition_manifest.get("partition_mode") != "non-iid":
        raise ValueError("PROTEAN finalization requires the frozen non-IID partition")
    return {
        "lock": lock,
        "lock_manifest": lock_manifest,
        "lock_sha256": sha256_file(lock_path),
        "lock_manifest_sha256": sha256_file(lock_manifest_path),
        "endpoints": endpoints,
        "baseline": baseline,
        "partition_manifest": partition_manifest,
        "partition_manifest_sha256": sha256_file(partition_manifest_path),
        "dataset_manifest_sha256": sha256_file(dataset_manifest_path),
    }


def _inference_arrays(
    *, model: Any, rows: list[dict[str, Any]], batch_size: int, np: Any, torch: Any
) -> dict[str, Any]:
    if not rows:
        raise ValueError("PROTEAN final evaluation cannot use an empty split")
    features = np.asarray([row["features"] for row in rows], dtype=np.float32)
    dataset = torch.utils.data.TensorDataset(torch.from_numpy(features))
    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=min(batch_size, len(dataset)),
        shuffle=False,
        num_workers=0,
    )
    model.to("cpu")
    model.eval()
    embeddings = []
    logits = []
    with torch.no_grad():
        for (batch_features,) in loader:
            batch_embeddings = model.encoder(batch_features)
            embeddings.append(batch_embeddings.cpu().numpy())
            logits.append(model.classification_head(batch_embeddings).cpu().numpy())
    return {
        "features": features,
        "embeddings": np.concatenate(embeddings, axis=0),
        "logits": np.concatenate(logits, axis=0),
    }


def _classification_metrics(
    *,
    labels: Any,
    predictions: Any,
    class_names: list[str],
    loss: float | None,
    dependency_values: tuple[Any, ...],
) -> dict[str, Any]:
    (
        _np,
        _torch,
        _flwr,
        _sklearn,
        _aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependency_values
    label_ids = list(range(len(class_names)))
    precision, recall, f1, support = precision_recall_fscore_support(
        labels, predictions, labels=label_ids, zero_division=0
    )
    observed_ids = sorted(set(labels.tolist()))
    return {
        "row_count": len(labels),
        "observed_labels": [class_names[index] for index in observed_ids],
        "observed_class_count": len(observed_ids),
        "loss": loss,
        "accuracy": float(accuracy_score(labels, predictions)),
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
            "values": confusion_matrix(labels, predictions, labels=label_ids)
            .astype(int)
            .tolist(),
        },
    }


def _distribution(values: list[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "mean": math.fsum(values) / len(values) if values else None,
        "minimum": min(values) if values else None,
        "maximum": max(values) if values else None,
    }


def _prototype_explainability(
    *,
    actual: Any,
    predicted: Any,
    nearest: dict[str, Any],
    class_names: list[str],
) -> dict[str, Any]:
    distances = [float(value) for value in nearest["nearest_distances"]]
    margins = [
        None if value is None else float(value)
        for value in nearest["distance_margins"]
    ]

    def grouped(indices: list[int]) -> dict[str, Any]:
        group_distances = [distances[index] for index in indices]
        group_margins = [margins[index] for index in indices if margins[index] is not None]
        return {
            "row_count": len(indices),
            "nearest_distance": _distribution(group_distances),
            "distance_margin": _distribution(group_margins),
        }

    return {
        "method": "nearest_global_prototype_euclidean_distance",
        "available_classes": nearest["available_classes"],
        "unavailable_classes": nearest["unavailable_classes"],
        "overall": grouped(list(range(len(distances)))),
        "by_actual_class": {
            name: grouped(
                [index for index, value in enumerate(actual.tolist()) if value == class_id]
            )
            for class_id, name in enumerate(class_names)
        },
        "by_predicted_class": {
            name: grouped(
                [
                    index
                    for index, value in enumerate(predicted.tolist())
                    if value == class_id
                ]
            )
            for class_id, name in enumerate(class_names)
        },
        "privacy_boundary": "no row embeddings or row distances are persisted",
    }


def _feature_records(
    *, signed_sum: Any, absolute_sum: Any, count: int, feature_names: list[str]
) -> list[dict[str, Any]]:
    records = [
        {
            "feature": name,
            "mean_signed_attribution": float(signed_sum[index] / count),
            "mean_absolute_attribution": float(absolute_sum[index] / count),
        }
        for index, name in enumerate(feature_names)
    ]
    records.sort(key=lambda item: (-item["mean_absolute_attribution"], item["feature"]))
    for rank, record in enumerate(records, start=1):
        record["mean_absolute_rank"] = rank
    return records


def _gradient_x_input_explainability(
    *,
    model: Any,
    rows: list[dict[str, Any]],
    class_names: list[str],
    feature_names: list[str],
    batch_size: int,
    np: Any,
    torch: Any,
    minimum_group_rows: int = MINIMUM_EXPLAINABILITY_GROUP_ROWS,
) -> dict[str, Any]:
    features = np.asarray([row["features"] for row in rows], dtype=np.float32)
    dataset = torch.utils.data.TensorDataset(torch.from_numpy(features))
    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=min(batch_size, len(dataset)),
        shuffle=False,
        num_workers=0,
    )
    feature_count = len(feature_names)
    overall_signed = np.zeros(feature_count, dtype=np.float64)
    overall_absolute = np.zeros(feature_count, dtype=np.float64)
    class_signed = {
        index: np.zeros(feature_count, dtype=np.float64)
        for index in range(len(class_names))
    }
    class_absolute = {
        index: np.zeros(feature_count, dtype=np.float64)
        for index in range(len(class_names))
    }
    class_counts = {index: 0 for index in range(len(class_names))}
    model.to("cpu")
    model.eval()
    for (batch_features,) in loader:
        batch_features = batch_features.detach().clone().requires_grad_(True)
        logits = model(batch_features)
        predicted = logits.detach().argmax(dim=1)
        target = logits.gather(1, predicted.unsqueeze(1)).sum()
        gradients = torch.autograd.grad(target, batch_features)[0]
        attribution = (
            gradients.mul(batch_features).detach().cpu().numpy().astype(np.float64)
        )
        predicted_values = predicted.cpu().numpy()
        overall_signed += attribution.sum(axis=0)
        overall_absolute += np.abs(attribution).sum(axis=0)
        for class_id in range(len(class_names)):
            mask = predicted_values == class_id
            count = int(mask.sum())
            if count:
                class_signed[class_id] += attribution[mask].sum(axis=0)
                class_absolute[class_id] += np.abs(attribution[mask]).sum(axis=0)
                class_counts[class_id] += count

    row_count = len(rows)
    by_class: dict[str, Any] = {}
    for class_id, name in enumerate(class_names):
        count = class_counts[class_id]
        if count < minimum_group_rows:
            by_class[name] = {
                "row_count": count,
                "status": "suppressed_below_minimum_group_size",
                "features": [],
            }
        else:
            by_class[name] = {
                "row_count": count,
                "status": "reported",
                "features": _feature_records(
                    signed_sum=class_signed[class_id],
                    absolute_sum=class_absolute[class_id],
                    count=count,
                    feature_names=feature_names,
                ),
            }
    return {
        "method": "gradient_x_input",
        "target": "classification_head_predicted_class_logit",
        "grouping": "classification_head_predicted_class",
        "baseline": "zero_in_training_standardized_feature_space",
        "aggregation": "mean_signed_and_mean_absolute",
        "minimum_group_rows": minimum_group_rows,
        "overall": {
            "row_count": row_count,
            "features": _feature_records(
                signed_sum=overall_signed,
                absolute_sum=overall_absolute,
                count=row_count,
                feature_names=feature_names,
            ),
        },
        "by_predicted_class": by_class,
        "privacy_boundary": "no row-level gradients or attributions are persisted",
    }


def _head_prototype_agreement(
    *, head_predictions: Any, prototype_predictions: Any, class_names: list[str]
) -> dict[str, Any]:
    matches = head_predictions == prototype_predictions
    total = len(head_predictions)
    by_class = {}
    for class_id, name in enumerate(class_names):
        mask = head_predictions == class_id
        count = int(mask.sum())
        agreements = int(matches[mask].sum()) if count else 0
        by_class[name] = {
            "head_prediction_count": count,
            "agreement_count": agreements,
            "agreement_rate": agreements / count if count else None,
        }
    agreement_count = int(matches.sum())
    return {
        "row_count": total,
        "agreement_count": agreement_count,
        "disagreement_count": total - agreement_count,
        "agreement_rate": agreement_count / total,
        "by_head_predicted_class": by_class,
    }


def _evaluate_endpoint_split(
    *,
    classifier: str,
    model: Any,
    prototypes: dict[str, list[float]],
    rows: list[dict[str, Any]],
    class_names: list[str],
    feature_names: list[str],
    batch_size: int,
    dependency_values: tuple[Any, ...],
) -> tuple[dict[str, Any], dict[str, Any]]:
    np, torch, *_rest = dependency_values
    label_indices = {name: index for index, name in enumerate(class_names)}
    labels = np.asarray(
        [label_indices[str(row["label"])] for row in rows], dtype=np.int64
    )
    inference = _inference_arrays(
        model=model, rows=rows, batch_size=batch_size, np=np, torch=torch
    )
    nearest = nearest_prototype_predictions(
        embeddings=inference["embeddings"],
        class_names=class_names,
        global_prototypes=prototypes,
        np=np,
    )
    prototype_predictions = np.asarray(
        nearest["prediction_indices"], dtype=np.int64
    )
    head_predictions = inference["logits"].argmax(axis=1).astype(np.int64)
    if classifier == "nearest_global_prototype":
        predictions = prototype_predictions
        loss = None
    elif classifier == "classification_head":
        predictions = head_predictions
        logits = torch.from_numpy(inference["logits"])
        label_tensor = torch.from_numpy(labels)
        loss = float(
            torch.nn.functional.cross_entropy(
                logits, label_tensor, reduction="sum"
            ).item()
            / len(labels)
        )
    else:
        raise ValueError(f"unsupported frozen endpoint classifier: {classifier}")
    metrics = _classification_metrics(
        labels=labels,
        predictions=predictions,
        class_names=class_names,
        loss=loss,
        dependency_values=dependency_values,
    )
    metrics["operational_metrics"] = {
        "benign_false_alarms": _benign_false_alarm_summary(metrics)
    }
    prototype_evidence = _prototype_explainability(
        actual=labels,
        predicted=prototype_predictions,
        nearest=nearest,
        class_names=class_names,
    )
    explanation: dict[str, Any] = {"prototype_evidence": prototype_evidence}
    if classifier == "classification_head":
        explanation.update(
            {
                "head_prototype_agreement": _head_prototype_agreement(
                    head_predictions=head_predictions,
                    prototype_predictions=prototype_predictions,
                    class_names=class_names,
                ),
                "feature_attribution": _gradient_x_input_explainability(
                    model=model,
                    rows=rows,
                    class_names=class_names,
                    feature_names=feature_names,
                    batch_size=batch_size,
                    np=np,
                    torch=torch,
                ),
            }
        )
    return metrics, explanation


def _endpoint_payload(
    *,
    endpoint: dict[str, Any],
    source: dict[str, Any],
    split_rows: dict[str, list[dict[str, Any]]],
    class_names: list[str],
    feature_names: list[str],
    dependency_values: tuple[Any, ...],
) -> tuple[dict[str, Any], dict[str, Any]]:
    np, torch, *_rest = dependency_values
    model, model_classes = _model_from_export(
        source["model_export"], torch=torch, np=np
    )
    if model_classes != class_names:
        raise ValueError("frozen endpoint model class order does not match partition")
    prototypes = available_prototype_values(source["prototype_object"])
    batch_size = int(source["manifest"]["training"]["batch_size"])
    evaluations = {}
    explanations = {}
    for split in FINAL_SPLITS:
        metrics, explanation = _evaluate_endpoint_split(
            classifier=str(endpoint["classifier"]),
            model=model,
            prototypes=prototypes,
            rows=split_rows[split],
            class_names=class_names,
            feature_names=feature_names,
            batch_size=batch_size,
            dependency_values=dependency_values,
        )
        evaluations[split] = metrics
        explanations[split] = explanation
    provenance = {
        "candidate_manifest_sha256": source["manifest_sha256"],
        "round": int(endpoint["round"]),
        "round_record_path": source["round_record_path"],
        "round_record_sha256": source["round_record_sha256"],
        "model_path": source["model_path"],
        "model_sha256": endpoint["model_sha256"],
        "global_prototypes_path": source["prototype_path"],
        "global_prototypes_sha256": endpoint["global_prototypes_sha256"],
    }
    return (
        {
            "endpoint_id": endpoint["endpoint_id"],
            "role": endpoint["role"],
            "classifier": endpoint["classifier"],
            "paper_faithful_inference": endpoint["paper_faithful_inference"],
            "prototype_alignment_weight": endpoint["prototype_alignment_weight"],
            "validation_metric_locked_pretest": endpoint["validation_metric"],
            "provenance": provenance,
            **evaluations,
        },
        {
            "endpoint_id": endpoint["endpoint_id"],
            "classifier": endpoint["classifier"],
            "provenance": provenance,
            **explanations,
        },
    )


def _comparison_payload(
    *, endpoints: dict[str, dict[str, Any]], baseline_selected: dict[str, Any]
) -> dict[str, Any]:
    baseline_test = baseline_selected["test"]
    baseline_holdout = baseline_selected["temporal_holdout"]
    baseline_false_alarm = _benign_false_alarm_summary(baseline_holdout)
    comparisons = {}
    for endpoint_id, endpoint in endpoints.items():
        endpoint_test = endpoint["test"]
        endpoint_holdout = endpoint["temporal_holdout"]
        endpoint_false_alarm = endpoint_holdout["operational_metrics"][
            "benign_false_alarms"
        ]
        comparisons[endpoint_id] = {
            "test_macro_f1": endpoint_test[SELECTION_METRIC],
            "test_macro_f1_delta_vs_fedavg": (
                endpoint_test[SELECTION_METRIC] - baseline_test[SELECTION_METRIC]
            ),
            "test_accuracy": endpoint_test["accuracy"],
            "test_accuracy_delta_vs_fedavg": (
                endpoint_test["accuracy"] - baseline_test["accuracy"]
            ),
            "temporal_holdout_accuracy": endpoint_holdout["accuracy"],
            "temporal_holdout_accuracy_delta_vs_fedavg": (
                endpoint_holdout["accuracy"] - baseline_holdout["accuracy"]
            ),
            "temporal_holdout_false_alarm_rate": endpoint_false_alarm[
                "false_alarm_rate"
            ],
            "temporal_holdout_false_alarm_rate_delta_vs_fedavg": (
                endpoint_false_alarm["false_alarm_rate"]
                - baseline_false_alarm["false_alarm_rate"]
            ),
        }
    return {
        "fedavg": {
            "test_macro_f1": baseline_test[SELECTION_METRIC],
            "test_accuracy": baseline_test["accuracy"],
            "temporal_holdout_accuracy": baseline_holdout["accuracy"],
            "temporal_holdout_false_alarm_rate": baseline_false_alarm[
                "false_alarm_rate"
            ],
        },
        "endpoints": comparisons,
        "interpretation": (
            "The temporal holdout is benign-only; its accuracy is interpreted as one "
            "minus the false-alarm rate, not as multiclass effectiveness."
        ),
    }


def _confusion_figure(
    *, plt: Any, class_names: list[str], endpoints: dict[str, dict[str, Any]]
) -> Any:
    fig, axes = plt.subplots(1, 2, figsize=(15.5, 6.2))
    for ax, endpoint_id, title in zip(
        axes,
        (PRIMARY_ENDPOINT_ID, SECONDARY_ENDPOINT_ID),
        ("Primary: nearest prototype", "Secondary: classification head"),
        strict=True,
    ):
        values = endpoints[endpoint_id]["test"]["confusion_matrix"]["values"]
        row_totals = [sum(row) for row in values]
        normalized = [
            [value / total if total else 0.0 for value in row]
            for row, total in zip(values, row_totals, strict=True)
        ]
        image = ax.imshow(normalized, cmap="Blues", vmin=0.0, vmax=1.0)
        ax.set_xticks(range(len(class_names)), class_names, rotation=35, ha="right")
        ax.set_yticks(range(len(class_names)), class_names)
        ax.set_xlabel("Predicted class")
        ax.set_ylabel("Actual class")
        ax.set_title(title)
        for row_index, row in enumerate(values):
            for column_index, value in enumerate(row):
                ax.text(
                    column_index,
                    row_index,
                    str(value),
                    ha="center",
                    va="center",
                    fontsize=8,
                    color="white" if normalized[row_index][column_index] > 0.55 else "black",
                )
    fig.colorbar(image, ax=axes.ravel().tolist(), shrink=0.82, label="Row-normalized rate")
    fig.suptitle("Frozen PROTEAN endpoints: final test confusion matrices")
    return fig


def _performance_figure(
    *, plt: Any, evaluation: dict[str, Any]
) -> Any:
    comparison = evaluation["comparison"]
    labels = ["FedAvg", "Primary", "Secondary"]
    test_f1 = [
        comparison["fedavg"]["test_macro_f1"],
        comparison["endpoints"][PRIMARY_ENDPOINT_ID]["test_macro_f1"],
        comparison["endpoints"][SECONDARY_ENDPOINT_ID]["test_macro_f1"],
    ]
    holdout_accuracy = [
        comparison["fedavg"]["temporal_holdout_accuracy"],
        comparison["endpoints"][PRIMARY_ENDPOINT_ID]["temporal_holdout_accuracy"],
        comparison["endpoints"][SECONDARY_ENDPOINT_ID]["temporal_holdout_accuracy"],
    ]
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.8))
    colors = ["#7f8c8d", "#1f77b4", "#ff7f0e"]
    axes[0].bar(labels, test_f1, color=colors)
    axes[0].set_title("Multiclass test macro-F1")
    axes[1].bar(labels, holdout_accuracy, color=colors)
    axes[1].set_title("Benign temporal holdout accuracy")
    for ax, values in zip(axes, (test_f1, holdout_accuracy), strict=True):
        _style_axes(ax)
        ax.set_ylim(max(0.0, min(values) - 0.08), min(1.0, max(values) + 0.04))
        for index, value in enumerate(values):
            ax.text(index, value + 0.006, f"{value:.4f}", ha="center", fontsize=9)
    fig.suptitle("Final frozen-model comparison")
    return fig


def _feature_figure(*, plt: Any, explainability: dict[str, Any]) -> Any:
    features = explainability["endpoints"][SECONDARY_ENDPOINT_ID]["test"][
        "feature_attribution"
    ]["overall"]["features"][:12]
    names = [item["feature"] for item in reversed(features)]
    values = [item["mean_absolute_attribution"] for item in reversed(features)]
    fig, ax = plt.subplots(figsize=(10.5, 6.2))
    ax.barh(names, values, color="#ff7f0e")
    ax.set_xlabel("Mean absolute gradient × input")
    ax.set_title("Secondary endpoint: aggregate test feature importance")
    _style_axes(ax, grid_axis="x")
    return fig


def _write_final_workspace(
    *,
    output: Path,
    inputs: dict[str, Any],
    evaluation: dict[str, Any],
    explainability: dict[str, Any],
    dependency_values: tuple[Any, ...],
    server_evaluation_sha256: str,
) -> dict[str, Any]:
    evaluation_bytes = derived_json_bytes(evaluation)
    explainability["evaluation_sha256"] = sha256_bytes(evaluation_bytes)
    explainability_bytes = derived_json_bytes(explainability)
    receipt = {
        "schema_version": "1.0",
        "artifact_type": "protean_final_test_access_receipt",
        "dataset": DATASET_NAME,
        "selection_lock_sha256": inputs["lock_sha256"],
        "precondition": "verified_selection_lock_with_test_gate_locked",
        "access_scope": list(FINAL_SPLITS),
        "endpoint_ids": [PRIMARY_ENDPOINT_ID, SECONDARY_ENDPOINT_ID],
        "scientific_evaluation_passes_per_endpoint_and_split": 1,
        "purpose": "final_generalization_and_temporal_false_alarm_evaluation",
        "post_access_prohibitions": [
            "hyperparameter_changes",
            "checkpoint_reselection",
            "threshold_tuning",
            "class_remapping",
        ],
        "test_data_accessed": True,
    }
    write_once(output / "evaluation.json", evaluation_bytes)
    write_once(output / "explainability.json", explainability_bytes)
    write_once(output / "test_access_receipt.json", derived_json_bytes(receipt))

    _matplotlib, plt = _plotting_dependencies()
    figures = []
    figure_specs = (
        (
            "figures/final_performance.png",
            "Final test macro-F1 and benign temporal-holdout accuracy.",
            lambda: _performance_figure(plt=plt, evaluation=evaluation),
        ),
        (
            "figures/test_confusion_matrices.png",
            "Row-normalized final test confusion matrices with absolute counts.",
            lambda: _confusion_figure(
                plt=plt,
                class_names=evaluation["class_names"],
                endpoints=evaluation["endpoints"],
            ),
        ),
        (
            "figures/secondary_test_feature_importance.png",
            "Aggregate gradient-times-input importance for the operational endpoint.",
            lambda: _feature_figure(plt=plt, explainability=explainability),
        ),
    )
    for relative, description, build in figure_specs:
        path = output / relative
        write_once(path, _figure_bytes(build(), plt=plt))
        figures.append(
            {
                "path": relative,
                "description": description,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )

    artifact_files = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    np, torch, _flwr, sklearn, *_rest = dependency_values
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "protean_final_evaluation_manifest",
        "dataset": DATASET_NAME,
        "code_version": __version__,
        "partition_mode": "non-iid",
        "selection_lock_sha256": inputs["lock_sha256"],
        "selection_lock_manifest_sha256": inputs["lock_manifest_sha256"],
        "partition_manifest_sha256": inputs["partition_manifest_sha256"],
        "dataset_manifest_sha256": inputs["dataset_manifest_sha256"],
        "server_evaluation_sha256": server_evaluation_sha256,
        "candidate_sources": {
            endpoint_id: evaluation["endpoints"][endpoint_id]["provenance"]
            for endpoint_id in (PRIMARY_ENDPOINT_ID, SECONDARY_ENDPOINT_ID)
        },
        "fedavg_source": inputs["baseline"]["source_digests"],
        "implementation_files": {
            "protean_finalization.py": sha256_file(Path(__file__)),
            "protean.py": sha256_file(Path(__file__).with_name("protean.py")),
            "federated_model.py": sha256_file(
                Path(__file__).with_name("federated_model.py")
            ),
        },
        "framework": {
            "torch_version": torch.__version__,
            "numpy_version": np.__version__,
            "sklearn_version": sklearn.__version__,
        },
        "artifact_files": artifact_files,
        "figures": figures,
        "test_data_accessed": True,
        "selection_changed_after_test_access": False,
    }
    write_once(output / "manifest.json", derived_json_bytes(manifest))
    return manifest


def finalize_protean_endpoints(
    *,
    candidate_workspaces: list[Path],
    fedavg_workspace: Path,
    report_workspace: Path,
    selection_lock_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Evaluate exactly the two frozen endpoints after verifying every precondition."""

    if output.exists():
        raise FileExistsError(
            f"final PROTEAN output is write-once and already exists: {output}"
        )
    inputs = _verified_pretest_inputs(
        candidate_workspaces=candidate_workspaces,
        fedavg_workspace=fedavg_workspace,
        report_workspace=report_workspace,
        selection_lock_workspace=selection_lock_workspace,
        partition_workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
        config_path=config_path,
    )
    partition_manifest = inputs["partition_manifest"]
    server_path = partition_workspace / str(
        partition_manifest["server_evaluation_path"]
    )
    if sha256_file(server_path) != partition_manifest.get("server_evaluation_sha256"):
        raise ValueError("server-evaluation snapshot digest mismatch")
    server_evaluation = _load_json(server_path, "frozen server evaluation snapshot")
    split_rows = {split: server_evaluation["rows"][split] for split in FINAL_SPLITS}
    class_names = [str(value) for value in partition_manifest["class_names"]]
    feature_names = [str(value) for value in partition_manifest["feature_names"]]
    if server_evaluation.get("class_names") != class_names:
        raise ValueError("server-evaluation class order does not match partition")
    if server_evaluation.get("feature_names") != feature_names:
        raise ValueError("server-evaluation feature order does not match partition")
    dependency_values = dependencies()

    endpoint_evaluations = {}
    endpoint_explanations = {}
    for endpoint_key, endpoint_id in (
        ("primary_endpoint", PRIMARY_ENDPOINT_ID),
        ("secondary_endpoint", SECONDARY_ENDPOINT_ID),
    ):
        endpoint_evaluation, endpoint_explanation = _endpoint_payload(
            endpoint=inputs["lock"][endpoint_key],
            source=inputs["endpoints"][endpoint_id],
            split_rows=split_rows,
            class_names=class_names,
            feature_names=feature_names,
            dependency_values=dependency_values,
        )
        endpoint_evaluations[endpoint_id] = endpoint_evaluation
        endpoint_explanations[endpoint_id] = endpoint_explanation

    baseline_selected = inputs["baseline"]["comparison"]["fedavg_selected"]
    evaluation = {
        "schema_version": "1.0",
        "artifact_type": "protean_final_locked_endpoint_evaluation",
        "dataset": DATASET_NAME,
        "partition_mode": "non-iid",
        "class_names": class_names,
        "mitre_tactic_mapping": {
            name: MITRE_TACTIC_MAPPING[name] for name in class_names
        },
        "selection_lock_sha256": inputs["lock_sha256"],
        "selection_policy": "immutable_pretest_lock",
        "fedavg_reference": {
            "source_digests": inputs["baseline"]["source_digests"],
            "test": baseline_selected["test"],
            "temporal_holdout": baseline_selected["temporal_holdout"],
        },
        "endpoints": endpoint_evaluations,
        "comparison": _comparison_payload(
            endpoints=endpoint_evaluations, baseline_selected=baseline_selected
        ),
        "test_data_accessed": True,
        "selection_changed_after_test_access": False,
        "interpretation_constraints": [
            "The primary endpoint is the confirmatory paper-faithful result.",
            "The secondary endpoint is a validation-selected operational adaptation.",
            "The temporal holdout is benign-only and measures false-alarm behavior.",
            (
                "No tuning, checkpoint selection, threshold selection, or class "
                "remapping is permitted after this evaluation."
            ),
            "UWF-ZeekData24 is controlled cyber-range traffic, not production traffic.",
        ],
    }
    explainability = {
        "schema_version": "1.0",
        "artifact_type": "protean_final_aggregate_explainability",
        "dataset": DATASET_NAME,
        "selection_lock_sha256": inputs["lock_sha256"],
        "feature_names": feature_names,
        "endpoints": endpoint_explanations,
        "privacy_boundary": (
            "Only split-level and class-level aggregates are persisted; row embeddings, "
            "row distances, gradients, and row attributions are excluded."
        ),
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".fl-forensics-protean-final-", dir=output.parent
    ) as temporary:
        stage = Path(temporary) / "workspace"
        manifest = _write_final_workspace(
            output=stage,
            inputs=inputs,
            evaluation=evaluation,
            explainability=explainability,
            dependency_values=dependency_values,
            server_evaluation_sha256=sha256_file(server_path),
        )
        os.replace(stage, output)
    return {
        "status": "finalized",
        "workspace": str(output),
        "primary_endpoint": PRIMARY_ENDPOINT_ID,
        "primary_test_macro_f1": endpoint_evaluations[PRIMARY_ENDPOINT_ID]["test"][
            SELECTION_METRIC
        ],
        "secondary_endpoint": SECONDARY_ENDPOINT_ID,
        "secondary_test_macro_f1": endpoint_evaluations[SECONDARY_ENDPOINT_ID][
            "test"
        ][SELECTION_METRIC],
        "fedavg_test_macro_f1": baseline_selected["test"][SELECTION_METRIC],
        "figure_count": len(manifest["figures"]),
        "manifest_sha256": sha256_file(output / "manifest.json"),
        "selection_lock_sha256": inputs["lock_sha256"],
        "test_data_accessed": True,
        "selection_changed_after_test_access": False,
    }


def _check_metric_consistency(metrics: dict[str, Any]) -> list[str]:
    errors = []
    matrix = metrics.get("confusion_matrix", {})
    labels = matrix.get("labels", [])
    values = matrix.get("values", [])
    if not labels or len(values) != len(labels) or any(
        len(row) != len(labels) for row in values
    ):
        return ["invalid confusion-matrix shape"]
    row_count = sum(sum(int(value) for value in row) for row in values)
    if row_count != int(metrics.get("row_count", -1)):
        errors.append("confusion-matrix row count mismatch")
    correct = sum(int(values[index][index]) for index in range(len(labels)))
    if row_count and not _same_float(metrics.get("accuracy"), correct / row_count):
        errors.append("accuracy does not match confusion matrix")
    per_class = metrics.get("per_class", {})
    supports = [sum(int(value) for value in row) for row in values]
    for index, name in enumerate(labels):
        if int(per_class.get(name, {}).get("support", -1)) != supports[index]:
            errors.append(f"per-class support mismatch: {name}")
    return errors


def verify_protean_finalization(
    *,
    candidate_workspaces: list[Path],
    fedavg_workspace: Path,
    report_workspace: Path,
    selection_lock_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Verify final evidence without performing another scientific inference pass."""

    errors: list[str] = []
    manifest: dict[str, Any] = {}
    evaluation: dict[str, Any] = {}
    try:
        lock_verification = verify_protean_selection_lock(
            candidate_workspaces=candidate_workspaces,
            fedavg_workspace=fedavg_workspace,
            report_workspace=report_workspace,
            workspace=selection_lock_workspace,
            config_path=config_path,
        )
        if lock_verification["status"] != "verified":
            errors.append("referenced PROTEAN selection lock does not verify")
        partition_verification = verify_partitions(
            workspace=partition_workspace, dataset_workspace=dataset_workspace
        )
        if partition_verification["status"] != "verified":
            errors.append("referenced partition workspace does not verify")
        if not workspace.is_dir():
            raise ValueError(f"missing PROTEAN final workspace: {workspace}")
        manifest_path = workspace / "manifest.json"
        manifest = _load_json(manifest_path, "PROTEAN final manifest")
        if manifest.get("artifact_type") != "protean_final_evaluation_manifest":
            errors.append("unexpected PROTEAN final manifest type")
        lock_path = selection_lock_workspace / "selection_lock.json"
        lock_manifest_path = selection_lock_workspace / "manifest.json"
        lock = _load_json(lock_path, "PROTEAN selection lock")
        partition_manifest = _load_json(
            partition_workspace / "manifest.json", "non-IID partition manifest"
        )
        expected_bindings = {
            "selection_lock_sha256": sha256_file(lock_path),
            "selection_lock_manifest_sha256": sha256_file(lock_manifest_path),
            "partition_manifest_sha256": sha256_file(
                partition_workspace / "manifest.json"
            ),
            "dataset_manifest_sha256": sha256_file(dataset_workspace / "manifest.json"),
        }
        for field, expected in expected_bindings.items():
            if manifest.get(field) != expected:
                errors.append(f"final manifest source binding mismatch: {field}")
        server_path = partition_workspace / str(
            partition_manifest["server_evaluation_path"]
        )
        if manifest.get("server_evaluation_sha256") != sha256_file(server_path):
            errors.append("final manifest server-evaluation binding mismatch")
        expected_implementations = {
            "protean_finalization.py": sha256_file(Path(__file__)),
            "protean.py": sha256_file(Path(__file__).with_name("protean.py")),
            "federated_model.py": sha256_file(
                Path(__file__).with_name("federated_model.py")
            ),
        }
        if manifest.get("implementation_files") != expected_implementations:
            errors.append("finalizer implementation digest mismatch")

        sources = _candidate_sources(candidate_workspaces)
        expected_sources = {}
        for endpoint_key, endpoint_id in (
            ("primary_endpoint", PRIMARY_ENDPOINT_ID),
            ("secondary_endpoint", SECONDARY_ENDPOINT_ID),
        ):
            source = _endpoint_source(endpoint=lock[endpoint_key], sources=sources)
            expected_sources[endpoint_id] = {
                "candidate_manifest_sha256": source["manifest_sha256"],
                "round": int(lock[endpoint_key]["round"]),
                "round_record_path": source["round_record_path"],
                "round_record_sha256": source["round_record_sha256"],
                "model_path": source["model_path"],
                "model_sha256": lock[endpoint_key]["model_sha256"],
                "global_prototypes_path": source["prototype_path"],
                "global_prototypes_sha256": lock[endpoint_key][
                    "global_prototypes_sha256"
                ],
            }
        if manifest.get("candidate_sources") != expected_sources:
            errors.append("final manifest candidate-source binding mismatch")
        baseline = _validated_fedavg(fedavg_workspace)
        if manifest.get("fedavg_source") != baseline["source_digests"]:
            errors.append("final manifest FedAvg-source binding mismatch")
        declared_files = manifest.get("artifact_files", {})
        if not isinstance(declared_files, dict):
            raise TypeError("final manifest artifact_files must be an object")
        actual_files = {
            path.relative_to(workspace).as_posix(): sha256_file(path)
            for path in sorted(workspace.rglob("*"))
            if path.is_file() and path.name != "manifest.json"
        }
        if set(declared_files) != set(actual_files):
            errors.append("final artifact file set mismatch")
        for relative in sorted(set(declared_files) & set(actual_files)):
            if declared_files[relative] != actual_files[relative]:
                errors.append(f"final artifact digest mismatch: {relative}")
        evaluation = _load_json(workspace / "evaluation.json", "final evaluation")
        explainability = _load_json(
            workspace / "explainability.json", "final explainability"
        )
        receipt = _load_json(
            workspace / "test_access_receipt.json", "final test-access receipt"
        )
        if explainability.get("evaluation_sha256") != sha256_file(
            workspace / "evaluation.json"
        ):
            errors.append("explainability/evaluation binding mismatch")
        if any(
            item.get("selection_lock_sha256")
            != manifest.get("selection_lock_sha256")
            for item in (evaluation, explainability, receipt)
        ):
            errors.append("final artifact selection-lock binding mismatch")
        if evaluation.get("test_data_accessed") is not True:
            errors.append("final evaluation does not declare test access")
        if evaluation.get("selection_changed_after_test_access") is not False:
            errors.append("final evaluation does not preserve the frozen selection")
        for endpoint_id in (PRIMARY_ENDPOINT_ID, SECONDARY_ENDPOINT_ID):
            endpoint = evaluation.get("endpoints", {}).get(endpoint_id, {})
            if endpoint.get("provenance") != expected_sources[endpoint_id]:
                errors.append(f"{endpoint_id} provenance mismatch")
            for split in FINAL_SPLITS:
                for error in _check_metric_consistency(endpoint.get(split, {})):
                    errors.append(f"{endpoint_id} {split}: {error}")
                expected_rows = int(partition_manifest["split_counts"][split])
                if endpoint.get(split, {}).get("row_count") != expected_rows:
                    errors.append(f"{endpoint_id} {split}: split row count mismatch")
                explanation = explainability.get("endpoints", {}).get(
                    endpoint_id, {}
                ).get(split, {})
                prototype_rows = explanation.get("prototype_evidence", {}).get(
                    "overall", {}
                ).get("row_count")
                if prototype_rows != expected_rows:
                    errors.append(
                        f"{endpoint_id} {split}: prototype explanation row count mismatch"
                    )
                if endpoint_id == SECONDARY_ENDPOINT_ID:
                    attribution_rows = explanation.get("feature_attribution", {}).get(
                        "overall", {}
                    ).get("row_count")
                    if attribution_rows != expected_rows:
                        errors.append(
                            f"{endpoint_id} {split}: attribution row count mismatch"
                        )
        if receipt.get("artifact_type") != "protean_final_test_access_receipt":
            errors.append("unexpected final test-access receipt type")
        if receipt.get("access_scope") != list(FINAL_SPLITS):
            errors.append("final test-access scope mismatch")
        if receipt.get("scientific_evaluation_passes_per_endpoint_and_split") != 1:
            errors.append("final scientific evaluation-pass declaration mismatch")
        forbidden_keys = {"rows", "row_attributions", "row_embeddings", "window_id"}

        def contains_forbidden(value: Any) -> bool:
            if isinstance(value, dict):
                return bool(forbidden_keys.intersection(value)) or any(
                    contains_forbidden(item) for item in value.values()
                )
            if isinstance(value, list):
                return any(contains_forbidden(item) for item in value)
            return False

        if contains_forbidden(explainability):
            errors.append("explainability artifact crosses the row-level privacy boundary")
    except (KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "error_count": len(errors),
        "errors": errors,
        "primary_endpoint": PRIMARY_ENDPOINT_ID,
        "primary_test_macro_f1": evaluation.get("endpoints", {})
        .get(PRIMARY_ENDPOINT_ID, {})
        .get("test", {})
        .get(SELECTION_METRIC),
        "secondary_endpoint": SECONDARY_ENDPOINT_ID,
        "secondary_test_macro_f1": evaluation.get("endpoints", {})
        .get(SECONDARY_ENDPOINT_ID, {})
        .get("test", {})
        .get(SELECTION_METRIC),
        "manifest_sha256": (
            sha256_file(workspace / "manifest.json")
            if (workspace / "manifest.json").is_file()
            else None
        ),
        "test_data_accessed": evaluation.get("test_data_accessed"),
        "verification_recomputed_model_inference": False,
    }
