"""Validation-only auditable runner for PROTEAN hyperparameter candidates."""

from __future__ import annotations

import json
import math
import statistics
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_bytes, sha256_file
from .config import load_yaml
from .dataset24 import DATASET_NAME
from .federated_model import (
    architecture_record,
    arrays_from_export,
    build_model,
    dependencies,
    export_state,
    fedavg,
    load_ndarrays,
    model_to_ndarrays,
    seed_everything,
)
from .federated_partitioning import verify_partitions
from .federated_training import (
    SELECTION_METRIC,
    _evaluate,
    _load_client_snapshots,
    _model_from_export,
    _same_json,
)
from .preprocessing import derived_json_bytes
from .protean import (
    aggregate_global_prototypes,
    available_prototype_values,
    extract_local_prototypes,
    nearest_prototype_predictions,
    train_local_protean,
)
from .storage import write_once

PROTEAN_CANDIDATE_SELECTION_POLICY = {
    "classifier": "nearest_global_prototype",
    "split": "validation",
    "metric": SELECTION_METRIC,
    "mode": "maximize",
    "tie_breaker": "earliest_round",
    "test_policy": "withheld_until_cross_candidate_selection",
}
FORBIDDEN_SELECTION_SPLITS = {"test", "temporal_holdout"}
TRAINING_LOSS_KEYS = (
    "objective_loss",
    "supervised_loss",
    "prototype_alignment_loss",
    "proximal_penalty",
)


def _object_path(category: str, digest: str) -> Path:
    return Path("objects") / category / "sha256" / digest[:2] / f"{digest[2:]}.json"


def _store_object(
    output: Path, category: str, value: dict[str, Any]
) -> tuple[str, str]:
    content = derived_json_bytes(value)
    digest = sha256_bytes(content)
    relative = _object_path(category, digest)
    write_once(output / relative, content)
    return relative.as_posix(), digest


def _select_candidate_checkpoint(history: list[dict[str, Any]]) -> dict[str, Any]:
    if not history:
        raise ValueError("cannot select a PROTEAN checkpoint without validation metrics")
    return max(
        history,
        key=lambda item: (
            float(item["validation"]["nearest_global_prototype"][SELECTION_METRIC]),
            -int(item["round"]),
        ),
    )


def _contains_forbidden_evaluation_split(value: Any) -> bool:
    if isinstance(value, dict):
        if FORBIDDEN_SELECTION_SPLITS.intersection(value):
            return True
        return any(_contains_forbidden_evaluation_split(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_evaluation_split(item) for item in value)
    return False


def _evaluate_prototype_rows(
    *,
    model: Any,
    rows: list[dict[str, Any]],
    class_names: list[str],
    global_prototypes: dict[str, list[float]],
    batch_size: int,
    dependency_values: tuple[Any, ...],
) -> dict[str, Any]:
    (
        np,
        torch,
        _flwr,
        _sklearn,
        _aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependency_values
    if not rows:
        raise ValueError("PROTEAN validation cannot evaluate an empty split")
    label_indices = {name: index for index, name in enumerate(class_names)}
    features = np.asarray([row["features"] for row in rows], dtype=np.float32)
    labels = np.asarray(
        [label_indices[str(row["label"])] for row in rows], dtype=np.int64
    )
    dataset = torch.utils.data.TensorDataset(torch.from_numpy(features))
    loader = torch.utils.data.DataLoader(
        dataset,
        batch_size=min(batch_size, len(dataset)),
        shuffle=False,
        num_workers=0,
    )
    model.to("cpu")
    model.eval()
    embedding_batches = []
    with torch.no_grad():
        for (batch_features,) in loader:
            embedding_batches.append(model.encoder(batch_features).cpu().numpy())
    embeddings = np.concatenate(embedding_batches, axis=0)
    nearest = nearest_prototype_predictions(
        embeddings=embeddings,
        class_names=class_names,
        global_prototypes=global_prototypes,
        np=np,
    )
    predictions = np.asarray(nearest["prediction_indices"], dtype=np.int64)
    label_ids = list(range(len(class_names)))
    precision, recall, f1, support = precision_recall_fscore_support(
        labels, predictions, labels=label_ids, zero_division=0
    )
    observed_ids = sorted(set(labels.tolist()))
    margins = [
        float(value) for value in nearest["distance_margins"] if value is not None
    ]
    distances = [float(value) for value in nearest["nearest_distances"]]
    return {
        "row_count": len(labels),
        "observed_labels": [class_names[index] for index in observed_ids],
        "observed_class_count": len(observed_ids),
        "loss": None,
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
        "prototype_distance": {
            "metric": "euclidean",
            "available_classes": nearest["available_classes"],
            "unavailable_classes": nearest["unavailable_classes"],
            "mean_nearest_distance": statistics.fmean(distances),
            "maximum_nearest_distance": max(distances),
            "mean_distance_margin": statistics.fmean(margins) if margins else None,
        },
    }


def _weighted_training_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    total_examples = sum(int(record["num_examples"]) for record in records)
    if total_examples <= 0:
        raise ValueError("PROTEAN aggregation requires positive training support")
    return {
        key: math.fsum(
            float(record["training"][key]) * int(record["num_examples"])
            for record in records
        )
        / total_examples
        for key in TRAINING_LOSS_KEYS
    }


def _candidate_value(
    requested: float, configured_values: list[Any]
) -> float:
    for configured in configured_values:
        candidate = float(configured)
        if math.isclose(requested, candidate, rel_tol=0.0, abs_tol=1e-12):
            return candidate
    raise ValueError(
        "prototype alignment weight must be one of the validation candidates: "
        f"{[float(value) for value in configured_values]}"
    )


def _selected_client_validation(
    *,
    model: Any,
    global_prototypes: dict[str, list[float]],
    clients: list[tuple[dict[str, Any], dict[str, Any]]],
    class_names: list[str],
    batch_size: int,
    dependency_values: tuple[Any, ...],
) -> list[dict[str, Any]]:
    return [
        {
            "client_id": str(record["client_id"]),
            "client_snapshot_sha256": str(record["dataset_sha256"]),
            "training_class_support": record["train_class_counts"],
            "validation": {
                "classification_head": _evaluate(
                    model=model,
                    rows=snapshot["rows"]["validation"],
                    class_names=class_names,
                    batch_size=batch_size,
                    dependency_values=dependency_values,
                ),
                "nearest_global_prototype": _evaluate_prototype_rows(
                    model=model,
                    rows=snapshot["rows"]["validation"],
                    class_names=class_names,
                    global_prototypes=global_prototypes,
                    batch_size=batch_size,
                    dependency_values=dependency_values,
                ),
            },
        }
        for record, snapshot in clients
    ]


def run_protean_candidate(
    *,
    partition_workspace: Path,
    dataset_workspace: Path,
    output: Path,
    config_path: Path,
    prototype_alignment_weight: float,
    device_override: str | None = None,
) -> dict[str, Any]:
    partition_result = verify_partitions(
        workspace=partition_workspace, dataset_workspace=dataset_workspace
    )
    if partition_result["status"] != "verified":
        raise ValueError(
            f"M3 partition verification failed: {partition_result['errors']}"
        )
    config, config_digest = load_yaml(config_path)
    training = config["training"]
    model_config = config["model"]
    protean_config = config["protean"]
    if str(config.get("method")) != "auditable-protean-adaptation":
        raise ValueError("PROTEAN runner requires the auditable adaptation config")
    if training.get("checkpoint_selection") != PROTEAN_CANDIDATE_SELECTION_POLICY:
        raise ValueError("invalid validation-only PROTEAN checkpoint policy")
    selection_config = protean_config["objective"][
        "prototype_alignment_weight_selection"
    ]
    alignment_weight = _candidate_value(
        prototype_alignment_weight, selection_config["candidates"]
    )
    proximal_weight = float(protean_config["objective"]["proximal_weight"])
    if not math.isclose(proximal_weight, 0.1, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError("the PROTEAN paper proximal weight must remain mu=0.1")
    minimum_support = int(protean_config["minimum_local_support"])
    class_quorum = int(protean_config["class_quorum"])
    prototype_aggregation = str(protean_config["baseline_aggregation"])

    dependency_values = dependencies()
    np, torch, flwr, sklearn, aggregate, *_metric_functions = dependency_values
    configured_device = str(training["device"])
    device_name = device_override or configured_device
    if device_name not in {"cpu", "cuda"}:
        raise ValueError("PROTEAN device must be cpu or cuda")
    if device_name == "cuda" and not torch.cuda.is_available():
        raise ValueError("CUDA was requested but is not available")

    partition_manifest = json.loads(
        (partition_workspace / "manifest.json").read_text(encoding="utf-8")
    )
    if partition_manifest.get("dataset") != DATASET_NAME:
        raise ValueError("PROTEAN accepts only UWF-ZeekData24 partitions")
    if partition_manifest.get("partition_mode") != "non-iid":
        raise ValueError("PROTEAN candidate training requires the frozen non-IID partition")
    client_count = int(partition_manifest["client_count"])
    if client_count != int(training["minimum_fit_clients"]):
        raise ValueError("PROTEAN requires full participation from every configured client")
    if float(training["participation_fraction"]) != 1.0:
        raise ValueError("PROTEAN candidate participation must be 1.0")
    if class_quorum > client_count:
        raise ValueError("prototype class quorum exceeds the client count")

    class_names = [str(value) for value in partition_manifest["class_names"]]
    feature_names = [str(value) for value in partition_manifest["feature_names"]]
    class_weights = {
        str(key): float(value)
        for key, value in partition_manifest["global_class_weights"].items()
    }
    seed = int(training["seed"])
    rounds = int(training["rounds"])
    local_epochs = int(training["local_epochs"])
    batch_size = int(training["batch_size"])
    learning_rate = float(training["learning_rate"])
    hidden_layers = [int(value) for value in model_config["hidden_layers"]]
    embedding_size = int(model_config["embedding_size"])
    dropout = float(model_config["dropout"])
    architecture = architecture_record(
        input_features=len(feature_names),
        class_count=len(class_names),
        hidden_layers=hidden_layers,
        embedding_size=embedding_size,
        dropout=dropout,
    )

    def new_model(model_seed: int) -> Any:
        seed_everything(model_seed, torch=torch, np=np)
        return build_model(
            input_features=len(feature_names),
            class_count=len(class_names),
            hidden_layers=hidden_layers,
            embedding_size=embedding_size,
            dropout=dropout,
            torch=torch,
        )

    clients = _load_client_snapshots(partition_workspace, partition_manifest)
    server_evaluation = json.loads(
        (partition_workspace / partition_manifest["server_evaluation_path"]).read_text(
            encoding="utf-8"
        )
    )
    validation_rows = server_evaluation["rows"]["validation"]
    global_model = new_model(seed)
    initial_export = export_state(
        global_model, architecture=architecture, class_names=class_names
    )
    initial_model_path, initial_model_digest = _store_object(
        output, "models", initial_export
    )
    previous_model_digest = initial_model_digest
    previous_prototype_digest = "0" * 64
    previous_prototype_values: dict[str, list[float]] = {}
    previous_round_hash = "0" * 64
    round_index: list[dict[str, Any]] = []
    metrics_history: list[dict[str, Any]] = []

    for round_number in range(1, rounds + 1):
        base_arrays = model_to_ndarrays(global_model, np=np)
        update_inputs: list[tuple[list[Any], int]] = []
        update_refs: list[dict[str, Any]] = []
        update_records: list[dict[str, Any]] = []
        prototype_submissions: list[dict[str, Any]] = []
        upload_model_bytes = 0
        upload_prototype_bytes = 0
        for record, snapshot in clients:
            client_id = str(record["client_id"])
            local_model = new_model(seed)
            load_ndarrays(local_model, base_arrays, torch=torch, np=np)
            local_seed = seed + round_number * 10_000 + int(record["partition_id"])
            training_metrics = train_local_protean(
                model=local_model,
                rows=snapshot["rows"]["train"],
                class_names=class_names,
                class_weights=class_weights,
                global_prototypes=(
                    previous_prototype_values if round_number > 1 else None
                ),
                prototype_alignment_weight=alignment_weight,
                proximal_weight=proximal_weight,
                minimum_local_support=minimum_support,
                epochs=local_epochs,
                batch_size=batch_size,
                learning_rate=learning_rate,
                seed=local_seed,
                device_name=device_name,
                torch=torch,
                np=np,
            )
            local_arrays = model_to_ndarrays(local_model, np=np)
            model_object = export_state(
                local_model, architecture=architecture, class_names=class_names
            )
            model_object.update(
                {
                    "artifact_type": "protean_local_model_update",
                    "client_id": client_id,
                    "round": round_number,
                    "base_global_model_sha256": previous_model_digest,
                    "base_global_prototypes_sha256": previous_prototype_digest,
                    "client_snapshot_sha256": record["dataset_sha256"],
                    "num_examples": training_metrics["num_examples"],
                    "prototype_alignment_weight": alignment_weight,
                    "proximal_weight": proximal_weight,
                }
            )
            model_path, model_digest = _store_object(
                output, "protean-model-updates", model_object
            )
            prototype_object = extract_local_prototypes(
                model=local_model,
                rows=snapshot["rows"]["train"],
                class_names=class_names,
                minimum_local_support=minimum_support,
                batch_size=batch_size,
                device_name="cpu",
                torch=torch,
                np=np,
            )
            prototype_object.update(
                {
                    "client_id": client_id,
                    "round": round_number,
                    "client_snapshot_sha256": record["dataset_sha256"],
                    "base_global_model_sha256": previous_model_digest,
                    "base_global_prototypes_sha256": previous_prototype_digest,
                    "source_local_model_sha256": model_digest,
                }
            )
            prototype_path, prototype_digest = _store_object(
                output, "local-prototypes", prototype_object
            )
            update_record = {
                "schema_version": "1.0",
                "artifact_type": "protean_local_update_record",
                "round": round_number,
                "client_id": client_id,
                "base_global_model_sha256": previous_model_digest,
                "base_global_prototypes_sha256": previous_prototype_digest,
                "client_snapshot_sha256": record["dataset_sha256"],
                "model_object_path": model_path,
                "model_object_sha256": model_digest,
                "prototype_object_path": prototype_path,
                "prototype_object_sha256": prototype_digest,
                "num_examples": training_metrics["num_examples"],
                "training": training_metrics,
            }
            update_bytes = derived_json_bytes(update_record)
            update_relative = (
                Path("updates") / f"round-{round_number:03d}" / f"{client_id}.json"
            )
            write_once(output / update_relative, update_bytes)
            update_refs.append(
                {
                    "client_id": client_id,
                    "record_path": update_relative.as_posix(),
                    "record_sha256": sha256_bytes(update_bytes),
                    "model_object_path": model_path,
                    "model_object_sha256": model_digest,
                    "prototype_object_path": prototype_path,
                    "prototype_object_sha256": prototype_digest,
                    "num_examples": training_metrics["num_examples"],
                }
            )
            update_records.append(update_record)
            update_inputs.append((local_arrays, training_metrics["num_examples"]))
            prototype_submissions.append(
                {"client_id": client_id, "prototypes": prototype_object["prototypes"]}
            )
            upload_model_bytes += (output / model_path).stat().st_size
            upload_prototype_bytes += (output / prototype_path).stat().st_size

        aggregated_arrays = fedavg(update_inputs, aggregate=aggregate)
        load_ndarrays(global_model, aggregated_arrays, torch=torch, np=np)
        global_model_export = export_state(
            global_model, architecture=architecture, class_names=class_names
        )
        global_model_path, global_model_digest = _store_object(
            output, "models", global_model_export
        )
        global_prototype_object = aggregate_global_prototypes(
            submissions=prototype_submissions,
            class_names=class_names,
            minimum_local_support=minimum_support,
            class_quorum=class_quorum,
            method=prototype_aggregation,
            previous_global_prototypes=previous_prototype_values,
            np=np,
        )
        global_prototype_object.update(
            {
                "round": round_number,
                "base_global_model_sha256": previous_model_digest,
                "previous_global_prototypes_sha256": previous_prototype_digest,
                "aggregated_global_model_sha256": global_model_digest,
                "source_local_prototype_sha256": {
                    item["client_id"]: item["prototype_object_sha256"]
                    for item in update_refs
                },
            }
        )
        global_prototype_path, global_prototype_digest = _store_object(
            output, "global-prototypes", global_prototype_object
        )
        current_prototype_values = available_prototype_values(global_prototype_object)
        global_validation = {
            "classification_head": _evaluate(
                model=global_model,
                rows=validation_rows,
                class_names=class_names,
                batch_size=batch_size,
                dependency_values=dependency_values,
            ),
            "nearest_global_prototype": _evaluate_prototype_rows(
                model=global_model,
                rows=validation_rows,
                class_names=class_names,
                global_prototypes=current_prototype_values,
                batch_size=batch_size,
                dependency_values=dependency_values,
            ),
        }
        weighted_training = _weighted_training_summary(update_records)
        model_broadcast_bytes = (output / global_model_path).stat().st_size * client_count
        prototype_broadcast_bytes = (
            output / global_prototype_path
        ).stat().st_size * client_count
        round_record = {
            "schema_version": "1.0",
            "artifact_type": "protean_federated_round_record",
            "round": round_number,
            "previous_round_sha256": previous_round_hash,
            "base_global_model_sha256": previous_model_digest,
            "base_global_prototypes_sha256": previous_prototype_digest,
            "selected_clients": [str(record["client_id"]) for record, _ in clients],
            "participation": {
                "available": client_count,
                "selected": client_count,
                "successful": len(update_refs),
                "failed": 0,
            },
            "model_aggregation": {
                "strategy": "FedAvg",
                "weighted_by": "num_examples",
                "total_examples": sum(item["num_examples"] for item in update_refs),
            },
            "prototype_aggregation": {
                "strategy": prototype_aggregation,
                "minimum_local_support": minimum_support,
                "class_quorum": class_quorum,
            },
            "updates": update_refs,
            "aggregated_global_model_path": global_model_path,
            "aggregated_global_model_sha256": global_model_digest,
            "aggregated_global_prototypes_path": global_prototype_path,
            "aggregated_global_prototypes_sha256": global_prototype_digest,
            "weighted_training": weighted_training,
            "global_validation": global_validation,
            "communication": {
                "client_upload_model_bytes": upload_model_bytes,
                "client_upload_prototype_bytes": upload_prototype_bytes,
                "server_broadcast_model_bytes": model_broadcast_bytes,
                "server_broadcast_prototype_bytes": prototype_broadcast_bytes,
                "total_bytes": (
                    upload_model_bytes
                    + upload_prototype_bytes
                    + model_broadcast_bytes
                    + prototype_broadcast_bytes
                ),
            },
        }
        round_bytes = derived_json_bytes(round_record)
        round_hash = sha256_bytes(round_bytes)
        round_relative = Path("rounds") / f"{round_number:06d}-{round_hash}.json"
        write_once(output / round_relative, round_bytes)
        round_index.append(
            {
                "round": round_number,
                "path": round_relative.as_posix(),
                "sha256": round_hash,
                "base_global_model_sha256": previous_model_digest,
                "base_global_prototypes_sha256": previous_prototype_digest,
                "aggregated_global_model_sha256": global_model_digest,
                "aggregated_global_prototypes_sha256": global_prototype_digest,
            }
        )
        metrics_history.append(
            {
                "round": round_number,
                "global_model_sha256": global_model_digest,
                "global_prototypes_sha256": global_prototype_digest,
                "weighted_training": weighted_training,
                "validation": global_validation,
                "communication": round_record["communication"],
            }
        )
        previous_round_hash = round_hash
        previous_model_digest = global_model_digest
        previous_prototype_digest = global_prototype_digest
        previous_prototype_values = current_prototype_values

    selected_metric = _select_candidate_checkpoint(metrics_history)
    selected_round = int(selected_metric["round"])
    selected_index = round_index[selected_round - 1]
    selected_round_record = json.loads(
        (output / selected_index["path"]).read_text(encoding="utf-8")
    )
    selected_model_path = str(selected_round_record["aggregated_global_model_path"])
    selected_prototype_path = str(
        selected_round_record["aggregated_global_prototypes_path"]
    )
    selected_model_export = json.loads(
        (output / selected_model_path).read_text(encoding="utf-8")
    )
    selected_model, selected_classes = _model_from_export(
        selected_model_export, torch=torch, np=np
    )
    if selected_classes != class_names:
        raise ValueError("selected PROTEAN model class order mismatch")
    selected_prototype_object = json.loads(
        (output / selected_prototype_path).read_text(encoding="utf-8")
    )
    selected_prototype_values = available_prototype_values(selected_prototype_object)
    selected = {
        "round": selected_round,
        "round_record_path": selected_index["path"],
        "round_record_sha256": selected_index["sha256"],
        "model_path": selected_model_path,
        "model_sha256": selected_index["aggregated_global_model_sha256"],
        "global_prototypes_path": selected_prototype_path,
        "global_prototypes_sha256": selected_index[
            "aggregated_global_prototypes_sha256"
        ],
        "selection": {
            **PROTEAN_CANDIDATE_SELECTION_POLICY,
            "value": selected_metric["validation"]["nearest_global_prototype"][
                SELECTION_METRIC
            ],
        },
        "validation": selected_metric["validation"],
    }
    selected_clients = {
        "schema_version": "1.0",
        "artifact_type": "protean_selected_client_validation",
        "selected_round": selected_round,
        "selected_model_sha256": selected["model_sha256"],
        "selected_global_prototypes_sha256": selected[
            "global_prototypes_sha256"
        ],
        "clients": _selected_client_validation(
            model=selected_model,
            global_prototypes=selected_prototype_values,
            clients=clients,
            class_names=class_names,
            batch_size=batch_size,
            dependency_values=dependency_values,
        ),
    }
    selected_clients_bytes = derived_json_bytes(selected_clients)
    write_once(output / "selected_client_validation.json", selected_clients_bytes)

    metrics = {
        "schema_version": "1.0",
        "artifact_type": "protean_candidate_validation_metrics",
        "dataset": DATASET_NAME,
        "partition_mode": "non-iid",
        "prototype_alignment_weight": alignment_weight,
        "rounds": metrics_history,
        "selected": selected,
        "test_data_accessed": False,
        "interpretation_constraints": [
            "This workspace represents one lambda candidate, not a selected result.",
            "Only validation rows are evaluated in this candidate workspace.",
            "Test and temporal holdout remain withheld until cross-candidate selection.",
            "This is an auditable adaptation of PROTEAN, not an exact paper reproduction.",
        ],
    }
    if _contains_forbidden_evaluation_split(metrics):
        raise ValueError("candidate metrics crossed the test-data selection barrier")
    metrics_bytes = derived_json_bytes(metrics)
    index_bytes = derived_json_bytes(
        {
            "schema_version": "1.0",
            "artifact_type": "protean_round_index",
            "rounds": round_index,
            "final_round_sha256": previous_round_hash,
        }
    )
    write_once(output / "metrics.json", metrics_bytes)
    write_once(output / "round_index.json", index_bytes)
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "protean_candidate_run_manifest",
        "dataset": DATASET_NAME,
        "code_version": __version__,
        "method": "auditable-protean-adaptation",
        "paper_reference": config["paper_reference"],
        "partition_mode": "non-iid",
        "partition_manifest_sha256": sha256_file(partition_workspace / "manifest.json"),
        "dataset_manifest_sha256": sha256_file(dataset_workspace / "manifest.json"),
        "protean_config_sha256": config_digest,
        "implementation_files": {
            "protean_training.py": sha256_file(Path(__file__)),
            "protean.py": sha256_file(Path(__file__).with_name("protean.py")),
            "federated_model.py": sha256_file(
                Path(__file__).with_name("federated_model.py")
            ),
        },
        "framework": {
            "flower_version": flwr.__version__,
            "torch_version": torch.__version__,
            "numpy_version": np.__version__,
            "sklearn_version": sklearn.__version__,
        },
        "training": {
            "strategy": "PROTEAN-model-and-prototype-aggregation",
            "rounds": rounds,
            "local_epochs": local_epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "optimizer": str(training["optimizer"]),
            "client_count": client_count,
            "participation_fraction": 1.0,
            "seed": seed,
            "configured_device": configured_device,
            "device": device_name,
            "device_override": device_override,
            "prototype_alignment_weight": alignment_weight,
            "proximal_weight": proximal_weight,
            "minimum_local_support": minimum_support,
            "class_quorum": class_quorum,
            "prototype_aggregation": prototype_aggregation,
        },
        "initial_model_path": initial_model_path,
        "initial_model_sha256": initial_model_digest,
        "initial_global_prototypes_sha256": "0" * 64,
        "final_model_sha256": previous_model_digest,
        "final_global_prototypes_sha256": previous_prototype_digest,
        "final_round_sha256": previous_round_hash,
        "selected_round": selected_round,
        "selected_round_sha256": selected_index["sha256"],
        "selected_model_sha256": selected["model_sha256"],
        "selected_global_prototypes_sha256": selected[
            "global_prototypes_sha256"
        ],
        "selection_policy": PROTEAN_CANDIDATE_SELECTION_POLICY,
        "test_data_accessed": False,
        "metrics_sha256": sha256_bytes(metrics_bytes),
        "round_index_sha256": sha256_bytes(index_bytes),
        "selected_client_validation_sha256": sha256_bytes(selected_clients_bytes),
    }
    write_once(output / "manifest.json", derived_json_bytes(manifest))
    return {
        "status": "trained_validation_only",
        "workspace": str(output),
        "partition_mode": "non-iid",
        "client_count": client_count,
        "rounds": rounds,
        "prototype_alignment_weight": alignment_weight,
        "selected_round": selected_round,
        "best_validation_prototype_macro_f1": selected["selection"]["value"],
        "selected_round_head_macro_f1": selected["validation"][
            "classification_head"
        ][SELECTION_METRIC],
        "test_data_accessed": False,
        "final_round_sha256": previous_round_hash,
    }


def verify_protean_candidate(
    *,
    workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = workspace / "manifest.json"
    if not manifest_path.is_file():
        return {
            "status": "failed",
            "workspace": str(workspace),
            "error_count": 1,
            "errors": ["missing PROTEAN candidate manifest.json"],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _config, config_digest = load_yaml(config_path)
    partition_result = verify_partitions(
        workspace=partition_workspace, dataset_workspace=dataset_workspace
    )
    if partition_result["status"] != "verified":
        errors.append("referenced non-IID partition workspace does not verify")
    if sha256_file(partition_workspace / "manifest.json") != manifest.get(
        "partition_manifest_sha256"
    ):
        errors.append("partition manifest digest mismatch")
    if sha256_file(dataset_workspace / "manifest.json") != manifest.get(
        "dataset_manifest_sha256"
    ):
        errors.append("dataset manifest digest mismatch")
    if config_digest != manifest.get("protean_config_sha256"):
        errors.append("PROTEAN configuration digest mismatch")
    if manifest.get("selection_policy") != PROTEAN_CANDIDATE_SELECTION_POLICY:
        errors.append("PROTEAN validation-only selection policy mismatch")
    if manifest.get("test_data_accessed") is not False:
        errors.append("manifest does not prove the test-data barrier")

    metrics_path = workspace / "metrics.json"
    index_path = workspace / "round_index.json"
    clients_path = workspace / "selected_client_validation.json"
    for path, field in (
        (metrics_path, "metrics_sha256"),
        (index_path, "round_index_sha256"),
        (clients_path, "selected_client_validation_sha256"),
    ):
        if not path.is_file() or sha256_file(path) != manifest.get(field):
            errors.append(f"artifact digest mismatch: {path.name}")
    if errors:
        return {
            "status": "failed",
            "workspace": str(workspace),
            "error_count": len(errors),
            "errors": errors,
        }

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    index = json.loads(index_path.read_text(encoding="utf-8"))
    selected_clients = json.loads(clients_path.read_text(encoding="utf-8"))
    if _contains_forbidden_evaluation_split(metrics) or _contains_forbidden_evaluation_split(
        selected_clients
    ):
        errors.append("candidate artifacts expose a forbidden evaluation split")
    if metrics.get("test_data_accessed") is not False:
        errors.append("metrics do not preserve the test-data barrier")

    dependency_values = dependencies()
    np, torch, _flwr, _sklearn, aggregate, *_functions = dependency_values
    partition_manifest = json.loads(
        (partition_workspace / "manifest.json").read_text(encoding="utf-8")
    )
    class_names = [str(value) for value in partition_manifest["class_names"]]
    clients = _load_client_snapshots(partition_workspace, partition_manifest)
    server_evaluation = json.loads(
        (partition_workspace / partition_manifest["server_evaluation_path"]).read_text(
            encoding="utf-8"
        )
    )
    validation_rows = server_evaluation["rows"]["validation"]
    training = manifest["training"]
    minimum_support = int(training["minimum_local_support"])
    class_quorum = int(training["class_quorum"])
    prototype_aggregation = str(training["prototype_aggregation"])
    batch_size = int(training["batch_size"])
    expected_rounds = int(training["rounds"])
    if len(index.get("rounds", [])) != expected_rounds:
        errors.append("round index length mismatch")
    if len(metrics.get("rounds", [])) != expected_rounds:
        errors.append("metrics history length mismatch")

    previous_round_hash = "0" * 64
    previous_model_digest = str(manifest["initial_model_sha256"])
    previous_prototype_digest = "0" * 64
    previous_prototype_values: dict[str, list[float]] = {}
    verified_records: dict[int, dict[str, Any]] = {}
    for expected_round, item in enumerate(index.get("rounds", []), start=1):
        if item.get("round") != expected_round:
            errors.append(f"round index sequence mismatch: {expected_round}")
            continue
        round_path = workspace / str(item["path"])
        if not round_path.is_file() or sha256_file(round_path) != item.get("sha256"):
            errors.append(f"round record digest mismatch: {expected_round}")
            continue
        record = json.loads(round_path.read_text(encoding="utf-8"))
        verified_records[expected_round] = record
        if record.get("previous_round_sha256") != previous_round_hash:
            errors.append(f"round hash-chain mismatch: {expected_round}")
        if record.get("base_global_model_sha256") != previous_model_digest:
            errors.append(f"round base-model mismatch: {expected_round}")
        if record.get("base_global_prototypes_sha256") != previous_prototype_digest:
            errors.append(f"round base-prototype mismatch: {expected_round}")

        updates: list[tuple[list[Any], int]] = []
        submissions: list[dict[str, Any]] = []
        update_records: list[dict[str, Any]] = []
        source_digests: dict[str, str] = {}
        for update_ref in record.get("updates", []):
            client_id = str(update_ref["client_id"])
            update_path = workspace / str(update_ref["record_path"])
            model_path = workspace / str(update_ref["model_object_path"])
            prototype_path = workspace / str(update_ref["prototype_object_path"])
            digest_checks = (
                (update_path, update_ref["record_sha256"]),
                (model_path, update_ref["model_object_sha256"]),
                (prototype_path, update_ref["prototype_object_sha256"]),
            )
            if any(
                not path.is_file() or sha256_file(path) != digest
                for path, digest in digest_checks
            ):
                errors.append(
                    f"local update artifact mismatch: round {expected_round} {client_id}"
                )
                continue
            update_record = json.loads(update_path.read_text(encoding="utf-8"))
            model_object = json.loads(model_path.read_text(encoding="utf-8"))
            prototype_object = json.loads(prototype_path.read_text(encoding="utf-8"))
            lineage_values = (
                update_record.get("base_global_model_sha256"),
                model_object.get("base_global_model_sha256"),
                prototype_object.get("base_global_model_sha256"),
            )
            if any(value != previous_model_digest for value in lineage_values):
                errors.append(
                    f"local model lineage mismatch: round {expected_round} {client_id}"
                )
            prototype_lineage = (
                update_record.get("base_global_prototypes_sha256"),
                model_object.get("base_global_prototypes_sha256"),
                prototype_object.get("base_global_prototypes_sha256"),
            )
            if any(value != previous_prototype_digest for value in prototype_lineage):
                errors.append(
                    f"local prototype lineage mismatch: round {expected_round} {client_id}"
                )
            if prototype_object.get("source_local_model_sha256") != update_ref.get(
                "model_object_sha256"
            ):
                errors.append(
                    f"prototype/model binding mismatch: round {expected_round} {client_id}"
                )
            updates.append(
                (
                    arrays_from_export(model_object, np=np),
                    int(update_ref["num_examples"]),
                )
            )
            submissions.append(
                {"client_id": client_id, "prototypes": prototype_object["prototypes"]}
            )
            update_records.append(update_record)
            source_digests[client_id] = str(update_ref["prototype_object_sha256"])

        if len(updates) != int(training["client_count"]):
            errors.append(f"successful update count mismatch: {expected_round}")
            continue
        recomputed_arrays = fedavg(updates, aggregate=aggregate)
        global_model_path = workspace / str(record["aggregated_global_model_path"])
        if not global_model_path.is_file() or sha256_file(global_model_path) != record.get(
            "aggregated_global_model_sha256"
        ):
            errors.append(f"global model object mismatch: {expected_round}")
            continue
        global_model_export = json.loads(global_model_path.read_text(encoding="utf-8"))
        stored_arrays = arrays_from_export(global_model_export, np=np)
        if len(stored_arrays) != len(recomputed_arrays) or any(
            not np.array_equal(left, right)
            for left, right in zip(stored_arrays, recomputed_arrays, strict=True)
        ):
            errors.append(f"FedAvg recomputation mismatch: {expected_round}")

        global_prototype_path = workspace / str(
            record["aggregated_global_prototypes_path"]
        )
        if not global_prototype_path.is_file() or sha256_file(
            global_prototype_path
        ) != record.get("aggregated_global_prototypes_sha256"):
            errors.append(f"global prototype object mismatch: {expected_round}")
            continue
        stored_prototypes = json.loads(
            global_prototype_path.read_text(encoding="utf-8")
        )
        recomputed_prototypes = aggregate_global_prototypes(
            submissions=submissions,
            class_names=class_names,
            minimum_local_support=minimum_support,
            class_quorum=class_quorum,
            method=prototype_aggregation,
            previous_global_prototypes=previous_prototype_values,
            np=np,
        )
        recomputed_prototypes.update(
            {
                "round": expected_round,
                "base_global_model_sha256": previous_model_digest,
                "previous_global_prototypes_sha256": previous_prototype_digest,
                "aggregated_global_model_sha256": record[
                    "aggregated_global_model_sha256"
                ],
                "source_local_prototype_sha256": source_digests,
            }
        )
        if not _same_json(stored_prototypes, recomputed_prototypes):
            errors.append(f"prototype aggregation mismatch: {expected_round}")
        expected_weighted = _weighted_training_summary(update_records)
        if not _same_json(record.get("weighted_training"), expected_weighted):
            errors.append(f"weighted training metrics mismatch: {expected_round}")

        checkpoint_model, checkpoint_classes = _model_from_export(
            global_model_export, torch=torch, np=np
        )
        if checkpoint_classes != class_names:
            errors.append(f"checkpoint class order mismatch: {expected_round}")
        prototype_values = available_prototype_values(stored_prototypes)
        recomputed_validation = {
            "classification_head": _evaluate(
                model=checkpoint_model,
                rows=validation_rows,
                class_names=class_names,
                batch_size=batch_size,
                dependency_values=dependency_values,
            ),
            "nearest_global_prototype": _evaluate_prototype_rows(
                model=checkpoint_model,
                rows=validation_rows,
                class_names=class_names,
                global_prototypes=prototype_values,
                batch_size=batch_size,
                dependency_values=dependency_values,
            ),
        }
        if not _same_json(record.get("global_validation"), recomputed_validation):
            errors.append(f"validation inference mismatch: {expected_round}")
        metric_record = metrics.get("rounds", [])[expected_round - 1]
        metric_expectation = {
            "round": expected_round,
            "global_model_sha256": record["aggregated_global_model_sha256"],
            "global_prototypes_sha256": record[
                "aggregated_global_prototypes_sha256"
            ],
            "weighted_training": record["weighted_training"],
            "validation": record["global_validation"],
            "communication": record["communication"],
        }
        if not _same_json(metric_record, metric_expectation):
            errors.append(f"round metrics mismatch: {expected_round}")
        previous_round_hash = str(item["sha256"])
        previous_model_digest = str(record["aggregated_global_model_sha256"])
        previous_prototype_digest = str(
            record["aggregated_global_prototypes_sha256"]
        )
        previous_prototype_values = prototype_values

    if previous_round_hash != manifest.get("final_round_sha256"):
        errors.append("final round hash mismatch")
    if previous_model_digest != manifest.get("final_model_sha256"):
        errors.append("final model digest mismatch")
    if previous_prototype_digest != manifest.get("final_global_prototypes_sha256"):
        errors.append("final global prototype digest mismatch")

    if metrics.get("rounds"):
        expected_selection = _select_candidate_checkpoint(metrics["rounds"])
        selected_round = int(expected_selection["round"])
        selected = metrics.get("selected", {})
        selected_record = verified_records.get(selected_round, {})
        expectations = {
            "selected round": (selected.get("round"), selected_round),
            "manifest selected round": (manifest.get("selected_round"), selected_round),
            "selected model": (
                selected.get("model_sha256"),
                selected_record.get("aggregated_global_model_sha256"),
            ),
            "selected prototypes": (
                selected.get("global_prototypes_sha256"),
                selected_record.get("aggregated_global_prototypes_sha256"),
            ),
            "selected validation": (
                selected.get("validation"),
                expected_selection.get("validation"),
            ),
        }
        for description, (actual, expected) in expectations.items():
            if not _same_json(actual, expected):
                errors.append(f"{description} mismatch")

        selected_model_path = workspace / str(selected.get("model_path"))
        selected_prototype_path = workspace / str(
            selected.get("global_prototypes_path")
        )
        if selected_model_path.is_file() and selected_prototype_path.is_file():
            selected_model, selected_class_names = _model_from_export(
                json.loads(selected_model_path.read_text(encoding="utf-8")),
                torch=torch,
                np=np,
            )
            selected_prototype_object = json.loads(
                selected_prototype_path.read_text(encoding="utf-8")
            )
            recomputed_clients = {
                "schema_version": "1.0",
                "artifact_type": "protean_selected_client_validation",
                "selected_round": selected_round,
                "selected_model_sha256": selected.get("model_sha256"),
                "selected_global_prototypes_sha256": selected.get(
                    "global_prototypes_sha256"
                ),
                "clients": _selected_client_validation(
                    model=selected_model,
                    global_prototypes=available_prototype_values(
                        selected_prototype_object
                    ),
                    clients=clients,
                    class_names=selected_class_names,
                    batch_size=batch_size,
                    dependency_values=dependency_values,
                ),
            }
            if not _same_json(selected_clients, recomputed_clients):
                errors.append("selected per-client validation mismatch")
        else:
            errors.append("selected model or prototype object is missing")

    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "prototype_alignment_weight": manifest["training"][
            "prototype_alignment_weight"
        ],
        "rounds": expected_rounds,
        "test_data_accessed": False,
        "final_round_sha256": manifest.get("final_round_sha256"),
        "error_count": len(errors),
        "errors": errors,
    }
