"""Auditable deterministic FedAvg runner for the M3 federated baseline."""

from __future__ import annotations

import json
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
    delta_l2,
    dependencies,
    evaluate_rows,
    export_state,
    fedavg,
    load_ndarrays,
    model_to_ndarrays,
    seed_everything,
    train_local,
)
from .federated_partitioning import verify_partitions
from .preprocessing import derived_json_bytes
from .storage import write_once


def _object_path(category: str, digest: str) -> Path:
    return Path("objects") / category / "sha256" / digest[:2] / f"{digest[2:]}.json"


def _store_object(output: Path, category: str, value: dict[str, Any]) -> tuple[str, str]:
    content = derived_json_bytes(value)
    digest = sha256_bytes(content)
    relative = _object_path(category, digest)
    write_once(output / relative, content)
    return relative.as_posix(), digest


def _load_client_snapshots(
    partition_workspace: Path, partition_manifest: dict[str, Any]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    snapshots = []
    for record in partition_manifest["clients"]:
        dataset = json.loads(
            (partition_workspace / record["dataset_path"]).read_text(encoding="utf-8")
        )
        snapshots.append((record, dataset))
    return snapshots


def _load_client_local_tests(
    partition_workspace: Path, partition_manifest: dict[str, Any]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Load evaluation-only client tests after checkpoint selection."""

    snapshots = []
    for record in partition_manifest["clients"]:
        relative = record.get("local_test_path")
        if not relative:
            raise ValueError("partition does not provide evaluation-only local tests")
        relative_path = Path(str(relative))
        expected_prefix = f"evaluation/clients/{record['client_id']}/"
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or not relative_path.as_posix().startswith(expected_prefix)
        ):
            raise ValueError(f"local test path escapes evaluation boundary: {relative}")
        snapshot = json.loads((partition_workspace / relative_path).read_text(encoding="utf-8"))
        snapshots.append((record, snapshot))
    return snapshots


def _load_server_split(
    partition_workspace: Path,
    partition_manifest: dict[str, Any],
    split: str,
) -> list[dict[str, Any]]:
    records = partition_manifest.get("server_evaluation_splits")
    if not isinstance(records, dict) or split not in records:
        raise ValueError("partition does not provide isolated server evaluation splits")
    relative = Path(str(records[split].get("path", "")))
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not relative.as_posix().startswith("server/splits/")
    ):
        raise ValueError(f"server {split} path escapes split boundary")
    snapshot = json.loads((partition_workspace / relative).read_text(encoding="utf-8"))
    if snapshot.get("split") != split or set(snapshot.get("rows", {})) != {split}:
        raise ValueError(f"server {split} isolated artifact has the wrong identity")
    return list(snapshot["rows"][split])


def _evaluate(
    *,
    model: Any,
    rows: list[dict[str, Any]],
    class_names: list[str],
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
    return evaluate_rows(
        model=model,
        rows=rows,
        class_names=class_names,
        batch_size=batch_size,
        torch=torch,
        np=np,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )


def _mean_metric(items: list[dict[str, Any]], key: str) -> dict[str, Any]:
    values = [float(item[key]) for item in items if item.get(key) is not None]
    return {
        "client_count": len(values),
        "mean": statistics.fmean(values) if values else None,
        "population_stddev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "minimum": min(values) if values else None,
        "maximum": max(values) if values else None,
    }


SELECTION_METRIC = "macro_f1_all_model_classes"
SELECTION_POLICY = {
    "split": "validation",
    "metric": SELECTION_METRIC,
    "mode": "maximize",
    "tie_breaker": "earliest_round",
    "test_policy": "selected-checkpoint-only",
}


def _select_validation_checkpoint(
    metrics_history: list[dict[str, Any]],
) -> dict[str, Any]:
    """Select the earliest round with the highest validation macro-F1."""

    if not metrics_history:
        raise ValueError("cannot select a checkpoint without round metrics")
    return max(
        metrics_history,
        key=lambda item: (
            float(item["validation"][SELECTION_METRIC]),
            -int(item["round"]),
        ),
    )


def _benign_false_alarm_summary(
    evaluation: dict[str, Any], *, benign_label: str = "benign"
) -> dict[str, Any]:
    """Summarize attack alerts raised for rows whose actual class is benign."""

    matrix = evaluation["confusion_matrix"]
    labels = [str(value) for value in matrix["labels"]]
    if benign_label not in labels:
        raise ValueError(f"evaluation does not contain the benign class: {benign_label}")
    benign_index = labels.index(benign_label)
    benign_row = [int(value) for value in matrix["values"][benign_index]]
    benign_count = sum(benign_row)
    false_alarm_count = benign_count - benign_row[benign_index]
    return {
        "actual_benign_count": benign_count,
        "false_alarm_count": false_alarm_count,
        "false_alarm_rate": (false_alarm_count / benign_count if benign_count else None),
        "definition": "actual benign rows predicted as any non-benign class",
    }


def _same_json(left: Any, right: Any) -> bool:
    return derived_json_bytes(left) == derived_json_bytes(right)


def _model_from_export(value: dict[str, Any], *, torch: Any, np: Any) -> tuple[Any, list[str]]:
    architecture = value["architecture"]
    class_names = [str(item) for item in value["class_names"]]
    model = build_model(
        input_features=int(architecture["input_features"]),
        class_count=int(architecture["classification_head_outputs"]),
        hidden_layers=[int(item) for item in architecture["encoder_hidden_layers"]],
        embedding_size=int(architecture["embedding_size"]),
        dropout=float(architecture["dropout"]),
        torch=torch,
    )
    load_ndarrays(
        model,
        arrays_from_export(value, np=np),
        torch=torch,
        np=np,
    )
    return model, class_names


def run_federated_baseline(
    *,
    partition_workspace: Path,
    dataset_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    partition_verification = verify_partitions(
        workspace=partition_workspace, dataset_workspace=dataset_workspace
    )
    if partition_verification["status"] != "verified":
        raise ValueError(
            f"M3 partition workspace verification failed: {partition_verification['errors']}"
        )
    dependency_values = dependencies()
    (
        np,
        torch,
        flwr,
        sklearn,
        aggregate,
        _accuracy_score,
        _confusion_matrix,
        _precision_recall_fscore_support,
    ) = dependency_values
    config, config_digest = load_yaml(config_path)
    training = config["training"]
    model_config = config["model"]
    partition_manifest = json.loads(
        (partition_workspace / "manifest.json").read_text(encoding="utf-8")
    )
    if partition_manifest.get("dataset") != DATASET_NAME:
        raise ValueError("M3 federation accepts only UWF-ZeekData24 partitions")
    client_count = int(partition_manifest["client_count"])
    if client_count != int(training["minimum_fit_clients"]):
        raise ValueError("M3 clean baseline requires full participation from all 15 clients")
    if float(training["participation_fraction"]) != 1.0:
        raise ValueError("M3 clean baseline participation fraction must be 1.0")
    if str(training["aggregator"]).lower() != "fedavg":
        raise ValueError("M3 baseline aggregator must be FedAvg")
    configured_selection = training.get("checkpoint_selection", SELECTION_POLICY)
    if configured_selection != SELECTION_POLICY:
        raise ValueError(
            "M3 checkpoint selection must maximize validation macro-F1, break ties "
            "by earliest round, and evaluate test only after selection"
        )

    class_names = list(partition_manifest["class_names"])
    feature_names = list(partition_manifest["feature_names"])
    class_weights = {
        key: float(value) for key, value in partition_manifest["global_class_weights"].items()
    }
    seed = int(training["seed"])
    rounds = int(training["rounds"])
    local_epochs = int(training["local_epochs"])
    batch_size = int(training["batch_size"])
    learning_rate = float(training["learning_rate"])
    device_name = str(training["device"])
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
    server_validation_rows = _load_server_split(
        partition_workspace, partition_manifest, "validation"
    )
    global_model = new_model(seed)
    initial_export = export_state(global_model, architecture=architecture, class_names=class_names)
    initial_model_path, initial_model_digest = _store_object(output, "models", initial_export)
    previous_model_digest = initial_model_digest
    previous_round_hash = "0" * 64
    round_index: list[dict[str, Any]] = []
    metrics_history: list[dict[str, Any]] = []

    for round_number in range(1, rounds + 1):
        base_arrays = model_to_ndarrays(global_model, np=np)
        update_inputs: list[tuple[list[Any], int]] = []
        update_refs: list[dict[str, Any]] = []
        weighted_loss_sum = 0.0
        weighted_examples = 0
        for record, snapshot in clients:
            client_id = record["client_id"]
            local_model = new_model(seed)
            load_ndarrays(local_model, base_arrays, torch=torch, np=np)
            local_seed = seed + round_number * 10_000 + int(record["partition_id"])
            training_metrics = train_local(
                model=local_model,
                rows=snapshot["rows"]["train"],
                class_names=class_names,
                class_weights=class_weights,
                epochs=local_epochs,
                batch_size=batch_size,
                learning_rate=learning_rate,
                seed=local_seed,
                device_name=device_name,
                torch=torch,
                np=np,
            )
            local_arrays = model_to_ndarrays(local_model, np=np)
            local_validation = _evaluate(
                model=local_model,
                rows=snapshot["rows"]["validation"],
                class_names=class_names,
                batch_size=batch_size,
                dependency_values=dependency_values,
            )
            update_object = export_state(
                local_model, architecture=architecture, class_names=class_names
            )
            update_object.update(
                {
                    "artifact_type": "m3_local_model_update",
                    "client_id": client_id,
                    "round": round_number,
                    "base_model_sha256": previous_model_digest,
                    "client_snapshot_sha256": record["dataset_sha256"],
                    "num_examples": training_metrics["num_examples"],
                }
            )
            object_path, object_digest = _store_object(output, "updates", update_object)
            update_record = {
                "schema_version": "1.0",
                "artifact_type": "m3_local_update_record",
                "round": round_number,
                "client_id": client_id,
                "base_model_sha256": previous_model_digest,
                "client_snapshot_sha256": record["dataset_sha256"],
                "update_object_path": object_path,
                "update_object_sha256": object_digest,
                "num_examples": training_metrics["num_examples"],
                "training": training_metrics,
                "local_validation": local_validation,
                "update_delta_l2": delta_l2(base_arrays, local_arrays, np=np),
            }
            update_bytes = derived_json_bytes(update_record)
            update_relative = Path("updates") / f"round-{round_number:03d}" / f"{client_id}.json"
            write_once(output / update_relative, update_bytes)
            update_refs.append(
                {
                    "client_id": client_id,
                    "record_path": update_relative.as_posix(),
                    "record_sha256": sha256_bytes(update_bytes),
                    "update_object_path": object_path,
                    "update_object_sha256": object_digest,
                    "num_examples": training_metrics["num_examples"],
                }
            )
            update_inputs.append((local_arrays, training_metrics["num_examples"]))
            weighted_loss_sum += training_metrics["train_loss"] * training_metrics["num_examples"]
            weighted_examples += training_metrics["num_examples"]

        aggregated_arrays = fedavg(update_inputs, aggregate=aggregate)
        load_ndarrays(global_model, aggregated_arrays, torch=torch, np=np)
        global_export = export_state(
            global_model, architecture=architecture, class_names=class_names
        )
        global_model_path, global_model_digest = _store_object(output, "models", global_export)
        global_metrics = {
            "validation": _evaluate(
                model=global_model,
                rows=server_validation_rows,
                class_names=class_names,
                batch_size=batch_size,
                dependency_values=dependency_values,
            )
        }
        round_record = {
            "schema_version": "1.0",
            "artifact_type": "m3_federated_round_record",
            "round": round_number,
            "previous_round_sha256": previous_round_hash,
            "base_global_model_sha256": previous_model_digest,
            "selected_clients": [record["client_id"] for record, _snapshot in clients],
            "participation": {
                "available": client_count,
                "selected": client_count,
                "successful": len(update_refs),
                "failed": 0,
            },
            "aggregation": {
                "strategy": "FedAvg",
                "implementation": "flwr.server.strategy.aggregate.aggregate",
                "weighted_by": "num_examples",
                "total_examples": weighted_examples,
            },
            "updates": update_refs,
            "aggregated_global_model_path": global_model_path,
            "aggregated_global_model_sha256": global_model_digest,
            "aggregated_delta_l2": delta_l2(base_arrays, aggregated_arrays, np=np),
            "weighted_training_loss": weighted_loss_sum / weighted_examples,
            "global_metrics": global_metrics,
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
                "aggregated_global_model_sha256": global_model_digest,
            }
        )
        metrics_history.append(
            {
                "round": round_number,
                "global_model_sha256": global_model_digest,
                "weighted_training_loss": weighted_loss_sum / weighted_examples,
                "validation": global_metrics["validation"],
            }
        )
        previous_round_hash = round_hash
        previous_model_digest = global_model_digest

    selected_round_metrics = _select_validation_checkpoint(metrics_history)
    selected_round_number = int(selected_round_metrics["round"])
    selected_round_entry = round_index[selected_round_number - 1]
    selected_model_path = str(
        json.loads((output / selected_round_entry["path"]).read_text(encoding="utf-8"))[
            "aggregated_global_model_path"
        ]
    )
    selected_model_digest = str(selected_round_entry["aggregated_global_model_sha256"])
    selected_model_export = json.loads((output / selected_model_path).read_text(encoding="utf-8"))
    selected_model, selected_class_names = _model_from_export(
        selected_model_export, torch=torch, np=np
    )
    if selected_class_names != class_names:
        raise ValueError("selected checkpoint class order does not match the partition")
    selected_validation = _evaluate(
        model=selected_model,
        rows=server_validation_rows,
        class_names=class_names,
        batch_size=batch_size,
        dependency_values=dependency_values,
    )
    selected_global_client_validation = [
        {
            "client_id": record["client_id"],
            "client_snapshot_sha256": record["dataset_sha256"],
            "validation": _evaluate(
                model=selected_model,
                rows=snapshot["rows"]["validation"],
                class_names=class_names,
                batch_size=batch_size,
                dependency_values=dependency_values,
            ),
        }
        for record, snapshot in clients
    ]
    local_baselines: list[dict[str, Any]] = []
    local_models: dict[str, Any] = {}
    if bool(training.get("run_local_baselines", True)):
        initial_arrays = arrays_from_export(initial_export, np=np)
        local_only_epochs = rounds * local_epochs
        for record, snapshot in clients:
            local_model = new_model(seed)
            load_ndarrays(local_model, initial_arrays, torch=torch, np=np)
            training_metrics = train_local(
                model=local_model,
                rows=snapshot["rows"]["train"],
                class_names=class_names,
                class_weights=class_weights,
                epochs=local_only_epochs,
                batch_size=batch_size,
                learning_rate=learning_rate,
                seed=seed + 500_000 + int(record["partition_id"]),
                device_name=device_name,
                torch=torch,
                np=np,
            )
            local_export = export_state(
                local_model, architecture=architecture, class_names=class_names
            )
            local_path, local_digest = _store_object(output, "local-models", local_export)
            local_models[record["client_id"]] = local_model
            local_baselines.append(
                {
                    "client_id": record["client_id"],
                    "client_snapshot_sha256": record["dataset_sha256"],
                    "local_test_snapshot_sha256": record["local_test_sha256"],
                    "epochs": local_only_epochs,
                    "training": training_metrics,
                    "model_path": local_path,
                    "model_sha256": local_digest,
                    "local_validation": _evaluate(
                        model=local_model,
                        rows=snapshot["rows"]["validation"],
                        class_names=class_names,
                        batch_size=batch_size,
                        dependency_values=dependency_values,
                    ),
                    "global_validation": _evaluate(
                        model=local_model,
                        rows=server_validation_rows,
                        class_names=class_names,
                        batch_size=batch_size,
                        dependency_values=dependency_values,
                    ),
                }
            )

    # Test artifacts are opened only after every FedAvg and local-only training
    # operation has completed and validation has already selected the checkpoint.
    server_test_rows = _load_server_split(partition_workspace, partition_manifest, "test")
    temporal_holdout_rows = _load_server_split(
        partition_workspace, partition_manifest, "temporal_holdout"
    )
    client_local_tests = _load_client_local_tests(partition_workspace, partition_manifest)
    selected_evaluations = {
        "validation": selected_validation,
        "test": _evaluate(
            model=selected_model,
            rows=server_test_rows,
            class_names=class_names,
            batch_size=batch_size,
            dependency_values=dependency_values,
        ),
        "temporal_holdout": _evaluate(
            model=selected_model,
            rows=temporal_holdout_rows,
            class_names=class_names,
            batch_size=batch_size,
            dependency_values=dependency_values,
        ),
    }
    selected_global_client_test = [
        {
            "client_id": record["client_id"],
            "local_test_snapshot_sha256": record["local_test_sha256"],
            "test": _evaluate(
                model=selected_model,
                rows=snapshot["rows"]["test"],
                class_names=class_names,
                batch_size=batch_size,
                dependency_values=dependency_values,
            ),
        }
        for record, snapshot in client_local_tests
    ]
    local_tests_by_client = {
        record["client_id"]: snapshot for record, snapshot in client_local_tests
    }
    for baseline in local_baselines:
        client_id = baseline["client_id"]
        local_model = local_models[client_id]
        baseline["local_test"] = _evaluate(
            model=local_model,
            rows=local_tests_by_client[client_id]["rows"]["test"],
            class_names=class_names,
            batch_size=batch_size,
            dependency_values=dependency_values,
        )
        baseline["global_test"] = _evaluate(
            model=local_model,
            rows=server_test_rows,
            class_names=class_names,
            batch_size=batch_size,
            dependency_values=dependency_values,
        )
    selected_checkpoint = {
        "round": selected_round_number,
        "round_record_path": selected_round_entry["path"],
        "round_record_sha256": selected_round_entry["sha256"],
        "model_path": selected_model_path,
        "model_sha256": selected_model_digest,
        "selection": {
            "split": "validation",
            "metric": SELECTION_METRIC,
            "mode": "maximize",
            "tie_breaker": "earliest_round",
            "value": selected_evaluations["validation"][SELECTION_METRIC],
        },
        **selected_evaluations,
        "operational_metrics": {
            "test_benign_false_alarms": _benign_false_alarm_summary(selected_evaluations["test"]),
            "temporal_holdout_benign_false_alarms": _benign_false_alarm_summary(
                selected_evaluations["temporal_holdout"]
            ),
        },
    }

    final_global_metrics = metrics_history[-1]
    local_global_validation = [item["global_validation"] for item in local_baselines]
    local_client_test = [item["local_test"] for item in local_baselines]
    local_global_test = [item["global_test"] for item in local_baselines]
    comparison = {
        "schema_version": "2.0",
        "artifact_type": "m3_local_fedavg_comparison",
        "comparison_fairness": {
            "same_initial_model": initial_model_digest,
            "same_frozen_client_snapshots": True,
            "same_total_local_epochs_per_client": rounds * local_epochs,
            "same_optimizer": str(training["optimizer"]),
            "same_learning_rate": learning_rate,
            "test_access": "after all training and validation-only checkpoint selection",
            "local_test_partition_strategy": partition_manifest["local_test_strategy"],
        },
        "fedavg_selected": selected_checkpoint,
        "selected_global_client_validation": selected_global_client_validation,
        "selected_global_client_validation_summary": {
            "macro_f1_all_model_classes": _mean_metric(
                [item["validation"] for item in selected_global_client_validation],
                SELECTION_METRIC,
            )
        },
        "selected_global_client_test": selected_global_client_test,
        "selected_global_client_test_summary": {
            "macro_f1_all_model_classes": _mean_metric(
                [item["test"] for item in selected_global_client_test],
                SELECTION_METRIC,
            )
        },
        "local_only_clients": local_baselines,
        "local_only_summary": {
            "global_validation_macro_f1": _mean_metric(
                local_global_validation, "macro_f1_all_model_classes"
            ),
            "local_test_macro_f1": _mean_metric(local_client_test, "macro_f1_all_model_classes"),
            "global_test_macro_f1": _mean_metric(local_global_test, "macro_f1_all_model_classes"),
        },
    }
    comparison_bytes = derived_json_bytes(comparison)
    metrics_artifact = {
        "schema_version": "2.0",
        "artifact_type": "m3_fedavg_metrics",
        "dataset": DATASET_NAME,
        "partition_mode": partition_manifest["partition_mode"],
        "rounds": metrics_history,
        "final": final_global_metrics,
        "selected": selected_checkpoint,
        "interpretation_constraints": [
            "The temporal holdout is benign-only and is not a multiclass test.",
            "Data24 retains its documented acquisition-time/class confound.",
            "This is a clean FedAvg baseline; Byzantine behavior and defenses are not active.",
            (
                "FedAvg checkpoint selection uses validation macro-F1 only; test and temporal "
                "holdout are evaluated only after selection; client-local tests are separate "
                "evaluation artifacts and are also opened only after selection."
            ),
        ],
    }
    metrics_bytes = derived_json_bytes(metrics_artifact)
    round_index_bytes = derived_json_bytes(
        {
            "schema_version": "1.0",
            "artifact_type": "m3_round_index",
            "rounds": round_index,
            "final_round_sha256": previous_round_hash,
        }
    )
    write_once(output / "metrics.json", metrics_bytes)
    write_once(output / "comparison.json", comparison_bytes)
    write_once(output / "round_index.json", round_index_bytes)
    run_manifest = {
        "schema_version": "2.0",
        "artifact_type": "m3_fedavg_run_manifest",
        "dataset": DATASET_NAME,
        "code_version": __version__,
        "partition_mode": partition_manifest["partition_mode"],
        "partition_manifest_sha256": sha256_file(partition_workspace / "manifest.json"),
        "dataset_manifest_sha256": sha256_file(dataset_workspace / "manifest.json"),
        "federation_config_sha256": config_digest,
        "implementation_files": {
            "federated_training.py": sha256_file(Path(__file__)),
            "federated_model.py": sha256_file(Path(__file__).with_name("federated_model.py")),
        },
        "framework": {
            "flower_version": flwr.__version__,
            "torch_version": torch.__version__,
            "numpy_version": np.__version__,
            "sklearn_version": sklearn.__version__,
        },
        "training": {
            "strategy": "FedAvg",
            "rounds": rounds,
            "local_epochs": local_epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "optimizer": str(training["optimizer"]),
            "client_count": client_count,
            "participation_fraction": 1.0,
            "seed": seed,
            "device": device_name,
        },
        "initial_model_path": initial_model_path,
        "initial_model_sha256": initial_model_digest,
        "final_model_sha256": previous_model_digest,
        "final_round_sha256": previous_round_hash,
        "selected_round": selected_round_number,
        "selected_round_sha256": selected_round_entry["sha256"],
        "selected_model_path": selected_model_path,
        "selected_model_sha256": selected_model_digest,
        "selection_policy": SELECTION_POLICY,
        "metrics_sha256": sha256_bytes(metrics_bytes),
        "comparison_sha256": sha256_bytes(comparison_bytes),
        "round_index_sha256": sha256_bytes(round_index_bytes),
    }
    write_once(output / "manifest.json", derived_json_bytes(run_manifest))
    return {
        "status": "trained",
        "dataset": DATASET_NAME,
        "partition_mode": partition_manifest["partition_mode"],
        "client_count": client_count,
        "rounds": rounds,
        "workspace": str(output),
        "final_model_sha256": previous_model_digest,
        "selected_round": selected_round_number,
        "selected_model_sha256": selected_model_digest,
        "validation_macro_f1": selected_evaluations["validation"][SELECTION_METRIC],
        "test_macro_f1": selected_evaluations["test"][SELECTION_METRIC],
        "client_unweighted_mean_test_macro_f1": comparison["selected_global_client_test_summary"][
            "macro_f1_all_model_classes"
        ]["mean"],
        "local_only_mean_test_macro_f1": comparison["local_only_summary"]["global_test_macro_f1"][
            "mean"
        ],
    }


def verify_federated_baseline(
    *,
    workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = workspace / "manifest.json"
    if not manifest_path.is_file():
        return {
            "status": "failed",
            "workspace": str(workspace),
            "error_count": 1,
            "errors": ["missing M3 federation manifest.json"],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    partition_result = verify_partitions(
        workspace=partition_workspace, dataset_workspace=dataset_workspace
    )
    if partition_result["status"] != "verified":
        errors.append("referenced M3 partition workspace does not verify")
    if sha256_file(partition_workspace / "manifest.json") != manifest.get(
        "partition_manifest_sha256"
    ):
        errors.append("referenced partition manifest digest mismatch")
    if sha256_file(dataset_workspace / "manifest.json") != manifest.get("dataset_manifest_sha256"):
        errors.append("referenced dataset manifest digest mismatch")
    direct_artifacts = {
        "metrics.json": manifest.get("metrics_sha256"),
        "comparison.json": manifest.get("comparison_sha256"),
        "round_index.json": manifest.get("round_index_sha256"),
    }
    for name, expected in direct_artifacts.items():
        path = workspace / name
        if not path.is_file() or not expected or sha256_file(path) != expected:
            errors.append(f"M3 direct artifact digest mismatch: {name}")
    if errors:
        return {
            "status": "failed",
            "dataset": manifest.get("dataset"),
            "workspace": str(workspace),
            "error_count": len(errors),
            "errors": errors,
        }

    dependency_values = dependencies()
    np, torch, _flwr, _sklearn, aggregate, *_metrics = dependency_values
    index = json.loads((workspace / "round_index.json").read_text(encoding="utf-8"))
    metrics = json.loads((workspace / "metrics.json").read_text(encoding="utf-8"))
    comparison = json.loads((workspace / "comparison.json").read_text(encoding="utf-8"))
    partition_manifest = json.loads(
        (partition_workspace / "manifest.json").read_text(encoding="utf-8")
    )
    schema_version = str(manifest.get("schema_version", "1.0"))
    previous_round_hash = "0" * 64
    previous_model_digest = manifest.get("initial_model_sha256")
    round_records: dict[int, dict[str, Any]] = {}
    for expected_round, item in enumerate(index.get("rounds", []), start=1):
        path = workspace / item["path"]
        if not path.is_file() or sha256_file(path) != item.get("sha256"):
            errors.append(f"round record digest mismatch: {expected_round}")
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("round") != expected_round:
            errors.append(f"round sequence mismatch: {expected_round}")
        if record.get("previous_round_sha256") != previous_round_hash:
            errors.append(f"round hash-chain mismatch: {expected_round}")
        if record.get("base_global_model_sha256") != previous_model_digest:
            errors.append(f"round base-model mismatch: {expected_round}")
        if schema_version == "2.0" and set(record.get("global_metrics", {})) != {"validation"}:
            errors.append(f"round metrics are not validation-only: {expected_round}")
        updates: list[tuple[list[Any], int]] = []
        for update_ref in record.get("updates", []):
            update_record_path = workspace / update_ref["record_path"]
            update_object_path = workspace / update_ref["update_object_path"]
            record_digest_valid = update_record_path.is_file() and sha256_file(
                update_record_path
            ) == update_ref.get("record_sha256")
            if not record_digest_valid:
                errors.append(
                    "update record digest mismatch: "
                    f"round {expected_round} {update_ref['client_id']}"
                )
                continue
            object_digest_valid = update_object_path.is_file() and sha256_file(
                update_object_path
            ) == update_ref.get("update_object_sha256")
            if not object_digest_valid:
                errors.append(
                    "update object digest mismatch: "
                    f"round {expected_round} {update_ref['client_id']}"
                )
                continue
            update_object = json.loads(update_object_path.read_text(encoding="utf-8"))
            if update_object.get("base_model_sha256") != previous_model_digest:
                errors.append(
                    f"update base-model mismatch: round {expected_round} {update_ref['client_id']}"
                )
            updates.append(
                (
                    arrays_from_export(update_object, np=np),
                    int(update_ref["num_examples"]),
                )
            )
        if len(updates) == int(manifest["training"]["client_count"]):
            recomputed = fedavg(updates, aggregate=aggregate)
            global_path = workspace / record["aggregated_global_model_path"]
            if not global_path.is_file() or sha256_file(global_path) != record.get(
                "aggregated_global_model_sha256"
            ):
                errors.append(f"global model object mismatch: round {expected_round}")
            else:
                stored = arrays_from_export(
                    json.loads(global_path.read_text(encoding="utf-8")), np=np
                )
                if len(stored) != len(recomputed) or any(
                    not np.array_equal(left, right)
                    for left, right in zip(stored, recomputed, strict=True)
                ):
                    errors.append(f"FedAvg recomputation mismatch: round {expected_round}")
        previous_round_hash = item["sha256"]
        previous_model_digest = record.get("aggregated_global_model_sha256")
        round_records[expected_round] = record

    if previous_round_hash != manifest.get("final_round_sha256"):
        errors.append("final round hash does not match run manifest")
    if previous_model_digest != manifest.get("final_model_sha256"):
        errors.append("final model digest does not match run manifest")

    if schema_version == "2.0":
        metrics_history = metrics.get("rounds", [])
        server_evaluation = json.loads(
            (partition_workspace / partition_manifest["server_evaluation_path"]).read_text(
                encoding="utf-8"
            )
        )
        batch_size = int(manifest["training"]["batch_size"])
        if len(metrics_history) != len(index.get("rounds", [])):
            errors.append("metrics history length does not match round index")
        for position, metric_record in enumerate(metrics_history, start=1):
            if metric_record.get("round") != position:
                errors.append(f"metrics round sequence mismatch: {position}")
                continue
            if "test" in metric_record or "temporal_holdout" in metric_record:
                errors.append(f"pre-selection metrics expose test data: {position}")
            round_record = round_records.get(position)
            if round_record is None:
                continue
            if metric_record.get("global_model_sha256") != round_record.get(
                "aggregated_global_model_sha256"
            ):
                errors.append(f"metrics model digest mismatch: {position}")
            if not _same_json(
                metric_record.get("validation"),
                round_record.get("global_metrics", {}).get("validation"),
            ):
                errors.append(f"round validation metrics mismatch: {position}")
            if metric_record.get("weighted_training_loss") != round_record.get(
                "weighted_training_loss"
            ):
                errors.append(f"round training loss mismatch: {position}")
            checkpoint_path = workspace / str(round_record.get("aggregated_global_model_path"))
            if checkpoint_path.is_file():
                try:
                    checkpoint_export = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                    checkpoint_model, checkpoint_classes = _model_from_export(
                        checkpoint_export, torch=torch, np=np
                    )
                    if checkpoint_classes != partition_manifest.get("class_names"):
                        errors.append(f"checkpoint class order mismatch: {position}")
                    recomputed_validation = _evaluate(
                        model=checkpoint_model,
                        rows=server_evaluation["rows"]["validation"],
                        class_names=checkpoint_classes,
                        batch_size=batch_size,
                        dependency_values=dependency_values,
                    )
                    if not _same_json(metric_record.get("validation"), recomputed_validation):
                        errors.append(f"round validation inference mismatch: {position}")
                except (json.JSONDecodeError, KeyError, OSError, TypeError, ValueError) as exc:
                    errors.append(f"round validation verification failed: {position}: {exc}")
        if metrics_history and not _same_json(metrics.get("final"), metrics_history[-1]):
            errors.append("final metrics do not match the final round")

        selected = metrics.get("selected")
        if not isinstance(selected, dict):
            errors.append("missing selected checkpoint metrics")
        elif metrics_history:
            expected_selection = _select_validation_checkpoint(metrics_history)
            selected_round = int(expected_selection["round"])
            selected_record = round_records.get(selected_round)
            selected_index = next(
                (item for item in index.get("rounds", []) if item.get("round") == selected_round),
                {},
            )
            if selected_record is None or not selected_index:
                errors.append("selected round is absent from the verified round chain")
            expected_model_path = (
                selected_record.get("aggregated_global_model_path")
                if selected_record is not None
                else None
            )
            expected_model_digest = selected_index.get("aggregated_global_model_sha256")
            selection_expectations = {
                "selected round": (selected.get("round"), selected_round),
                "manifest selected round": (
                    manifest.get("selected_round"),
                    selected_round,
                ),
                "selected round digest": (
                    selected.get("round_record_sha256"),
                    selected_index.get("sha256"),
                ),
                "selected round path": (
                    selected.get("round_record_path"),
                    selected_index.get("path"),
                ),
                "manifest selected round digest": (
                    manifest.get("selected_round_sha256"),
                    selected_index.get("sha256"),
                ),
                "selected model path": (
                    selected.get("model_path"),
                    expected_model_path,
                ),
                "manifest selected model path": (
                    manifest.get("selected_model_path"),
                    expected_model_path,
                ),
                "selected model digest": (
                    selected.get("model_sha256"),
                    expected_model_digest,
                ),
                "manifest selected model digest": (
                    manifest.get("selected_model_sha256"),
                    expected_model_digest,
                ),
            }
            for description, (actual, expected) in selection_expectations.items():
                if actual != expected:
                    errors.append(f"{description} mismatch")
            policy = manifest.get("selection_policy", {})
            if policy != SELECTION_POLICY:
                errors.append("checkpoint selection policy mismatch")
            selection_record = selected.get("selection", {})
            expected_selection_criterion = {
                "split": "validation",
                "metric": SELECTION_METRIC,
                "mode": "maximize",
                "tie_breaker": "earliest_round",
                "value": expected_selection.get("validation", {}).get(SELECTION_METRIC),
            }
            if selection_record != expected_selection_criterion:
                errors.append("selected checkpoint criterion mismatch")
            if not _same_json(selected.get("validation"), expected_selection.get("validation")):
                errors.append("selected validation metrics mismatch")

            selected_model_path = workspace / str(expected_model_path)
            if (
                not selected_model_path.is_file()
                or sha256_file(selected_model_path) != expected_model_digest
            ):
                errors.append("selected model object mismatch")
            else:
                try:
                    selected_export = json.loads(selected_model_path.read_text(encoding="utf-8"))
                    selected_model, class_names = _model_from_export(
                        selected_export, torch=torch, np=np
                    )
                    if class_names != partition_manifest.get("class_names"):
                        errors.append("selected checkpoint class order mismatch")
                    recomputed_evaluations = {
                        split: _evaluate(
                            model=selected_model,
                            rows=server_evaluation["rows"][split],
                            class_names=class_names,
                            batch_size=batch_size,
                            dependency_values=dependency_values,
                        )
                        for split in ("validation", "test", "temporal_holdout")
                    }
                    for split, evaluation in recomputed_evaluations.items():
                        if not _same_json(selected.get(split), evaluation):
                            errors.append(f"selected checkpoint {split} inference mismatch")
                    expected_operational = {
                        "test_benign_false_alarms": _benign_false_alarm_summary(
                            recomputed_evaluations["test"]
                        ),
                        "temporal_holdout_benign_false_alarms": (
                            _benign_false_alarm_summary(recomputed_evaluations["temporal_holdout"])
                        ),
                    }
                    if not _same_json(selected.get("operational_metrics"), expected_operational):
                        errors.append("selected checkpoint operational metrics mismatch")

                    client_results = comparison.get("selected_global_client_validation", [])
                    local_test_results = comparison.get("selected_global_client_test", [])
                    clients = _load_client_snapshots(partition_workspace, partition_manifest)
                    expected_clients = []
                    for client_record, snapshot in clients:
                        expected_clients.append(
                            {
                                "client_id": client_record["client_id"],
                                "client_snapshot_sha256": client_record["dataset_sha256"],
                                "validation": _evaluate(
                                    model=selected_model,
                                    rows=snapshot["rows"]["validation"],
                                    class_names=class_names,
                                    batch_size=batch_size,
                                    dependency_values=dependency_values,
                                ),
                            }
                        )
                    if not _same_json(client_results, expected_clients):
                        errors.append("selected model per-client validation mismatch")
                    local_tests = _load_client_local_tests(partition_workspace, partition_manifest)
                    expected_local_tests = [
                        {
                            "client_id": client_record["client_id"],
                            "local_test_snapshot_sha256": client_record["local_test_sha256"],
                            "test": _evaluate(
                                model=selected_model,
                                rows=snapshot["rows"]["test"],
                                class_names=class_names,
                                batch_size=batch_size,
                                dependency_values=dependency_values,
                            ),
                        }
                        for client_record, snapshot in local_tests
                    ]
                    if not _same_json(local_test_results, expected_local_tests):
                        errors.append("selected model per-client local test mismatch")
                    expected_summary = {
                        "macro_f1_all_model_classes": _mean_metric(
                            [item["test"] for item in expected_local_tests],
                            SELECTION_METRIC,
                        )
                    }
                    if not _same_json(
                        comparison.get("selected_global_client_test_summary"),
                        expected_summary,
                    ):
                        errors.append("selected model per-client test summary mismatch")
                    baseline_by_client = {
                        item.get("client_id"): item
                        for item in comparison.get("local_only_clients", [])
                    }
                    if set(baseline_by_client) not in (
                        set(),
                        {record["client_id"] for record, _snapshot in clients},
                    ):
                        errors.append("local-only client result list is incomplete")
                    recomputed_global_validation = []
                    recomputed_local_test = []
                    recomputed_global_test = []
                    local_test_by_client = {
                        record["client_id"]: snapshot for record, snapshot in local_tests
                    }
                    for client_record, snapshot in clients:
                        client_id = client_record["client_id"]
                        baseline = baseline_by_client.get(client_id)
                        if baseline is None:
                            continue
                        if (
                            baseline.get("client_snapshot_sha256")
                            != client_record["dataset_sha256"]
                            or baseline.get("local_test_snapshot_sha256")
                            != client_record["local_test_sha256"]
                        ):
                            errors.append(f"local-only snapshot binding mismatch: {client_id}")
                        model_path = workspace / str(baseline.get("model_path", ""))
                        if not model_path.is_file() or sha256_file(model_path) != baseline.get(
                            "model_sha256"
                        ):
                            errors.append(f"local-only model object mismatch: {client_id}")
                            continue
                        local_export = json.loads(model_path.read_text(encoding="utf-8"))
                        local_model, local_classes = _model_from_export(
                            local_export, torch=torch, np=np
                        )
                        if local_classes != class_names:
                            errors.append(f"local-only class order mismatch: {client_id}")
                        recomputed = {
                            "local_validation": _evaluate(
                                model=local_model,
                                rows=snapshot["rows"]["validation"],
                                class_names=class_names,
                                batch_size=batch_size,
                                dependency_values=dependency_values,
                            ),
                            "global_validation": _evaluate(
                                model=local_model,
                                rows=server_evaluation["rows"]["validation"],
                                class_names=class_names,
                                batch_size=batch_size,
                                dependency_values=dependency_values,
                            ),
                            "local_test": _evaluate(
                                model=local_model,
                                rows=local_test_by_client[client_id]["rows"]["test"],
                                class_names=class_names,
                                batch_size=batch_size,
                                dependency_values=dependency_values,
                            ),
                            "global_test": _evaluate(
                                model=local_model,
                                rows=server_evaluation["rows"]["test"],
                                class_names=class_names,
                                batch_size=batch_size,
                                dependency_values=dependency_values,
                            ),
                        }
                        for name, evaluation in recomputed.items():
                            if not _same_json(baseline.get(name), evaluation):
                                errors.append(f"local-only {name} inference mismatch: {client_id}")
                        recomputed_global_validation.append(recomputed["global_validation"])
                        recomputed_local_test.append(recomputed["local_test"])
                        recomputed_global_test.append(recomputed["global_test"])
                    expected_local_only_summary = {
                        "global_validation_macro_f1": _mean_metric(
                            recomputed_global_validation, SELECTION_METRIC
                        ),
                        "local_test_macro_f1": _mean_metric(
                            recomputed_local_test, SELECTION_METRIC
                        ),
                        "global_test_macro_f1": _mean_metric(
                            recomputed_global_test, SELECTION_METRIC
                        ),
                    }
                    if not _same_json(
                        comparison.get("local_only_summary"),
                        expected_local_only_summary,
                    ):
                        errors.append("local-only metric summary mismatch")
                    if not _same_json(comparison.get("fedavg_selected"), selected):
                        errors.append("selected checkpoint comparison mismatch")
                except (
                    json.JSONDecodeError,
                    KeyError,
                    OSError,
                    TypeError,
                    ValueError,
                ) as exc:
                    errors.append(f"selected checkpoint verification failed: {exc}")
    return {
        "status": "verified" if not errors else "failed",
        "dataset": manifest.get("dataset"),
        "partition_mode": manifest.get("partition_mode"),
        "rounds": manifest.get("training", {}).get("rounds"),
        "workspace": str(workspace),
        "final_model_sha256": manifest.get("final_model_sha256"),
        "final_round_sha256": manifest.get("final_round_sha256"),
        "selected_round": manifest.get("selected_round"),
        "selected_model_sha256": manifest.get("selected_model_sha256"),
        "error_count": len(errors),
        "errors": errors,
    }
