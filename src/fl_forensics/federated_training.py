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
    server_evaluation = json.loads(
        (partition_workspace / partition_manifest["server_evaluation_path"]).read_text(
            encoding="utf-8"
        )
    )
    global_model = new_model(seed)
    initial_export = export_state(
        global_model, architecture=architecture, class_names=class_names
    )
    initial_model_path, initial_model_digest = _store_object(
        output, "models", initial_export
    )
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
            update_relative = (
                Path("updates") / f"round-{round_number:03d}" / f"{client_id}.json"
            )
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
            split: _evaluate(
                model=global_model,
                rows=server_evaluation["rows"][split],
                class_names=class_names,
                batch_size=batch_size,
                dependency_values=dependency_values,
            )
            for split in ("validation", "test", "temporal_holdout")
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
                "test": global_metrics["test"],
                "temporal_holdout": global_metrics["temporal_holdout"],
            }
        )
        previous_round_hash = round_hash
        previous_model_digest = global_model_digest

    local_baselines: list[dict[str, Any]] = []
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
            local_baselines.append(
                {
                    "client_id": record["client_id"],
                    "client_snapshot_sha256": record["dataset_sha256"],
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
                        rows=server_evaluation["rows"]["validation"],
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
            )

    final_global_metrics = metrics_history[-1]
    local_global_validation = [item["global_validation"] for item in local_baselines]
    local_global_test = [item["global_test"] for item in local_baselines]
    comparison = {
        "schema_version": "1.0",
        "artifact_type": "m3_local_fedavg_comparison",
        "comparison_fairness": {
            "same_initial_model": initial_model_digest,
            "same_frozen_client_snapshots": True,
            "same_total_local_epochs_per_client": rounds * local_epochs,
            "same_optimizer": str(training["optimizer"]),
            "same_learning_rate": learning_rate,
        },
        "fedavg_final": {
            "validation": final_global_metrics["validation"],
            "test": final_global_metrics["test"],
            "temporal_holdout": final_global_metrics["temporal_holdout"],
        },
        "local_only_clients": local_baselines,
        "local_only_summary": {
            "global_validation_macro_f1": _mean_metric(
                local_global_validation, "macro_f1_all_model_classes"
            ),
            "global_test_macro_f1": _mean_metric(
                local_global_test, "macro_f1_all_model_classes"
            ),
        },
    }
    comparison_bytes = derived_json_bytes(comparison)
    metrics_artifact = {
        "schema_version": "1.0",
        "artifact_type": "m3_fedavg_metrics",
        "dataset": DATASET_NAME,
        "partition_mode": partition_manifest["partition_mode"],
        "rounds": metrics_history,
        "final": final_global_metrics,
        "interpretation_constraints": [
            "The temporal holdout is benign-only and is not a multiclass test.",
            "Data24 retains its documented acquisition-time/class confound.",
            "This is a clean FedAvg baseline; Byzantine behavior and defenses are not active.",
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
        "schema_version": "1.0",
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
        "validation_macro_f1": final_global_metrics["validation"][
            "macro_f1_all_model_classes"
        ],
        "test_macro_f1": final_global_metrics["test"]["macro_f1_all_model_classes"],
        "local_only_mean_test_macro_f1": comparison["local_only_summary"][
            "global_test_macro_f1"
        ]["mean"],
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
    if sha256_file(dataset_workspace / "manifest.json") != manifest.get(
        "dataset_manifest_sha256"
    ):
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
    np, _torch, _flwr, _sklearn, aggregate, *_metrics = dependency_values
    index = json.loads((workspace / "round_index.json").read_text(encoding="utf-8"))
    previous_round_hash = "0" * 64
    previous_model_digest = manifest.get("initial_model_sha256")
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

    if previous_round_hash != manifest.get("final_round_sha256"):
        errors.append("final round hash does not match run manifest")
    if previous_model_digest != manifest.get("final_model_sha256"):
        errors.append("final model digest does not match run manifest")
    return {
        "status": "verified" if not errors else "failed",
        "dataset": manifest.get("dataset"),
        "partition_mode": manifest.get("partition_mode"),
        "rounds": manifest.get("training", {}).get("rounds"),
        "workspace": str(workspace),
        "final_model_sha256": manifest.get("final_model_sha256"),
        "final_round_sha256": manifest.get("final_round_sha256"),
        "error_count": len(errors),
        "errors": errors,
    }
