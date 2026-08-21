"""Auditable M6 prototype-poisoning freeze, comparison, and verification."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

import numpy as np

from . import __version__
from .byzantine_experiment import (
    _model_from_export,
    _verified_snapshot_file,
    _verify_partition_snapshot_files,
)
from .canonical import sha256_bytes, sha256_file
from .config import load_yaml
from .federated_model import dependencies, evaluate_rows
from .preprocessing import derived_json_bytes
from .prototypes import (
    PrototypeConfigurationError,
    aggregate_class_prototypes,
    extract_class_prototypes,
    poison_prototype_records,
    prototype_distance_indicators,
)
from .secure_round import verify_secure_round
from .storage import load_json, write_once


class PrototypeExperimentError(RuntimeError):
    """Raised when prototype evidence, lineage, or recomputation is invalid."""


def _write_json(path: Path, value: dict[str, Any]) -> str:
    content = derived_json_bytes(value)
    write_once(path, content)
    return sha256_bytes(content)


def _safe_file(root: Path, relative_path: Any, digest: Any, label: str) -> Path:
    try:
        return _verified_snapshot_file(
            root=root,
            relative_path=relative_path,
            expected_sha256=digest,
            description=label,
        )
    except RuntimeError as exc:
        raise PrototypeExperimentError(str(exc)) from exc


def _select_attackers(client_ids: list[str], *, f: int, seed: int) -> list[str]:
    if f <= 0 or f >= len(client_ids):
        raise PrototypeExperimentError("prototype poisoning requires 0 < f < client count")
    ranked = sorted(
        client_ids,
        key=lambda client_id: (
            hashlib.sha256(f"{seed}:{client_id}".encode()).hexdigest(),
            client_id,
        ),
    )
    return sorted(ranked[:f])


def _checked_attackers(
    client_ids: list[str],
    *,
    f: int,
    seed: int,
    attacker_ids: list[str] | None,
) -> list[str]:
    selected = (
        _select_attackers(client_ids, f=f, seed=seed)
        if attacker_ids is None
        else sorted(str(item) for item in attacker_ids)
    )
    if (
        len(selected) != f
        or len(set(selected)) != f
        or not set(selected).issubset(client_ids)
    ):
        raise PrototypeExperimentError("attacker identities must be f unique M5 clients")
    return selected


def _source_inputs(
    *,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    verification = verify_secure_round(
        workspace=source_round_workspace,
        trust_workspace=trust_workspace,
        submissions_root=source_round_workspace / "submissions",
    )
    if verification["status"] != "verified":
        raise PrototypeExperimentError(
            f"source M5 round does not verify: {verification['errors']}"
        )
    config, config_digest = load_yaml(config_path)
    if config.get("experiment", {}).get("attack") != "prototype_poisoning":
        raise PrototypeExperimentError("configuration is not a prototype-poisoning experiment")

    context_path = source_round_workspace / "public" / "round-context.json"
    checkpoint_manifest_path = source_round_workspace / "checkpoint" / "manifest.json"
    model_path = source_round_workspace / "checkpoint" / "global-model.json"
    source_partition_path = source_round_workspace / "public" / "partition-manifest.json"
    context = load_json(context_path)
    checkpoint = load_json(checkpoint_manifest_path)
    model_export = load_json(model_path)
    partition_manifest = load_json(source_partition_path)
    core = context["core"]
    checkpoint_core = checkpoint["core"]

    if sha256_file(source_partition_path) != core["partition_manifest_sha256"]:
        raise PrototypeExperimentError("M5 partition manifest differs from signed context")
    if sha256_file(model_path) != checkpoint_core["global_model_sha256"]:
        raise PrototypeExperimentError("M5 global model differs from signed checkpoint")
    if checkpoint_core["context_digest"] != context["core_digest"]:
        raise PrototypeExperimentError("M5 checkpoint/context binding mismatch")
    try:
        _verify_partition_snapshot_files(
            partition_workspace=partition_workspace,
            partition_manifest=partition_manifest,
        )
    except RuntimeError as exc:
        raise PrototypeExperimentError(str(exc)) from exc
    client_ids = [str(item["client_id"]) for item in core["clients"]]
    partition_clients = partition_manifest.get("clients", [])
    if [str(item.get("client_id")) for item in partition_clients] != client_ids:
        raise PrototypeExperimentError("M5 context and partition client order differ")
    if len(client_ids) != int(config["experiment"]["client_count"]):
        raise PrototypeExperimentError("configured client count differs from signed M5 context")
    for context_client, partition_client in zip(
        core["clients"], partition_clients, strict=True
    ):
        if (
            context_client["snapshot_sha256"] != partition_client["dataset_sha256"]
            or context_client["snapshot_manifest_sha256"]
            != partition_client["manifest_sha256"]
            or int(context_client["train_row_count"])
            != int(partition_client["train_row_count"])
        ):
            raise PrototypeExperimentError(
                f"M5 client snapshot binding mismatch: {context_client['client_id']}"
            )
    if [str(item) for item in model_export["class_names"]] != [
        str(item) for item in partition_manifest["class_names"]
    ]:
        raise PrototypeExperimentError("checkpoint and partition class schemas differ")
    return {
        "config": config,
        "config_digest": config_digest,
        "context_path": context_path,
        "checkpoint_manifest_path": checkpoint_manifest_path,
        "model_path": model_path,
        "partition_path": source_partition_path,
        "context": context,
        "checkpoint": checkpoint,
        "model_export": model_export,
        "partition_manifest": partition_manifest,
        "client_ids": client_ids,
    }


def _submission(
    *,
    client_id: str,
    client_record: dict[str, Any],
    dataset_path: Path,
    model: Any,
    model_sha256: str,
    config: dict[str, Any],
    attacked: bool,
    torch: Any,
) -> dict[str, Any]:
    dataset = load_json(dataset_path)
    prototype_config = config["prototypes"]
    attack_config = config["attack"]
    clean = extract_class_prototypes(
        model=model,
        rows=dataset["rows"]["train"],
        class_names=[str(item) for item in dataset["class_names"]],
        minimum_support=int(prototype_config["minimum_local_support"]),
        batch_size=int(prototype_config["batch_size"]),
        torch=torch,
    )
    submitted = (
        poison_prototype_records(
            clean,
            source_class=str(attack_config["source_class"]),
            target_class=str(attack_config["target_class"]),
            scale=float(attack_config["scale"]),
        )
        if attacked
        else copy.deepcopy(clean)
    )
    return {
        "schema_version": "1.0",
        "artifact_type": "m6_frozen_prototype_submission",
        "client_id": client_id,
        "attacker": attacked,
        "source_client_dataset_sha256": str(client_record["dataset_sha256"]),
        "source_client_manifest_sha256": str(client_record["manifest_sha256"]),
        "encoder_model_sha256": model_sha256,
        "attack": (
            {
                "name": "prototype_poisoning",
                "source_class": str(attack_config["source_class"]),
                "target_class": str(attack_config["target_class"]),
                "scale": float(attack_config["scale"]),
            }
            if attacked
            else {"name": "clean"}
        ),
        "privacy": {"row_embeddings_preserved": False},
        "clean": clean,
        "submitted": submitted,
    }


def freeze_prototype_scenario(
    *,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    output: Path,
    f: int,
    config_path: Path,
    attacker_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Freeze clean and poisoned prototype submissions from a verified M5 checkpoint."""

    source = _source_inputs(
        source_round_workspace=source_round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        config_path=config_path,
    )
    config = source["config"]
    seed = int(config["experiment"]["seed"])
    selected = _checked_attackers(
        source["client_ids"], f=f, seed=seed, attacker_ids=attacker_ids
    )
    selected_set = set(selected)
    _np, torch, *_rest = dependencies()
    model = _model_from_export(source["model_export"], torch=torch)
    model_digest = sha256_file(source["model_path"])

    source_records: dict[str, dict[str, str]] = {}
    for name, path in {
        "round_context": source["context_path"],
        "checkpoint_manifest": source["checkpoint_manifest_path"],
        "global_model": source["model_path"],
        "partition_manifest": source["partition_path"],
    }.items():
        relative = Path("source") / f"{name.replace('_', '-')}.json"
        write_once(output / relative, path.read_bytes())
        source_records[name] = {
            "path": relative.as_posix(),
            "sha256": sha256_file(output / relative),
        }

    records: list[dict[str, Any]] = []
    for client_record in source["partition_manifest"]["clients"]:
        client_id = str(client_record["client_id"])
        dataset_path = _safe_file(
            partition_workspace,
            client_record["dataset_path"],
            client_record["dataset_sha256"],
            f"{client_id} dataset",
        )
        value = _submission(
            client_id=client_id,
            client_record=client_record,
            dataset_path=dataset_path,
            model=model,
            model_sha256=model_digest,
            config=config,
            attacked=client_id in selected_set,
            torch=torch,
        )
        relative = Path("submissions") / f"{client_id}.json"
        digest = _write_json(output / relative, value)
        records.append(
            {
                "client_id": client_id,
                "attacker": client_id in selected_set,
                "submission_path": relative.as_posix(),
                "submission_sha256": digest,
                "eligible_clean_class_count": int(value["clean"]["eligible_class_count"]),
                "eligible_submitted_class_count": int(
                    value["submitted"]["eligible_class_count"]
                ),
            }
        )

    manifest = {
        "schema_version": "1.0",
        "artifact_type": "m6_frozen_prototype_poisoning_scenario",
        "code_version": __version__,
        "attack": "prototype_poisoning",
        "f": f,
        "seed": seed,
        "attacker_ids": selected,
        "client_count": len(records),
        "source_semantics": "post-training-prototype-overlay-on-verified-m5-global-encoder",
        "source_round_number": int(source["context"]["core"]["round_number"]),
        "source_files": source_records,
        "prototype_config_sha256": source["config_digest"],
        "implementation_sha256": {
            "prototype_core": sha256_file(Path(__file__).with_name("prototypes.py")),
            "prototype_experiment": sha256_file(Path(__file__)),
        },
        "test_data_accessed": False,
        "clients": records,
    }
    manifest_digest = _write_json(output / "manifest.json", manifest)
    return {
        "status": "frozen",
        "attack": "prototype_poisoning",
        "f": f,
        "attacker_ids": selected,
        "client_count": len(records),
        "manifest_sha256": manifest_digest,
        "test_data_accessed": False,
        "workspace": str(output),
    }


def _validate_frozen(workspace: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = workspace / "manifest.json"
    if not manifest_path.is_file():
        raise PrototypeExperimentError("missing frozen prototype manifest")
    manifest = load_json(manifest_path)
    if manifest.get("artifact_type") != "m6_frozen_prototype_poisoning_scenario":
        raise PrototypeExperimentError("unexpected frozen prototype artifact type")
    clients = manifest.get("clients", [])
    identities = [str(item.get("client_id")) for item in clients]
    expected = [f"client{index:02d}" for index in range(1, 16)]
    if identities != expected:
        raise PrototypeExperimentError("frozen scenario lacks 15 ordered unique clients")
    submissions: list[dict[str, Any]] = []
    for record in clients:
        path = _safe_file(
            workspace,
            record.get("submission_path"),
            record.get("submission_sha256"),
            f"{record.get('client_id')} prototype submission",
        )
        submission = load_json(path)
        if (
            submission.get("client_id") != record.get("client_id")
            or bool(submission.get("attacker")) != bool(record.get("attacker"))
            or submission.get("privacy", {}).get("row_embeddings_preserved") is not False
        ):
            raise PrototypeExperimentError(
                f"frozen submission binding mismatch: {record.get('client_id')}"
            )
        submissions.append(submission)
    attackers = sorted(
        str(item["client_id"]) for item in clients if bool(item.get("attacker"))
    )
    if (
        attackers != manifest.get("attacker_ids")
        or len(attackers) != int(manifest.get("f", -1))
    ):
        raise PrototypeExperimentError("frozen attacker/f binding mismatch")
    for name, record in manifest.get("source_files", {}).items():
        _safe_file(workspace, record.get("path"), record.get("sha256"), name)
    return manifest, submissions


def verify_frozen_prototype_scenario(
    *,
    workspace: Path,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Re-extract every prototype and compare it with the frozen evidence bytes."""

    errors: list[str] = []
    manifest: dict[str, Any] = {}
    try:
        manifest, stored = _validate_frozen(workspace)
        source = _source_inputs(
            source_round_workspace=source_round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            config_path=config_path,
        )
        if source["config_digest"] != manifest.get("prototype_config_sha256"):
            raise PrototypeExperimentError("prototype configuration digest mismatch")
        for name, path in {
            "round_context": source["context_path"],
            "checkpoint_manifest": source["checkpoint_manifest_path"],
            "global_model": source["model_path"],
            "partition_manifest": source["partition_path"],
        }.items():
            if sha256_file(path) != manifest["source_files"][name]["sha256"]:
                raise PrototypeExperimentError(f"source lineage changed: {name}")
        _np, torch, *_rest = dependencies()
        model = _model_from_export(source["model_export"], torch=torch)
        model_digest = sha256_file(source["model_path"])
        attackers = set(manifest["attacker_ids"])
        for stored_value, client_record in zip(
            stored, source["partition_manifest"]["clients"], strict=True
        ):
            client_id = str(client_record["client_id"])
            dataset_path = _safe_file(
                partition_workspace,
                client_record["dataset_path"],
                client_record["dataset_sha256"],
                f"{client_id} dataset",
            )
            recomputed = _submission(
                client_id=client_id,
                client_record=client_record,
                dataset_path=dataset_path,
                model=model,
                model_sha256=model_digest,
                config=source["config"],
                attacked=client_id in attackers,
                torch=torch,
            )
            if derived_json_bytes(recomputed) != derived_json_bytes(stored_value):
                errors.append(f"prototype recomputation mismatch: {client_id}")
    except (KeyError, OSError, PrototypeConfigurationError, PrototypeExperimentError, ValueError) as exc:
        errors.append(str(exc))
    manifest_path = workspace / "manifest.json"
    return {
        "status": "verified" if not errors else "failed",
        "attack": manifest.get("attack"),
        "f": manifest.get("f"),
        "client_count": len(manifest.get("clients", [])),
        "manifest_sha256": sha256_file(manifest_path) if manifest_path.is_file() else None,
        "recomputed_client_count": len(manifest.get("clients", [])) if not errors else 0,
        "test_data_accessed": False,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }


def _prototype_submission(value: dict[str, Any], key: str) -> dict[str, Any]:
    record = value[key]
    return {
        "client_id": str(value["client_id"]),
        "embedding_size": int(record["embedding_size"]),
        "prototypes": record["prototypes"],
    }


def _metric_record(
    *,
    labels: Any,
    predictions: Any,
    class_names: list[str],
    accuracy_score: Any,
    confusion_matrix: Any,
    precision_recall_fscore_support: Any,
) -> dict[str, Any]:
    label_ids = list(range(len(class_names)))
    precision, recall, f1, support = precision_recall_fscore_support(
        labels, predictions, labels=label_ids, zero_division=0
    )
    observed = sorted(set(labels.tolist()))
    return {
        "row_count": len(labels),
        "observed_labels": [class_names[index] for index in observed],
        "observed_class_count": len(observed),
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


def _nearest_prototype_evaluation(
    *,
    model: Any,
    aggregate: dict[str, Any],
    server_evaluation: dict[str, Any],
    class_names: list[str],
    splits: list[str],
    batch_size: int,
    torch: Any,
    accuracy_score: Any,
    confusion_matrix: Any,
    precision_recall_fscore_support: Any,
) -> dict[str, Any]:
    for class_name in class_names:
        if aggregate["classes"][class_name]["status"] != "aggregated":
            raise PrototypeExperimentError(
                f"class quorum not met for evaluation: {class_name}"
            )
    prototype_matrix = np.asarray(
        [aggregate["classes"][name]["values"] for name in class_names],
        dtype=np.float64,
    )
    label_indices = {name: index for index, name in enumerate(class_names)}
    result: dict[str, Any] = {}
    model.to("cpu")
    model.eval()
    for split in splits:
        rows = server_evaluation["rows"][split]
        features = np.asarray([row["features"] for row in rows], dtype=np.float32)
        labels = np.asarray(
            [label_indices[str(row["label"])] for row in rows], dtype=np.int64
        )
        batches: list[np.ndarray] = []
        with torch.no_grad():
            for start in range(0, len(features), batch_size):
                encoded = model.encoder(
                    torch.from_numpy(features[start : start + batch_size])
                )
                batches.append(encoded.detach().cpu().numpy().astype(np.float64))
        embeddings = np.concatenate(batches, axis=0)
        distances = np.linalg.norm(
            embeddings[:, np.newaxis, :] - prototype_matrix[np.newaxis, :, :],
            axis=2,
        )
        predictions = distances.argmin(axis=1)
        result[split] = _metric_record(
            labels=labels,
            predictions=predictions,
            class_names=class_names,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        )
    return result


def _source_to_target_rate(
    metrics: dict[str, Any], *, source_class: str, target_class: str
) -> dict[str, Any]:
    labels = metrics["confusion_matrix"]["labels"]
    matrix = metrics["confusion_matrix"]["values"]
    source_index = labels.index(source_class)
    target_index = labels.index(target_class)
    eligible = int(sum(matrix[source_index]))
    successes = int(matrix[source_index][target_index])
    return {
        "eligible_source_row_count": eligible,
        "source_to_target_prediction_count": successes,
        "attack_success_rate": float(successes / eligible) if eligible else 0.0,
    }


def _source_class_integrity(
    metrics: dict[str, Any], *, source_class: str, target_class: str
) -> dict[str, Any]:
    """Separate targeted success from any other loss of source-class integrity."""

    labels = metrics["confusion_matrix"]["labels"]
    matrix = metrics["confusion_matrix"]["values"]
    source_index = labels.index(source_class)
    target_index = labels.index(target_class)
    row = matrix[source_index]
    support = int(sum(row))
    correct = int(row[source_index])
    targeted = int(row[target_index])
    other = support - correct - targeted
    return {
        "source_row_count": support,
        "correct_source_prediction_count": correct,
        "target_class_prediction_count": targeted,
        "other_class_prediction_count": other,
        "source_recall": float(correct / support) if support else 0.0,
        "source_misclassification_rate": float((support - correct) / support)
        if support
        else 0.0,
        "targeted_attack_success_rate": float(targeted / support) if support else 0.0,
        "other_class_misclassification_rate": float(other / support)
        if support
        else 0.0,
    }


def _aggregate_shift_l2(
    clean: dict[str, Any], attacked: dict[str, Any], *, class_name: str
) -> float:
    first = np.asarray(clean["classes"][class_name]["values"], dtype=np.float64)
    second = np.asarray(attacked["classes"][class_name]["values"], dtype=np.float64)
    return float(np.linalg.norm(second - first))


def _compute_comparison(
    *,
    frozen_workspace: Path,
    partition_workspace: Path,
    config_path: Path,
    include_source_integrity: bool = True,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    manifest, frozen_submissions = _validate_frozen(frozen_workspace)
    config, config_digest = load_yaml(config_path)
    if config_digest != manifest.get("prototype_config_sha256"):
        raise PrototypeExperimentError("comparison configuration differs from freeze")
    source_partition = manifest["source_files"]["partition_manifest"]
    frozen_partition_path = _safe_file(
        frozen_workspace,
        source_partition["path"],
        source_partition["sha256"],
        "frozen signed partition manifest",
    )
    partition_manifest = load_json(frozen_partition_path)
    server_path = _verify_partition_snapshot_files(
        partition_workspace=partition_workspace,
        partition_manifest=partition_manifest,
    )
    server_evaluation = load_json(server_path)
    model_path = _safe_file(
        frozen_workspace,
        manifest["source_files"]["global_model"]["path"],
        manifest["source_files"]["global_model"]["sha256"],
        "frozen global model",
    )
    model_export = load_json(model_path)
    class_names = [str(item) for item in model_export["class_names"]]
    if class_names != [str(item) for item in server_evaluation["class_names"]]:
        raise PrototypeExperimentError("model and server evaluation class schemas differ")

    prototype_config = config["prototypes"]
    evaluation_config = config["evaluation"]
    strategies = {
        "baseline": str(prototype_config["baseline_aggregation"]),
        "robust": str(prototype_config["robust_aggregation"]),
    }
    conditions = {
        "clean": [
            _prototype_submission(item, "clean") for item in frozen_submissions
        ],
        "attacked": [
            _prototype_submission(item, "submitted") for item in frozen_submissions
        ],
    }
    aggregates: dict[str, dict[str, Any]] = {}
    for condition, submissions in conditions.items():
        for defense, strategy in strategies.items():
            profile_id = f"{condition}-{defense}-{strategy}"
            aggregates[profile_id] = aggregate_class_prototypes(
                submissions,
                class_names=class_names,
                minimum_local_support=int(prototype_config["minimum_local_support"]),
                class_quorum=int(prototype_config["class_quorum"]),
                strategy=strategy,  # type: ignore[arg-type]
            )

    (
        _np,
        torch,
        _flwr,
        _sklearn,
        _aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependencies()
    model = _model_from_export(model_export, torch=torch)
    splits = [str(item) for item in evaluation_config["splits"]]
    outcomes: list[dict[str, Any]] = []
    for profile_id in sorted(aggregates):
        metrics = _nearest_prototype_evaluation(
            model=model,
            aggregate=aggregates[profile_id],
            server_evaluation=server_evaluation,
            class_names=class_names,
            splits=splits,
            batch_size=int(prototype_config["batch_size"]),
            torch=torch,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        )
        outcome = {
            "profile_id": profile_id,
            "condition": profile_id.split("-", 1)[0],
            "aggregation_strategy": aggregates[profile_id]["strategy"],
            "metrics": metrics,
            "source_to_target": {
                split: _source_to_target_rate(
                    metrics[split],
                    source_class=str(config["attack"]["source_class"]),
                    target_class=str(config["attack"]["target_class"]),
                )
                for split in splits
            },
        }
        if include_source_integrity:
            outcome["source_class_integrity"] = {
                split: _source_class_integrity(
                    metrics[split],
                    source_class=str(config["attack"]["source_class"]),
                    target_class=str(config["attack"]["target_class"]),
                )
                for split in splits
            }
        outcomes.append(outcome)
    outcome_by_profile = {item["profile_id"]: item for item in outcomes}
    effects: list[dict[str, Any]] = []
    for defense, strategy in strategies.items():
        clean_id = f"clean-{defense}-{strategy}"
        attacked_id = f"attacked-{defense}-{strategy}"
        clean_outcome = outcome_by_profile[clean_id]
        attacked_outcome = outcome_by_profile[attacked_id]
        effect = {
            "aggregation_strategy": strategy,
            "source_prototype_shift_l2": _aggregate_shift_l2(
                aggregates[clean_id],
                aggregates[attacked_id],
                class_name=str(config["attack"]["source_class"]),
            ),
            "validation_macro_f1_delta": float(
                attacked_outcome["metrics"]["validation"][
                    "macro_f1_all_model_classes"
                ]
                - clean_outcome["metrics"]["validation"][
                    "macro_f1_all_model_classes"
                ]
            ),
            "test_macro_f1_delta": float(
                attacked_outcome["metrics"]["test"][
                    "macro_f1_all_model_classes"
                ]
                - clean_outcome["metrics"]["test"][
                    "macro_f1_all_model_classes"
                ]
            ),
            "test_attack_success_rate_delta": float(
                attacked_outcome["source_to_target"]["test"][
                    "attack_success_rate"
                ]
                - clean_outcome["source_to_target"]["test"][
                    "attack_success_rate"
                ]
            ),
        }
        if include_source_integrity:
            for split in ("validation", "test"):
                attacked_integrity = attacked_outcome["source_class_integrity"][
                    split
                ]
                clean_integrity = clean_outcome["source_class_integrity"][split]
                effect[f"{split}_source_recall_delta"] = float(
                    attacked_integrity["source_recall"]
                    - clean_integrity["source_recall"]
                )
                effect[f"{split}_source_misclassification_rate_delta"] = float(
                    attacked_integrity["source_misclassification_rate"]
                    - clean_integrity["source_misclassification_rate"]
                )
                effect[f"{split}_other_class_misclassification_rate_delta"] = float(
                    attacked_integrity["other_class_misclassification_rate"]
                    - clean_integrity["other_class_misclassification_rate"]
                )
        effects.append(effect)

    reference = {
        split: evaluate_rows(
            model=model,
            rows=server_evaluation["rows"][split],
            class_names=class_names,
            batch_size=int(prototype_config["batch_size"]),
            torch=torch,
            np=np,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        )
        for split in splits
    }
    indicators = prototype_distance_indicators(
        conditions["attacked"], class_names=class_names
    )
    attacker_set = set(manifest["attacker_ids"])
    for indicator in indicators:
        indicator["attacker"] = indicator["client_id"] in attacker_set
    comparison = {
        "schema_version": "1.1" if include_source_integrity else "1.0",
        "artifact_type": "m6_prototype_poisoning_comparison",
        "attack": "prototype_poisoning",
        "f": int(manifest["f"]),
        "attacker_ids": manifest["attacker_ids"],
        "source_semantics": manifest["source_semantics"],
        "classifier": str(evaluation_config["classifier"]),
        "distance": str(evaluation_config["distance"]),
        "source_class": str(config["attack"]["source_class"]),
        "target_class": str(config["attack"]["target_class"]),
        "frozen_manifest_sha256": sha256_file(frozen_workspace / "manifest.json"),
        "partition_manifest_sha256": sha256_file(frozen_partition_path),
        "server_evaluation_sha256": sha256_file(server_path),
        "prototype_config_sha256": config_digest,
        "same_frozen_submissions_for_every_aggregator": True,
        "test_data_accessed": "test" in splits,
        "reference_classification_head": reference,
        "indicators": indicators,
        "outcomes": outcomes,
        "attack_effects": effects,
    }
    if include_source_integrity:
        comparison["comparison_implementation_sha256"] = sha256_file(Path(__file__))
    return comparison, aggregates


def run_prototype_comparison(
    *,
    frozen_workspace: Path,
    partition_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    comparison, aggregates = _compute_comparison(
        frozen_workspace=frozen_workspace,
        partition_workspace=partition_workspace,
        config_path=config_path,
    )
    aggregate_records: list[dict[str, str]] = []
    for profile_id in sorted(aggregates):
        relative = Path("aggregates") / f"{profile_id}.json"
        digest = _write_json(output / relative, aggregates[profile_id])
        aggregate_records.append(
            {
                "profile_id": profile_id,
                "aggregate_path": relative.as_posix(),
                "aggregate_sha256": digest,
            }
        )
    comparison["aggregates"] = aggregate_records
    digest = _write_json(output / "comparison.json", comparison)
    effects = {item["aggregation_strategy"]: item for item in comparison["attack_effects"]}
    return {
        "status": "compared",
        "attack": comparison["attack"],
        "f": comparison["f"],
        "profile_count": len(comparison["outcomes"]),
        "baseline_test_macro_f1_delta": effects["support_weighted_mean"][
            "test_macro_f1_delta"
        ],
        "robust_test_macro_f1_delta": effects["coordinate_median"][
            "test_macro_f1_delta"
        ],
        "baseline_test_source_recall_delta": effects["support_weighted_mean"][
            "test_source_recall_delta"
        ],
        "robust_test_source_recall_delta": effects["coordinate_median"][
            "test_source_recall_delta"
        ],
        "comparison_sha256": digest,
        "test_data_accessed": comparison["test_data_accessed"],
        "workspace": str(output),
    }


def verify_prototype_comparison(
    *,
    frozen_workspace: Path,
    partition_workspace: Path,
    workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Recompute metrics and aggregates and reject any modified evidence."""

    errors: list[str] = []
    stored: dict[str, Any] = {}
    stored_path = workspace / "comparison.json"
    try:
        stored = load_json(stored_path)
        if stored.get("artifact_type") != "m6_prototype_poisoning_comparison":
            raise PrototypeExperimentError("unexpected prototype comparison type")
        schema_version = str(stored.get("schema_version", "1.0"))
        if schema_version not in {"1.0", "1.1"}:
            raise PrototypeExperimentError(
                f"unsupported prototype comparison schema: {schema_version}"
            )
        recomputed, aggregates = _compute_comparison(
            frozen_workspace=frozen_workspace,
            partition_workspace=partition_workspace,
            config_path=config_path,
            include_source_integrity=schema_version == "1.1",
        )
        records = stored.get("aggregates", [])
        if [item.get("profile_id") for item in records] != sorted(aggregates):
            errors.append("aggregate profile set mismatch")
        for record in records:
            profile_id = str(record["profile_id"])
            path = workspace / str(record.get("aggregate_path", ""))
            expected = derived_json_bytes(aggregates[profile_id])
            if (
                not path.is_file()
                or sha256_file(path) != record.get("aggregate_sha256")
                or path.read_bytes() != expected
            ):
                errors.append(f"aggregate prototype mismatch: {profile_id}")
        recomputed["aggregates"] = records
        if derived_json_bytes(recomputed) != derived_json_bytes(stored):
            errors.append("comparison metrics or lineage differ from recomputation")
    except (
        KeyError,
        OSError,
        PrototypeConfigurationError,
        PrototypeExperimentError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "attack": stored.get("attack"),
        "f": stored.get("f"),
        "profile_count": len(stored.get("outcomes", [])),
        "comparison_sha256": sha256_file(stored_path) if stored_path.is_file() else None,
        "verification_recomputed_model_inference": True,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
