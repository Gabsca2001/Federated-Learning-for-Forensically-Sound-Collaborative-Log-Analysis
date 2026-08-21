"""Digest-linked M6 scenario freezing, comparison, and independent verification."""

from __future__ import annotations

import copy
import hashlib
import math
from pathlib import Path
from typing import Any

import numpy as np

from . import __version__
from .byzantine import (
    ByzantineConfigurationError,
    aggregate_deltas,
    apply_delta,
    attack_delta,
    backdoor_rows,
    clip_delta_l2,
    label_flip_rows,
    model_delta,
    model_replacement_delta,
    update_indicators,
)
from .canonical import sha256_bytes, sha256_file
from .config import load_yaml
from .federated_model import (
    arrays_from_export,
    build_model,
    dependencies,
    evaluate_rows,
    export_state,
    load_ndarrays,
    train_local,
)
from .preprocessing import derived_json_bytes
from .secure_round import verify_secure_round
from .storage import load_json, write_once

ATTACKS = {
    "clean",
    "label_flip",
    "gaussian_noise",
    "sign_flip",
    "update_amplification",
    "model_replacement",
    "backdoor",
    "colluding",
}


class ByzantineExperimentError(RuntimeError):
    """Raised when M6 lineage, frozen inputs, or recomputation do not verify."""


def _write_json(path: Path, value: dict[str, Any]) -> str:
    content = derived_json_bytes(value)
    write_once(path, content)
    return sha256_bytes(content)


def _verified_snapshot_file(
    *, root: Path, relative_path: Any, expected_sha256: Any, description: str
) -> Path:
    relative = Path(str(relative_path))
    if relative.is_absolute() or ".." in relative.parts:
        raise ByzantineExperimentError(
            f"partition snapshot contains an unsafe path: {description}"
        )
    path = root / relative
    if not path.is_file():
        raise ByzantineExperimentError(
            f"partition snapshot file is missing: {description}"
        )
    if sha256_file(path) != str(expected_sha256):
        raise ByzantineExperimentError(
            f"partition snapshot digest mismatch: {description}"
        )
    return path


def _verify_partition_snapshot_files(
    *, partition_workspace: Path, partition_manifest: dict[str, Any]
) -> Path:
    records = partition_manifest.get("clients")
    if not isinstance(records, list):
        raise ByzantineExperimentError("partition manifest has no client records")
    client_ids = [str(item.get("client_id")) for item in records]
    expected_ids = [f"client{index:02d}" for index in range(1, 16)]
    if client_ids != expected_ids:
        raise ByzantineExperimentError(
            "partition manifest does not contain 15 ordered unique clients"
        )
    for item in records:
        client_id = str(item["client_id"])
        _verified_snapshot_file(
            root=partition_workspace,
            relative_path=item.get("dataset_path"),
            expected_sha256=item.get("dataset_sha256"),
            description=f"{client_id} dataset",
        )
        _verified_snapshot_file(
            root=partition_workspace,
            relative_path=item.get("manifest_path"),
            expected_sha256=item.get("manifest_sha256"),
            description=f"{client_id} manifest",
        )
    return _verified_snapshot_file(
        root=partition_workspace,
        relative_path=partition_manifest.get("server_evaluation_path"),
        expected_sha256=partition_manifest.get("server_evaluation_sha256"),
        description="server evaluation",
    )


def _model_from_export(value: dict[str, Any], *, torch: Any) -> Any:
    architecture = value["architecture"]
    model = build_model(
        input_features=int(architecture["input_features"]),
        class_count=int(architecture["classification_head_outputs"]),
        hidden_layers=[int(item) for item in architecture["encoder_hidden_layers"]],
        embedding_size=int(architecture["embedding_size"]),
        dropout=float(architecture["dropout"]),
        torch=torch,
    )
    load_ndarrays(model, arrays_from_export(value, np=np), torch=torch, np=np)
    return model


def _export_with_arrays(base: dict[str, Any], arrays: list[np.ndarray]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    if len(arrays) != len(result["parameters"]):
        raise ByzantineExperimentError("aggregated tensor count differs from base model")
    for parameter, array in zip(result["parameters"], arrays, strict=True):
        value = np.asarray(array, dtype=np.dtype(parameter["dtype"]))
        if list(value.shape) != list(parameter["shape"]):
            raise ByzantineExperimentError("aggregated tensor shape differs from base model")
        parameter["values"] = value.tolist()
    return result


def _select_attackers(client_ids: list[str], *, f: int, seed: int) -> list[str]:
    if f < 0 or f > len(client_ids):
        raise ByzantineExperimentError("f must be between zero and the client count")
    ranked = sorted(
        client_ids,
        key=lambda client_id: (
            hashlib.sha256(f"{seed}:{client_id}".encode()).hexdigest(),
            client_id,
        ),
    )
    return sorted(ranked[:f])


def _clean_clip_threshold(deltas: list[list[np.ndarray]]) -> dict[str, Any]:
    norms = np.asarray(
        [math.sqrt(sum(float(np.square(item).sum()) for item in delta)) for delta in deltas],
        dtype=np.float64,
    )
    median = float(np.median(norms))
    mad = float(np.median(np.abs(norms - median)))
    threshold = median + 3.0 * mad
    if threshold <= 0:
        threshold = float(max(norms.max(initial=0.0), 1e-12))
    return {
        "method": "verified-clean-M5-delta-median-plus-3-mad",
        "median_l2": median,
        "mad_l2": mad,
        "max_norm": threshold,
    }


def _train_data_attack(
    *,
    base: dict[str, Any],
    client_dataset: dict[str, Any],
    partition_id: int,
    context: dict[str, Any],
    training_contract: dict[str, Any],
    attack: str,
    attack_config: dict[str, Any],
    seed: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    dependency_values = dependencies()
    (
        _np,
        torch,
        _flwr,
        _sklearn,
        _aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependency_values
    rows = client_dataset["rows"]["train"]
    attack_record: dict[str, Any]
    if attack == "label_flip":
        profile = attack_config["label_flip"]
        rows, changed = label_flip_rows(
            rows,
            source_label=str(profile["source"]),
            target_label=str(profile["target"]),
        )
        attack_record = {
            "changed_row_count": changed,
            "source_label": str(profile["source"]),
            "target_label": str(profile["target"]),
        }
    elif attack == "backdoor":
        profile = attack_config["backdoor"]
        rows, selected = backdoor_rows(
            rows,
            target_label=str(profile["target"]),
            feature_indices=[int(item) for item in profile["feature_indices"]],
            trigger_value=float(profile["trigger_value"]),
            fraction=float(profile["fraction"]),
            seed=seed,
        )
        attack_record = {
            "poisoned_row_count": len(selected),
            "selected_window_ids_sha256": sha256_bytes(
                derived_json_bytes(sorted(selected))
            ),
            "target_label": str(profile["target"]),
            "feature_indices": [int(item) for item in profile["feature_indices"]],
            "trigger_value": float(profile["trigger_value"]),
            "fraction": float(profile["fraction"]),
        }
    else:
        raise ByzantineExperimentError(f"unsupported data attack: {attack}")
    model = _model_from_export(base, torch=torch)
    train_local(
        model=model,
        rows=rows,
        class_names=[str(item) for item in training_contract["class_names"]],
        class_weights={
            key: float(value)
            for key, value in training_contract["global_class_weights"].items()
        },
        epochs=int(context["core"]["local_epochs"]),
        batch_size=int(context["core"]["batch_size"]),
        learning_rate=float(context["core"]["learning_rate_decimal"]),
        seed=(
            int(context["core"]["seed"])
            + int(context["core"]["round_number"]) * 10_000
            + partition_id
        ),
        device_name="cpu",
        torch=torch,
        np=np,
        validation_rows=client_dataset["rows"].get("validation", []),
        evaluation_functions=(
            accuracy_score,
            confusion_matrix,
            precision_recall_fscore_support,
        ),
        record_history=False,
    )
    return (
        export_state(
            model,
            architecture=base["architecture"],
            class_names=[str(item) for item in base["class_names"]],
        ),
        attack_record,
    )


def freeze_byzantine_scenario(
    *,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    output: Path,
    attack: str,
    f: int,
    config_path: Path,
    attacker_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Derive and freeze one attack realization from a verified M5 round."""

    if attack not in ATTACKS:
        raise ByzantineExperimentError(f"unsupported M6 attack: {attack}")
    source_verification = verify_secure_round(
        workspace=source_round_workspace,
        trust_workspace=trust_workspace,
        submissions_root=source_round_workspace / "submissions",
    )
    if source_verification["status"] != "verified":
        raise ByzantineExperimentError(
            f"source M5 round does not verify: {source_verification['errors']}"
        )
    config, config_digest = load_yaml(config_path)
    experiment_config = config["experiment"]
    attack_config = config["attacks"]
    context_path = source_round_workspace / "public" / "round-context.json"
    base_path = source_round_workspace / "public" / "base-model.json"
    contract_path = source_round_workspace / "public" / "training-contract.json"
    partition_manifest_path = (
        source_round_workspace / "public" / "partition-manifest.json"
    )
    context = load_json(context_path)
    base = load_json(base_path)
    training_contract = load_json(contract_path)
    partition_manifest = load_json(partition_manifest_path)
    if sha256_file(partition_manifest_path) != context["core"]["partition_manifest_sha256"]:
        raise ByzantineExperimentError(
            "M5 public partition manifest differs from signed round context"
        )
    client_ids = [str(item["client_id"]) for item in context["core"]["clients"]]
    if len(client_ids) != int(experiment_config["client_count"]):
        raise ByzantineExperimentError("M6 client count differs from signed M5 context")
    partition_client_ids = [
        str(item.get("client_id")) for item in partition_manifest.get("clients", [])
    ]
    if partition_client_ids != client_ids:
        raise ByzantineExperimentError(
            "signed partition manifest client order differs from signed M5 context"
        )
    for context_client, partition_client in zip(
        context["core"]["clients"], partition_manifest["clients"], strict=True
    ):
        if (
            context_client["snapshot_sha256"] != partition_client["dataset_sha256"]
            or context_client["snapshot_manifest_sha256"]
            != partition_client["manifest_sha256"]
            or int(context_client["train_row_count"])
            != int(partition_client["train_row_count"])
        ):
            raise ByzantineExperimentError(
                f"signed M5 client snapshot binding mismatch: {context_client['client_id']}"
            )
    _verify_partition_snapshot_files(
        partition_workspace=partition_workspace,
        partition_manifest=partition_manifest,
    )
    seed = int(experiment_config["seed"])
    selected_attackers = (
        _select_attackers(client_ids, f=f, seed=seed)
        if attacker_ids is None
        else sorted(str(item) for item in attacker_ids)
    )
    if len(selected_attackers) != f or not set(selected_attackers).issubset(client_ids):
        raise ByzantineExperimentError("attacker identities must be f unique M5 clients")
    if attack == "clean" and f != 0:
        raise ByzantineExperimentError("clean scenario requires f=0")
    if attack != "clean" and f == 0:
        raise ByzantineExperimentError("an attack scenario requires f>0")

    base_arrays = arrays_from_export(base, np=np)
    clean_updates: dict[str, dict[str, Any]] = {}
    clean_deltas: dict[str, list[np.ndarray]] = {}
    source_records: dict[str, dict[str, Any]] = {}
    for client_id in client_ids:
        submission = source_round_workspace / "submissions" / client_id
        bundle_path = submission / "bundle.json"
        update_path = submission / "update.json"
        bundle = load_json(bundle_path)
        update = load_json(update_path)
        if bundle["core"]["update_sha256"] != sha256_file(update_path):
            raise ByzantineExperimentError(f"signed source update mismatch: {client_id}")
        clean_updates[client_id] = update
        clean_deltas[client_id] = model_delta(
            base_arrays, arrays_from_export(update, np=np)
        )
        source_records[client_id] = {
            "bundle_sha256": sha256_file(bundle_path),
            "update_sha256": sha256_file(update_path),
            "num_examples": int(bundle["core"]["num_examples"]),
        }
    threshold = _clean_clip_threshold([clean_deltas[item] for item in client_ids])
    collusion_template = (
        clean_deltas[selected_attackers[0]] if selected_attackers else None
    )
    records: list[dict[str, Any]] = []
    for client_id in client_ids:
        attacked = client_id in selected_attackers
        derivation: dict[str, Any] = {"attack": attack if attacked else "clean"}
        if not attacked or attack == "clean":
            frozen_update = clean_updates[client_id]
        elif attack in {"gaussian_noise", "sign_flip", "update_amplification"}:
            scale_key = {
                "gaussian_noise": "gaussian_noise_scale",
                "sign_flip": "sign_flip_scale",
                "update_amplification": "model_replacement_scale",
            }[attack]
            scale = float(attack_config[scale_key])
            transformed = attack_delta(
                clean_deltas[client_id],
                attack=attack,
                seed=seed + int(client_id[-2:]),
                scale=scale,
            )
            frozen_update = _export_with_arrays(base, apply_delta(base_arrays, transformed))
            derivation["scale"] = scale
        elif attack == "model_replacement":
            client_record = next(
                item
                for item in partition_manifest["clients"]
                if item["client_id"] == client_id
            )
            client_dataset = load_json(
                partition_workspace / str(client_record["dataset_path"])
            )
            objective = attack_config["model_replacement"]["objective"]
            malicious_update, detail = _train_data_attack(
                base=base,
                client_dataset=client_dataset,
                partition_id=int(client_record["partition_id"]),
                context=context,
                training_contract=training_contract,
                attack="label_flip",
                attack_config={**attack_config, "label_flip": objective},
                seed=seed + int(client_id[-2:]),
            )
            if int(detail["changed_row_count"]) == 0:
                raise ByzantineExperimentError(
                    f"model replacement objective changed no rows: {client_id}"
                )
            scale = float(attack_config["model_replacement_scale"])
            replacement = model_replacement_delta(
                base_arrays,
                arrays_from_export(malicious_update, np=np),
                scale=scale,
            )
            frozen_update = _export_with_arrays(
                base, apply_delta(base_arrays, replacement)
            )
            derivation.update(
                {
                    "objective": str(objective["type"]),
                    "scale": scale,
                    **detail,
                }
            )
        elif attack == "colluding":
            assert collusion_template is not None
            scale = float(attack_config["model_replacement_scale"])
            frozen_update = _export_with_arrays(
                base,
                apply_delta(
                    base_arrays,
                    [np.asarray(item) * scale for item in collusion_template],
                ),
            )
            derivation.update(
                {"scale": scale, "template_client_id": selected_attackers[0]}
            )
        elif attack in {"label_flip", "backdoor"}:
            client_record = next(
                item for item in partition_manifest["clients"] if item["client_id"] == client_id
            )
            client_dataset = load_json(
                partition_workspace / str(client_record["dataset_path"])
            )
            frozen_update, detail = _train_data_attack(
                base=base,
                client_dataset=client_dataset,
                partition_id=int(client_record["partition_id"]),
                context=context,
                training_contract=training_contract,
                attack=attack,
                attack_config=attack_config,
                seed=seed + int(client_id[-2:]),
            )
            derivation.update(detail)
        else:  # pragma: no cover
            raise ByzantineExperimentError(f"unsupported attack derivation: {attack}")
        relative = Path("updates") / client_id / "model-update.json"
        frozen_digest = _write_json(output / relative, frozen_update)
        records.append(
            {
                "client_id": client_id,
                "attacker": attacked,
                "derivation": derivation,
                "source_bundle_sha256": source_records[client_id]["bundle_sha256"],
                "source_update_sha256": source_records[client_id]["update_sha256"],
                "frozen_update_path": relative.as_posix(),
                "frozen_update_sha256": frozen_digest,
                "num_examples": source_records[client_id]["num_examples"],
            }
        )
    _write_json(output / "base-model.json", base)
    frozen_partition_path = output / "source-partition-manifest.json"
    write_once(frozen_partition_path, partition_manifest_path.read_bytes())
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "m6_frozen_byzantine_update_set",
        "code_version": __version__,
        "attack": attack,
        "f": f,
        "seed": seed,
        "attacker_ids": selected_attackers,
        "source_semantics": (
            "controlled derivation from verified M5 updates; a runtime-compromised client "
            "would apply the same transformation before hashing and TPM signing"
        ),
        "source_round_context_sha256": sha256_file(context_path),
        "source_round_checkpoint_sha256": sha256_file(
            source_round_workspace / "checkpoint" / "manifest.json"
        ),
        "base_model_sha256": sha256_file(output / "base-model.json"),
        "partition_manifest_path": "source-partition-manifest.json",
        "partition_manifest_sha256": sha256_file(partition_manifest_path),
        "byzantine_config_sha256": config_digest,
        "implementation_sha256": sha256_file(Path(__file__)),
        "clip_threshold": threshold,
        "clients": records,
    }
    manifest_digest = _write_json(output / "manifest.json", manifest)
    return {
        "status": "frozen",
        "attack": attack,
        "f": f,
        "client_count": len(records),
        "attacker_ids": selected_attackers,
        "manifest_sha256": manifest_digest,
        "workspace": str(output),
    }


def verify_frozen_update_set(*, workspace: Path) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = workspace / "manifest.json"
    if not manifest_path.is_file():
        return {
            "status": "failed",
            "error_count": 1,
            "errors": ["missing frozen-update manifest"],
            "workspace": str(workspace),
        }
    manifest = load_json(manifest_path)
    if manifest.get("artifact_type") != "m6_frozen_byzantine_update_set":
        errors.append("unexpected frozen-update artifact type")
    base_path = workspace / "base-model.json"
    if not base_path.is_file() or sha256_file(base_path) != manifest.get(
        "base_model_sha256"
    ):
        errors.append("frozen base model digest mismatch")
    partition_manifest_relative = manifest.get("partition_manifest_path")
    if partition_manifest_relative is not None:
        try:
            _verified_snapshot_file(
                root=workspace,
                relative_path=partition_manifest_relative,
                expected_sha256=manifest.get("partition_manifest_sha256"),
                description="frozen source partition manifest",
            )
        except ByzantineExperimentError as exc:
            errors.append(str(exc))
    clients = manifest.get("clients", [])
    identities = [item.get("client_id") for item in clients]
    if len(identities) != 15 or len(set(identities)) != 15 or identities != sorted(identities):
        errors.append("frozen update set does not contain 15 ordered unique clients")
    for item in clients:
        path = workspace / str(item.get("frozen_update_path", ""))
        if not path.is_file() or sha256_file(path) != item.get("frozen_update_sha256"):
            errors.append(f"frozen update digest mismatch: {item.get('client_id')}")
    attackers = sorted(item["client_id"] for item in clients if item.get("attacker"))
    if attackers != manifest.get("attacker_ids") or len(attackers) != int(
        manifest.get("f", -1)
    ):
        errors.append("frozen attacker set/f binding mismatch")
    return {
        "status": "verified" if not errors else "failed",
        "attack": manifest.get("attack"),
        "f": manifest.get("f"),
        "client_count": len(clients),
        "manifest_sha256": sha256_file(manifest_path),
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }


def _evaluate_export(
    *, model_export: dict[str, Any], server_evaluation: dict[str, Any], batch_size: int
) -> dict[str, Any]:
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
    return {
        split: evaluate_rows(
            model=model,
            rows=server_evaluation["rows"][split],
            class_names=[str(item) for item in model_export["class_names"]],
            batch_size=batch_size,
            torch=torch,
            np=np,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        )
        for split in ("validation", "test", "temporal_holdout")
    }


def _evaluate_export_rows(
    *, model_export: dict[str, Any], rows: list[dict[str, Any]], batch_size: int
) -> dict[str, Any]:
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
    return evaluate_rows(
        model=model,
        rows=rows,
        class_names=[str(item) for item in model_export["class_names"]],
        batch_size=batch_size,
        torch=torch,
        np=np,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )


def _backdoor_evaluation_contract(
    *,
    manifest: dict[str, Any],
    server_evaluation: dict[str, Any],
    base: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    profiles: list[dict[str, Any]] = []
    for record in manifest["clients"]:
        if not record.get("attacker"):
            continue
        derivation = record.get("derivation", {})
        if derivation.get("attack") != "backdoor":
            raise ByzantineExperimentError(
                f"backdoor attacker has a different derivation: {record['client_id']}"
            )
        profiles.append(
            {
                "target_label": str(derivation["target_label"]),
                "feature_indices": [
                    int(item) for item in derivation["feature_indices"]
                ],
                "trigger_value": float(derivation["trigger_value"]),
                "training_poison_fraction": float(derivation["fraction"]),
            }
        )
    if not profiles:
        raise ByzantineExperimentError("backdoor scenario has no attacker profile")
    profile = profiles[0]
    if any(
        derived_json_bytes(item) != derived_json_bytes(profile)
        for item in profiles[1:]
    ):
        raise ByzantineExperimentError(
            "backdoor attackers do not share one frozen trigger contract"
        )
    target_label = profile["target_label"]
    if target_label not in [str(item) for item in base["class_names"]]:
        raise ByzantineExperimentError(
            "backdoor target label is outside the frozen model classes"
        )
    feature_indices = profile["feature_indices"]
    if not feature_indices or len(set(feature_indices)) != len(feature_indices):
        raise ByzantineExperimentError(
            "backdoor evaluation feature indices must be non-empty and unique"
        )
    source_rows = [
        copy.deepcopy(row)
        for row in server_evaluation["rows"]["test"]
        if str(row.get("label")) != target_label
    ]
    if not source_rows:
        raise ByzantineExperimentError(
            "backdoor evaluation has no non-target test rows"
        )
    original_label_counts: dict[str, int] = {}
    triggered_rows = copy.deepcopy(source_rows)
    for row in triggered_rows:
        original_label = str(row.get("label"))
        original_label_counts[original_label] = (
            original_label_counts.get(original_label, 0) + 1
        )
        features = row.get("features", [])
        if any(index < 0 or index >= len(features) for index in feature_indices):
            raise ByzantineExperimentError(
                "backdoor trigger index is outside a server test feature vector"
            )
        for feature_index in feature_indices:
            features[feature_index] = profile["trigger_value"]
        row["label"] = target_label
    contract = {
        **profile,
        "source_split": "test",
        "eligibility": "original_label != target_label",
        "metric": "predicted_target_count / triggered_non_target_row_count",
        "triggered_row_count": len(triggered_rows),
        "original_label_counts": dict(sorted(original_label_counts.items())),
        "eligible_source_rows_sha256": sha256_bytes(
            derived_json_bytes(source_rows)
        ),
        "triggered_rows_sha256": sha256_bytes(
            derived_json_bytes(triggered_rows)
        ),
    }
    return triggered_rows, contract


def _compute_comparison(
    *,
    frozen_workspace: Path,
    partition_workspace: Path,
    config_path: Path,
    include_validation_impact: bool = True,
    include_backdoor_evaluation: bool = True,
    include_backdoor_client_impact: bool = True,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    verification = verify_frozen_update_set(workspace=frozen_workspace)
    if verification["status"] != "verified":
        raise ByzantineExperimentError(f"frozen inputs do not verify: {verification['errors']}")
    config, config_digest = load_yaml(config_path)
    manifest = load_json(frozen_workspace / "manifest.json")
    partition_manifest_relative = manifest.get("partition_manifest_path")
    partition_manifest_path = (
        frozen_workspace / str(partition_manifest_relative)
        if partition_manifest_relative is not None
        else partition_workspace / "manifest.json"
    )
    if sha256_file(partition_manifest_path) != manifest["partition_manifest_sha256"]:
        raise ByzantineExperimentError("frozen partition manifest digest mismatch")
    partition_manifest = load_json(partition_manifest_path)
    if partition_manifest_relative is not None:
        server_path = _verify_partition_snapshot_files(
            partition_workspace=partition_workspace,
            partition_manifest=partition_manifest,
        )
    else:
        server_path = _verified_snapshot_file(
            root=partition_workspace,
            relative_path=partition_manifest.get("server_evaluation_path"),
            expected_sha256=partition_manifest.get("server_evaluation_sha256"),
            description="legacy server evaluation",
        )
    server_evaluation = load_json(server_path)
    base = load_json(frozen_workspace / "base-model.json")
    base_arrays = arrays_from_export(base, np=np)
    records = manifest["clients"]
    frozen_updates = [
        load_json(frozen_workspace / item["frozen_update_path"]) for item in records
    ]
    deltas = [
        model_delta(
            base_arrays,
            arrays_from_export(update, np=np),
        )
        for update in frozen_updates
    ]
    indicators = update_indicators(
        deltas, client_ids=[str(item["client_id"]) for item in records]
    )
    validation_impact_reference: dict[str, Any] | None = None
    if include_validation_impact:
        base_validation_f1 = float(
            _evaluate_export(
                model_export=base,
                server_evaluation=server_evaluation,
                batch_size=128,
            )["validation"]["macro_f1_all_model_classes"]
        )
        for indicator, update in zip(indicators, frozen_updates, strict=True):
            client_validation_f1 = float(
                _evaluate_export(
                    model_export=update,
                    server_evaluation=server_evaluation,
                    batch_size=128,
                )["validation"]["macro_f1_all_model_classes"]
            )
            indicator["validation_macro_f1"] = client_validation_f1
            indicator["validation_impact"] = base_validation_f1 - client_validation_f1
        validation_impact_reference = {
            "metric": "base_validation_macro_f1_minus_client_validation_macro_f1",
            "base_validation_macro_f1": base_validation_f1,
        }
    backdoor_rows_for_evaluation: list[dict[str, Any]] | None = None
    backdoor_evaluation: dict[str, Any] | None = None
    if include_backdoor_evaluation and manifest["attack"] == "backdoor":
        backdoor_rows_for_evaluation, backdoor_evaluation = (
            _backdoor_evaluation_contract(
                manifest=manifest,
                server_evaluation=server_evaluation,
                base=base,
            )
        )
        base_triggered = _evaluate_export_rows(
            model_export=base, rows=backdoor_rows_for_evaluation, batch_size=128
        )
        backdoor_evaluation["base_model_attack_success_rate"] = float(
            base_triggered["accuracy"]
        )
        if include_backdoor_client_impact:
            baseline_asr = float(
                backdoor_evaluation["base_model_attack_success_rate"]
            )
            for indicator, update in zip(
                indicators, frozen_updates, strict=True
            ):
                client_triggered = _evaluate_export_rows(
                    model_export=update,
                    rows=backdoor_rows_for_evaluation,
                    batch_size=128,
                )
                client_asr = float(client_triggered["accuracy"])
                indicator["backdoor_attack_success_rate"] = client_asr
                indicator["backdoor_attack_success_rate_lift"] = (
                    client_asr - baseline_asr
                )
    threshold = float(manifest["clip_threshold"]["max_norm"])
    clipped: list[list[np.ndarray]] = []
    clip_scales: list[float] = []
    for delta in deltas:
        value, scale = clip_delta_l2(delta, max_norm=threshold)
        clipped.append(value)
        clip_scales.append(scale)
    strategies = [str(item) for item in config["defenses"]["aggregators"]]
    clipping_enabled = bool(config["defenses"]["clipping"]["enabled"])
    f = int(manifest["f"])
    weights = [int(item["num_examples"]) for item in records]
    models: dict[str, dict[str, Any]] = {}
    outcomes: list[dict[str, Any]] = []
    for strategy in strategies:
        for use_clipping in ([False, True] if clipping_enabled else [False]):
            profile_id = f"{strategy}{'-clipped' if use_clipping else ''}"
            aggregate = aggregate_deltas(
                clipped if use_clipping else deltas,
                strategy=strategy,
                f=f,
                weights=weights if strategy == "fedavg" else None,
            )
            model_export = _export_with_arrays(base, apply_delta(base_arrays, aggregate))
            models[profile_id] = model_export
            evaluation = _evaluate_export(
                model_export=model_export,
                server_evaluation=server_evaluation,
                batch_size=128,
            )
            outcome = {
                "profile_id": profile_id,
                "aggregator": strategy,
                "clipping": use_clipping,
                "validation_macro_f1": evaluation["validation"][
                    "macro_f1_all_model_classes"
                ],
                "test_macro_f1": evaluation["test"]["macro_f1_all_model_classes"],
                "temporal_holdout_accuracy": evaluation["temporal_holdout"][
                    "accuracy"
                ],
                "evaluation": evaluation,
            }
            if (
                backdoor_rows_for_evaluation is not None
                and backdoor_evaluation is not None
            ):
                triggered = _evaluate_export_rows(
                    model_export=model_export,
                    rows=backdoor_rows_for_evaluation,
                    batch_size=128,
                )
                attack_success_rate = float(triggered["accuracy"])
                outcome["backdoor_attack_success_rate"] = attack_success_rate
                outcome["backdoor_attack_success_rate_lift"] = (
                    attack_success_rate
                    - float(backdoor_evaluation["base_model_attack_success_rate"])
                )
                outcome["backdoor_targeted_evaluation"] = triggered
            outcomes.append(outcome)
    if backdoor_evaluation is not None:
        schema_version = (
            "1.3" if include_backdoor_client_impact else "1.2"
        )
    else:
        schema_version = "1.1" if include_validation_impact else "1.0"
    comparison = {
        "schema_version": schema_version,
        "artifact_type": "m6_byzantine_aggregator_comparison",
        "attack": manifest["attack"],
        "f": f,
        "seed": int(manifest["seed"]),
        "attacker_ids": manifest["attacker_ids"],
        "frozen_manifest_sha256": sha256_file(frozen_workspace / "manifest.json"),
        "partition_manifest_sha256": sha256_file(partition_manifest_path),
        "server_evaluation_sha256": sha256_file(server_path),
        "byzantine_config_sha256": config_digest,
        "same_frozen_input_order": [str(item["client_id"]) for item in records],
        "clip_threshold": manifest["clip_threshold"],
        "clip_scales": {
            str(item["client_id"]): scale
            for item, scale in zip(records, clip_scales, strict=True)
        },
        "indicators": indicators,
        "outcomes": outcomes,
    }
    if validation_impact_reference is not None:
        comparison["validation_impact_reference"] = validation_impact_reference
    if backdoor_evaluation is not None:
        comparison["backdoor_evaluation"] = backdoor_evaluation
    return comparison, models


def run_byzantine_comparison(
    *,
    frozen_workspace: Path,
    partition_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    comparison, models = _compute_comparison(
        frozen_workspace=frozen_workspace,
        partition_workspace=partition_workspace,
        config_path=config_path,
    )
    model_records: list[dict[str, Any]] = []
    for profile_id in sorted(models):
        relative = Path("models") / f"{profile_id}.json"
        digest = _write_json(output / relative, models[profile_id])
        model_records.append(
            {
                "profile_id": profile_id,
                "model_path": relative.as_posix(),
                "model_sha256": digest,
            }
        )
    comparison["models"] = model_records
    comparison_digest = _write_json(output / "comparison.json", comparison)
    best = max(
        comparison["outcomes"],
        key=lambda item: (float(item["validation_macro_f1"]), item["profile_id"]),
    )
    return {
        "status": "compared",
        "attack": comparison["attack"],
        "f": comparison["f"],
        "profile_count": len(comparison["outcomes"]),
        "best_validation_profile": best["profile_id"],
        "best_validation_macro_f1": best["validation_macro_f1"],
        "best_profile_test_macro_f1": best["test_macro_f1"],
        "comparison_sha256": comparison_digest,
        "workspace": str(output),
    }


def verify_byzantine_comparison(
    *,
    frozen_workspace: Path,
    partition_workspace: Path,
    workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    stored_path = workspace / "comparison.json"
    if not stored_path.is_file():
        return {
            "status": "failed",
            "error_count": 1,
            "errors": ["missing M6 comparison.json"],
            "workspace": str(workspace),
        }
    stored = load_json(stored_path)
    try:
        schema_version = str(stored.get("schema_version", "1.0"))
        if schema_version not in {"1.0", "1.1", "1.2", "1.3"}:
            raise ByzantineExperimentError(
                f"unsupported M6 comparison schema: {schema_version}"
            )
        recomputed, models = _compute_comparison(
            frozen_workspace=frozen_workspace,
            partition_workspace=partition_workspace,
            config_path=config_path,
            include_validation_impact=schema_version in {"1.1", "1.2", "1.3"},
            include_backdoor_evaluation=schema_version in {"1.2", "1.3"},
            include_backdoor_client_impact=schema_version == "1.3",
        )
        model_records = stored.get("models", [])
        if [item.get("profile_id") for item in model_records] != sorted(models):
            errors.append("comparison model profile set mismatch")
        for record in model_records:
            path = workspace / str(record.get("model_path", ""))
            expected_bytes = derived_json_bytes(models[str(record["profile_id"])])
            if (
                not path.is_file()
                or sha256_file(path) != record.get("model_sha256")
                or path.read_bytes() != expected_bytes
            ):
                errors.append(f"comparison model mismatch: {record.get('profile_id')}")
        recomputed["models"] = model_records
        if derived_json_bytes(recomputed) != derived_json_bytes(stored):
            errors.append("comparison metrics or lineage differ from recomputation")
    except (
        ByzantineConfigurationError,
        ByzantineExperimentError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "attack": stored.get("attack"),
        "f": stored.get("f"),
        "profile_count": len(stored.get("outcomes", [])),
        "comparison_sha256": sha256_file(stored_path),
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
