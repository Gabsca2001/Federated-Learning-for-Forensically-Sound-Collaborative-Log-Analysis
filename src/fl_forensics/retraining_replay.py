"""Controlled CPU FedAvg replay with genuine local training in every round.

This is an analyst-signed experimental trajectory, not newly attested clients.
Adam is reset for each local call, matching the existing training implementation.
"""

from __future__ import annotations

import copy
import importlib.metadata
import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator

from .campaign_derivation import _pinned
from .canonical import sha256_bytes, sha256_file
from .crypto import DigestSigner
from .federated_model import (
    arrays_from_export,
    dependencies,
    evaluate_rows,
    export_state,
    train_local,
)
from .models import HEX_256_PATTERN, SignatureBlock, StrictModel, _require_utc
from .preprocessing import derived_json_bytes
from .round_derivation import _signed, _verify_signature, implementation_sha256
from .secure_round import _model_from_export
from .storage import write_json_once, write_once


def _replay_device() -> str:
    """Local-training device; CPU unless FL_FORENSICS_REPLAY_DEVICE overrides it.

    Non-CPU execution is not bit-reproducible and is not reflected in the signed
    protocol label, so callers must record the actual device separately.
    """
    import os

    return os.environ.get("FL_FORENSICS_REPLAY_DEVICE", "cpu")


class RetrainingReplayError(ValueError):
    """The pinned experimental replay protocol cannot be reproduced."""


class RetrainingPlan(StrictModel):
    protocol: Literal["controlled-offline-cpu-fedavg-v1"] = "controlled-offline-cpu-fedavg-v1"
    rounds: int = Field(gt=0)
    seed: int = Field(ge=0)
    local_epochs: int = Field(gt=0)
    batch_size: int = Field(gt=0)
    learning_rate_decimal: str
    minimum_contributors: int = Field(gt=0)
    clients: list[str] = Field(min_length=1)
    remove_at_round: dict[str, list[str]] = Field(default_factory=dict)
    optimizer_state: Literal["fresh-Adam-per-client-per-round"] = "fresh-Adam-per-client-per-round"
    seed_schedule: Literal["seed+round*10000+partition_id"] = "seed+round*10000+partition_id"
    cpu_threads: Literal[1] = 1

    @field_validator("clients")
    @classmethod
    def ordered_clients(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("replay clients must be unique and sorted")
        if any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", client) is None for client in value
        ):
            raise ValueError("unsafe replay client identifier")
        return value


class RetrainingReplayCore(StrictModel):
    domain: Literal["fl-retraining-replay-v1"] = "fl-retraining-replay-v1"
    plan: RetrainingPlan
    base_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    partition_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    validation_split_sha256: str = Field(pattern=HEX_256_PATTERN)
    training_snapshot_sha256: dict[str, str]
    artifacts: dict[str, str]
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    environment: dict[str, str]
    created_at: str
    fresh_attestation_performed: Literal[False] = False
    future_historical_updates_reused: Literal[False] = False

    _created_utc = field_validator("created_at")(_require_utc)


class RetrainingReplayManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["retraining_replay_manifest"] = "retraining_replay_manifest"
    manifest_id: str
    core: RetrainingReplayCore
    core_digest: str = Field(pattern=HEX_256_PATTERN)
    signature: SignatureBlock


def _read(path: Path, expected: str) -> bytes:
    data = path.read_bytes()
    if sha256_bytes(data) != expected:
        raise RetrainingReplayError(f"changed pinned replay input: {path}")
    return data


def _replay(
    *,
    plan: RetrainingPlan,
    base_model_path: Path,
    expected_base_sha256: str,
    partition_workspace: Path,
    expected_partition_sha256: str,
    validation_split_path: Path,
    expected_validation_sha256: str,
) -> tuple[dict[str, bytes], dict[str, str], dict[str, str]]:
    from decimal import Decimal

    plan = RetrainingPlan.model_validate(plan.model_dump(mode="json"))
    rate = Decimal(plan.learning_rate_decimal)
    if not rate.is_finite() or rate <= 0 or not math.isfinite(float(rate)) or not float(rate) > 0:
        raise RetrainingReplayError("learning rate must be finite and positive")
    if plan.minimum_contributors > len(plan.clients):
        raise RetrainingReplayError("quorum exceeds the declared client population")
    for key, removed in plan.remove_at_round.items():
        if (
            key != str(int(key))
            or not 1 <= int(key) <= plan.rounds
            or len(set(removed)) != len(removed)
            or set(removed) - set(plan.clients)
        ):
            raise RetrainingReplayError("invalid removal schedule")
    model_export = json.loads(_read(base_model_path, expected_base_sha256))
    partition = json.loads(_read(partition_workspace / "manifest.json", expected_partition_sha256))
    validation = json.loads(_read(validation_split_path, expected_validation_sha256))
    classes = model_export["class_names"]
    if (
        partition["class_names"] != classes
        or validation.get("class_names") != classes
        or validation.get("split") != "validation"
    ):
        raise RetrainingReplayError("class order/validation split differs from the model")
    validation_rows = validation["rows"]["validation"]
    if not validation_rows:
        raise RetrainingReplayError("validation split is empty")
    records = {record["client_id"]: record for record in partition["clients"]}
    if len(records) != len(partition["clients"]) or set(plan.clients) - set(records):
        raise RetrainingReplayError("unknown or ambiguous replay client")
    snapshots, snapshot_hashes, partition_ids = {}, {}, {}
    for client in plan.clients:
        record = records[client]
        path = partition_workspace / record["dataset_path"]
        if not path.resolve().is_relative_to(partition_workspace.resolve()):
            raise RetrainingReplayError("snapshot path escapes partition workspace")
        snapshot = json.loads(_read(path, record["dataset_sha256"]))
        if (
            snapshot["client_id"] != client
            or snapshot["class_names"] != classes
            or len(snapshot["rows"]["train"]) != record["train_row_count"]
            or not snapshot["rows"]["train"]
        ):
            raise RetrainingReplayError("training snapshot/client mismatch")
        snapshots[client] = snapshot["rows"]["train"]
        snapshot_hashes[client] = record["dataset_sha256"]
        partition_ids[client] = int(record["partition_id"])
    if len(set(partition_ids.values())) != len(partition_ids):
        raise RetrainingReplayError("duplicate seed partition identifier")
    (
        np,
        torch,
        _flwr,
        _sklearn,
        aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependencies()
    for rows in [validation_rows, *snapshots.values()]:
        if any(
            row["label"] not in classes
            or len(row["features"]) != model_export["architecture"]["input_features"]
            or not np.isfinite(np.asarray(row["features"], dtype=np.float32)).all()
            for row in rows
        ):
            raise RetrainingReplayError("invalid training/evaluation feature row")
    weights = {label: float(partition["global_class_weights"][label]) for label in classes}
    if any(not np.isfinite(weight) or weight <= 0 for weight in weights.values()):
        raise RetrainingReplayError("invalid frozen class weights")
    environment = {
        name: importlib.metadata.version(name)
        for name in ("numpy", "torch", "flwr", "scikit-learn")
    }
    files = {}
    old_threads = torch.get_num_threads()
    try:
        torch.set_num_threads(plan.cpu_threads)
        for number in range(1, plan.rounds + 1):
            prefix = f"rounds/round-{number:03d}"
            selected = [
                client
                for client in plan.clients
                if client not in plan.remove_at_round.get(str(number), [])
            ]
            training = []
            base_hash = sha256_bytes(derived_json_bytes(model_export))
            if len(selected) < plan.minimum_contributors:
                files[f"{prefix}/round.json"] = derived_json_bytes(
                    {
                        "round_number": number,
                        "status": "failed_without_model",
                        "base_model_sha256": base_hash,
                        "selected_clients": selected,
                        "local_training_runs": [],
                        "reason": "insufficient contributors under the declared replay contract",
                    }
                )
                break
            updates = []
            for client in selected:
                model = _model_from_export(model_export, torch=torch, np=np)
                seed = plan.seed + number * 10_000 + partition_ids[client]
                metrics = train_local(
                    model=model,
                    rows=snapshots[client],
                    class_names=classes,
                    class_weights=weights,
                    epochs=plan.local_epochs,
                    batch_size=plan.batch_size,
                    learning_rate=float(rate),
                    seed=seed,
                    device_name=_replay_device(),
                    torch=torch,
                    np=np,
                )
                local = export_state(
                    model, architecture=model_export["architecture"], class_names=classes
                )
                data = derived_json_bytes(local)
                files[f"{prefix}/updates/{client}.json"] = data
                updates.append((arrays_from_export(local, np=np), len(snapshots[client])))
                training.append(
                    {
                        "client_id": client,
                        "seed": seed,
                        "base_model_sha256": base_hash,
                        "training_snapshot_sha256": snapshot_hashes[client],
                        "local_model_sha256": sha256_bytes(data),
                        "metrics": metrics,
                    }
                )
            averaged = aggregate(updates)
            model_export = copy.deepcopy(model_export)
            for parameter, array in zip(model_export["parameters"], averaged, strict=True):
                parameter["values"] = np.asarray(array, dtype=np.dtype(parameter["dtype"])).tolist()
            model_data = derived_json_bytes(model_export)
            evaluation = evaluate_rows(
                model=_model_from_export(model_export, torch=torch, np=np),
                rows=validation_rows,
                class_names=classes,
                batch_size=plan.batch_size,
                torch=torch,
                np=np,
                accuracy_score=accuracy_score,
                confusion_matrix=confusion_matrix,
                precision_recall_fscore_support=precision_recall_fscore_support,
            )
            files[f"{prefix}/model.json"] = model_data
            files[f"{prefix}/evaluation.json"] = derived_json_bytes(evaluation)
            files[f"{prefix}/round.json"] = derived_json_bytes(
                {
                    "round_number": number,
                    "status": "aggregated",
                    "base_model_sha256": base_hash,
                    "selected_clients": selected,
                    "local_training_runs": training,
                    "global_model_sha256": sha256_bytes(model_data),
                    "total_examples": sum(count for _arrays, count in updates),
                }
            )
    finally:
        torch.set_num_threads(old_threads)
    return files, snapshot_hashes, environment


def create_retraining_replay(
    *,
    output: Path,
    plan: RetrainingPlan,
    base_model_path: Path,
    expected_base_sha256: str,
    partition_workspace: Path,
    expected_partition_sha256: str,
    validation_split_path: Path,
    expected_validation_sha256: str,
    signer: DigestSigner,
    authority_public_key: Any,
) -> dict[str, Any]:
    if output.resolve().is_relative_to(partition_workspace.resolve()):
        raise RetrainingReplayError("keep replay outputs outside source partitions")
    files, snapshots, environment = _replay(
        plan=plan,
        base_model_path=base_model_path,
        expected_base_sha256=expected_base_sha256,
        partition_workspace=partition_workspace,
        expected_partition_sha256=expected_partition_sha256,
        validation_split_path=validation_split_path,
        expected_validation_sha256=expected_validation_sha256,
    )
    path = output / "manifest.json"
    previous = (
        RetrainingReplayManifest.model_validate_json(path.read_bytes()) if path.exists() else None
    )
    if previous is not None:
        _verify_signature(previous, authority_public_key, "manifest_id", "retraining-replay-")
    core = RetrainingReplayCore(
        plan=plan,
        base_model_sha256=expected_base_sha256,
        partition_manifest_sha256=expected_partition_sha256,
        validation_split_sha256=expected_validation_sha256,
        training_snapshot_sha256=snapshots,
        artifacts={name: sha256_bytes(data) for name, data in sorted(files.items())},
        implementation_sha256=implementation_sha256(),
        environment=environment,
        created_at=previous.core.created_at
        if previous
        else datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )
    if previous is not None and previous.core != core:
        raise RetrainingReplayError(
            "existing replay has different inputs, outputs, or implementation"
        )
    manifest = previous or _signed(
        RetrainingReplayManifest, core, "manifest_id", "retraining-replay-", signer
    )
    _verify_signature(manifest, authority_public_key, "manifest_id", "retraining-replay-")
    for name, data in sorted(files.items()):
        write_once(output / name, data)
    write_json_once(path, manifest.model_dump(mode="json"))
    round_records = [
        json.loads(data) for name, data in sorted(files.items()) if name.endswith("/round.json")
    ]
    return {
        "status": "created",
        "manifest_sha256": sha256_file(path),
        "manifest_id": manifest.manifest_id,
        "actual_local_training_runs": sum(
            len(record["local_training_runs"]) for record in round_records
        ),
        "completed_aggregated_rounds": sum(
            record["status"] == "aggregated" for record in round_records
        ),
        "terminated_without_model": round_records[-1]["status"] != "aggregated",
        "protocol": plan.protocol,
        "new_attestation_performed": False,
    }


def verify_retraining_replay(
    *,
    workspace: Path,
    expected_sha256: str,
    base_model_path: Path,
    partition_workspace: Path,
    validation_split_path: Path,
    authority_public_key: Any,
) -> dict[str, Any]:
    try:
        manifest = _pinned(workspace / "manifest.json", expected_sha256, RetrainingReplayManifest)
        _verify_signature(manifest, authority_public_key, "manifest_id", "retraining-replay-")
        if manifest.core.implementation_sha256 != implementation_sha256():
            raise RetrainingReplayError("use the preserved source release to recompute this replay")
        files, snapshots, environment = _replay(
            plan=manifest.core.plan,
            base_model_path=base_model_path,
            expected_base_sha256=manifest.core.base_model_sha256,
            partition_workspace=partition_workspace,
            expected_partition_sha256=manifest.core.partition_manifest_sha256,
            validation_split_path=validation_split_path,
            expected_validation_sha256=manifest.core.validation_split_sha256,
        )
        if (
            snapshots != manifest.core.training_snapshot_sha256
            or environment != manifest.core.environment
            or {name: sha256_bytes(data) for name, data in sorted(files.items())}
            != manifest.core.artifacts
        ):
            raise RetrainingReplayError("retraining trajectory does not reproduce")
        actual_names = {
            path.relative_to(workspace).as_posix()
            for path in workspace.rglob("*")
            if path.is_file()
        }
        if actual_names != {"manifest.json", *files}:
            raise RetrainingReplayError("missing or unexpected replay artifact")
        for name, data in files.items():
            if (workspace / name).read_bytes() != data:
                raise RetrainingReplayError(f"replay artifact does not reproduce: {name}")
        return {
            "status": "verified",
            "training_reexecuted": True,
            "future_historical_updates_reused": False,
            "reproduced_files": len(files),
            "protocol": manifest.core.plan.protocol,
        }
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
        return {"status": "failed", "errors": [str(exc)]}
