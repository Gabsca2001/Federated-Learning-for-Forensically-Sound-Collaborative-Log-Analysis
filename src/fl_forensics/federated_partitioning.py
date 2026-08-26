"""Deterministic IID/non-IID client snapshots for the M3 federation."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_bytes, sha256_file
from .class_weighting import compute_class_weights
from .config import load_yaml
from .dataset24 import DATASET_NAME
from .dataset24 import verify_workspace as verify_m2_workspace
from .preprocessing import derived_json_bytes
from .storage import write_once


class FederatedPartitionError(ValueError):
    """Raised when an M3 partition contract cannot be satisfied."""


def _numpy() -> Any:
    try:
        import numpy as np
    except ImportError as exc:
        raise RuntimeError(
            'M3 partitioning requires: python -m pip install -e ".[federated]"'
        ) from exc
    return np


def _scaled_row(row: dict[str, Any], means: Any, scales: Any, np: Any) -> dict[str, Any]:
    values = np.asarray(row["features"], dtype=np.float64)
    scaled = (values - means) / scales
    return {
        "window_id": str(row["window_id"]),
        "capture_id": str(row["capture_id"]),
        "label": str(row["label"]),
        "features": scaled.tolist(),
    }


def _iid_assignments(
    rows: list[dict[str, Any]], *, client_count: int, seed: int, np: Any
) -> list[list[dict[str, Any]]]:
    assignments: list[list[dict[str, Any]]] = [[] for _ in range(client_count)]
    by_label: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_label.setdefault(str(row["label"]), []).append(row)
    offset = 0
    for label_index, label in enumerate(sorted(by_label)):
        items = sorted(by_label[label], key=lambda item: item["window_id"])
        rng = np.random.default_rng(seed + label_index)
        order = rng.permutation(len(items)).tolist()
        for index, position in enumerate(order):
            assignments[(offset + index) % client_count].append(items[position])
        offset = (offset + len(items)) % client_count
    for items in assignments:
        items.sort(key=lambda item: item["window_id"])
    return assignments


def _dirichlet_assignments(
    rows: list[dict[str, Any]],
    *,
    client_count: int,
    seed: int,
    alpha: float,
    minimum_rows: int,
    np: Any,
) -> list[list[dict[str, Any]]]:
    if alpha <= 0:
        raise FederatedPartitionError("Dirichlet alpha must be positive")
    if len(rows) < client_count * minimum_rows:
        raise FederatedPartitionError("not enough training rows for the configured client minimum")
    by_label: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_label.setdefault(str(row["label"]), []).append(row)

    for attempt in range(512):
        rng = np.random.default_rng(seed + attempt)
        assignments: list[list[dict[str, Any]]] = [[] for _ in range(client_count)]
        for label in sorted(by_label):
            items = sorted(by_label[label], key=lambda item: item["window_id"])
            shuffled = [items[index] for index in rng.permutation(len(items)).tolist()]
            proportions = rng.dirichlet(np.full(client_count, alpha, dtype=np.float64))
            exact = proportions * len(shuffled)
            counts = np.floor(exact).astype(int)
            remainder = len(shuffled) - int(counts.sum())
            residual_order = np.argsort(-(exact - counts), kind="stable")
            for client_index in residual_order[:remainder]:
                counts[int(client_index)] += 1
            cursor = 0
            for client_index, count in enumerate(counts.tolist()):
                assignments[client_index].extend(shuffled[cursor : cursor + count])
                cursor += count
        if min(len(items) for items in assignments) >= minimum_rows:
            for items in assignments:
                items.sort(key=lambda item: item["window_id"])
            return assignments
    raise FederatedPartitionError(
        "could not obtain a deterministic non-IID allocation satisfying the client minimum"
    )


def _profile_assignments(
    rows: list[dict[str, Any]],
    *,
    reference_assignments: list[list[dict[str, Any]]],
    seed: int,
    np: Any,
) -> list[list[dict[str, Any]]]:
    """Allocate evaluation rows in proportion to each client's training profile."""

    client_count = len(reference_assignments)
    assignments: list[list[dict[str, Any]]] = [[] for _ in range(client_count)]
    reference_counts = [
        Counter(str(row["label"]) for row in items) for items in reference_assignments
    ]
    by_label: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_label.setdefault(str(row["label"]), []).append(row)

    for label_index, label in enumerate(sorted(by_label)):
        items = sorted(by_label[label], key=lambda item: item["window_id"])
        rng = np.random.default_rng(seed + label_index)
        shuffled = [items[index] for index in rng.permutation(len(items)).tolist()]
        weights = np.asarray(
            [counts.get(label, 0) for counts in reference_counts], dtype=np.float64
        )
        if float(weights.sum()) == 0.0:
            weights = np.ones(client_count, dtype=np.float64)
        exact = weights / weights.sum() * len(shuffled)
        counts = np.floor(exact).astype(int)
        remainder = len(shuffled) - int(counts.sum())
        residual_order = np.argsort(-(exact - counts), kind="stable")
        for client_index in residual_order[:remainder]:
            counts[int(client_index)] += 1
        cursor = 0
        for client_index, count in enumerate(counts.tolist()):
            assignments[client_index].extend(shuffled[cursor : cursor + count])
            cursor += count

    for items in assignments:
        items.sort(key=lambda item: item["window_id"])
    return assignments


def _class_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(row["label"]) for row in rows).items()))


def _is_bounded_relative_path(value: Any, *, prefix: str) -> bool:
    relative = Path(str(value))
    return (
        not relative.is_absolute()
        and ".." not in relative.parts
        and relative.as_posix().startswith(prefix)
    )


def prepare_partitions(
    *,
    dataset_workspace: Path,
    output: Path,
    mode: str,
    config_path: Path,
) -> dict[str, Any]:
    verification = verify_m2_workspace(dataset_workspace)
    if verification["status"] != "verified":
        raise FederatedPartitionError(f"M2 workspace verification failed: {verification['errors']}")
    if mode not in {"iid", "non-iid"}:
        raise FederatedPartitionError("partition mode must be 'iid' or 'non-iid'")

    np = _numpy()
    config, config_digest = load_yaml(config_path)
    partition_config = config["partitioning"]
    training_config = config["training"]
    client_count = int(partition_config["client_count"])
    seed = int(partition_config["seed"])
    dataset = json.loads((dataset_workspace / "dataset.json").read_text(encoding="utf-8"))
    scaler = json.loads((dataset_workspace / "scaler.json").read_text(encoding="utf-8"))
    m2_manifest = json.loads((dataset_workspace / "manifest.json").read_text(encoding="utf-8"))
    if dataset.get("dataset") != DATASET_NAME:
        raise FederatedPartitionError("M3 accepts only UWF-ZeekData24 M2 snapshots")

    means = np.asarray(scaler["mean"], dtype=np.float64)
    scales = np.asarray(scaler["scale"], dtype=np.float64)
    split_rows = {
        split: [
            _scaled_row(row, means, scales, np) for row in dataset["rows"] if row["split"] == split
        ]
        for split in ("train", "validation", "test", "temporal_holdout")
    }
    train_rows = split_rows["train"]
    validation_rows = split_rows["validation"]
    if mode == "iid":
        train_assignments = _iid_assignments(
            train_rows, client_count=client_count, seed=seed, np=np
        )
        strategy = str(partition_config["iid_strategy"])
    else:
        train_assignments = _dirichlet_assignments(
            train_rows,
            client_count=client_count,
            seed=seed,
            alpha=float(partition_config["dirichlet_alpha"]),
            minimum_rows=int(partition_config["minimum_train_rows_per_client"]),
            np=np,
        )
        strategy = str(partition_config["non_iid_strategy"])
    validation_assignments = _iid_assignments(
        validation_rows, client_count=client_count, seed=seed + 100_000, np=np
    )
    local_test_strategy = str(
        partition_config.get("local_test_strategy", "train-profile-proportional")
    )
    if local_test_strategy != "train-profile-proportional":
        raise FederatedPartitionError("unsupported local test partition strategy")
    local_test_assignments = _profile_assignments(
        split_rows["test"], reference_assignments=train_assignments, seed=seed + 200_000, np=np
    )

    class_names = sorted({row["label"] for row in train_rows})
    weighting_strategy = str(training_config["class_weighting"])
    class_weights = compute_class_weights(
        (row["label"] for row in train_rows), strategy=weighting_strategy
    )
    client_records: list[dict[str, Any]] = []
    for client_index in range(client_count):
        client_id = f"client{client_index + 1:02d}"
        client_dataset = {
            "schema_version": "1.0",
            "artifact_type": "m3_client_feature_snapshot",
            "dataset": DATASET_NAME,
            "client_id": client_id,
            "partition_id": client_index,
            "partition_mode": mode,
            "feature_names": dataset["feature_names"],
            "class_names": class_names,
            "rows": {
                "train": train_assignments[client_index],
                "validation": validation_assignments[client_index],
            },
        }
        dataset_bytes = derived_json_bytes(client_dataset)
        relative_dataset = Path("clients") / client_id / "dataset.json"
        dataset_digest = sha256_bytes(dataset_bytes)
        local_test = {
            "schema_version": "1.0",
            "artifact_type": "m3_client_local_test_snapshot",
            "dataset": DATASET_NAME,
            "client_id": client_id,
            "partition_id": client_index,
            "partition_mode": mode,
            "partition_strategy": local_test_strategy,
            "feature_names": dataset["feature_names"],
            "class_names": class_names,
            "rows": {"test": local_test_assignments[client_index]},
            "data_boundary": "post-selection evaluation only; never mounted for client training",
        }
        local_test_bytes = derived_json_bytes(local_test)
        relative_local_test = Path("evaluation") / "clients" / client_id / "test.json"
        local_test_digest = sha256_bytes(local_test_bytes)
        client_manifest = {
            "schema_version": "1.0",
            "artifact_type": "m3_client_partition_manifest",
            "dataset": DATASET_NAME,
            "client_id": client_id,
            "partition_id": client_index,
            "partition_mode": mode,
            "source_m2_dataset_sha256": m2_manifest["artifacts"]["dataset.json"],
            "source_m2_scaler_sha256": m2_manifest["artifacts"]["scaler.json"],
            "dataset_path": relative_dataset.as_posix(),
            "dataset_sha256": dataset_digest,
            "local_test_path": relative_local_test.as_posix(),
            "local_test_sha256": local_test_digest,
            "train_row_count": len(train_assignments[client_index]),
            "validation_row_count": len(validation_assignments[client_index]),
            "local_test_row_count": len(local_test_assignments[client_index]),
            "train_class_counts": _class_counts(train_assignments[client_index]),
            "validation_class_counts": _class_counts(validation_assignments[client_index]),
            "local_test_class_counts": _class_counts(local_test_assignments[client_index]),
        }
        manifest_bytes = derived_json_bytes(client_manifest)
        relative_manifest = Path("clients") / client_id / "manifest.json"
        write_once(output / relative_dataset, dataset_bytes)
        write_once(output / relative_local_test, local_test_bytes)
        write_once(output / relative_manifest, manifest_bytes)
        client_records.append(
            {
                "client_id": client_id,
                "partition_id": client_index,
                "dataset_path": relative_dataset.as_posix(),
                "dataset_sha256": dataset_digest,
                "manifest_path": relative_manifest.as_posix(),
                "manifest_sha256": sha256_bytes(manifest_bytes),
                "local_test_path": relative_local_test.as_posix(),
                "local_test_sha256": local_test_digest,
                "train_row_count": len(train_assignments[client_index]),
                "validation_row_count": len(validation_assignments[client_index]),
                "local_test_row_count": len(local_test_assignments[client_index]),
                "train_class_counts": _class_counts(train_assignments[client_index]),
                "local_test_class_counts": _class_counts(local_test_assignments[client_index]),
            }
        )

    server_evaluation = {
        "schema_version": "1.0",
        "artifact_type": "m3_server_feature_evaluation_snapshot",
        "dataset": DATASET_NAME,
        "feature_names": dataset["feature_names"],
        "class_names": class_names,
        "rows": {
            "validation": split_rows["validation"],
            "test": split_rows["test"],
            "temporal_holdout": split_rows["temporal_holdout"],
        },
        "data_boundary": "scaled feature windows only; no raw Zeek records",
    }
    server_bytes = derived_json_bytes(server_evaluation)
    server_relative = Path("server") / "evaluation.json"
    write_once(output / server_relative, server_bytes)
    server_split_records: dict[str, dict[str, Any]] = {}
    for split in ("validation", "test", "temporal_holdout"):
        split_snapshot = {
            "schema_version": "1.0",
            "artifact_type": "m3_server_feature_evaluation_split",
            "dataset": DATASET_NAME,
            "split": split,
            "feature_names": dataset["feature_names"],
            "class_names": class_names,
            "rows": {split: split_rows[split]},
            "data_boundary": "scaled feature windows only; no raw Zeek records",
        }
        split_bytes = derived_json_bytes(split_snapshot)
        split_relative = Path("server") / "splits" / f"{split}.json"
        write_once(output / split_relative, split_bytes)
        server_split_records[split] = {
            "path": split_relative.as_posix(),
            "sha256": sha256_bytes(split_bytes),
            "row_count": len(split_rows[split]),
            "class_counts": _class_counts(split_rows[split]),
        }

    manifest = {
        "schema_version": "1.0",
        "artifact_type": "m3_federated_partition_set",
        "dataset": DATASET_NAME,
        "code_version": __version__,
        "partition_mode": mode,
        "partition_strategy": strategy,
        "validation_strategy": str(partition_config["validation_strategy"]),
        "local_test_strategy": local_test_strategy,
        "client_count": client_count,
        "seed": seed,
        "dirichlet_alpha": (
            float(partition_config["dirichlet_alpha"]) if mode == "non-iid" else None
        ),
        "source_m2_manifest_sha256": sha256_file(dataset_workspace / "manifest.json"),
        "source_m2_dataset_sha256": sha256_file(dataset_workspace / "dataset.json"),
        "source_m2_scaler_sha256": sha256_file(dataset_workspace / "scaler.json"),
        "feature_names": dataset["feature_names"],
        "class_names": class_names,
        "class_weighting": weighting_strategy,
        "class_weighting_scope": "global-training-only",
        "global_class_weights": class_weights,
        "partition_config_sha256": config_digest,
        "implementation_sha256": sha256_file(Path(__file__)),
        "class_weighting_implementation_sha256": sha256_file(
            Path(__file__).with_name("class_weighting.py")
        ),
        "clients": client_records,
        "server_evaluation_path": server_relative.as_posix(),
        "server_evaluation_sha256": sha256_bytes(server_bytes),
        "server_evaluation_splits": server_split_records,
        "split_counts": {split: len(rows) for split, rows in split_rows.items()},
        "privacy_boundary": {
            "server_reads": ["server/splits/<authorized-split>.json", "manifest.json"],
            "server_forbidden": [
                "M2 dataset.json",
                "normalized_events.jsonl",
                "raw CSV or Parquet source records",
            ],
            "client_snapshots_contain": "scaled feature windows and labels only",
            "training_clients_read": ["clients/<client_id>/dataset.json"],
            "training_clients_forbidden": ["evaluation/clients/<client_id>/test.json"],
            "local_test_access": "selected-checkpoint-only",
        },
    }
    write_once(output / "manifest.json", derived_json_bytes(manifest))
    return {
        "status": "prepared",
        "dataset": DATASET_NAME,
        "partition_mode": mode,
        "client_count": client_count,
        "workspace": str(output),
        "train_row_count": len(train_rows),
        "validation_row_count": len(validation_rows),
        "local_test_row_count": len(split_rows["test"]),
        "minimum_client_train_rows": min(len(rows) for rows in train_assignments),
        "maximum_client_train_rows": max(len(rows) for rows in train_assignments),
        "manifest_sha256": sha256_file(output / "manifest.json"),
    }


def verify_partitions(*, workspace: Path, dataset_workspace: Path) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = workspace / "manifest.json"
    if not manifest_path.is_file():
        return {
            "status": "failed",
            "workspace": str(workspace),
            "error_count": 1,
            "errors": ["missing M3 partition manifest.json"],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    m2_status = verify_m2_workspace(dataset_workspace)
    if m2_status["status"] != "verified":
        errors.append("referenced M2 workspace does not verify")
    input_refs = {
        "manifest.json": manifest.get("source_m2_manifest_sha256"),
        "dataset.json": manifest.get("source_m2_dataset_sha256"),
        "scaler.json": manifest.get("source_m2_scaler_sha256"),
    }
    for name, expected in input_refs.items():
        path = dataset_workspace / name
        if not path.is_file() or not expected or sha256_file(path) != expected:
            errors.append(f"referenced M2 digest mismatch: {name}")

    m2_dataset = json.loads((dataset_workspace / "dataset.json").read_text(encoding="utf-8"))
    expected_ids = {
        split: {row["window_id"] for row in m2_dataset["rows"] if row["split"] == split}
        for split in ("train", "validation", "test", "temporal_holdout")
    }
    observed_train: list[str] = []
    observed_validation: list[str] = []
    observed_local_test: list[str] = []
    local_test_enabled = bool(manifest.get("local_test_strategy"))
    expected_clients = [f"client{index + 1:02d}" for index in range(int(manifest["client_count"]))]
    if [item.get("client_id") for item in manifest.get("clients", [])] != expected_clients:
        errors.append("M3 client list is incomplete or out of deterministic order")
    forbidden_row_keys = {"source_records", "_source_records", "raw", "source_event_ids"}
    for record in manifest.get("clients", []):
        client_id = record["client_id"]
        for path_key, digest_key in (
            ("manifest_path", "manifest_sha256"),
            ("dataset_path", "dataset_sha256"),
        ):
            path = workspace / record[path_key]
            if not path.is_file() or sha256_file(path) != record[digest_key]:
                errors.append(f"client artifact digest mismatch: {client_id}/{path.name}")
        dataset_path = workspace / record["dataset_path"]
        if not dataset_path.is_file():
            continue
        client_dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
        if client_dataset.get("client_id") != client_id:
            errors.append(f"client snapshot identity mismatch: {client_id}")
        if "test" in client_dataset.get("rows", {}):
            errors.append(f"test rows leaked into training snapshot: {client_id}")
        for split, collector in (
            ("train", observed_train),
            ("validation", observed_validation),
        ):
            for row in client_dataset.get("rows", {}).get(split, []):
                if forbidden_row_keys & set(row):
                    errors.append(f"raw lineage leaked into {client_id} {split} snapshot")
                if len(row.get("features", [])) != len(manifest["feature_names"]):
                    errors.append(f"feature width mismatch in {client_id} {split}")
                collector.append(str(row.get("window_id")))
        if local_test_enabled:
            local_path_value = record.get("local_test_path")
            local_digest = record.get("local_test_sha256")
            if not local_path_value or not local_digest:
                errors.append(f"missing local test binding: {client_id}")
                continue
            local_path = workspace / str(local_path_value)
            expected_prefix = f"evaluation/clients/{client_id}/"
            if not _is_bounded_relative_path(local_path_value, prefix=expected_prefix):
                errors.append(f"local test is outside evaluation boundary: {client_id}")
                continue
            if not local_path.is_file() or sha256_file(local_path) != local_digest:
                errors.append(f"local test artifact digest mismatch: {client_id}")
                continue
            local_test = json.loads(local_path.read_text(encoding="utf-8"))
            if (
                local_test.get("client_id") != client_id
                or local_test.get("partition_id") != record.get("partition_id")
                or set(local_test.get("rows", {})) != {"test"}
            ):
                errors.append(f"local test identity or split mismatch: {client_id}")
            local_rows = local_test.get("rows", {}).get("test", [])
            if len(local_rows) != int(record.get("local_test_row_count", -1)):
                errors.append(f"local test row count mismatch: {client_id}")
            if _class_counts(local_rows) != record.get("local_test_class_counts"):
                errors.append(f"local test class counts mismatch: {client_id}")
            for row in local_rows:
                if forbidden_row_keys & set(row):
                    errors.append(f"raw lineage leaked into {client_id} local test")
                if len(row.get("features", [])) != len(manifest["feature_names"]):
                    errors.append(f"feature width mismatch in {client_id} local test")
                observed_local_test.append(str(row.get("window_id")))

    if len(observed_train) != len(set(observed_train)):
        errors.append("training windows overlap across clients")
    if set(observed_train) != expected_ids["train"]:
        errors.append("client training windows do not exactly cover the M2 training split")
    if len(observed_validation) != len(set(observed_validation)):
        errors.append("validation windows overlap across clients")
    if set(observed_validation) != expected_ids["validation"]:
        errors.append("client validation windows do not exactly cover the M2 validation split")
    if local_test_enabled:
        if len(observed_local_test) != len(set(observed_local_test)):
            errors.append("local test windows overlap across clients")
        if set(observed_local_test) != expected_ids["test"]:
            errors.append("client local test windows do not exactly cover the M2 test split")

    server_path = workspace / str(manifest.get("server_evaluation_path", ""))
    if not server_path.is_file() or sha256_file(server_path) != manifest.get(
        "server_evaluation_sha256"
    ):
        errors.append("server evaluation artifact digest mismatch")
    else:
        server = json.loads(server_path.read_text(encoding="utf-8"))
        for split in ("validation", "test", "temporal_holdout"):
            observed = [str(row.get("window_id")) for row in server["rows"].get(split, [])]
            if len(observed) != len(set(observed)) or set(observed) != expected_ids[split]:
                errors.append(f"server evaluation split mismatch: {split}")
        serialized = derived_json_bytes(server)
        if b"normalized_events" in serialized or b"raw_line_sha256" in serialized:
            errors.append("server artifact contains forbidden raw-data references")

    split_records = manifest.get("server_evaluation_splits")
    if split_records is not None:
        expected_splits = {"validation", "test", "temporal_holdout"}
        if set(split_records) != expected_splits:
            errors.append("server evaluation split artifact list is incomplete")
        for split in sorted(expected_splits):
            record = split_records.get(split, {})
            relative = record.get("path", "")
            if not _is_bounded_relative_path(relative, prefix="server/splits/"):
                errors.append(f"server {split} artifact is outside split boundary")
                continue
            path = workspace / str(relative)
            if not path.is_file() or sha256_file(path) != record.get("sha256"):
                errors.append(f"server {split} split artifact digest mismatch")
                continue
            snapshot = json.loads(path.read_text(encoding="utf-8"))
            if snapshot.get("split") != split or set(snapshot.get("rows", {})) != {split}:
                errors.append(f"server {split} split artifact identity mismatch")
            rows = snapshot.get("rows", {}).get(split, [])
            observed = [str(row.get("window_id")) for row in rows]
            if len(observed) != len(set(observed)) or set(observed) != expected_ids[split]:
                errors.append(f"server {split} isolated split mismatch")
            if len(rows) != int(record.get("row_count", -1)):
                errors.append(f"server {split} isolated row count mismatch")
            if _class_counts(rows) != record.get("class_counts"):
                errors.append(f"server {split} isolated class counts mismatch")
            for row in rows:
                if forbidden_row_keys & set(row):
                    errors.append(f"raw lineage leaked into server {split} split")
                if len(row.get("features", [])) != len(manifest["feature_names"]):
                    errors.append(f"feature width mismatch in server {split} split")

    return {
        "status": "verified" if not errors else "failed",
        "dataset": manifest.get("dataset"),
        "partition_mode": manifest.get("partition_mode"),
        "client_count": manifest.get("client_count"),
        "workspace": str(workspace),
        "dataset_workspace": str(dataset_workspace),
        "manifest_sha256": sha256_file(manifest_path),
        "error_count": len(errors),
        "errors": errors,
    }
