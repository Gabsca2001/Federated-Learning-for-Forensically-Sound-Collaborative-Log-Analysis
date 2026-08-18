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
from .dataset24 import DATASET_NAME, verify_workspace as verify_m2_workspace
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


def _class_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(row["label"]) for row in rows).items()))


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
            _scaled_row(row, means, scales, np)
            for row in dataset["rows"]
            if row["split"] == split
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
            "train_row_count": len(train_assignments[client_index]),
            "validation_row_count": len(validation_assignments[client_index]),
            "train_class_counts": _class_counts(train_assignments[client_index]),
            "validation_class_counts": _class_counts(validation_assignments[client_index]),
        }
        manifest_bytes = derived_json_bytes(client_manifest)
        relative_manifest = Path("clients") / client_id / "manifest.json"
        write_once(output / relative_dataset, dataset_bytes)
        write_once(output / relative_manifest, manifest_bytes)
        client_records.append(
            {
                "client_id": client_id,
                "partition_id": client_index,
                "dataset_path": relative_dataset.as_posix(),
                "dataset_sha256": dataset_digest,
                "manifest_path": relative_manifest.as_posix(),
                "manifest_sha256": sha256_bytes(manifest_bytes),
                "train_row_count": len(train_assignments[client_index]),
                "validation_row_count": len(validation_assignments[client_index]),
                "train_class_counts": _class_counts(train_assignments[client_index]),
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

    manifest = {
        "schema_version": "1.0",
        "artifact_type": "m3_federated_partition_set",
        "dataset": DATASET_NAME,
        "code_version": __version__,
        "partition_mode": mode,
        "partition_strategy": strategy,
        "validation_strategy": str(partition_config["validation_strategy"]),
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
        "split_counts": {split: len(rows) for split, rows in split_rows.items()},
        "privacy_boundary": {
            "server_reads": [server_relative.as_posix(), "manifest.json"],
            "server_forbidden": ["M2 dataset.json", "normalized_events.jsonl", "raw CSV"],
            "client_snapshots_contain": "scaled feature windows and labels only",
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

    if len(observed_train) != len(set(observed_train)):
        errors.append("training windows overlap across clients")
    if set(observed_train) != expected_ids["train"]:
        errors.append("client training windows do not exactly cover the M2 training split")
    if len(observed_validation) != len(set(observed_validation)):
        errors.append("validation windows overlap across clients")
    if set(observed_validation) != expected_ids["validation"]:
        errors.append("client validation windows do not exactly cover the M2 validation split")

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
