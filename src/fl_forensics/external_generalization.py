"""Deterministic post-selection evaluation on the external UWF-ZeekData22 CSV subset."""

from __future__ import annotations

import csv
import json
import math
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file
from .config import load_yaml
from .dataset24 import verify_workspace as verify_m2_workspace
from .federated_model import arrays_from_export, build_model, load_ndarrays
from .preprocessing import FEATURE_NAMES, build_window_row, derived_json_bytes
from .secure_campaign import verify_secure_campaign
from .storage import write_once

EXTERNAL_DATASET = "UWF-ZeekData22"
TRAINING_DATASET = "UWF-ZeekData24"
EXPECTED_COLUMNS = [
    "resp_pkts",
    "service",
    "orig_ip_bytes",
    "local_resp",
    "missed_bytes",
    "protocol",
    "duration",
    "conn_state",
    "dest_ip",
    "orig_pkts",
    "community_id",
    "resp_ip_bytes",
    "dest_port",
    "orig_bytes",
    "local_orig",
    "datetime",
    "history",
    "resp_bytes",
    "uid",
    "src_port",
    "ts",
    "src_ip",
    "mitre_attack_tactics",
]
LABEL_COLUMN = "mitre_attack_tactics"


class ExternalGeneralizationError(ValueError):
    """Raised when the external-data or post-selection contract is violated."""


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _bounded_relative(value: Any) -> Path:
    relative = Path(str(value))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ExternalGeneralizationError(f"unbounded source path: {value}")
    return relative


def _finite_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def _nonnegative_int(value: Any) -> int:
    return max(int(_finite_float(value)), 0)


def _category(value: Any) -> str:
    return "missing" if value in (None, "", "-") else str(value).strip().lower()


def _external_label(value: Any, benign_labels: set[str]) -> str:
    normalized = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    normalized = normalized.strip("_")
    return "benign" if str(value).strip().lower() in benign_labels else normalized


def _identity(row: dict[str, str]) -> str:
    return sha256_bytes(
        canonical_json_bytes([row[column] for column in EXPECTED_COLUMNS if column != LABEL_COLUMN])
    )


def _verified_sources(source_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = source_root / "download_manifest.json"
    if not manifest_path.is_file():
        raise ExternalGeneralizationError(f"missing controlled-ingestion manifest: {manifest_path}")
    manifest = _load_json(manifest_path)
    if manifest.get("dataset") != EXTERNAL_DATASET:
        raise ExternalGeneralizationError("download manifest does not name UWF-ZeekData22")
    if manifest.get("source_format") != "csv":
        raise ExternalGeneralizationError("external generalization requires the official CSV subset")

    records: list[dict[str, Any]] = []
    manifested: set[str] = set()
    for item in sorted(manifest.get("files", []), key=lambda value: value["relative_path"]):
        relative = _bounded_relative(item["relative_path"])
        relative_text = relative.as_posix()
        if relative_text in manifested:
            raise ExternalGeneralizationError(f"duplicate manifest path: {relative_text}")
        manifested.add(relative_text)
        path = source_root / relative
        if not path.is_file():
            raise ExternalGeneralizationError(f"manifested CSV is missing: {relative_text}")
        size = path.stat().st_size
        digest = sha256_file(path)
        if size != int(item["size_bytes"]):
            raise ExternalGeneralizationError(f"source size mismatch: {relative_text}")
        if digest != str(item["sha256"]):
            raise ExternalGeneralizationError(f"source SHA-256 mismatch: {relative_text}")
        records.append(
            {
                "relative_path": relative_text,
                "source_url": str(item.get("source_url", "")),
                "size_bytes": size,
                "sha256": digest,
            }
        )
    discovered = {
        path.relative_to(source_root).as_posix() for path in source_root.rglob("*.csv")
    }
    if not records or discovered != manifested:
        raise ExternalGeneralizationError(
            "download manifest/file set mismatch; "
            f"unmanifested={sorted(discovered - manifested)}, missing={sorted(manifested - discovered)}"
        )
    return manifest, records


def _create_index(
    *,
    source_root: Path,
    sources: list[dict[str, Any]],
    benign_labels: set[str],
    database_path: Path,
) -> tuple[sqlite3.Connection, dict[str, Any]]:
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute(
        "CREATE TABLE identities ("
        "identity TEXT PRIMARY KEY, row_json TEXT NOT NULL, occurrence_count INTEGER NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE identity_labels ("
        "identity TEXT NOT NULL, label TEXT NOT NULL, PRIMARY KEY(identity, label))"
    )
    upsert_identity = (
        "INSERT INTO identities(identity, row_json, occurrence_count) VALUES (?, ?, 1) "
        "ON CONFLICT(identity) DO UPDATE SET occurrence_count=occurrence_count+1"
    )
    insert_label = "INSERT OR IGNORE INTO identity_labels(identity, label) VALUES (?, ?)"
    raw_label_counts: Counter[str] = Counter()
    file_reports: list[dict[str, Any]] = []
    total_rows = 0

    for source in sources:
        relative = str(source["relative_path"])
        path = source_root / relative
        local_count = 0
        local_labels: Counter[str] = Counter()
        pending_identities: list[tuple[str, str]] = []
        pending_labels: list[tuple[str, str]] = []
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != EXPECTED_COLUMNS:
                raise ExternalGeneralizationError(
                    f"unexpected Data22 CSV schema in {relative}; "
                    f"expected {EXPECTED_COLUMNS}, got {reader.fieldnames}"
                )
            for row_number, row in enumerate(reader, start=2):
                if None in row or set(row) != set(EXPECTED_COLUMNS):
                    raise ExternalGeneralizationError(
                        f"malformed Data22 record at {relative}:{row_number}"
                    )
                identity = _identity(row)
                label = _external_label(row[LABEL_COLUMN], benign_labels)
                if not label:
                    raise ExternalGeneralizationError(
                        f"empty external label at {relative}:{row_number}"
                    )
                pending_identities.append(
                    (identity, json.dumps(row, sort_keys=True, separators=(",", ":")))
                )
                pending_labels.append((identity, label))
                local_count += 1
                total_rows += 1
                local_labels[label] += 1
                raw_label_counts[label] += 1
                if len(pending_identities) >= 10_000:
                    connection.executemany(upsert_identity, pending_identities)
                    connection.executemany(insert_label, pending_labels)
                    pending_identities.clear()
                    pending_labels.clear()
        if pending_identities:
            connection.executemany(upsert_identity, pending_identities)
            connection.executemany(insert_label, pending_labels)
        connection.commit()
        file_reports.append(
            {
                **source,
                "row_count": local_count,
                "raw_label_counts": dict(sorted(local_labels.items())),
            }
        )

    unique_count = int(connection.execute("SELECT COUNT(*) FROM identities").fetchone()[0])
    conflict_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM (SELECT identity FROM identity_labels "
            "GROUP BY identity HAVING COUNT(*) > 1)"
        ).fetchone()[0]
    )
    return connection, {
        "schema_version": "1.0",
        "artifact_type": "external_dataset_audit",
        "dataset": EXTERNAL_DATASET,
        "source_format": "csv",
        "source_subset": "official-five-file-csv-subset",
        "source_files": file_reports,
        "raw_record_count": total_rows,
        "unique_connection_identity_count": unique_count,
        "consolidated_record_count": total_rows - unique_count,
        "multi_label_identity_count": conflict_count,
        "raw_label_counts": dict(sorted(raw_label_counts.items())),
        "identity_policy": "SHA-256 of every ordered non-label CSV field",
    }


def _event(
    *, identity: str, row: dict[str, str], labels: list[str], occurrence_count: int
) -> dict[str, Any]:
    attacks = sorted(label for label in labels if label != "benign")
    if not attacks:
        label = "benign"
    elif len(attacks) == 1:
        label = attacks[0]
    else:
        label = "multi_tactic"
    timestamp = _finite_float(row["ts"], default=-1.0)
    if timestamp < 0:
        raise ExternalGeneralizationError(f"invalid timestamp for identity {identity}")
    capture_id = str(row["datetime"])[:10]
    if len(capture_id) != 10:
        raise ExternalGeneralizationError(f"invalid datetime for identity {identity}")
    return {
        "event_id": f"event-data22-{identity[:24]}",
        "timestamp": timestamp,
        "capture_id": capture_id,
        "uid": str(row["uid"]),
        "originator_host": str(row["src_ip"]),
        "responder_host": str(row["dest_ip"]),
        "responder_port": _nonnegative_int(row["dest_port"]),
        "protocol": _category(row["protocol"]),
        "service": _category(row["service"]),
        "connection_state": _category(row["conn_state"]),
        "duration": _finite_float(row["duration"]),
        "originator_bytes": _nonnegative_int(row["orig_bytes"]),
        "responder_bytes": _nonnegative_int(row["resp_bytes"]),
        "originator_packets": _nonnegative_int(row["orig_pkts"]),
        "responder_packets": _nonnegative_int(row["resp_pkts"]),
        "label": label,
        "observed_external_labels": labels,
        "source_identity_sha256": identity,
        "source_record_occurrence_count": occurrence_count,
    }


def _derive_external_windows(
    connection: sqlite3.Connection, *, window_seconds: int
) -> tuple[list[dict[str, Any]], bytes, dict[str, int]]:
    connection.execute(
        "CREATE TABLE events (capture_id TEXT NOT NULL, bucket INTEGER NOT NULL, "
        "timestamp REAL NOT NULL, uid TEXT NOT NULL, identity TEXT NOT NULL, "
        "event_json TEXT NOT NULL)"
    )
    insert = (
        "INSERT INTO events(capture_id, bucket, timestamp, uid, identity, event_json) "
        "VALUES (?, ?, ?, ?, ?, ?)"
    )
    pending: list[tuple[Any, ...]] = []
    cursor = connection.execute(
        "SELECT i.identity, i.row_json, i.occurrence_count, "
        "GROUP_CONCAT(l.label, ',') "
        "FROM identities i JOIN identity_labels l ON l.identity=i.identity "
        "GROUP BY i.identity ORDER BY i.identity"
    )
    for identity, row_json, occurrence_count, labels_text in cursor:
        labels = sorted(str(labels_text).split(","))
        event = _event(
            identity=str(identity),
            row=json.loads(row_json),
            labels=labels,
            occurrence_count=int(occurrence_count),
        )
        bucket = math.floor(float(event["timestamp"]) / window_seconds)
        pending.append(
            (
                event["capture_id"],
                bucket,
                event["timestamp"],
                event["uid"],
                identity,
                json.dumps(event, sort_keys=True, separators=(",", ":")),
            )
        )
        if len(pending) >= 10_000:
            connection.executemany(insert, pending)
            pending.clear()
    if pending:
        connection.executemany(insert, pending)
    connection.execute("DROP TABLE identity_labels")
    connection.execute("DROP TABLE identities")
    connection.execute(
        "CREATE INDEX event_order ON events(capture_id, bucket, timestamp, uid, identity)"
    )
    connection.commit()

    rows: list[dict[str, Any]] = []
    lineage_parts: list[bytes] = []
    window_labels: Counter[str] = Counter()
    current_key: tuple[str, int] | None = None
    current_events: list[dict[str, Any]] = []

    def flush() -> None:
        if current_key is None:
            return
        capture_id, bucket = current_key
        row, _ = build_window_row(
            events=current_events,
            capture_id=capture_id,
            bucket=bucket,
            window_seconds=window_seconds,
            client_id="external-data22",
            benign_labels={"benign"},
            mixed_attack_label="multi_tactic",
            split_seed=0,
            split_percentages={"train": 0, "validation": 0, "test": 100},
        )
        source_ids = [str(item["source_identity_sha256"]) for item in current_events]
        row["window_id"] = (
            "external-window-data22-"
            f"{sha256_bytes(f'{capture_id}:{bucket}'.encode())[:24]}"
        )
        row["split"] = "external"
        row.pop("source_event_ids", None)
        row["source_event_count"] = len(source_ids)
        row["source_identity_set_sha256"] = sha256_bytes(
            canonical_json_bytes(sorted(source_ids))
        )
        rows.append(row)
        window_labels[str(row["label"])] += 1
        lineage_parts.append(
            derived_json_bytes(
                {
                    "window_id": row["window_id"],
                    "capture_id": capture_id,
                    "window_start_epoch": row["window_start_epoch"],
                    "window_end_epoch": row["window_end_epoch"],
                    "source_event_count": len(source_ids),
                    "source_identity_set_sha256": row["source_identity_set_sha256"],
                    "observed_labels": row["observed_labels"],
                }
            )
        )

    cursor = connection.execute(
        "SELECT capture_id, bucket, event_json FROM events "
        "ORDER BY capture_id, bucket, timestamp, uid, identity"
    )
    for capture_id, bucket, event_json in cursor:
        key = (str(capture_id), int(bucket))
        if current_key != key:
            flush()
            current_key = key
            current_events = []
        current_events.append(json.loads(event_json))
    flush()
    return rows, b"".join(lineage_parts), dict(sorted(window_labels.items()))


def _snapshot(
    *, source_root: Path, config_path: Path
) -> tuple[dict[str, bytes], dict[str, Any]]:
    config, config_sha256 = load_yaml(config_path)
    settings = dict(config.get("external_dataset", {}))
    if settings.get("dataset") != EXTERNAL_DATASET:
        raise ExternalGeneralizationError("configuration does not name UWF-ZeekData22")
    if settings.get("training_dataset") != TRAINING_DATASET:
        raise ExternalGeneralizationError("training-dataset boundary must remain UWF-ZeekData24")
    window_seconds = int(settings.get("window_seconds", 60))
    if window_seconds <= 0:
        raise ExternalGeneralizationError("window_seconds must be positive")
    benign_labels = {
        str(item).strip().lower() for item in settings.get("benign_labels", ["none"])
    }
    source_manifest, sources = _verified_sources(source_root)
    with tempfile.TemporaryDirectory(prefix="fl-forensics-data22-") as temporary:
        connection, audit = _create_index(
            source_root=source_root,
            sources=sources,
            benign_labels=benign_labels,
            database_path=Path(temporary) / "external.sqlite3",
        )
        rows, lineage_bytes, class_counts = _derive_external_windows(
            connection, window_seconds=window_seconds
        )
        connection.close()
    if not rows:
        raise ExternalGeneralizationError("external snapshot contains no feature windows")

    dataset = {
        "schema_version": "1.0",
        "artifact_type": "external_feature_snapshot",
        "dataset": EXTERNAL_DATASET,
        "purpose": "post-selection external evaluation only",
        "feature_names": FEATURE_NAMES,
        "rows": rows,
    }
    feature_schema = {
        "schema_version": "zeek-window-v1",
        "dataset": EXTERNAL_DATASET,
        "window_seconds": window_seconds,
        "feature_names": FEATURE_NAMES,
        "source_field_adapter": {
            "protocol": "protocol",
            "originator_host": "src_ip",
            "responder_host": "dest_ip",
            "responder_port": "dest_port",
            "label": LABEL_COLUMN,
        },
        "scaling": "none in external snapshot; apply frozen UWF-ZeekData24 train scaler at evaluation",
        "label_policy": (
            "none-like labels become benign; one attack label is retained; multiple attack "
            "labels in one 60-second window become multi_tactic"
        ),
        "identity_policy": audit["identity_policy"],
    }
    audit_bytes = derived_json_bytes(audit)
    dataset_bytes = derived_json_bytes(dataset)
    schema_bytes = derived_json_bytes(feature_schema)
    artifacts = {
        "audit.json": audit_bytes,
        "dataset.json": dataset_bytes,
        "feature_schema.json": schema_bytes,
        "lineage.jsonl": lineage_bytes,
    }
    artifact_digests = {name: sha256_bytes(value) for name, value in artifacts.items()}
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "external_dataset_snapshot_manifest",
        "dataset": EXTERNAL_DATASET,
        "dataset_version": "2022",
        "source_subset": "official-five-file-csv-subset",
        "code_version": __version__,
        "implementation_files": {
            "external_generalization.py": sha256_file(Path(__file__)),
            "preprocessing.py": sha256_file(Path(__file__).with_name("preprocessing.py")),
        },
        "download_manifest_sha256": sha256_bytes(canonical_json_bytes(source_manifest)),
        "configuration_sha256": config_sha256,
        "source_files": sources,
        "raw_record_count": audit["raw_record_count"],
        "unique_event_count": audit["unique_connection_identity_count"],
        "window_count": len(rows),
        "feature_count": len(FEATURE_NAMES),
        "class_counts": class_counts,
        "artifacts": artifact_digests,
        "isolation_contract": {
            "allowed_use": "post-selection evaluation only",
            "forbidden_uses": [
                "training",
                "validation",
                "checkpoint selection",
                "hyperparameter selection",
                "threshold selection",
            ],
            "scaler_source": "frozen UWF-ZeekData24 training split only",
        },
    }
    manifest_bytes = derived_json_bytes(manifest)
    artifacts["manifest.json"] = manifest_bytes
    return artifacts, manifest


def prepare_external_dataset(
    *, source_root: Path, output: Path, config_path: Path
) -> dict[str, Any]:
    artifacts, manifest = _snapshot(source_root=source_root, config_path=config_path)
    for name, value in artifacts.items():
        write_once(output / name, value)
    return {
        "status": "prepared",
        "dataset": EXTERNAL_DATASET,
        "workspace": str(output),
        "raw_record_count": manifest["raw_record_count"],
        "unique_event_count": manifest["unique_event_count"],
        "window_count": manifest["window_count"],
        "class_counts": manifest["class_counts"],
        "manifest_sha256": sha256_bytes(artifacts["manifest.json"]),
    }


def _structural_external_errors(workspace: Path) -> tuple[list[str], dict[str, Any] | None]:
    errors: list[str] = []
    manifest_path = workspace / "manifest.json"
    if not manifest_path.is_file():
        return ["missing external manifest.json"], None
    try:
        manifest = _load_json(manifest_path)
        if manifest.get("dataset") != EXTERNAL_DATASET:
            errors.append("external manifest dataset mismatch")
        if manifest.get("isolation_contract", {}).get("allowed_use") != (
            "post-selection evaluation only"
        ):
            errors.append("external isolation contract mismatch")
        for name, digest in manifest.get("artifacts", {}).items():
            path = workspace / _bounded_relative(name)
            if not path.is_file() or sha256_file(path) != digest:
                errors.append(f"external artifact digest mismatch: {name}")
        dataset = _load_json(workspace / "dataset.json")
        rows = dataset.get("rows", [])
        if dataset.get("feature_names") != FEATURE_NAMES:
            errors.append("external feature order mismatch")
        if len(rows) != int(manifest.get("window_count", -1)):
            errors.append("external window count mismatch")
        observed_counts = dict(sorted(Counter(str(row.get("label")) for row in rows).items()))
        if observed_counts != manifest.get("class_counts"):
            errors.append("external class counts mismatch")
        identifiers: list[str] = []
        for row in rows:
            identifiers.append(str(row.get("window_id")))
            values = row.get("features", [])
            if len(values) != len(FEATURE_NAMES) or not all(
                isinstance(value, (int, float)) and math.isfinite(float(value))
                for value in values
            ):
                errors.append(f"invalid external features: {row.get('window_id')}")
        if len(identifiers) != len(set(identifiers)):
            errors.append("external window identifiers are not unique")
        implementation = manifest.get("implementation_files", {})
        expected_implementation = {
            "external_generalization.py": sha256_file(Path(__file__)),
            "preprocessing.py": sha256_file(Path(__file__).with_name("preprocessing.py")),
        }
        if implementation != expected_implementation:
            errors.append("external implementation binding mismatch")
    except (FileNotFoundError, json.JSONDecodeError, KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
        manifest = None
    return errors, manifest


def verify_external_dataset(
    *,
    workspace: Path,
    source_root: Path | None = None,
    config_path: Path | None = None,
) -> dict[str, Any]:
    errors, manifest = _structural_external_errors(workspace)
    recomputed = False
    if not errors and (source_root is not None or config_path is not None):
        if source_root is None or config_path is None:
            errors.append("source_root and config_path are both required for source recomputation")
        else:
            try:
                expected, _ = _snapshot(source_root=source_root, config_path=config_path)
                for name, value in expected.items():
                    path = workspace / name
                    if not path.is_file() or path.read_bytes() != value:
                        errors.append(f"recomputed external artifact mismatch: {name}")
                recomputed = not errors
            except (OSError, TypeError, ValueError) as exc:
                errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "dataset": manifest.get("dataset") if manifest else None,
        "window_count": int(manifest.get("window_count", 0)) if manifest else 0,
        "source_recomputed": recomputed,
        "error_count": len(errors),
        "errors": errors,
    }


def _dependencies() -> tuple[Any, Any]:
    try:
        import numpy as np
        import torch
    except ImportError as exc:
        raise ExternalGeneralizationError(
            'external evaluation requires: python -m pip install -e ".[ml,dev]"'
        ) from exc
    return np, torch


def _model_from_export(value: dict[str, Any], *, np: Any, torch: Any) -> Any:
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


def _predict(
    *, model_export: dict[str, Any], features: Any, batch_size: int, np: Any, torch: Any
) -> tuple[list[int], list[float]]:
    model = _model_from_export(model_export, np=np, torch=torch)
    model.eval()
    tensor = torch.from_numpy(np.asarray(features, dtype=np.float32))
    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(tensor),
        batch_size=min(batch_size, len(tensor)),
        shuffle=False,
        num_workers=0,
    )
    predictions: list[int] = []
    confidence: list[float] = []
    with torch.no_grad():
        for (batch,) in loader:
            probabilities = torch.softmax(model(batch), dim=1)
            values, indices = probabilities.max(dim=1)
            predictions.extend(indices.tolist())
            confidence.extend(float(value) for value in values.tolist())
    return predictions, confidence


def _binary_metrics(actual: list[str], predicted: list[str], *, benign: str) -> dict[str, Any]:
    tn = fp = fn = tp = 0
    for actual_label, predicted_label in zip(actual, predicted, strict=True):
        actual_attack = actual_label != benign
        predicted_attack = predicted_label != benign
        if not actual_attack and not predicted_attack:
            tn += 1
        elif not actual_attack and predicted_attack:
            fp += 1
        elif actual_attack and not predicted_attack:
            fn += 1
        else:
            tp += 1
    total = tn + fp + fn + tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return {
        "scope": "all external windows; every non-benign truth and prediction collapses to attack",
        "row_count": total,
        "accuracy": (tn + tp) / total if total else None,
        "attack_precision": precision,
        "attack_recall": recall,
        "attack_f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "benign_specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2,
        "false_positive_rate": fp / (tn + fp) if tn + fp else None,
        "confusion_matrix": {
            "labels": ["benign", "attack"],
            "values": [[tn, fp], [fn, tp]],
        },
    }


def _shared_label_metrics(
    actual: list[str], predicted: list[str], *, shared_labels: list[str], model_labels: list[str]
) -> dict[str, Any]:
    selected = [
        (actual_label, predicted_label)
        for actual_label, predicted_label in zip(actual, predicted, strict=True)
        if actual_label in shared_labels
    ]
    matrix = [
        [
            sum(1 for actual_label, predicted_label in selected if actual_label == truth and predicted_label == guess)
            for guess in model_labels
        ]
        for truth in shared_labels
    ]
    per_class: dict[str, Any] = {}
    for label in shared_labels:
        tp = sum(1 for truth, guess in selected if truth == label and guess == label)
        fp = sum(1 for truth, guess in selected if truth != label and guess == label)
        fn = sum(1 for truth, guess in selected if truth == label and guess != label)
        support = sum(1 for truth, _ in selected if truth == label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "support": support,
        }
    f1_values = [per_class[label]["f1"] for label in shared_labels]
    return {
        "scope": "external windows whose truth label is explicitly shared with the fixed model",
        "shared_labels": shared_labels,
        "row_count": len(selected),
        "accuracy": (
            sum(1 for truth, guess in selected if truth == guess) / len(selected)
            if selected
            else None
        ),
        "macro_f1_shared_labels": sum(f1_values) / len(f1_values) if f1_values else None,
        "prediction_outside_shared_label_count": sum(
            1 for _, guess in selected if guess not in shared_labels
        ),
        "per_class": per_class,
        "rectangular_confusion_matrix": {
            "actual_labels": shared_labels,
            "predicted_model_labels": model_labels,
            "values": matrix,
        },
    }


def _feature_shift(scaled: Any, *, feature_names: list[str], np: Any) -> dict[str, Any]:
    absolute = np.abs(scaled)
    records = []
    for index, name in enumerate(feature_names):
        values = scaled[:, index]
        records.append(
            {
                "feature": name,
                "external_scaled_mean": float(values.mean()),
                "external_scaled_std_population": float(values.std()),
                "absolute_z_gt_3_fraction": float((np.abs(values) > 3).mean()),
                "absolute_z_gt_5_fraction": float((np.abs(values) > 5).mean()),
            }
        )
    return {
        "definition": "Data22 features after the frozen Data24 training-only standard scaler",
        "row_any_absolute_z_gt_3_fraction": float((absolute > 3).any(axis=1).mean()),
        "row_any_absolute_z_gt_5_fraction": float((absolute > 5).any(axis=1).mean()),
        "features": records,
    }


def _validated_evaluation_inputs(
    *,
    external_workspace: Path,
    campaign_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    training_dataset_workspace: Path,
) -> dict[str, Any]:
    external_status = verify_external_dataset(workspace=external_workspace)
    if external_status["status"] != "verified":
        raise ExternalGeneralizationError(
            f"external snapshot verification failed: {external_status['errors']}"
        )
    m2_status = verify_m2_workspace(training_dataset_workspace)
    if m2_status["status"] != "verified":
        raise ExternalGeneralizationError(f"training M2 verification failed: {m2_status['errors']}")
    partition_manifest_path = partition_workspace / "manifest.json"
    partition = _load_json(partition_manifest_path)
    server_evaluation_path = partition_workspace / _bounded_relative(
        partition["server_evaluation_path"]
    )
    campaign_status = verify_secure_campaign(
        workspace=campaign_workspace,
        trust_workspace=trust_workspace,
        partition_manifest_path=partition_manifest_path,
        server_evaluation_path=server_evaluation_path,
    )
    if campaign_status["status"] != "verified":
        raise ExternalGeneralizationError(
            f"secure campaign verification failed: {campaign_status['errors']}"
        )
    campaign = _load_json(campaign_workspace / "campaign-manifest.json")
    core = campaign["core"]
    selected_round = int(core["selected_round"])
    model_path = (
        campaign_workspace
        / "rounds"
        / f"round-{selected_round:03d}"
        / "checkpoint"
        / "global-model.json"
    )
    if not model_path.is_file() or sha256_file(model_path) != core["selected_model_sha256"]:
        raise ExternalGeneralizationError("selected secure model digest mismatch")
    model_export = _load_json(model_path)
    class_names = [str(item) for item in model_export["class_names"]]
    if class_names != partition.get("class_names"):
        raise ExternalGeneralizationError("selected model and partition class order differ")
    scaler_path = training_dataset_workspace / "scaler.json"
    if sha256_file(scaler_path) != partition.get("source_m2_scaler_sha256"):
        raise ExternalGeneralizationError("frozen training scaler digest mismatch")
    scaler = _load_json(scaler_path)
    external = _load_json(external_workspace / "dataset.json")
    if scaler.get("feature_names") != FEATURE_NAMES or external.get("feature_names") != FEATURE_NAMES:
        raise ExternalGeneralizationError("training/external feature order mismatch")
    return {
        "external": external,
        "external_manifest": _load_json(external_workspace / "manifest.json"),
        "campaign": campaign,
        "partition": partition,
        "model": model_export,
        "class_names": class_names,
        "scaler": scaler,
        "selected_round": selected_round,
        "model_path": model_path,
        "partition_manifest_path": partition_manifest_path,
        "server_evaluation_path": server_evaluation_path,
    }


def _evaluation_artifacts(
    *,
    external_workspace: Path,
    campaign_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    training_dataset_workspace: Path,
    config_path: Path,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    validated = _validated_evaluation_inputs(
        external_workspace=external_workspace,
        campaign_workspace=campaign_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        training_dataset_workspace=training_dataset_workspace,
    )
    config, config_sha256 = load_yaml(config_path)
    settings = dict(config.get("evaluation", {}))
    batch_size = int(settings.get("batch_size", 1024))
    if batch_size <= 0:
        raise ExternalGeneralizationError("evaluation batch_size must be positive")
    benign_label = str(settings.get("benign_label", "benign"))
    shared_labels = [str(item) for item in settings.get("shared_labels", [])]
    class_names = validated["class_names"]
    if not shared_labels or any(label not in class_names for label in shared_labels):
        raise ExternalGeneralizationError("shared_labels must be a non-empty model-label subset")

    np, torch = _dependencies()
    rows = sorted(validated["external"]["rows"], key=lambda item: item["window_id"])
    raw = np.asarray([row["features"] for row in rows], dtype=np.float64)
    means = np.asarray(validated["scaler"]["mean"], dtype=np.float64)
    scales = np.asarray(validated["scaler"]["scale"], dtype=np.float64)
    if raw.shape[1] != len(means) or len(means) != len(scales):
        raise ExternalGeneralizationError("external/scaler feature width mismatch")
    scaled = (raw - means) / scales
    if not np.isfinite(scaled).all():
        raise ExternalGeneralizationError("external scaling produced non-finite values")
    prediction_ids, confidence = _predict(
        model_export=validated["model"],
        features=scaled,
        batch_size=batch_size,
        np=np,
        torch=torch,
    )
    actual_labels = [str(row["label"]) for row in rows]
    predicted_labels = [class_names[index] for index in prediction_ids]
    prediction_records = [
        {
            "window_id": row["window_id"],
            "actual_external_label": actual,
            "actual_binary_label": "benign" if actual == benign_label else "attack",
            "predicted_model_label": predicted,
            "predicted_binary_label": "benign" if predicted == benign_label else "attack",
            "maximum_softmax_probability": round(probability, 12),
        }
        for row, actual, predicted, probability in zip(
            rows, actual_labels, predicted_labels, confidence, strict=True
        )
    ]
    predictions_bytes = b"".join(derived_json_bytes(item) for item in prediction_records)
    external_counts = dict(sorted(Counter(actual_labels).items()))
    model_label_rows = sum(count for label, count in external_counts.items() if label in class_names)
    shared_rows = sum(count for label, count in external_counts.items() if label in shared_labels)
    total_rows = len(rows)
    label_space = {
        "model_labels": class_names,
        "configured_shared_labels": shared_labels,
        "external_label_counts": external_counts,
        "external_labels_in_model": sorted(set(external_counts) & set(class_names)),
        "external_labels_outside_model": sorted(set(external_counts) - set(class_names)),
        "model_label_coverage_row_count": model_label_rows,
        "model_label_coverage_fraction": model_label_rows / total_rows,
        "strict_shared_evaluation_row_count": shared_rows,
        "strict_shared_evaluation_fraction": shared_rows / total_rows,
    }
    metrics = {
        "schema_version": "1.0",
        "artifact_type": "external_generalization_metrics",
        "training_dataset": TRAINING_DATASET,
        "external_dataset": EXTERNAL_DATASET,
        "protocol": "frozen-selected-secure-checkpoint-post-selection-external-evaluation",
        "selected_round": validated["selected_round"],
        "selected_model_sha256": sha256_file(validated["model_path"]),
        "external_window_count": total_rows,
        "label_space": label_space,
        "binary_all_external": _binary_metrics(
            actual_labels, predicted_labels, benign=benign_label
        ),
        "shared_label_closed_set": _shared_label_metrics(
            actual_labels,
            predicted_labels,
            shared_labels=shared_labels,
            model_labels=class_names,
        ),
        "prediction_distribution": dict(sorted(Counter(predicted_labels).items())),
        "feature_shift": _feature_shift(scaled, feature_names=FEATURE_NAMES, np=np),
        "interpretation_constraints": [
            "UWF-ZeekData22 was not used for training, validation, checkpoint selection, hyperparameter selection, or threshold selection.",
            "The official Data22 CSV subset does not cover the full tactic distribution of the Parquet release.",
            "Discovery is absent from the fixed six-class Data24 model and is evaluated only after benign/non-benign collapse.",
            "The strict tactic view is limited to explicitly shared labels and reports its coverage.",
            "This is cross-dataset evidence for one frozen checkpoint, not a universal generalization claim.",
        ],
    }
    metrics_bytes = derived_json_bytes(metrics)
    core = {
        "training_dataset_manifest_sha256": sha256_file(
            training_dataset_workspace / "manifest.json"
        ),
        "training_scaler_sha256": sha256_file(training_dataset_workspace / "scaler.json"),
        "partition_manifest_sha256": sha256_file(validated["partition_manifest_path"]),
        "campaign_manifest_sha256": sha256_file(campaign_workspace / "campaign-manifest.json"),
        "selected_round": validated["selected_round"],
        "selected_model_sha256": sha256_file(validated["model_path"]),
        "external_manifest_sha256": sha256_file(external_workspace / "manifest.json"),
        "configuration_sha256": config_sha256,
        "metrics_sha256": sha256_bytes(metrics_bytes),
        "predictions_sha256": sha256_bytes(predictions_bytes),
    }
    evaluation_id = f"m5-external-generalization-{sha256_bytes(canonical_json_bytes(core))[:24]}"
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "external_generalization_manifest",
        "evaluation_id": evaluation_id,
        "code_version": __version__,
        "implementation_files": {
            "external_generalization.py": sha256_file(Path(__file__)),
            "federated_model.py": sha256_file(Path(__file__).with_name("federated_model.py")),
        },
        "core": core,
        "artifacts": {
            "metrics.json": sha256_bytes(metrics_bytes),
            "predictions.jsonl": sha256_bytes(predictions_bytes),
        },
        "selection_boundary": (
            "selected secure checkpoint is verified before Data22 rows are opened for inference"
        ),
    }
    manifest_bytes = derived_json_bytes(manifest)
    return {
        "metrics.json": metrics_bytes,
        "predictions.jsonl": predictions_bytes,
        "manifest.json": manifest_bytes,
    }, metrics


def evaluate_external_generalization(
    *,
    external_workspace: Path,
    campaign_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    training_dataset_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    artifacts, metrics = _evaluation_artifacts(
        external_workspace=external_workspace,
        campaign_workspace=campaign_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        training_dataset_workspace=training_dataset_workspace,
        config_path=config_path,
    )
    for name, value in artifacts.items():
        write_once(output / name, value)
    manifest = json.loads(artifacts["manifest.json"])
    return {
        "status": "evaluated_external_post_selection",
        "workspace": str(output),
        "evaluation_id": manifest["evaluation_id"],
        "selected_round": metrics["selected_round"],
        "external_window_count": metrics["external_window_count"],
        "binary_attack_f1": metrics["binary_all_external"]["attack_f1"],
        "shared_label_macro_f1": metrics["shared_label_closed_set"][
            "macro_f1_shared_labels"
        ],
        "strict_shared_evaluation_fraction": metrics["label_space"][
            "strict_shared_evaluation_fraction"
        ],
        "manifest_sha256": sha256_bytes(artifacts["manifest.json"]),
    }


def verify_external_generalization(
    *,
    workspace: Path,
    external_workspace: Path,
    source_root: Path,
    campaign_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    training_dataset_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    external_status = verify_external_dataset(
        workspace=external_workspace,
        source_root=source_root,
        config_path=config_path,
    )
    if external_status["status"] != "verified":
        errors.extend(f"external source: {item}" for item in external_status["errors"])
    recomputed_metrics = False
    recomputed_predictions = False
    implementation_binding = False
    manifest: dict[str, Any] | None = None
    if not errors:
        try:
            expected, _ = _evaluation_artifacts(
                external_workspace=external_workspace,
                campaign_workspace=campaign_workspace,
                trust_workspace=trust_workspace,
                partition_workspace=partition_workspace,
                training_dataset_workspace=training_dataset_workspace,
                config_path=config_path,
            )
            for name, value in expected.items():
                path = workspace / name
                if not path.is_file() or path.read_bytes() != value:
                    errors.append(f"recomputed evaluation artifact mismatch: {name}")
            recomputed_metrics = (
                (workspace / "metrics.json").is_file()
                and (workspace / "metrics.json").read_bytes() == expected["metrics.json"]
            )
            recomputed_predictions = (
                (workspace / "predictions.jsonl").is_file()
                and (workspace / "predictions.jsonl").read_bytes()
                == expected["predictions.jsonl"]
            )
            manifest = json.loads(expected["manifest.json"])
            implementation_binding = manifest["implementation_files"] == {
                "external_generalization.py": sha256_file(Path(__file__)),
                "federated_model.py": sha256_file(
                    Path(__file__).with_name("federated_model.py")
                ),
            }
        except (FileNotFoundError, OSError, TypeError, ValueError) as exc:
            errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "evaluation_id": manifest.get("evaluation_id") if manifest else None,
        "external_source_recomputed": external_status["source_recomputed"],
        "campaign_and_selection_reverified": not errors and manifest is not None,
        "metrics_recomputed": recomputed_metrics,
        "predictions_recomputed": recomputed_predictions,
        "implementation_binding_verified": implementation_binding,
        "error_count": len(errors),
        "errors": errors,
    }
