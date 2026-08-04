"""Deterministic UWF-ZeekData24 audit and M2 dataset construction."""

from __future__ import annotations

import csv
import json
import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file
from .preprocessing import FEATURE_NAMES, derived_json_bytes, normalize_and_window
from .storage import write_once

DATASET_NAME = "UWF-ZeekData24"
DATASET_VERSION = "2024"
EXPECTED_COLUMNS = [
    "community_id",
    "conn_state",
    "duration",
    "history",
    "src_ip_zeek",
    "src_port_zeek",
    "dest_ip_zeek",
    "dest_port_zeek",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "orig_bytes",
    "orig_ip_bytes",
    "orig_pkts",
    "proto",
    "resp_bytes",
    "resp_ip_bytes",
    "resp_pkts",
    "service",
    "ts",
    "uid",
    "datetime",
    "label_tactic",
    "label_technique",
    "label_binary",
    "label_cve",
]
LABEL_COLUMNS = {
    "label_tactic",
    "label_technique",
    "label_binary",
    "label_cve",
}
MISSING_VALUES = {"", "-"}


class Dataset24Error(ValueError):
    """Raised when the Data24 source violates the frozen M2 contract."""


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Dataset24Error(f"timestamp has no UTC offset: {value}")
    return parsed


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    return normalized or "unknown"


def _label(value: str) -> str:
    return "benign" if value.strip().lower() == "none" else _slug(value)


def _identity_digest(row: dict[str, str], columns: list[str]) -> str:
    values = [row[column] for column in columns if column not in LABEL_COLUMNS]
    return sha256_bytes(canonical_json_bytes(values))


def _full_row_digest(row: dict[str, str], columns: list[str]) -> str:
    return sha256_bytes(canonical_json_bytes([row[column] for column in columns]))


def _iter_csv_rows(path: Path) -> Iterator[tuple[int, str, dict[str, str]]]:
    """Yield physical Data24 CSV rows while retaining a digestible source line."""

    with path.open("r", encoding="utf-8", newline="") as stream:
        header_line = stream.readline()
        if not header_line:
            raise Dataset24Error(f"empty CSV file: {path}")
        header = next(csv.reader([header_line]))
        if header != EXPECTED_COLUMNS:
            raise Dataset24Error(
                f"unexpected CSV schema in {path}; expected {EXPECTED_COLUMNS}, got {header}"
            )
        for line_number, raw_line in enumerate(stream, start=2):
            if not raw_line.strip():
                continue
            values = next(csv.reader([raw_line]))
            if len(values) != len(header):
                raise Dataset24Error(
                    f"physical CSV record spans lines or is malformed at {path}:{line_number}"
                )
            yield line_number, raw_line, dict(zip(header, values, strict=True))


def discover_csv_files(source_root: Path) -> list[Path]:
    files = sorted(path for path in source_root.glob("*/*.csv") if path.is_file())
    if not files:
        raise Dataset24Error(f"no UWF-ZeekData24 CSV partitions found below {source_root}")
    return files


def verify_download_manifest(source_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = source_root / "download_manifest.json"
    if not manifest_path.is_file():
        raise Dataset24Error(f"missing controlled-ingestion manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("dataset") != DATASET_NAME:
        raise Dataset24Error(
            f"download manifest names {manifest.get('dataset')!r}, expected {DATASET_NAME!r}"
        )

    verified: list[dict[str, Any]] = []
    for record in sorted(manifest.get("files", []), key=lambda item: item["relative_path"]):
        relative_path = str(record["relative_path"])
        path = source_root / relative_path
        if not path.is_file():
            raise Dataset24Error(f"manifested source file is missing: {path}")
        size = path.stat().st_size
        digest = sha256_file(path)
        if size != int(record["size_bytes"]):
            raise Dataset24Error(f"size mismatch for source file: {relative_path}")
        if digest != record["sha256"]:
            raise Dataset24Error(f"SHA-256 mismatch for source file: {relative_path}")
        verified.append(
            {
                "relative_path": relative_path,
                "size_bytes": size,
                "sha256": digest,
                "source_url": str(record.get("source_url", "")),
            }
        )

    discovered = {path.relative_to(source_root).as_posix() for path in discover_csv_files(source_root)}
    manifested = {record["relative_path"] for record in verified}
    if discovered != manifested:
        missing = sorted(discovered - manifested)
        extra = sorted(manifested - discovered)
        raise Dataset24Error(
            f"download manifest/file set mismatch; unmanifested={missing}, missing={extra}"
        )
    return manifest, verified


def audit_dataset(source_root: Path) -> dict[str, Any]:
    """Audit the real CSV release without deriving features or fitting a model."""

    download_manifest, verified_files = verify_download_manifest(source_root)
    global_nulls: Counter[str] = Counter()
    tactic_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    binary_counts: Counter[str] = Counter()
    cve_counts: Counter[str] = Counter()
    label_ranges: dict[str, list[datetime]] = {}
    daily_labels: dict[str, Counter[str]] = defaultdict(Counter)
    exact_digests: set[str] = set()
    identity_labels: dict[str, set[str]] = defaultdict(set)
    exact_duplicates = 0
    duplicate_technique_rows = 0
    total_rows = 0
    file_reports: list[dict[str, Any]] = []

    for path in discover_csv_files(source_root):
        relative_path = path.relative_to(source_root).as_posix()
        local_nulls: Counter[str] = Counter()
        local_tactics: Counter[str] = Counter()
        local_techniques: Counter[str] = Counter()
        local_start: datetime | None = None
        local_end: datetime | None = None
        local_rows = 0
        for _line_number, _raw_line, row in _iter_csv_rows(path):
            local_rows += 1
            total_rows += 1
            tactic = _label(row["label_tactic"])
            technique = row["label_technique"].strip()
            timestamp = _parse_utc(row["datetime"])
            local_start = timestamp if local_start is None else min(local_start, timestamp)
            local_end = timestamp if local_end is None else max(local_end, timestamp)
            label_range = label_ranges.setdefault(tactic, [timestamp, timestamp])
            label_range[0] = min(label_range[0], timestamp)
            label_range[1] = max(label_range[1], timestamp)
            daily_labels[timestamp.date().isoformat()][tactic] += 1
            local_tactics[tactic] += 1
            local_techniques[technique] += 1
            tactic_counts[tactic] += 1
            technique_counts[technique] += 1
            binary_counts[row["label_binary"].strip().lower()] += 1
            cve_counts[row["label_cve"].strip()] += 1
            if technique.lower() == "duplicate":
                duplicate_technique_rows += 1
            for column, value in row.items():
                if value in MISSING_VALUES:
                    local_nulls[column] += 1
                    global_nulls[column] += 1
            full_digest = _full_row_digest(row, EXPECTED_COLUMNS)
            if full_digest in exact_digests:
                exact_duplicates += 1
            exact_digests.add(full_digest)
            identity_labels[_identity_digest(row, EXPECTED_COLUMNS)].add(tactic)

        if local_start is None or local_end is None:
            raise Dataset24Error(f"source partition contains no rows: {relative_path}")
        file_reports.append(
            {
                "relative_path": relative_path,
                "row_count": local_rows,
                "observed_start": local_start.isoformat().replace("+00:00", "Z"),
                "observed_end": local_end.isoformat().replace("+00:00", "Z"),
                "tactic_counts": dict(sorted(local_tactics.items())),
                "technique_counts": dict(sorted(local_techniques.items())),
                "missing_counts": dict(sorted(local_nulls.items())),
            }
        )

    conflict_sets: Counter[tuple[str, ...]] = Counter()
    for labels in identity_labels.values():
        if len(labels) > 1:
            conflict_sets[tuple(sorted(labels))] += 1
    conflicting_identities = sum(conflict_sets.values())

    benign_range = label_ranges.get("benign")
    attack_ranges = [value for key, value in label_ranges.items() if key != "benign"]
    temporal_separation = False
    if benign_range and attack_ranges:
        attack_start = min(item[0] for item in attack_ranges)
        attack_end = max(item[1] for item in attack_ranges)
        temporal_separation = benign_range[0] > attack_end or attack_start > benign_range[1]

    rare_tactics = {
        label: count for label, count in sorted(tactic_counts.items()) if count < 100
    }
    risks = [
        {
            "id": "R-DATA24-TIME-LABEL",
            "present": temporal_separation,
            "detail": (
                "Benign and attack records occupy disjoint acquisition periods; a single global "
                "chronological split would confound time with class."
            ),
        },
        {
            "id": "R-DATA24-CROSS-LABEL",
            "present": conflicting_identities > 0,
            "detail": (
                f"{conflicting_identities} connection identities occur under multiple tactics."
            ),
        },
        {
            "id": "R-DATA24-DUPLICATE-MARKER",
            "present": duplicate_technique_rows > 0,
            "detail": (
                f"{duplicate_technique_rows} rows use the literal technique marker 'Duplicate'."
            ),
        },
        {
            "id": "R-DATA24-RARE-CLASS",
            "present": bool(rare_tactics),
            "detail": f"Tactics with fewer than 100 records: {rare_tactics}",
        },
    ]

    return {
        "schema_version": "1.0",
        "artifact_type": "uwf_zeekdata24_schema_label_audit",
        "dataset": DATASET_NAME,
        "dataset_version": DATASET_VERSION,
        "source_format": "csv",
        "download_manifest_sha256": sha256_bytes(
            canonical_json_bytes(download_manifest)
        ),
        "source_files": verified_files,
        "columns": EXPECTED_COLUMNS,
        "row_count": total_rows,
        "unique_connection_identity_count": len(identity_labels),
        "exact_duplicate_row_count": exact_duplicates,
        "cross_label_identity_count": conflicting_identities,
        "cross_label_sets": [
            {"labels": list(labels), "count": count}
            for labels, count in sorted(conflict_sets.items())
        ],
        "tactic_counts": dict(sorted(tactic_counts.items())),
        "technique_counts": dict(sorted(technique_counts.items())),
        "binary_counts": dict(sorted(binary_counts.items())),
        "cve_counts": dict(sorted(cve_counts.items())),
        "missing_counts": dict(sorted(global_nulls.items())),
        "missing_rates": {
            column: round(global_nulls.get(column, 0) / total_rows, 12)
            for column in EXPECTED_COLUMNS
        },
        "label_time_ranges": {
            label: {
                "observed_start": values[0].isoformat().replace("+00:00", "Z"),
                "observed_end": values[1].isoformat().replace("+00:00", "Z"),
            }
            for label, values in sorted(label_ranges.items())
        },
        "daily_label_counts": {
            day: dict(sorted(counts.items())) for day, counts in sorted(daily_labels.items())
        },
        "files": file_reports,
        "leakage_and_quality_risks": risks,
    }


def _load_consolidated_events(source_root: Path) -> tuple[bytes, int]:
    records: dict[str, dict[str, Any]] = {}
    for path in discover_csv_files(source_root):
        relative_path = path.relative_to(source_root).as_posix()
        for line_number, raw_line, row in _iter_csv_rows(path):
            identity = _identity_digest(row, EXPECTED_COLUMNS)
            source_ref = {
                "relative_path": relative_path,
                "line_number": line_number,
                "raw_line_sha256": sha256_bytes(raw_line.encode("utf-8")),
                "label_tactic": row["label_tactic"],
                "label_technique": row["label_technique"],
            }
            if identity not in records:
                records[identity] = {
                    "row": row,
                    "tactics": set(),
                    "techniques": set(),
                    "sources": [],
                }
            record = records[identity]
            record["tactics"].add(_label(row["label_tactic"]))
            if row["label_technique"].strip().lower() not in {"none", "duplicate"}:
                record["techniques"].add(row["label_technique"].strip())
            record["sources"].append(source_ref)

    events: list[dict[str, Any]] = []
    for identity, record in records.items():
        row = record["row"]
        tactics = sorted(record["tactics"])
        attack_tactics = [label for label in tactics if label != "benign"]
        if not attack_tactics:
            resolved_label = "benign"
        elif len(attack_tactics) == 1:
            resolved_label = attack_tactics[0]
        else:
            resolved_label = "multi_tactic"
        event = {
            "ts": row["ts"],
            "uid": row["uid"],
            "capture_id": row["datetime"][:10],
            "id.orig_h": row["src_ip_zeek"],
            "id.orig_p": row["src_port_zeek"],
            "id.resp_h": row["dest_ip_zeek"],
            "id.resp_p": row["dest_port_zeek"],
            "proto": row["proto"],
            "service": row["service"],
            "duration": row["duration"],
            "orig_bytes": row["orig_bytes"],
            "resp_bytes": row["resp_bytes"],
            "orig_pkts": row["orig_pkts"],
            "resp_pkts": row["resp_pkts"],
            "conn_state": row["conn_state"],
            "label": resolved_label,
            "observed_tactics": tactics,
            "observed_techniques": sorted(record["techniques"]),
            "source_identity_sha256": identity,
            "_source_records": sorted(
                record["sources"], key=lambda item: (item["relative_path"], item["line_number"])
            ),
        }
        events.append(event)

    events.sort(key=lambda item: (float(item["ts"]), item["uid"], item["source_identity_sha256"]))
    return b"".join(derived_json_bytes(event) for event in events), len(events)


def _allocate_group_splits(
    groups: list[tuple[str, int]], percentages: dict[str, int]
) -> dict[str, str]:
    if len(groups) < 3:
        raise Dataset24Error(
            "each pre-holdout traffic regime needs at least three capture groups"
        )
    if sum(int(percentages[name]) for name in ("train", "validation", "test")) != 100:
        raise Dataset24Error("split percentages must add up to 100")

    count = len(groups)
    train_count = max(1, math.floor(count * int(percentages["train"]) / 100))
    validation_count = max(
        1, math.floor(count * int(percentages["validation"]) / 100)
    )
    if train_count + validation_count >= count:
        train_count = count - 2
        validation_count = 1
    assignments: dict[str, str] = {}
    for index, (group_id, _start) in enumerate(sorted(groups, key=lambda item: item[1])):
        if index < train_count:
            split = "train"
        elif index < train_count + validation_count:
            split = "validation"
        else:
            split = "test"
        assignments[group_id] = split
    return assignments


def _apply_group_temporal_split(
    rows: list[dict[str, Any]], config: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    holdout_start_text = str(config["temporal_holdout_start"])
    holdout_epoch = int(_parse_utc(holdout_start_text).timestamp())
    benign_labels = {str(item).lower() for item in config["benign_labels"]}
    percentages = dict(config["split_percentages"])
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        group = groups.setdefault(
            row["capture_id"],
            {"start": row["window_start_epoch"], "labels": set(), "row_count": 0},
        )
        group["start"] = min(group["start"], row["window_start_epoch"])
        group["labels"].add(row["label"])
        group["row_count"] += 1

    assignments: dict[str, str] = {}
    strata: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for group_id, group in groups.items():
        if group["start"] >= holdout_epoch:
            assignments[group_id] = "temporal_holdout"
            continue
        labels = group["labels"]
        stratum = "benign_only" if labels and labels.issubset(benign_labels) else "attack_present"
        strata[stratum].append((group_id, group["start"]))
    for stratum_groups in strata.values():
        assignments.update(_allocate_group_splits(stratum_groups, percentages))

    updated: list[dict[str, Any]] = []
    for row in rows:
        new_row = dict(row)
        new_row["split"] = assignments[row["capture_id"]]
        updated.append(new_row)

    split_groups: dict[str, list[str]] = defaultdict(list)
    for group_id, split in assignments.items():
        split_groups[split].append(group_id)
    split_manifest = {
        "schema_version": "1.0",
        "strategy": "grouped_chronological_with_reserved_last_week",
        "group_key": "UTC calendar date derived from Data24 datetime",
        "development_strata": "benign_only versus attack_present",
        "temporal_holdout_start": holdout_start_text,
        "percentages": percentages,
        "groups": {
            split: sorted(values) for split, values in sorted(split_groups.items())
        },
        "group_details": {
            group_id: {
                "split": assignments[group_id],
                "start_epoch": group["start"],
                "labels": sorted(group["labels"]),
                "row_count": group["row_count"],
            }
            for group_id, group in sorted(groups.items())
        },
        "limitations": [
            "The reserved last-week holdout is benign-only in the published CSV release.",
            (
                "Development groups are chronological within traffic regime because benign and "
                "attack acquisition periods do not overlap."
            ),
        ],
    }
    return updated, split_manifest


def _fit_training_scaler(rows: list[dict[str, Any]]) -> dict[str, Any]:
    training = [row["features"] for row in rows if row["split"] == "train"]
    if not training:
        raise Dataset24Error("training split is empty")
    feature_count = len(FEATURE_NAMES)
    means = [math.fsum(row[index] for row in training) / len(training) for index in range(feature_count)]
    variances = [
        math.fsum((row[index] - means[index]) ** 2 for row in training) / len(training)
        for index in range(feature_count)
    ]
    scales = [math.sqrt(value) if value > 0 else 1.0 for value in variances]
    return {
        "schema_version": "1.0",
        "method": "standard_score_population_variance",
        "fitted_on_split": "train",
        "training_row_count": len(training),
        "feature_names": FEATURE_NAMES,
        "mean": means,
        "scale": scales,
        "zero_variance_features": [
            FEATURE_NAMES[index] for index, value in enumerate(variances) if value == 0
        ],
    }


def _feature_schema(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": str(config["schema_version"]),
        "dataset": DATASET_NAME,
        "window_seconds": int(config["window_seconds"]),
        "feature_names": FEATURE_NAMES,
        "feature_type": "finite_float64",
        "missing_numeric": "zero",
        "missing_categorical": "missing",
        "categorical_encoding": "fixed protocol/service/connection-state fractions",
        "event_identity_policy": "deduplicate non-label connection columns and union labels",
        "mixed_attack_window_label": str(config["mixed_attack_label"]),
        "scaling": "standard score; parameters fitted on train split only",
    }


def prepare_dataset(
    *, source_root: Path, output: Path, preprocessing_config: dict[str, Any]
) -> dict[str, Any]:
    """Build the deterministic M2 feature snapshot and training-only scaler."""

    audit = audit_dataset(source_root)
    transformed_raw, unique_event_count = _load_consolidated_events(source_root)
    transformed_digest = sha256_bytes(transformed_raw)
    result = normalize_and_window(
        raw=transformed_raw,
        batch_id=f"data24-controlled-ingestion-{transformed_digest[:24]}",
        batch_digest=transformed_digest,
        client_id="central",
        config=preprocessing_config,
    )
    rows, split_manifest = _apply_group_temporal_split(result.rows, preprocessing_config)
    feature_schema = _feature_schema(preprocessing_config)
    scaler = _fit_training_scaler(rows)
    dataset = {
        "schema_version": str(preprocessing_config["schema_version"]),
        "dataset": DATASET_NAME,
        "feature_names": FEATURE_NAMES,
        "rows": rows,
    }

    audit_bytes = derived_json_bytes(audit)
    schema_bytes = derived_json_bytes(feature_schema)
    dataset_bytes = derived_json_bytes(dataset)
    lineage_bytes = derived_json_bytes(result.lineage)
    split_bytes = derived_json_bytes(split_manifest)
    scaler_bytes = derived_json_bytes(scaler)
    normalized_bytes = b"".join(
        derived_json_bytes(event) for event in result.normalized_events
    )
    artifact_digests = {
        "audit.json": sha256_bytes(audit_bytes),
        "feature_schema.json": sha256_bytes(schema_bytes),
        "dataset.json": sha256_bytes(dataset_bytes),
        "lineage.json": sha256_bytes(lineage_bytes),
        "split_manifest.json": sha256_bytes(split_bytes),
        "scaler.json": sha256_bytes(scaler_bytes),
        "normalized_events.jsonl": sha256_bytes(normalized_bytes),
    }
    class_counts = Counter(row["label"] for row in rows)
    split_counts = Counter(row["split"] for row in rows)
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "m2_central_dataset_snapshot",
        "dataset": DATASET_NAME,
        "dataset_version": DATASET_VERSION,
        "code_version": __version__,
        "implementation_files": {
            "fl_forensics/dataset24.py": sha256_file(Path(__file__)),
            "fl_forensics/preprocessing.py": sha256_file(
                Path(normalize_and_window.__code__.co_filename)
            ),
        },
        "source_format": "csv",
        "source_files": audit["source_files"],
        "preprocessing_config_sha256": sha256_bytes(
            canonical_json_bytes(preprocessing_config)
        ),
        "transformed_event_stream_sha256": transformed_digest,
        "input_row_count": audit["row_count"],
        "unique_event_count": unique_event_count,
        "window_count": len(rows),
        "feature_count": len(FEATURE_NAMES),
        "class_counts": dict(sorted(class_counts.items())),
        "split_counts": dict(sorted(split_counts.items())),
        "artifacts": artifact_digests,
    }
    manifest_bytes = derived_json_bytes(manifest)

    write_once(output / "audit.json", audit_bytes)
    write_once(output / "feature_schema.json", schema_bytes)
    write_once(output / "dataset.json", dataset_bytes)
    write_once(output / "lineage.json", lineage_bytes)
    write_once(output / "split_manifest.json", split_bytes)
    write_once(output / "scaler.json", scaler_bytes)
    write_once(output / "normalized_events.jsonl", normalized_bytes)
    write_once(output / "manifest.json", manifest_bytes)
    return {
        "status": "prepared",
        "dataset": DATASET_NAME,
        "workspace": str(output),
        "input_row_count": audit["row_count"],
        "unique_event_count": unique_event_count,
        "window_count": len(rows),
        "feature_count": len(FEATURE_NAMES),
        "class_counts": dict(sorted(class_counts.items())),
        "split_counts": dict(sorted(split_counts.items())),
        "dataset_sha256": artifact_digests["dataset.json"],
    }


def write_audit(source_root: Path, output_path: Path) -> dict[str, Any]:
    audit = audit_dataset(source_root)
    write_once(output_path, derived_json_bytes(audit))
    return {
        "status": "audited",
        "dataset": DATASET_NAME,
        "row_count": audit["row_count"],
        "cross_label_identity_count": audit["cross_label_identity_count"],
        "output": str(output_path),
        "audit_sha256": sha256_file(output_path),
    }


def verify_workspace(workspace: Path) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = workspace / "manifest.json"
    if not manifest_path.is_file():
        return {
            "status": "failed",
            "workspace": str(workspace),
            "error_count": 1,
            "errors": ["missing M2 manifest.json"],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("dataset") != DATASET_NAME:
        errors.append("manifest dataset is not UWF-ZeekData24")
    for name, expected in sorted(manifest.get("artifacts", {}).items()):
        path = workspace / name
        if not path.is_file():
            errors.append(f"missing M2 artifact: {name}")
        elif sha256_file(path) != expected:
            errors.append(f"M2 artifact digest mismatch: {name}")

    if not errors:
        dataset = json.loads((workspace / "dataset.json").read_text(encoding="utf-8"))
        scaler = json.loads((workspace / "scaler.json").read_text(encoding="utf-8"))
        split_manifest = json.loads(
            (workspace / "split_manifest.json").read_text(encoding="utf-8")
        )
        rows = dataset.get("rows", [])
        train_count = sum(row.get("split") == "train" for row in rows)
        if scaler.get("fitted_on_split") != "train":
            errors.append("scaler was not fitted on the training split")
        if scaler.get("training_row_count") != train_count:
            errors.append("scaler training row count does not match dataset")
        group_sets = [set(values) for values in split_manifest.get("groups", {}).values()]
        for index, left in enumerate(group_sets):
            for right in group_sets[index + 1 :]:
                if left & right:
                    errors.append("capture groups overlap across M2 splits")
                    break

    return {
        "status": "verified" if not errors else "failed",
        "dataset": manifest.get("dataset"),
        "workspace": str(workspace),
        "dataset_sha256": manifest.get("artifacts", {}).get("dataset.json"),
        "error_count": len(errors),
        "errors": errors,
    }
