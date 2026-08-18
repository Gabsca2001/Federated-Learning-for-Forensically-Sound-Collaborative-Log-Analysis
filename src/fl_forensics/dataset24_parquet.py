"""Pinned Parquet ingestion for the full UWF-ZeekData24 release."""

from __future__ import annotations

import json
import math
import os
import shutil
import sqlite3
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file
from .dataset24 import (
    DATASET_NAME,
    DATASET_VERSION,
    EXPECTED_COLUMNS,
    LABEL_COLUMNS,
    MISSING_VALUES,
    Dataset24Error,
    _apply_group_temporal_split,
    _feature_schema,
    _fit_training_scaler,
    _full_row_digest,
    _identity_digest,
    _label,
    _parse_utc,
    apply_training_sampling,
)
from .preprocessing import FEATURE_NAMES, build_window_row, derived_json_bytes
from .storage import write_once


PINNED_PARQUET_FILES: dict[str, tuple[int, str]] = {
    (
        "2024-02-25 - 2024-03-03/"
        "part-00000-8b838a85-76eb-4896-a0b6-2fc425e828c2-c000.snappy.parquet"
    ): (
        18_779_592,
        "4d833656b31d4d360691c2178c5c4d1b3c31f01db12c59f6779a08d55e5f0cc7",
    ),
    (
        "2024-03-03 - 2024-03-10/"
        "part-00000-0955ed97-8460-41bd-872a-7375a7f0207e-c000.snappy.parquet"
    ): (
        3_733_862,
        "5a085f2749556f2c711af6f9c2bca9d43b3f19bb43696ef9194869f4ea69eb21",
    ),
    (
        "2024-03-10 - 2024-03-17/"
        "part-00000-071774ae-97f3-4f31-9700-8bfcdf41305a-c000.snappy.parquet"
    ): (
        12_282_299,
        "47bceaf2dd16aee21bd774513fa4549616c066bbe4a20e42f55378f688d9b414",
    ),
    (
        "2024-03-17 - 2024-03-24/"
        "part-00000-5f556208-a1fc-40a1-9cc2-a4e24c76aeb3-c000.snappy.parquet"
    ): (
        27_802_118,
        "97dda852f7240375ec76afcfc96964b4edcda3516ebc0f45a9cd92ae60319f63",
    ),
    (
        "2024-03-24 - 2024-03-31/"
        "part-00000-ea3a47a3-0973-4d6b-a3a2-8dd441ee7901-c000.snappy.parquet"
    ): (
        7_834_447,
        "f7e557a250502782c60b10b955e6d87724730be519006ce30418511bc5ecf512",
    ),
    (
        "2024-10-27 - 2024-11-03/"
        "part-00000-69700ccb-c1c1-4763-beb7-cd0f1a61c268-c000.snappy.parquet"
    ): (
        33_163_904,
        "cadcaf2084ab599d31a530a8cd5f93e010804b9e91ca1e3f8f2631a45ece2575",
    ),
    (
        "2024-11-03 - 2024-11-10/"
        "part-00000-f078acc1-ab56-40a6-a6e1-99d780645c57-c000.snappy.parquet"
    ): (
        36_635_805,
        "0a61b52c3527e6e2e2a5f277778752d89a8ab2bb03147da5aee5d923055ccb7a",
    ),
}
TARGET_TACTICS = {
    "credential_access",
    "exfiltration",
    "initial_access",
    "reconnaissance",
}


def _parquet() -> Any:
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise RuntimeError(
            'Parquet M2 preparation requires: python -m pip install -e ".[m2]"'
        ) from exc
    return parquet


def discover_parquet_files(source_root: Path) -> list[Path]:
    files = sorted(source_root.rglob("*.parquet"))
    if not files:
        raise Dataset24Error(
            f"no UWF-ZeekData24 Parquet partitions found below {source_root}"
        )
    return files


def verify_parquet_manifest(
    source_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = source_root / "download_manifest.json"
    if not manifest_path.is_file():
        raise Dataset24Error(f"missing controlled-ingestion manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("dataset") != DATASET_NAME:
        raise Dataset24Error("Parquet manifest does not name UWF-ZeekData24")
    if manifest.get("source_format") != "parquet":
        raise Dataset24Error("Parquet manifest has the wrong source_format")

    records = {
        str(record["relative_path"]): record for record in manifest.get("files", [])
    }
    if set(records) != set(PINNED_PARQUET_FILES):
        missing = sorted(set(PINNED_PARQUET_FILES) - set(records))
        extra = sorted(set(records) - set(PINNED_PARQUET_FILES))
        raise Dataset24Error(
            f"manifest does not match pinned Parquet release; missing={missing}, extra={extra}"
        )

    verified: list[dict[str, Any]] = []
    for relative_path, (expected_size, expected_digest) in sorted(
        PINNED_PARQUET_FILES.items()
    ):
        record = records[relative_path]
        if int(record["size_bytes"]) != expected_size:
            raise Dataset24Error(f"unpinned size in manifest: {relative_path}")
        if str(record["sha256"]) != expected_digest:
            raise Dataset24Error(f"unpinned SHA-256 in manifest: {relative_path}")
        path = source_root / relative_path
        if not path.is_file():
            raise Dataset24Error(f"manifested Parquet source is missing: {path}")
        if path.stat().st_size != expected_size:
            raise Dataset24Error(f"size mismatch for Parquet source: {relative_path}")
        if sha256_file(path) != expected_digest:
            raise Dataset24Error(f"SHA-256 mismatch for Parquet source: {relative_path}")
        verified.append(
            {
                "relative_path": relative_path,
                "capture_period": str(record.get("capture_period", path.parent.name)),
                "size_bytes": expected_size,
                "sha256": expected_digest,
                "source_url": str(record.get("source_url", "")),
            }
        )

    discovered = {
        path.relative_to(source_root).as_posix()
        for path in discover_parquet_files(source_root)
    }
    if discovered != set(PINNED_PARQUET_FILES):
        raise Dataset24Error("Parquet source directory contains an unexpected file set")
    return manifest, verified


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and not math.isfinite(value):
        return ""
    return str(value)


def _iter_parquet_rows(
    path: Path, parquet: Any
) -> Iterator[tuple[int, dict[str, str]]]:
    source = parquet.ParquetFile(path)
    columns = list(source.schema_arrow.names)
    if columns != EXPECTED_COLUMNS:
        raise Dataset24Error(
            f"unexpected Parquet schema in {path}; expected {EXPECTED_COLUMNS}, got {columns}"
        )
    row_number = 0
    for batch in source.iter_batches(batch_size=65_536, columns=EXPECTED_COLUMNS):
        for physical in batch.to_pylist():
            row_number += 1
            yield row_number, {
                column: _stringify(physical[column]) for column in EXPECTED_COLUMNS
            }


def _database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("PRAGMA cache_size=-131072")
    connection.execute(
        """
        CREATE TABLE raw_records (
            identity TEXT NOT NULL,
            full_digest TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            row_number INTEGER NOT NULL,
            row_json TEXT NOT NULL,
            tactic TEXT NOT NULL,
            technique TEXT NOT NULL,
            binary_label TEXT NOT NULL
        )
        """
    )
    return connection


def _build_index(
    source_root: Path, database_path: Path
) -> tuple[sqlite3.Connection, dict[str, Any]]:
    parquet = _parquet()
    download_manifest, verified_files = verify_parquet_manifest(source_root)
    connection = _database(database_path)

    global_nulls: Counter[str] = Counter()
    tactic_counts: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    binary_counts: Counter[str] = Counter()
    cve_counts: Counter[str] = Counter()
    label_ranges: dict[str, list[datetime]] = {}
    daily_labels: dict[str, Counter[str]] = defaultdict(Counter)
    duplicate_technique_rows = 0
    total_rows = 0
    file_reports: list[dict[str, Any]] = []

    insert = (
        "INSERT INTO raw_records "
        "(identity, full_digest, relative_path, row_number, row_json, tactic, technique, "
        "binary_label) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    for path in discover_parquet_files(source_root):
        relative_path = path.relative_to(source_root).as_posix()
        local_nulls: Counter[str] = Counter()
        local_tactics: Counter[str] = Counter()
        local_techniques: Counter[str] = Counter()
        local_start: datetime | None = None
        local_end: datetime | None = None
        local_rows = 0
        pending: list[tuple[Any, ...]] = []
        for row_number, row in _iter_parquet_rows(path, parquet):
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
            pending.append(
                (
                    _identity_digest(row, EXPECTED_COLUMNS),
                    _full_row_digest(row, EXPECTED_COLUMNS),
                    relative_path,
                    row_number,
                    json.dumps(row, sort_keys=True, separators=(",", ":")),
                    tactic,
                    technique,
                    row["label_binary"].strip().lower(),
                )
            )
            if len(pending) >= 10_000:
                connection.executemany(insert, pending)
                pending.clear()
        if pending:
            connection.executemany(insert, pending)
        connection.commit()
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

    connection.execute(
        "CREATE INDEX raw_identity_source ON raw_records "
        "(identity, relative_path, row_number)"
    )
    connection.commit()
    unique_identities = int(
        connection.execute(
            "SELECT COUNT(DISTINCT identity) FROM raw_records"
        ).fetchone()[0]
    )
    unique_full_rows = int(
        connection.execute(
            "SELECT COUNT(DISTINCT full_digest) FROM raw_records"
        ).fetchone()[0]
    )
    conflict_sets: Counter[tuple[str, ...]] = Counter()
    for _identity, tactics_text in connection.execute(
        "SELECT identity, GROUP_CONCAT(DISTINCT tactic) FROM raw_records "
        "GROUP BY identity HAVING COUNT(DISTINCT tactic) > 1"
    ):
        conflict_sets[tuple(sorted(str(tactics_text).split(",")))] += 1
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
    audit = {
        "schema_version": "1.0",
        "artifact_type": "uwf_zeekdata24_schema_label_audit",
        "dataset": DATASET_NAME,
        "dataset_version": DATASET_VERSION,
        "source_format": "parquet",
        "source_release": "official-weekly-2024",
        "download_manifest_sha256": sha256_bytes(
            canonical_json_bytes(download_manifest)
        ),
        "source_files": verified_files,
        "columns": EXPECTED_COLUMNS,
        "row_count": total_rows,
        "unique_connection_identity_count": unique_identities,
        "exact_duplicate_row_count": total_rows - unique_full_rows,
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
            day: dict(sorted(counts.items()))
            for day, counts in sorted(daily_labels.items())
        },
        "files": file_reports,
        "leakage_and_quality_risks": risks,
    }
    return connection, audit


def audit_parquet_dataset(source_root: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="fl-forensics-parquet-audit-") as temporary:
        connection, audit = _build_index(
            source_root, Path(temporary) / "source-index.sqlite"
        )
        connection.close()
        return audit


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


def _flush_consolidated_event(
    *,
    identity: str,
    row: dict[str, str],
    tactics: set[str],
    primary_tactics: set[str],
    techniques: set[str],
    sources: list[dict[str, Any]],
    batch_id: str,
    batch_digest: str,
) -> tuple[Any, ...]:
    observed_attacks = sorted(label for label in tactics if label != "benign")
    primary_attacks = sorted(
        label for label in primary_tactics if label != "benign"
    )
    primary_targets = sorted(set(primary_attacks) & TARGET_TACTICS)
    observed_targets = sorted(set(observed_attacks) & TARGET_TACTICS)
    if not observed_attacks:
        label = "benign"
    elif len(primary_targets) == 1:
        label = primary_targets[0]
    elif len(primary_targets) > 1:
        label = "multi_tactic"
    elif primary_attacks:
        label = "multi_tactic"
    elif len(observed_targets) == 1:
        label = observed_targets[0]
    else:
        label = "multi_tactic"
    timestamp = _finite_float(row["ts"], default=-1.0)
    if timestamp < 0:
        raise Dataset24Error(f"invalid timestamp for Parquet identity {identity}")
    capture_id = row["datetime"][:10]
    event_id = f"event-central-{identity[:20]}"
    event = {
        "event_id": event_id,
        "batch_id": batch_id,
        "batch_digest": batch_digest,
        "timestamp": timestamp,
        "capture_id": capture_id,
        "uid": row["uid"],
        "originator_host": row["src_ip_zeek"],
        "responder_host": row["dest_ip_zeek"],
        "responder_port": _nonnegative_int(row["dest_port_zeek"]),
        "protocol": _category(row["proto"]),
        "service": _category(row["service"]),
        "connection_state": _category(row["conn_state"]),
        "duration": _finite_float(row["duration"]),
        "originator_bytes": _nonnegative_int(row["orig_bytes"]),
        "responder_bytes": _nonnegative_int(row["resp_bytes"]),
        "originator_packets": _nonnegative_int(row["orig_pkts"]),
        "responder_packets": _nonnegative_int(row["resp_pkts"]),
        "label": label,
        "observed_tactics": sorted(tactics),
        "primary_tactics": primary_attacks,
        "observed_techniques": sorted(techniques),
        "source_identity_sha256": identity,
    }
    window_seconds_placeholder = 0
    return (
        capture_id,
        window_seconds_placeholder,
        timestamp,
        row["uid"],
        identity,
        json.dumps(event, sort_keys=True, separators=(",", ":")),
        json.dumps(sources, sort_keys=True, separators=(",", ":")),
    )


def _consolidate_events(
    connection: sqlite3.Connection,
    *,
    window_seconds: int,
    batch_digest: str,
) -> int:
    connection.execute(
        """
        CREATE TABLE events (
            capture_id TEXT NOT NULL,
            bucket INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            uid TEXT NOT NULL,
            identity TEXT NOT NULL,
            event_json TEXT NOT NULL,
            sources_json TEXT NOT NULL
        )
        """
    )
    batch_id = f"data24-parquet-{batch_digest[:24]}"
    insert = (
        "INSERT INTO events "
        "(capture_id, bucket, timestamp, uid, identity, event_json, sources_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    cursor = connection.execute(
        "SELECT identity, row_json, tactic, technique, binary_label, relative_path, "
        "row_number, full_digest FROM raw_records "
        "ORDER BY identity, relative_path, row_number"
    )
    pending: list[tuple[Any, ...]] = []
    current_identity: str | None = None
    current_row: dict[str, str] | None = None
    tactics: set[str] = set()
    primary_tactics: set[str] = set()
    techniques: set[str] = set()
    sources: list[dict[str, Any]] = []
    unique_count = 0

    def flush() -> None:
        nonlocal unique_count
        if current_identity is None or current_row is None:
            return
        record = list(
            _flush_consolidated_event(
                identity=current_identity,
                row=current_row,
                tactics=tactics,
                primary_tactics=primary_tactics,
                techniques=techniques,
                sources=sources,
                batch_id=batch_id,
                batch_digest=batch_digest,
            )
        )
        record[1] = math.floor(float(record[2]) / window_seconds)
        pending.append(tuple(record))
        unique_count += 1
        if len(pending) >= 10_000:
            connection.executemany(insert, pending)
            pending.clear()

    for (
        identity,
        row_json,
        tactic,
        technique,
        binary_label,
        relative_path,
        row_number,
        digest,
    ) in cursor:
        identity = str(identity)
        if current_identity != identity:
            flush()
            current_identity = identity
            current_row = json.loads(row_json)
            tactics = set()
            primary_tactics = set()
            techniques = set()
            sources = []
        tactics.add(str(tactic))
        if str(binary_label).lower() != "duplicate":
            primary_tactics.add(str(tactic))
        if str(technique).strip().lower() not in {"none", "duplicate"}:
            techniques.add(str(technique).strip())
        sources.append(
            {
                "relative_path": str(relative_path),
                "row_number": int(row_number),
                "source_record_sha256": str(digest),
                "label_tactic": str(tactic),
                "label_technique": str(technique),
                "label_binary": str(binary_label),
            }
        )
    flush()
    if pending:
        connection.executemany(insert, pending)
    connection.execute("DROP TABLE raw_records")
    connection.execute(
        "CREATE INDEX event_window_order ON events "
        "(capture_id, bucket, timestamp, uid, identity)"
    )
    connection.commit()
    return unique_count


def _copy_once(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if source.stat().st_size != destination.stat().st_size:
            raise FileExistsError(
                f"protected artifact already exists with different bytes: {destination}"
            )
        if sha256_file(source) != sha256_file(destination):
            raise FileExistsError(
                f"protected artifact already exists with different bytes: {destination}"
            )
        return
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
        output_stream.flush()
        os.fsync(output_stream.fileno())


def _derive_windows(
    connection: sqlite3.Connection,
    *,
    preprocessing_config: dict[str, Any],
    normalized_path: Path,
    lineage_path: Path,
) -> list[dict[str, Any]]:
    window_seconds = int(preprocessing_config["window_seconds"])
    benign_labels = {
        str(item).lower() for item in preprocessing_config["benign_labels"]
    }
    mixed_attack_label = preprocessing_config.get("mixed_attack_label")
    if mixed_attack_label is not None:
        mixed_attack_label = str(mixed_attack_label)
    percentages = dict(preprocessing_config["split_percentages"])
    split_seed = int(preprocessing_config["split_seed"])
    rows: list[dict[str, Any]] = []
    current_key: tuple[str, int] | None = None
    current_events: list[dict[str, Any]] = []

    def flush_window() -> None:
        if current_key is None:
            return
        capture_id, bucket = current_key
        row, _lineage = build_window_row(
            events=current_events,
            capture_id=capture_id,
            bucket=bucket,
            window_seconds=window_seconds,
            client_id="central",
            benign_labels=benign_labels,
            mixed_attack_label=mixed_attack_label,
            split_seed=split_seed,
            split_percentages=percentages,
        )
        rows.append(row)

    with normalized_path.open("wb") as normalized, lineage_path.open("wb") as lineage:
        cursor = connection.execute(
            "SELECT capture_id, bucket, event_json, sources_json FROM events "
            "ORDER BY capture_id, bucket, timestamp, uid, identity"
        )
        for capture_id, bucket, event_json, sources_json in cursor:
            event = json.loads(event_json)
            key = (str(capture_id), int(bucket))
            if current_key != key:
                flush_window()
                current_key = key
                current_events = []
            current_events.append(event)
            normalized.write(derived_json_bytes(event))
            lineage.write(
                derived_json_bytes(
                    {
                        "record_type": "event",
                        "event_id": event["event_id"],
                        "source_identity_sha256": event["source_identity_sha256"],
                        "source_records": json.loads(sources_json),
                    }
                )
            )
        flush_window()
    return rows


def _append_window_lineage(
    lineage_path: Path,
    rows: list[dict[str, Any]],
    preprocessing_config: dict[str, Any],
) -> None:
    window_seconds = int(preprocessing_config["window_seconds"])
    mixed_label = preprocessing_config.get("mixed_attack_label")
    with lineage_path.open("ab") as lineage:
        for row in rows:
            lineage.write(
                derived_json_bytes(
                    {
                        "record_type": "window",
                        "window_id": row["window_id"],
                        "source_event_ids": row["source_event_ids"],
                        "feature_schema": str(preprocessing_config["schema_version"]),
                        "operations": {
                            "grouping": (
                                f"floor(timestamp/{window_seconds}) within capture_id"
                            ),
                            "feature_names": FEATURE_NAMES,
                            "label_policy": (
                                f"multiple attack labels become {mixed_label}"
                            ),
                        },
                    }
                )
            )


def prepare_parquet_dataset(
    *, source_root: Path, output: Path, preprocessing_config: dict[str, Any]
) -> dict[str, Any]:
    """Build a disk-backed deterministic M2 snapshot from pinned Parquet files."""

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="fl-forensics-parquet-", dir=output.parent
    ) as temporary:
        temporary_root = Path(temporary)
        connection, audit = _build_index(
            source_root, temporary_root / "source-index.sqlite"
        )
        manifest_digest = str(audit["download_manifest_sha256"])
        unique_event_count = _consolidate_events(
            connection,
            window_seconds=int(preprocessing_config["window_seconds"]),
            batch_digest=manifest_digest,
        )
        normalized_path = temporary_root / "normalized_events.jsonl"
        lineage_path = temporary_root / "lineage.jsonl"
        all_rows = _derive_windows(
            connection,
            preprocessing_config=preprocessing_config,
            normalized_path=normalized_path,
            lineage_path=lineage_path,
        )
        connection.close()

        split_rows, split_manifest = _apply_group_temporal_split(
            all_rows, preprocessing_config
        )
        rows, sampling_manifest = apply_training_sampling(
            split_rows, preprocessing_config
        )
        _append_window_lineage(lineage_path, rows, preprocessing_config)
        feature_schema = _feature_schema(preprocessing_config)
        feature_schema["source_format"] = "parquet"
        feature_schema["lineage_format"] = "JSON Lines: event records then retained window records"
        feature_schema["parquet_identity_label_resolution"] = (
            "union connection-identity labels; prefer one specific target tactic over generic "
            "Defense Evasion/Persistence/Privilege Escalation labels; multiple specific target "
            "tactics become multi_tactic"
        )
        scaler = _fit_training_scaler(rows)
        dataset = {
            "schema_version": str(preprocessing_config["schema_version"]),
            "dataset": DATASET_NAME,
            "source_format": "parquet",
            "feature_names": FEATURE_NAMES,
            "rows": rows,
        }

        audit_bytes = derived_json_bytes(audit)
        schema_bytes = derived_json_bytes(feature_schema)
        dataset_bytes = derived_json_bytes(dataset)
        split_bytes = derived_json_bytes(split_manifest)
        scaler_bytes = derived_json_bytes(scaler)
        sampling_bytes = derived_json_bytes(sampling_manifest)
        artifact_digests = {
            "audit.json": sha256_bytes(audit_bytes),
            "feature_schema.json": sha256_bytes(schema_bytes),
            "dataset.json": sha256_bytes(dataset_bytes),
            "lineage.jsonl": sha256_file(lineage_path),
            "split_manifest.json": sha256_bytes(split_bytes),
            "scaler.json": sha256_bytes(scaler_bytes),
            "training_sampling.json": sha256_bytes(sampling_bytes),
            "normalized_events.jsonl": sha256_file(normalized_path),
        }
        class_counts = Counter(row["label"] for row in rows)
        split_counts = Counter(row["split"] for row in rows)
        before_split_counts = Counter(row["split"] for row in split_rows)
        manifest = {
            "schema_version": "1.0",
            "artifact_type": "m2_central_dataset_snapshot",
            "dataset": DATASET_NAME,
            "dataset_version": DATASET_VERSION,
            "code_version": __version__,
            "implementation_files": {
                "fl_forensics/dataset24.py": sha256_file(
                    Path(__file__).with_name("dataset24.py")
                ),
                "fl_forensics/dataset24_parquet.py": sha256_file(Path(__file__)),
                "fl_forensics/preprocessing.py": sha256_file(
                    Path(build_window_row.__code__.co_filename)
                ),
            },
            "source_format": "parquet",
            "source_files": audit["source_files"],
            "download_manifest_sha256": audit["download_manifest_sha256"],
            "preprocessing_config_sha256": sha256_bytes(
                derived_json_bytes(preprocessing_config)
            ),
            "transformed_event_stream_sha256": sha256_file(normalized_path),
            "input_row_count": audit["row_count"],
            "unique_event_count": unique_event_count,
            "window_count_before_training_sampling": len(split_rows),
            "window_count": len(rows),
            "feature_count": len(FEATURE_NAMES),
            "class_counts": dict(sorted(class_counts.items())),
            "split_counts_before_training_sampling": dict(
                sorted(before_split_counts.items())
            ),
            "split_counts": dict(sorted(split_counts.items())),
            "training_sampling": sampling_manifest,
            "artifacts": artifact_digests,
        }
        manifest_bytes = derived_json_bytes(manifest)

        write_once(output / "audit.json", audit_bytes)
        write_once(output / "feature_schema.json", schema_bytes)
        write_once(output / "dataset.json", dataset_bytes)
        _copy_once(lineage_path, output / "lineage.jsonl")
        write_once(output / "split_manifest.json", split_bytes)
        write_once(output / "scaler.json", scaler_bytes)
        write_once(output / "training_sampling.json", sampling_bytes)
        _copy_once(normalized_path, output / "normalized_events.jsonl")
        write_once(output / "manifest.json", manifest_bytes)

    return {
        "status": "prepared",
        "dataset": DATASET_NAME,
        "source_format": "parquet",
        "workspace": str(output),
        "input_row_count": audit["row_count"],
        "unique_event_count": unique_event_count,
        "window_count_before_training_sampling": len(split_rows),
        "window_count": len(rows),
        "feature_count": len(FEATURE_NAMES),
        "class_counts": dict(sorted(class_counts.items())),
        "split_counts": dict(sorted(split_counts.items())),
        "training_sampling": sampling_manifest,
        "dataset_sha256": artifact_digests["dataset.json"],
    }
