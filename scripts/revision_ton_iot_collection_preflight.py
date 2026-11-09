"""Stream an indexed official ToN-IoT collection without extracting ZIP payloads.

This is a record and representation preflight, not a model evaluation. Missing
measurements remain visible and are never silently replaced with zero.
"""

from __future__ import annotations

import argparse
import ast
import csv
import datetime as dt
import hashlib
import io
import ipaddress
import json
import math
import os
import zipfile
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path

NUMERIC = ("ts", "dst_port", "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "label")
CATEGORIES = ("proto", "service", "conn_state")
REQUIRED = (*NUMERIC, "src_ip", "dst_ip", *CATEGORIES, "type")
MISSING = {"", "-", "(empty)", "nan", "null", "none"}
csv.field_size_limit(16 * 1024 * 1024)


def sha_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class DigestReader(io.RawIOBase):
    def __init__(self, source):
        super().__init__()
        self.source = source
        self.digest = hashlib.sha256()
        self.byte_count = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        chunk = self.source.read(len(buffer))
        size = len(chunk)
        buffer[:size] = chunk
        self.digest.update(chunk)
        self.byte_count += size
        return size


@lru_cache(maxsize=4096)
def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def scan_stream(source, *, name, minute_files=None, minute_labels=None, file_bit=1):
    """Validate each CSV record with bounded auxiliary memory and raw-byte SHA-256."""
    raw = DigestReader(source)
    stream = io.TextIOWrapper(
        io.BufferedReader(raw, buffer_size=1024 * 1024), encoding="utf-8-sig", newline=""
    )
    reader = csv.reader(stream)
    header = next(reader)
    if len(header) != len(set(header)) or not set(REQUIRED).issubset(header):
        raise ValueError(f"Missing or duplicate required header fields in {name}")
    positions = {field: header.index(field) for field in REQUIRED}
    numeric = [(field, positions[field]) for field in NUMERIC]
    categoricals = [(field, positions[field]) for field in CATEGORIES]
    missing, invalid, labels, types, days = Counter(), Counter(), Counter(), Counter(), Counter()
    categories = {field: Counter() for field in CATEGORIES}
    examples, row_count, strict_valid, policy_valid = [], 0, 0, 0
    rejected, daily_labels = [], defaultdict(Counter)
    minimum, maximum, previous, regressions, label_conflicts = None, None, None, 0, 0
    day_cache = {}
    for row in reader:
        row_count += 1
        if len(row) != len(header):
            invalid["row_width"] += 1
            if len(rejected) < 10000:
                rejected.append({"record_number": row_count, "reasons": ["row_width"]})
            if len(examples) < 5:
                examples.append({"record": row_count, "reason": "row_width", "columns": len(row)})
            continue
        bad = False
        reasons = []
        parsed = {}
        for field, index in numeric:
            value = row[index].strip()
            if value.lower() in MISSING:
                missing[field] += 1
                bad = True
                reasons.append("missing_" + field)
                continue
            try:
                number = float(value)
                if not math.isfinite(number) or number < 0:
                    raise ValueError("nonfinite or negative")
                if field not in ("ts", "duration") and (not number.is_integer() or number > 2**53):
                    raise ValueError("nonintegral or inexact integer")
                if field == "dst_port" and number > 65535:
                    raise ValueError("port outside range")
                if field == "label" and number not in (0, 1):
                    raise ValueError("nonbinary label")
                if field == "ts" and number > 253402300799:
                    raise ValueError("unrepresentable seconds epoch")
                parsed[field] = number
            except ValueError:
                invalid[field] += 1
                bad = True
                reasons.append("invalid_" + field)
        for field in ("src_ip", "dst_ip"):
            value = row[positions[field]].strip()
            if not valid_ip(value):
                invalid[field] += 1
                bad = True
                reasons.append("invalid_" + field)
        measurement_bad = bad
        for field, index in categoricals:
            value = row[index].strip().lower()
            categories[field][value] += 1
            if value in MISSING:
                missing[field] += 1
                bad = True
        kind = row[positions["type"]].strip().lower()
        types[kind] += 1
        if not kind or kind in MISSING:
            invalid["type"] += 1
            bad = True
            measurement_bad = True
            reasons.append("missing_type")
        if "label" in parsed:
            label = int(parsed["label"])
            labels[str(label)] += 1
            if (kind == "normal") != (label == 0):
                label_conflicts += 1
                bad = True
                measurement_bad = True
                reasons.append("label_type_conflict")
        timestamp = parsed.get("ts")
        if timestamp is not None:
            minimum = timestamp if minimum is None else min(minimum, timestamp)
            maximum = timestamp if maximum is None else max(maximum, timestamp)
            regressions += previous is not None and timestamp < previous
            previous = timestamp
            day = int(timestamp) // 86400
            if day not in day_cache:
                day_cache[day] = dt.datetime.fromtimestamp(day * 86400, dt.UTC).date().isoformat()
            date = day_cache[day]
            days[date] += 1
            if "label" in parsed:
                daily_labels[date][str(int(parsed["label"]))] += 1
            minute = int(timestamp) // 60
            if minute_files is not None:
                minute_files[minute] = minute_files.get(minute, 0) | file_bit
            if minute_labels is not None and "label" in parsed:
                minute_labels[minute] = minute_labels.get(minute, 0) | (1 << int(parsed["label"]))
        strict_valid += not bad
        policy_valid += not measurement_bad
        if measurement_bad and len(rejected) < 10000:
            rejected.append({"record_number": row_count, "reasons": reasons})
        if bad and len(examples) < 5:
            examples.append({"record": row_count, "reason": "missing_or_invalid_required_value"})
    result = {
        "name": name,
        "header": header,
        "field_count": len(header),
        "rows": row_count,
        "strict_fully_observed_valid_rows": strict_valid,
        "missing_values": dict(missing),
        "usable_rows_under_explicit_category_policy": policy_valid,
        "rejected_measurement_rows": row_count - policy_valid,
        "rejected_occurrences_first10000": rejected,
        "rejection_detail_truncated": row_count - policy_valid > 10000,
        "utc_day_binary_label_counts": {
            day: dict(counts) for day, counts in sorted(daily_labels.items())
        },
        "invalid_values": dict(invalid),
        "binary_label_counts": dict(labels),
        "attack_type_counts": dict(types),
        "label_type_conflicts": label_conflicts,
        "category_counts": {k: dict(v) for k, v in categories.items()},
        "utc_day_counts": dict(sorted(days.items())),
        "timestamp_range_seconds": [minimum, maximum],
        "timestamp_regressions_within_file": regressions,
        "diagnostic_examples": examples,
        "scanned_bytes": raw.byte_count,
        "sha256": raw.digest.hexdigest(),
    }
    stream.close()
    return result


def native_path(entry, field):
    if os.name != "nt":
        key = "wsl_archive_path" if field == "archive_path" else "wsl_path"
        if key in entry:
            return Path(entry[key])
        value = str(entry[field]).replace("\\", "/")
        if len(value) > 2 and value[1] == ":":
            return Path("/mnt/" + value[0].lower() + value[2:])
    return Path(entry[field])


def feature_mapping(reference):
    reference = Path(reference)
    paths = (
        [
            reference / "src/fl_forensics/preprocessing.py",
            reference / "src/fl_forensics/dataset24_parquet.py",
            reference / "configs/m2-parquet.yaml",
        ]
        if (reference / "src/fl_forensics/preprocessing.py").exists()
        else [
            reference / "preprocessing.py",
            reference / "dataset24_parquet.py",
            reference / "m2-parquet.yaml",
        ]
    )
    path = paths[0]
    root = ast.parse(path.read_text())
    names = next(
        ast.literal_eval(n.value)
        for n in root.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "FEATURE_NAMES" for t in n.targets)
    )
    dependencies = {}
    for name in names:
        if name == "connection_count":
            fields, operation = (
                ["ts"],
                "Count every retained event in the global capture-day/60-second bucket.",
            )
        elif name == "unique_destination_count":
            fields, operation = ["dst_ip"], "Count distinct nonempty destination IP values."
        elif name == "unique_destination_port_count":
            fields, operation = (
                ["dst_port"],
                "Count distinct nonzero destination ports, matching the existing implementation.",
            )
        elif name.startswith("duration_"):
            fields, operation = (
                ["duration"],
                {
                    "duration_mean": "Arithmetic mean in seconds.",
                    "duration_std": "Population standard deviation in seconds.",
                    "duration_max": "Maximum duration in seconds.",
                }[name],
            )
        elif name.endswith("_sum"):
            source = {
                "originator_bytes_sum": "src_bytes",
                "responder_bytes_sum": "dst_bytes",
                "originator_packets_sum": "src_pkts",
                "responder_packets_sum": "dst_pkts",
            }[name]
            fields, operation = (
                [source],
                "Sum the corresponding connection-level payload bytes or packet counts.",
            )
        elif name.startswith("protocol_"):
            fields, operation = (
                ["proto"],
                "Fraction of all retained connections in the named category; other is the complement of tcp/udp/icmp.",
            )
        elif name.startswith("service_"):
            fields, operation = (
                ["service"],
                "Fraction of all retained connections in the named category; other is the complement of dns/http/ssl/ssh.",
            )
        elif name.startswith("state_"):
            fields, operation = (
                ["conn_state"],
                "Fraction of all retained connections in the named category; other is the complement of SF/S0/REJ/RSTO/RSTR.",
            )
        else:
            raise ValueError(f"Unmapped feature {name}")
        dependencies[name] = {"source_fields": fields, "operation": operation}
    assert len(dependencies) == 25
    return {
        "feature_names": names,
        "feature_mapping": dependencies,
        "pipeline_sources": {p.name: sha_file(p) for p in paths},
        "window_seconds": 60,
        "grouping": "UTC capture day and floor(ts/60), merged across all source files; no source-IP partition is introduced.",
    }


def run(index_path, reference, output):
    index = json.loads(Path(index_path).read_text())
    entries = index["files"]
    expected = {f"Network_dataset_{n}.csv" for n in range(1, 24)}
    if len(entries) != 23 or {e["name"] for e in entries} != expected:
        raise ValueError("Expected exactly the 23 indexed official network CSVs")
    contract = feature_mapping(reference)
    minute_files, minute_labels, files, archives = {}, {}, [], {}
    auditor_sha256 = sha_file(__file__)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    try:
        for entry in entries:
            if entry["storage"] == "zip_entry":
                path = native_path(entry, "archive_path")
                if path not in archives:
                    if sha_file(path) != index["archive"]["sha256"]:
                        raise ValueError("Archive digest mismatch")
                    archives[path] = zipfile.ZipFile(path)
                stream = archives[path].open(entry["archive_entry"])
            elif entry["storage"] == "file":
                stream = native_path(entry, "path").open("rb")
            else:
                raise ValueError("Unknown source storage")
            with stream:
                report = scan_stream(
                    stream,
                    name=entry["name"],
                    minute_files=minute_files,
                    minute_labels=minute_labels,
                    file_bit=1 << len(files),
                )
            if report["sha256"] != entry["sha256"] or report["scanned_bytes"] != entry["bytes"]:
                raise ValueError(f"Source bytes differ from acquisition index: {entry['name']}")
            if ",".join(report["header"]) != entry["header"]:
                raise ValueError("Header differs from acquisition index")
            files.append(report)
            (output / "progress.json").write_text(
                json.dumps(
                    {
                        "verified_files": len(files),
                        "scanned_rows": sum(f["rows"] for f in files),
                        "last_file": entry["name"],
                    },
                    indent=2,
                )
                + "\n"
            )
            print(
                json.dumps(
                    {
                        "status": "file_audited",
                        "name": entry["name"],
                        "rows": report["rows"],
                        "strict_valid_rows": report["strict_fully_observed_valid_rows"],
                        "missing": report["missing_values"],
                        "invalid": report["invalid_values"],
                    }
                ),
                flush=True,
            )
    finally:
        for archive in archives.values():
            archive.close()
    sums = {}
    for key in (
        "missing_values",
        "invalid_values",
        "binary_label_counts",
        "attack_type_counts",
        "utc_day_counts",
    ):
        total = Counter()
        for file in files:
            total.update(file[key])
        sums[key] = dict(sorted(total.items()))
    result = dict(
        domain="ToN-IoT-official-network-collection-preflight-v1",
        verified_utc=dt.datetime.now(dt.UTC).isoformat(),
        acquisition_index_sha256=sha_file(index_path),
        auditor_sha256=auditor_sha256,
        source_files=files,
        **contract,
        **sums,
        file_count=len(files),
        scanned_rows=sum(f["rows"] for f in files),
        strict_fully_observed_valid_rows=sum(f["strict_fully_observed_valid_rows"] for f in files),
        usable_rows_under_explicit_category_policy=sum(
            f["usable_rows_under_explicit_category_policy"] for f in files
        ),
        rejected_measurement_rows=sum(f["rejected_measurement_rows"] for f in files),
        category_missing_value_policy="Empty or dash categories become missing and contribute to the existing other fractions; no record is dropped merely for unknown service.",
        label_type_conflicts=sum(f["label_type_conflicts"] for f in files),
        global_occupied_60s_buckets=len(minute_files),
        buckets_spanning_multiple_files=sum(v.bit_count() > 1 for v in minute_files.values()),
        mixed_binary_label_buckets=sum(v == 3 for v in minute_labels.values()),
        pure_benign_buckets=sum(v == 1 for v in minute_labels.values()),
        pure_attack_buckets=sum(v == 2 for v in minute_labels.values()),
        all_indexed_bytes_reverified=True,
        all_25_feature_source_columns_present=all(
            set(REQUIRED).issubset(f["header"]) for f in files
        ),
        timestamp_unit_declared="seconds",
        missing_values_imputed=False,
        source_records_discarded=False,
        source_data_modified=False,
        exact_duplicate_identity_audit_performed=False,
        source_connection_identity_policy_frozen=False,
        model_evaluation_started=False,
        dataset_compatibility_verified=False,
        limitations=[
            "Processed release completeness does not establish recovery of every original raw capture event.",
            "Record counts are CSV occurrences; cross-file join multiplicity and exact connection identities require a separate audit.",
            "Missing numeric values require an explicit policy and sensitivity analysis before claiming representation equivalence.",
            "Binary labels remain separate from attack types; no forced MITRE mapping is performed.",
            "Timestamp and duration units must be checked against official source documentation; a declared unit alone is not evidence.",
        ],
    )
    (output / "collection-preflight.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "status": "collection_preflight_complete",
                "files": len(files),
                "rows": result["scanned_rows"],
                "missing": result["missing_values"],
                "invalid": result["invalid_values"],
                "cross_file_buckets": result["buckets_spanning_multiple_files"],
            }
        ),
        flush=True,
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument(
        "--pipeline-reference",
        "--pipeline-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.index, args.pipeline_reference, args.output)
