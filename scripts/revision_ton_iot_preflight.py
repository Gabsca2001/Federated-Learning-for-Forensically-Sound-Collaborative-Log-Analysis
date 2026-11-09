"""Read-only field/value audit before constructing ToN-IoT network windows.

Column coverage is necessary but insufficient: a sampled Train_Test release does
not establish complete per-source/time windows or equivalent feature semantics.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
from collections import Counter
from decimal import Decimal, InvalidOperation
from pathlib import Path

DEFAULT_COLUMNS = {
    "timestamp": "ts",
    "source_ip": "src_ip",
    "destination_ip": "dst_ip",
    "destination_port": "dst_port",
    "duration": "duration",
    "originator_bytes": "src_bytes",
    "responder_bytes": "dst_bytes",
    "originator_packets": "src_pkts",
    "responder_packets": "dst_pkts",
    "protocol": "proto",
    "service": "service",
    "connection_state": "conn_state",
    "binary_label": "label",
}


def digest(path):
    with path.open("rb") as stream:
        value = hashlib.file_digest(stream, "sha256")
    return value.hexdigest()


def audit(path: Path, *, columns=None, timestamp_unit="seconds", release_scope="unknown"):
    mapping = dict(DEFAULT_COLUMNS if columns is None else columns)
    if set(mapping) != set(DEFAULT_COLUMNS) or len(set(mapping.values())) != len(mapping):
        raise ValueError("supply exactly one distinct source column for every required field")
    if timestamp_unit not in ("seconds", "milliseconds") or release_scope not in (
        "complete-processed-flows",
        "selected-train-test",
        "unknown",
    ):
        raise ValueError("unknown timestamp unit or release scope")
    before = digest(path)
    errors = Counter()
    labels, categories = (
        Counter(),
        {field: Counter() for field in ("protocol", "service", "connection_state")},
    )
    times, count, valid = [], 0, 0
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        header = reader.fieldnames or []
        duplicate_headers = len(header) != len(set(header))
        missing = {field: source for field, source in mapping.items() if source not in header}
        if not missing and not duplicate_headers:
            for row in reader:
                count += 1
                if None in row:
                    errors["row_width"] += 1
                    continue
                bad = False
                for field, source in mapping.items():
                    raw = (row.get(source) or "").strip()
                    try:
                        if field in ("source_ip", "destination_ip"):
                            ipaddress.ip_address(raw)
                        elif field in categories:
                            if not raw:
                                raise ValueError("missing categorical field")
                            categories[field][raw] += 1
                        else:
                            number = Decimal(raw)
                            if not number.is_finite() or number < 0:
                                raise ValueError("missing/nonfinite/negative number")
                            if field == "timestamp":
                                # Bound only representability as an epoch; never guess units.
                                seconds = number / (1000 if timestamp_unit == "milliseconds" else 1)
                                if seconds > Decimal(253402300799):
                                    raise ValueError("unrepresentable declared epoch")
                                times.append(seconds)
                            elif field == "duration":
                                pass
                            elif number != number.to_integral_value():
                                raise ValueError("nonintegral count/port/label")
                            elif field == "destination_port" and number > 65535:
                                raise ValueError("port outside range")
                            elif field == "binary_label":
                                if number not in (0, 1):
                                    raise ValueError("binary ground truth must be 0 or 1")
                                labels[str(int(number))] += 1
                    except (ValueError, InvalidOperation):
                        errors[field] += 1
                        bad = True
                valid += not bad
    after = digest(path)
    if before != after:
        raise ValueError("CSV changed while being audited")
    coverage = bool(count and not missing and not duplicate_headers and not errors)
    return {
        "domain": "ToN-IoT-network-field-preflight-v1",
        "source_file": str(path),
        "source_sha256": before,
        "mapping": mapping,
        "source_header": header,
        "missing_required_columns": missing,
        "duplicate_headers": duplicate_headers,
        "scanned_rows": count,
        "fully_valid_rows": valid,
        "invalid_values_by_field": dict(errors),
        "binary_label_counts": dict(labels),
        "categorical_values_top20": {
            field: dict(counter.most_common(20)) for field, counter in categories.items()
        },
        "timestamp_unit_declared": timestamp_unit,
        "timestamp_range_epoch_seconds": [str(min(times)), str(max(times))] if times else None,
        "required_field_coverage_supported_under_declared_mapping": coverage,
        "release_scope_declared": release_scope,
        "complete_window_coverage_established": False,
        "selected_release_count_distortion_risk": release_scope != "complete-processed-flows",
        "feature_semantics_and_units_verified_against_description": False,
        "dataset_compatibility_verified": False,
        "missing_values_imputed": False,
        "labels_forced_into_MITRE_classes": False,
        "remaining_checks": [
            "Match timestamp/byte/packet definitions and missing-value policy to the official feature description.",
            "Establish release/capture coverage before deriving counts and fractions in source-IP/time windows.",
            "Inspect per-capture and temporal label coverage before defining disjoint train/validation/test groups.",
            "Freeze Data24 model, scaler, binary collapse rule, and optional explicit shared-label mapping before external inference.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument(
        "--columns", type=Path, help="explicit JSON mapping, no first-column guessing"
    )
    parser.add_argument("--timestamp-unit", choices=("seconds", "milliseconds"), default="seconds")
    parser.add_argument(
        "--release-scope",
        choices=("complete-processed-flows", "selected-train-test", "unknown"),
        default="unknown",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(
        args.csv,
        columns=json.loads(args.columns.read_bytes()) if args.columns else None,
        timestamp_unit=args.timestamp_unit,
        release_scope=args.release_scope,
    )
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
