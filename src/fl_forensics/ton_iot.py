"""Explicit ToN-IoT network-record mapping to the existing Zeek window inputs.

The mapping preserves source-occurrence identity and binary ground truth. It
does not infer missing measurements or treat occurrence IDs as connection IDs.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import math
import re
from decimal import Decimal, InvalidOperation
from typing import Any


class ToNIoTRecordError(ValueError):
    """A source occurrence cannot satisfy the declared mapping contract."""


def _number(row: dict[str, str], field: str, *, integer: bool = False) -> float | int:
    raw = row.get(field)
    try:
        value = Decimal(str(raw).strip())
        if not value.is_finite() or value < 0:
            raise ValueError("nonfinite or negative value")
        if integer:
            if value != value.to_integral_value() or value > 2**53:
                raise ValueError("nonintegral or inexact integer")
            return int(value)
        converted = float(value)
        if not math.isfinite(converted):
            raise ValueError("unrepresentable float")
        return converted
    except (ValueError, InvalidOperation) as error:
        raise ToNIoTRecordError(f"invalid required measurement {field}: {raw!r}") from error


def _category(row: dict[str, str], field: str) -> str:
    if field not in row or row[field] is None:
        raise ToNIoTRecordError(f"missing source column {field}")
    value = str(row[field]).strip().lower()
    return "missing" if value in ("", "-") else value


def normalize_network_record(
    row: dict[str, str], *, source_sha256: str, source_name: str, record_number: int
) -> dict[str, Any]:
    """Map one occurrence; callers must record every accepted or rejected input.

    `record_number` is one-based among CSV data records and excludes the header.
    All files use the same UTC-day/60-second grouping as the Data24 pipeline.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
        raise ValueError("source_sha256 must pin the original source bytes")
    if not re.fullmatch(r"Network_dataset_\d+\.csv", source_name):
        raise ValueError("unexpected source name")
    if isinstance(record_number, bool) or not isinstance(record_number, int) or record_number < 1:
        raise ValueError("record_number must be a positive CSV data-record index")
    addresses = {}
    for field in ("src_ip", "dst_ip"):
        value = str(row.get(field, "")).strip()
        try:
            ipaddress.ip_address(value)
        except ValueError as error:
            raise ToNIoTRecordError(f"invalid source address {field}: {value!r}") from error
        addresses[field] = value
    timestamp = _number(row, "ts")
    if timestamp > 253402300799:
        raise ToNIoTRecordError("timestamp outside the declared seconds-epoch range")
    port = _number(row, "dst_port", integer=True)
    if port > 65535:
        raise ToNIoTRecordError("destination port outside range")
    label = _number(row, "label", integer=True)
    if label not in (0, 1):
        raise ToNIoTRecordError("binary label must be 0 or 1")
    kind = str(row.get("type", "")).strip().lower()
    if kind in ("", "-", "null", "none", "nan") or (kind == "normal") != (label == 0):
        raise ToNIoTRecordError("attack type missing or inconsistent with binary label")
    return {
        "event_id": f"event-toniot-{source_name[:-4]}-{source_sha256}-{record_number}",
        "timestamp": timestamp,
        "capture_id": dt.datetime.fromtimestamp(timestamp, dt.UTC).date().isoformat(),
        "uid": str(row.get("uid") or ""),
        "originator_host": addresses["src_ip"],
        "responder_host": addresses["dst_ip"],
        "responder_port": port,
        "protocol": _category(row, "proto"),
        "service": _category(row, "service"),
        "connection_state": _category(row, "conn_state"),
        "duration": _number(row, "duration"),
        "originator_bytes": _number(row, "src_bytes", integer=True),
        "responder_bytes": _number(row, "dst_bytes", integer=True),
        "originator_packets": _number(row, "src_pkts", integer=True),
        "responder_packets": _number(row, "dst_pkts", integer=True),
        "label": "benign" if label == 0 else "attack",
        "source_attack_type": kind,
        "source_occurrence": {
            "source_name": source_name,
            "source_sha256": source_sha256,
            "record_number": record_number,
        },
        "identity_scope": "CSV occurrence; distinct-connection identity has not been established",
    }
