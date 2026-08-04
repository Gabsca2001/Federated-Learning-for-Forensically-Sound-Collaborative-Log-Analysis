"""Deterministic Zeek JSONL normalization and fixed-size window features."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from .canonical import sha256_bytes


FEATURE_NAMES = [
    "connection_count",
    "unique_destination_count",
    "unique_destination_port_count",
    "duration_mean",
    "duration_std",
    "duration_max",
    "originator_bytes_sum",
    "responder_bytes_sum",
    "originator_packets_sum",
    "responder_packets_sum",
    "protocol_tcp_fraction",
    "protocol_udp_fraction",
    "protocol_icmp_fraction",
    "protocol_other_fraction",
    "service_dns_fraction",
    "service_http_fraction",
    "service_ssl_fraction",
    "service_ssh_fraction",
    "service_other_fraction",
    "state_sf_fraction",
    "state_s0_fraction",
    "state_rej_fraction",
    "state_rsto_fraction",
    "state_rstr_fraction",
    "state_other_fraction",
]


@dataclass(frozen=True)
class PreprocessingResult:
    normalized_events: list[dict[str, Any]]
    rows: list[dict[str, Any]]
    lineage: dict[str, Any]
    discarded_records: dict[str, int]


def _finite_float(value: Any, default: float = 0.0) -> float:
    if value in (None, "", "-"):
        return default
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def _nonnegative_int(value: Any, default: int = 0) -> int:
    result = int(_finite_float(value, float(default)))
    return max(result, 0)


def _category(value: Any, *, missing: str = "missing") -> str:
    if value in (None, "", "-"):
        return missing
    return str(value).strip().lower()


def _event_label(event: dict[str, Any], label_fields: list[str]) -> str | None:
    for field in label_fields:
        value = event.get(field)
        if value not in (None, ""):
            return str(value).strip().lower()
    return None


def _stable_split(group_id: str, seed: int, percentages: dict[str, int]) -> str:
    train = int(percentages["train"])
    validation = int(percentages["validation"])
    test = int(percentages["test"])
    if train + validation + test != 100:
        raise ValueError("split percentages must add up to 100")
    bucket = int.from_bytes(
        hashlib.sha256(f"{seed}:{group_id}".encode("utf-8")).digest()[:8], "big"
    ) % 100
    if bucket < train:
        return "train"
    if bucket < train + validation:
        return "validation"
    return "test"


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _fraction(counter: Counter[str], key: str, total: int) -> float:
    return counter.get(key, 0) / total if total else 0.0


def _choose_label(labels: list[str], benign_labels: set[str]) -> tuple[str, list[str]]:
    observed = sorted(set(labels))
    attacks = [label for label in observed if label not in benign_labels]
    if attacks:
        # Multiple attack labels in a window are surfaced in `observed_labels`.
        # Lexicographic selection is deterministic and never hidden.
        return attacks[0], observed
    return (observed[0] if observed else "unlabeled"), observed


def normalize_and_window(
    *,
    raw: bytes,
    batch_id: str,
    batch_digest: str,
    client_id: str,
    config: dict[str, Any],
) -> PreprocessingResult:
    window_seconds = int(config["window_seconds"])
    seed = int(config["split_seed"])
    percentages = dict(config["split_percentages"])
    label_fields = [str(item) for item in config["label_fields"]]
    benign_labels = {str(item).lower() for item in config["benign_labels"]}

    normalized: list[dict[str, Any]] = []
    discarded: Counter[str] = Counter()
    event_lineage: dict[str, Any] = {}

    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            source = json.loads(raw_line)
        except json.JSONDecodeError:
            discarded["invalid_json"] += 1
            continue
        if not isinstance(source, dict) or "ts" not in source:
            discarded["missing_timestamp"] += 1
            continue
        timestamp = _finite_float(source.get("ts"), default=-1.0)
        if timestamp < 0:
            discarded["invalid_timestamp"] += 1
            continue
        label = _event_label(source, label_fields)
        if label is None:
            discarded["missing_label"] += 1
            continue

        raw_line_digest = sha256_bytes(raw_line)
        event_id = f"event-{client_id}-{sha256_bytes(f'{batch_id}:{line_number}:{raw_line_digest}'.encode())[:20]}"
        capture_id = str(source.get("capture_id") or source.get("pcap") or batch_id)
        event = {
            "event_id": event_id,
            "batch_id": batch_id,
            "batch_digest": batch_digest,
            "source_line": line_number,
            "timestamp": timestamp,
            "capture_id": capture_id,
            "uid": str(source.get("uid") or ""),
            "originator_host": str(source.get("id.orig_h") or source.get("orig_h") or ""),
            "responder_host": str(source.get("id.resp_h") or source.get("resp_h") or ""),
            "responder_port": _nonnegative_int(
                source.get("id.resp_p", source.get("resp_p", 0))
            ),
            "protocol": _category(source.get("proto")),
            "service": _category(source.get("service")),
            "connection_state": _category(source.get("conn_state")),
            "duration": _finite_float(source.get("duration")),
            "originator_bytes": _nonnegative_int(source.get("orig_bytes")),
            "responder_bytes": _nonnegative_int(source.get("resp_bytes")),
            "originator_packets": _nonnegative_int(source.get("orig_pkts")),
            "responder_packets": _nonnegative_int(source.get("resp_pkts")),
            "label": label,
        }
        normalized.append(event)
        event_lineage[event_id] = {
            "batch_id": batch_id,
            "batch_digest": batch_digest,
            "source_line": line_number,
            "raw_line_sha256": raw_line_digest,
            "timestamp": timestamp,
        }

    normalized.sort(key=lambda item: (item["timestamp"], item["source_line"], item["event_id"]))
    windows: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in normalized:
        bucket = math.floor(event["timestamp"] / window_seconds)
        windows[(event["capture_id"], bucket)].append(event)

    rows: list[dict[str, Any]] = []
    window_lineage: dict[str, Any] = {}
    for (capture_id, bucket), events in sorted(windows.items()):
        total = len(events)
        durations = [event["duration"] for event in events]
        protocols = Counter(event["protocol"] for event in events)
        services = Counter(event["service"] for event in events)
        states = Counter(event["connection_state"] for event in events)
        protocol_other = total - sum(protocols.get(key, 0) for key in ("tcp", "udp", "icmp"))
        service_other = total - sum(services.get(key, 0) for key in ("dns", "http", "ssl", "ssh"))
        state_other = total - sum(states.get(key, 0) for key in ("sf", "s0", "rej", "rsto", "rstr"))
        features = [
            float(total),
            float(len({event["responder_host"] for event in events if event["responder_host"]})),
            float(len({event["responder_port"] for event in events if event["responder_port"]})),
            statistics.fmean(durations) if durations else 0.0,
            statistics.pstdev(durations) if len(durations) > 1 else 0.0,
            max(durations, default=0.0),
            float(sum(event["originator_bytes"] for event in events)),
            float(sum(event["responder_bytes"] for event in events)),
            float(sum(event["originator_packets"] for event in events)),
            float(sum(event["responder_packets"] for event in events)),
            _fraction(protocols, "tcp", total),
            _fraction(protocols, "udp", total),
            _fraction(protocols, "icmp", total),
            protocol_other / total,
            _fraction(services, "dns", total),
            _fraction(services, "http", total),
            _fraction(services, "ssl", total),
            _fraction(services, "ssh", total),
            service_other / total,
            _fraction(states, "sf", total),
            _fraction(states, "s0", total),
            _fraction(states, "rej", total),
            _fraction(states, "rsto", total),
            _fraction(states, "rstr", total),
            state_other / total,
        ]
        features = [round(value, 12) for value in features]
        label, observed_labels = _choose_label(
            [event["label"] for event in events], benign_labels
        )
        window_id = f"window-{client_id}-{sha256_bytes(f'{capture_id}:{bucket}'.encode())[:20]}"
        rows.append(
            {
                "window_id": window_id,
                "window_start_epoch": bucket * window_seconds,
                "window_end_epoch": (bucket + 1) * window_seconds,
                "capture_id": capture_id,
                "split": _stable_split(capture_id, seed, percentages),
                "label": label,
                "observed_labels": observed_labels,
                "features": features,
                "source_event_ids": [event["event_id"] for event in events],
            }
        )
        window_lineage[window_id] = {
            "source_event_ids": [event["event_id"] for event in events],
            "feature_schema": str(config["schema_version"]),
            "operations": {
                "grouping": f"floor(timestamp/{window_seconds}) within capture_id",
                "feature_names": FEATURE_NAMES,
                "label_policy": "non-benign lexical priority with all observed labels retained",
            },
        }

    lineage = {
        "schema_version": "1.0",
        "artifact_type": "window_lineage_map",
        "events": event_lineage,
        "windows": window_lineage,
    }
    return PreprocessingResult(
        normalized_events=normalized,
        rows=rows,
        lineage=lineage,
        discarded_records=dict(sorted(discarded.items())),
    )


def derived_json_bytes(value: Any) -> bytes:
    """Deterministic serialization for finite, rounded derived numeric data."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

