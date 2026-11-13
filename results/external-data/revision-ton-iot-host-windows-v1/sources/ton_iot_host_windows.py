"""Batched source-host/minute aggregation with occurrence-level accounting."""

import hashlib
import ipaddress

import numpy as np

from fl_forensics.ton_iot_windows import WindowAccumulator


def canonical_host(value):
    return str(ipaddress.ip_address(str(value).strip()))


def host_window_id(host, bucket):
    return f"toniot-host-occurrence-{int(bucket)}-{hashlib.sha256(canonical_host(host).encode()).hexdigest()}"


def exact_integer_sum(values):
    values = np.asarray(values, dtype=np.int64)
    if values.ndim != 1 or not len(values) or np.any(values < 0):
        raise ValueError("Nonempty nonnegative integer vector required")
    if int(values.max()) * len(values) <= np.iinfo(np.int64).max:
        return int(values.sum(dtype=np.int64))
    return sum(map(int, values))


class HostAccumulator(WindowAccumulator):
    def __init__(self):
        super().__init__()
        self.last_ordinal = -1

    def add_block(self, columns, ordinals, source_name):
        ordinals = np.asarray(ordinals, dtype=np.int64)
        if not len(ordinals) or np.any(np.diff(ordinals) <= 0) or ordinals[0] <= self.last_ordinal:
            raise ValueError("Strictly increasing original occurrence ordinals required")
        if any(len(values) != len(ordinals) for values in columns.values()):
            raise ValueError("Column length mismatch")
        durations = np.asarray(columns["duration"], dtype=np.float64)
        if not np.isfinite(durations).all() or np.any(durations < 0):
            raise ValueError("Finite nonnegative duration required")
        self.durations.frombytes(durations.astype("=f8", copy=False).tobytes())
        self.hosts.update(str(v).strip() for v in columns["dst_ip"] if str(v).strip())
        self.ports.update(int(v) for v in columns["dst_port"] if int(v))
        for counter, field in (
            (self.protocols, "proto"),
            (self.services, "service"),
            (self.states, "conn_state"),
        ):
            counter.update(
                "missing" if str(v).strip().lower() in ("", "-") else str(v).strip().lower()
                for v in columns[field]
            )
        for i, field in enumerate(("src_bytes", "dst_bytes", "src_pkts", "dst_pkts")):
            self.sums[i] += exact_integer_sum(columns[field])
        labels = np.asarray(columns["label"], dtype=np.int64)
        if not np.isin(labels, [0, 1]).all():
            raise ValueError("Binary source labels required")
        counts = np.bincount(labels, minlength=2)
        self.labels.update({str(i): int(n) for i, n in enumerate(counts) if n})
        self.types.update(str(v).strip().lower() for v in columns["type"])
        self.sources[source_name] += len(ordinals)
        self.occurrence_digest.update(ordinals.astype(">u8").tobytes())
        self.last_ordinal = int(ordinals[-1])

    def finish_host(self, host, bucket):
        result = self.finish(bucket, profile="occurrence")
        result["window_id"] = host_window_id(host, bucket)
        result["originator_host_sha256"] = hashlib.sha256(canonical_host(host).encode()).hexdigest()
        result["aggregation"] = "canonical source IP and UTC minute; address is metadata only"
        return result


def pool_host_scores(buckets, scores, labels):
    buckets = np.asarray(buckets)
    scores = np.asarray(scores, dtype=np.float64)
    labels = np.asarray(labels)
    if (
        buckets.ndim != 1
        or not len(buckets)
        or scores.shape != buckets.shape
        or labels.shape != buckets.shape
    ):
        raise ValueError("Equal nonempty vectors required")
    if not np.isfinite(scores).all() or not np.isin(labels, [0, 1]).all():
        raise ValueError("Finite scores and binary labels required")
    order = np.argsort(buckets, kind="stable")
    ordered = buckets[order]
    starts = np.r_[0, np.flatnonzero(ordered[1:] != ordered[:-1]) + 1]
    return (
        ordered[starts],
        np.maximum.reduceat(scores[order], starts),
        np.maximum.reduceat(labels[order], starts).astype(np.int64),
    )
