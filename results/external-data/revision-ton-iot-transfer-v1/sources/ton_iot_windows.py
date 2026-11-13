"""Memory-conscious window aggregation and an exact-field duplicate audit.

Duplicate projection equality is not proof of a repeated physical connection.
"""

import datetime as dt
import hashlib
import statistics
import struct
from array import array
from collections import Counter


class WindowAccumulator:
    def __init__(self):
        self.durations = array("d")
        self.hosts, self.ports = set(), set()
        self.protocols, self.services, self.states = Counter(), Counter(), Counter()
        self.sums = [0, 0, 0, 0]
        self.labels, self.types, self.sources = Counter(), Counter(), Counter()
        self.occurrence_digest = hashlib.sha256()

    def add(self, row, *, ordinal, source_name, label_override=None):
        self.durations.append(float(row["duration"]))
        destination = row["dst_ip"].strip()
        if destination:
            self.hosts.add(destination)
        port = int(float(row["dst_port"]))
        if port:
            self.ports.add(port)
        for counter, field in [
            (self.protocols, "proto"),
            (self.services, "service"),
            (self.states, "conn_state"),
        ]:
            value = row[field].strip().lower()
            counter["missing" if value in ("", "-") else value] += 1
        for index, field in enumerate(("src_bytes", "dst_bytes", "src_pkts", "dst_pkts")):
            self.sums[index] += int(float(row[field]))
        label = int(float(row["label"])) if label_override is None else label_override
        self.labels[str(label)] += 1
        self.types[row["type"].strip().lower()] += 1
        self.sources[source_name] += 1
        self.occurrence_digest.update(struct.pack(">Q", ordinal))

    def finish(self, bucket, *, profile):
        n = len(self.durations)
        if not n:
            raise ValueError("Empty window")
        groups = [
            (self.protocols, ("tcp", "udp", "icmp")),
            (self.services, ("dns", "http", "ssl", "ssh")),
            (self.states, ("sf", "s0", "rej", "rsto", "rstr")),
        ]
        features = [
            float(n),
            float(len(self.hosts)),
            float(len(self.ports)),
            statistics.fmean(self.durations),
            statistics.pstdev(self.durations) if n > 1 else 0.0,
            max(self.durations),
            *map(float, self.sums),
        ]
        for counter, keys in groups:
            features.extend(counter[key] / n for key in keys)
            features.append((n - sum(counter[key] for key in keys)) / n)
        assert len(features) == 25
        return {
            "window_id": f"toniot-{profile}-{bucket}",
            "capture_id": dt.datetime.fromtimestamp(bucket * 60, dt.UTC).date().isoformat(),
            "window_start_epoch": bucket * 60,
            "window_end_epoch": (bucket + 1) * 60,
            "label": "attack" if self.labels.get("1", 0) else "benign",
            "features": [round(v, 12) for v in features],
            "source_record_count": n,
            "binary_record_counts": dict(self.labels),
            "source_type_counts": dict(self.types),
            "source_file_counts": dict(self.sources),
            "ordered_source_ordinal_sha256": self.occurrence_digest.hexdigest(),
            "identity_scope": "source occurrences"
            if profile == "occurrence"
            else "exact non-label projection groups; physical-connection identity unproved",
        }


def duplicate_projection(row, columns):
    """Length-prefix raw UTF-8 field values, excluding uid and both labels."""
    h = hashlib.sha256()
    for field in columns:
        if field in ("uid", "label", "type"):
            continue
        value = row[field].encode("utf-8")
        h.update(struct.pack(">I", len(value)))
        h.update(value)
    return h.digest()


def fold_duplicate_index(records, keep, *, chunk_size=200000):
    """Sort on disk, retain the earliest occurrence and union binary labels.

    The caller owns scratch storage and retains the index digest and aggregate
    diagnostics before deleting the scratch file. `keep` is indexed by original
    global ordinal: 0 = omit, 1 = normal, 2 = attack.
    """
    import numpy as np

    records.sort(order=["digest", "ordinal"], kind="quicksort")
    summary = {
        "valid_occurrences": len(records),
        "projection_groups": 0,
        "duplicate_groups": 0,
        "excess_occurrences": 0,
        "conflicting_binary_groups": 0,
        "conflicting_type_groups": 0,
        "largest_group": 0,
    }
    carry = None

    def emit(minimum, counts, labels, kinds):
        if not len(minimum):
            return
        keep[minimum] = np.where((labels & 2) != 0, 2, 1)
        summary["projection_groups"] += len(minimum)
        summary["duplicate_groups"] += int((counts > 1).sum())
        summary["excess_occurrences"] += int((counts - 1).sum())
        summary["conflicting_binary_groups"] += int((labels == 3).sum())
        summary["conflicting_type_groups"] += int(((kinds & (kinds - 1)) != 0).sum())
        summary["largest_group"] = max(summary["largest_group"], int(counts.max()))

    for offset in range(0, len(records), chunk_size):
        block = records[offset : offset + chunk_size]
        starts = np.r_[0, np.flatnonzero(block["digest"][1:] != block["digest"][:-1]) + 1]
        sizes = np.diff(np.r_[starts, len(block)]).astype(np.int64)
        minimum = np.minimum.reduceat(block["ordinal"], starts).astype(np.int64)
        labels = np.bitwise_or.reduceat(block["label"], starts)
        kinds = np.bitwise_or.reduceat(block["kind"], starts)
        if carry is not None:
            digest, previous_minimum, count, label, kind = carry
            if block["digest"][0] == digest:
                minimum[0] = min(int(minimum[0]), previous_minimum)
                sizes[0] += count
                labels[0] |= label
                kinds[0] |= kind
            else:
                emit(
                    np.array([previous_minimum]),
                    np.array([count]),
                    np.array([label]),
                    np.array([kind]),
                )
        emit(minimum[:-1], sizes[:-1], labels[:-1], kinds[:-1])
        carry = (
            block["digest"][-1],
            int(minimum[-1]),
            int(sizes[-1]),
            int(labels[-1]),
            int(kinds[-1]),
        )
    if carry is not None:
        _, minimum, count, label, kind = carry
        emit(np.array([minimum]), np.array([count]), np.array([label]), np.array([kind]))
    if hasattr(keep, "flush"):
        keep.flush()
    assert summary["projection_groups"] + summary["excess_occurrences"] == len(records)
    return summary
