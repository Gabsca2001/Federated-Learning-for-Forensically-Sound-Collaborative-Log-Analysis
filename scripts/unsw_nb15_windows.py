"""Build 25-feature 60-second windows from UNSW-NB15 (approved Argus→Zeek mapping).

Grouping follows Data24: UTC capture day and floor(Stime / 60) over all records.
Feature formulas follow ``fl_forensics.preprocessing.build_window_row``; a random
sample of windows is recomputed with that function as an independent check.

Field mapping: dstip → responder host, dsport → responder port (0 or missing excluded),
dur → duration, sbytes/dbytes → originator/responder bytes (UNSW transaction bytes),
Spkts/Dpkts → packets, proto/service lower-cased ('-' → missing → other).
State mapping (approved): FIN, CON → sf; INT, REQ → s0; RST → rsto; others → other.
Window label: attack if any record is an attack; family = the single attack category,
'multiple' if several. 'Backdoors' is merged into 'Backdoor'.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from unsw_nb15_preflight import COLUMNS

from fl_forensics.preprocessing import FEATURE_NAMES, build_window_row

STATE_MAP = {"FIN": "sf", "CON": "sf", "INT": "s0", "REQ": "s0", "RST": "rsto"}
CATEGORY_MERGE = {"Backdoors": "Backdoor"}
IDX = {c: i for i, c in enumerate(COLUMNS)}


def normalize(row: list[str]) -> dict:
    port = row[IDX["dsport"]].strip()
    try:
        port_val = int(port, 0) if port not in ("", "-") else 0
    except ValueError:
        port_val = 0
    service = row[IDX["service"]].strip().lower()
    cat = row[IDX["attack_cat"]].strip()
    cat = CATEGORY_MERGE.get(cat, cat)
    return {
        "responder_host": row[IDX["dstip"]].strip(),
        "responder_port": port_val,
        "duration": float(row[IDX["dur"]]),
        "originator_bytes": int(float(row[IDX["sbytes"]])),
        "responder_bytes": int(float(row[IDX["dbytes"]])),
        "originator_packets": int(float(row[IDX["Spkts"]])),
        "responder_packets": int(float(row[IDX["Dpkts"]])),
        "protocol": row[IDX["proto"]].strip().lower(),
        "service": "missing" if service in ("", "-") else service,
        "connection_state": STATE_MAP.get(row[IDX["state"]].strip(), "other"),
        "label": "benign" if int(row[IDX["Label"]]) == 0 else (cat or "attack"),
        "stime": int(float(row[IDX["Stime"]])),
    }


class Acc:
    __slots__ = ("dur", "hosts", "labels", "n", "ob", "op", "ports", "proto", "rb", "rp", "state", "svc")

    def __init__(self):
        self.n = 0
        self.hosts, self.ports, self.dur = set(), set(), []
        self.ob = self.rb = self.op = self.rp = 0
        self.proto, self.svc, self.state, self.labels = Counter(), Counter(), Counter(), Counter()

    def add(self, e: dict) -> None:
        self.n += 1
        if e["responder_host"]:
            self.hosts.add(e["responder_host"])
        if e["responder_port"]:
            self.ports.add(e["responder_port"])
        self.dur.append(e["duration"])
        self.ob += e["originator_bytes"]
        self.rb += e["responder_bytes"]
        self.op += e["originator_packets"]
        self.rp += e["responder_packets"]
        self.proto[e["protocol"]] += 1
        self.svc[e["service"]] += 1
        self.state[e["connection_state"]] += 1
        self.labels[e["label"]] += 1

    def features(self) -> list[float]:
        n = self.n

        def fr(c, k):
            return c.get(k, 0) / n

        return [
            float(n), float(len(self.hosts)), float(len(self.ports)),
            statistics.fmean(self.dur), statistics.pstdev(self.dur) if n > 1 else 0.0, max(self.dur),
            float(self.ob), float(self.rb), float(self.op), float(self.rp),
            fr(self.proto, "tcp"), fr(self.proto, "udp"), fr(self.proto, "icmp"),
            (n - sum(self.proto.get(k, 0) for k in ("tcp", "udp", "icmp"))) / n,
            fr(self.svc, "dns"), fr(self.svc, "http"), fr(self.svc, "ssl"), fr(self.svc, "ssh"),
            (n - sum(self.svc.get(k, 0) for k in ("dns", "http", "ssl", "ssh"))) / n,
            fr(self.state, "sf"), fr(self.state, "s0"), fr(self.state, "rej"),
            fr(self.state, "rsto"), fr(self.state, "rstr"),
            (n - sum(self.state.get(k, 0) for k in ("sf", "s0", "rej", "rsto", "rstr"))) / n,
        ]


def iter_events(files):
    for path in files:
        with path.open(newline="", encoding="utf-8-sig") as f:
            for row in csv.reader(f):
                if len(row) == len(COLUMNS):
                    yield normalize(row)


def key_of(stime: int) -> tuple[str, int]:
    return datetime.fromtimestamp(stime, UTC).strftime("%Y-%m-%d"), stime // 60


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, default=root / "data/unsw-nb15/raw")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--check-windows", type=int, default=12)
    a = p.parse_args(argv)
    if a.output.exists():
        raise SystemExit(f"refusing existing output {a.output}")
    files = sorted(a.input.glob("UNSW-NB15_[1-4].csv"))

    accs: dict[tuple[str, int], Acc] = defaultdict(Acc)
    total = 0
    for e in iter_events(files):
        accs[key_of(e["stime"])].add(e)
        total += 1

    rows = []
    for (day, bucket), acc in sorted(accs.items(), key=lambda kv: kv[0][1]):
        attacks = sorted(k for k in acc.labels if k != "benign")
        rows.append({
            "window_id": f"unsw-{bucket}",
            "capture_id": day,
            "window_start_epoch": bucket * 60,
            "window_end_epoch": bucket * 60 + 60,
            "label": "attack" if attacks else "benign",
            "family": "benign" if not attacks else (attacks[0] if len(attacks) == 1 else "multiple"),
            "attack_record_fraction": sum(v for k, v in acc.labels.items() if k != "benign") / acc.n,
            "source_label_counts": dict(acc.labels),
            "source_record_count": acc.n,
            "features": acc.features(),
        })

    # Independent check: recompute sampled windows with the reference build_window_row.
    rng = random.Random(0)
    sample = set(rng.sample([r["window_start_epoch"] // 60 for r in rows], min(a.check_windows, len(rows))))
    events = defaultdict(list)
    for e in iter_events(files):
        b = e["stime"] // 60
        if b in sample:
            events[b].append(e | {"event_id": f"unsw-{b}-{len(events[b])}"})
    by_bucket = {r["window_start_epoch"] // 60: r for r in rows}
    checks = []
    for b in sorted(sample):
        ref, _ = build_window_row(
            events=events[b], capture_id=by_bucket[b]["capture_id"], bucket=b, window_seconds=60,
            client_id="unsw", benign_labels={"benign"}, mixed_attack_label="multiple",
            split_seed=0, split_percentages={"train": 100, "validation": 0, "test": 0},
        )
        ref_feat = ref["features"]
        diff = max(abs(x - y) / max(1.0, abs(y)) for x, y in zip(by_bucket[b]["features"], ref_feat, strict=True))
        checks.append({"bucket": b, "records": len(events[b]), "max_relative_difference": diff})
    if any(c["max_relative_difference"] > 1e-9 for c in checks):
        raise SystemExit(f"reference check failed: {checks}")

    fam = Counter(r["family"] for r in rows)
    out = {
        "dataset": "UNSW-NB15",
        "feature_names": FEATURE_NAMES,
        "window_seconds": 60,
        "state_mapping": STATE_MAP | {"*": "other"},
        "category_merge": CATEGORY_MERGE,
        "source_files": {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
        "records": total,
        "rows": rows,
    }
    a.output.mkdir(parents=True)
    (a.output / "windows.json").write_text(json.dumps(out) + "\n")
    summary = {
        "records": total,
        "windows": len(rows),
        "label_counts": dict(Counter(r["label"] for r in rows)),
        "family_counts": dict(fam.most_common()),
        "windows_by_day": dict(Counter(r["capture_id"] for r in rows)),
        "attack_record_fraction_in_attack_windows": {
            "median": statistics.median(r["attack_record_fraction"] for r in rows if r["label"] == "attack"),
            "p10": sorted(r["attack_record_fraction"] for r in rows if r["label"] == "attack")[
                len([r for r in rows if r["label"] == "attack"]) // 10],
        },
        "reference_checks": checks,
        "windows_sha256": hashlib.sha256((a.output / "windows.json").read_bytes()).hexdigest(),
    }
    (a.output / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
