"""UNSW-NB15 record preflight for the 25-feature window contract (read-only).

The four official CSVs have no header; column order follows the publisher's
UNSW-NB15_features.csv (49 fields). This script records row counts, malformed rows,
time span, label/category counts, categorical values (proto, state, service) and how
benign and attack records share 60-second windows. It does not build features.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt",
    "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label",
]
NEEDED = ["srcip", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "Spkts", "Dpkts",
          "service", "Stime", "Ltime", "attack_cat", "Label"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, default=root / "data/unsw-nb15/raw")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    if a.output.exists():
        raise SystemExit(f"refusing existing output {a.output}")

    files = sorted(a.input.glob("UNSW-NB15_[1-4].csv"))
    per_file = {}
    malformed = []
    label_counts = Counter()
    cat_counts = Counter()
    proto = Counter()
    state = Counter()
    service = Counter()
    state_by_label = defaultdict(Counter)
    label_cat_conflicts = 0
    tmin, tmax = None, None
    minute = defaultdict(lambda: [0, 0])  # minute -> [benign, attack]
    hour = defaultdict(lambda: [0, 0])
    missing = Counter()
    neg = Counter()
    blank_lines = 0
    idx = {c: i for i, c in enumerate(COLUMNS)}

    for path in files:
        n = 0
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
            for lineno, row in enumerate(csv.reader(f), start=1):
                if not row or all(not x.strip() for x in row):
                    blank_lines += 1
                    continue
                if len(row) != len(COLUMNS):
                    malformed.append({"file": path.name, "line": lineno, "fields": len(row)})
                    continue
                n += 1
                for c in NEEDED:
                    if c != "attack_cat" and row[idx[c]].strip() in ("", "-") and c != "service":
                        missing[c] += 1
                try:
                    st = int(float(row[idx["Stime"]]))
                    lab = int(row[idx["Label"]])
                    for c in ("dur", "sbytes", "dbytes", "Spkts", "Dpkts"):
                        if float(row[idx[c]]) < 0:
                            neg[c] += 1
                except ValueError:
                    malformed.append({"file": path.name, "line": lineno, "reason": "non-numeric"})
                    continue
                cat = row[idx["attack_cat"]].strip() or "(none)"
                tmin = st if tmin is None else min(tmin, st)
                tmax = st if tmax is None else max(tmax, st)
                label_counts[lab] += 1
                cat_counts[cat] += 1
                if (lab == 0) != (cat == "(none)"):
                    label_cat_conflicts += 1
                proto[row[idx["proto"]]] += 1
                state[row[idx["state"]]] += 1
                service[row[idx["service"]]] += 1
                state_by_label[lab][row[idx["state"]]] += 1
                minute[st // 60][lab] += 1
                hour[st // 3600][lab] += 1
        per_file[path.name] = {"sha256": sha256_file(path), "records": n}

    mixed = sum(1 for b, at in minute.values() if b and at)
    attack_only = sum(1 for b, at in minute.values() if at and not b)
    benign_only = sum(1 for b, at in minute.values() if b and not at)
    days = Counter(datetime.fromtimestamp(m * 60, UTC).strftime("%Y-%m-%d") for m in minute)

    result = {
        "files": per_file,
        "records_total": sum(v["records"] for v in per_file.values()),
        "blank_lines_skipped": blank_lines,
        "malformed": {"count": len(malformed), "examples": malformed[:20]},
        "time_span_utc": [datetime.fromtimestamp(tmin, UTC).isoformat(), datetime.fromtimestamp(tmax, UTC).isoformat()],
        "occupied_minutes_by_utc_day": dict(sorted(days.items())),
        "label_counts": {str(k): v for k, v in label_counts.items()},
        "attack_cat_counts": dict(cat_counts.most_common()),
        "label_attack_cat_conflicts": label_cat_conflicts,
        "proto_top": dict(proto.most_common(15)),
        "proto_distinct": len(proto),
        "state_counts": dict(state.most_common()),
        "state_by_label": {str(k): dict(v.most_common()) for k, v in state_by_label.items()},
        "service_counts": dict(service.most_common()),
        "missing_needed_fields": dict(missing),
        "negative_numeric": dict(neg),
        "minute_windows": {"total": len(minute), "mixed_benign_attack": mixed,
                           "attack_only": attack_only, "benign_only": benign_only},
        "hourly_benign_attack": {datetime.fromtimestamp(h * 3600, UTC).strftime("%Y-%m-%d %H"): v
                                 for h, v in sorted(hour.items())},
    }
    a.output.mkdir(parents=True)
    (a.output / "preflight.json").write_text(json.dumps(result, indent=1) + "\n")
    show = {k: result[k] for k in ("records_total", "blank_lines_skipped", "malformed", "time_span_utc",
                                    "occupied_minutes_by_utc_day", "label_counts", "attack_cat_counts",
                                    "label_attack_cat_conflicts", "proto_distinct", "state_counts",
                                    "service_counts", "missing_needed_fields", "negative_numeric", "minute_windows")}
    show["state_by_label"] = result["state_by_label"]
    print(json.dumps(show, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
