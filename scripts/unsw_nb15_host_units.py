"""Build source-host x minute units from UNSW-NB15 with the 25-feature formulas.

Same normalization, state mapping and feature formulas as ``unsw_nb15_windows.py``;
grouping is (srcip, UTC day, floor(Stime / 60)). Unit label: attack if any record of
that source host in that minute is an attack. Sampled units are recomputed with the
reference ``build_window_row`` as an independent check.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from unsw_nb15_preflight import COLUMNS
from unsw_nb15_windows import CATEGORY_MERGE, STATE_MAP, Acc, key_of, normalize

from fl_forensics.preprocessing import FEATURE_NAMES, build_window_row

SRC = COLUMNS.index("srcip")


def iter_events(files):
    for path in files:
        with path.open(newline="", encoding="utf-8-sig") as f:
            for row in csv.reader(f):
                if len(row) == len(COLUMNS):
                    e = normalize(row)
                    e["srcip"] = row[SRC].strip()
                    yield e


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, default=root / "data/unsw-nb15/raw")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    if a.output.exists():
        raise SystemExit(f"refusing existing output {a.output}")
    files = sorted(a.input.glob("UNSW-NB15_[1-4].csv"))

    accs: dict[tuple[str, str, int], Acc] = defaultdict(Acc)
    for e in iter_events(files):
        day, bucket = key_of(e["stime"])
        accs[(e["srcip"], day, bucket)].add(e)

    rows = []
    for (src, day, bucket), acc in sorted(accs.items(), key=lambda kv: (kv[0][2], kv[0][0])):
        attacks = sorted(k for k in acc.labels if k != "benign")
        rows.append({
            "unit_id": f"unsw-{src}-{bucket}",
            "source_host": src,
            "capture_id": day,
            "window_start_epoch": bucket * 60,
            "label": "attack" if attacks else "benign",
            "family": "benign" if not attacks else (attacks[0] if len(attacks) == 1 else "multiple"),
            "attack_record_fraction": sum(v for k, v in acc.labels.items() if k != "benign") / acc.n,
            "source_record_count": acc.n,
            "features": acc.features(),
        })

    rng = random.Random(0)
    keys = rng.sample([(r["source_host"], r["window_start_epoch"] // 60) for r in rows], 20)
    wanted = set(keys)
    ev = defaultdict(list)
    for e in iter_events(files):
        k = (e["srcip"], e["stime"] // 60)
        if k in wanted:
            ev[k].append(e | {"event_id": f"{k}-{len(ev[k])}"})
    by_key = {(r["source_host"], r["window_start_epoch"] // 60): r for r in rows}
    checks = []
    for k in keys:
        ref, _ = build_window_row(
            events=ev[k], capture_id=by_key[k]["capture_id"], bucket=k[1], window_seconds=60, client_id="u",
            benign_labels={"benign"}, mixed_attack_label="multiple", split_seed=0,
            split_percentages={"train": 100, "validation": 0, "test": 0},
        )
        d = max(abs(x - y) / max(1.0, abs(y)) for x, y in zip(by_key[k]["features"], ref["features"], strict=True))
        checks.append(d)
    if max(checks) > 1e-9:
        raise SystemExit(f"reference check failed: {checks}")

    minute = defaultdict(lambda: [0, 0])
    for r in rows:
        minute[r["window_start_epoch"]][r["label"] == "attack"] += 1
    attack_minutes = [m for m, v in minute.items() if v[1]]
    out = {
        "dataset": "UNSW-NB15", "unit": "source host x 60 s", "feature_names": FEATURE_NAMES,
        "state_mapping": STATE_MAP | {"*": "other"}, "category_merge": CATEGORY_MERGE, "rows": rows,
    }
    a.output.mkdir(parents=True)
    (a.output / "units.json").write_text(json.dumps(out) + "\n")
    att = [r for r in rows if r["label"] == "attack"]
    summary = {
        "units": len(rows),
        "label_counts": dict(Counter(r["label"] for r in rows)),
        "units_by_day": dict(Counter(r["capture_id"] for r in rows)),
        "distinct_source_hosts": len({r["source_host"] for r in rows}),
        "attack_source_hosts": sorted({r["source_host"] for r in att}),
        "hosts_with_both_labels": len({r["source_host"] for r in att} & {r["source_host"] for r in rows if r["label"] == "benign"}),
        "attack_record_fraction_in_attack_units": {
            "median": statistics.median(r["attack_record_fraction"] for r in att),
            "share_pure": sum(r["attack_record_fraction"] == 1.0 for r in att) / len(att),
        },
        "minutes_with_attack_units": len(attack_minutes),
        "attack_minutes_that_also_have_benign_units": sum(1 for m in attack_minutes if minute[m][0]),
        "reference_check_max_relative_difference": max(checks),
        "units_sha256": hashlib.sha256((a.output / "units.json").read_bytes()).hexdigest(),
    }
    (a.output / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
