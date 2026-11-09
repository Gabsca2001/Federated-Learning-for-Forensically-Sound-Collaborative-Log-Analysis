"""Post-hoc diagnostic of AB1 alerts on ToN-IoT benign minutes recorded on attack dates.

Read-only, inference only. Not part of the frozen domain-adaptation protocol. For each
test benign window it records the AB1 decision, the distance in minutes to the nearest
attack window, the source files, and compares features against the baseline benign,
the 4 April benign and the attack windows.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae

from fl_forensics.external_generalization import _model_from_export
from fl_forensics.preprocessing import FEATURE_NAMES


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    if a.output.exists():
        raise SystemExit(f"refusing existing output {a.output}")

    export = json.loads((dae.TRANSFER / "frozen-model.json").read_text())
    scaler = json.loads((dae.TRANSFER / "frozen-scaler.json").read_text())
    model = _model_from_export(export, np=np, torch=torch)
    model.eval()
    bi = export["class_names"].index("benign")
    rows = json.loads((dae.TRANSFER / "windows/occurrence-windows.json").read_text())["rows"]
    X = np.array([r["features"] for r in rows], dtype=float)
    dates = np.array([r["capture_id"] for r in rows])
    lab = np.array([r["label"] for r in rows])
    start = np.array([r["window_start_epoch"] for r in rows])
    base = np.isin(dates, dae.BASELINE_DATES["ton_iot"])
    mu = X[base].mean(0)
    sd = X[base].std(0)
    sd = np.where(sd < dae.MIN_STD, np.asarray(scaler["scale"]), sd)
    Z = (X - mu) / sd
    with torch.no_grad():
        prob = torch.softmax(model(torch.from_numpy(Z.astype(np.float32))), 1).numpy()
    s = 1 - prob[:, bi]
    thr = float(np.quantile(s[base], 0.99))
    alert = s > thr

    attack_starts = np.sort(start[lab != "benign"])
    attack_dates = set(dates[lab != "benign"].tolist())

    def gap_minutes(t: int) -> float:
        i = np.searchsorted(attack_starts, t)
        c = [abs(t - attack_starts[j]) for j in (i - 1, i) if 0 <= j < len(attack_starts)]
        return min(c) / 60.0

    groups = {
        "baseline_benign": base & (lab == "benign"),
        "apr04_benign": (dates == "2019-04-04") & (lab == "benign"),
        "attack_date_benign": (~base) & (lab == "benign") & np.isin(dates, list(attack_dates)),
        "attack": lab != "benign",
    }
    late = np.where(groups["attack_date_benign"])[0]
    late_records = []
    for i in late:
        late_records.append(
            {
                "window_id": rows[i]["window_id"],
                "date": dates[i],
                "alert": bool(alert[i]),
                "score": float(s[i]),
                "minutes_to_nearest_attack_window": gap_minutes(int(start[i])),
                "source_files": rows[i]["source_file_counts"],
                "source_record_count": rows[i]["source_record_count"],
            }
        )
    gaps = np.array([r["minutes_to_nearest_attack_window"] for r in late_records])
    alerts_late = np.array([r["alert"] for r in late_records])

    def gap_bucket(g: float) -> str:
        return "<=1" if g <= 1 else "<=5" if g <= 5 else "<=30" if g <= 30 else ">30"

    by_gap = Counter((gap_bucket(g), bool(al)) for g, al in zip(gaps, alerts_late, strict=True))

    medians = {
        g: {f: float(np.median(X[m, j])) for j, f in enumerate(FEATURE_NAMES)} for g, m in groups.items()
    }
    # Features where attack-date benign sits closer to attacks than to the baseline (median, baseline z units).
    closer = []
    for j, f in enumerate(FEATURE_NAMES):
        zb = (medians["baseline_benign"][f] - mu[j]) / sd[j]
        zl = (medians["attack_date_benign"][f] - mu[j]) / sd[j]
        za = (medians["attack"][f] - mu[j]) / sd[j]
        if abs(zl - za) < abs(zl - zb):
            closer.append({"feature": f, "z_baseline": zb, "z_attack_date_benign": zl, "z_attack": za})
    late_files = Counter(k for r in late_records for k in r["source_files"])
    apr4_files = Counter(k for i in np.where(groups["apr04_benign"])[0] for k in rows[i]["source_file_counts"])

    result = {
        "status": "post-hoc diagnostic, not part of protocol v1",
        "threshold_ab1": thr,
        "group_sizes": {g: int(m.sum()) for g, m in groups.items()},
        "group_alert_rate_ab1": {g: float(alert[m].mean()) for g, m in groups.items()},
        "attack_date_benign_minutes_to_attack": {
            "median": float(np.median(gaps)),
            "min": float(gaps.min()),
            "max": float(gaps.max()),
            "by_bucket_and_alert": {f"{k[0]}|alert={k[1]}": v for k, v in sorted(by_gap.items())},
        },
        "features_where_attack_date_benign_is_closer_to_attacks": closer,
        "group_feature_medians": medians,
        "source_files": {"attack_date_benign": dict(late_files), "apr04_benign": dict(apr4_files)},
        "attack_date_benign_windows": late_records,
    }
    a.output.mkdir(parents=True)
    (a.output / "late-benign-diagnostic.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("group_sizes", "group_alert_rate_ab1",
                                             "attack_date_benign_minutes_to_attack", "source_files")}, indent=1))
    for c in closer:
        print(f"  closer-to-attack: {c['feature']:32s} zb={c['z_baseline']:.2f} zl={c['z_attack_date_benign']:.2f} za={c['z_attack']:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
