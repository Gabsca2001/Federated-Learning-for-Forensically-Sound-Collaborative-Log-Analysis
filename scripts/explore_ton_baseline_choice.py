"""EXPLORATORY: effect of the label-free baseline on ToN-IoT host units.

Fixed test: host units of 2019-04-24 .. 29. Baselines (labels never used to build them):
  B1  2019-04-02/03 (as before)
  B2  2019-04-02/03/04 (all pre-attack days)
  B3  2019-04-23 (day before the test; contains attacks, used as if normal)
  B4  rolling: for each test day, all units of the previous day (contaminated)
Scorers: NOV (Mahalanobis), D24-B and D24-MAX (Data24-only models), 5-unit trailing median.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_temporal_persistence as tp
import explore_ton_host_units as th
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-ton-baseline-choice-v1"
TEST_DAYS = ["2019-04-24", "2019-04-25", "2019-04-26", "2019-04-27", "2019-04-28", "2019-04-29"]


def main() -> int:
    torch.set_num_threads(4)
    z = np.load(th.NPZ)
    X = z["features"].astype(float)
    y = z["actual"].astype(bool)
    t = z["bucket"].astype(np.int64) * 60
    host = z["host"]
    day = np.array([datetime.fromtimestamp(int(v), UTC).strftime("%Y-%m-%d") for v in t])
    Xl = X.copy()
    Xl[:, ms.LOG_IDX] = np.log1p(np.maximum(Xl[:, ms.LOG_IDX], 0))
    dom = ms.load_domains()
    d24 = dom["data24"]
    W24, _ = vb.build(d24["Z"], d24["baseline"])
    models = {}
    for v in ("A", "B"):
        ms.new_model = lambda arch, seed, w=W24[v].shape[1]: ed.model_for(arch, seed, w)
        models[v] = [ms.fedavg(None, [(W24[v][d24["train"]], d24["y"][d24["train"]])], s) for s in ms.SEEDS]

    def score_block(base, idx):
        """Scores for units idx using baseline mask base (both boolean over all units)."""
        mu, sd = Xl[base].mean(0), Xl[base].std(0)
        sd[sd < 1e-9] = 1.0
        sub = base | idx
        W, maha = vb.build((Xl[sub] - mu) / sd, base[sub])
        b = base[sub]
        mg = {v: np.mean([ed.margin(m, W[v]) for m in models[v]], axis=0) for v in ("A", "B")}
        rk = {k: ef.rank(s, b) for k, s in (("NOV", maha), ("A", mg["A"]), ("B", mg["B"]))}
        out = {"NOV": rk["NOV"], "D24-B": rk["B"], "D24-MAX": np.maximum(rk["A"], rk["B"])}
        thr = {k: None for k in out}
        full = {}
        for k, s in out.items():
            arr = np.full(len(y), np.nan)
            arr[np.where(sub)[0]] = s
            full[k] = arr
        return full

    test = np.isin(day, TEST_DAYS)
    baselines = {"B1 Apr02-03": np.isin(day, ["2019-04-02", "2019-04-03"]),
                 "B2 Apr02-04": np.isin(day, ["2019-04-02", "2019-04-03", "2019-04-04"]),
                 "B3 Apr23 (contaminated)": day == "2019-04-23"}
    res = {}
    for name, base in baselines.items():
        print(f"\n{name}: baseline units {int(base.sum())}, attack share in baseline {(y[base].mean()):.3f}")
        sc = score_block(base, test)
        res[name] = {}
        for k, s in sc.items():
            # persistence, then threshold at the 99th percentile of the smoothed baseline score
            ss = tp.smooth(np.nan_to_num(s), t, host, 5)
            thr = np.quantile(ss[base], 0.99)
            al = ss > thr
            tp_ = (al & test & y).sum(); fn = (~al & test & y).sum(); fp = (al & test & ~y).sum(); tn = (~al & test & ~y).sum()
            rec, fpr = tp_ / (tp_ + fn), fp / (fp + tn)
            auc = dae.auroc(y[test], ss[test])
            r1 = ef.recall_at_fpr(ss[test], y[test], 0.001)
            res[name][k] = {"ba": (rec + 1 - fpr) / 2, "fpr": fpr, "recall": rec, "auroc": auc, "rec@0.1%": r1}
            print(f"  {k:8s} BA={(rec + 1 - fpr) / 2:.3f} FPR={fpr:.3f} REC={rec:.3f} AUROC={auc:.3f} rec@0.1%={r1:.3f}")
    # B4 rolling: per test day, baseline = previous day
    print("\nB4 rolling previous day (contaminated):")
    alerts = {k: np.zeros(len(y), bool) for k in ("NOV", "D24-B", "D24-MAX")}
    smooth_all = {k: np.full(len(y), np.nan) for k in alerts}
    prev = {"2019-04-24": "2019-04-23"}
    for i in range(1, len(TEST_DAYS)):
        prev[TEST_DAYS[i]] = TEST_DAYS[i - 1]
    for d in TEST_DAYS:
        base = day == prev[d]
        idx = day == d
        sc = score_block(base, idx)
        for k, s in sc.items():
            ss = tp.smooth(np.nan_to_num(s), t, host, 5)
            thr = np.quantile(ss[base], 0.99)
            alerts[k][idx] = ss[idx] > thr
            smooth_all[k][idx] = ss[idx]
    res["B4 rolling"] = {}
    for k in alerts:
        al = alerts[k]
        tp_ = (al & test & y).sum(); fn = (~al & test & y).sum(); fp = (al & test & ~y).sum(); tn = (~al & test & ~y).sum()
        rec, fpr = tp_ / (tp_ + fn), fp / (fp + tn)
        res["B4 rolling"][k] = {"ba": (rec + 1 - fpr) / 2, "fpr": fpr, "recall": rec}
        print(f"  {k:8s} BA={(rec + 1 - fpr) / 2:.3f} FPR={fpr:.3f} REC={rec:.3f}")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1, default=float) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
