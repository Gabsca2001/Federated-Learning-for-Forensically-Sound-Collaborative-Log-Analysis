"""EXPLORATORY: how much benign baseline is needed, and how robust is it to contamination?

Setting: UNSW-NB15 source-host x minute units (benign and attack in the same minutes).
Test: all session S1 units (2015-02-18). Baseline: S0 units starting at 14:00 UTC on
2015-01-22 (benign-only period), of length L in {15, 30, 60, 120} minutes. Contamination:
attack units sampled from the S0 attack period (before 14:00, never part of the S1 test)
are added to the 120-minute baseline at rate c in {0, 1, 5, 10, 20}% of baseline units.
Scorers (Data24-only models, seed-averaged margins, no retraining): view A, the two-view
system MAX(A,B), and local novelty NOV; 5-unit trailing median per host; threshold at the
99th percentile of the smoothed baseline score. Contamination draws: 3 repetitions.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_temporal_persistence as tp
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-baseline-requirements-v1"


def ts(h, m=0):
    return int(datetime(2015, 1, 22, h, m, tzinfo=UTC).timestamp())


def main() -> int:
    torch.set_num_threads(4)
    d24 = ms.load_domains()["data24"]
    W24, _ = vb.build(d24["Z"], d24["baseline"])
    models = {}
    for v in ("A", "B"):
        ms.new_model = lambda arch, seed, w=W24[v].shape[1]: ed.model_for(arch, seed, w)
        models[v] = [ms.fedavg(None, [(W24[v][d24["train"]], d24["y"][d24["train"]])], s) for s in ms.SEEDS]
    rows = json.loads((dae.ROOT / "artifacts/unsw-nb15-host-units-v1/units.json").read_text())["rows"]
    X = np.array([r["features"] for r in rows], float)
    y = np.array([r["label"] == "attack" for r in rows])
    t = np.array([r["window_start_epoch"] for r in rows])
    host = np.array([r["source_host"] for r in rows])
    s1 = np.array([r["capture_id"] == "2015-02-18" for r in rows])
    s0 = ~s1
    attack_pool = np.where(s0 & y & (t < ts(14)))[0]
    Xl = X.copy()
    Xl[:, ms.LOG_IDX] = np.log1p(np.maximum(Xl[:, ms.LOG_IDX], 0))

    def evaluate(base_idx):
        base = np.zeros(len(y), bool)
        base[base_idx] = True
        mu, sd = Xl[base].mean(0), Xl[base].std(0)
        sd[sd < 1e-9] = 1.0
        sub = base | s1
        W, maha = vb.build((Xl[sub] - mu) / sd, base[sub])
        b = base[sub]
        mg = {v: np.mean([ed.margin(m, W[v]) for m in models[v]], axis=0) for v in ("A", "B")}
        rk = {"A": ef.rank(mg["A"], b), "SYSTEM": np.maximum(ef.rank(mg["A"], b), ef.rank(mg["B"], b)), "NOV": ef.rank(maha, b)}
        tt, hh, yy = t[sub], host[sub], y[sub]
        test = ~b
        out = {}
        for k, r in rk.items():
            ss = tp.smooth(r, tt, hh, 5)
            al = ss > np.quantile(ss[b], 0.99)
            tp_, fn = (al & test & yy).sum(), (~al & test & yy).sum()
            fp, tn = (al & test & ~yy).sum(), (~al & test & ~yy).sum()
            rec, fpr = tp_ / (tp_ + fn), fp / (fp + tn)
            out[k] = {"ba": float((rec + 1 - fpr) / 2), "fpr": float(fpr), "recall": float(rec),
                      "rec@1%": ef.recall_at_fpr(ss[test], yy[test], 0.01)}
        return out

    res = {"length": {}, "contamination": {}}
    print("== baseline length (clean, starting 14:00 UTC on 2015-01-22)")
    for L in (15, 30, 60, 120):
        idx = np.where(s0 & (t >= ts(14)) & (t < ts(14) + L * 60))[0]
        r = evaluate(idx)
        res["length"][L] = {"units": len(idx), "attack_units": int(y[idx].sum()), **r}
        print(f"  {L:3d} min ({len(idx):4d} units): " + " | ".join(f"{k} BA={v['ba']:.3f} FPR={v['fpr']:.3f} REC={v['recall']:.3f} r@1%={v['rec@1%']:.3f}" for k, v in r.items()), flush=True)
    clean = np.where(s0 & (t >= ts(14)) & (t < ts(16)))[0]
    print("== contamination of the 120-minute baseline (3 draws each)")
    for c in (0.0, 0.01, 0.05, 0.10, 0.20):
        reps = []
        for rep in range(3 if c else 1):
            rng = np.random.default_rng(rep)
            n_add = int(round(c * len(clean)))
            idx = np.concatenate([clean, rng.choice(attack_pool, n_add, replace=False)]) if n_add else clean
            reps.append(evaluate(idx))
        agg = {k: {m: mean(r[k][m] for r in reps) for m in ("ba", "fpr", "recall", "rec@1%")} for k in reps[0]}
        res["contamination"][c] = agg
        print(f"  {int(c * 100):3d}%: " + " | ".join(f"{k} BA={v['ba']:.3f} FPR={v['fpr']:.3f} REC={v['recall']:.3f} r@1%={v['rec@1%']:.3f}" for k, v in agg.items()), flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1, default=float) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
