"""EXPLORATORY: cleaned close baselines and novelty + Data24 fusion on ToN-IoT host units.

Test: host units of 2019-04-24 .. 29. For each test day the baseline is the previous day,
label-free cleaned: units are iteratively trimmed by Mahalanobis distance to the remaining
set (two passes), keeping the (1 - q) least anomalous; q in {0.2, 0.4, 0.6}. Reference: the
fixed far baseline 2019-04-02/03 (B1). Scorers: NOV, D24-B, D24-MAX and fusions of NOV with
D24-B (SUM and MEAN of ranks). 5-unit trailing median per host, threshold at the 99th
percentile of the smoothed score on the (cleaned) baseline.
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

OUT = dae.ROOT / "artifacts/explore-ton-clean-baseline-v1"
TEST_DAYS = ["2019-04-24", "2019-04-25", "2019-04-26", "2019-04-27", "2019-04-28", "2019-04-29"]
PREV = {"2019-04-24": "2019-04-23", **{TEST_DAYS[i]: TEST_DAYS[i - 1] for i in range(1, len(TEST_DAYS))}}


def maha(Zref, Z):
    inv = np.linalg.pinv(np.cov(Zref, rowvar=False) + 1e-6 * np.eye(Z.shape[1]))
    d = Z - Zref.mean(0)
    return np.sqrt(np.einsum("ij,jk,ik->i", d, inv, d))


def trim(Xl, idx, q):
    keep = idx.copy()
    for _ in range(2):
        sub = np.where(keep)[0]
        mu, sd = Xl[sub].mean(0), Xl[sub].std(0)
        sd[sd < 1e-9] = 1.0
        Z = (Xl[sub] - mu) / sd
        dist = maha(Z, Z)
        cut = np.quantile(dist, 1 - q)
        keep = np.zeros_like(keep)
        keep[sub[dist <= cut]] = True
    return keep


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
    test = np.isin(day, TEST_DAYS)

    def ranks_for(base, idx):
        mu, sd = Xl[base].mean(0), Xl[base].std(0)
        sd[sd < 1e-9] = 1.0
        sub = base | idx
        W, m = vb.build((Xl[sub] - mu) / sd, base[sub])
        b = base[sub]
        mg = {v: np.mean([ed.margin(mm, W[v]) for mm in models[v]], axis=0) for v in ("A", "B")}
        r = {"NOV": ef.rank(m, b), "A": ef.rank(mg["A"], b), "B": ef.rank(mg["B"], b)}
        out = {"NOV": r["NOV"], "D24-B": r["B"], "D24-MAX": np.maximum(r["A"], r["B"]),
               "SUM(NOV,B)": r["NOV"] + r["B"], "MIN(NOV,B)": np.minimum(r["NOV"], r["B"])}
        full = {}
        for k, s in out.items():
            a = np.full(len(y), np.nan)
            a[np.where(sub)[0]] = s
            full[k] = a
        return full

    def run(baseline_for_day):
        alerts, scores = {}, {}
        for d in TEST_DAYS:
            base = baseline_for_day(d)
            idx = day == d
            for k, s in ranks_for(base, idx).items():
                ss = tp.smooth(np.nan_to_num(s), t, host, 5)
                thr = np.quantile(ss[base], 0.99)
                alerts.setdefault(k, np.zeros(len(y), bool))[idx] = ss[idx] > thr
                scores.setdefault(k, np.full(len(y), np.nan))[idx] = ss[idx]
        out = {}
        for k in alerts:
            al = alerts[k]
            tp_, fn = (al & test & y).sum(), (~al & test & y).sum()
            fp, tn = (al & test & ~y).sum(), (~al & test & ~y).sum()
            rec, fpr = tp_ / (tp_ + fn), fp / (fp + tn)
            out[k] = {"ba": float((rec + 1 - fpr) / 2), "fpr": float(fpr), "recall": float(rec)}
        return out

    b1 = np.isin(day, ["2019-04-02", "2019-04-03"])
    configs = {"B1 far (Apr 2-3)": lambda d: b1}
    for q in (0.2, 0.4, 0.6):
        cache = {}

        def f(d, q=q, cache=cache):
            if d not in cache:
                cache[d] = trim(Xl, day == PREV[d], q)
            return cache[d]
        configs[f"prev day trimmed q={q}"] = f
    res = {}
    for name, fn in configs.items():
        res[name] = run(fn)
        if name.startswith("prev"):
            q = float(name.split("=")[1])
            cont = []
            for d in TEST_DAYS:
                b = fn(d)
                cont.append((y[b].mean(), y[day == PREV[d]].mean()))
            res[name]["_baseline_attack_share_after_vs_before"] = [(round(a, 3), round(b, 3)) for a, b in cont]
        print(f"\n{name}")
        if "_baseline_attack_share_after_vs_before" in res[name]:
            print("  baseline attack share after/before trimming per test day:", res[name]["_baseline_attack_share_after_vs_before"])
        for k, r in res[name].items():
            if not k.startswith("_"):
                print(f"  {k:11s} BA={r['ba']:.3f} FPR={r['fpr']:.3f} REC={r['recall']:.3f}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1, default=float) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
