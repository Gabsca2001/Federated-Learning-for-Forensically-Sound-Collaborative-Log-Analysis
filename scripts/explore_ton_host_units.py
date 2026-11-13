"""EXPLORATORY: two-view site-relative systems on ToN-IoT source-host x minute units.

Units: the verified 80,172 host windows of results/external-data/revision-ton-iot-host-windows-v1 (same
25-feature contract). Baseline (label-free, assumed normal): units of 2019-04-02/03.
Test: units of the attack dates (2019-04-23 .. 29), where benign and attack hosts share
minutes; secondary view restricted to minutes containing at least one attack unit.
Models are not retrained on ToN-IoT: D24 = Data24 only; MS = Data24 + Data22 + UNSW-NB15
(ToN-IoT held out). Fusion MAX(A,B) of baseline ranks, 5-unit trailing median per host.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_controls as dac
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_temporal_persistence as tp
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-ton-host-units-v1"
NPZ = Path(__file__).resolve().parents[1] / "artifacts/ton-iot-host-20261109/windows/host-windows.npz"


def main() -> int:
    torch.set_num_threads(4)
    z = np.load(NPZ)
    X = z["features"].astype(float)
    y = z["actual"].astype(bool)
    t = z["bucket"].astype(np.int64) * 60
    host = z["host"]
    fam = z["family"]
    day = np.array([datetime.fromtimestamp(int(v), UTC).strftime("%Y-%m-%d") for v in t])
    base = np.isin(day, ["2019-04-02", "2019-04-03"])
    test = day >= "2019-04-23"
    att_min = set(t[test & y].tolist())
    same_min = test & np.isin(t, list(att_min))
    print(f"units {len(y)} | baseline {int(base.sum())} (attack {int((base & y).sum())}) | test {int(test.sum())} "
          f"(attack {int((test & y).sum())}, benign {int((test & ~y).sum())}) | same-minute benign {int((same_min & ~y).sum())}")
    Xl = X.copy()
    Xl[:, ms.LOG_IDX] = np.log1p(np.maximum(Xl[:, ms.LOG_IDX], 0))
    mu, sd = Xl[base].mean(0), Xl[base].std(0)
    sd[sd < 1e-9] = 1.0
    W, maha = vb.build((Xl - mu) / sd, base)

    dom = ms.load_domains()
    WS = {n: vb.build(d["Z"], d["baseline"])[0] for n, d in dom.items()}
    sources = {"D24": ["data24"], "MS": ["data24", "data22", "unsw_nb15"]}

    def std(v):
        return (v - v[base].mean()) / (v[base].std() + 1e-9)

    def ev(sc, mask):
        sel = base | mask
        e = dac.evaluate(sc[sel], base[sel], y[sel])
        for q in (0.001, 0.01, 0.05):
            e[f"rec@{q}"] = ef.recall_at_fpr(sc[mask], y[mask], q)
        return e

    scores = {"NOV": tp.smooth(ef.rank(maha, base) + 1e-6 * std(maha), t, host, 5)}
    t0 = time.time()
    for arm, names in sources.items():
        mg = {}
        for v in ("A", "B"):
            ms.new_model = lambda arch, seed, w=WS["data24"][v].shape[1]: ed.model_for(arch, seed, w)
            mg[v] = np.mean([ed.margin(ms.fedavg(None, [(WS[n][v][dom[n]["train"]], dom[n]["y"][dom[n]["train"]]) for n in names], s), W[v])
                             for s in ms.SEEDS], axis=0)
        ra, rb = ef.rank(mg["A"], base), ef.rank(mg["B"], base)
        scores[f"{arm}-A"] = tp.smooth(ra + 1e-6 * std(mg["A"]), t, host, 5)
        scores[f"{arm}-B"] = tp.smooth(rb + 1e-6 * std(mg["B"]), t, host, 5)
        scores[f"{arm}-MAX"] = tp.smooth(np.maximum(ra, rb) + 1e-6 * np.maximum(std(mg["A"]), std(mg["B"])), t, host, 5)
        print(f"trained {arm} ({time.time() - t0:.0f}s)", flush=True)
    res = {}
    for vname, mask in (("attack_dates", test), ("same_minute", same_min)):
        res[vname] = {}
        print(f"\n== {vname}")
        for k, sc in scores.items():
            e = ev(sc, mask)
            res[vname][k] = e
            print(f"  {k:8s} BA={e['balanced_accuracy']:.3f} FPR={e['false_positive_rate']:.3f} REC={e['attack_recall']:.3f} AUROC={e['auroc']:.3f} "
                  f"| rec@0.1%={e['rec@0.001']:.3f} @1%={e['rec@0.01']:.3f} @5%={e['rec@0.05']:.3f}", flush=True)
    best = "MS-MAX"
    al = scores[best] > np.quantile(scores[best][base], 0.99)
    print(f"\nper family recall ({best}):")
    res["family_recall"] = {}
    for f in sorted(set(fam[test & y])):
        m = test & y & (fam == f)
        res["family_recall"][f] = float(al[m].mean())
        print(f"  {f:11s} {int(m.sum()):5d}  {al[m].mean():.3f}")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
