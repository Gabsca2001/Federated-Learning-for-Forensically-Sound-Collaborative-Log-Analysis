"""EXPLORATORY: temporal persistence (trailing rolling median) on two-view ensemble scores.

Scores (baseline-relative ranks) are replaced by the median over the last k units of the same
entity (source host on UNSW-NB15, the whole network elsewhere), past only, restarting after a
gap > 10 minutes. Same smoothing is applied to NOV. Models: Data24-only, seed-averaged margins.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_controls as dac
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-temporal-persistence-v1"


def meta():
    m = {}
    r = json.loads((dae.ROOT / "artifacts/revision-data22-external-v1/dataset.json").read_text())["rows"]
    m["data22"] = (np.array([x["window_start_epoch"] for x in r]), np.array(["net"] * len(r)))
    r = json.loads((dae.TRANSFER / "windows/occurrence-windows.json").read_text())["rows"]
    m["ton_iot"] = (np.array([x["window_start_epoch"] for x in r]), np.array(["net"] * len(r)))
    r = json.loads((dae.ROOT / "artifacts/unsw-nb15-host-units-v1/units.json").read_text())["rows"]
    m["unsw_nb15"] = (np.array([x["window_start_epoch"] for x in r]), np.array([x["source_host"] for x in r]))
    return m


def smooth(score, t, ent, k):
    if k == 1:
        return score
    out = np.empty_like(score, dtype=float)
    groups = defaultdict(list)
    for i in np.argsort(t, kind="mergesort"):
        groups[ent[i]].append(i)
    for idx in groups.values():
        buf = []
        prev = None
        for i in idx:
            if prev is not None and t[i] - prev > 600:
                buf = []
            buf.append(score[i])
            buf = buf[-k:]
            out[i] = float(np.median(buf))
            prev = t[i]
    return out


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    W, M = {}, {}
    for n, d in dom.items():
        W[n], M[n] = vb.build(d["Z"], d["baseline"])
    d24 = dom["data24"]
    targets = ("data22", "ton_iot", "unsw_nb15")
    mg = {}
    for v in ("A", "B", "B+agg"):
        ms.new_model = lambda arch, seed, w=W["data24"][v].shape[1]: ed.model_for(arch, seed, w)
        per = {t: [] for t in targets}
        for s in ms.SEEDS:
            m = ms.fedavg(None, [(W["data24"][v][d24["train"]], d24["y"][d24["train"]])], s)
            for t in targets:
                per[t].append(ed.margin(m, W[t][v]))
        mg[v] = {t: np.mean(per[t], axis=0) for t in targets}
    mt = meta()
    res = {}
    for t in targets:
        D = dom[t]
        base, test, y = D["baseline"], D["test"], D["y"]
        sel = base | test
        tt, ent = mt[t]
        r = {v: ef.rank(mg[v][t], base) for v in mg}
        raw = {"A": r["A"], "B+agg": r["B+agg"], "MAX(A,B)": np.maximum(r["A"], r["B"]),
               "MAX(A,B+agg)": np.maximum(r["A"], r["B+agg"]), "NOV": ef.rank(M[t], base)}
        tie = {"A": mg["A"][t], "B+agg": mg["B+agg"][t], "MAX(A,B)": np.maximum(mg["A"][t], mg["B"][t]),
               "MAX(A,B+agg)": np.maximum(mg["A"][t], mg["B+agg"][t]), "NOV": M[t]}
        res[t] = {}
        print(f"\n{t}")
        for name, sc in raw.items():
            z = (tie[name] - tie[name][base].mean()) / (tie[name][base].std() + 1e-9)
            for k in (1, 3, 5):
                s = smooth(sc + 1e-6 * z, tt, ent, k)
                e = dac.evaluate(s[sel], base[sel], y[sel])
                for q in (0.001, 0.01, 0.05):
                    e[f"rec@{q}"] = ef.recall_at_fpr(s[test], y[test], q)
                res[t][f"{name}|k={k}"] = e
                print(f"  {name:13s} k={k} BA={e['balanced_accuracy']:.3f} FPR={e['false_positive_rate']:.3f} REC={e['attack_recall']:.3f} "
                      f"AUROC={e['auroc']:.3f} | rec@0.1%={e['rec@0.001']:.3f} @1%={e['rec@0.01']:.3f} @5%={e['rec@0.05']:.3f}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
