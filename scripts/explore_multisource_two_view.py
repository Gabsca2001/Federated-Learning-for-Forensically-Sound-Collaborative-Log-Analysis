"""EXPLORATORY: multi-source FedAvg with site-relative two views, leave-one-domain-out.

Each network is a client; inputs are view A ([clip z, log1p|z|]) and view B (sorted log1p|z|),
z relative to the client's own benign baseline. For each held-out network:
  MS     FedAvg over the other three networks (separate models for A and B)
  D24    Data24 only (reference; for held-out Data24 the single source is UNSW-NB15)
  NOV    Mahalanobis to the held-out baseline
Fusion MAX(A,B) of baseline ranks, 5-unit trailing median per entity, threshold at the 99th
baseline percentile. Seed-averaged margins (seeds 0-2) plus per-seed BA of the fused system.
"""

from __future__ import annotations

import json
import sys
import time
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

OUT = dae.ROOT / "artifacts/explore-multisource-two-view-v1"


def meta():
    m = tp.meta()
    r = json.loads((dae.ROOT / "artifacts/m2-data24-parquet/dataset.json").read_text())["rows"]
    m["data24"] = (np.array([x["window_start_epoch"] for x in r]), np.array(["net"] * len(r)))
    return m


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    W, M = {}, {}
    for n, d in dom.items():
        W[n], M[n] = vb.build(d["Z"], d["baseline"])
    mt = meta()
    res = {}
    t0 = time.time()
    for held in ms.DOMAINS:
        D = dom[held]
        base, test, y = D["baseline"], D["test"], D["y"]
        sel = base | test
        tt, ent = mt[held]
        sources = {"MS": [n for n in ms.DOMAINS if n != held], "D24": ["data24"] if held != "data24" else ["unsw_nb15"]}

        def std(v, base=base):
            return (v - v[base].mean()) / (v[base].std() + 1e-9)

        def ev(sc, test=test, sel=sel, base=base, y=y):
            e = dac.evaluate(sc[sel], base[sel], y[sel])
            for q in (0.001, 0.01, 0.05):
                e[f"rec@{q}"] = ef.recall_at_fpr(sc[test], y[test], q)
            return e

        out = {"NOV": ev(tp.smooth(ef.rank(M[held], base) + 1e-6 * std(M[held]), tt, ent, 5))}
        for arm, names in sources.items():
            per_seed = {"A": [], "B": []}
            for v in ("A", "B"):
                ms.new_model = lambda arch, seed, w=W["data24"][v].shape[1]: ed.model_for(arch, seed, w)
                for s in ms.SEEDS:
                    m = ms.fedavg(None, [(W[n][v][dom[n]["train"]], dom[n]["y"][dom[n]["train"]]) for n in names], s)
                    per_seed[v].append(ed.margin(m, W[held][v]))
            seed_ba = []
            for i in range(len(ms.SEEDS)):
                a, b = per_seed["A"][i], per_seed["B"][i]
                f = tp.smooth(np.maximum(ef.rank(a, base), ef.rank(b, base)) + 1e-6 * np.maximum(std(a), std(b)), tt, ent, 5)
                seed_ba.append(ev(f)["balanced_accuracy"])
            a, b = np.mean(per_seed["A"], 0), np.mean(per_seed["B"], 0)
            out[f"{arm}-A"] = ev(tp.smooth(ef.rank(a, base) + 1e-6 * std(a), tt, ent, 5))
            out[f"{arm}-B"] = ev(tp.smooth(ef.rank(b, base) + 1e-6 * std(b), tt, ent, 5))
            out[f"{arm}-MAX"] = ev(tp.smooth(np.maximum(ef.rank(a, base), ef.rank(b, base)) + 1e-6 * np.maximum(std(a), std(b)), tt, ent, 5))
            out[f"{arm}-MAX"]["ba_per_seed"] = seed_ba
        res[held] = out
        print(f"\n{held} ({time.time() - t0:.0f}s)")
        for k, r in out.items():
            extra = f" seeds={[round(x, 3) for x in r['ba_per_seed']]}" if "ba_per_seed" in r else ""
            print(f"  {k:8s} BA={r['balanced_accuracy']:.3f} FPR={r['false_positive_rate']:.3f} REC={r['attack_recall']:.3f} AUROC={r['auroc']:.3f} "
                  f"| rec@0.1%={r['rec@0.001']:.3f} @1%={r['rec@0.01']:.3f} @5%={r['rec@0.05']:.3f}{extra}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
