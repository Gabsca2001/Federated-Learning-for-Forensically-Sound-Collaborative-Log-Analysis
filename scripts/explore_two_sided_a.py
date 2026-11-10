"""EXPLORATORY: two-sided reading of view A (no retraining).

On Data22 and ToN-IoT the Data24-only view-A margin of attack units falls *below* almost all
baseline benign units. Two-sided score = |baseline rank - 0.5|: alert when the margin is
abnormal in either direction relative to the target baseline. Compared with one-sided A,
view B, NOV; with and without 5-unit trailing median; seed-averaged margins (seeds 0-2).
"""

from __future__ import annotations

import json
import sys
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

OUT = dae.ROOT / "artifacts/explore-two-sided-a-v1"


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    d24 = dom["data24"]
    W24, _ = vb.build(d24["Z"], d24["baseline"])
    models = {}
    for v in ("A", "B"):
        ms.new_model = lambda arch, seed, w=W24[v].shape[1]: ed.model_for(arch, seed, w)
        models[v] = [ms.fedavg(None, [(W24[v][d24["train"]], d24["y"][d24["train"]])], s) for s in ms.SEEDS]
    mt = tp.meta()
    res = {}
    for name in ("data22", "ton_iot", "unsw_nb15"):
        D = dom[name]
        base, test, y = D["baseline"], D["test"], D["y"]
        sel = base | test
        W, maha = vb.build(D["Z"], base)
        mg = {v: np.mean([ed.margin(m, W[v]) for m in models[v]], axis=0) for v in ("A", "B")}
        ra, rb = ef.rank(mg["A"], base), ef.rank(mg["B"], base)
        # two-sided: distance of the margin from the baseline median, in baseline MAD units (continuous)
        med = np.median(mg["A"][base])
        mad = np.median(np.abs(mg["A"][base] - med)) + 1e-9
        two = np.abs(mg["A"] - med) / mad
        r2 = ef.rank(two, base)
        cands = {"A one-sided": ra, "A two-sided": r2 + 1e-9 * two, "B": rb, "MAX(A2,B)": np.maximum(r2, rb), "NOV": ef.rank(maha, base) + 1e-9 * maha}
        tt, ent = mt[name]
        res[name] = {}
        print(f"\n{name}")
        for cn, sc in cands.items():
            for k in (1, 5):
                s = tp.smooth(sc, tt, ent, k)
                e = dac.evaluate(s[sel], base[sel], y[sel])
                for q in (0.001, 0.01, 0.05):
                    e[f"rec@{q}"] = ef.recall_at_fpr(s[test], y[test], q)
                res[name][f"{cn}|k={k}"] = e
                print(f"  {cn:12s} k={k} BA={e['balanced_accuracy']:.3f} FPR={e['false_positive_rate']:.3f} REC={e['attack_recall']:.3f} "
                      f"AUROC={e['auroc']:.3f} | rec@0.1%={e['rec@0.001']:.3f} @1%={e['rec@0.01']:.3f} @5%={e['rec@0.05']:.3f}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
