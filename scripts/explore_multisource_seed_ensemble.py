"""EXPLORATORY: seed ensemble of the multi-source view-A model on held-out Data24.

Retrains the confirmed configuration for seeds 3-7 (identical to the confirmation run) and
compares individual seeds with ensembles of averaged margins (all 5; and every 3-subset).
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path
from statistics import mean

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_controls as dac
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_multisource_two_view as e2
import explore_temporal_persistence as tp
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-multisource-seed-ensemble-v1"
SEEDS = (3, 4, 5, 6, 7)


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    W = {n: vb.build(d["Z"], d["baseline"])[0]["A"] for n, d in dom.items()}
    D = dom["data24"]
    base, test, y = D["baseline"], D["test"], D["y"]
    sel = base | test
    tt, ent = e2.meta()["data24"]
    ms.new_model = lambda arch, seed: ed.model_for(arch, seed, 50)
    marg = {}
    for s in SEEDS:
        m = ms.fedavg(None, [(W[n][dom[n]["train"]], dom[n]["y"][dom[n]["train"]]) for n in ("data22", "ton_iot", "unsw_nb15")], s)
        marg[s] = ed.margin(m, W["data24"])

    def ev(g):
        sc = tp.smooth(ef.rank(g, base) + 1e-6 * (g - g[base].mean()) / (g[base].std() + 1e-9), tt, ent, 5)
        e = dac.evaluate(sc[sel], base[sel], y[sel])
        e["rec@0.001"] = ef.recall_at_fpr(sc[test], y[test], 0.001)
        return e

    res = {"single": {s: ev(marg[s]) for s in SEEDS}}
    res["ensemble5"] = ev(np.mean([marg[s] for s in SEEDS], 0))
    res["ensemble5_rankavg"] = ev(np.mean([ef.rank(marg[s], base) for s in SEEDS], 0))
    trip = {str(c): ev(np.mean([marg[s] for s in c], 0))["balanced_accuracy"] for c in itertools.combinations(SEEDS, 3)}
    res["ensemble3_all_subsets_ba"] = trip
    for s, e in res["single"].items():
        print(f"seed {s}: BA={e['balanced_accuracy']:.3f} FPR={e['false_positive_rate']:.3f} REC={e['attack_recall']:.3f} rec@0.1%={e['rec@0.001']:.3f}")
    for k in ("ensemble5", "ensemble5_rankavg"):
        e = res[k]
        print(f"{k}: BA={e['balanced_accuracy']:.3f} FPR={e['false_positive_rate']:.3f} REC={e['attack_recall']:.3f} AUROC={e['auroc']:.3f} rec@0.1%={e['rec@0.001']:.3f}")
    v = list(trip.values())
    print(f"3-model ensembles (10 subsets): BA mean {mean(v):.3f}, min {min(v):.3f}, max {max(v):.3f}")
    s_ba = [res['single'][s]['balanced_accuracy'] for s in SEEDS]
    print(f"single seeds: BA mean {mean(s_ba):.3f}, min {min(s_ba):.3f}, max {max(s_ba):.3f}")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1, default=str) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
