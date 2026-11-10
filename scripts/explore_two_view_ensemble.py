"""EXPLORATORY: two-view ensemble of Data24-only FedAvg classifiers.

View A: [clip z, log1p|z|] (feature identity kept). View B: sorted log1p|z| (identity-free).
Both trained on Data24 only. Scores are converted to baseline-relative ranks on the target
network and fused (SUM, MAX). Label-free threshold: 99th percentile of the fused score on
the target baseline. NOV (Mahalanobis) is the reference.
"""

from __future__ import annotations

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
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-two-view-ensemble-v1"


def views(Z):
    a = np.log1p(np.abs(Z))
    return {"A": np.concatenate([np.clip(Z, -20, 20), a], 1).astype(np.float32), "B": (-np.sort(-a, axis=1)).astype(np.float32)}


def soft(score, base):
    r = ef.rank(score, base)
    z = (score - score[base].mean()) / (score[base].std() + 1e-9)
    return r, z


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    W = {n: views(d["Z"]) for n, d in dom.items()}
    d24 = dom["data24"]
    res = {}
    for held in ("data22", "ton_iot", "unsw_nb15"):
        D = dom[held]
        base, test, y = D["baseline"], D["test"], D["y"]
        sel = base | test
        Zb = D["Z"][base]
        inv = np.linalg.pinv(np.cov(Zb, rowvar=False) + 1e-6 * np.eye(25))
        dd = D["Z"] - Zb.mean(0)
        nov = np.sqrt(np.einsum("ij,jk,ik->i", dd, inv, dd))
        rows = {k: [] for k in ("A", "B", "SUM", "MAX", "NOV")}
        for s in ms.SEEDS:
            sc = {}
            for v in ("A", "B"):
                ms.new_model = lambda arch, seed, w=W["data24"][v].shape[1]: ed.model_for(arch, seed, w)
                m = ms.fedavg(None, [(W["data24"][v][d24["train"]], d24["y"][d24["train"]])], s)
                sc[v] = ed.margin(m, W[held][v])
            (ra, za), (rb, zb) = soft(sc["A"], base), soft(sc["B"], base)
            fused = {"A": sc["A"], "B": sc["B"], "SUM": ra + rb + 1e-6 * (za + zb),
                     "MAX": np.maximum(ra, rb) + 1e-6 * np.maximum(za, zb), "NOV": nov}
            for k, f in fused.items():
                e = dac.evaluate(f[sel], base[sel], y[sel])
                for q in (0.001, 0.01, 0.05):
                    e[f"rec@{q}"] = ef.recall_at_fpr(f[test], y[test], q)
                rows[k].append(e)
        res[held] = {k: {m_: mean(r[m_] for r in v) for m_ in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc", "rec@0.001", "rec@0.01", "rec@0.05")} for k, v in rows.items()}
        res[held]["_ba_per_seed"] = {k: [r["balanced_accuracy"] for r in v] for k, v in rows.items()}
        print(f"\n{held}")
        for k in ("A", "B", "SUM", "MAX", "NOV"):
            r = res[held][k]
            print(f"  {k:4s} BA={r['balanced_accuracy']:.3f} FPR={r['false_positive_rate']:.3f} REC={r['attack_recall']:.3f} AUROC={r['auroc']:.3f} "
                  f"| rec@0.1%={r['rec@0.001']:.3f} @1%={r['rec@0.01']:.3f} @5%={r['rec@0.05']:.3f}  seeds={[round(x, 3) for x in res[held]['_ba_per_seed'][k]]}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
