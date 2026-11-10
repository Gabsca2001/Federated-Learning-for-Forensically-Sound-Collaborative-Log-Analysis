"""EXPLORATORY: fusion of local novelty with the Data24 federated classifier (z + |z| input).

For each external network: NOV = Mahalanobis to its benign baseline; CLF = logit margin of a
FedAvg classifier trained on Data24 only (input [z, log1p|z|]). Both scores are converted to
baseline-relative ranks (empirical CDF on the baseline), so fusion needs no labels.
Reported: label-free decisions (99th baseline percentile) and ROC points (recall at fixed
test FPR), where methods are compared at the same false-positive rate.
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
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-fusion-v1"


def rank(score, base):
    ref = np.sort(score[base])
    return np.searchsorted(ref, score, side="right") / len(ref)


def recall_at_fpr(score, y, fpr):
    thr = np.quantile(score[~y], 1 - fpr)
    return float((score[y] > thr).mean())


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    fn = ed.REPS["both"]
    V = {n: fn(d["Z"]).astype(np.float32) for n, d in dom.items()}
    ms.new_model = lambda arch, seed: ed.model_for(arch, seed, 50)
    res = {}
    for held in ("data22", "ton_iot", "unsw_nb15"):
        D = dom[held]
        base, test, y = D["baseline"], D["test"], D["y"]
        sel = base | test
        Zb = D["Z"][base]
        inv = np.linalg.pinv(np.cov(Zb, rowvar=False) + 1e-6 * np.eye(25))
        dd = D["Z"] - Zb.mean(0)
        nov = np.sqrt(np.einsum("ij,jk,ik->i", dd, inv, dd))
        rn = rank(nov, base)
        rows = {k: [] for k in ("NOV", "CLF", "SUM", "MAX", "MIN")}
        for s in ms.SEEDS:
            m = ms.fedavg(None, [(V["data24"][dom["data24"]["train"]], dom["data24"]["y"][dom["data24"]["train"]])], s)
            clf = ed.margin(m, V[held])
            rc = rank(clf, base)
            # tie-break ranks with tiny standardized raw scores so saturated ranks still order
            zn = (nov - nov[base].mean()) / (nov[base].std() + 1e-9)
            zc = (clf - clf[base].mean()) / (clf[base].std() + 1e-9)
            fused = {"NOV": nov, "CLF": clf, "SUM": rn + rc + 1e-6 * (zn + zc),
                     "MAX": np.maximum(rn, rc) + 1e-6 * np.maximum(zn, zc),
                     "MIN": np.minimum(rn, rc) + 1e-6 * np.minimum(zn, zc)}
            for k, sc in fused.items():
                e = dac.evaluate(sc[sel], base[sel], y[sel])
                e["rec@fpr1%"] = recall_at_fpr(sc[test], y[test], 0.01)
                e["rec@fpr0.1%"] = recall_at_fpr(sc[test], y[test], 0.001)
                e["rec@fpr5%"] = recall_at_fpr(sc[test], y[test], 0.05)
                rows[k].append(e)
        res[held] = {k: {m_: mean(r[m_] for r in v) for m_ in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc", "rec@fpr0.1%", "rec@fpr1%", "rec@fpr5%")} for k, v in rows.items()}
        print(f"\n{held}: test benign {int((test & ~y).sum())}, attack {int((test & y).sum())}")
        print(f"  {'':5s} {'BA':>6s} {'FPR':>6s} {'REC':>6s} {'AUROC':>6s} | recall at test FPR 0.1% / 1% / 5%")
        for k, r in res[held].items():
            print(f"  {k:5s} {r['balanced_accuracy']:6.3f} {r['false_positive_rate']:6.3f} {r['attack_recall']:6.3f} {r['auroc']:6.3f} | "
                  f"{r['rec@fpr0.1%']:.3f} / {r['rec@fpr1%']:.3f} / {r['rec@fpr5%']:.3f}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
