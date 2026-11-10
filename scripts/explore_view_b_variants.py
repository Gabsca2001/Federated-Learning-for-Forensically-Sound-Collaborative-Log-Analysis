"""EXPLORATORY: improving the identity-free view (B) of the Data24-only two-view ensemble.

B      sorted log1p|z|
B+agg  B + [log1p(mahalanobis), share(|z|>3), mean log1p|z|]
Bw     sorted log1p|whitened z| (whitening by the network's baseline covariance)
Bw+agg Bw + the same aggregates
Each model: FedAvg on Data24 only. Margins of the three seeds are averaged ("seed ensemble").
MAX = max of baseline-relative ranks of view A ([clip z, log1p|z|]) and the B variant.
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
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-view-b-variants-v1"


def build(Z, base):
    a = np.log1p(np.abs(Z))
    mu = Z[base].mean(0)
    cov = np.cov(Z[base], rowvar=False) + 1e-6 * np.eye(Z.shape[1])
    lam, U = np.linalg.eigh(cov)
    Zw = (Z - mu) @ U / np.sqrt(lam)
    aw = np.log1p(np.abs(Zw))
    maha = np.sqrt((Zw**2).sum(1))
    agg = np.stack([np.log1p(maha), (np.abs(Z) > 3).mean(1), a.mean(1)], 1)
    s, sw = -np.sort(-a, 1), -np.sort(-aw, 1)
    v = {"A": np.concatenate([np.clip(Z, -20, 20), a], 1), "B": s, "B+agg": np.concatenate([s, agg], 1),
         "Bw": sw, "Bw+agg": np.concatenate([sw, agg], 1)}
    return {k: x.astype(np.float32) for k, x in v.items()}, maha


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    W, M = {}, {}
    for n, d in dom.items():
        W[n], M[n] = build(d["Z"], d["baseline"])
    d24 = dom["data24"]
    targets = ("data22", "ton_iot", "unsw_nb15")
    margins = {}
    for v in ("A", "B", "B+agg", "Bw", "Bw+agg"):
        ms.new_model = lambda arch, seed, w=W["data24"][v].shape[1]: ed.model_for(arch, seed, w)
        per = {t: [] for t in targets}
        for s in ms.SEEDS:
            m = ms.fedavg(None, [(W["data24"][v][d24["train"]], d24["y"][d24["train"]])], s)
            for t in targets:
                per[t].append(ed.margin(m, W[t][v]))
        margins[v] = {t: np.mean(per[t], axis=0) for t in targets}
        print("trained", v, flush=True)

    res = {}
    for t in targets:
        D = dom[t]
        base, test, y = D["baseline"], D["test"], D["y"]
        sel = base | test

        def ev(sc, base=base, test=test, y=y, sel=sel):
            e = dac.evaluate(sc[sel], base[sel], y[sel])
            for q in (0.001, 0.01, 0.05):
                e[f"rec@{q}"] = ef.recall_at_fpr(sc[test], y[test], q)
            return e

        ra = ef.rank(margins["A"][t], base)
        out = {"A": ev(margins["A"][t]), "NOV": ev(M[t])}
        for v in ("B", "B+agg", "Bw", "Bw+agg"):
            sc = margins[v][t]
            out[v] = ev(sc)
            rb = ef.rank(sc, base)
            zs = (sc - sc[base].mean()) / (sc[base].std() + 1e-9)
            za = (margins["A"][t] - margins["A"][t][base].mean()) / (margins["A"][t][base].std() + 1e-9)
            out[f"MAX(A,{v})"] = ev(np.maximum(ra, rb) + 1e-6 * np.maximum(za, zs))
        res[t] = out
        print(f"\n{t}")
        for k, r in out.items():
            print(f"  {k:14s} BA={r['balanced_accuracy']:.3f} FPR={r['false_positive_rate']:.3f} REC={r['attack_recall']:.3f} "
                  f"AUROC={r['auroc']:.3f} | rec@0.1%={r['rec@0.001']:.3f} @1%={r['rec@0.01']:.3f} @5%={r['rec@0.05']:.3f}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
