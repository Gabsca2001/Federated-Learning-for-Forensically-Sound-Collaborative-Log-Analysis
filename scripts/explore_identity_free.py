"""EXPLORATORY: identity-free deviation inputs for cross-network transfer (leave-one-domain-out).

Representations built from baseline-standardized z (per network):
  agg          [clip z, log1p|z|, log1p(mahalanobis), log1p(max|z|), mean log1p|z|, share(|z|>3)]
  sorted       log1p|z| sorted descending (which feature deviates is discarded)
  both+sorted  [clip z, log1p|z|, sorted log1p|z|]
Arms: D24 (Data24 only) and MS (the three other networks). Label-free threshold at the 99th
baseline percentile of the logit margin; also AUROC and recall at 1% test FPR.
"""

from __future__ import annotations

import json
import sys
import time
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

OUT = dae.ROOT / "artifacts/explore-identity-free-v1"


def reps(Z, base):
    a = np.log1p(np.abs(Z))
    c = np.clip(Z, -20, 20)
    inv = np.linalg.pinv(np.cov(Z[base], rowvar=False) + 1e-6 * np.eye(Z.shape[1]))
    d = Z - Z[base].mean(0)
    maha = np.sqrt(np.einsum("ij,jk,ik->i", d, inv, d))
    agg = np.stack([np.log1p(maha), a.max(1), a.mean(1), (np.abs(Z) > 3).mean(1)], axis=1)
    srt = -np.sort(-a, axis=1)
    return {"agg": np.concatenate([c, a, agg], 1), "sorted": srt, "both+sorted": np.concatenate([c, a, srt], 1)}


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    R = {n: {k: v.astype(np.float32) for k, v in reps(d["Z"], d["baseline"]).items()} for n, d in dom.items()}
    res = {}
    t0 = time.time()
    for rep in ("agg", "sorted", "both+sorted"):
        width = R["data24"][rep].shape[1]
        ms.new_model = lambda arch, seed, w=width: ed.model_for(arch, seed, w)
        for held in ms.DOMAINS:
            D = dom[held]
            base, test, y = D["baseline"], D["test"], D["y"]
            sel = base | test
            for arm, names in (("D24", ["data24"] if held != "data24" else None),
                               ("MS", [n for n in ms.DOMAINS if n != held])):
                if names is None:
                    continue
                rs = []
                for s in ms.SEEDS:
                    m = ms.fedavg(None, [(R[n][rep][dom[n]["train"]], dom[n]["y"][dom[n]["train"]]) for n in names], s)
                    sc = ed.margin(m, R[held][rep])
                    e = dac.evaluate(sc[sel], base[sel], y[sel])
                    e["rec@1%"] = ef.recall_at_fpr(sc[test], y[test], 0.01)
                    rs.append(e)
                key = f"{rep}|{arm}|{held}"
                res[key] = {k: [r[k] for r in rs] for k in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc", "rec@1%")}
                v = res[key]
                print(f"{key:30s} BA={mean(v['balanced_accuracy']):.3f} FPR={mean(v['false_positive_rate']):.3f} "
                      f"REC={mean(v['attack_recall']):.3f} AUROC={mean(v['auroc']):.3f} [{min(v['auroc']):.2f}-{max(v['auroc']):.2f}] "
                      f"rec@1%={mean(v['rec@1%']):.3f} ({time.time() - t0:.0f}s)", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
