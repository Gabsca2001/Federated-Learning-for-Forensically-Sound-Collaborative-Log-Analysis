"""EXPLORATORY: few local labels on ToN-IoT host units (site-relative view A).

Labelled pool: host units of 2019-04-23 (first attack day). Test: 2019-04-24 .. 29.
Normalization: label-free baseline 2019-04-02/03. Budgets k (balanced benign/attack).
Arms, all with the view-A architecture:
  MS-head   multi-source model (Data24 + Data22 + UNSW-NB15) with only the head fine-tuned
  MS-full   same model, all layers fine-tuned
  D24-full  Data24-only model, all layers fine-tuned
  SCRATCH   random initialization trained on the k labels
Decision: argmax (margin > 0). Also AUROC and recall at 1% test FPR. Seeds 0-2.
"""

from __future__ import annotations

import copy
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_ton_host_units as th
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-ton-few-labels-v1"
BUDGETS = (20, 50, 100, 200, "all")


def finetune(model, X, y, seed, head_only, epochs):
    m = copy.deepcopy(model)
    params = m.head.parameters() if head_only else m.parameters()
    if head_only:
        for p in m.encoder.parameters():
            p.requires_grad_(False)
    x, t = torch.from_numpy(X), torch.from_numpy(y.astype(np.int64))
    c = np.bincount(y.astype(int), minlength=2).astype(float)
    lf = torch.nn.CrossEntropyLoss(weight=torch.tensor(len(y) / (2 * np.maximum(c, 1)), dtype=torch.float32))
    opt = torch.optim.Adam(params, lr=1e-3)
    g = torch.Generator().manual_seed(seed)
    bs = min(32, len(y))
    m.train()
    for _ in range(epochs):
        perm = torch.randperm(len(y), generator=g)
        for i in range(0, len(y), bs):
            b = perm[i : i + bs]
            opt.zero_grad()
            lf(m(x[b]), t[b]).backward()
            opt.step()
    return m


def main() -> int:
    torch.set_num_threads(4)
    z = np.load(th.NPZ)
    X = z["features"].astype(float)
    y = z["actual"].astype(bool)
    t = z["bucket"].astype(np.int64) * 60
    fam = z["family"]
    day = np.array([datetime.fromtimestamp(int(v), UTC).strftime("%Y-%m-%d") for v in t])
    base = np.isin(day, ["2019-04-02", "2019-04-03"])
    pool = day == "2019-04-23"
    test = day >= "2019-04-24"
    Xl = X.copy()
    Xl[:, ms.LOG_IDX] = np.log1p(np.maximum(Xl[:, ms.LOG_IDX], 0))
    mu, sd = Xl[base].mean(0), Xl[base].std(0)
    sd[sd < 1e-9] = 1.0
    V = vb.build((Xl - mu) / sd, base)[0]["A"]
    print(f"pool units {int(pool.sum())} (attack {int((pool & y).sum())}, families {sorted(set(fam[pool & y]))}); "
          f"test {int(test.sum())} (attack {int((test & y).sum())})")
    dom = ms.load_domains()
    WS = {n: vb.build(d["Z"], d["baseline"])[0]["A"] for n, d in dom.items()}
    ms.new_model = lambda arch, seed: ed.model_for(arch, seed, 50)
    pre = {}
    for name, srcs in (("MS", ["data24", "data22", "unsw_nb15"]), ("D24", ["data24"])):
        pre[name] = [ms.fedavg(None, [(WS[n][dom[n]["train"]], dom[n]["y"][dom[n]["train"]]) for n in srcs], s) for s in ms.SEEDS]
    yi = y.astype(int)
    pidx = np.where(pool)[0]
    rows = []
    t0 = time.time()
    for k in BUDGETS:
        for si, s in enumerate(ms.SEEDS):
            rng = np.random.default_rng(s)
            if k == "all":
                idx = pidx
            else:
                b, a = pidx[yi[pidx] == 0], pidx[yi[pidx] == 1]
                idx = np.concatenate([rng.choice(b, k // 2, replace=False), rng.choice(a, k - k // 2, replace=False)])
            arms = {
                "MS-head": finetune(pre["MS"][si], V[idx], yi[idx], s, True, 100),
                "MS-full": finetune(pre["MS"][si], V[idx], yi[idx], s, False, 60),
                "D24-full": finetune(pre["D24"][si], V[idx], yi[idx], s, False, 60),
                "SCRATCH": finetune(ed.model_for(None, 1000 + s, 50), V[idx], yi[idx], s, False, 60),
            }
            rec = {"k": k, "seed": s}
            for a_, m in arms.items():
                g = ed.margin(m, V[test])
                e = dae.binary_metrics(y[test], g > 0, g)
                rec[a_] = {"ba": e["balanced_accuracy"], "fpr": e["false_positive_rate"], "recall": e["attack_recall"], "auroc": e["auroc"],
                           "rec@1%": ef.recall_at_fpr(g, y[test], 0.01)}
            rows.append(rec)
        sm = {a_: {m_: mean(r[a_][m_] for r in rows if r["k"] == k) for m_ in ("ba", "fpr", "recall", "auroc", "rec@1%")} for a_ in arms}
        print(f"k={k!s:>4} " + " | ".join(f"{a_} BA={v['ba']:.3f} FPR={v['fpr']:.3f} AUROC={v['auroc']:.3f} r@1%={v['rec@1%']:.3f}" for a_, v in sm.items())
              + f" ({time.time() - t0:.0f}s)", flush=True)
    # per-family recall for the best small-budget arm
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(rows, indent=1, default=str) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
