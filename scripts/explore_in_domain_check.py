"""EXPLORATORY: does site-relative preprocessing preserve in-domain Data24 performance?

Same training recipe for every representation (FedAvg single client, 30 rounds, final round,
train+validation splits), evaluated on the Data24 test split and the benign temporal holdout.
  standard  z with the training-split mean/std (the thesis preprocessing)
  A         [clip z_b, log1p|z_b|], z_b relative to the benign baseline (benign train+val)
  B         sorted log1p|z_b|
Six-class head: macro-F1 / accuracy. Binary head: BA at argmax, holdout FPR.
"""

from __future__ import annotations

import copy
import json
import sys
from collections import Counter
from pathlib import Path
from statistics import mean

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-in-domain-check-v1"


def net(width, classes, seed):
    torch.manual_seed(seed)
    return torch.nn.Sequential(
        torch.nn.Linear(width, 128), torch.nn.ReLU(), torch.nn.Linear(128, 64), torch.nn.ReLU(),
        torch.nn.Linear(64, 32), torch.nn.ReLU(), torch.nn.Linear(32, classes))


def train(X, y, classes, seed):
    m = net(X.shape[1], classes, seed)
    x, t = torch.from_numpy(X), torch.from_numpy(y.astype(np.int64))
    c = np.bincount(y, minlength=classes).astype(float)
    lf = torch.nn.CrossEntropyLoss(weight=torch.tensor(len(y) / (classes * np.maximum(c, 1)), dtype=torch.float32))
    for rnd in range(ms.ROUNDS):
        loc = copy.deepcopy(m)
        opt = torch.optim.Adam(loc.parameters(), lr=1e-3)
        g = torch.Generator().manual_seed(seed * 100_000 + rnd)
        loc.train()
        for _ in range(ms.LOCAL_EPOCHS):
            perm = torch.randperm(len(y), generator=g)
            for i in range(0, len(y), ms.BATCH):
                b = perm[i : i + ms.BATCH]
                opt.zero_grad()
                lf(loc(x[b]), t[b]).backward()
                opt.step()
        m = loc
    m.eval()
    return m


def pred(m, X):
    with torch.no_grad():
        return m(torch.from_numpy(X)).argmax(1).numpy()


def macro_f1(y, p, classes):
    f = []
    for c in range(classes):
        tp = ((p == c) & (y == c)).sum()
        fp = ((p == c) & (y != c)).sum()
        fn = ((p != c) & (y == c)).sum()
        f.append(2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0)
    return float(np.mean(f))


def main() -> int:
    torch.set_num_threads(4)
    rows = json.loads((dae.ROOT / "artifacts/m2-data24-parquet/dataset.json").read_text())["rows"]
    X = np.array([r["features"] for r in rows], float)
    lab = np.array([r["label"] for r in rows])
    split = np.array([r["split"] for r in rows])
    print("splits:", dict(Counter(split)))
    names = sorted(set(lab))
    y6 = np.array([names.index(v) for v in lab])
    y2 = (lab != "benign").astype(int)
    tr = np.isin(split, ["train", "validation"])
    te = split == "test"
    ho = ~np.isin(split, ["train", "validation", "test"])
    mu, sd = X[split == "train"].mean(0), X[split == "train"].std(0)
    sd[sd < 1e-9] = 1.0
    dom = ms.load_domains()["data24"]
    W, _ = vb.build(dom["Z"], dom["baseline"])
    reps = {"standard": ((X - mu) / sd).astype(np.float32), "A": W["A"], "B": W["B"]}
    bi = names.index("benign")
    res = {}
    for rep, V in reps.items():
        r6, r2 = [], []
        for s in ms.SEEDS:
            m6 = train(V[tr], y6[tr], len(names), s)
            p = pred(m6, V[te])
            r6.append({"macro_f1": macro_f1(y6[te], p, len(names)), "accuracy": float((p == y6[te]).mean()),
                       "holdout_fpr": float((pred(m6, V[ho]) != bi).mean()) if ho.any() else None})
            m2 = train(V[tr], y2[tr], 2, s)
            p = pred(m2, V[te]).astype(bool)
            e = dae.binary_metrics(y2[te].astype(bool), p, p.astype(float))
            r2.append({"balanced_accuracy": e["balanced_accuracy"], "fpr": e["false_positive_rate"], "recall": e["attack_recall"],
                       "holdout_fpr": float(pred(m2, V[ho]).mean()) if ho.any() else None})
        res[rep] = {"six_class": {k: mean(x[k] for x in r6) for k in r6[0] if r6[0][k] is not None},
                    "binary": {k: mean(x[k] for x in r2) for k in r2[0] if r2[0][k] is not None},
                    "six_class_macro_f1_per_seed": [x["macro_f1"] for x in r6]}
        print(f"{rep:9s} 6-class macroF1={res[rep]['six_class']['macro_f1']:.4f} acc={res[rep]['six_class']['accuracy']:.4f} "
              f"holdoutFPR={res[rep]['six_class'].get('holdout_fpr', float('nan')):.4f} seeds={[round(v, 3) for v in res[rep]['six_class_macro_f1_per_seed']]} | "
              f"binary BA={res[rep]['binary']['balanced_accuracy']:.4f} FPR={res[rep]['binary']['fpr']:.4f} REC={res[rep]['binary']['recall']:.4f} "
              f"holdoutFPR={res[rep]['binary'].get('holdout_fpr', float('nan')):.4f}", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps({"classes": names, "results": res}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
