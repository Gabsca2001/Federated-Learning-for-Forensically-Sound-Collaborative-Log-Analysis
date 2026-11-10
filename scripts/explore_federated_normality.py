"""EXPLORATORY: federated model of normality (autoencoder on benign baselines), leave-one-domain-out.

Each client trains only on its own benign baseline in baseline-standardized coordinates
(no attack labels anywhere). Score on the held-out network = reconstruction error; alert
above the 99th percentile of its baseline. Arms:
  FED      zero-shot: FedAvg AE over the three other networks
  FED+FT   FED fine-tuned for 5 epochs on the held-out baseline (label-free)
  LOCAL    AE trained only on the held-out baseline (no federation)
  NOV      Mahalanobis on the held-out baseline (reference)
Not a frozen protocol: all four domains were seen before.
"""

from __future__ import annotations

import copy
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
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-federated-normality-v1"
ROUNDS, LOCAL_EPOCHS, BATCH = 30, 2, 128


def ae(seed):
    torch.manual_seed(seed)
    return torch.nn.Sequential(
        torch.nn.Linear(25, 32), torch.nn.ReLU(), torch.nn.Linear(32, 8), torch.nn.ReLU(),
        torch.nn.Linear(8, 32), torch.nn.ReLU(), torch.nn.Linear(32, 25))


def fit(model, Z, epochs, seed):
    x = torch.from_numpy(Z)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    g = torch.Generator().manual_seed(seed)
    model.train()
    for _ in range(epochs):
        perm = torch.randperm(len(x), generator=g)
        for i in range(0, len(x), BATCH):
            b = perm[i : i + BATCH]
            opt.zero_grad()
            torch.nn.functional.mse_loss(model(x[b]), x[b]).backward()
            opt.step()


def err(model, Z):
    model.eval()
    with torch.no_grad():
        x = torch.from_numpy(Z)
        return ((model(x) - x) ** 2).mean(1).numpy()


def fed(clients, seed):
    glob = ae(seed)
    n = np.array([len(c) for c in clients], float)
    w = n / n.sum()
    for rnd in range(ROUNDS):
        states = []
        for ci, Z in enumerate(clients):
            m = copy.deepcopy(glob)
            fit(m, Z, LOCAL_EPOCHS, seed * 100_000 + rnd * 100 + ci)
            states.append(m.state_dict())
        glob.load_state_dict({k: sum(a * s[k] for a, s in zip(w, states, strict=True)) for k in states[0]})
    return glob


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    V = {n: np.clip(d["Z"], -10, 10).astype(np.float32) for n, d in dom.items()}
    res = {}
    t0 = time.time()
    for held in ms.DOMAINS:
        D = dom[held]
        base, sel, y = D["baseline"], D["baseline"] | D["test"], D["y"]
        Zb = D["Z"][base]
        inv = np.linalg.pinv(np.cov(Zb, rowvar=False) + 1e-6 * np.eye(25))
        dd = D["Z"] - Zb.mean(0)
        nov = dac.evaluate(np.sqrt(np.einsum("ij,jk,ik->i", dd, inv, dd))[sel], base[sel], y[sel])
        arms = {"FED": [], "FED+FT": [], "LOCAL": []}
        for s in ms.SEEDS:
            g = fed([V[n][dom[n]["baseline"]] for n in ms.DOMAINS if n != held], s)
            arms["FED"].append(dac.evaluate(err(g, V[held])[sel], base[sel], y[sel]))
            ft = copy.deepcopy(g)
            fit(ft, V[held][base], 5, s)
            arms["FED+FT"].append(dac.evaluate(err(ft, V[held])[sel], base[sel], y[sel]))
            loc = ae(s)
            fit(loc, V[held][base], ROUNDS * LOCAL_EPOCHS, s)
            arms["LOCAL"].append(dac.evaluate(err(loc, V[held])[sel], base[sel], y[sel]))
        res[held] = {"NOV": nov, **{a: {k: [r[k] for r in rs] for k in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc")} for a, rs in arms.items()}}
        print(f"{held:9s} NOV    BA={nov['balanced_accuracy']:.3f} FPR={nov['false_positive_rate']:.3f} REC={nov['attack_recall']:.3f} AUROC={nov['auroc']:.3f}")
        for a in arms:
            r = res[held][a]
            print(f"{held:9s} {a:6s} BA={mean(r['balanced_accuracy']):.3f} [{min(r['balanced_accuracy']):.3f}-{max(r['balanced_accuracy']):.3f}] "
                  f"FPR={mean(r['false_positive_rate']):.3f} REC={mean(r['attack_recall']):.3f} AUROC={mean(r['auroc']):.3f} ({time.time() - t0:.0f}s)", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
