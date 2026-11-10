"""EXPLORATORY: federated classifiers on direction-free deviation inputs, leave-one-domain-out.

Motivated by the observed concept shift (attack-vs-benign feature directions differ across
networks). Inputs are derived from baseline-standardized z: signed z (reference), log1p|z|
(magnitude only), or both. Scores are logit margins (no softmax saturation); alert above the
99th percentile of the held-out baseline. Not a frozen protocol: all four domains were seen.
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
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-deviation-fl-v1"
REPS = {
    "signed": lambda Z: np.clip(Z, -20, 20),
    "abs": lambda Z: np.log1p(np.abs(Z)),
    "both": lambda Z: np.concatenate([np.clip(Z, -20, 20), np.log1p(np.abs(Z))], axis=1),
}


def model_for(arch, seed, width):
    torch.manual_seed(seed)
    enc = torch.nn.Sequential(
        torch.nn.Linear(width, 128), torch.nn.ReLU(), torch.nn.Linear(128, 64), torch.nn.ReLU(),
        torch.nn.Linear(64, 32), torch.nn.ReLU())
    return ms.le.Binary(enc, 32)


def margin(model, Z):
    model.eval()
    with torch.no_grad():
        o = model(torch.from_numpy(Z.astype(np.float32)))
    return (o[:, 1] - o[:, 0]).numpy()


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    arch = json.loads((dae.TRANSFER / "frozen-model.json").read_text())["architecture"]
    ms.new_model = None  # replaced below per representation
    res = {}
    t0 = time.time()
    for rep, fn in REPS.items():
        V = {n: fn(d["Z"]).astype(np.float32) for n, d in dom.items()}
        width = next(iter(V.values())).shape[1]
        ms.new_model = lambda arch, seed, w=width: model_for(arch, seed, w)
        for held in ms.DOMAINS:
            D = dom[held]
            sel = D["baseline"] | D["test"]
            for arm, names in (("MS", [n for n in ms.DOMAINS if n != held]),
                               ("D24", ["data24"] if held != "data24" else None)):
                if names is None:
                    continue
                rs = []
                for s in ms.SEEDS:
                    clients = [(V[n][dom[n]["train"]], dom[n]["y"][dom[n]["train"]]) for n in names]
                    m = ms.fedavg(arch, clients, s)
                    sc = margin(m, V[held])
                    rs.append(dac.evaluate(sc[sel], D["baseline"][sel], D["y"][sel]))
                key = f"{rep}|{arm}|{held}"
                res[key] = {k: [r[k] for r in rs] for k in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc")}
                print(f"{key:28s} BA={mean(res[key]['balanced_accuracy']):.3f} "
                      f"[{min(res[key]['balanced_accuracy']):.3f}-{max(res[key]['balanced_accuracy']):.3f}] "
                      f"FPR={mean(res[key]['false_positive_rate']):.3f} REC={mean(res[key]['attack_recall']):.3f} "
                      f"AUROC={mean(res[key]['auroc']):.3f} ({time.time() - t0:.0f}s)", flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
