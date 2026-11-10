"""Multi-source federated training, leave-one-domain-out (protocol v1)."""

from __future__ import annotations

import argparse
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
import domain_adaptation_controls as dac
import domain_adaptation_eval as dae
import label_efficiency as le

from fl_forensics.federated_model import build_model
from fl_forensics.preprocessing import FEATURE_NAMES

ROOT = dae.ROOT
OUT = ROOT / "artifacts/multisource-fl-v1"
DOMAINS = ("data24", "data22", "ton_iot", "unsw_nb15")
ROUNDS, LOCAL_EPOCHS, BATCH, SEEDS = 30, 2, 128, (0, 1, 2)
LOG_IDX = [FEATURE_NAMES.index(f) for f in le.LOG_FEATURES]
U0 = int(datetime(2015, 1, 22, 14, tzinfo=UTC).timestamp())
U1 = int(datetime(2015, 1, 22, 16, tzinfo=UTC).timestamp())


def load_domains() -> dict:
    d = {}
    rows = json.loads((ROOT / "artifacts/m2-data24-parquet/dataset.json").read_text())["rows"]
    X = np.array([r["features"] for r in rows], float)
    y = np.array([r["label"] != "benign" for r in rows])
    split = np.array([r["split"] for r in rows])
    trv = np.isin(split, ["train", "validation"])
    d["data24"] = {"X": X, "y": y, "baseline": trv & ~y, "train": trv, "test": split == "test"}
    for name in ("data22", "ton_iot"):
        X, _, dates, att, _ = dae.load_dataset(
            name, ROOT / "artifacts/revision-data22-external-v1/dataset.json",
            dae.TRANSFER / "windows/occurrence-windows.json")
        base = np.isin(dates, dae.BASELINE_DATES[name])
        d[name] = {"X": X, "y": att, "baseline": base, "train": np.ones(len(X), bool), "test": ~base}
    rows = json.loads((ROOT / "artifacts/unsw-nb15-host-units-v1/units.json").read_text())["rows"]
    X = np.array([r["features"] for r in rows], float)
    y = np.array([r["label"] == "attack" for r in rows])
    t = np.array([r["window_start_epoch"] for r in rows])
    s1 = np.array([r["capture_id"] == "2015-02-18" for r in rows])
    d["unsw_nb15"] = {"X": X, "y": y, "baseline": (t >= U0) & (t < U1), "train": ~s1, "test": s1}
    for v in d.values():
        Xl = v["X"].copy()
        Xl[:, LOG_IDX] = np.log1p(np.maximum(Xl[:, LOG_IDX], 0))
        mu = Xl[v["baseline"]].mean(0)
        sd = Xl[v["baseline"]].std(0)
        sd[sd < 1e-9] = 1.0
        v["Z"] = ((Xl - mu) / sd).astype(np.float32)
    return d


def new_model(arch, seed):
    torch.manual_seed(seed)
    base = build_model(input_features=25, class_count=arch["classification_head_outputs"],
                       hidden_layers=list(arch["encoder_hidden_layers"]), embedding_size=arch["embedding_size"],
                       dropout=0.0, torch=torch)
    torch.manual_seed(seed)
    return le.Binary(base.encoder, arch["embedding_size"])


def local_train(model, Z, y, seed):
    x = torch.from_numpy(Z)
    t = torch.from_numpy(y.astype(np.int64))
    c = np.bincount(y.astype(int), minlength=2).astype(float)
    w = torch.tensor(len(y) / (2 * np.maximum(c, 1)), dtype=torch.float32)
    lf = torch.nn.CrossEntropyLoss(weight=w)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    g = torch.Generator().manual_seed(seed)
    model.train()
    for _ in range(LOCAL_EPOCHS):
        perm = torch.randperm(len(y), generator=g)
        for i in range(0, len(y), BATCH):
            b = perm[i : i + BATCH]
            opt.zero_grad()
            lf(model(x[b]), t[b]).backward()
            opt.step()


def fedavg(arch, clients, seed):
    glob = new_model(arch, seed)
    n = np.array([len(c[1]) for c in clients], float)
    wts = n / n.sum()
    for rnd in range(ROUNDS):
        states = []
        for ci, (Z, y) in enumerate(clients):
            m = copy.deepcopy(glob)
            local_train(m, Z, y, seed * 100_000 + rnd * 100 + ci)
            states.append(m.state_dict())
        glob.load_state_dict({k: sum(w * s[k] for w, s in zip(wts, states, strict=True)) for k in states[0]})
    return glob


def evaluate_arm(score, dom):
    base, test, y = dom["baseline"], dom["test"], dom["y"]
    sel = base | test
    return dac.evaluate(score[sel], base[sel], y[sel])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=OUT)
    a = p.parse_args(argv)
    recorded = (a.output / "protocol.sha256").read_text().split()[0]
    if dae.sha256_file(a.output / "protocol.md") != recorded:
        raise SystemExit("protocol digest mismatch")
    if (a.output / "results.json").exists():
        raise SystemExit("results.json already exists")
    torch.set_num_threads(4)
    arch = json.loads((dae.TRANSFER / "frozen-model.json").read_text())["architecture"]
    dom = load_domains()
    t0 = time.time()
    res = {}
    for held in DOMAINS:
        D = dom[held]
        train_names = [n for n in DOMAINS if n != held]
        single = "data24" if held != "data24" else "unsw_nb15"
        r = {"train_domains": train_names, "single_source": single,
             "baseline_units": int(D["baseline"].sum()), "baseline_attack_check": int((D["baseline"] & D["y"]).sum()),
             "test_units": int(D["test"].sum()), "test_attack": int((D["test"] & D["y"]).sum()), "seeds": {}}
        Zb = D["Z"][D["baseline"]]
        inv = np.linalg.pinv(np.cov(Zb, rowvar=False) + 1e-6 * np.eye(25))
        dd = D["Z"] - Zb.mean(0)
        r["NOV"] = evaluate_arm(np.sqrt(np.einsum("ij,jk,ik->i", dd, inv, dd)), D)
        for s in SEEDS:
            out = {}
            for arm, names in (("MS", train_names), ("SS", [single])):
                clients = [(dom[n]["Z"][dom[n]["train"]], dom[n]["y"][dom[n]["train"]]) for n in names]
                m = fedavg(arch, clients, s)
                sc = le.predict(m, D["Z"])
                out[arm] = evaluate_arm(sc, D)
                out[arm + "_t05"] = dae.binary_metrics(D["y"][D["test"]], sc[D["test"]] > 0.5, sc[D["test"]])
            r["seeds"][s] = out
            print(f"held={held:9s} seed={s} MS={out['MS']['balanced_accuracy']:.3f} SS={out['SS']['balanced_accuracy']:.3f} "
                  f"NOV={r['NOV']['balanced_accuracy']:.3f} MS@0.5={out['MS_t05']['balanced_accuracy']:.3f} "
                  f"({time.time() - t0:.0f}s)", flush=True)
        for arm in ("MS", "SS", "MS_t05", "SS_t05"):
            r[arm + "_mean"] = {m: mean(r["seeds"][s][arm][m] for s in SEEDS)
                                for m in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc")}
        res[held] = r

    d_ss = {h: res[h]["MS_mean"]["balanced_accuracy"] - res[h]["SS_mean"]["balanced_accuracy"] for h in DOMAINS}
    d_nov = {h: res[h]["MS_mean"]["balanced_accuracy"] - res[h]["NOV"]["balanced_accuracy"] for h in DOMAINS}
    ms_vs_ss = ("multi_source_helps" if sum(v >= 0.05 for v in d_ss.values()) >= 2 and all(v >= -0.02 for v in d_ss.values())
                else "mixed_or_no_benefit")
    if sum(v >= 0.03 for v in d_nov.values()) >= 2 and all(v >= -0.02 for v in d_nov.values()):
        ms_vs_nov = "adds_value_beyond_novelty"
    elif sum(abs(v) < 0.03 for v in d_nov.values()) >= 3:
        ms_vs_nov = "equivalent_to_novelty"
    else:
        ms_vs_nov = "mixed"
    out = {"protocol_sha256": recorded, "script_sha256": dae.sha256_file(Path(__file__)),
           "delta_ms_minus_ss": d_ss, "delta_ms_minus_nov": d_nov,
           "decision_ms_vs_ss": ms_vs_ss, "decision_ms_vs_nov": ms_vs_nov, "held_out": res}
    (a.output / "results.json").write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    print("\nheld-out | MS | SS | NOV | MS@0.5  (BA, mean of seeds; label-free baseline threshold)")
    for h in DOMAINS:
        r = res[h]
        print(f"  {h:9s} {r['MS_mean']['balanced_accuracy']:.3f} | {r['SS_mean']['balanced_accuracy']:.3f} | "
              f"{r['NOV']['balanced_accuracy']:.3f} | {r['MS_t05_mean']['balanced_accuracy']:.3f}   "
              f"(MS FPR {r['MS_mean']['false_positive_rate']:.3f}, REC {r['MS_mean']['attack_recall']:.3f}, AUROC {r['MS_mean']['auroc']:.3f})")
    print("MS vs SS:", ms_vs_ss, {k: round(v, 3) for k, v in d_ss.items()})
    print("MS vs NOV:", ms_vs_nov, {k: round(v, 3) for k, v in d_nov.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
