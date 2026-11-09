"""Label efficiency on ToN-IoT: Data24 pre-trained encoder vs scratch (protocol v1)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from statistics import mean, stdev

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae

from fl_forensics.external_generalization import _model_from_export
from fl_forensics.federated_model import build_model
from fl_forensics.preprocessing import FEATURE_NAMES

OUT = dae.ROOT / "artifacts/label-efficiency-v1"
ROBUST = dae.ROOT / "artifacts/ton-iot-robust-transfer-v1"
LOG_FEATURES = [
    "connection_count", "unique_destination_count", "unique_destination_port_count",
    "duration_mean", "duration_std", "duration_max",
    "originator_bytes_sum", "responder_bytes_sum", "originator_packets_sum", "responder_packets_sum",
]
BUDGETS = (16, 32, 64, 128, 256, 512, "all")
SEEDS = (0, 1, 2)
SOURCE_BY_SEED = {0: ("frozen", None), 1: ("342593", 13), 2: ("343593", 11)}
PURGE_SECONDS = 3600
EPOCHS = 60


def family(row: dict) -> str:
    t = sorted(k for k in row["source_type_counts"] if k != "normal")
    return "benign" if not t else (t[0] if len(t) == 1 else "mixed")


def split(rows: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    fam = np.array([family(r) for r in rows])
    start = np.array([r["window_start_epoch"] for r in rows])
    pool = np.zeros(len(rows), bool)
    test = np.zeros(len(rows), bool)
    for f in sorted(set(fam)):
        idx = np.where(fam == f)[0]
        idx = idx[np.argsort(start[idx], kind="mergesort")]
        n_pool = round(0.7 * len(idx))
        p_idx, t_idx = idx[:n_pool], idx[n_pool:]
        if len(t_idx):
            first_test = start[t_idx].min()
            p_idx = p_idx[start[p_idx] <= first_test - PURGE_SECONDS]
        pool[p_idx] = True
        test[t_idx] = True
    return pool, test


def preprocess(X: np.ndarray, pool: np.ndarray) -> np.ndarray:
    X = X.copy()
    for f in LOG_FEATURES:
        j = FEATURE_NAMES.index(f)
        X[:, j] = np.log1p(np.maximum(X[:, j], 0))
    mu = X[pool].mean(0)
    sd = X[pool].std(0)
    sd[sd < 1e-9] = 1.0
    return (X - mu) / sd


def sample(pool_idx: np.ndarray, y: np.ndarray, k, seed: int) -> np.ndarray:
    if k == "all":
        return pool_idx
    rng = np.random.default_rng(seed)
    ben = pool_idx[y[pool_idx] == 0]
    att = pool_idx[y[pool_idx] == 1]
    nb = min(k // 2, len(ben))
    na = min(k - nb, len(att))
    return np.concatenate([rng.choice(ben, nb, replace=False), rng.choice(att, na, replace=False)])


class Binary(torch.nn.Module):
    def __init__(self, encoder: torch.nn.Module, width: int):
        super().__init__()
        self.encoder = encoder
        self.head = torch.nn.Linear(width, 2)

    def forward(self, x):
        return self.head(self.encoder(x))


def make_model(arch: dict, encoder_state: dict | None, init_seed: int) -> Binary:
    torch.manual_seed(init_seed)
    base = build_model(
        input_features=arch["input_features"], class_count=arch["classification_head_outputs"],
        hidden_layers=list(arch["encoder_hidden_layers"]), embedding_size=arch["embedding_size"],
        dropout=arch["dropout"], torch=torch,
    )
    if encoder_state is not None:
        base.encoder.load_state_dict(encoder_state)
    torch.manual_seed(init_seed)
    return Binary(base.encoder, arch["embedding_size"])


def train(model: Binary, Z: np.ndarray, y: np.ndarray, seed: int) -> None:
    torch.manual_seed(seed)
    x = torch.from_numpy(Z.astype(np.float32))
    t = torch.from_numpy(y.astype(np.int64))
    counts = np.bincount(y, minlength=2).astype(float)
    w = torch.tensor(len(y) / (2 * np.maximum(counts, 1)), dtype=torch.float32)
    loss_fn = torch.nn.CrossEntropyLoss(weight=w)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    bs = min(32, len(y))
    g = torch.Generator().manual_seed(seed)
    model.train()
    for _ in range(EPOCHS):
        perm = torch.randperm(len(y), generator=g)
        for i in range(0, len(y), bs):
            b = perm[i : i + bs]
            opt.zero_grad()
            loss_fn(model(x[b]), t[b]).backward()
            opt.step()


def predict(model: Binary, Z: np.ndarray) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        return torch.softmax(model(torch.from_numpy(Z.astype(np.float32))), 1)[:, 1].numpy()


def metrics(y: np.ndarray, pred: np.ndarray, score: np.ndarray) -> dict:
    m = dae.binary_metrics(y.astype(bool), pred.astype(bool), score)
    return {k: m[k] for k in ("balanced_accuracy", "binary_macro_f1", "false_positive_rate", "attack_recall", "auroc")}


def novelty(Z: np.ndarray, ben_idx: np.ndarray, test: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    B = Z[ben_idx]
    cov = np.cov(B, rowvar=False) + 1e-3 * np.eye(Z.shape[1])
    inv = np.linalg.pinv(cov)
    mu = B.mean(0)

    def score(A):
        d = A - mu
        return np.sqrt(np.einsum("ij,jk,ik->i", d, inv, d))

    thr = np.quantile(score(B), 0.99)
    s = score(Z[test])
    return s > thr, s


def load_sources(arch_ref: dict) -> dict:
    sel = json.loads((ROBUST / "selection-before-ton-iot.json").read_text())
    out = {}
    for s, (name, rnd) in SOURCE_BY_SEED.items():
        if name == "frozen":
            path = dae.TRANSFER / "frozen-model.json"
            if dae.sha256_file(path) != dae.MODEL_SHA256:
                raise SystemExit("frozen digest mismatch")
        else:
            run = sel["runs"][f"standard-s{name}"]
            if run["selected_round"] != rnd:
                raise SystemExit(f"round mismatch for {name}")
            path = ROBUST / "runs" / f"standard-s{name}" / "rounds" / f"round-{rnd:03d}" / "model.json"
            if dae.sha256_file(path) != run["selected_model_sha256"]:
                raise SystemExit(f"digest mismatch for {name}")
        export = json.loads(path.read_text())
        if export["architecture"] != arch_ref:
            raise SystemExit("architecture mismatch")
        model = _model_from_export(export, np=np, torch=torch)
        out[s] = {"name": name, "sha256": dae.sha256_file(path),
                  "encoder": {k: v.clone() for k, v in model.encoder.state_dict().items()}}
    return out


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

    frozen = json.loads((dae.TRANSFER / "frozen-model.json").read_text())
    arch = frozen["architecture"]
    sources = load_sources(arch)
    win_path = dae.TRANSFER / "windows/occurrence-windows.json"
    rows = json.loads(win_path.read_text())["rows"]
    X = np.array([r["features"] for r in rows], dtype=float)
    y = np.array([0 if r["label"] == "benign" else 1 for r in rows])
    pool, test = split(rows)
    Z = preprocess(X, pool)
    pool_idx = np.where(pool)[0]

    runs = []
    t0 = time.time()
    for k in BUDGETS:
        for s in SEEDS:
            idx = sample(pool_idx, y, k, s)
            rec = {"k": k, "seed": s, "n_labelled": len(idx), "n_benign": int((y[idx] == 0).sum())}
            for arm in ("P", "R"):
                enc = sources[s]["encoder"] if arm == "P" else None
                model = make_model(arch, enc, s if arm == "P" else 1000 + s)
                train(model, Z[idx], y[idx], s)
                sc = predict(model, Z[test])
                rec[arm] = metrics(y[test], sc > 0.5, sc)
            ben = idx[y[idx] == 0]
            alert, sc = novelty(Z, ben, test)
            rec["N"] = metrics(y[test], alert, sc)
            rec["P_source"] = sources[s]["name"]
            runs.append(rec)
            print(f"k={k!s:>4} s={s} P={rec['P']['balanced_accuracy']:.3f} R={rec['R']['balanced_accuracy']:.3f} "
                  f"N={rec['N']['balanced_accuracy']:.3f}  ({time.time() - t0:.0f}s)", flush=True)

    summary = {}
    for k in BUDGETS:
        rs = [r for r in runs if r["k"] == k]
        summary[str(k)] = {
            arm: {m: {"mean": mean(r[arm][m] for r in rs), "sd": stdev(r[arm][m] for r in rs)}
                  for m in ("balanced_accuracy", "binary_macro_f1", "false_positive_rate", "attack_recall", "auroc")}
            for arm in ("P", "R", "N")
        }
        summary[str(k)]["delta_ba"] = summary[str(k)]["P"]["balanced_accuracy"]["mean"] - summary[str(k)]["R"]["balanced_accuracy"]["mean"]
    small = [summary[str(k)]["delta_ba"] for k in (16, 32, 64)]
    alld = [summary[str(k)]["delta_ba"] for k in BUDGETS]
    if sum(d >= 0.05 for d in small) >= 2 and all(d >= -0.02 for d in alld):
        conclusion = "pretraining_helps"
    elif all(abs(d) < 0.05 for d in small):
        conclusion = "no_benefit"
    elif sum(d <= -0.05 for d in small) >= 2:
        conclusion = "pretraining_hurts"
    else:
        conclusion = "mixed"

    def first_k(arm):
        for k in BUDGETS:
            if summary[str(k)][arm]["balanced_accuracy"]["mean"] >= 0.80:
                return k
        return None

    out = {
        "protocol_sha256": recorded,
        "script_sha256": dae.sha256_file(Path(__file__)),
        "windows_sha256": dae.sha256_file(win_path),
        "sources": {s: {"name": v["name"], "sha256": v["sha256"]} for s, v in sources.items()},
        "pool_windows": int(pool.sum()), "test_windows": int(test.sum()),
        "test_benign": int((test & (y == 0)).sum()), "test_attack": int((test & (y == 1)).sum()),
        "summary": summary, "conclusion": conclusion,
        "first_k_ba_ge_0.80": {arm: first_k(arm) for arm in ("P", "R", "N")},
        "runs": runs,
    }
    (a.output / "results.json").write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    print(f"pool={out['pool_windows']} test={out['test_windows']} (benign {out['test_benign']}, attack {out['test_attack']})")
    for k in BUDGETS:
        sm = summary[str(k)]
        print(f"k={k!s:>4}  P={sm['P']['balanced_accuracy']['mean']:.3f}±{sm['P']['balanced_accuracy']['sd']:.3f}  "
              f"R={sm['R']['balanced_accuracy']['mean']:.3f}±{sm['R']['balanced_accuracy']['sd']:.3f}  "
              f"N={sm['N']['balanced_accuracy']['mean']:.3f}  delta={sm['delta_ba']:+.3f}")
    print("CONCLUSION:", conclusion, "| first k with BA>=0.80:", out["first_k_ba_ge_0.80"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
