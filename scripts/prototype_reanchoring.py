"""Prototype re-anchoring in the Data24 encoder space vs raw features (protocol v1)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_controls as dac
import domain_adaptation_eval as dae

from fl_forensics.external_generalization import _model_from_export
from fl_forensics.federated_model import build_model

OUT = dae.ROOT / "artifacts/prototype-reanchoring-v1"
UNSW = dae.ROOT / "artifacts/unsw-nb15-host-units-v1/units.json"
U_BASE = (int(datetime(2015, 1, 22, 14, tzinfo=UTC).timestamp()), int(datetime(2015, 1, 22, 16, tzinfo=UTC).timestamp()))


def targets():
    out = {}
    for name in ("data22", "ton_iot"):
        X, _, dates, attack, _ = dae.load_dataset(
            name, dae.ROOT / "artifacts/revision-data22-external-v1/dataset.json",
            dae.TRANSFER / "windows/occurrence-windows.json")
        base = np.isin(dates, dae.BASELINE_DATES[name])
        out[name] = (X, attack, base, ~base)
    rows = json.loads(UNSW.read_text())["rows"]
    X = np.array([r["features"] for r in rows], dtype=float)
    y = np.array([r["label"] == "attack" for r in rows])
    t = np.array([r["window_start_epoch"] for r in rows])
    day = np.array([r["capture_id"] for r in rows])
    out["unsw_nb15"] = (X, y, (t >= U_BASE[0]) & (t < U_BASE[1]), day == "2015-02-18")
    return out


def embed(model, Z: np.ndarray) -> np.ndarray:
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(Z), 4096):
            out.append(model.encoder(torch.from_numpy(Z[i : i + 4096].astype(np.float32))).numpy())
    return np.concatenate(out)


def scores(V: np.ndarray, base: np.ndarray, ridge: float) -> dict:
    B = V[base]
    mu = B.mean(0)
    inv = np.linalg.pinv(np.cov(B, rowvar=False) + ridge * np.eye(V.shape[1]))
    d = V - mu
    return {"mahalanobis": np.sqrt(np.einsum("ij,jk,ik->i", d, inv, d)), "euclidean": np.linalg.norm(d, axis=1)}


def evaluate(score, base, test, y):
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

    fpath = dae.TRANSFER / "frozen-model.json"
    if dae.sha256_file(fpath) != dae.MODEL_SHA256:
        raise SystemExit("frozen digest mismatch")
    fexp = json.loads(fpath.read_text())
    arch = fexp["architecture"]
    scaler = json.loads((dae.TRANSFER / "frozen-scaler.json").read_text())
    src_mean, src_scale = np.asarray(scaler["mean"]), np.asarray(scaler["scale"])
    d24 = {"frozen": _model_from_export(fexp, np=np, torch=torch)}
    sel = json.loads((dac.ROBUST / "selection-before-ton-iot.json").read_text())
    for seed, rnd in (("342593", 13), ("343593", 11)):
        path = dac.ROBUST / "runs" / f"standard-s{seed}" / "rounds" / f"round-{rnd:03d}" / "model.json"
        if dae.sha256_file(path) != sel["runs"][f"standard-s{seed}"]["selected_model_sha256"]:
            raise SystemExit("digest mismatch")
        d24[f"s{seed}"] = _model_from_export(json.loads(path.read_text()), np=np, torch=torch)
    rand = {}
    for s in (0, 1, 2):
        torch.manual_seed(s)
        rand[f"rand{s}"] = build_model(
            input_features=arch["input_features"], class_count=arch["classification_head_outputs"],
            hidden_layers=list(arch["encoder_hidden_layers"]), embedding_size=arch["embedding_size"],
            dropout=arch["dropout"], torch=torch)

    res = {}
    for tname, (X, y, base, test) in targets().items():
        mu, sd = X[base].mean(0), X[base].std(0)
        sd = np.where(sd < dae.MIN_STD, src_scale, sd)
        Z = (X - mu) / sd
        Zs = (X - src_mean) / src_scale
        r = {"baseline_units": int(base.sum()), "baseline_attack_check": int((base & y).sum()),
             "test_units": int(test.sum()), "test_attack": int((test & y).sum())}
        sc = scores(Z, base, 1e-6)
        r["RAW"] = {k: evaluate(v, base, test, y) for k, v in sc.items()}
        for k, m in d24.items():
            r[f"EMB-D24-{k}"] = {s: evaluate(v, base, test, y) for s, v in scores(embed(m, Z), base, 1e-3).items()}
            r[f"EMB-D24-{k}-srcscaled"] = {s: evaluate(v, base, test, y) for s, v in scores(embed(m, Zs), base, 1e-3).items()}
        for k, m in rand.items():
            r[f"EMB-RAND-{k}"] = {s: evaluate(v, base, test, y) for s, v in scores(embed(m, Z), base, 1e-3).items()}

        def ba(key, r=r):
            return r[key]["mahalanobis"]["balanced_accuracy"]

        r["mean_BA_EMB_D24"] = mean(ba(f"EMB-D24-{k}") for k in d24)
        r["mean_BA_EMB_RAND"] = mean(ba(f"EMB-RAND-{k}") for k in rand)
        r["delta_raw"] = r["mean_BA_EMB_D24"] - ba("RAW")
        r["delta_rand"] = r["mean_BA_EMB_D24"] - r["mean_BA_EMB_RAND"]
        res[tname] = r

    dr = [res[t]["delta_raw"] for t in res]
    dd = [res[t]["delta_rand"] for t in res]
    if sum(x >= 0.03 for x in dr) >= 2 and all(x >= -0.02 for x in dr) and sum(x >= 0.03 for x in dd) >= 2:
        concl = "data24_embedding_helps"
    elif all(abs(x) < 0.03 for x in dr):
        concl = "equivalent"
    elif sum(x <= -0.03 for x in dr) >= 2:
        concl = "data24_embedding_worse"
    else:
        concl = "mixed"
    out = {"protocol_sha256": recorded, "script_sha256": dae.sha256_file(Path(__file__)), "conclusion": concl, "targets": res}
    (a.output / "results.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    for t, r in res.items():
        print(f"{t}: baseline {r['baseline_units']} (attack {r['baseline_attack_check']}), test {r['test_units']} (attack {r['test_attack']})")
        for k in [k for k in r if k.startswith(("RAW", "EMB"))]:
            m, e = r[k]["mahalanobis"], r[k]["euclidean"]
            print(f"  {k:26s} maha BA={m['balanced_accuracy']:.3f} FPR={m['false_positive_rate']:.3f} REC={m['attack_recall']:.3f} AUROC={m['auroc']:.3f} | eucl BA={e['balanced_accuracy']:.3f}")
        print(f"  delta_raw={r['delta_raw']:+.3f} delta_rand={r['delta_rand']:+.3f}")
    print("CONCLUSION:", concl)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
