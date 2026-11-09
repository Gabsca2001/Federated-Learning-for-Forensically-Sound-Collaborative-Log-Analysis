"""Controls for the label-free baseline adaptation result (protocol v1).

Compares AB1 with the frozen Data24 model against novelty detectors without Data24
knowledge (N1), untrained networks (N2) and other Data24 models (N3), using the same
baseline standardization and 99th-percentile baseline threshold.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import NearestNeighbors

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae

from fl_forensics.external_generalization import _model_from_export
from fl_forensics.federated_model import build_model

OUT = dae.ROOT / "artifacts/domain-adaptation-controls-v1"
ROBUST = dae.ROOT / "artifacts/ton-iot-robust-transfer-v1"
N3_RUNS = {"341593": 11, "342593": 13, "343593": 11}
N2_SEEDS = (0, 1, 2)
MARGIN = 0.05


def nn_scores(Zb: np.ndarray, Z: np.ndarray, base_mask: np.ndarray, k: int = 5) -> np.ndarray:
    nn = NearestNeighbors(n_neighbors=k + 1).fit(Zb)
    dist, _ = nn.kneighbors(Z)
    out = dist[:, :k].mean(axis=1)
    out[base_mask] = dist[base_mask, 1 : k + 1].mean(axis=1)  # exclude self for baseline windows
    return out


def classifier_score(model, Z: np.ndarray, benign_idx: int) -> np.ndarray:
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(Z), 1024):
            out.append(torch.softmax(model(torch.from_numpy(Z[i : i + 1024].astype(np.float32))), 1).numpy())
    p = np.concatenate(out)
    assert np.isfinite(p).all()
    return 1.0 - p[:, benign_idx]


def evaluate(score: np.ndarray, base: np.ndarray, attack: np.ndarray) -> dict:
    thr = float(np.quantile(score[base], 0.99))
    alert = score > thr
    test = ~base
    m = dae.binary_metrics(attack[test], alert[test], score[test])
    m["threshold"] = thr
    m["baseline_alert_rate"] = float(alert[base].mean())
    m["verdict"] = dae.verdict(m)
    return m


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=OUT)
    a = p.parse_args(argv)
    recorded = (a.output / "protocol.sha256").read_text().split()[0]
    if dae.sha256_file(a.output / "protocol.md") != recorded:
        raise SystemExit("protocol digest mismatch")
    if (a.output / "results.json").exists():
        raise SystemExit("results.json already exists")

    frozen_path = dae.TRANSFER / "frozen-model.json"
    if dae.sha256_file(frozen_path) != dae.MODEL_SHA256:
        raise SystemExit("unexpected frozen model digest")
    frozen = json.loads(frozen_path.read_text())
    scaler = json.loads((dae.TRANSFER / "frozen-scaler.json").read_text())
    src_scale = np.asarray(scaler["scale"], dtype=float)
    classes = frozen["class_names"]
    benign_idx = classes.index("benign")
    arch = frozen["architecture"]

    selection = json.loads((ROBUST / "selection-before-ton-iot.json").read_text())
    n3 = {}
    for seed, rnd in N3_RUNS.items():
        run = selection["runs"][f"standard-s{seed}"]
        if run["selected_round"] != rnd:
            raise SystemExit(f"N3 seed {seed}: selected round {run['selected_round']} != {rnd}")
        path = ROBUST / "runs" / f"standard-s{seed}" / "rounds" / f"round-{rnd:03d}" / "model.json"
        if dae.sha256_file(path) != run["selected_model_sha256"]:
            raise SystemExit(f"N3 seed {seed}: model digest mismatch")
        export = json.loads(path.read_text())
        if export["class_names"] != classes:
            raise SystemExit("N3 class order differs")
        n3[f"N3-data24-s{seed}"] = (_model_from_export(export, np=np, torch=torch), dae.sha256_file(path))

    n2 = {}
    for s in N2_SEEDS:
        torch.manual_seed(s)
        n2[f"N2-random-s{s}"] = build_model(
            input_features=arch["input_features"],
            class_count=arch["classification_head_outputs"],
            hidden_layers=list(arch["encoder_hidden_layers"]),
            embedding_size=arch["embedding_size"],
            dropout=arch["dropout"],
            torch=torch,
        )
    frozen_model = _model_from_export(frozen, np=np, torch=torch)

    results = {}
    for name in ("data22", "ton_iot"):
        X, _labels, dates, attack, path = dae.load_dataset(
            name,
            dae.ROOT / "artifacts/revision-data22-external-v1/dataset.json",
            dae.TRANSFER / "windows/occurrence-windows.json",
        )
        base = np.isin(dates, dae.BASELINE_DATES[name])
        mu = X[base].mean(0)
        sd = X[base].std(0)
        sd = np.where(sd < dae.MIN_STD, src_scale, sd)
        Z = (X - mu) / sd
        Zb = Z[base]

        scores = {"AB1-frozen": classifier_score(frozen_model, Z, benign_idx)}
        scores["N1-maxz"] = np.abs(Z).max(axis=1)
        cov = np.cov(Zb, rowvar=False) + 1e-6 * np.eye(Z.shape[1])
        inv = np.linalg.pinv(cov)
        d = Z - Zb.mean(0)
        scores["N1-mahalanobis"] = np.sqrt(np.einsum("ij,jk,ik->i", d, inv, d))
        scores["N1-knn"] = nn_scores(Zb, Z, base)
        iforest = IsolationForest(n_estimators=200, random_state=0).fit(Zb)
        scores["N1-iforest"] = -iforest.score_samples(Z)
        for k, mdl in n2.items():
            scores[k] = classifier_score(mdl, Z, benign_idx)
        for k, (mdl, _) in n3.items():
            scores[k] = classifier_score(mdl, Z, benign_idx)

        per = {k: evaluate(v, base, attack) for k, v in scores.items()}
        ref = per["AB1-frozen"]["balanced_accuracy"]
        best_n1 = max((k for k in per if k.startswith("N1-")), key=lambda k: per[k]["balanced_accuracy"])
        best_n2 = max((k for k in per if k.startswith("N2-")), key=lambda k: per[k]["balanced_accuracy"])
        results[name] = {
            "input": {"path": str(path), "sha256": dae.sha256_file(path)},
            "test_benign": int((~base & ~attack).sum()),
            "test_attack": int((~base & attack).sum()),
            "scorers": per,
            "best_n1": best_n1,
            "delta_n1": ref - per[best_n1]["balanced_accuracy"],
            "best_n2": best_n2,
            "delta_n2": ref - per[best_n2]["balanced_accuracy"],
        }

    d1 = [results[n]["delta_n1"] for n in results]
    d2 = [results[n]["delta_n2"] for n in results]
    if all(x >= MARGIN for x in d1) and all(x >= MARGIN for x in d2):
        conclusion = "data24_knowledge_contributes"
    elif all(abs(x) < MARGIN for x in d1):
        conclusion = "equivalent_to_novelty_detection"
    elif all(x <= -MARGIN for x in d1):
        conclusion = "data24_model_worse"
    else:
        conclusion = "mixed"
    stable = all(
        results[n]["scorers"][k]["verdict"] == "improvement" for n in results for k in results[n]["scorers"] if k.startswith("N3-")
    )
    out = {
        "protocol_sha256": recorded,
        "script_sha256": dae.sha256_file(Path(__file__)),
        "frozen_model_sha256": dae.MODEL_SHA256,
        "n3_model_sha256": {k: v[1] for k, v in n3.items()},
        "conclusion": conclusion,
        "n3_model_stable": stable,
        "datasets": results,
    }
    (a.output / "results.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    for n, r in results.items():
        print(f"{n}: test benign/attack {r['test_benign']}/{r['test_attack']}")
        for k, m in r["scorers"].items():
            print(f"  {k:18s} BA={m['balanced_accuracy']:.3f} FPR={m['false_positive_rate']:.3f} "
                  f"REC={m['attack_recall']:.3f} AUROC={m['auroc']:.3f} -> {m['verdict']}")
        print(f"  delta_n1={r['delta_n1']:+.3f} (best {r['best_n1']})  delta_n2={r['delta_n2']:+.3f} (best {r['best_n2']})")
    print("CONCLUSION:", conclusion, "| N3 stable:", stable)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
