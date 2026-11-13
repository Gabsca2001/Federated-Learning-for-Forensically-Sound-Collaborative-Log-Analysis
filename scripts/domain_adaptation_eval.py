"""Label-free benign-baseline adaptation of the frozen Data24 model (protocol v1).

Inference only: no model parameter is fitted. For each target dataset the earliest
capture dates form a baseline assumed normal; standardization (A) and/or the alert
threshold on s = 1 - P(benign) (B) are re-estimated there and evaluated on later dates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import torch

from fl_forensics.external_generalization import _model_from_export
from fl_forensics.preprocessing import FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[1]
TRANSFER = ROOT / "artifacts/ton-iot-transfer-20261109"
MODEL_SHA256 = "39075d9cbf7c45248c475ae3ddfb66f0e032d55cc210eba2a9e97c19e3d594e5"
BASELINE_DATES = {
    "data22": ("2022-01-09", "2022-01-10", "2022-01-11", "2022-01-12"),
    "ton_iot": ("2019-04-02", "2019-04-03"),
}
CONFIGS = ("C0", "A", "B1", "B5", "AB1", "AB5")
MIN_STD = 1e-9


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def binary_metrics(actual: np.ndarray, predicted: np.ndarray, score: np.ndarray) -> dict:
    tp = int(np.sum(actual & predicted))
    tn = int(np.sum(~actual & ~predicted))
    fp = int(np.sum(~actual & predicted))
    fn = int(np.sum(actual & ~predicted))
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    precision = tp / (tp + fp) if tp + fp else 0.0
    attack_f1 = 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0
    benign_f1 = 2 * tn / (2 * tn + fp + fn) if tn + fp + fn else 0.0
    return {
        "confusion_matrix": {"rows_true_benign_attack": [[tn, fp], [fn, tp]]},
        "balanced_accuracy": (recall + (1 - fpr)) / 2 if recall is not None and fpr is not None else None,
        "false_positive_rate": fpr,
        "attack_recall": recall,
        "attack_precision": precision,
        "binary_macro_f1": (attack_f1 + benign_f1) / 2,
        "auroc": auroc(actual, score),
    }


def auroc(actual: np.ndarray, score: np.ndarray) -> float | None:
    pos, neg = score[actual], score[~actual]
    if not len(pos) or not len(neg):
        return None
    order = np.argsort(np.concatenate([pos, neg]), kind="mergesort")
    ranks = np.empty(len(order))
    allv = np.concatenate([pos, neg])[order]
    i = 0
    while i < len(allv):  # average ranks for ties
        j = i
        while j + 1 < len(allv) and allv[j + 1] == allv[i]:
            j += 1
        ranks[order[i : j + 1]] = (i + j) / 2 + 1
        i = j + 1
    return float((ranks[: len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def verdict(m: dict) -> str:
    ba, fpr = m["balanced_accuracy"], m["false_positive_rate"]
    if ba is None:
        return "undefined"
    if ba >= 0.70 and fpr <= 0.30:
        return "improvement"
    if ba < 0.60:
        return "negative"
    return "inconclusive"


def load_dataset(name: str, data22: Path, ton_iot: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, Path]:
    path = data22 if name == "data22" else ton_iot
    d = json.loads(path.read_text())
    if d["feature_names"] != FEATURE_NAMES:
        raise SystemExit(f"{name}: feature contract differs")
    rows = d["rows"]
    X = np.array([r["features"] for r in rows], dtype=float)
    labels = np.array([r["label"] for r in rows])
    dates = np.array([r["capture_id"] for r in rows])
    attack = labels != "benign"
    return X, labels, dates, attack, path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=ROOT / "artifacts/domain-adaptation-v1")
    p.add_argument("--data22", type=Path, default=ROOT / "artifacts/revision-data22-external-v1/dataset.json")
    p.add_argument("--ton-iot", type=Path, default=TRANSFER / "windows/occurrence-windows.json")
    p.add_argument("--model", type=Path, default=TRANSFER / "frozen-model.json")
    p.add_argument("--scaler", type=Path, default=TRANSFER / "frozen-scaler.json")
    a = p.parse_args(argv)

    protocol = a.output / "protocol.md"
    recorded = (a.output / "protocol.sha256").read_text().split()[0]
    if sha256_file(protocol) != recorded:
        raise SystemExit("protocol digest mismatch")
    if (a.output / "results.json").exists():
        raise SystemExit("results.json already exists")
    if sha256_file(a.model) != MODEL_SHA256:
        raise SystemExit("unexpected model digest")

    export = json.loads(a.model.read_text())
    scaler = json.loads(a.scaler.read_text())
    classes = export["class_names"]
    benign_idx = classes.index("benign")
    model = _model_from_export(export, np=np, torch=torch)
    model.eval()
    src_mean = np.asarray(scaler["mean"], dtype=float)
    src_scale = np.asarray(scaler["scale"], dtype=float)

    def infer(Z: np.ndarray) -> np.ndarray:
        out = []
        with torch.no_grad():
            for i in range(0, len(Z), 1024):
                out.append(torch.softmax(model(torch.from_numpy(Z[i : i + 1024].astype(np.float32))), dim=1).numpy())
        prob = np.concatenate(out)
        assert np.isfinite(prob).all()
        return prob

    results = {}
    for name in ("data22", "ton_iot"):
        X, labels, dates, attack, path = load_dataset(name, a.data22, a.ton_iot)
        base = np.isin(dates, BASELINE_DATES[name])
        test = ~base
        base_labels = sorted(set(labels[base].tolist()))
        b_mean = X[base].mean(axis=0)
        b_std = X[base].std(axis=0)
        replaced = [FEATURE_NAMES[j] for j in range(len(b_std)) if b_std[j] < MIN_STD]
        b_std = np.where(b_std < MIN_STD, src_scale, b_std)

        prob = {
            "source": infer((X - src_mean) / src_scale),
            "baseline": infer((X - b_mean) / b_std),
        }
        score = {k: 1.0 - v[:, benign_idx] for k, v in prob.items()}
        argmax_attack = {k: v.argmax(axis=1) != benign_idx for k, v in prob.items()}
        thr = {
            (k, q): float(np.quantile(score[k][base], q / 100)) for k in score for q in (99, 95)
        }
        decisions = {
            "C0": (argmax_attack["source"], score["source"]),
            "A": (argmax_attack["baseline"], score["baseline"]),
            "B1": (score["source"] > thr[("source", 99)], score["source"]),
            "B5": (score["source"] > thr[("source", 95)], score["source"]),
            "AB1": (score["baseline"] > thr[("baseline", 99)], score["baseline"]),
            "AB5": (score["baseline"] > thr[("baseline", 95)], score["baseline"]),
        }
        per = {}
        for cid in CONFIGS:
            dec, s = decisions[cid]
            m = binary_metrics(attack[test], dec[test], s[test])
            m["baseline_alert_rate"] = float(np.mean(dec[base]))
            m["verdict"] = verdict(m)
            per[cid] = m
        extra = {}
        if name == "data22":
            pred_labels = np.array(classes)[prob["baseline"].argmax(axis=1)]
            recon = test & (labels == "reconnaissance")
            extra["A_reconnaissance_recall_six_class"] = float(np.mean(pred_labels[recon] == "reconnaissance"))
            pred_c0 = np.array(classes)[prob["source"].argmax(axis=1)]
            extra["C0_reconnaissance_recall_six_class"] = float(np.mean(pred_c0[recon] == "reconnaissance"))
        results[name] = {
            "input": {"path": str(path), "sha256": sha256_file(path)},
            "baseline_dates": list(BASELINE_DATES[name]),
            "baseline_windows": int(base.sum()),
            "baseline_released_labels_check": base_labels,
            "test_windows": int(test.sum()),
            "test_benign": int((test & ~attack).sum()),
            "test_attack": int((test & attack).sum()),
            "baseline_std_replaced_by_source_scale": replaced,
            "thresholds": {f"{k}_p{q}": v for (k, q), v in thr.items()},
            "configs": per,
            **extra,
        }

    overall = {
        cid: {
            "data22": results["data22"]["configs"][cid]["verdict"],
            "ton_iot": results["ton_iot"]["configs"][cid]["verdict"],
            "label_free_generalization": all(
                results[d]["configs"][cid]["verdict"] == "improvement" for d in ("data22", "ton_iot")
            ),
        }
        for cid in CONFIGS
    }
    out = {
        "protocol_sha256": recorded,
        "script_sha256": sha256_file(Path(__file__)),
        "model_sha256": MODEL_SHA256,
        "scaler_sha256": sha256_file(a.scaler),
        "device": "cpu",
        "datasets": results,
        "overall": overall,
    }
    (a.output / "results.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    for name in results:
        print(name, "test benign/attack =", results[name]["test_benign"], "/", results[name]["test_attack"],
              "| baseline labels:", results[name]["baseline_released_labels_check"])
        for cid in CONFIGS:
            m = results[name]["configs"][cid]
            print(f"  {cid:4s} BA={m['balanced_accuracy']:.3f} FPR={m['false_positive_rate']:.3f} "
                  f"REC={m['attack_recall']:.3f} AUROC={m['auroc']:.3f} baseAlert={m['baseline_alert_rate']:.3f} -> {m['verdict']}")
    print(json.dumps(overall, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
