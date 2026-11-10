"""Data24 generalization tests on UNSW-NB15 source-host x minute units (protocol v1)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, stdev

import numpy as np
import torch
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_controls as dac
import domain_adaptation_eval as dae
import label_efficiency as le

from fl_forensics.external_generalization import _model_from_export
from fl_forensics.federated_model import build_model
from fl_forensics.preprocessing import FEATURE_NAMES

ROOT = dae.ROOT
OUT = ROOT / "artifacts/unsw-generalization-v1"
UNITS = ROOT / "artifacts/unsw-nb15-host-units-v1/units.json"
WINDOWS = ROOT / "artifacts/unsw-nb15-windows-v1/windows.json"
BASE_START = int(datetime(2015, 1, 22, 14, tzinfo=UTC).timestamp())
BASE_END = int(datetime(2015, 1, 22, 16, tzinfo=UTC).timestamp())
S1_DAY = "2015-02-18"
STATE_IDX = [FEATURE_NAMES.index(f) for f in FEATURE_NAMES if f.startswith("state_")]


def load(path: Path):
    d = json.loads(path.read_text())
    rows = d["rows"]
    X = np.array([r["features"] for r in rows], dtype=float)
    y = np.array([r["label"] == "attack" for r in rows])
    t = np.array([r["window_start_epoch"] for r in rows])
    day = np.array([r["capture_id"] for r in rows])
    host = np.array([r.get("source_host", "") for r in rows])
    return X, y, t, day, host


def scorers(frozen, n2, n3, benign_idx, src_scale, X, base):
    mu = X[base].mean(0)
    sd = X[base].std(0)
    sd = np.where(sd < dae.MIN_STD, src_scale, sd)
    Z = (X - mu) / sd
    Zb = Z[base]
    s = {"AB1-frozen": dac.classifier_score(frozen, Z, benign_idx)}
    s["N1-maxz"] = np.abs(Z).max(axis=1)
    inv = np.linalg.pinv(np.cov(Zb, rowvar=False) + 1e-6 * np.eye(Z.shape[1]))
    d = Z - Zb.mean(0)
    s["N1-mahalanobis"] = np.sqrt(np.einsum("ij,jk,ik->i", d, inv, d))
    s["N1-knn"] = dac.nn_scores(Zb, Z, base)
    s["N1-iforest"] = -IsolationForest(n_estimators=200, random_state=0).fit(Zb).score_samples(Z)
    for k, m in n2.items():
        s[k] = dac.classifier_score(m, Z, benign_idx)
    for k, m in n3.items():
        s[k] = dac.classifier_score(m, Z, benign_idx)
    return s


def eval_views(scores, base, y, views):
    out = {}
    for vname, mask in views.items():
        sel = base | mask  # evaluate() uses ~base as test; restrict to view
        out[vname] = {}
        for k, sc in scores.items():
            out[vname][k] = dac.evaluate(sc[sel], base[sel], y[sel])
    return out


def decide(per):
    ref = per["AB1-frozen"]["balanced_accuracy"]
    n1 = max(v["balanced_accuracy"] for k, v in per.items() if k.startswith("N1-"))
    n2 = max(v["balanced_accuracy"] for k, v in per.items() if k.startswith("N2-"))
    d1, d2 = ref - n1, ref - n2
    if d1 >= 0.05 and d2 >= 0.05:
        c = "data24_knowledge_contributes"
    elif abs(d1) < 0.05:
        c = "equivalent_to_novelty_detection"
    elif d1 <= -0.05:
        c = "data24_model_worse"
    else:
        c = "mixed"
    stable = all(abs(v["balanced_accuracy"] - ref) <= 0.05 for k, v in per.items() if k.startswith("N3-"))
    return {"delta_n1": d1, "delta_n2": d2, "conclusion": c, "n3_within_0.05": stable}


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

    fpath = dae.TRANSFER / "frozen-model.json"
    if dae.sha256_file(fpath) != dae.MODEL_SHA256:
        raise SystemExit("frozen digest mismatch")
    fexp = json.loads(fpath.read_text())
    arch = fexp["architecture"]
    classes = fexp["class_names"]
    bi = classes.index("benign")
    scaler = json.loads((dae.TRANSFER / "frozen-scaler.json").read_text())
    src_mean = np.asarray(scaler["mean"])
    src_scale = np.asarray(scaler["scale"])
    frozen = _model_from_export(fexp, np=np, torch=torch)
    n2 = {}
    for s in dac.N2_SEEDS:
        torch.manual_seed(s)
        n2[f"N2-random-s{s}"] = build_model(
            input_features=arch["input_features"], class_count=arch["classification_head_outputs"],
            hidden_layers=list(arch["encoder_hidden_layers"]), embedding_size=arch["embedding_size"],
            dropout=arch["dropout"], torch=torch)
    sel = json.loads((dac.ROBUST / "selection-before-ton-iot.json").read_text())
    n3 = {}
    for seed, rnd in dac.N3_RUNS.items():
        path = dac.ROBUST / "runs" / f"standard-s{seed}" / "rounds" / f"round-{rnd:03d}" / "model.json"
        if dae.sha256_file(path) != sel["runs"][f"standard-s{seed}"]["selected_model_sha256"]:
            raise SystemExit("N3 digest mismatch")
        n3[f"N3-data24-s{seed}"] = _model_from_export(json.loads(path.read_text()), np=np, torch=torch)

    X, y, t, day, host = load(UNITS)
    base = (t >= BASE_START) & (t < BASE_END)
    s1 = day == S1_DAY
    attack_minutes = set(t[s1 & y].tolist())
    attack_hosts = set(host[y].tolist())
    views = {
        "all_S1": s1,
        "same_minute": s1 & np.isin(t, list(attack_minutes)),
        "attacker_hosts": s1 & np.isin(host, list(attack_hosts)),
    }
    results = {"baseline_units": int(base.sum()), "baseline_attack_units_check": int((base & y).sum()),
               "test_units": int(s1.sum()), "test_attack": int((s1 & y).sum())}

    # C0
    prob = []
    with torch.no_grad():
        Zs = (X - src_mean) / src_scale
        for i in range(0, len(Zs), 4096):
            prob.append(torch.softmax(frozen(torch.from_numpy(Zs[i:i + 4096].astype(np.float32))), 1).numpy())
    prob = np.concatenate(prob)
    c0 = prob.argmax(1) != bi
    results["C0_all_S1"] = dae.binary_metrics(y[s1], c0[s1], 1 - prob[s1, bi])

    sc = scorers(frozen, n2, n3, bi, src_scale, X, base)
    part1 = eval_views(sc, base, y, views)
    results["part1"] = part1
    results["part1_decision"] = decide(part1["all_S1"])

    Xn = X.copy()
    Xn[:, STATE_IDX] = X[base][:, STATE_IDX].mean(0)
    scn = scorers(frozen, n2, n3, bi, src_scale, Xn, base)
    results["state_neutralized_all_S1"] = eval_views(scn, base, y, {"all_S1": s1})["all_S1"]
    results["state_neutralized_decision"] = decide(results["state_neutralized_all_S1"])

    # Part 2 – label efficiency
    sources = le.load_sources(arch)
    pool = ~s1
    Z = le.preprocess(X, pool)
    pool_idx = np.where(pool)[0]
    yi = y.astype(int)
    runs = []
    t0 = time.time()
    for k in le.BUDGETS:
        for s in le.SEEDS:
            idx = le.sample(pool_idx, yi, k, s)
            rec = {"k": k, "seed": s}
            for arm in ("P", "R"):
                model = le.make_model(arch, sources[s]["encoder"] if arm == "P" else None, s if arm == "P" else 1000 + s)
                le.train(model, Z[idx], yi[idx], s)
                p_ = le.predict(model, Z[s1])
                rec[arm] = le.metrics(yi[s1], p_ > 0.5, p_)
            alert, nsc = le.novelty(Z, idx[yi[idx] == 0], s1)
            rec["N"] = le.metrics(yi[s1], alert, nsc)
            runs.append(rec)
            print(f"k={k!s:>4} s={s} P={rec['P']['balanced_accuracy']:.3f} R={rec['R']['balanced_accuracy']:.3f} "
                  f"N={rec['N']['balanced_accuracy']:.3f} ({time.time() - t0:.0f}s)", flush=True)
    summ = {}
    for k in le.BUDGETS:
        rs = [r for r in runs if r["k"] == k]
        summ[str(k)] = {arm: {"mean": mean(r[arm]["balanced_accuracy"] for r in rs),
                              "sd": stdev(r[arm]["balanced_accuracy"] for r in rs)} for arm in ("P", "R", "N")}
    dl = {str(k): summ[str(k)]["P"]["mean"] - summ[str(k)]["R"]["mean"] for k in le.BUDGETS}
    small = [dl[str(k)] for k in (16, 32, 64)]
    if sum(d >= 0.05 for d in small) >= 2 and all(d >= -0.02 for d in dl.values()):
        c2 = "pretraining_helps"
    elif all(abs(d) < 0.05 for d in small):
        c2 = "no_benefit"
    elif sum(d <= -0.05 for d in small) >= 2:
        c2 = "pretraining_hurts"
    else:
        c2 = "mixed"
    results["part2"] = {"summary": summ, "delta": dl, "conclusion": c2, "runs": runs}

    # Secondary: global windows
    Xw, yw, tw, dw, _ = load(WINDOWS)
    bw = (tw >= BASE_START) & (tw < BASE_END)
    s1w = dw == S1_DAY
    muw = Xw[bw].mean(0)
    sdw = np.where(Xw[bw].std(0) < dae.MIN_STD, src_scale, Xw[bw].std(0))
    Zw = (Xw - muw) / sdw
    gw = {"AB1-frozen": dac.classifier_score(frozen, Zw, bi)}
    inv = np.linalg.pinv(np.cov(Zw[bw], rowvar=False) + 1e-6 * np.eye(25))
    dd = Zw - Zw[bw].mean(0)
    gw["N1-mahalanobis"] = np.sqrt(np.einsum("ij,jk,ik->i", dd, inv, dd))
    selw = bw | s1w
    results["global_windows_secondary"] = {k: dac.evaluate(v[selw], bw[selw], yw[selw]) for k, v in gw.items()}
    probw = []
    with torch.no_grad():
        probw = torch.softmax(frozen(torch.from_numpy(((Xw - src_mean) / src_scale).astype(np.float32))), 1).numpy()
    results["global_windows_secondary"]["C0"] = dae.binary_metrics(yw[s1w], (probw.argmax(1) != bi)[s1w], 1 - probw[s1w, bi])

    out = {"protocol_sha256": recorded, "script_sha256": dae.sha256_file(Path(__file__)),
           "units_sha256": dae.sha256_file(UNITS), "windows_sha256": dae.sha256_file(WINDOWS), **results}
    (a.output / "results.json").write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")

    print("\nbaseline units", results["baseline_units"], "attack in baseline", results["baseline_attack_units_check"],
          "| test", results["test_units"], "attack", results["test_attack"])
    m = results["C0_all_S1"]
    print(f"C0 all_S1: BA={m['balanced_accuracy']:.3f} FPR={m['false_positive_rate']:.3f} REC={m['attack_recall']:.3f}")
    for v in views:
        print("VIEW", v)
        for k, m in part1[v].items():
            print(f"  {k:18s} BA={m['balanced_accuracy']:.3f} FPR={m['false_positive_rate']:.3f} "
                  f"REC={m['attack_recall']} AUROC={m['auroc']}")
    print("PART1 decision:", results["part1_decision"])
    print("STATE-NEUTRALIZED decision:", results["state_neutralized_decision"])
    for k in le.BUDGETS:
        sm = summ[str(k)]
        print(f"k={k!s:>4} P={sm['P']['mean']:.3f} R={sm['R']['mean']:.3f} N={sm['N']['mean']:.3f} delta={dl[str(k)]:+.3f}")
    print("PART2 decision:", c2)
    for k, m in results["global_windows_secondary"].items():
        print(f"GLOBAL {k:16s} BA={m['balanced_accuracy']:.3f} FPR={m['false_positive_rate']:.3f} REC={m['attack_recall']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
