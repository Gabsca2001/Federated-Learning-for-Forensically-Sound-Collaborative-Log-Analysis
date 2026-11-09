"""Leave-one-family-out: Data24 pre-training vs scratch on unseen ToN-IoT families (protocol v1)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from statistics import mean

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae
import label_efficiency as le

OUT = dae.ROOT / "artifacts/lofo-v1"
FAMILIES = ("backdoor", "ddos", "dos", "injection", "mitm", "password", "ransomware", "scanning", "xss")
BUDGETS = (32, 128, "all")


def run_family(f, rows, X, y, fam, pool0, test0, arch, sources):
    held = fam == f
    pool = pool0 & ~held
    test = (test0 & (y == 0)) | held
    Z = le.preprocess(X, pool)
    pool_idx = np.where(pool)[0]
    out = []
    for k in BUDGETS:
        for s in le.SEEDS:
            idx = le.sample(pool_idx, y, k, s)
            rec = {"family": f, "k": k, "seed": s}
            for arm in ("P", "R"):
                enc = sources[s]["encoder"] if arm == "P" else None
                model = le.make_model(arch, enc, s if arm == "P" else 1000 + s)
                le.train(model, Z[idx], y[idx], s)
                sc = le.predict(model, Z[test])
                m = le.metrics(y[test], sc > 0.5, sc)
                m["family_recall"] = m.pop("attack_recall")
                rec[arm] = m
            alert, sc = le.novelty(Z, idx[y[idx] == 0], test)
            m = le.metrics(y[test], alert, sc)
            m["family_recall"] = m.pop("attack_recall")
            rec["N"] = m
            out.append(rec)
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

    arch = json.loads((dae.TRANSFER / "frozen-model.json").read_text())["architecture"]
    sources = le.load_sources(arch)
    win = dae.TRANSFER / "windows/occurrence-windows.json"
    rows = json.loads(win.read_text())["rows"]
    X = np.array([r["features"] for r in rows], dtype=float)
    y = np.array([0 if r["label"] == "benign" else 1 for r in rows])
    fam = np.array([le.family(r) for r in rows])
    pool0, test0 = le.split(rows)

    runs = []
    t0 = time.time()
    for f in FAMILIES:
        runs += run_family(f, rows, X, y, fam, pool0, test0, arch, sources)
        last = [r for r in runs if r["family"] == f and r["k"] == "all"]
        print(f"{f:10s} k=all P={mean(r['P']['balanced_accuracy'] for r in last):.3f} "
              f"R={mean(r['R']['balanced_accuracy'] for r in last):.3f} "
              f"N={mean(r['N']['balanced_accuracy'] for r in last):.3f} ({time.time() - t0:.0f}s)", flush=True)

    per_family = {}
    for f in FAMILIES:
        per_family[f] = {}
        for k in BUDGETS:
            rs = [r for r in runs if r["family"] == f and r["k"] == k]
            per_family[f][str(k)] = {
                arm: {m: mean(r[arm][m] for r in rs) for m in ("balanced_accuracy", "family_recall", "false_positive_rate", "auroc")}
                for arm in ("P", "R", "N")
            }
    macro = {
        str(k): {arm: mean(per_family[f][str(k)][arm]["balanced_accuracy"] for f in FAMILIES) for arm in ("P", "R", "N")}
        for k in BUDGETS
    }
    deltas = [macro[str(k)]["P"] - macro[str(k)]["R"] for k in BUDGETS]
    if sum(d >= 0.05 for d in deltas) >= 2 and all(d >= -0.02 for d in deltas):
        conclusion = "pretraining_helps_unseen"
    elif all(abs(d) < 0.05 for d in deltas):
        conclusion = "no_benefit"
    elif sum(d <= -0.05 for d in deltas) >= 2:
        conclusion = "pretraining_hurts"
    else:
        conclusion = "mixed"
    wins = sum(
        per_family[f]["all"]["P"]["balanced_accuracy"] - per_family[f]["all"]["R"]["balanced_accuracy"] >= 0.05 for f in FAMILIES
    )
    out = {
        "protocol_sha256": recorded,
        "script_sha256": dae.sha256_file(Path(__file__)),
        "windows_sha256": dae.sha256_file(win),
        "macro_ba": macro,
        "delta_macro_ba": dict(zip([str(k) for k in BUDGETS], deltas, strict=True)),
        "families_p_beats_r_by_0.05_at_all": wins,
        "conclusion": conclusion,
        "per_family": per_family,
        "runs": runs,
    }
    (a.output / "results.json").write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    print("\nper family (k=all): BA P / R / N | family recall P / R / N")
    for f in FAMILIES:
        v = per_family[f]["all"]
        print(f"  {f:10s} {v['P']['balanced_accuracy']:.3f} / {v['R']['balanced_accuracy']:.3f} / {v['N']['balanced_accuracy']:.3f}"
              f" | {v['P']['family_recall']:.3f} / {v['R']['family_recall']:.3f} / {v['N']['family_recall']:.3f}")
    for k in BUDGETS:
        m = macro[str(k)]
        print(f"macro k={k!s:>4}: P={m['P']:.3f} R={m['R']:.3f} N={m['N']:.3f} delta={m['P'] - m['R']:+.3f}")
    print("CONCLUSION:", conclusion, "| families with P-R>=0.05 at all:", wins)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
