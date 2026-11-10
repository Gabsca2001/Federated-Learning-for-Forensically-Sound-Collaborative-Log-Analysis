"""Confirmation of Data24 -> UNSW-NB15 transfer on session S0 (protocol v1)."""

from __future__ import annotations

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
import explore_deviation_fl as ed
import explore_fusion as ef
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/unsw-s0-confirmation-v1"
SEEDS = (0, 1, 2, 3, 4)


def ts(h):
    return int(datetime(2015, 1, 22, h, tzinfo=UTC).timestamp())


def main() -> int:
    recorded = (OUT / "protocol.sha256").read_text().split()[0]
    if dae.sha256_file(OUT / "protocol.md") != recorded:
        raise SystemExit("protocol digest mismatch")
    if (OUT / "results.json").exists():
        raise SystemExit("results.json already exists")
    torch.set_num_threads(4)
    dom = ms.load_domains()
    d24 = dom["data24"]
    rows = json.loads((dae.ROOT / "artifacts/unsw-nb15-host-units-v1/units.json").read_text())["rows"]
    X = np.array([r["features"] for r in rows], float)
    y = np.array([r["label"] == "attack" for r in rows])
    t = np.array([r["window_start_epoch"] for r in rows])
    s0 = np.array([r["capture_id"] != "2015-02-18" for r in rows])
    base = s0 & (t >= ts(20)) & (t < ts(22))
    tests = {"primary_attack_period": s0 & (t < ts(14)), "secondary_all_S0": s0 & ~base}
    Xl = X.copy()
    Xl[:, ms.LOG_IDX] = np.log1p(np.maximum(Xl[:, ms.LOG_IDX], 0))
    mu, sd = Xl[base].mean(0), Xl[base].std(0)
    sd[sd < 1e-9] = 1.0
    Z = (Xl - mu) / sd
    V = ed.REPS["both"](Z).astype(np.float32)
    V24 = ed.REPS["both"](d24["Z"]).astype(np.float32)
    ms.new_model = lambda arch, seed: ed.model_for(arch, seed, 50)
    inv = np.linalg.pinv(np.cov(Z[base], rowvar=False) + 1e-6 * np.eye(25))
    dd = Z - Z[base].mean(0)
    nov = np.sqrt(np.einsum("ij,jk,ik->i", dd, inv, dd))
    rn = ef.rank(nov, base)

    res = {"baseline_units": int(base.sum()), "baseline_attack_check": int((base & y).sum()), "tests": {}}
    clfs = {}
    for s in SEEDS:
        m = ms.fedavg(None, [(V24[d24["train"]], d24["y"][d24["train"]])], s)
        clfs[s] = ed.margin(m, V)
    for name, test in tests.items():
        r = {"units": int(test.sum()), "attack": int((test & y).sum()), "seeds": {}}
        sel = base | test

        def ev(sc, test=test, sel=sel):
            e = dac.evaluate(sc[sel], base[sel], y[sel])
            for f in (0.001, 0.01, 0.05):
                e[f"rec@{f}"] = ef.recall_at_fpr(sc[test], y[test], f)
            return e

        r["NOV"] = ev(nov)
        for s in SEEDS:
            c = clfs[s]
            zc = (c - c[base].mean()) / (c[base].std() + 1e-9)
            zn = (nov - nov[base].mean()) / (nov[base].std() + 1e-9)
            r["seeds"][s] = {"CLF": ev(c), "SUM": ev(rn + ef.rank(c, base) + 1e-6 * (zn + zc))}
        for arm in ("CLF", "SUM"):
            r[arm + "_mean"] = {k: mean(r["seeds"][s][arm][k] for s in SEEDS)
                                for k in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc", "rec@0.001", "rec@0.01", "rec@0.05")}
        res["tests"][name] = r
    p = res["tests"]["primary_attack_period"]
    c1, n1 = p["CLF_mean"]["rec@0.01"], p["NOV"]["rec@0.01"]
    ok_seeds = sum(p["seeds"][s]["CLF"]["rec@0.01"] >= 0.40 for s in SEEDS)
    if c1 >= 0.50 and c1 - n1 >= 0.20 and ok_seeds >= 4:
        verdict = "confirmed"
    elif c1 < 0.30:
        verdict = "not_confirmed"
    else:
        verdict = "partial"
    res.update({"protocol_sha256": recorded, "script_sha256": dae.sha256_file(Path(__file__)),
                "verdict": verdict, "seeds_with_recall_ge_0.40_at_1pct": ok_seeds})
    (OUT / "results.json").write_text(json.dumps(res, indent=1, sort_keys=True, default=str) + "\n")
    print("baseline units", res["baseline_units"], "attack in baseline", res["baseline_attack_check"])
    for name, r in res["tests"].items():
        print(f"\n{name}: units {r['units']}, attack {r['attack']}")
        for arm, e in (("NOV", r["NOV"]), ("CLF", r["CLF_mean"]), ("SUM", r["SUM_mean"])):
            print(f"  {arm} BA={e['balanced_accuracy']:.3f} FPR={e['false_positive_rate']:.3f} REC={e['attack_recall']:.3f} "
                  f"AUROC={e['auroc']:.3f} | rec@0.1%={e['rec@0.001']:.3f} @1%={e['rec@0.01']:.3f} @5%={e['rec@0.05']:.3f}")
        print("  CLF rec@1% per seed:", [round(r["seeds"][s]["CLF"]["rec@0.01"], 3) for s in SEEDS])
    print("\nVERDICT:", verdict, "| seeds >=0.40:", ok_seeds, "/ 5")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
