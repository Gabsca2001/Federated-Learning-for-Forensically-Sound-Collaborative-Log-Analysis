"""Confirmation of the two-view Data24 system on UNSW-NB15 session S0 (protocol v1)."""

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
import explore_temporal_persistence as tp
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/two-view-confirmation-v1"
SEEDS = (0, 1, 2, 3, 4)
K = 5


def ts(h):
    return int(datetime(2015, 1, 22, h, tzinfo=UTC).timestamp())


def main() -> int:
    recorded = (OUT / "protocol.sha256").read_text().split()[0]
    if dae.sha256_file(OUT / "protocol.md") != recorded:
        raise SystemExit("protocol digest mismatch")
    if (OUT / "results.json").exists():
        raise SystemExit("results.json already exists")
    torch.set_num_threads(4)
    d24 = ms.load_domains()["data24"]
    W24, _ = vb.build(d24["Z"], d24["baseline"])
    rows = json.loads((dae.ROOT / "artifacts/unsw-nb15-host-units-v1/units.json").read_text())["rows"]
    X = np.array([r["features"] for r in rows], float)
    y = np.array([r["label"] == "attack" for r in rows])
    t = np.array([r["window_start_epoch"] for r in rows])
    host = np.array([r["source_host"] for r in rows])
    s0 = np.array([r["capture_id"] != "2015-02-18" for r in rows])
    base = s0 & (t >= ts(20)) & (t < ts(22))
    tests = {"primary_attack_period": s0 & (t < ts(14)), "secondary_all_S0": s0 & ~base}
    Xl = X.copy()
    Xl[:, ms.LOG_IDX] = np.log1p(np.maximum(Xl[:, ms.LOG_IDX], 0))
    mu, sd = Xl[base].mean(0), Xl[base].std(0)
    sd[sd < 1e-9] = 1.0
    Z = (Xl - mu) / sd
    W, maha = vb.build(Z, base)

    def std(v):
        return (v - v[base].mean()) / (v[base].std() + 1e-9)

    nov_s = tp.smooth(ef.rank(maha, base) + 1e-6 * std(maha), t, host, K)
    per_seed = {}
    for s in SEEDS:
        mg = {}
        for v in ("A", "B"):
            ms.new_model = lambda arch, seed, w=W24[v].shape[1]: ed.model_for(arch, seed, w)
            m = ms.fedavg(None, [(W24[v][d24["train"]], d24["y"][d24["train"]])], s)
            mg[v] = ed.margin(m, W[v])
        ra, rb = ef.rank(mg["A"], base), ef.rank(mg["B"], base)
        per_seed[s] = {
            "SYSTEM": tp.smooth(np.maximum(ra, rb) + 1e-6 * np.maximum(std(mg["A"]), std(mg["B"])), t, host, K),
            "A": tp.smooth(ra + 1e-6 * std(mg["A"]), t, host, K),
        }
    res = {"baseline_units": int(base.sum()), "baseline_attack_check": int((base & y).sum()), "tests": {}}
    for name, test in tests.items():
        sel = base | test

        def ev(sc, test=test, sel=sel):
            e = dac.evaluate(sc[sel], base[sel], y[sel])
            for q in (0.001, 0.01, 0.05):
                e[f"rec@{q}"] = ef.recall_at_fpr(sc[test], y[test], q)
            return e

        r = {"units": int(test.sum()), "attack": int((test & y).sum()), "NOV": ev(nov_s),
             "seeds": {s: {k: ev(v) for k, v in per_seed[s].items()} for s in SEEDS}}
        for arm in ("SYSTEM", "A"):
            r[arm + "_mean"] = {k: mean(r["seeds"][s][arm][k] for s in SEEDS)
                                for k in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc", "rec@0.001", "rec@0.01", "rec@0.05")}
        res["tests"][name] = r
    p = res["tests"]["primary_attack_period"]
    sys_ba, sys_fpr, nov_ba = p["SYSTEM_mean"]["balanced_accuracy"], p["SYSTEM_mean"]["false_positive_rate"], p["NOV"]["balanced_accuracy"]
    ok = sum(p["seeds"][s]["SYSTEM"]["balanced_accuracy"] >= 0.85 for s in SEEDS)
    a1 = p["A_mean"]["rec@0.01"]
    checks = {"ba_ge_0.90_and_fpr_le_0.10": sys_ba >= 0.90 and sys_fpr <= 0.10, "non_inferior_to_nov": sys_ba - nov_ba >= -0.02,
              "seeds_ge_0.85": ok >= 4, "view_a_rec_at_1pct_ge_0.60": a1 >= 0.60}
    if all(checks.values()):
        verdict = "confirmed"
    elif sys_ba < 0.80 or sys_ba - nov_ba < -0.10:
        verdict = "not_confirmed"
    else:
        verdict = "partial"
    res.update({"protocol_sha256": recorded, "script_sha256": dae.sha256_file(Path(__file__)), "checks": checks, "verdict": verdict})
    (OUT / "results.json").write_text(json.dumps(res, indent=1, sort_keys=True, default=str) + "\n")
    print("baseline", res["baseline_units"], "attack in baseline", res["baseline_attack_check"])
    for name, r in res["tests"].items():
        print(f"\n{name}: units {r['units']}, attack {r['attack']}")
        for arm, e in (("NOV", r["NOV"]), ("SYSTEM", r["SYSTEM_mean"]), ("A", r["A_mean"])):
            print(f"  {arm:6s} BA={e['balanced_accuracy']:.3f} FPR={e['false_positive_rate']:.3f} REC={e['attack_recall']:.3f} AUROC={e['auroc']:.3f} "
                  f"| rec@0.1%={e['rec@0.001']:.3f} @1%={e['rec@0.01']:.3f} @5%={e['rec@0.05']:.3f}")
        print("  SYSTEM BA per seed:", [round(r["seeds"][s]["SYSTEM"]["balanced_accuracy"], 3) for s in SEEDS])
    print("\nchecks:", checks, "\nVERDICT:", verdict)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
