"""EXPLORATORY diagnostic: per-attacker-host and per-category behaviour of the two-view system on UNSW-NB15.

No training on UNSW-NB15 (Data24-only models, seed-averaged margins over seeds 0-2).
Settings: S1 (baseline S0 14-16 UTC) and S0 attack period (baseline S0 20-22 UTC).
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_temporal_persistence as tp
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/explore-unsw-per-host-v1"


def ts(h):
    return int(datetime(2015, 1, 22, h, tzinfo=UTC).timestamp())


def main() -> int:
    torch.set_num_threads(4)
    d24 = ms.load_domains()["data24"]
    W24, _ = vb.build(d24["Z"], d24["baseline"])
    models = {}
    for v in ("A", "B"):
        ms.new_model = lambda arch, seed, w=W24[v].shape[1]: ed.model_for(arch, seed, w)
        models[v] = [ms.fedavg(None, [(W24[v][d24["train"]], d24["y"][d24["train"]])], s) for s in ms.SEEDS]
    rows = json.loads((dae.ROOT / "artifacts/unsw-nb15-host-units-v1/units.json").read_text())["rows"]
    X = np.array([r["features"] for r in rows], float)
    y = np.array([r["label"] == "attack" for r in rows])
    t = np.array([r["window_start_epoch"] for r in rows])
    host = np.array([r["source_host"] for r in rows])
    fam = np.array([r["family"] for r in rows])
    frac = np.array([r["attack_record_fraction"] for r in rows])
    s0 = np.array([r["capture_id"] != "2015-02-18" for r in rows])
    attackers = sorted(set(host[y]))
    settings = {
        "S1_feb18": ((s0 & (t >= ts(14)) & (t < ts(16))), ~s0),
        "S0_jan22_attack_period": ((s0 & (t >= ts(20)) & (t < ts(22))), s0 & (t < ts(14))),
    }
    Xl = X.copy()
    Xl[:, ms.LOG_IDX] = np.log1p(np.maximum(Xl[:, ms.LOG_IDX], 0))
    res = {}
    for name, (base, test) in settings.items():
        mu, sd = Xl[base].mean(0), Xl[base].std(0)
        sd[sd < 1e-9] = 1.0
        W, _ = vb.build((Xl - mu) / sd, base)
        mg = {v: np.mean([ed.margin(m, W[v]) for m in models[v]], axis=0) for v in ("A", "B")}

        def std(v, base=base):
            return (v - v[base].mean()) / (v[base].std() + 1e-9)

        ra, rb = ef.rank(mg["A"], base), ef.rank(mg["B"], base)
        sc = {"SYSTEM": tp.smooth(np.maximum(ra, rb) + 1e-6 * np.maximum(std(mg["A"]), std(mg["B"])), t, host, 5),
              "A": tp.smooth(ra + 1e-6 * std(mg["A"]), t, host, 5)}
        alert = {k: v > np.quantile(v[base], 0.99) for k, v in sc.items()}
        r = {"baseline_units_of_attacker_hosts": int((base & np.isin(host, attackers)).sum()), "hosts": {}, "families": {}, "purity": {}}
        print(f"\n== {name}: baseline units from attacker hosts = {r['baseline_units_of_attacker_hosts']}")
        print("  host            attack units  recall SYSTEM / A   | benign units of same host  flagged SYSTEM / A")
        for h in attackers:
            a, b = test & y & (host == h), test & ~y & (host == h)
            r["hosts"][h] = {"attack_units": int(a.sum()), "recall_system": float(alert["SYSTEM"][a].mean()) if a.any() else None,
                             "recall_A": float(alert["A"][a].mean()) if a.any() else None, "benign_units": int(b.sum()),
                             "benign_flagged_system": float(alert["SYSTEM"][b].mean()) if b.any() else None,
                             "benign_flagged_A": float(alert["A"][b].mean()) if b.any() else None}
            x = r["hosts"][h]
            print(f"  {h:15s} {x['attack_units']:6d}        {x['recall_system']} / {x['recall_A']}   | {x['benign_units']:5d}   {x['benign_flagged_system']} / {x['benign_flagged_A']}")
        other = test & ~y & ~np.isin(host, attackers)
        r["other_hosts_benign"] = {"units": int(other.sum()), "flagged_system": float(alert["SYSTEM"][other].mean()), "flagged_A": float(alert["A"][other].mean())}
        print(f"  non-attacker hosts: benign units {int(other.sum())}, flagged SYSTEM {alert['SYSTEM'][other].mean():.3f} / A {alert['A'][other].mean():.3f}")
        byf = defaultdict(list)
        for i in np.where(test & y)[0]:
            byf[fam[i]].append(i)
        print("  category: units, recall SYSTEM / A")
        for f, idx in sorted(byf.items(), key=lambda kv: -len(kv[1])):
            idx = np.array(idx)
            r["families"][f] = {"units": len(idx), "recall_system": float(alert["SYSTEM"][idx].mean()), "recall_A": float(alert["A"][idx].mean())}
            print(f"    {f:16s} {len(idx):5d}  {alert['SYSTEM'][idx].mean():.3f} / {alert['A'][idx].mean():.3f}")
        print("  attack-record share in the unit: units, recall SYSTEM / A")
        for lo, hi in ((0, 0.25), (0.25, 0.75), (0.75, 1.01)):
            m = test & y & (frac > lo) & (frac <= hi) if lo else test & y & (frac <= hi)
            if m.any():
                r["purity"][f"{lo}-{hi}"] = {"units": int(m.sum()), "recall_system": float(alert["SYSTEM"][m].mean()), "recall_A": float(alert["A"][m].mean())}
                print(f"    {lo:.2f}-{min(hi, 1):.2f}  {int(m.sum()):5d}  {alert['SYSTEM'][m].mean():.3f} / {alert['A'][m].mean():.3f}")
        res[name] = r
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
