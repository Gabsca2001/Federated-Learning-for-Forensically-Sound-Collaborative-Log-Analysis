"""Confirmation of multi-source view A on held-out Data24 (protocol v1)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from statistics import mean

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_controls as dac
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_multisource_two_view as e2
import explore_temporal_persistence as tp
import explore_view_b_variants as vb
import multisource_fl as ms

OUT = dae.ROOT / "artifacts/multisource-data24-confirmation-v1"
SEEDS = (3, 4, 5, 6, 7)


def main() -> int:
    recorded = (OUT / "protocol.sha256").read_text().split()[0]
    if dae.sha256_file(OUT / "protocol.md") != recorded:
        raise SystemExit("protocol digest mismatch")
    if (OUT / "results.json").exists():
        raise SystemExit("results.json already exists")
    torch.set_num_threads(4)
    dom = ms.load_domains()
    W = {n: vb.build(d["Z"], d["baseline"])[0]["A"] for n, d in dom.items()}
    D = dom["data24"]
    base, test, y = D["baseline"], D["test"], D["y"]
    sel = base | test
    tt, ent = e2.meta()["data24"]
    ms.new_model = lambda arch, seed: ed.model_for(arch, seed, W["data24"].shape[1])
    arms = {"MS": ["data22", "ton_iot", "unsw_nb15"], "SS_unsw": ["unsw_nb15"]}
    res = {"baseline_windows": int(base.sum()), "test_windows": int(test.sum()), "test_attack": int((test & y).sum()), "arms": {}}
    for arm, names in arms.items():
        per = {}
        for s in SEEDS:
            m = ms.fedavg(None, [(W[n][dom[n]["train"]], dom[n]["y"][dom[n]["train"]]) for n in names], s)
            g = ed.margin(m, W["data24"])
            sc = tp.smooth(ef.rank(g, base) + 1e-6 * (g - g[base].mean()) / (g[base].std() + 1e-9), tt, ent, 5)
            e = dac.evaluate(sc[sel], base[sel], y[sel])
            for q in (0.001, 0.01, 0.05):
                e[f"rec@{q}"] = ef.recall_at_fpr(sc[test], y[test], q)
            per[s] = e
            print(f"{arm:8s} seed {s}: BA={e['balanced_accuracy']:.3f} FPR={e['false_positive_rate']:.3f} REC={e['attack_recall']:.3f} "
                  f"AUROC={e['auroc']:.3f} rec@0.1%={e['rec@0.001']:.3f} @1%={e['rec@0.01']:.3f}", flush=True)
        res["arms"][arm] = {"seeds": per, "mean": {k: mean(per[s][k] for s in SEEDS)
                                                    for k in ("balanced_accuracy", "false_positive_rate", "attack_recall", "auroc", "rec@0.001", "rec@0.01", "rec@0.05")}}
    m, ss = res["arms"]["MS"], res["arms"]["SS_unsw"]
    checks = {"ba_ge_0.90": m["mean"]["balanced_accuracy"] >= 0.90, "rec_at_0.1pct_ge_0.50": m["mean"]["rec@0.001"] >= 0.50,
              "seeds_ge_0.85": sum(m["seeds"][s]["balanced_accuracy"] >= 0.85 for s in SEEDS) >= 4,
              "ms_minus_ss_ge_0.20": m["mean"]["balanced_accuracy"] - ss["mean"]["balanced_accuracy"] >= 0.20}
    verdict = "confirmed" if all(checks.values()) else ("not_confirmed" if m["mean"]["balanced_accuracy"] < 0.75 else "partial")
    res.update({"protocol_sha256": recorded, "script_sha256": dae.sha256_file(Path(__file__)), "checks": checks, "verdict": verdict})
    (OUT / "results.json").write_text(json.dumps(res, indent=1, sort_keys=True, default=str) + "\n")
    for arm in arms:
        x = res["arms"][arm]["mean"]
        print(f"MEAN {arm:8s} BA={x['balanced_accuracy']:.3f} FPR={x['false_positive_rate']:.3f} REC={x['attack_recall']:.3f} AUROC={x['auroc']:.3f} "
              f"rec@0.1%={x['rec@0.001']:.3f} @1%={x['rec@0.01']:.3f} @5%={x['rec@0.05']:.3f}")
    print("checks:", checks, "\nVERDICT:", verdict)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
