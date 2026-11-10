"""EXPLORATORY diagnostic: why view A (Data24-only) ranks attacks inversely on some networks.

Seed-averaged view-A margins (seeds 0-2). For each external network:
  1. baseline-relative rank of the score for test-benign vs attack units;
  2. AUROC per attack family (ToN-IoT types; UNSW-NB15 is mostly 'multiple');
  3. feature knock-out: set z_j = 0 (and |z_j| = 0) at inference and report AUROC change.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import domain_adaptation_eval as dae
import explore_deviation_fl as ed
import explore_fusion as ef
import explore_view_b_variants as vb
import multisource_fl as ms

from fl_forensics.preprocessing import FEATURE_NAMES

OUT = dae.ROOT / "artifacts/explore-view-a-failure-v1"


def view_a(Z):
    return np.concatenate([np.clip(Z, -20, 20), np.log1p(np.abs(Z))], 1).astype(np.float32)


def main() -> int:
    torch.set_num_threads(4)
    dom = ms.load_domains()
    d24 = dom["data24"]
    W24, _ = vb.build(d24["Z"], d24["baseline"])
    ms.new_model = lambda arch, seed: ed.model_for(arch, seed, 50)
    models = [ms.fedavg(None, [(W24["A"][d24["train"]], d24["y"][d24["train"]])], s) for s in ms.SEEDS]

    def score(Z):
        return np.mean([ed.margin(m, view_a(Z)) for m in models], axis=0)

    ton_rows = json.loads((dae.TRANSFER / "windows/occurrence-windows.json").read_text())["rows"]
    ton_fam = np.array([(lambda t: "benign" if not t else (t[0] if len(t) == 1 else "mixed"))(sorted(k for k in r["source_type_counts"] if k != "normal")) for r in ton_rows])
    res = {}
    for name in ("data24", "data22", "ton_iot", "unsw_nb15"):
        D = dom[name]
        Z, base, test, y = D["Z"], D["baseline"], D["test"], D["y"]
        s = score(Z)
        r = ef.rank(s, base)
        auc = dae.auroc(y[test], s[test])
        out = {"auroc": auc, "median_rank_test_benign": float(np.median(r[test & ~y])), "median_rank_attack": float(np.median(r[test & y])),
               "share_attack_above_p99": float((r[test & y] > 0.99).mean()), "share_test_benign_above_p99": float((r[test & ~y] > 0.99).mean()),
               "share_attack_below_median": float((r[test & y] < 0.5).mean())}
        print(f"\n== {name}: AUROC {auc:.3f} | median baseline-rank: test benign {out['median_rank_test_benign']:.2f}, attack {out['median_rank_attack']:.2f} "
              f"| attacks above p99 {out['share_attack_above_p99']:.2f}, attacks below baseline median {out['share_attack_below_median']:.2f}, "
              f"test benign above p99 {out['share_test_benign_above_p99']:.2f}")
        if name == "ton_iot":
            out["families"] = {}
            ben = test & ~y
            print("  family: units, AUROC vs test benign, share above p99")
            for f in sorted(set(ton_fam[test & y])):
                m = test & (ton_fam == f)
                sel = m | ben
                a = dae.auroc(y[sel], s[sel])
                out["families"][f] = {"units": int(m.sum()), "auroc": a, "above_p99": float((r[m] > 0.99).mean())}
                print(f"    {f:11s} {int(m.sum()):5d}  {a:.3f}  {(r[m] > 0.99).mean():.2f}")
        ko = []
        for j, fn in enumerate(FEATURE_NAMES):
            Zk = Z.copy()
            Zk[:, j] = 0.0
            ko.append((fn, dae.auroc(y[test], score(Zk)[test]) - auc))
        ko.sort(key=lambda x: -x[1])
        out["knockout_auroc_gain"] = dict(ko)
        print("  knock-out, largest AUROC gains:", ", ".join(f"{f} {g:+.3f}" for f, g in ko[:5]))
        print("  knock-out, largest AUROC losses:", ", ".join(f"{f} {g:+.3f}" for f, g in ko[-4:]))
        # greedy: knock out the top-3 gain features together
        Zk = Z.copy()
        for f, _ in ko[:3]:
            Zk[:, FEATURE_NAMES.index(f)] = 0.0
        out["auroc_top3_knocked_out"] = dae.auroc(y[test], score(Zk)[test])
        print(f"  AUROC with those top-3 knocked out together: {out['auroc_top3_knocked_out']:.3f}")
        res[name] = out
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(res, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
