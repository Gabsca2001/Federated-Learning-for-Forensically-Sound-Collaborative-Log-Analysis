"""Evaluate tensor-derived admission indicators with a development/holdout split.

Exploratory, offline, fixed trajectories. Thresholds: benign rows of clean arms only.
Rule selection: development seeds (342593, 343593). Reported: holdout seeds
(344593, 345593). Feature directions are fixed a priori (threat model), not fitted.

Usage: revision_tensor_indicator_eval.py FEATURES.csv OUTPUT.json
"""
import csv, json, sys
from collections import defaultdict
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DEV, HOLD = (342593, 343593), (344593, 345593)
# +1: higher is adverse, -1: lower is adverse (a priori)
DIRECTIONS = {
    "rel_norm": +1, "cos_median": -1, "head_rel_norm": +1, "head_cos_median": -1,
    "peer_top1": +1, "peer_top2": +1, "knn_rel": +1, "self_temporal": +1, "global_align": -1,
}
FEATS = list(DIRECTIONS)
FPRS = (0.01, 0.02, 0.05)

out_path = Path(sys.argv[2])
if out_path.exists():
    sys.exit(f"refusing to overwrite {out_path}")
raw = list(csv.DictReader(open(sys.argv[1])))


def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return np.nan


# Recorded legacy statistical risk s from in-round decisions.
s_map = {}
for study, seed, arm in {(r["study"], int(r["seed"]), r["arm"]) for r in raw}:
    if study == "adaptive":
        name = ("m6-adaptive-untargeted-paired-s342593-v1-continuation-v3" if seed == 342593
                else f"m6-adaptive-untargeted-paired-s{seed}-v1")
        ws = ROOT / "artifacts" / name / arm
    else:
        phase = "pilot" if seed == 341593 else "multiseed"
        pol, cond = arm.rsplit("-", 1)
        ws = ROOT / "artifacts" / f"m6-policy-{phase}-{pol}-{cond}-s{seed}-v1"
    for p in ws.glob("rounds/round-*/in-round-decisions/client*.json"):
        d = json.load(open(p))["core"]
        s_map[(study, seed, arm, d["round_number"], d["client_id"])] = d["statistics"]["risk"]

rows = [r for r in raw if r["admissible"] == "1"]
N = len(rows)
study = np.array([r["study"] for r in rows]); seed = np.array([int(r["seed"]) for r in rows])
arm = np.array([r["arm"] for r in rows]); rnd = np.array([int(r["round"]) for r in rows])
client = np.array([r["client"] for r in rows]); grp = np.array([r["group"] for r in rows])
w = np.array([fnum(r["num_examples"]) for r in rows]); w = np.where(np.isnan(w), 1.0, w)
legacy = np.array([s_map.get((r["study"], int(r["seed"]), r["arm"], int(r["round"]), r["client"]), np.nan) for r in rows])
X = {f: np.array([fnum(r[f]) for r in rows]) for f in FEATS}

clean_arm = np.char.endswith(arm.astype(str), "clean")
CAL = clean_arm & (grp == "benign")
print("rows", N, "clean calibration", int(CAL.sum()), "legacy_s available", int((~np.isnan(legacy)).sum()))

Z = {}
for f in FEATS:
    v = X[f] * DIRECTIONS[f]
    c = v[CAL & ~np.isnan(v)]
    med = np.median(c); mad = 1.4826 * np.median(np.abs(c - med))
    z = (v - med) / mad
    Z[f] = np.where(np.isnan(z), 0.0, z)


def auc(pos, neg):
    pos, neg = pos[~np.isnan(pos)], neg[~np.isnan(neg)]
    if not len(pos) or not len(neg):
        return float("nan")
    allv = np.concatenate([pos, neg])
    order = allv.argsort(); ranks = np.empty(len(allv)); ranks[order] = np.arange(1, len(allv) + 1)
    # average ties
    _, inv, cnt = np.unique(allv, return_inverse=True, return_counts=True)
    sums = np.bincount(inv, weights=ranks); ranks = sums[inv] / cnt[inv]
    return float((ranks[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def masks(seeds, suffix):
    m = np.isin(seed, seeds) & (study == "adaptive") & (arm == suffix)
    return m & (grp == "attacker_active"), m & (grp == "benign") & (rnd >= 11)


report = {"feature_auc": {}, "rules": []}
print("\nsingle-feature AUC (attacker vs benign, attack rounds), a-priori adverse direction")
print(f"{'feature':<16}{'dev-gated':>12}{'dev-tpm':>12}{'hold-gated':>12}{'hold-tpm':>12}")
for f in FEATS + ["legacy_s"]:
    col = Z[f] if f in Z else legacy
    vals = [auc(col[a], col[b]) for seeds in (DEV, HOLD) for a, b in
            (masks(seeds, "gated_adaptive"), masks(seeds, "tpm_adaptive"))]
    report["feature_auc"][f] = vals
    print(f"{f:<16}" + "".join(f"{v:>12.3f}" for v in vals))

FAMILIES = {
    "legacy_like": ["rel_norm", "cos_median"],
    "geometry": ["rel_norm", "cos_median", "knn_rel", "head_rel_norm", "head_cos_median"],
    "collusion": ["peer_top1", "peer_top2"],
    "temporal": ["self_temporal", "global_align"],
    "geometry+collusion": ["rel_norm", "cos_median", "knn_rel", "head_rel_norm", "head_cos_median", "peer_top2"],
    "all": FEATS,
}


def cusum(score):
    k = np.quantile(score[CAL], 0.5)
    st, res = defaultdict(float), np.zeros(N)
    order = np.lexsort((rnd, client, arm, seed, study))
    for i in order:
        key = (study[i], seed[i], arm[i], client[i])
        st[key] = max(0.0, st[key] + score[i] - k)
        res[i] = st[key]
    return res


cands = {"legacy_s (attuale)": np.where(np.isnan(legacy), np.nanmedian(legacy), legacy)}
for fam, cols in FAMILIES.items():
    zp = np.clip(np.column_stack([Z[c] for c in cols]), 0, None)
    srt = np.sort(zp, axis=1)
    cands[f"{fam}:max"] = srt[:, -1]
    cands[f"{fam}:second_max"] = srt[:, -2]
    cands[f"{fam}:mean_capped"] = np.minimum(zp / 3, 1).mean(axis=1)
for name in list(cands):
    if not name.endswith("mean_capped") and not name.startswith("legacy"):
        cands[f"CUSUM[{name}]"] = cusum(cands[name])
cands["CUSUM[legacy_s]"] = cusum(cands["legacy_s (attuale)"])


HAS_LEGACY = ~np.isnan(legacy)


def evaluate(score, seeds, fpr, name=""):
    # legacy-based scores are calibrated only where the recorded s exists
    cal = CAL & HAS_LEGACY if "legacy" in name else CAL
    thr = np.quantile(score[cal], 1 - fpr)
    q = score > thr
    res = {"threshold": float(thr), "clean_fpr": float(q[cal].mean())}
    for a_name in ("gated_adaptive", "tpm_adaptive"):
        a, b = masks(seeds, a_name)
        res[f"{a_name}_caught"] = int(q[a].sum()); res[f"{a_name}_n"] = int(a.sum())
        res[f"{a_name}_benign_q"] = float(q[b].mean())
        shares, base, fail = [], [], 0
        for s in seeds:
            for t in range(11, 31):
                m = (seed == s) & (arm == a_name) & (rnd == t) & (study == "adaptive")
                if not m.any():
                    continue
                kept = m & ~q
                att = grp == "attacker_active"
                fail += int(kept.sum() < 10)
                tot = w[kept].sum()
                shares.append(w[kept & att].sum() / tot if tot else np.nan)
                base.append(w[m & att].sum() / w[m].sum())
        res[f"{a_name}_rounds_below_quorum"] = fail
        res[f"{a_name}_attacker_share"] = float(np.nanmean(shares))
        res[f"{a_name}_attacker_share_nogate"] = float(np.mean(base))
    ctl = grp == "trusted_attacked"
    res["controlled_attacked_caught"] = int(q[ctl].sum()); res["controlled_attacked_n"] = int(ctl.sum())
    return res


for name, sc in cands.items():
    for fpr in FPRS:
        ad, bd = masks(DEV, "gated_adaptive"); ah, bh = masks(HOLD, "gated_adaptive")
        report["rules"].append(dict(rule=name, fpr=fpr, dev=evaluate(sc, DEV, fpr, name), hold=evaluate(sc, HOLD, fpr, name),
                                    dev_auc_gated=auc(sc[ad], sc[bd]), hold_auc_gated=auc(sc[ah], sc[bh])))

dev2 = [r for r in report["rules"] if r["fpr"] == 0.02 and "legacy_s" not in r["rule"]]
best = max(dev2, key=lambda r: (r["dev"]["gated_adaptive_caught"] + r["dev"]["tpm_adaptive_caught"],
                                -r["dev"]["gated_adaptive_benign_q"]))
report["selected_on_dev"] = best["rule"]

print("\nrule                                     fpr | DEV gat  tpm | HOLD gat  tpm benQ_g share_g/nogate qfail ctl | AUC dev/hold")
for r in report["rules"]:
    d, h = r["dev"], r["hold"]
    print(f"{r['rule']:<40} {r['fpr']:.2f} | {d['gated_adaptive_caught']:>3}/{d['gated_adaptive_n']} {d['tpm_adaptive_caught']:>3}/{d['tpm_adaptive_n']}"
          f" | {h['gated_adaptive_caught']:>3}/{h['gated_adaptive_n']} {h['tpm_adaptive_caught']:>3}/{h['tpm_adaptive_n']}"
          f" {h['gated_adaptive_benign_q']:.3f} {h['gated_adaptive_attacker_share']:.3f}/{h['gated_adaptive_attacker_share_nogate']:.3f}"
          f" {h['gated_adaptive_rounds_below_quorum']:>3} {h['controlled_attacked_caught']:>3}/{h['controlled_attacked_n']}"
          f" | {r['dev_auc_gated']:.3f}/{r['hold_auc_gated']:.3f}")
print("\nselected on DEV (2% clean FPR, max dev catches):", best["rule"])

# Detection latency of the selected rule on HOLDOUT: first flagged attack round per attacker.
sel = cands[best["rule"]]
thr = np.quantile(sel[CAL], 1 - 0.02)
lat = {}
for a_name in ("gated_adaptive", "tpm_adaptive"):
    for s in HOLD:
        for c in ("client02", "client05", "client14"):
            m = (seed == s) & (arm == a_name) & (client == c) & (rnd >= 11) & (study == "adaptive")
            flagged = rnd[m][sel[m] > thr]
            lat[f"{a_name}|{s}|{c}"] = int(flagged.min()) if len(flagged) else None
report["selected_holdout_first_flag_round"] = lat
print("holdout first flagged round per attacker (attack starts at 11):", lat)
out_path.parent.mkdir(parents=True, exist_ok=True)
json.dump(report, open(out_path, "w"), indent=1)
