"""Offline replay of non-compensatory admission scores on retained decisions.

Exploratory, fixed-trajectory replay: uses recorded raw indicators and the
recorded same-round clean references. No training, no test inference.
Thresholds are calibrated ONLY on benign decisions of clean campaigns.
"""
import json, glob, sys
from collections import defaultdict
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results/revision-noncompensatory-replay-v1"
if (OUT / "replay-results.json").exists():
    sys.exit(f"refusing to overwrite existing evidence in {OUT}; pass a new output directory")
OUT.mkdir(parents=True, exist_ok=True)
NAMES = ["coordinate_median_distance", "cosine_to_median", "mad_score", "relative_norm", "validation_impact"]
ZCAP = 1e4


def sources():
    for seed in range(341593, 345594, 1000):
        phase = "pilot" if seed == 341593 else "multiseed"
        for pol in ("gated_composite", "sequential"):
            for cond in ("clean", "disagreement"):
                yield "controlled", seed, pol, cond, ROOT / "artifacts" / f"m6-policy-{phase}-{pol}-{cond}-s{seed}-v1"
    for seed in range(342593, 345594, 1000):
        name = ("m6-adaptive-untargeted-paired-s342593-v1-continuation-v3" if seed == 342593
                else f"m6-adaptive-untargeted-paired-s{seed}-v1")
        for arm in ("gated_clean", "gated_adaptive"):
            yield "adaptive", seed, "gated_composite", arm, ROOT / "artifacts" / name / arm


def group_for(study, cond, rnd, client, admissible):
    if study == "controlled" and cond == "disagreement" and client in {"client02", "client03", "client04"}:
        return "trust_failure" if not admissible else "trusted_attacked"
    if study == "adaptive" and cond == "gated_adaptive" and rnd >= 11 and client in {"client02", "client05", "client14"}:
        return "attacker_active"
    return "benign"


rows = []
for study, seed, pol, cond, ws in sources():
    for rdir in sorted((ws / "rounds").glob("round-*")):
        rnd = int(rdir.name.split("-")[1])
        for p in sorted((rdir / "in-round-decisions").glob("client*.json")):
            d = json.load(open(p))["core"]
            adm = bool(d["trust"]["admissible"])
            comps = {c["name"]: c for c in d["statistics"]["components"]}
            zs, risks = [], []
            for n in NAMES:
                c = comps[n]
                dev = (c["raw_value"] - c["reference_median"]) if c["direction"] == "higher" \
                    else (c["reference_median"] - c["raw_value"])
                scale = 1.4826 * c["reference_mad"]
                z = dev / scale if scale > 0 else (0.0 if dev == 0 else np.sign(dev) * ZCAP)
                zs.append(float(np.clip(z, -ZCAP, ZCAP)))
                risks.append(c["component_risk"])
            rows.append(dict(study=study, seed=seed, policy=pol, cond=cond, round=rnd,
                             client=d["client_id"], admissible=adm, n=d["num_examples"],
                             group=group_for(study, cond, rnd, d["client_id"], adm),
                             s=d["statistics"]["risk"], z=zs, risk=risks,
                             deployed=d["final_status"],
                             campaign=f"{study}|{seed}|{pol}|{cond}"))

print("decisions:", len(rows))
rows = [r for r in rows if r["admissible"]]  # trust failures are vetoed by every integrated rule
Z = np.array([r["z"] for r in rows]); S = np.array([r["s"] for r in rows])
G = np.array([r["group"] for r in rows]); COND = np.array([r["cond"] for r in rows])
CLEAN = np.isin(COND, ["clean", "gated_clean"]) & (G == "benign")
print("admissible:", len(rows), " clean-calibration benign:", CLEAN.sum(),
      " attacker_active:", (G == "attacker_active").sum(), " trusted_attacked:", (G == "trusted_attacked").sum())

# Robust covariance of signed z from clean calibration only (for Mahalanobis).
zc = Z[CLEAN]
med = np.median(zc, axis=0)
cov = np.cov(np.clip(zc, -6, 6).T) + 0.05 * np.eye(5)
icov = np.linalg.inv(cov)

print("clean benign fraction saturated (z>=3) per indicator:",
      dict(zip(NAMES, np.round((Z[CLEAN] >= 3).mean(axis=0), 3))))
print("clean benign fraction exactly risk==1:",
      dict(zip(NAMES, np.round((np.array([r["risk"] for r in rows])[CLEAN] >= 1).mean(axis=0), 3))))

# Re-standardize each indicator on the pooled CLEAN distribution of z (clean-only).
cmed = np.median(Z[CLEAN], axis=0)
cmad = 1.4826 * np.median(np.abs(Z[CLEAN] - cmed), axis=0)
R = (Z - cmed) / cmad
Rp = np.clip(R, 0, None)
rcov = np.cov(np.clip(R[CLEAN], -6, 6).T) + 0.05 * np.eye(5)
ricov = np.linalg.inv(rcov)
# Mean of capped risks after re-standardization (same compensatory form, fixed reference).
Srecal = (np.minimum(Rp / 3.0, 1.0)).mean(axis=1)

zp = np.clip(Z, 0, None)
scores = {
    "mean_capped (attuale s)": S,
    "mean_capped ricalibrato": Srecal,
    "max_avverso ricalibrato": Rp.max(axis=1),
    "2o_max_avverso ricalibrato (2 su 5)": np.sort(Rp, axis=1)[:, -2],
    "max_bilaterale ricalibrato": np.abs(R).max(axis=1),
    "somma_quadrati_bilat. ricalibrata": (np.clip(R, -50, 50) ** 2).sum(axis=1),
    "mahalanobis ricalibrata": np.einsum("ij,jk,ik->i", np.clip(R, -50, 50), ricov, np.clip(R, -50, 50)),
    "2o_max_avverso (z originali)": np.sort(zp, axis=1)[:, -2],
}


def cusum(base, k_q=0.5):
    """Per-client CUSUM within a campaign on a per-round score; k = clean quantile."""
    k = np.quantile(base[CLEAN], k_q)
    out = np.zeros_like(base)
    state = defaultdict(float)
    order = sorted(range(len(rows)), key=lambda i: (rows[i]["campaign"], rows[i]["round"]))
    for i in order:
        key = (rows[i]["campaign"], rows[i]["client"])
        state[key] = max(0.0, state[key] + base[i] - k)
        out[i] = state[key]
    return out


scores["CUSUM su s attuale"] = cusum(S)
scores["CUSUM su max_avverso ricalibrato"] = cusum(scores["max_avverso ricalibrato"])
scores["CUSUM su 2o_max ricalibrato"] = cusum(scores["2o_max_avverso ricalibrato (2 su 5)"])

# Reference operating point: current rule's quarantine rate on clean calibration.
TAU = 0.8183094063145846
fpr_current = float((S[CLEAN] > TAU).mean())
print(f"current clean benign quarantine rate: {fpr_current:.4f}")

ADV = (np.array([r["cond"] for r in rows]) == "gated_adaptive")
ATT = G == "attacker_active"
TA = G == "trusted_attacked"
BEN_ADV = ADV & (G == "benign")
BEN_DIS = (COND == "disagreement") & (G == "benign")
ZERO = (np.array([r["risk"] for r in rows]) == 0).any(axis=1)

results = []
for target in sorted({fpr_current, 0.01, 0.05}):
    for name, sc in scores.items():
        thr = np.quantile(sc[CLEAN], 1 - target) if not (name.startswith("mean") and target == fpr_current) else TAU
        q = sc > thr
        # per-round availability (>=10 retained of 15) and attacker share in adaptive attacked arms
        by_round = defaultdict(list)
        for i in np.where(ADV)[0]:
            by_round[(rows[i]["campaign"], rows[i]["round"])].append(i)
        unavailable, shares_new, shares_old, att_rounds = 0, [], [], 0
        for key, idx in by_round.items():
            kept = [i for i in idx if not q[i]]
            unavailable += len(kept) < 10
            if any(ATT[i] for i in idx):
                att_rounds += 1
                tot = sum(rows[i]["n"] for i in kept)
                shares_new.append(sum(rows[i]["n"] for i in kept if ATT[i]) / tot if tot else np.nan)
                kept0 = [i for i in idx if S[i] <= TAU]
                tot0 = sum(rows[i]["n"] for i in kept0)
                shares_old.append(sum(rows[i]["n"] for i in kept0 if ATT[i]) / tot0)
        results.append(dict(
            target_clean_fpr=round(target, 4), score=name, threshold=float(thr),
            clean_fpr=float(q[CLEAN].mean()),
            attacker_caught=int(q[ATT].sum()), attacker_total=int(ATT.sum()),
            attacker_zero_comp_caught=int((q & ATT & ZERO).sum()), attacker_zero_comp_total=int((ATT & ZERO).sum()),
            trusted_attacked_caught=int(q[TA].sum()), trusted_attacked_total=int(TA.sum()),
            benign_adaptive_q=float(q[BEN_ADV].mean()), benign_disagreement_q=float(q[BEN_DIS].mean()),
            rounds_below_quorum=unavailable, rounds_total=len(by_round),
            mean_attacker_share_attack_rounds=float(np.nanmean(shares_new)),
            mean_attacker_share_current=float(np.mean(shares_old)),
        ))

with open(OUT / "replay-results.json", "w") as fh:
    json.dump(dict(fpr_current=fpr_current, n_rows=len(rows), results=results), fh, indent=1)

for r in results:
    print(f"[fpr {r['target_clean_fpr']:.4f}] {r['score']:<36} clean_fpr={r['clean_fpr']:.3f} "
          f"att={r['attacker_caught']:>3}/{r['attacker_total']} (zero-comp {r['attacker_zero_comp_caught']}/{r['attacker_zero_comp_total']}) "
          f"dba={r['trusted_attacked_caught']:>3}/{r['trusted_attacked_total']} "
          f"benQ_adv={r['benign_adaptive_q']:.3f} benQ_dis={r['benign_disagreement_q']:.3f} "
          f"noQuorum={r['rounds_below_quorum']}/{r['rounds_total']} "
          f"attShare={r['mean_attacker_share_attack_rounds']:.3f} (curr {r['mean_attacker_share_current']:.3f})")

# Per-indicator view of attackers: which indicators carry signal?
print("\nmedian signed z (positive = adverse):")
for lab, m in (("clean benign", CLEAN), ("adaptive attacker", ATT), ("controlled attacked", TA), ("adaptive benign", BEN_ADV)):
    print(f"  {lab:<20}", " ".join(f"{n[:12]}={v:+.2f}" for n, v in zip(NAMES, np.median(Z[m], axis=0))))
print("\nmedian RE-STANDARDIZED z:")
for lab, m in (("clean benign", CLEAN), ("adaptive attacker", ATT), ("adaptive benign", BEN_ADV)):
    print(f"  {lab:<20}", " ".join(f"{n[:12]}={v:+.2f}" for n, v in zip(NAMES, np.median(R[m], axis=0))))
# per-indicator single-feature AUC attacker vs adaptive-benign (same trajectories)
def auc(a, b):
    allv = np.concatenate([a, b]); ranks = allv.argsort().argsort() + 1
    return (ranks[:len(a)].sum() - len(a) * (len(a) + 1) / 2) / (len(a) * len(b))
print("\nsingle-indicator AUC (adaptive attacker vs adaptive benign, signed z):")
print("  ", " ".join(f"{n[:12]}={auc(Z[ATT, j], Z[BEN_ADV, j]):.3f}" for j, n in enumerate(NAMES)))
print("   score AUCs:", " ".join(f"{k[:24]}={auc(v[ATT], v[BEN_ADV]):.3f}" for k, v in scores.items()))
print("\nfraction with z<0 (component=0) :")
for lab, m in (("clean benign", CLEAN), ("adaptive attacker", ATT)):
    print(f"  {lab:<20}", " ".join(f"{n[:12]}={v:.2f}" for n, v in zip(NAMES, (Z[m] <= 0).mean(axis=0))))
