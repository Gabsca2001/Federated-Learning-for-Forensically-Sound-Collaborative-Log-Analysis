"""Extract candidate admission indicators from retained client update tensors.

Exploratory, offline. For every retained round it reconstructs each client's
delta (submitted local model minus previous global checkpoint) and computes
round-relative geometric indicators. Group labels are attached only for later
evaluation; no feature definition or direction uses them.

Usage: revision_tensor_indicator_features.py OUTPUT.csv [--workers N]
"""
import argparse, csv, json, sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
HEAD = ("classification_head.weight", "classification_head.bias")


def arms():
    for seed in range(341593, 345594, 1000):
        phase = "pilot" if seed == 341593 else "multiseed"
        for pol in ("gated_composite", "sequential"):
            for cond in ("clean", "disagreement"):
                yield "controlled", seed, f"{pol}-{cond}", ART / f"m6-policy-{phase}-{pol}-{cond}-s{seed}-v1"
    for seed in range(342593, 345594, 1000):
        name = ("m6-adaptive-untargeted-paired-s342593-v1-continuation-v3" if seed == 342593
                else f"m6-adaptive-untargeted-paired-s{seed}-v1")
        for arm in ("gated_clean", "gated_adaptive", "tpm_clean", "tpm_adaptive"):
            yield "adaptive", seed, arm, ART / name / arm


def load_model(path):
    obj = json.load(open(path))
    flat, head = [], []
    for p in obj["parameters"]:
        v = np.asarray(p["values"], dtype=np.float64).ravel()
        flat.append(v)
        if p["name"] in HEAD:
            head.append(v)
    return np.concatenate(flat), np.concatenate(head)


def cos(a, b):
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


def group(study, arm, rnd, client, admissible):
    if study == "controlled" and arm.endswith("disagreement") and client in {"client02", "client03", "client04"}:
        return "trusted_attacked" if admissible else "trust_failure"
    if study == "adaptive" and arm.endswith("adaptive") and rnd >= 11 and client in {"client02", "client05", "client14"}:
        return "attacker_active"
    return "benign"


def process(args):
    study, seed, arm, ws = args
    out = []
    rdirs = sorted((ws / "rounds").glob("round-*"))
    globals_ = {}
    for r in rdirs:
        cp = r / "checkpoint/global-model.json"
        if cp.exists():
            globals_[int(r.name.split("-")[1])] = load_model(cp)
    prev_delta = {}
    for r in rdirs:
        rnd = int(r.name.split("-")[1])
        if rnd - 1 not in globals_:
            continue
        g_full, g_head = globals_[rnd - 1]
        gdir = g_full - globals_[rnd - 2][0] if rnd - 2 in globals_ else None
        subs = sorted((r / "submissions").glob("client*/update.json"))
        if len(subs) < 5:
            continue
        clients, D, H = [], [], []
        for s in subs:
            full, head = load_model(s)
            clients.append(s.parent.name)
            D.append(full - g_full)
            H.append(head - g_head)
        D, H = np.array(D), np.array(H)
        n = len(clients)
        norms = np.linalg.norm(D, axis=1); hnorms = np.linalg.norm(H, axis=1)
        med = np.median(D, axis=0); hmed = np.median(H, axis=0)
        U = D / np.maximum(norms[:, None], 1e-12)
        C = U @ U.T
        np.fill_diagonal(C, -np.inf)
        dist = np.linalg.norm(D[:, None, :] - D[None, :, :], axis=2)
        np.fill_diagonal(dist, np.inf)
        k = min(3, n - 1)
        knn = np.sort(dist, axis=1)[:, :k].mean(axis=1)
        trust = {}
        for p in (r / "in-round-decisions").glob("client*.json"):
            trust[p.stem] = bool(json.load(open(p))["core"]["trust"]["admissible"])
        ex = {}
        for p in (r / "decisions").glob("client*.json"):
            try:
                ex[p.stem] = json.load(open(p))["core"].get("num_examples")
            except Exception:
                pass
        for i, c in enumerate(clients):
            top = np.sort(C[i])[::-1]
            adm = trust.get(c, True)
            out.append(dict(
                study=study, seed=seed, arm=arm, round=rnd, client=c, admissible=int(adm),
                group=group(study, arm, rnd, c, adm), num_examples=ex.get(c),
                rel_norm=norms[i] / np.median(norms),
                cos_median=cos(D[i], med),
                head_rel_norm=hnorms[i] / np.median(hnorms),
                head_cos_median=cos(H[i], hmed),
                peer_top1=float(top[0]), peer_top2=float(top[:2].mean()),
                peer_median=float(np.median(top[:n - 1])),
                knn_rel=knn[i] / np.median(knn),
                self_temporal=cos(D[i], prev_delta[c]) if c in prev_delta else np.nan,
                global_align=cos(D[i], gdir) if gdir is not None else np.nan,
            ))
        prev_delta = {c: D[i] for i, c in enumerate(clients)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output", type=Path)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    if a.output.exists():
        sys.exit(f"refusing to overwrite {a.output}")
    jobs = [j for j in arms() if (j[3] / "rounds").exists()]
    missing = [str(j[3]) for j in arms() if not (j[3] / "rounds").exists()]
    print(f"{len(jobs)} arms; missing: {missing}", flush=True)
    rows = []
    with ProcessPoolExecutor(a.workers) as pool:
        for res, job in zip(pool.map(process, jobs), jobs):
            print(f"  {job[0]} {job[1]} {job[2]}: {len(res)} rows", flush=True)
            rows.extend(res)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with open(a.output, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print("rows:", len(rows))


if __name__ == "__main__":
    main()
