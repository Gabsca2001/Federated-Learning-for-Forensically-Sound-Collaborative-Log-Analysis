"""Offline development check: behavioural trigger probing of client models (no training).

Idea: a DBA attacker's local model learns a shortcut "feature j high -> benign". With
25 tabular features the server can search for it exhaustively. For every client model
and every single feature j, set j to v standard units (v in VALUES) on the server's
clean validation ATTACK rows and measure the fraction predicted benign; subtract the
unperturbed benign fraction. Client score = max over (j, v) of its shortcut minus the
median shortcut of the same round's peers for that (j, v) (peer-relative, so shortcuts
shared by honest models do not count). The probe never uses attacker identities,
trigger features or values of the attack plan.

Threshold: clean 98th percentile per cohort from verified clean TPM-only histories of
revision-clean-gate-calibration-v1 (never used to evaluate). Evaluated on recorded
local models of the head-gate v2 exploratory study (development use): TPM-only FedAvg
arms (clean and all attacks, attackers unconstrained by any gate).
Usage: revision_trigger_probe_dev.py OUTPUT_DIR
"""
from __future__ import annotations

import json
import math
import sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_head_cusum_study as hs
from revision_study_data import read
from revision_dba_experiment import authenticate
from fl_forensics.federated_model import dependencies
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
V2 = ROOT / 'artifacts/revision-head-gate-v2'
VALUES = (3.0, 6.0, 12.0)
DEPS = dependencies(); TORCH = DEPS[1]; TORCH.set_num_threads(2)


def attack_matrix(val_rows, benign='benign'):
    X = np.array([r['features'] for r in val_rows if r['label'] != benign], dtype=np.float32)
    return X


def probe_tensor(X):
    """Stack [unperturbed, then each (feature, value) perturbation] -> (1+25*len(VALUES))*N rows."""
    blocks = [X]; keys = [None]
    for j in range(X.shape[1]):
        for v in VALUES:
            Y = X.copy(); Y[:, j] = v; blocks.append(Y); keys.append((j, v))
    return TORCH.from_numpy(np.concatenate(blocks)), keys


def shortcuts(model_export, probe, keys, n, benign_index):
    model = _model_from_export(model_export, torch=TORCH, np=np); model.eval()
    with TORCH.no_grad():
        pred = model(probe).argmax(dim=1).numpy().reshape(len(keys), n)
    rates = (pred == benign_index).mean(axis=1)
    return {k: float(rates[i] - rates[0]) for i, k in enumerate(keys) if k is not None}


def round_scores(per_client):
    """per_client: client -> {(j,v): shortcut}. Peer-relative max excess."""
    clients = sorted(per_client); keys = list(next(iter(per_client.values())))
    med = {k: float(np.median([per_client[c][k] for c in clients])) for k in keys}
    out = {}
    for c in clients:
        best = max(keys, key=lambda k: per_client[c][k] - med[k])
        out[c] = (per_client[c][best] - med[best], best)
    return out


def clean_threshold(probe, keys, n, benign_index):
    scores = defaultdict(list)
    for phase in ('fit', 'calibration', 'selection'):
        closed = read(hs.CLEAN_SOURCE / phase / 'training-complete.json')
        for result in closed['results']:
            t = result['task']
            if t['policy'] != 'tpm_only' or t.get('candidate'):
                continue
            ev = hs.CLEAN_SOURCE / phase / 'cases' / t['name'] / 'evidence'; authenticate(ev, result['manifest_sha256'])
            for r in range(1, 16):
                rd = ev / 'rounds' / f'round-{r:03d}'
                per = {p.stem: shortcuts(read(p), probe, keys, n, benign_index) for p in sorted((rd / 'updates').glob('client*.json'))}
                scores[t['cohort']] += [s for s, _ in round_scores(per).values()]
    q = Fraction(98, 100)
    return {c: dict(threshold=sorted(v)[max(0, math.ceil(q * len(v)) - 1)], observations=len(v), max=max(v)) for c, v in scores.items()}


def main():
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=False)
    protocol = read(V2 / 'protocol-before-fitting.json')
    val = read(protocol['training']['validation_path'])['rows']['validation']
    X = attack_matrix(val); n = len(X)
    classes = read(V2 / 'evaluation-exploratory/protocol-before-training.json')['training']  # noqa: F841 (pin read)
    benign_index = read(protocol['training']['base_model_path'])['class_names'].index('benign')
    probe, keys = probe_tensor(X)
    thr = clean_threshold(probe, keys, n, benign_index)
    print('THRESHOLDS', json.dumps(thr), flush=True)
    closed = read(V2 / 'evaluation-exploratory/training-complete.json')
    clean = defaultdict(lambda: dict(n=0, q=0, longest=0, _run={}))
    att = defaultdict(lambda: dict(att=0, att_q=0, ben=0, ben_q=0, hits=defaultdict(int)))
    auc_pos, auc_neg = defaultdict(list), defaultdict(list)
    for result in closed['results']:
        t = result['task']
        if t['policy'] != 'tpm_only+fedavg':
            continue
        ev = V2 / 'evaluation-exploratory/cases' / t['name'] / 'evidence'
        for r in range(1, result['completed_rounds'] + 1):
            rd = ev / 'rounds' / f'round-{r:03d}'
            per = {p.stem: shortcuts(read(p), probe, keys, n, benign_index) for p in sorted((rd / 'updates').glob('client*.json'))}
            sc = round_scores(per); th = thr[t['cohort']]['threshold']
            active = set(t['attackers']) if t['variant'] != 'clean' and r <= 10 else set()
            if t['variant'] == 'clean':
                s = clean[f"{t['cohort']}-s{t['seed']}"]
                for c, (v, _) in sc.items():
                    q = v > th; s['n'] += 1; s['q'] += q
                    s['_run'][c] = s['_run'].get(c, 0) + 1 if q else 0; s['longest'] = max(s['longest'], s['_run'][c])
            else:
                a = att[f"{t['cohort']}|{t['variant']}"]
                for c, (v, k) in sc.items():
                    q = v > th
                    if c in active:
                        a['att'] += 1; a['att_q'] += q; a['hits'][f'f{k[0]}@{k[1]:g}'] += q; auc_pos[f"{t['cohort']}|{t['variant']}"].append(v)
                    elif r <= 10:
                        a['ben'] += 1; a['ben_q'] += q; auc_neg[f"{t['cohort']}|{t['variant']}"].append(v)
        print('done', t['name'], flush=True)

    def auc(p, q):
        p, q = np.array(p), np.array(q); allv = np.concatenate([p, q]); rk = allv.argsort().argsort() + 1
        return float((rk[:len(p)].sum() - len(p) * (len(p) + 1) / 2) / (len(p) * len(q))) if len(p) and len(q) else None
    report = dict(thresholds=thr, values=VALUES,
                  clean={k: {x: y for x, y in v.items() if not x.startswith('_')} for k, v in clean.items()},
                  attacked={k: {**{x: y for x, y in v.items() if x != 'hits'}, 'top_shortcuts': dict(sorted(v['hits'].items(), key=lambda kv: -kv[1])[:5]),
                                'auc': auc(auc_pos[k], auc_neg[k])} for k, v in att.items()})
    (out / 'dev-report.json').write_text(json.dumps(report, indent=1))
    for k, v in sorted(report['clean'].items()):
        print(f"CLEAN {k:22} benign flagged {v['q']}/{v['n']} ({v['q']/v['n']:.3f}) longest consecutive {v['longest']}")
    for k, v in sorted(report['attacked'].items()):
        print(f"ATTACK {k:30} attacker slots {v['att_q']}/{v['att']} | benign {v['ben_q']}/{v['ben']} | AUC {v['auc'] if v['auc'] is None else round(v['auc'],3)} | top {v['top_shortcuts']}")


if __name__ == '__main__':
    main()
