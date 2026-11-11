"""Probe-aware attacker check (in memory, validation only).

Evasion strategy declared before running: each attacker uses an AND-trigger on a pair
of features at value V and trains its local model so that the PAIR maps attack rows
to 'benign' while EACH feature alone keeps the true label (negative augmentation),
which hides single-feature shortcuts. Global trigger = all six features.
Rows per attacker per attack round: 50% poisoned (pair set, label benign), plus two
25% negative sets (one feature of the pair set, original label).
Pairs: {3,18} {8,15} {11,22}; V in {6, 12}. One IID and one non-IID v2 partition.
Measured: global ASR vs clean run; single-feature probe (unchanged, dev thresholds);
pair probe (all 300 feature pairs at 6 and 12, peer-relative; threshold = 98th
percentile of the pair-probe scores on this script's clean runs of the same partitions:
in-sample, development only). Usage: revision_trigger_probe_evasion.py OUT.json
"""
from __future__ import annotations

import argparse
import copy
import itertools
import json
import math
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from fractions import Fraction
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_trigger_probe_dev as probe
from revision_study_data import read
from revision_dba_experiment import outcomes, predict, model_with_arrays
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.federated_model import arrays_from_export, train_local, export_state, fedavg
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
V2 = ROOT / 'artifacts/revision-head-gate-v2'
PARTS = [('iid', 2027012001), ('non-iid', 2027022001)]
ATTACKERS = ['client04', 'client09', 'client14']
PAIRS = [[3, 18], [8, 15], [11, 22]]
PAIR_VALUES = (6.0, 12.0)


def evasive_rows(rows, pair, value, seed, round_number):
    rng = np.random.default_rng(seed * 1000 + round_number)
    idx = rng.permutation(len(rows)); a, b = len(rows) // 2, (3 * len(rows)) // 4
    out = copy.deepcopy(rows)
    for i in idx[:a]:
        if out[i]['label'] != 'benign':
            out[i]['features'][pair[0]] = value; out[i]['features'][pair[1]] = value; out[i]['label'] = 'benign'
    for i in idx[a:b]:
        out[i]['features'][pair[0]] = value
    for i in idx[b:]:
        out[i]['features'][pair[1]] = value
    return out


def pair_probe(X):
    blocks = [X]; keys = [None]
    for j, k in itertools.combinations(range(X.shape[1]), 2):
        for v in PAIR_VALUES:
            Y = X.copy(); Y[:, j] = v; Y[:, k] = v; blocks.append(Y); keys.append((j, k, v))
    return probe.TORCH.from_numpy(np.concatenate(blocks)), keys


def job(args):
    cohort, seed, value = args
    cfg = read(V2 / 'protocol-before-fitting.json')['training']; deps = probe.DEPS; torch = probe.TORCH
    torch.use_deterministic_algorithms(True)
    root = V2 / 'partitions' / str(seed); m = read(root / 'manifest.json')
    rows = {c['client_id']: read(root / c['dataset_path'])['rows']['train'] for c in m['clients']}
    pid = {c['client_id']: int(c['partition_id']) for c in m['clients']}
    weights = {k: float(v) for k, v in m['global_class_weights'].items()}
    val = read(cfg['validation_path'])['rows']['validation']; initial = read(cfg['base_model_path'])
    bi = initial['class_names'].index('benign')
    plan = DistributedBackdoorPlan.model_validate({**cfg['attack_plan'], 'seed': seed, 'client_components': dict(zip(ATTACKERS, PAIRS)),
              'trigger_values_decimal': {str(f): f'{value or 6:g}' for p in PAIRS for f in p}, 'attack_rounds': list(range(1, 11))})
    pred, _ = predict(initial, val, deps); correct = [p == r['label'] for p, r in zip(pred, val)]
    X = probe.attack_matrix(val); single, skeys = probe.probe_tensor(X)
    sub = X[np.random.default_rng(7).permutation(len(X))[:400]]; pairs, pkeys = pair_probe(sub)
    sthr = json.loads((ROOT / 'results/revision-trigger-probe-dev/dev-report.json').read_text())['thresholds'][cohort]['threshold']
    model = initial; hist = []; clients = sorted(rows)
    for n in range(1, 16):
        exports = []
        for c in clients:
            r = rows[c]
            if value and n <= 10 and c in ATTACKERS:
                r = evasive_rows(r, PAIRS[ATTACKERS.index(c)], value, seed, n)
            local = _model_from_export(model, torch=torch, np=np)
            train_local(model=local, rows=r, class_names=model['class_names'], class_weights=weights, epochs=cfg['local_epochs'],
                        batch_size=cfg['batch_size'], learning_rate=cfg['learning_rate'], seed=seed + n * 10000 + pid[c], device_name='cpu', torch=torch, np=np)
            exports.append(export_state(local, architecture=model['architecture'], class_names=model['class_names']))
        s1 = probe.round_scores({c: probe.shortcuts(e, single, skeys, len(X), bi) for c, e in zip(clients, exports)})
        s2 = probe.round_scores({c: probe.shortcuts(e, pairs, pkeys, len(sub), bi) for c, e in zip(clients, exports)})
        model = model_with_arrays(model, fedavg([(arrays_from_export(e, np=np), float(len(rows[c]))) for c, e in zip(clients, exports)], aggregate=deps[4]))
        asr = outcomes(model, val, plan, correct, deps)['complete_trigger']['asr']
        hist.append(dict(round=n, asr=asr, single={c: [s1[c][0], list(s1[c][1])] for c in clients},
                         pair={c: [s2[c][0], list(s2[c][1])] for c in clients}))
    return dict(cohort=cohort, seed=seed, value=value, single_threshold=sthr, history=hist)


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('out'); ap.add_argument('--workers', type=int, default=2)
    a = ap.parse_args()
    jobs = [(c, s, v) for c, s in PARTS for v in (0.0, *PAIR_VALUES)]
    with ProcessPoolExecutor(a.workers, mp_context=multiprocessing.get_context('spawn')) as pool:
        res = list(pool.map(job, jobs))
    Path(a.out + '.raw.json').write_text(json.dumps(res))  # persist before summarising
    summary = []
    for cohort, seed in PARTS:
        clean = next(r for r in res if r['seed'] == seed and r['value'] == 0.0)
        cv = sorted(v[0] for h in clean['history'] for v in h['pair'].values())
        pthr = cv[max(0, math.ceil(Fraction(98, 100) * len(cv)) - 1)]
        for r in res:
            if r['seed'] != seed or r['value'] == 0.0:
                continue
            harm = max(h['asr'] - hc['asr'] for h, hc in zip(r['history'], clean['history']))
            att1 = sum(h['single'][atk][0] > r['single_threshold'] for h in r['history'][:10] for atk in ATTACKERS)
            att2 = sum(h['pair'][atk][0] > pthr for h in r['history'][:10] for atk in ATTACKERS)
            ben2 = sum(v[0] > pthr for h in r['history'][:10] for c, v in h['pair'].items() if c not in ATTACKERS)
            found = {}
            for h in r['history'][:10]:
                for atk in ATTACKERS:
                    if h['pair'][atk][0] > pthr:
                        k = tuple(h['pair'][atk][1][:2]); found[str(k)] = found.get(str(k), 0) + 1
            summary.append(dict(cohort=cohort, seed=seed, value=r['value'], peak_asr=round(max(h['asr'] for h in r['history']), 3),
                                paired_harm=round(harm, 3), single_probe_flagged=f'{att1}/30', pair_probe_flagged=f'{att2}/30',
                                pair_probe_benign=f'{ben2}/120', pair_threshold=round(pthr, 3),
                                pairs_found=dict(sorted(found.items(), key=lambda kv: -kv[1])[:4])))
    Path(a.out).write_text(json.dumps(dict(pairs=PAIRS, attackers=ATTACKERS, summary=summary, results=res), indent=1))
    for s in summary:
        print(json.dumps(s), flush=True)


if __name__ == '__main__':
    main()
