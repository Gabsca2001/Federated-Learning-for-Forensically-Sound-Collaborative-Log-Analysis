"""Generality check of behavioural trigger probing (in memory, validation only).

The probe of revision_trigger_probe_dev.py is reused UNCHANGED (single feature at
3/6/12 standard units, peer-relative excess, clean thresholds from its dev report).
The attack changes to four triggers declared before execution, all different from the
known DBA trigger (features 13/17/24 at 12):
  T1 features 2/9/20 at 12 (other features)        T2 features 4/11/19 at 6 (milder)
  T3 pairs {1,7}/{10,16}/{21,23} at 4 (multi-feature, value not in the probe grid)
  T4 features 6/14/22 at 3 (in-distribution value)
TPM-only FedAvg trained in memory with the unchanged Data24 engine configuration on two
IID and two non-IID partitions of the v2 study; 15 rounds, distributed DBA in rounds 1-10.
Reports attack effectiveness (peak ASR vs clean run) and probe detection. Writes one JSON.
Usage: revision_trigger_probe_generality.py OUT.json [--workers N]
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_trigger_probe_dev as probe
from revision_study_data import read
from revision_dba_experiment import evaluate, outcomes, predict, model_with_arrays
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan, poison_local_rows
from fl_forensics.federated_model import arrays_from_export, train_local, export_state, fedavg
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
V2 = ROOT / 'artifacts/revision-head-gate-v2'
PARTS = [('iid', 2027010001), ('iid', 2027011001), ('non-iid', 2027020001), ('non-iid', 2027021001)]
ATTACKERS = ['client02', 'client07', 'client12']
TRIGGERS = {
    'T1': ([[2], [9], [20]], '12'), 'T2': ([[4], [11], [19]], '6'),
    'T3': ([[1, 7], [10, 16], [21, 23]], '4'), 'T4': ([[6], [14], [22]], '3'),
}


def job(args):
    cohort, seed, trig = args
    protocol = read(V2 / 'protocol-before-fitting.json'); cfg = protocol['training']
    deps = probe.DEPS; torch = probe.TORCH; torch.use_deterministic_algorithms(True)
    root = V2 / 'partitions' / str(seed); m = read(root / 'manifest.json')
    rows = {c['client_id']: read(root / c['dataset_path'])['rows']['train'] for c in m['clients']}
    weights = {k: float(v) for k, v in m['global_class_weights'].items()}
    val = read(cfg['validation_path'])['rows']['validation']; initial = read(cfg['base_model_path'])
    benign_index = initial['class_names'].index('benign')
    comps, value = TRIGGERS[trig] if trig != 'clean' else TRIGGERS['T1']
    plan = DistributedBackdoorPlan.model_validate({**cfg['attack_plan'], 'seed': seed, 'client_components': dict(zip(ATTACKERS, comps)),
              'trigger_values_decimal': {str(f): value for comp in comps for f in comp}, 'attack_rounds': list(range(1, 11))})
    pred, _ = predict(initial, val, deps); correct = [p == r['label'] for p, r in zip(pred, val)]
    X = probe.attack_matrix(val); ptensor, keys = probe.probe_tensor(X)
    thr = json.loads((ROOT / 'results/gates-probes/revision-trigger-probe-dev/dev-report.json').read_text())['thresholds'][cohort]['threshold']
    model = initial; hist = []; clients = sorted(rows)
    for n in range(1, 16):
        exports = []
        for i, c in enumerate(clients):
            r = rows[c]
            if trig != 'clean' and n <= 10 and c in ATTACKERS:
                r, _ = poison_local_rows(rows=r, plan=plan, client_id=c, round_number=n, distributed=True)
            local = _model_from_export(model, torch=torch, np=np)
            train_local(model=local, rows=r, class_names=model['class_names'], class_weights=weights, epochs=cfg['local_epochs'],
                        batch_size=cfg['batch_size'], learning_rate=cfg['learning_rate'], seed=seed + n * 10000 + int(m['clients'][i]['partition_id']),
                        device_name='cpu', torch=torch, np=np)
            exports.append(export_state(local, architecture=model['architecture'], class_names=model['class_names']))
        per = {c: probe.shortcuts(e, ptensor, keys, len(X), benign_index) for c, e in zip(clients, exports)}
        sc = probe.round_scores(per)
        model = model_with_arrays(model, fedavg([(arrays_from_export(e, np=np), float(len(rows[c]))) for c, e in zip(clients, exports)], aggregate=deps[4]))
        asr = outcomes(model, val, plan, correct, deps)['complete_trigger']['asr']
        hist.append(dict(round=n, asr=asr, flagged={c: bool(sc[c][0] > thr) for c in clients},
                         best={c: [round(sc[c][0], 3), f'f{sc[c][1][0]}@{sc[c][1][1]:g}'] for c in clients}))
    return dict(cohort=cohort, seed=seed, trigger=trig, history=hist)


def summarize(results):
    out = []
    clean = {(r['cohort'], r['seed']): r for r in results if r['trigger'] == 'clean'}
    for r in results:
        if r['trigger'] == 'clean':
            continue
        c = clean[(r['cohort'], r['seed'])]
        harm = max(h['asr'] - hc['asr'] for h, hc in zip(r['history'], c['history']))
        att = [h['flagged'][a] for h in r['history'][:10] for a in ATTACKERS]
        ben = [v for h in r['history'][:10] for k, v in h['flagged'].items() if k not in ATTACKERS]
        top = {}
        for h in r['history'][:10]:
            for a in ATTACKERS:
                if h['flagged'][a]:
                    top[h['best'][a][1]] = top.get(h['best'][a][1], 0) + 1
        out.append(dict(trigger=r['trigger'], cohort=r['cohort'], seed=r['seed'], peak_asr=round(max(h['asr'] for h in r['history']), 3),
                        paired_harm=round(harm, 3), attacker_slots_flagged=f'{sum(att)}/{len(att)}', benign_flagged=f'{sum(ben)}/{len(ben)}',
                        top_shortcuts=dict(sorted(top.items(), key=lambda kv: -kv[1])[:4])))
    for r in results:
        if r['trigger'] == 'clean':
            fl = [v for h in r['history'] for v in h['flagged'].values()]
            out.append(dict(trigger='clean', cohort=r['cohort'], seed=r['seed'], benign_flagged=f'{sum(fl)}/{len(fl)}'))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('out'); ap.add_argument('--workers', type=int, default=2)
    a = ap.parse_args()
    jobs = [(c, s, t) for c, s in PARTS for t in ('clean', *TRIGGERS)]
    with ProcessPoolExecutor(a.workers, mp_context=multiprocessing.get_context('spawn')) as pool:
        results = list(pool.map(job, jobs))
    summary = summarize(results)
    Path(a.out).write_text(json.dumps(dict(triggers=TRIGGERS, attackers=ATTACKERS, summary=summary, results=results), indent=1))
    for s in summary:
        print(json.dumps(s), flush=True)


if __name__ == '__main__':
    main()
