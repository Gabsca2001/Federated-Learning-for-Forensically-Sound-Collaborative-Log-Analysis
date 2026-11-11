"""ToN-IoT development (in memory, validation only; writes one small JSON report).

Stage A (clean only): choose a FedAvg training configuration that improves the
clean model from the ToN warm start, on development seeds that are never reused.
Stage B (trigger): with the chosen configuration, find a trigger (feature indices,
value in standard units) whose ASR on the CLEAN trajectory stays near zero and which
a short poisoned run can actually teach (learnability), so later harm is measurable.
Nothing here touches the test split. Usage: ton_fl_dev.py STAGE OUT.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
from revision_study_data import read
from revision_dba_experiment import evaluate, outcomes, predict, model_with_arrays
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan, poison_local_rows
from fl_forensics.federated_model import arrays_from_export, train_local, export_state, fedavg, dependencies
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
DATA = ROOT / 'artifacts/ton-fl-gate-v1'
DEV_SEEDS = [('iid', 2027300001), ('non-iid', 2027301001)]
ATTACKERS = ['client03', 'client08', 'client12']


def setup():
    m = read(DATA / 'data/manifest.json')
    pool = read(DATA / 'data/fl-pool.json')['rows']['train']
    val = read(DATA / 'data/validation.json')['rows']['validation']
    initial = read(DATA / 'base-model.json')
    return m, pool, val, initial, dependencies()


def partitions(pool, cohort, seed):
    alloc = (base._iid_assignments(pool, client_count=15, seed=seed, np=base.np) if cohort == 'iid' else
             base._dirichlet_assignments(pool, client_count=15, seed=seed, alpha=.3, minimum_rows=32, np=base.np))
    return {f'client{i+1:02d}': rows for i, rows in enumerate(alloc)}


def run(cfg, cohort, seed, pool, val, initial, deps, weights, rounds=15, plan=None, attack_rounds=10, correct=None):
    torch = deps[1]; torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
    parts = partitions(pool, cohort, seed); clients = sorted(parts); model = initial; hist = []
    for n in range(1, rounds + 1):
        updates = []
        for i, c in enumerate(clients):
            rows = parts[c]
            if plan is not None and n <= attack_rounds and c in plan.client_components:
                rows, _ = poison_local_rows(rows=rows, plan=plan, client_id=c, round_number=n, distributed=True)
            local = _model_from_export(model, torch=torch, np=np)
            train_local(model=local, rows=rows, class_names=model['class_names'], class_weights=weights, epochs=cfg['local_epochs'],
                        batch_size=cfg['batch_size'], learning_rate=cfg['learning_rate'], seed=seed + n * 10000 + i, device_name='cpu',
                        torch=torch, np=np)
            ex = export_state(local, architecture=model['architecture'], class_names=model['class_names'])
            updates.append((arrays_from_export(ex, np=np), float(len(parts[c]))))
        model = model_with_arrays(model, fedavg(updates, aggregate=deps[4]))
        rec = dict(round=n, f1=evaluate(model, val, deps)['macro_f1_all_model_classes'])
        if plan is not None or correct is not None:
            o = outcomes(model, val, plan, correct, deps)
            rec['full_asr'] = o['complete_trigger']['asr']
        hist.append(rec)
    return hist


def stage_a(out, weighting='balanced'):
    m, pool, val, initial, deps = setup()
    w = m['global_class_weights'] if weighting == 'balanced' else {c: 1.0 for c in m['class_names']}
    grid = ([dict(local_epochs=e, learning_rate=lr, batch_size=128) for e in (1, 2) for lr in (0.001, 0.0003)] if weighting == 'balanced'
            else [dict(local_epochs=e, learning_rate=0.0003, batch_size=128, weighting='uniform') for e in (1, 2)])
    report = []
    for cfg in grid:
        for cohort, seed in DEV_SEEDS:
            h = run(cfg, cohort, seed, pool, val, initial, deps, w)
            report.append(dict(cfg=cfg, cohort=cohort, seed=seed, f1=[round(x['f1'], 4) for x in h]))
            print(json.dumps(dict(cfg=cfg, cohort=cohort, f1_r1=round(h[0]['f1'], 3), f1_r5=round(h[4]['f1'], 3),
                                  f1_r10=round(h[9]['f1'], 3), f1_r15=round(h[-1]['f1'], 3), f1_min=round(min(x['f1'] for x in h), 3))), flush=True)
    Path(out).write_text(json.dumps(dict(stage='A', warm_start_f1=m['warm_start_validation']['macro_f1_all_model_classes'], runs=report), indent=1))


def stage_b(out, cfg):
    m, pool, val, initial, deps = setup()
    w = m['global_class_weights'] if cfg.get('weighting', 'balanced') == 'balanced' else {c: 1.0 for c in m['class_names']}
    template = read(ROOT / 'artifacts/revision-head-gate-v2/protocol-before-fitting.json')['training']['attack_plan']
    pred, _ = predict(initial, val, deps); correct = [p == r['label'] for p, r in zip(pred, val)]
    feats = [(13, 17, 24), (3, 10, 20), (1, 6, 15)]
    values = ['3', '6', '12']
    report = []
    for fs in feats:
        for v in values:
            plan = DistributedBackdoorPlan.model_validate({**template, 'seed': DEV_SEEDS[0][1],
                    'client_components': dict(zip(ATTACKERS, [[f] for f in fs])), 'trigger_values_decimal': {str(f): v for f in fs},
                    'attack_rounds': list(range(1, 11))})
            # clean trajectory (attack_rounds=0): trigger is only applied at evaluation
            ch = run(cfg, 'iid', DEV_SEEDS[0][1], pool, val, initial, deps, w, rounds=6, plan=plan, attack_rounds=0, correct=correct)
            po = run(cfg, 'iid', DEV_SEEDS[0][1], pool, val, initial, deps, w, rounds=6, plan=plan, attack_rounds=6, correct=correct)
            rec = dict(features=fs, value=v, clean_asr=[round(x['full_asr'], 3) for x in ch], poisoned_asr=[round(x['full_asr'], 3) for x in po],
                       clean_f1=round(ch[-1]['f1'], 3), poisoned_f1=round(po[-1]['f1'], 3))
            report.append(rec); print(json.dumps(rec), flush=True)
    Path(out).write_text(json.dumps(dict(stage='B', cfg=cfg, runs=report), indent=1))


def stage_c(out, cfg):
    """Effectiveness of the best stage-B trigger over the full attack window."""
    m, pool, val, initial, deps = setup()
    w = {c: 1.0 for c in m['class_names']}
    template = read(ROOT / 'artifacts/revision-head-gate-v2/protocol-before-fitting.json')['training']['attack_plan']
    pred, _ = predict(initial, val, deps); correct = [p == r['label'] for p, r in zip(pred, val)]
    report = []
    for cohort, seed in DEV_SEEDS:
        for frac in ('0.50', '1.00'):
            plan = DistributedBackdoorPlan.model_validate({**template, 'seed': seed, 'poisoned_fraction_decimal': frac,
                    'client_components': dict(zip(ATTACKERS, [[1], [6], [15]])), 'trigger_values_decimal': {'1': '12', '6': '12', '15': '12'},
                    'attack_rounds': list(range(1, 11))})
            ch = run(cfg, cohort, seed, pool, val, initial, deps, w, rounds=15, plan=plan, attack_rounds=0, correct=correct)
            po = run(cfg, cohort, seed, pool, val, initial, deps, w, rounds=15, plan=plan, attack_rounds=10, correct=correct)
            harm = max(p['full_asr'] - c['full_asr'] for p, c in zip(po, ch))
            rec = dict(cohort=cohort, fraction=frac, clean_asr_max=round(max(x['full_asr'] for x in ch), 3),
                       poisoned_asr_peak=round(max(x['full_asr'] for x in po), 3), poisoned_asr_final=round(po[-1]['full_asr'], 3),
                       paired_harm=round(harm, 3), clean_f1=round(ch[-1]['f1'], 3), poisoned_f1=round(po[-1]['f1'], 3))
            report.append(rec); print(json.dumps(rec), flush=True)
    Path(out).write_text(json.dumps(dict(stage='C', cfg=cfg, trigger=dict(features=[1, 6, 15], value='12'), runs=report), indent=1))


if __name__ == '__main__':
    stage, out = sys.argv[1], sys.argv[2]
    if stage == 'A':
        stage_a(out)
    elif stage == 'A2':
        stage_a(out, 'uniform')
    elif stage == 'B':
        stage_b(out, json.loads(sys.argv[3]))
    else:
        stage_c(out, json.loads(sys.argv[3]))
