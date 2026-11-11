"""Independent reconstruction of the trigger-probe live study from saved evidence.

Per completed round: authenticate; recompute probe shortcuts, peer-relative scores and
probe decisions from the saved local models and validation rows; recompute original
geometric indicators and original decisions (validation_impact from the record); check
deployed statuses, arm/gate binding, masses and the aggregate (FedAvg or bounded).
Usage: revision_probe_audit.py PHASE [--lab PATH]
"""
from __future__ import annotations

import argparse
import json
from fractions import Fraction
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_head_cusum_audit as au
import factorial_aggregators as fa
import trigger_probe_gate as tp
from revision_study_data import read, dependencies
from revision_dba_experiment import save, authenticate, model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT


def audit_case(lab, phase, result, protocol, deps, settings, bounds, probe_inputs, benign_index):
    task = result['task']; ev = lab / phase / 'cases' / task['name'] / 'evidence'; authenticate(ev, result['manifest_sha256'])
    sizes = {r['client_id']: r['train_row_count'] for r in read(lab / 'partitions' / str(task['seed']) / 'manifest.json')['clients']}
    clients = sorted(sizes); runtime = protocol['runtime_admission']; rho = Fraction(str(runtime['accepted_downweight_factor']))
    gate, operator = task['policy'].split('+'); thr = float(protocol['probe']['thresholds'][task['cohort']]); stack, keys, n = probe_inputs
    torch = deps[1]; checked = 0
    for r in range(1, 16):
        rd = ev / 'rounds' / f'round-{r:03d}'
        if not (rd / 'gate-state.json').exists():
            break
        state = read(rd / 'gate-state.json'); initial = read(rd / 'base-model.json')
        exports = [read(rd / 'updates' / f'{c}.json') for c in clients]
        per = {c: tp.shortcuts(_model_from_export(e, torch=torch, np=np), stack, keys, n, benign_index, torch) for c, e in zip(clients, exports)}
        scores = tp.round_scores(per); dec = tp.decide(scores, thr)
        base.require(state['probe']['threshold'] == thr, 'threshold binding')
        for c in clients:
            base.require(au.close(scores[c][0], state['probe']['score'][c]), f'probe score {c} r{r}')
            base.require(dec[c]['status'] == state['decisions'][c][tp.POLICY]['status'], f'probe decision {c} r{r}')
        au.legacy_check(initial, exports, clients, state, settings, r)
        if not (rd / 'round.json').exists():
            base.require((rd / 'failure.json').exists(), 'missing round without failure'); break
        row = read(rd / 'round.json')
        base.require(row['statuses'] == {c: state['decisions'][c][task['policy']]['status'] for c in clients}
                     == {c: state['decisions'][c][gate]['status'] for c in clients}, f'statuses r{r}')
        masses = {c: sizes[c] * (rho if row['statuses'][c] == 'accepted_downweighted' else Fraction(int(state['decisions'][c][gate]['contributes'])))
                  for c in clients}
        base.require({c: str(v) for c, v in masses.items()} == row['masses'], f'masses r{r}')
        if operator == 'fedavg':
            rebuilt = au.fedavg_rebuild(initial, exports, clients, masses, task, runtime, deps)
        else:
            b = bounds[task['cohort']]
            params, _ = fa.bounded(arrays_from_export(initial, np=base.np), {c: arrays_from_export(e, np=base.np) for c, e in zip(clients, exports)},
                                   masses, b['limits'], b, runtime['minimum_contributors'])
            rebuilt = model_with_arrays(initial, params) if params is not None else None
        base.require(rebuilt is not None and base.digest(rebuilt) == row['global_model_sha256'] == base.digest(read(rd / 'global-model.json')), f'aggregate r{r}')
        checked += 1
    base.require(checked == result['completed_rounds'], 'completed round count mismatch')
    return dict(task=task, completed_rounds=checked, complete=result['complete'])


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('phase', choices=('guard', 'evaluation'))
    ap.add_argument('--lab', type=Path, default=ROOT / 'artifacts/revision-trigger-probe-live')
    a = ap.parse_args(); lab = a.lab; folder = lab / a.phase
    protocol = read(folder / 'protocol-before-training.json'); closure = read(folder / 'training-complete.json')
    base.require(closure['protocol_sha256'] == sha256_file(folder / 'protocol-before-training.json'), 'closure pin')
    base.require(len(closure['results']) == len(protocol['tasks']), 'incomplete phase')
    out = folder / 'verified/summary.json'; base.require(not out.exists(), 'phase already verified')
    deps, settings = dependencies(), base.settings_for(protocol); deps[1].set_num_threads(2)
    bounds = {c: read(ROOT / pin['path']) for c, pin in protocol['tensor_bounds'].items()}
    val = read(protocol['training']['validation_path'])['rows']['validation']
    probe_inputs = tp.probe_inputs(val); benign_index = read(protocol['training']['base_model_path'])['class_names'].index('benign')
    cases = []
    for r in closure['results']:
        res = audit_case(lab, a.phase, r, protocol, deps, settings, bounds, probe_inputs, benign_index); cases.append(res)
        print('VERIFIED ' + json.dumps(dict(case=r['task']['name'], rounds=res['completed_rounds'])), flush=True)
    save(out, dict(status='verified', phase=a.phase, verifier_sha256=sha256_file(Path(__file__)),
                   training_closure_sha256=sha256_file(folder / 'training-complete.json'), test_accessed=False,
                   rounds_reconstructed=sum(c['completed_rounds'] for c in cases), cases=cases))
    print('PHASE_VERIFIED ' + json.dumps(dict(phase=a.phase, cases=len(cases))), flush=True)


if __name__ == '__main__':
    main()
