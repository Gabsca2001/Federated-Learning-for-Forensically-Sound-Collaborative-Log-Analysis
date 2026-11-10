"""Independent reconstruction of head gate v2 study phases from saved evidence.

Per completed round: authenticate the case manifest; recompute step-normalized
head features, adverse z, scores and head_v2 decisions from saved base model and
updates; recompute the original geometric indicators and tpm_only / sequential /
gated_composite decisions (validation_impact taken from the record); check the
deployed statuses, arm/gate binding, masses, and rebuild the aggregate with the
arm's operator (Flower FedAvg or per-tensor bounded) against the checkpoint.
Usage: revision_head_v2_audit.py PHASE [--lab PATH]
"""
from __future__ import annotations

import argparse
import json
from fractions import Fraction
from pathlib import Path

import revision_gate_trajectories as base  # numeric environment first
import revision_head_cusum_audit as au
import factorial_aggregators as fa
import head_cusum_gate as hg
import head_gate_steps as gs
from revision_study_data import read, dependencies
from revision_dba_experiment import save, authenticate, model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

ROOT = base.ROOT


def audit_case(lab, phase, result, model, model_sha, protocol, deps, settings, bounds):
    task = result['task']; ev = lab / phase / 'cases' / task['name'] / 'evidence'
    authenticate(ev, result['manifest_sha256'])
    sizes = {r['client_id']: r['train_row_count'] for r in read(lab / 'partitions' / str(task['seed']) / 'manifest.json')['clients']}
    clients = sorted(sizes); cfg = protocol['training']; runtime = protocol['runtime_admission']
    rho = Fraction(str(runtime['accepted_downweight_factor'])); gate, operator = task['policy'].split('+')
    checked = 0
    for n in range(1, 16):
        rd = ev / 'rounds' / f'round-{n:03d}'
        if not (rd / 'gate-state.json').exists():
            break
        state = read(rd / 'gate-state.json'); hv = state['head_v2']
        base.require(hv['model_sha256'] == model_sha and hv['cohort'] == task['cohort'] and hv['sizes'] == sizes, 'state binding')
        initial = read(rd / 'base-model.json'); exports = [read(rd / 'updates' / f'{c}.json') for c in clients]
        feats = gs.features(initial, exports, clients, sizes, cfg['local_epochs'], cfg['batch_size'])
        out = gs.decide(model, task['cohort'], feats)
        for c in clients:
            base.require(all(au.close(feats[c][f], hv['features'][c][f]) for f in hg.FEATURES), f'features {c} r{n}')
            base.require(au.close(out[c]['score'], hv['score'][c]), f'score {c} r{n}')
            base.require(out[c]['decision']['status'] == state['decisions'][c][gs.POLICY]['status'], f'head_v2 decision {c} r{n}')
        au.legacy_check(initial, exports, clients, state, settings, n)
        if not (rd / 'round.json').exists():
            base.require((rd / 'failure.json').exists(), 'missing round without failure'); break
        row = read(rd / 'round.json')
        base.require(row['statuses'] == {c: state['decisions'][c][task['policy']]['status'] for c in clients}
                     == {c: state['decisions'][c][gate]['status'] for c in clients}, f'deployed statuses r{n}')
        masses = {c: sizes[c] * (rho if row['statuses'][c] == 'accepted_downweighted' else Fraction(int(state['decisions'][c][gate]['contributes'])))
                  for c in clients}
        base.require({c: str(v) for c, v in masses.items()} == row['masses'], f'masses r{n}')
        if operator == 'fedavg':
            rebuilt = au.fedavg_rebuild(initial, exports, clients, masses, task, runtime, deps)
        else:
            b = bounds[task['cohort']]
            params, _ = fa.bounded(arrays_from_export(initial, np=base.np), {c: arrays_from_export(e, np=base.np) for c, e in zip(clients, exports)},
                                   masses, b['limits'], b, runtime['minimum_contributors'])
            rebuilt = model_with_arrays(initial, params) if params is not None else None
        base.require(rebuilt is not None and base.digest(rebuilt) == row['global_model_sha256'] == base.digest(read(rd / 'global-model.json')), f'aggregate r{n}')
        checked += 1
    base.require(checked == result['completed_rounds'], 'completed round count mismatch')
    return dict(task=task, completed_rounds=checked, complete=result['complete'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('phase', choices=('guard', 'evaluation', 'evaluation-exploratory'))
    ap.add_argument('--lab', type=Path, default=ROOT / 'artifacts/revision-head-gate-v2')
    a = ap.parse_args(); lab = a.lab; folder = lab / a.phase
    protocol = read(folder / 'protocol-before-training.json'); closure = read(folder / 'training-complete.json')
    base.require(closure['protocol_sha256'] == sha256_file(folder / 'protocol-before-training.json'), 'closure pin')
    base.require(len(closure['results']) == len(protocol['tasks']), 'incomplete phase')
    model_sha = sha256_file(lab / 'models/head-v2.json'); base.require(model_sha == protocol['model_sha256'], 'model pin')
    out = folder / 'verified/summary.json'; base.require(not out.exists(), 'phase already verified')
    bounds = {c: read(ROOT / pin['path']) for c, pin in protocol['tensor_bounds'].items()}
    model, deps, settings = read(lab / 'models/head-v2.json'), dependencies(), base.settings_for(protocol)
    cases = []
    for r in closure['results']:
        res = audit_case(lab, a.phase, r, model, model_sha, protocol, deps, settings, bounds); cases.append(res)
        print('VERIFIED ' + json.dumps(dict(case=r['task']['name'], rounds=res['completed_rounds'])), flush=True)
    save(out, dict(status='verified', phase=a.phase, verifier_sha256=sha256_file(Path(__file__)),
                   training_closure_sha256=sha256_file(folder / 'training-complete.json'), test_accessed=False,
                   rounds_reconstructed=sum(c['completed_rounds'] for c in cases), cases=cases))
    print('PHASE_VERIFIED ' + json.dumps(dict(phase=a.phase, cases=len(cases))), flush=True)


if __name__ == '__main__':
    main()
