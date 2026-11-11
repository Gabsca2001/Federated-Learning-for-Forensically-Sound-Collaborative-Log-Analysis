"""Independent reconstruction of the probe-evasion live study from saved evidence.

Does not import the study controller. Per completed round: authenticate; recompute the
single-feature probe and the pair probe (scores, peer-relative decisions) from the saved
local models and the validation rows with the pinned thresholds; recompute original
geometric indicators/decisions; check deployed statuses, arm/gate binding, masses and the
aggregate (FedAvg or bounded). Also checks, for attacked cases, that the executed rows of
attackers match the declared attack (evasive: recomputed rows; pair-dba: poisoning record
on the declared pair) and that honest clients trained on their unmodified snapshot.
Usage: revision_probe_evasion_audit.py PHASE [--lab PATH]
"""
from __future__ import annotations

import argparse
import copy
import json
from fractions import Fraction
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_head_cusum_audit as au
import factorial_aggregators as fa
import trigger_probe_gate as tp
import pair_probe_gate as pp
from revision_study_data import read, dependencies
from revision_dba_experiment import save, authenticate, model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT


def expected_evasive_digest(rows, pair, value, seed, number, client_index):
    """Independent re-implementation of the declared evasive row transformation."""
    rng = np.random.default_rng(seed + number * 10_000 + client_index)
    idx = rng.permutation(len(rows)); a, b = len(rows) // 2, (3 * len(rows)) // 4
    out = copy.deepcopy(rows)
    for i in idx[:a]:
        if out[i]['label'] != 'benign':
            out[i]['features'][pair[0]] = value; out[i]['features'][pair[1]] = value; out[i]['label'] = 'benign'
    for i in idx[a:b]:
        out[i]['features'][pair[0]] = value
    for i in idx[b:]:
        out[i]['features'][pair[1]] = value
    return base.digest(out)


def audit_case(lab, phase, result, protocol, deps, settings, bounds, single_inputs, pair_inputs, benign_index):
    task = result['task']; ev = lab / phase / 'cases' / task['name'] / 'evidence'; authenticate(ev, result['manifest_sha256'])
    part_root = lab / 'partitions' / str(task['seed']); manifest = read(part_root / 'manifest.json')
    base.require(sha256_file(part_root / 'manifest.json') == protocol['partitions'][str(task['seed'])], 'partition pin')
    sizes = {r['client_id']: r['train_row_count'] for r in manifest['clients']}
    clients = sorted(sizes); runtime = protocol['runtime_admission']; rho = Fraction(str(runtime['accepted_downweight_factor']))
    gate, operator = task['policy'].split('+')
    t1 = float(protocol['probe']['thresholds'][task['cohort']]); t2 = float(protocol['pair_probe']['thresholds'][task['cohort']])
    attack = protocol['attack']; pairs = dict(zip(task['attackers'], attack['pairs']))
    snap_rows = None
    torch = deps[1]; checked = 0
    for r in range(1, 16):
        rd = ev / 'rounds' / f'round-{r:03d}'
        if not (rd / 'gate-state.json').exists():
            break
        state = read(rd / 'gate-state.json'); initial = read(rd / 'base-model.json')
        exports = [read(rd / 'updates' / f'{c}.json') for c in clients]
        models = {c: _model_from_export(e, torch=torch, np=np) for c, e in zip(clients, exports)}
        s1 = tp.round_scores({c: tp.shortcuts(m, *single_inputs, benign_index, torch) for c, m in models.items()})
        s2 = pp.round_scores({c: tp.shortcuts(m, *pair_inputs, benign_index, torch) for c, m in models.items()})
        d1 = tp.decide(s1, t1); d2 = pp.decide(d1, s2, t2)
        base.require(state['probe']['threshold'] == t1 and state['pair_probe']['threshold'] == t2, 'threshold binding')
        for c in clients:
            base.require(au.close(s1[c][0], state['probe']['score'][c]) and au.close(s2[c][0], state['pair_probe']['score'][c]), f'probe score {c} r{r}')
            base.require(d1[c]['status'] == state['decisions'][c][tp.POLICY]['status'], f'probe decision {c} r{r}')
            base.require(d2[c]['status'] == state['decisions'][c][pp.POLICY]['status'], f'probe2 decision {c} r{r}')
        au.legacy_check(initial, exports, clients, state, settings, r)
        if not (rd / 'round.json').exists():
            base.require((rd / 'failure.json').exists(), 'missing round without failure'); break
        row = read(rd / 'round.json')
        # attack execution check
        active = task['variant'] != 'clean' and r <= 10
        base.require(row['attack_active'] == active, f'attack activity r{r}')
        for tr in row['training']:
            c = tr['client_id']
            if not active or c not in pairs:
                base.require(tr['poisoning'] is None or not tr['poisoning'].get('poisoned_window_ids'), f'unexpected poisoning {c} r{r}')
                if snap_rows is None:
                    snap_rows = {x['client_id']: read(part_root / x['dataset_path'])['rows']['train'] for x in manifest['clients']}
                base.require(tr['executed_rows_sha256'] == base.digest(snap_rows[c]), f'honest rows changed {c} r{r}')
            elif task['variant'] == 'evasive':
                if snap_rows is None:
                    snap_rows = {x['client_id']: read(part_root / x['dataset_path'])['rows']['train'] for x in manifest['clients']}
                want = expected_evasive_digest(snap_rows[c], pairs[c], float(attack['trigger_value']), task['seed'], r, sorted(pairs).index(c))
                base.require(tr['executed_rows_sha256'] == want and tr['poisoning']['strategy'] == 'evasive-and-trigger', f'evasive rows {c} r{r}')
            else:
                base.require(sorted(tr['poisoning']['feature_indices']) == sorted(pairs[c]) and tr['poisoning']['poisoned_window_ids'], f'pair-dba rows {c} r{r}')
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
        if r > 1:
            base.require(row['base_model_sha256'] == prev, f'chain r{r}')
        prev = row['global_model_sha256']; checked += 1
    base.require(checked == result['completed_rounds'], 'completed round count mismatch')
    return dict(task=task, completed_rounds=checked, complete=result['complete'])


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('phase', choices=('guard', 'evaluation'))
    ap.add_argument('--lab', type=Path, default=ROOT / 'artifacts/revision-trigger-probe-evasion-live')
    a = ap.parse_args(); lab = a.lab; folder = lab / a.phase
    protocol = read(folder / 'protocol-before-training.json'); closure = read(folder / 'training-complete.json')
    base.require(closure['protocol_sha256'] == sha256_file(folder / 'protocol-before-training.json'), 'closure pin')
    base.require(len(closure['results']) == len(protocol['tasks']), 'incomplete phase')
    base.require(sha256_file(ROOT / protocol['pair_probe']['thresholds_file']) == protocol['pair_probe']['thresholds_sha256'], 'pair threshold pin')
    base.require(sha256_file(ROOT / protocol['probe']['thresholds_file']) == protocol['probe']['thresholds_sha256'], 'single threshold pin')
    out = folder / 'verified/summary.json'; base.require(not out.exists(), 'phase already verified')
    deps, settings = dependencies(), base.settings_for(protocol); deps[1].set_num_threads(2)
    bounds = {c: read(ROOT / pin['path']) for c, pin in protocol['tensor_bounds'].items()}
    val = read(protocol['training']['validation_path'])['rows']['validation']
    single_inputs = tp.probe_inputs(val); pair_inputs = pp.probe_inputs(val)
    benign_index = read(protocol['training']['base_model_path'])['class_names'].index('benign')
    cases = []
    for r in closure['results']:
        res = audit_case(lab, a.phase, r, protocol, deps, settings, bounds, single_inputs, pair_inputs, benign_index); cases.append(res)
        print('VERIFIED ' + json.dumps(dict(case=r['task']['name'], rounds=res['completed_rounds'])), flush=True)
    save(out, dict(status='verified', phase=a.phase, verifier_sha256=sha256_file(Path(__file__)),
                   training_closure_sha256=sha256_file(folder / 'training-complete.json'), test_accessed=False,
                   rounds_reconstructed=sum(c['completed_rounds'] for c in cases), cases=cases))
    print('PHASE_VERIFIED ' + json.dumps(dict(phase=a.phase, cases=len(cases))), flush=True)


if __name__ == '__main__':
    main()
