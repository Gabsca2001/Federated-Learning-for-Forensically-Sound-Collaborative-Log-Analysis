"""Independent reconstruction of the per-key probe confirmatory study from saved evidence.

Does not import the study controllers. Per completed round: authenticate; recompute the raw
probe and the per-key normalised probe (scores, decisions) from saved local models and the
validation rows with the pinned thresholds / scales; recompute original geometric decisions;
check executed attacker rows (evasive: recomputed; pair-dba/adaptive: poisoning record on the
declared pair), honest rows unchanged, statuses, gate binding, masses, aggregate, model chain.
Usage: revision_probe_keynorm_audit.py PHASE [--lab PATH]
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
import keynorm_probe_gate as kp
from revision_probe_evasion_audit import expected_evasive_digest
from revision_study_data import read, dependencies
from revision_dba_experiment import save, authenticate, model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT


def audit_case(lab, phase, result, protocol, deps, settings, bounds, inputs, benign_index):
    task = result['task']; evd = lab / phase / 'cases' / task['name'] / 'evidence'; authenticate(evd, result['manifest_sha256'])
    part_root = lab / 'partitions' / str(task['seed']); manifest = read(part_root / 'manifest.json')
    base.require(sha256_file(part_root / 'manifest.json') == protocol['partitions'][str(task['seed'])], 'partition pin')
    sizes = {r['client_id']: r['train_row_count'] for r in manifest['clients']}; clients = sorted(sizes)
    runtime = protocol['runtime_admission']; rho = Fraction(str(runtime['accepted_downweight_factor']))
    gate, operator = task['policy'].split('+')
    t1 = float(protocol['probe']['thresholds'][task['cohort']]); m = float(protocol['probek']['multiplier'])
    scales = {(int(j), float(v)): float(s) for j, v, s in protocol['probek']['scales'][task['cohort']]}
    attack = protocol['attack']; pairs = dict(zip(task['attackers'], attack['pairs']))
    snap = {x['client_id']: read(part_root / x['dataset_path'])['rows']['train'] for x in manifest['clients']}
    snap_digest = {c: base.digest(r) for c, r in snap.items()}
    torch = deps[1]; checked = 0; prev = None
    for r in range(1, 16):
        rd = evd / 'rounds' / f'round-{r:03d}'
        if not (rd / 'gate-state.json').exists():
            break
        state = read(rd / 'gate-state.json'); initial = read(rd / 'base-model.json')
        exports = [read(rd / 'updates' / f'{c}.json') for c in clients]
        per = {c: tp.shortcuts(_model_from_export(e, torch=torch, np=np), *inputs, benign_index, torch) for c, e in zip(clients, exports)}
        s1 = tp.round_scores(per); sk = kp.round_scores(per, scales); d1 = tp.decide(s1, t1); dk = kp.decide(sk, m)
        base.require(state['probe']['threshold'] == t1 and state['probek']['multiplier'] == m, 'threshold binding')
        for c in clients:
            base.require(au.close(s1[c][0], state['probe']['score'][c]) and au.close(sk[c][0], state['probek']['score'][c]), f'probe score {c} r{r}')
            base.require(d1[c]['status'] == state['decisions'][c][tp.POLICY]['status'], f'probe decision {c} r{r}')
            base.require(dk[c]['status'] == state['decisions'][c][kp.POLICY]['status'], f'probek decision {c} r{r}')
        au.legacy_check(initial, exports, clients, state, settings, r)
        if not (rd / 'round.json').exists():
            base.require((rd / 'failure.json').exists(), 'missing round without failure'); break
        row = read(rd / 'round.json'); active = task['variant'] != 'clean' and r <= 10
        base.require(row['attack_active'] == active, f'attack activity r{r}')
        for tr in row['training']:
            c = tr['client_id']; p = tr['poisoning']
            poisoned = bool(p and p.get('poisoned_window_ids'))
            if not active or c not in pairs or (task['variant'] == 'adaptive' and not poisoned):
                base.require(not poisoned and tr['executed_rows_sha256'] == snap_digest[c], f'unmodified rows {c} r{r}')
            elif task['variant'] == 'evasive':
                want = expected_evasive_digest(snap[c], pairs[c], float(attack['trigger_value']), task['seed'], r, sorted(pairs).index(c))
                base.require(tr['executed_rows_sha256'] == want and p['strategy'] == 'evasive-and-trigger', f'evasive rows {c} r{r}')
            else:
                base.require(poisoned and sorted(p['feature_indices']) == sorted(pairs[c]), f'pair poisoning {c} r{r}')
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
        base.require(prev is None or row['base_model_sha256'] == prev, f'chain r{r}')
        prev = row['global_model_sha256']; checked += 1
    base.require(checked == result['completed_rounds'], 'completed round count mismatch')
    return dict(task=task, completed_rounds=checked, complete=result['complete'])


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('phase', choices=('guard', 'evaluation'))
    ap.add_argument('--lab', type=Path, default=ROOT / 'artifacts/revision-probe-keynorm-confirm')
    a = ap.parse_args(); lab = a.lab; folder = lab / a.phase
    protocol = read(folder / 'protocol-before-training.json'); closure = read(folder / 'training-complete.json')
    base.require(closure['protocol_sha256'] == sha256_file(folder / 'protocol-before-training.json'), 'closure pin')
    base.require(len(closure['results']) == len(protocol['tasks']), 'incomplete phase')
    base.require(sha256_file(ROOT / protocol['probek']['scales_file']) == protocol['probek']['scales_sha256'], 'scales pin')
    base.require(sha256_file(ROOT / protocol['probe']['thresholds_file']) == protocol['probe']['thresholds_sha256'], 'threshold pin')
    out = folder / 'verified/summary.json'; base.require(not out.exists(), 'phase already verified')
    deps, settings = dependencies(), base.settings_for(protocol); deps[1].set_num_threads(2)
    bounds = {c: read(ROOT / pin['path']) for c, pin in protocol['tensor_bounds'].items()}
    val = read(protocol['training']['validation_path'])['rows']['validation']; inputs = tp.probe_inputs(val)
    benign_index = read(protocol['training']['base_model_path'])['class_names'].index('benign')
    cases = []
    for r in closure['results']:
        res = audit_case(lab, a.phase, r, protocol, deps, settings, bounds, inputs, benign_index); cases.append(res)
        print('VERIFIED ' + json.dumps(dict(case=r['task']['name'], rounds=res['completed_rounds'])), flush=True)
    save(out, dict(status='verified', phase=a.phase, verifier_sha256=sha256_file(Path(__file__)),
                   training_closure_sha256=sha256_file(folder / 'training-complete.json'), test_accessed=False,
                   rounds_reconstructed=sum(c['completed_rounds'] for c in cases), cases=cases))
    print('PHASE_VERIFIED ' + json.dumps(dict(phase=a.phase, cases=len(cases))), flush=True)


if __name__ == '__main__':
    main()
