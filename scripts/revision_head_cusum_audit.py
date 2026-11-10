"""Independent reconstruction of head-CUSUM study phases from saved evidence.

For every completed round of every case it authenticates the signed manifest and
recomputes, from saved base model and client updates only: head-aware features,
adverse z, round scores, the CUSUM chain from round 1, both candidate decisions,
the deployed policy's effective masses and the Flower FedAvg global model.
It also recomputes the original geometric indicators from the deltas and the
original tpm_only/sequential/gated_composite decisions from them; only the
recorded validation_impact (which needs validation inference) is trusted.
No test data is read. Usage: revision_head_cusum_audit.py PHASE [--lab PATH]
"""
from __future__ import annotations

import argparse
import json
import math
from fractions import Fraction
from pathlib import Path

import revision_gate_trajectories as base  # numeric environment first
import head_cusum_gate as hg
from revision_study_data import read, dependencies
from revision_dba_experiment import save, authenticate, model_with_arrays
from fl_forensics.byzantine import model_delta, update_indicators
from fl_forensics.canonical import sha256_file
from fl_forensics.composite_admission import decide_admission_policies, score_statistical_indicators
from fl_forensics.composite_admission_models import IndicatorReference
from fl_forensics.federated_model import arrays_from_export, fedavg

LEGACY = ('tpm_only', 'sequential', 'gated_composite')


def legacy_check(initial, exports, clients, state, settings, number):
    """Recompute original geometric indicators and the three original decisions.

    validation_impact needs validation inference and is taken from the record.
    """
    values = arrays_from_export(initial, np=base.np)
    deltas = [model_delta(values, arrays_from_export(e, np=base.np)) for e in exports]
    fresh = update_indicators(deltas, client_ids=clients)
    stored = state['indicators']
    base.require([s['client_id'] for s in stored] == clients, 'indicator roster')
    for f, s in zip(fresh, stored, strict=True):
        for k, v in f.items():
            if k != 'client_id' and isinstance(v, float):
                base.require(close(v, s[k]), f'legacy indicator {k} {s["client_id"]} r{number}')
    cal = settings['calibration']
    refs = {n: IndicatorReference(name=n, **v) for n, v in cal['indicator_references'].items()}
    scores = score_statistical_indicators(stored, references=refs, weights=cal['indicator_weights'],
                                          z_cap=settings['robust_z_cap'])
    lim = cal['thresholds']
    for c in clients:
        decisions = {d.policy: d for d in decide_admission_policies(
            trust=base.TRUST, statistics=scores[c], statistical_threshold=lim['statistical_threshold'],
            composite_threshold=lim['composite_threshold'], trust_weight=lim['trust_weight'],
            composite_downweight_threshold=lim['composite_downweight_threshold'])}
        for p in LEGACY:
            base.require(decisions[p].status == state['decisions'][c][p]['status'], f'legacy decision {p} {c} r{number}')

ROOT = base.ROOT


def close(a, b, tol=1e-9):
    return math.isclose(a, b, rel_tol=tol, abs_tol=tol)


def fedavg_rebuild(initial, exports, clients, masses, task, runtime, deps):
    selected = [(arrays_from_export(e, np=base.np), float(masses[c])) for c, e in zip(clients, exports) if masses[c] > 0]
    base.require(len(selected) >= runtime['minimum_contributors'], 'quorum')
    return model_with_arrays(initial, fedavg(selected, aggregate=deps[4]))


def audit_case(lab, phase, result, model, model_sha, runtime, deps, settings, rebuild=fedavg_rebuild,
               gate_of=lambda policy: policy):
    task = result['task']; evidence = lab / phase / 'cases' / task['name'] / 'evidence'
    authenticate(evidence, result['manifest_sha256'])
    part = read(lab / 'partitions' / str(task['seed']) / 'manifest.json')
    sizes = {r['client_id']: r['train_row_count'] for r in part['clients']}
    rho = Fraction(str(runtime['accepted_downweight_factor']))
    prior, checked = {}, 0
    for number in range(1, 16):
        rd = evidence / 'rounds' / f'round-{number:03d}'
        if not (rd / 'gate-state.json').exists():
            break
        state = read(rd / 'gate-state.json'); hgs = state['head_gate']
        base.require(hgs['round'] == number and hgs['model_sha256'] == model_sha and hgs['cohort'] == task['cohort'], 'state binding')
        initial = read(rd / 'base-model.json')
        clients = sorted(sizes)
        exports = [read(rd / 'updates' / f'{c}.json') for c in clients]
        feats = hg.compute_features(initial, exports, clients)
        for c in clients:
            base.require(all(close(feats[c][f], hgs['features'][c][f]) for f in hg.FEATURES), f'features {c} r{number}')
        base.require(all(close(float(prior.get(c, 0.0)), hgs['previous_cusum'][c]) for c in clients), f'CUSUM chain r{number}')
        out = hg.decide(model, task['cohort'], feats, prior, trust_admissible=True)
        for c in clients:
            base.require(close(out[c]['score'], hgs['score'][c]) and close(out[c]['cusum'], hgs['cusum'][c]), f'score/cusum {c}')
            for p in hg.POLICIES:
                base.require(out[c]['decisions'][p]['status'] == state['decisions'][c][p]['status'], f'decision {p} {c} r{number}')
        prior = {c: out[c]['cusum'] for c in clients}
        legacy_check(initial, exports, clients, state, settings, number)
        if not (rd / 'round.json').exists():
            base.require((rd / 'failure.json').exists(), 'missing round record without failure')
            break
        row = read(rd / 'round.json'); policy = task['policy']
        base.require(row['statuses'] == {c: state['decisions'][c][policy]['status'] for c in clients}, 'deployed statuses')
        base.require(row['statuses'] == {c: state['decisions'][c][gate_of(policy)]['status'] for c in clients}, 'arm/gate binding')
        factors = {c: rho if row['statuses'][c] == 'accepted_downweighted' else
                   Fraction(int(state['decisions'][c][policy]['contributes'])) for c in clients}
        masses = {c: sizes[c] * factors[c] for c in clients}
        base.require({c: str(v) for c, v in masses.items()} == row['masses'], 'masses')
        rebuilt = rebuild(initial, exports, clients, masses, task, runtime, deps)
        base.require(rebuilt is not None, f'operator gave no aggregate r{number}')
        base.require(base.digest(rebuilt) == row['global_model_sha256'] == base.digest(read(rd / 'global-model.json')), f'FedAvg r{number}')
        base.require(row['base_model_sha256'] == base.digest(initial), 'base binding')
        checked += 1
    base.require(checked == result['completed_rounds'], 'completed round count mismatch')
    return dict(task=task, completed_rounds=checked, complete=result['complete'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('phase', choices=('guard', 'evaluation'))
    ap.add_argument('--lab', type=Path, default=ROOT / 'artifacts/revision-head-cusum-gate-v1')
    a = ap.parse_args(); lab = a.lab; folder = lab / a.phase
    protocol = read(folder / 'protocol-before-training.json')
    closure = read(folder / 'training-complete.json')
    base.require(closure['protocol_sha256'] == sha256_file(folder / 'protocol-before-training.json'), 'closure pin')
    base.require(len(closure['results']) == len(protocol['tasks']), 'incomplete phase')
    model_sha = sha256_file(lab / 'models/head-cusum.json')
    base.require(model_sha == protocol['head_model_sha256'], 'model pin')
    out = folder / 'verified/summary.json'
    base.require(not out.exists(), 'phase already verified')
    model, deps = read(lab / 'models/head-cusum.json'), dependencies()
    settings = base.settings_for(protocol)
    cases = []
    for r in closure['results']:
        res = audit_case(lab, a.phase, r, model, model_sha, protocol['runtime_admission'], deps, settings)
        cases.append(res)
        print('VERIFIED ' + json.dumps(dict(case=r['task']['name'], rounds=res['completed_rounds'])), flush=True)
    save(out, dict(status='verified', phase=a.phase, verifier_sha256=sha256_file(Path(__file__)),
                   training_closure_sha256=sha256_file(folder / 'training-complete.json'), test_accessed=False,
                   rounds_reconstructed=sum(c['completed_rounds'] for c in cases), cases=cases))
    print('PHASE_VERIFIED ' + json.dumps(dict(phase=a.phase, cases=len(cases),
                                              rounds=sum(c['completed_rounds'] for c in cases))), flush=True)


if __name__ == '__main__':
    main()
