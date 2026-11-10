"""Independent reconstruction of the gate x aggregation factorial phases.

Reuses the head-CUSUM verifier (head features, CUSUM chain, candidate and
original decisions, masses) and replaces the aggregate rebuild with the arm's
operator: Flower FedAvg, per-tensor clipped bounded aggregation, or trimmed
mean, recomputed from saved base model and updates with the pinned clean bounds.
Usage: revision_gate_aggregation_audit.py PHASE [--lab PATH]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import revision_gate_trajectories as base  # numeric environment first
import revision_head_cusum_audit as au
import factorial_aggregators as fa
from revision_study_data import read, dependencies
from revision_dba_experiment import save, model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

ROOT = base.ROOT
HEAD_LAB = ROOT / 'artifacts/revision-head-cusum-gate-v1'


def make_rebuild(protocol):
    bounds = {c: read(ROOT / pin['path']) for c, pin in protocol['tensor_bounds'].items()}

    def rebuild(initial, exports, clients, masses, task, runtime, deps):
        operator = task['policy'].split('+')[1]
        if operator == 'fedavg':
            return au.fedavg_rebuild(initial, exports, clients, masses, task, runtime, deps)
        base_arrays = arrays_from_export(initial, np=base.np)
        updates = {c: arrays_from_export(e, np=base.np) for c, e in zip(clients, exports)}
        if operator == 'bounded':
            b = bounds[task['cohort']]
            params, _ = fa.bounded(base_arrays, updates, masses, b['limits'], b, runtime['minimum_contributors'])
        else:
            params, _ = fa.trimmed_mean(base_arrays, updates, {c: masses[c] > 0 for c in clients})
        return model_with_arrays(initial, params) if params is not None else None
    return rebuild


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('phase', choices=('guard', 'evaluation'))
    ap.add_argument('--lab', type=Path, default=ROOT / 'artifacts/revision-gate-aggregation-factorial-v1')
    a = ap.parse_args(); lab = a.lab; folder = lab / a.phase
    protocol = read(folder / 'protocol-before-training.json')
    closure = read(folder / 'training-complete.json')
    base.require(closure['protocol_sha256'] == sha256_file(folder / 'protocol-before-training.json'), 'closure pin')
    base.require(len(closure['results']) == len(protocol['tasks']), 'incomplete phase')
    model_sha = sha256_file(HEAD_LAB / 'models/head-cusum.json')
    base.require(model_sha == protocol['head_model_sha256'], 'model pin')
    for c, pin in protocol['tensor_bounds'].items():
        base.require(sha256_file(ROOT / pin['path']) == pin['sha256'], 'bounds pin')
    out = folder / 'verified/summary.json'
    base.require(not out.exists(), 'phase already verified')
    model, deps, settings = read(HEAD_LAB / 'models/head-cusum.json'), dependencies(), base.settings_for(protocol)
    rebuild = make_rebuild(protocol); cases = []
    for r in closure['results']:
        res = au.audit_case(lab, a.phase, r, model, model_sha, protocol['runtime_admission'], deps, settings,
                            rebuild=rebuild, gate_of=lambda p: p.split('+')[0])
        cases.append(res)
        print('VERIFIED ' + json.dumps(dict(case=r['task']['name'], rounds=res['completed_rounds'])), flush=True)
    save(out, dict(status='verified', phase=a.phase, verifier_sha256=sha256_file(Path(__file__)),
                   base_verifier_sha256=sha256_file(Path(au.__file__)),
                   training_closure_sha256=sha256_file(folder / 'training-complete.json'), test_accessed=False,
                   rounds_reconstructed=sum(c['completed_rounds'] for c in cases), cases=cases))
    print('PHASE_VERIFIED ' + json.dumps(dict(phase=a.phase, cases=len(cases))), flush=True)


if __name__ == '__main__':
    main()
