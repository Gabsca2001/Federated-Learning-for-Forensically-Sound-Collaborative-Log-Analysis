"""Test-phase evaluation of closed, verified gate studies (head-CUSUM, factorial).

Refuses to run unless the evaluation phase is closed AND independently verified.
Writes a precommit (pins, time) before the test split is read, then evaluates
every saved global checkpoint of every case on the pinned test split. No model,
threshold or decision is changed; this only measures fixed checkpoints.

Usage: revision_head_cusum_test.py [--lab PATH] [--workers N]
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import revision_gate_trajectories as base  # numeric environment first
from revision_study_data import read, dependencies
from revision_dba_experiment import save, authenticate, outcomes, predict, read_pinned
from fl_forensics.canonical import sha256_file

ROOT = base.ROOT
SOURCE = ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1'


def test_rows(protocol):
    manifest_path = SOURCE / 'manifest.json'
    base.require(sha256_file(manifest_path) == protocol['source_snapshots'][str(manifest_path)], 'Evaluation manifest pin')
    split = read(manifest_path)['server_evaluation_splits']['test']
    path = SOURCE / split['path']
    base.require(sha256_file(path) == split['sha256'], 'Test pin')
    return read(path)['rows']['test'], dict(path=str(path.relative_to(ROOT)), sha256=split['sha256'])


def evaluate_case(lab, result, phase='evaluation'):
    folder = Path(lab) / phase
    protocol = read(folder / 'protocol-before-training.json'); task = result['task']
    evidence = folder / 'cases' / task['name'] / 'evidence'
    authenticate(evidence, result['manifest_sha256'])
    deps = dependencies()
    rows, _ = test_rows(protocol)
    cfg = protocol['training']
    initial = read_pinned(cfg['base_model_path'], cfg['base_model_sha256'])
    part = read(Path(lab) / 'partitions' / str(task['seed']) / 'manifest.json')
    train_ids = set()
    for r in part['clients']:
        train_ids |= {x['window_id'] for x in read(Path(lab) / 'partitions' / str(task['seed']) / r['dataset_path'])['rows']['train']}
    base.require(not ({r['window_id'] for r in rows} & train_ids), 'Train/test overlap')
    predicted, _ = predict(initial, rows, deps)
    correct = [p == r['label'] for p, r in zip(predicted, rows, strict=True)]
    plan = base.make_plan(protocol, task)
    out = []
    for number in range(1, result.get('completed_rounds', 0) + 1):
        rd = evidence / 'rounds' / f'round-{number:03d}'
        model = read(rd / 'global-model.json'); row = read(rd / 'round.json')
        base.require(base.digest(model) == row['global_model_sha256'], 'checkpoint binding')
        out.append(dict(round=number, test=outcomes(model, rows, plan, correct, deps)))
    return dict(task=task, complete=result['complete'], completed_rounds=result.get('completed_rounds', 0),
                failure=result.get('failure'), source_manifest_sha256=result['manifest_sha256'], rounds=out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab', type=Path, default=ROOT / 'artifacts/revision-head-cusum-gate-v1')
    ap.add_argument('--workers', type=int, default=2)
    ap.add_argument('--phase', default='evaluation')
    a = ap.parse_args(); folder = a.lab / a.phase
    closure_path = folder / 'training-complete.json'
    base.require(closure_path.exists(), 'Evaluation training has not closed')
    verified = read(folder / 'verified/summary.json')
    base.require(verified['status'] == 'verified' and verified['training_closure_sha256'] == sha256_file(closure_path),
                 'Evaluation not independently verified against this closure')
    out_dir = folder / 'test'
    base.require(not out_dir.exists(), 'Test phase already opened; results are write-once')
    protocol = read(folder / 'protocol-before-training.json')
    manifest_path = SOURCE / 'manifest.json'
    base.require(sha256_file(manifest_path) == protocol['source_snapshots'][str(manifest_path)], 'Evaluation manifest pin')
    split = read(manifest_path)['server_evaluation_splits']['test']  # pin only; rows are not read yet
    out_dir.mkdir()
    save(out_dir / 'precommit-before-test.json', dict(
        opened_at=datetime.now(timezone.utc).isoformat(), test_split=dict(path=split['path'], sha256=split['sha256']),
        training_closure_sha256=sha256_file(closure_path),
        verification_sha256=sha256_file(folder / 'verified/summary.json'),
        evaluator_sha256=sha256_file(Path(__file__)), no_parameter_change_after_test=True))
    closure = read(closure_path)
    done = []
    with ProcessPoolExecutor(max_workers=a.workers, mp_context=multiprocessing.get_context('spawn')) as pool:
        futures = {pool.submit(evaluate_case, str(a.lab), r, a.phase): r for r in closure['results']}
        for f in as_completed(futures):
            res = f.result()
            save(out_dir / 'cases' / f"{res['task']['name']}.json", res); done.append(res['task']['name'])
            print('TESTED ' + json.dumps(dict(case=res['task']['name'], rounds=len(res['rounds']))), flush=True)
    save(out_dir / 'summary.json', dict(status='tested', cases=sorted(done), evaluator_sha256=sha256_file(Path(__file__)),
                                        training_closure_sha256=sha256_file(closure_path)))


if __name__ == '__main__':
    main()
