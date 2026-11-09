"""Predeclared, software-only historical DBA intervention study.

Reexecute local training from the corrected global model at EVERY later round.
Never reuse historical updates after a branch diverges. No TPM claim is made.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import fl_forensics

from revision_dba_experiment import (
    authenticate, environment, model_with_arrays, outcomes, predict, read_pinned, save,
)
from fl_forensics.byzantine import aggregate_deltas, apply_delta, model_delta
from fl_forensics.canonical import sha256_bytes, sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan, poison_local_rows
from fl_forensics.federated_model import arrays_from_export, dependencies, export_state, train_local
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _model_from_export

SEEDS = (341593, 342593, 343593)
BRANCHES = ('control', 'remove-single-history', 'remove-group-history', 'clean-matched-single')
GROUP = ('client01', 'client06', 'client11')


def omitted(branch, number):
    if number > 10:
        return set()
    return {'client01'} if branch in ('remove-single-history', 'clean-matched-single') else set(GROUP) if branch in ('remove-group-history',) else set()


def read(path):
    return json.loads(path.read_bytes())


def protocol(source):
    pins = {}
    for seed in SEEDS:
        for mode in ('distributed', 'clean'):
            name = f'{mode}-s{seed}'
            creation = read(source / 'reports' / f'{name}.json')['creation']
            workspace = source / name
            assert sha256_file(workspace / 'experiment-authority.public.pem') == creation['public_key_sha256']
            authenticate(workspace, creation['manifest_sha256'])
            pins[name] = creation
    package = Path(fl_forensics.__file__).parent
    files = {str(p.resolve()): sha256_file(p) for p in sorted(package.glob('*.py'))}
    files[str(Path(__file__).resolve())] = sha256_file(Path(__file__))
    import revision_dba_experiment
    runner = Path(revision_dba_experiment.__file__)
    files[str(runner.resolve())] = sha256_file(runner)
    return {
        'profile': 'historical-DBA-full-retraining-interventions-v1',
        'seeds': list(SEEDS), 'branches': list(BRANCHES), 'source_pins': pins,
        'implementation_files': files, 'environment': environment(),
        'primary_endpoint': 10, 'persistence_endpoint': 15,
        'selection': 'All three previously used seeds; retrospective development study, not an untouched test.',
        'omission_schedule': {b: {str(n): sorted(omitted(b, n)) for n in range(1, 16)} for b in BRANCHES},
        'clean_matched_group': 'Same participation as single removal; all surviving local rows remain clean. Removed client returns clean at round 11.',
        'intervention_origin': 'Known experimental identities; no automatic collusion detection is claimed.',
        'fixed_training': 'Original warm checkpoint, 15 rounds, local Adam 10 epochs, deterministic per-client seeds, FedAvg delta recurrence.',
        'control_requirement': 'Every control local model and global model must equal the stored original bytes at every round, or stop.',
        'evaluation': 'Entire previously used validation set, full and component triggers, untriggered target rate, clean accuracy and macro-F1; no test selection.',
        'fresh_TPM_attestation': False,
    }


def run(source, output, declared):
    deps = dependencies()
    torch = deps[1]
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    for seed in SEEDS:
        original = source / f'distributed-s{seed}'
        cfg = read(original / 'protocol-before-training.json')
        partition_root = Path(cfg['partition_workspace'])
        partition = read_pinned(partition_root / 'manifest.json', cfg['partition_manifest_sha256'])
        initial = read_pinned(cfg['base_model_path'], cfg['base_model_sha256'])
        evaluation = read_pinned(cfg['validation_path'], cfg['validation_sha256'])
        rows = evaluation['rows']['validation']
        records = {r['client_id']: r for r in partition['clients']}
        snapshots = {c: read_pinned(partition_root / r['dataset_path'], r['dataset_sha256'])['rows']['train'] for c, r in records.items()}
        ids = [r['window_id'] for values in snapshots.values() for r in values]
        assert len(set(ids)) == len(ids) and not set(ids) & {r['window_id'] for r in rows}
        plan = DistributedBackdoorPlan.model_validate(cfg['attack_plan'])
        assert cfg['recurrence'] == 'fedavg' and cfg['rounds'] == 15 and plan.attack_rounds == list(range(1, 11))
        predicted, _ = predict(initial, rows, deps)
        reference_correct = [p == r['label'] for p, r in zip(predicted, rows, strict=True)]
        weights = {c: float(partition['global_class_weights'][c]) for c in initial['class_names']}
        for branch in BRANCHES:
            base = initial
            for number in range(1, 16):
                prefix = output / f'seed-{seed}' / branch / f'round-{number:03d}'
                # Resume only a fully closed, hash-checked round under this exact protocol.
                if (prefix / 'record.json').exists():
                    record = read(prefix / 'record.json')
                    assert record['protocol_sha256'] == sha256_file(output / 'protocol-before-training.json')
                    assert record['base_model_sha256'] == sha256_bytes(derived_json_bytes(base))
                    for name, digest in record['artifacts'].items():
                        assert sha256_file(prefix / name) == digest
                    base = read(prefix / 'global-model.json')
                    continue
                start = time.monotonic()
                base_arrays = arrays_from_export(base, np=np)
                selected = sorted(set(records) - omitted(branch, number))
                models, counts, poison_records = [], [], []
                for client in selected:
                    local_rows, poisoning = poison_local_rows(rows=snapshots[client], plan=plan,
                        client_id=client, round_number=number, distributed=True)
                    if branch == 'clean-matched-single':
                        local_rows = snapshots[client]
                        poisoning = {'client_id': client, 'round_number': number, 'poisoned_window_ids': [], 'clean_matched_control': True}
                    local_model = _model_from_export(base, torch=torch, np=np)
                    train_seed = seed + number * 10000 + int(records[client]['partition_id'])
                    train_local(model=local_model, rows=local_rows, class_names=base['class_names'],
                        class_weights=weights, epochs=cfg['local_epochs'], batch_size=cfg['batch_size'],
                        learning_rate=cfg['learning_rate'], seed=train_seed, device_name='cpu', torch=torch, np=np)
                    local = export_state(local_model, architecture=base['architecture'], class_names=base['class_names'])
                    if branch == 'control':
                        assert derived_json_bytes(local) == (original / 'rounds' / f'round-{number:03d}' / 'updates' / f'{client}.json').read_bytes(), (seed, number, client, 'control local mismatch')
                    save(prefix / 'updates' / f'{client}.json', local)
                    models.append(arrays_from_export(local, np=np))
                    counts.append(len(local_rows))
                    poison_records.append(poisoning)
                deltas = [model_delta(base_arrays, local) for local in models]
                arrays = apply_delta(base_arrays, aggregate_deltas(deltas, strategy='fedavg', f=0, weights=counts))
                result = model_with_arrays(base, arrays)
                if branch == 'control':
                    assert derived_json_bytes(result) == (original / 'rounds' / f'round-{number:03d}' / 'aggregates/fedavg.json').read_bytes(), (seed, number, 'control global mismatch')
                    assert poison_records == read(original / 'rounds' / f'round-{number:03d}' / 'poisoning-evaluation-only.json')
                save(prefix / 'global-model.json', result)
                save(prefix / 'poisoning.json', poison_records)
                save(prefix / 'outcomes.json', outcomes(result, rows, plan, reference_correct, deps))
                artifacts = {p.relative_to(prefix).as_posix(): sha256_file(p) for p in prefix.rglob('*') if p.is_file()}
                save(prefix / 'record.json', {'protocol_sha256': sha256_file(output / 'protocol-before-training.json'),
                    'seed': seed, 'branch': branch, 'round': number, 'selected_clients': selected,
                    'base_model_sha256': sha256_bytes(derived_json_bytes(base)), 'artifacts': artifacts,
                    'local_training_calls': len(selected), 'elapsed_seconds': time.monotonic()-start,
                    'control_byte_equality_verified': branch == 'control'})
                base = result
                print(json.dumps({'seed': seed, 'branch': branch, 'round': number, 'seconds': round(time.monotonic()-start, 2), 'asr': read(prefix/'outcomes.json')['complete_trigger']['asr']}), flush=True)
    artifacts = {p.relative_to(output).as_posix(): sha256_file(p) for p in output.rglob('*') if p.is_file() and p.name != 'closure.json'}
    save(output / 'closure.json', {'profile': declared['profile'], 'artifacts': artifacts,
        'rounds': len(SEEDS)*len(BRANCHES)*15, 'all_control_checkpoints_and_updates_byte_equal': True,
        'fresh_TPM_attestation': False, 'automatic_attacker_detection': False})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    declared = protocol(args.source)
    # This file is closed before the first new training call. Existing file must match.
    path = args.output / 'protocol-before-training.json'
    if path.exists():
        assert read(path) == declared
    else:
        save(path, declared)
    run(args.source, args.output, declared)
