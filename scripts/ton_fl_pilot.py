"""ToN-IoT feasibility pilot (NOT evidence for any hypothesis).

Questions: does clean FedAvg from the ToN warm start reach a usable model, and
does the transferred DBA (trigger features 13/17/24 at 12 standard units, target
'benign' = evasion) take hold under TPM-only? Two assignments (IID, Dirichlet 0.3),
four conditions, TPM-only FedAvg, 15 rounds (attack rounds 1-10). Validation only;
the test split is not opened.
Usage: ton_fl_pilot.py [--workers N]
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import revision_gate_trajectories as base  # numeric environment first
from revision_study_data import read
from revision_dba_experiment import save, environment
from fl_forensics.canonical import sha256_file

ROOT = base.ROOT
DATA = ROOT / 'artifacts/ton-fl-gate-v1'
LAB = DATA / 'pilot'
SEEDS = [('iid', 2027200001), ('non-iid', 2027201001)]
ATTACKERS = ['client03', 'client08', 'client12']


def training_cfg():
    m = read(DATA / 'data/manifest.json')
    template = read(ROOT / 'artifacts/revision-head-gate-v2/protocol-before-fitting.json')['training']
    cfg = dict(template)
    cfg.update(base_model_path=str(DATA / 'base-model.json'), base_model_sha256=m['base_model_sha256'],
               validation_path=str(DATA / 'data/validation.json'), validation_sha256=m['pins']['validation'],
               partition_workspace=str(DATA), partition_manifest_sha256=None, clean_reference_workspace=None,
               clean_reference_manifest_sha256=None, dataset='ToN-IoT host/minute windows (binary)')
    return cfg, m


def build_partitions(cfg, m):
    rows = read(DATA / 'data/fl-pool.json')['rows']['train']
    parts = {}
    for cohort, seed in SEEDS:
        folder = LAB / 'partitions' / str(seed)
        allocation = (base._iid_assignments(rows, client_count=15, seed=seed, np=base.np) if cohort == 'iid' else
                      base._dirichlet_assignments(rows, client_count=15, seed=seed, alpha=.3, minimum_rows=32, np=base.np))
        clients = []
        for i, part in enumerate(allocation):
            client = f'client{i+1:02d}'; path = folder / 'clients' / client / 'dataset.json'
            save(path, dict(client_id=client, partition_id=i, class_names=m['class_names'], rows={'train': part}))
            clients.append(dict(client_id=client, partition_id=i, dataset_path=str(path.relative_to(folder)),
                                dataset_sha256=sha256_file(path), train_row_count=len(part)))
        save(folder / 'manifest.json', dict(profile='ton-pilot-allocation', seed=seed, partition_mode=cohort, class_names=m['class_names'],
                                            global_class_weights=m['global_class_weights'], clients=clients))
        parts[str(seed)] = sha256_file(folder / 'manifest.json')
    return parts


def worker(task):
    base.LAB = LAB
    base.assert_locks = lambda protocol: None  # pilot only: not evidence
    base.POLICIES = ('tpm_only', 'sequential', 'gated_composite')
    return base.run_case(task)


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--workers', type=int, default=2)
    a = ap.parse_args()
    if not (LAB / 'protocol-before-training.json').exists():
        cfg, m = training_cfg(); LAB.mkdir(parents=True)
        parts = build_partitions(cfg, m)
        tasks = [dict(name=f'{c}-s{s}-tpm_only-{mode}', cohort=c, seed=s, attackers=ATTACKERS, policy='tpm_only', mode=mode)
                 for c, s in SEEDS for mode in base.MODES]
        runtime = read(ROOT / 'artifacts/revision-head-gate-v2/protocol-before-fitting.json')['runtime_admission']
        save(LAB / 'protocol-before-training.json', dict(profile='ton-fl-pilot', NOT_EVIDENCE=True, tasks=tasks, training=cfg,
             runtime_admission=runtime, partitions=parts, environment=environment(), source_locks={}))
    p = read(LAB / 'protocol-before-training.json')
    results = []
    with ProcessPoolExecutor(max_workers=a.workers, mp_context=multiprocessing.get_context('spawn')) as pool:
        futs = {pool.submit(worker, t): t for t in p['tasks']}
        for f in as_completed(futs):
            t = futs[f]
            try:
                r = f.result(); results.append(r)
            except Exception as exc:
                r = dict(task=t, complete=False, error=f'{type(exc).__name__}: {exc}')
            print('PILOT_CASE ' + json.dumps(dict(task=t['name'], complete=r.get('complete'), error=r.get('error'))), flush=True)
    summary = []
    for t in p['tasks']:
        rows = []
        for n in range(1, 16):
            path = LAB / 'cases' / t['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json'
            if path.exists():
                v = read(path)['validation']
                rows.append(dict(round=n, f1=round(v['clean']['macro_f1_all_model_classes'], 4),
                                 full_asr=round(v['complete_trigger']['asr'], 4),
                                 worst_component=round(max(c['asr'] for c in v['component_triggers'].values()), 4)))
        summary.append(dict(task=t['name'], rounds=rows))
    (LAB / 'pilot-summary.json').write_text(json.dumps(summary, indent=1))
    for s in summary:
        r = s['rounds']
        if r:
            print(f"{s['task']:36} F1 r1={r[0]['f1']:.3f} r10={r[min(9,len(r)-1)]['f1']:.3f} r15={r[-1]['f1']:.3f} | "
                  f"peak full ASR={max(x['full_asr'] for x in r):.3f} final={r[-1]['full_asr']:.3f} peak comp={max(x['worst_component'] for x in r):.3f}")


if __name__ == '__main__':
    main()
