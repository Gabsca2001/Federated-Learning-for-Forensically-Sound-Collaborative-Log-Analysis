"""Predeclared live study: behavioural trigger-probe gate + per-tensor clipping.

Arms: tpm_only+fedavg (reference), tpm_only+bounded, probe+bounded.
Variants: clean, distributed, complete-trigger, adaptive (the adaptive attacker's search
scores candidates after the complete defence, i.e. probe decisions and clipping).
Probe: unchanged single-feature probe (trigger_probe_gate.py) on the server's validation
attack rows; threshold = clean maximum per cohort from verified clean histories
(results/revision-trigger-probe-thresholds/thresholds.json, pinned). No fitting here.
Stages: prepare -> guard (clean; revised rule) -> guard-decide -> evaluation; smoke.
Software trust assumption; no new TPM Quotes.
"""
from __future__ import annotations

import argparse
import copy
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_head_v2_study as v2
import clean_gate_calibration as cal
import trigger_probe_gate as tp
from revision_study_data import read, Generator
from revision_dba_experiment import save, authenticate, environment
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
LAB = ROOT / 'artifacts/revision-trigger-probe-live'
THRESHOLDS_FILE = ROOT / 'results/revision-trigger-probe-thresholds/thresholds.json'
ORIGINAL_CONTEXT, ORIGINAL_STATE = base.context, base.gate_state
GATE_POLICIES = ('tpm_only', 'sequential', 'gated_composite', tp.POLICY)
ARMS = ('tpm_only+fedavg', 'tpm_only+bounded', 'probe+bounded')
REFERENCE_ARM = 'tpm_only+fedavg'
VARIANTS = ('clean', 'distributed', 'complete-trigger', 'adaptive')
STAGES = {
    'guard': [('iid', 2027500001), ('iid', 2027501001), ('non-iid', 2027502001), ('non-iid', 2027503001)],
    'evaluation': [('iid', 2027510001 + 1000 * k) for k in range(4)] + [('non-iid', 2027520001 + 1000 * k) for k in range(4)],
}
PRIOR = (*v2.PRIOR_PARTITION_ROOTS, 'revision-head-gate-v2', 'revision-head-gate-v2-confirm')
HYPOTHESES = [
    dict(id='P1_probe_adds_to_clipping', a='probe+bounded', b='tpm_only+bounded', variants=['distributed', 'complete-trigger', 'adaptive'],
         text='probe+bounded lower paired peak harm than clipping alone (majority of defined comparisons)'),
    dict(id='P2_dba', a='probe+bounded', b='tpm_only+bounded', variants=['distributed', 'complete-trigger'],
         text='same restricted to DBA (the attack the probe targets)'),
    dict(id='P3_vs_reference', a='probe+bounded', b='tpm_only+fedavg', variants=['distributed', 'complete-trigger', 'adaptive'], only_effective=True,
         text='probe+bounded lower paired peak harm than TPM-only FedAvg in effective controls'),
]
GUARD = dict(maximum_quarantine_rate=.05, minimum_nominal_mass_retention=.90, maximum_consecutive_rounds_excluded=1,
             maximum_fixed_endpoint_validation_f1_loss=.02)


def source_locks():
    paths = sorted((ROOT / 'src/fl_forensics').glob('*.py'))
    paths += [ROOT / 'scripts' / n for n in ('revision_gate_trajectories.py', 'revision_study_data.py', 'revision_dba_experiment.py',
              'clean_gate_calibration.py', 'factorial_aggregators.py', 'head_cusum_gate.py', 'revision_head_cusum_study.py',
              'head_gate_steps.py', 'revision_head_v2_study.py', 'trigger_probe_gate.py', 'revision_probe_study.py')]
    paths += [ROOT / 'configs/in-round-admission.yaml', THRESHOLDS_FILE]
    return {str(p.relative_to(ROOT)): sha256_file(p) for p in paths}


def assert_locks(protocol):
    base.require(source_locks() == protocol['source_locks'], 'Locked probe study source changed')
    for c, pin in protocol['tensor_bounds'].items():
        base.require(sha256_file(ROOT / pin['path']) == pin['sha256'], 'Tensor bounds changed')


def context(protocol, task):
    gen, rows, correct = ORIGINAL_CONTEXT(protocol, task)
    gen.gate_cohort = task['cohort']; gen.head_frozen = False
    gen.tensor_bounds = read(ROOT / protocol['tensor_bounds'][task['cohort']]['path'])
    gen.probe_threshold = float(protocol['probe']['thresholds'][task['cohort']])
    gen.probe_stack, gen.probe_keys, gen.probe_n = tp.probe_inputs(rows)
    gen.benign_index = gen.initial['class_names'].index('benign')
    return gen, rows, correct


def gate_state(initial, exports, gen, settings, rows):
    state, arrays = ORIGINAL_STATE(initial, exports, gen, settings, rows)
    per = {c: tp.shortcuts(_model_from_export(e, torch=gen.torch, np=np), gen.probe_stack, gen.probe_keys, gen.probe_n,
                           gen.benign_index, gen.torch) for c, e in zip(gen.clients, exports)}
    scores = tp.round_scores(per)
    decisions = tp.decide(scores, gen.probe_threshold, trust_admissible=base.TRUST.admissible)
    for c in gen.clients:
        state['decisions'][c][tp.POLICY] = decisions[c]
        for arm in ARMS:
            state['decisions'][c][arm] = copy.deepcopy(state['decisions'][c][arm.split('+')[0]])
    state['probe'] = dict(threshold=gen.probe_threshold, cohort=gen.gate_cohort,
                          score={c: scores[c][0] for c in gen.clients}, best={c: scores[c][1] for c in gen.clients})
    return state, arrays


def configure(phase_dir):
    base.LAB = Path(phase_dir)
    base.context, base.gate_state, base.numerical, base.assert_locks = context, gate_state, v2.numerical, assert_locks
    base.POLICIES = GATE_POLICIES


def worker(task, phase_dir, lab):
    global LAB
    LAB = Path(lab); configure(phase_dir)
    return base.run_case(task)


def prepare():
    base.require(not LAB.exists(), 'Preserve existing probe study')
    clean_root = read(v2.hs.CLEAN_SOURCE / 'protocol-before-clean-fitting.json')
    source = ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1'; manifest = read(source / 'manifest.json')
    union, seen = [], set()
    for record in manifest['clients']:
        path = source / record['dataset_path']; base.require(sha256_file(path) == record['dataset_sha256'], 'Changed snapshot')
        for row in read(path)['rows']['train']:
            base.require(row['window_id'] not in seen, 'Duplicate'); seen.add(row['window_id']); union.append(row)
    v2.PRIOR_PARTITION_ROOTS = PRIOR; prior = v2.prior_signatures()
    LAB.mkdir(parents=True); partitions, sigs, attackers = {}, {}, {}
    for stage, rows in STAGES.items():
        for cohort, seed in rows:
            alloc = (base._iid_assignments(union, client_count=15, seed=seed, np=base.np) if cohort == 'iid' else
                     base._dirichlet_assignments(union, client_count=15, seed=seed, alpha=.3, minimum_rows=32, np=base.np))
            base.require({r['window_id'] for rs in alloc for r in rs} == seen, 'Coverage')
            folder = LAB / 'partitions' / str(seed); clients = []
            for i, part in enumerate(alloc):
                client = f'client{i+1:02d}'; path = folder / 'clients' / client / 'dataset.json'
                save(path, dict(client_id=client, partition_id=i, class_names=manifest['class_names'], rows={'train': part}))
                clients.append(dict(client_id=client, partition_id=i, dataset_path=str(path.relative_to(folder)),
                                    dataset_sha256=sha256_file(path), train_row_count=len(part)))
            m = dict(profile='probe-live-allocation', seed=seed, partition_mode=cohort, dirichlet_alpha=.3 if cohort == 'non-iid' else None,
                     class_names=manifest['class_names'], global_class_weights=manifest['global_class_weights'], clients=clients,
                     training_occurrences=len(seen), M3_full_profile_verification_claimed=False)
            sig = v2.partition_signature(m)
            base.require(sig not in sigs.values() and sig not in prior, f'Duplicated partition {seed}')
            sigs[seed] = sig; save(folder / 'manifest.json', m); partitions[str(seed)] = sha256_file(folder / 'manifest.json')
            if stage == 'evaluation':
                attackers[str(seed)] = [f'client{i+1:02d}' for i in sorted(np.random.default_rng(seed).choice(15, 3, replace=False).tolist())]
    share = {}
    for s, att in attackers.items():
        cl = read(LAB / 'partitions' / s / 'manifest.json')['clients']; tot = sum(c['train_row_count'] for c in cl)
        share[s] = sum(c['train_row_count'] for c in cl if c['client_id'] in att) / tot
    thr = read(THRESHOLDS_FILE)['max']['thresholds']
    bounds = {c: dict(path=str(p.relative_to(ROOT)), sha256=sha256_file(p)) for c, p in v2.BOUNDS.items()}
    protocol = dict(
        profile='trigger-probe-live-study', stages=STAGES, attackers=attackers, attacker_data_share=share, arms=ARMS,
        reference_arm=REFERENCE_ARM, variants=VARIANTS, hypotheses=HYPOTHESES, guard_rule=GUARD,
        training=clean_root['training'], runtime_admission=clean_root['runtime_admission'], partitions=partitions,
        source_snapshots=clean_root['source_snapshots'], source_locks=source_locks(), environment=environment(), tensor_bounds=bounds,
        probe=dict(values=list(tp.VALUES), thresholds=thr, threshold_rule='clean maximum per cohort (zero honest flags in development)',
                   thresholds_file=str(THRESHOLDS_FILE.relative_to(ROOT)), thresholds_sha256=sha256_file(THRESHOLDS_FILE),
                   development='results/revision-trigger-probe-dev (detection, generality, evasion); results/revision-trigger-probe-thresholds'),
        partition_distinctness='checked within study and against surviving earlier gate studies; retired v1/factorial partitions cannot be compared',
        endpoints='Paired worst-trigger peak harm; full/component peak and final test ASR; clean F1; failures undefined; attacker data share.',
        promotion='No automatic promotion. Seed is the repetition unit; one dataset (Data24).', new_TPM_Quotes=0)
    save(LAB / 'protocol-before-guard.json', protocol)
    (LAB / 'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print('PREPARED ' + json.dumps(dict(protocol_sha256=sha256_file(LAB / 'protocol-before-guard.json'), thresholds=thr, attacker_share=share)), flush=True)


def make_tasks(phase):
    tasks = []
    if phase == 'guard':
        for cohort, seed in STAGES['guard']:
            for arm in ARMS:
                tasks.append(dict(name=f'{cohort}-s{seed}-{arm}-clean', cohort=cohort, seed=seed,
                                  attackers=['client01', 'client06', 'client11'], policy=arm, mode='clean', variant='clean'))
        return tasks
    decision = read(LAB / 'guard-decision.json'); arms = [a for a in ARMS if a == REFERENCE_ARM or a in decision['qualified_arms']]
    p = read(LAB / 'protocol-before-guard.json')
    for cohort, seed in STAGES['evaluation']:
        for arm in arms:
            for v in VARIANTS:
                tasks.append(dict(name=f'{cohort}-s{seed}-{arm}-{v}', cohort=cohort, seed=seed, attackers=p['attackers'][str(seed)],
                                  policy=arm, mode='adaptive' if v == 'adaptive' else v, variant=v))
    return tasks


def phase_protocol(phase):
    folder = LAB / phase; path = folder / 'protocol-before-training.json'
    if path.exists():
        p = read(path); assert_locks(p); return p
    root = read(LAB / 'protocol-before-guard.json'); assert_locks(root)
    folder.mkdir(); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    p = {**root, 'phase': phase, 'tasks': make_tasks(phase),
         'guard_decision_sha256': sha256_file(LAB / 'guard-decision.json') if phase == 'evaluation' else None}
    save(path, p); return p


def run_phase(phase, workers):
    folder = LAB / phase; protocol = phase_protocol(phase)
    if (folder / 'training-complete.json').exists():
        closed = read(folder / 'training-complete.json')
        for r in closed['results']:
            authenticate(folder / 'cases' / r['task']['name'] / 'evidence', r['manifest_sha256'])
        return closed
    results = []
    with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context('spawn')) as pool:
        futures = {pool.submit(worker, t, str(folder), str(LAB)): t for t in protocol['tasks']}
        for future in as_completed(futures):
            task = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                case = folder / 'cases' / task['name']; evidence = case / 'evidence'
                error = dict(task=task, complete=False, error=str(exc), exception_type=type(exc).__name__)
                save(evidence / 'terminal-exception.json', error)
                if not (evidence / 'manifest.json').exists():
                    Generator.close(evidence)
                result = {**error, 'completed_rounds': len(list(evidence.glob('rounds/round-*/round.json'))),
                          'manifest_sha256': sha256_file(evidence / 'manifest.json')}
                if not (case / 'result.json').exists():
                    save(case / 'result.json', result)
            results.append(result)
            (folder / 'progress.json').write_text(json.dumps(dict(terminal_cases=len(results), planned_cases=len(protocol['tasks']),
                complete_cases=sum(r['complete'] for r in results)), sort_keys=True) + '\n')
            print('PHASE_CASE ' + json.dumps(dict(phase=phase, task=task['name'], complete=result['complete'])), flush=True)
    assert_locks(protocol)
    closed = dict(protocol_sha256=sha256_file(folder / 'protocol-before-training.json'),
                  results=sorted(results, key=lambda r: r['task']['name']), test_inference_performed=False)
    save(folder / 'training-complete.json', closed); return closed


def guard_decide():
    base.require((LAB / 'guard/training-complete.json').exists() and (LAB / 'guard/verified/summary.json').exists(), 'Guard closed+verified first')
    base.require(not (LAB / 'guard-decision.json').exists(), 'Guard decision exists')
    closed = read(LAB / 'guard/training-complete.json'); by = {(r['task']['seed'], r['task']['policy']): r for r in closed['results']}
    details, qualified = {}, []
    for arm in ARMS:
        rows = []
        for cohort, seed in STAGES['guard']:
            res, ref = by[(seed, arm)], by[(seed, REFERENCE_ARM)]
            entry = dict(cohort=cohort, seed=seed, complete=bool(res['complete'] and ref['complete']), qualified=False)
            if entry['complete']:
                sizes = {r['client_id']: r['train_row_count'] for r in read(LAB / 'partitions' / str(seed) / 'manifest.json')['clients']}
                summaries, losses, excluded = [], [], []
                for n in range(1, 16):
                    row = read(LAB / 'guard/cases' / res['task']['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json')
                    summaries.append(dict(statuses=row['statuses'], masses=row['masses'], example_counts=sizes))
                    excluded.append({c for c, s in row['statuses'].items() if s.endswith('quarantined')})
                    if n in (10, 15):
                        other = read(LAB / 'guard/cases' / ref['task']['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json')
                        losses.append(other['validation']['clean']['macro_f1_all_model_classes'] - row['validation']['clean']['macro_f1_all_model_classes'])
                longest = 0
                for c in sizes:
                    run_len = 0
                    for ex in excluded:
                        run_len = run_len + 1 if c in ex else 0; longest = max(longest, run_len)
                b = cal.budget_summary(summaries)
                entry.update(budget=b, validation_losses=losses, longest_consecutive_exclusion=longest, qualified=bool(
                    b['quarantine_rate'] <= GUARD['maximum_quarantine_rate'] and b['nominal_mass_retention'] >= GUARD['minimum_nominal_mass_retention']
                    and longest <= GUARD['maximum_consecutive_rounds_excluded'] and max(losses) <= GUARD['maximum_fixed_endpoint_validation_f1_loss']))
            rows.append(entry)
        details[arm] = rows
        if all(r['qualified'] for r in rows):
            qualified.append(arm)
    save(LAB / 'guard-decision.json', dict(qualified_arms=qualified, rule=GUARD, details=details, uses_attack_or_test_outcomes=False,
                                           guard_closure_sha256=sha256_file(LAB / 'guard/training-complete.json')))
    print('GUARD ' + json.dumps(dict(qualified_arms=qualified)), flush=True)


def smoke(folder):
    import builtins
    folder = Path(folder); base.require(not folder.exists(), 'Smoke folder must be new')
    root = read(LAB / 'protocol-before-guard.json'); assert_locks(root)
    folder.mkdir(parents=True); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    cohort, seed = STAGES['evaluation'][4]
    tasks = [dict(name=f'smoke-{a}-{v}', cohort=cohort, seed=seed, attackers=root['attackers'][str(seed)], policy=a,
                  mode='adaptive' if v == 'adaptive' else v, variant=v)
             for a, v in (('probe+bounded', 'distributed'), ('probe+bounded', 'adaptive'), ('tpm_only+bounded', 'complete-trigger'), ('probe+bounded', 'clean'))]
    save(folder / 'protocol-before-training.json', {**root, 'phase': 'smoke', 'tasks': tasks, 'NOT_EVIDENCE': True})
    base.range = lambda *x: builtins.range(1, 3) if x == (1, 16) else builtins.range(*x)
    try:
        configure(folder)
        for t in tasks:
            r = base.run_case(t)
            st = read(folder / 'cases' / t['name'] / 'evidence/rounds/round-002/gate-state.json')
            flagged = {c: st['probe']['best'][c] for c, d in st['decisions'].items() if not d['probe']['contributes']}
            print('SMOKE ' + json.dumps(dict(task=t['name'], rounds=r['completed_rounds'], attackers=t['attackers'], probe_flagged=flagged)), flush=True)
    finally:
        del base.range


def main():
    global LAB
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('prepare', 'guard', 'guard-decide', 'evaluation', 'smoke'))
    ap.add_argument('--workers', type=int, default=2); ap.add_argument('--lab', type=Path, default=LAB); ap.add_argument('--smoke-dir', type=Path)
    a = ap.parse_args(); LAB = a.lab
    {'prepare': prepare, 'guard': lambda: run_phase('guard', a.workers), 'guard-decide': guard_decide,
     'evaluation': lambda: run_phase('evaluation', a.workers), 'smoke': lambda: smoke(a.smoke_dir)}[a.command]()


if __name__ == '__main__':
    main()
