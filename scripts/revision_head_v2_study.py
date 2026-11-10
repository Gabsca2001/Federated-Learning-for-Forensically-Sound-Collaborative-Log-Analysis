"""Predeclared live study of head gate v2 (step-normalized, per-round) x aggregation.

Arms: tpm_only+fedavg (reference), tpm_only+bounded, gated_composite+fedavg,
head_v2+fedavg, head_v2+bounded. Variants: clean, distributed, complete-trigger,
adaptive (+ adaptive-headfrozen for tpm_only and head_v2 arms). Adaptive attackers
query the complete defence of each arm.

Stages: prepare (partitions; refuses duplicated partitions, also vs earlier studies)
-> fit (clean-only references/thresholds) -> guard (clean, decides arms) ->
guard-decide -> evaluation. ``smoke`` is a 2-round developer check.
Software trust assumption; no new TPM Quotes. Engine reused via adapters.
"""
from __future__ import annotations

import argparse
import copy
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from fractions import Fraction
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_head_cusum_study as hs
import clean_gate_calibration as cal
import factorial_aggregators as fa
import head_cusum_gate as hg
import head_gate_steps as gs
from revision_study_data import read, Generator
from revision_dba_experiment import save, authenticate, environment
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

ROOT = base.ROOT
LAB = ROOT / 'artifacts/revision-head-gate-v2'
BOUNDS = {c: ROOT / 'artifacts/revision-bounded-influence-v1' / f'{c}-bounds.json' for c in ('iid', 'non-iid')}
ORIGINAL_CONTEXT, ORIGINAL_STATE, ORIGINAL_NUMERICAL = base.context, base.gate_state, base.numerical
GATE_POLICIES = ('tpm_only', 'sequential', 'gated_composite', gs.POLICY)
ARMS = ('tpm_only+fedavg', 'tpm_only+bounded', 'gated_composite+fedavg', 'head_v2+fedavg', 'head_v2+bounded')
REFERENCE_ARM = 'tpm_only+fedavg'
VARIANTS = ('clean', 'distributed', 'complete-trigger', 'adaptive')
HEADFROZEN_GATES = ('tpm_only', 'head_v2')
STAGES = {
    'guard': [('iid', 2027000001), ('iid', 2027001001), ('non-iid', 2027002001), ('non-iid', 2027003001)],
    'evaluation': [('iid', 2027010001 + 1000 * k) for k in range(5)] + [('non-iid', 2027020001 + 1000 * k) for k in range(5)],
}
PRIOR_PARTITION_ROOTS = ('revision-clean-gate-calibration-v1', 'revision-head-cusum-gate-v1',
                         'revision-gate-aggregation-factorial-v1', 'revision-gate-trajectories-v1', 'revision-capped-final-v1')
HYPOTHESES = [
    dict(id='H1_complementarity', a='head_v2+bounded', b='tpm_only+bounded', variants=['distributed', 'complete-trigger', 'adaptive', 'adaptive-headfrozen'],
         text='head_v2 adds protection on top of clipping: lower paired peak harm in a majority of defined attacked comparisons'),
    dict(id='H2_gate_vs_reference', a='head_v2+fedavg', b='tpm_only+fedavg', variants=['distributed', 'complete-trigger', 'adaptive', 'adaptive-headfrozen'], only_effective=True,
         text='head_v2 lowers paired peak harm vs TPM-only in effective controls (majority)'),
    dict(id='H3_vs_original_composite', a='head_v2+fedavg', b='gated_composite+fedavg', variants=['distributed', 'complete-trigger', 'adaptive'],
         text='head_v2 vs original composite (descriptive; composite failures are undefined and counted separately)'),
    dict(id='H4_headfrozen', a='head_v2+bounded', b='tpm_only+bounded', variants=['adaptive-headfrozen'],
         text='under the head-frozen evasion, head_v2+bounded keeps a benefit over clipping alone'),
]


def source_locks():
    paths = sorted((ROOT / 'src/fl_forensics').glob('*.py'))
    paths += [ROOT / 'scripts' / n for n in ('revision_gate_trajectories.py', 'revision_study_data.py', 'revision_dba_experiment.py',
              'clean_gate_calibration.py', 'head_cusum_gate.py', 'revision_head_cusum_study.py', 'factorial_aggregators.py',
              'head_gate_steps.py', 'revision_head_v2_study.py')]
    paths += [ROOT / 'configs/in-round-admission.yaml']
    return {str(p.relative_to(ROOT)): sha256_file(p) for p in paths}


def assert_locks(protocol):
    base.require(source_locks() == protocol['source_locks'], 'Locked v2 study source changed')
    if protocol.get('model_sha256'):
        base.require(sha256_file(LAB / 'models/head-v2.json') == protocol['model_sha256'], 'Bound model changed')
    for c, pin in protocol['tensor_bounds'].items():
        base.require(sha256_file(ROOT / pin['path']) == pin['sha256'], 'Tensor bounds changed')


# ---------------------------------------------------------------- adapters
def context(protocol, task):
    gen, rows, correct = ORIGINAL_CONTEXT(protocol, task)
    gen.gate_cohort = task['cohort']
    gen.head_frozen = task.get('variant') == 'adaptive-headfrozen'
    gen.v2_model = read(LAB / 'models/head-v2.json')
    base.require(sha256_file(LAB / 'models/head-v2.json') == protocol['model_sha256'], 'Model pin mismatch')
    gen.v2_model_sha256 = protocol['model_sha256']
    gen.tensor_bounds = read(ROOT / protocol['tensor_bounds'][task['cohort']]['path'])
    base.require([int(v.size) for v in arrays_from_export(gen.initial, np=base.np)] == gen.tensor_bounds['sizes'], 'Bounds schema')
    return gen, rows, correct


def gate_state(initial, exports, gen, settings, rows):
    state, arrays = ORIGINAL_STATE(initial, exports, gen, settings, rows)
    sizes = {c: len(gen.rows[c]) for c in gen.clients}
    feats = gs.features(initial, exports, gen.clients, sizes, gen.cfg['local_epochs'], gen.cfg['batch_size'])
    out = gs.decide(gen.v2_model, gen.gate_cohort, feats, trust_admissible=base.TRUST.admissible)
    for c in gen.clients:
        state['decisions'][c][gs.POLICY] = out[c]['decision']
        for arm in ARMS:
            state['decisions'][c][arm] = copy.deepcopy(state['decisions'][c][arm.split('+')[0]])
    state['head_v2'] = dict(cohort=gen.gate_cohort, model_sha256=gen.v2_model_sha256, sizes=sizes, features=feats,
                            adverse_z={c: out[c]['adverse_z'] for c in gen.clients}, score={c: out[c]['score'] for c in gen.clients})
    return state, arrays


def masses_for(gen, state, gate, settings):
    rho = Fraction(str(settings['accepted_downweight_factor'])); out = {}
    for c in gen.clients:
        d = state['decisions'][c][gate]
        out[c] = len(gen.rows[c]) * (rho if d['status'] == 'accepted_downweighted' else Fraction(int(d['contributes'])))
    return out


def numerical(initial, local_arrays, gen, state, settings, policy):
    if '+' not in policy:
        return ORIGINAL_NUMERICAL(initial, local_arrays, gen, state, settings, policy)
    gate, operator = policy.split('+')
    if operator == 'fedavg':
        return ORIGINAL_NUMERICAL(initial, local_arrays, gen, state, settings, gate)
    masses = masses_for(gen, state, gate, settings)
    if sum(m > 0 for m in masses.values()) < settings['minimum_contributors']:
        return None, masses, None
    params, report = fa.bounded(arrays_from_export(initial, np=base.np), dict(zip(gen.clients, local_arrays, strict=True)),
                                masses, gen.tensor_bounds['limits'], gen.tensor_bounds, settings['minimum_contributors'])
    state.setdefault('aggregation', {})[policy] = dict(operator='bounded', min_clipping={c: min(v) for c, v in report['clipping_factors'].items()})
    return (base.model_with_arrays(initial, params) if params is not None else None), masses, (report['coefficients'] if params is not None else None)


def configure(phase_dir):
    base.LAB = Path(phase_dir)
    base.context, base.gate_state, base.numerical, base.assert_locks = context, gate_state, numerical, assert_locks
    base.train_one = hs.train_one  # head-frozen evasion (inactive unless variant requests it)
    base.POLICIES = GATE_POLICIES


def worker(task, phase_dir, lab):
    global LAB
    LAB = Path(lab); configure(phase_dir)
    return base.run_case(task)


# ---------------------------------------------------------------- prepare / fit
def partition_signature(manifest):
    return tuple(c['dataset_sha256'] for c in manifest['clients'])


def prior_signatures():
    sigs = {}
    for name in PRIOR_PARTITION_ROOTS:
        root = ROOT / 'artifacts' / name / 'partitions'
        if root.exists():
            for d in root.iterdir():
                if (d / 'manifest.json').exists():
                    sigs[partition_signature(read(d / 'manifest.json'))] = f'{name}/{d.name}'
    return sigs


def prepare():
    base.require(not LAB.exists(), 'Preserve existing v2 study')
    clean_root = read(hs.CLEAN_SOURCE / 'protocol-before-clean-fitting.json')
    source = ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1'; manifest = read(source / 'manifest.json')
    union, seen = [], set()
    for record in manifest['clients']:
        path = source / record['dataset_path']; base.require(sha256_file(path) == record['dataset_sha256'], 'Changed snapshot')
        for row in read(path)['rows']['train']:
            base.require(row['window_id'] not in seen, 'Duplicate'); seen.add(row['window_id']); union.append(row)
    prior = prior_signatures(); LAB.mkdir(parents=True); partitions, signatures, attackers = {}, {}, {}
    for stage, rows in STAGES.items():
        for cohort, seed in rows:
            allocation = (base._iid_assignments(union, client_count=15, seed=seed, np=base.np) if cohort == 'iid' else
                          base._dirichlet_assignments(union, client_count=15, seed=seed, alpha=.3, minimum_rows=32, np=base.np))
            base.require({r['window_id'] for rs in allocation for r in rs} == seen and sum(map(len, allocation)) == len(seen), 'Coverage')
            folder = LAB / 'partitions' / str(seed); clients = []
            for i, part_rows in enumerate(allocation):
                client = f'client{i+1:02d}'; path = folder / 'clients' / client / 'dataset.json'
                save(path, dict(client_id=client, partition_id=i, class_names=manifest['class_names'], rows={'train': part_rows}))
                clients.append(dict(client_id=client, partition_id=i, dataset_path=str(path.relative_to(folder)),
                                    dataset_sha256=sha256_file(path), train_row_count=len(part_rows)))
            m = dict(profile='head-v2-allocation', seed=seed, partition_mode=cohort, dirichlet_alpha=.3 if cohort == 'non-iid' else None,
                     class_names=manifest['class_names'], global_class_weights=manifest['global_class_weights'], clients=clients,
                     training_occurrences=len(seen), M3_full_profile_verification_claimed=False)
            sig = partition_signature(m)
            base.require(sig not in signatures.values(), f'Duplicated partition {seed}')
            base.require(sig not in prior, f'Partition {seed} duplicates {prior.get(sig)}')
            signatures[seed] = sig
            save(folder / 'manifest.json', m); partitions[str(seed)] = sha256_file(folder / 'manifest.json')
            if stage == 'evaluation':
                pick = sorted(np.random.default_rng(seed).choice(15, size=3, replace=False).tolist())
                attackers[str(seed)] = [f'client{i+1:02d}' for i in pick]
    base.require(len(set(signatures.values())) == len(signatures), 'Duplicated partition within study')
    bounds = {c: dict(path=str(p.relative_to(ROOT)), sha256=sha256_file(p)) for c, p in BOUNDS.items()}
    attacker_share = {}
    for seed, att in attackers.items():
        cl = read(LAB / 'partitions' / seed / 'manifest.json')['clients']
        tot = sum(c['train_row_count'] for c in cl); attacker_share[seed] = sum(c['train_row_count'] for c in cl if c['client_id'] in att) / tot
    protocol = dict(
        profile='head-gate-v2-live-study', stages=STAGES, attackers=attackers, attacker_data_share=attacker_share,
        arms=ARMS, reference_arm=REFERENCE_ARM, variants=VARIANTS, headfrozen_gates=HEADFROZEN_GATES, hypotheses=HYPOTHESES,
        training=clean_root['training'], runtime_admission=clean_root['runtime_admission'], partitions=partitions,
        partition_distinctness='checked within study and against prior gate studies at prepare time',
        source_snapshots=clean_root['source_snapshots'], source_locks=source_locks(), environment=environment(), tensor_bounds=bounds,
        candidate=dict(policy=gs.POLICY, rule='per-round maximum adverse robust z of v1 head-aware indicators computed on deltas divided '
                       'by local SGD steps (epochs*ceil(n/batch)), rescaled by the round median; quarantine above the clean 98th '
                       'percentile, cohort-specific; no CUSUM, no exclusion state; mandatory trust veto unchanged',
                       development='results/revision-head-gate-v2b-dev (offline, recorded trajectories); linear size correction '
                                   'rejected (results/revision-head-gate-v2-dev)'),
        fitting=dict(references='revision-clean-gate-calibration-v1 fit TPM-only clean histories',
                     thresholds='revision-clean-gate-calibration-v1 calibration+selection TPM-only clean histories', target_rate='0.02'),
        guard=dict(seeds=STAGES['guard'], budgets=hs.BUDGETS, rule='An arm is evaluated only if on every guard assignment its clean '
                   'history completes, quarantine <=5%, pooled mass >=90%, every round >=80%, and validation macro-F1 loss vs paired '
                   f'{REFERENCE_ARM} <=2 points at rounds 10 and 15. Reference always evaluated. No change after outcomes.'),
        endpoints='Paired worst-trigger peak harm vs own clean history; full/component peak and final test ASR; clean F1; attacker '
                  'influence; failures undefined (never 0%); per-seed attacker data share reported.',
        promotion='No automatic promotion. Seed is the repetition unit; one dataset; test split inspected in earlier work.',
        mandatory_trust='Assumed passed in software; no new TPM Quotes.', new_TPM_Quotes=0)
    save(LAB / 'protocol-before-fitting.json', protocol)
    (LAB / 'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print('PREPARED ' + json.dumps(dict(protocol_sha256=sha256_file(LAB / 'protocol-before-fitting.json'), attacker_share=attacker_share)), flush=True)


def clean_records(phase, cfg):
    closed = read(hs.CLEAN_SOURCE / phase / 'training-complete.json')
    receipt = read(hs.CLEAN_SOURCE / phase / 'verified/summary.json')
    base.require(receipt['status'] == 'verified' and not receipt['test_accessed'], 'Unverified source')
    recs = []
    for result in closed['results']:
        t = result['task']
        if t['policy'] != 'tpm_only' or t.get('candidate'):
            continue
        base.require(result['complete'] and t['mode'] == 'clean', 'Clean TPM-only histories only')
        ev = hs.CLEAN_SOURCE / phase / 'cases' / t['name'] / 'evidence'; authenticate(ev, result['manifest_sha256'])
        part = read(hs.CLEAN_SOURCE / 'partitions' / str(t['seed']) / 'manifest.json')
        sizes = {c['client_id']: c['train_row_count'] for c in part['clients']}; clients = sorted(sizes)
        for n in range(1, 16):
            rd = ev / 'rounds' / f'round-{n:03d}'
            f = gs.features(read(rd / 'base-model.json'), [read(rd / 'updates' / f'{c}.json') for c in clients], clients, sizes,
                            cfg['local_epochs'], cfg['batch_size'])
            recs += [dict(cohort=t['cohort'], round=n, history=t['name'], client=c, features=f[c]) for c in clients]
    return recs


def fit():
    protocol = read(LAB / 'protocol-before-fitting.json'); assert_locks(protocol)
    path = LAB / 'models/head-v2.json'; base.require(not path.exists(), 'Model already fitted')
    cfg = protocol['training']
    model = gs.fit(clean_records('fit', cfg), clean_records('calibration', cfg) + clean_records('selection', cfg), '0.02')
    save(path, model); print('FITTED ' + json.dumps(model['thresholds']), flush=True)


# ---------------------------------------------------------------- phases
def make_tasks(phase):
    tasks = []
    if phase == 'guard':
        for cohort, seed in STAGES['guard']:
            for arm in ARMS:
                tasks.append(dict(name=f'{cohort}-s{seed}-{arm}-clean', cohort=cohort, seed=seed,
                                  attackers=['client01', 'client06', 'client11'], policy=arm, mode='clean', variant='clean'))
        return tasks
    decision = read(LAB / 'guard-decision.json')
    arms = [a for a in ARMS if a == REFERENCE_ARM or a in decision['qualified_arms']]
    protocol = read(LAB / 'protocol-before-fitting.json')
    for cohort, seed in STAGES['evaluation']:
        for arm in arms:
            for v in list(VARIANTS) + (['adaptive-headfrozen'] if arm.split('+')[0] in HEADFROZEN_GATES else []):
                tasks.append(dict(name=f'{cohort}-s{seed}-{arm}-{v}', cohort=cohort, seed=seed, attackers=protocol['attackers'][str(seed)],
                                  policy=arm, mode='adaptive' if v.startswith('adaptive') else v, variant=v))
    return tasks


def phase_protocol(phase):
    folder = LAB / phase; path = folder / 'protocol-before-training.json'
    if path.exists():
        p = read(path); assert_locks(p); return p
    root = read(LAB / 'protocol-before-fitting.json'); assert_locks(root)
    base.require((LAB / 'models/head-v2.json').exists(), 'Fit the model first')
    folder.mkdir(); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    p = {**root, 'phase': phase, 'tasks': make_tasks(phase), 'model_sha256': sha256_file(LAB / 'models/head-v2.json'),
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
    base.require((LAB / 'guard/training-complete.json').exists() and (LAB / 'guard/verified/summary.json').exists(),
                 'Guard must be closed and verified')
    base.require(not (LAB / 'guard-decision.json').exists(), 'Guard decision exists')
    closed = run_phase('guard', 1); by = {(r['task']['seed'], r['task']['policy']): r for r in closed['results']}
    details, qualified = {}, []
    for arm in ARMS:
        rows = []
        for cohort, seed in STAGES['guard']:
            result, control = by[(seed, arm)], by[(seed, REFERENCE_ARM)]
            entry = dict(cohort=cohort, seed=seed, complete=bool(result['complete'] and control['complete']), qualified=False)
            if entry['complete']:
                sizes = {r['client_id']: r['train_row_count'] for r in read(LAB / 'partitions' / str(seed) / 'manifest.json')['clients']}
                summaries, losses = [], []
                for n in range(1, 16):
                    row = read(LAB / 'guard/cases' / result['task']['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json')
                    summaries.append(dict(statuses=row['statuses'], masses=row['masses'], example_counts=sizes))
                    if n in (10, 15):
                        other = read(LAB / 'guard/cases' / control['task']['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json')
                        losses.append(other['validation']['clean']['macro_f1_all_model_classes'] - row['validation']['clean']['macro_f1_all_model_classes'])
                b = cal.budget_summary(summaries); B = hs.BUDGETS
                entry.update(budget=b, validation_losses=losses, qualified=bool(
                    b['quarantine_rate'] <= B['maximum_quarantine_rate'] and b['nominal_mass_retention'] >= B['minimum_nominal_mass_retention']
                    and b['minimum_round_mass_retention'] >= B['minimum_round_mass_retention'] and max(losses) <= B['maximum_fixed_endpoint_validation_f1_loss']))
            rows.append(entry)
        details[arm] = rows
        if all(r['qualified'] for r in rows):
            qualified.append(arm)
    decision = dict(qualified_arms=qualified, details=details, uses_attack_or_test_outcomes=False,
                    guard_closure_sha256=sha256_file(LAB / 'guard/training-complete.json'))
    save(LAB / 'guard-decision.json', decision); print('GUARD ' + json.dumps(dict(qualified_arms=qualified)), flush=True)


def smoke(folder):
    import builtins
    folder = Path(folder); base.require(not folder.exists(), 'Smoke folder must be new')
    root = read(LAB / 'protocol-before-fitting.json'); assert_locks(root)
    folder.mkdir(parents=True); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    cohort, seed = STAGES['evaluation'][5]
    att = root['attackers'][str(seed)]
    picks = (('head_v2+bounded', 'adaptive'), ('head_v2+fedavg', 'adaptive-headfrozen'), ('gated_composite+fedavg', 'distributed'),
             ('tpm_only+bounded', 'complete-trigger'), ('head_v2+fedavg', 'clean'))
    tasks = [dict(name=f'smoke-{a}-{v}', cohort=cohort, seed=seed, attackers=att, policy=a,
                  mode='adaptive' if v.startswith('adaptive') else v, variant=v) for a, v in picks]
    save(folder / 'protocol-before-training.json', {**root, 'phase': 'smoke', 'tasks': tasks,
         'model_sha256': sha256_file(LAB / 'models/head-v2.json'), 'NOT_EVIDENCE': True})
    base.range = lambda *a: builtins.range(1, 3) if a == (1, 16) else builtins.range(*a)
    try:
        configure(folder)
        for t in tasks:
            r = base.run_case(t)
            st = read(folder / 'cases' / t['name'] / 'evidence/rounds/round-002/gate-state.json')
            hv = st['head_v2']
            print('SMOKE ' + json.dumps(dict(task=t['name'], rounds=r['completed_rounds'], max_score=round(max(hv['score'].values()), 2),
                  q_head_v2=sum(not d['head_v2']['contributes'] for d in st['decisions'].values()),
                  q_deployed=sum(not d[t['policy']]['contributes'] for d in st['decisions'].values()),
                  clipping=st.get('aggregation', {}).get(t['policy'], {}).get('min_clipping') and round(min(st['aggregation'][t['policy']]['min_clipping'].values()), 3))), flush=True)
    finally:
        del base.range


def main():
    global LAB
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('prepare', 'fit', 'guard', 'guard-decide', 'evaluation', 'smoke'))
    ap.add_argument('--workers', type=int, default=2)
    ap.add_argument('--lab', type=Path, default=LAB)
    ap.add_argument('--smoke-dir', type=Path)
    a = ap.parse_args(); LAB = a.lab
    {'prepare': prepare, 'fit': fit, 'guard': lambda: run_phase('guard', a.workers), 'guard-decide': guard_decide,
     'evaluation': lambda: run_phase('evaluation', a.workers), 'smoke': lambda: smoke(a.smoke_dir)}[a.command]()


if __name__ == '__main__':
    main()
