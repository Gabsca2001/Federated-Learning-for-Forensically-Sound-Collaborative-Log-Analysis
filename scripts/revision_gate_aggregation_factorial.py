"""Predeclared gate x aggregation factorial study.

Arms = {tpm_only, gated_composite, head_cusum} x {fedavg, bounded, trimmed_mean}.
The admission gate decides participation (masses); the operator then aggregates
only retained clients. Adaptive attackers query the COMPLETE defence (gate,
CUSUM state and operator); ``adaptive-headfrozen`` additionally keeps the
attacker classification head at its clean endpoint (head_cusum arms only).

Stages: prepare -> guard (clean only, decides which arms are evaluated)
-> guard-decide -> evaluation. ``smoke`` is a 2-round developer check in a
scratch lab. The head-CUSUM model is reused, pinned, from
``revision-head-cusum-gate-v1``; per-tensor limits are the existing clean
``revision-bounded-influence-v1`` bounds. Nothing is fitted on attack data.
Prerequisite trust assumed passed in software; no new TPM Quotes.
"""
from __future__ import annotations

import argparse
import copy
import json
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from fractions import Fraction
from pathlib import Path

import revision_gate_trajectories as base  # numeric environment first
import revision_head_cusum_study as hs
import clean_gate_calibration as cal
import factorial_aggregators as fa
from revision_study_data import read, Generator
from revision_dba_experiment import save, authenticate, environment
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

ROOT = base.ROOT
LAB = ROOT / 'artifacts/revision-gate-aggregation-factorial-v1'
HEAD_LAB = ROOT / 'artifacts/revision-head-cusum-gate-v1'
BOUNDS = {c: ROOT / 'artifacts/revision-bounded-influence-v1' / f'{c}-bounds.json' for c in ('iid', 'non-iid')}
ORIGINAL_NUMERICAL = base.numerical
GATES = ('tpm_only', 'gated_composite', 'head_cusum')
ARMS = tuple(f'{g}+{a}' for g in GATES for a in fa.OPERATORS)
VARIANTS = ('clean', 'distributed', 'complete-trigger', 'adaptive')
HEADFROZEN_GATES = ('head_cusum',)
REFERENCE_ARM = 'tpm_only+fedavg'
STAGES = {
    'guard': [('iid', 2026111041), ('iid', 2026111042), ('non-iid', 2026111043), ('non-iid', 2026111044)],
    'evaluation': [('iid', 2026111031), ('iid', 2026111032), ('iid', 2026111033),
                   ('non-iid', 2026111034), ('non-iid', 2026111035), ('non-iid', 2026111036)],
}
ATTACKERS = [['client03', 'client08', 'client12'], ['client01', 'client07', 'client14'],
             ['client02', 'client06', 'client15'], ['client05', 'client09', 'client13'],
             ['client04', 'client10', 'client11'], ['client03', 'client06', 'client13']]
BUDGETS = hs.BUDGETS


def source_locks():
    locks = hs.source_locks()
    for name in ('factorial_aggregators.py', 'revision_gate_aggregation_factorial.py'):
        p = ROOT / 'scripts' / name
        locks[str(p.relative_to(ROOT))] = sha256_file(p)
    return locks


def assert_locks(protocol):
    base.require(source_locks() == protocol['source_locks'], 'Locked factorial source changed')
    base.require(sha256_file(HEAD_LAB / 'models/head-cusum.json') == protocol['head_model_sha256'], 'Head model changed')
    for c, pin in protocol['tensor_bounds'].items():
        base.require(sha256_file(ROOT / pin['path']) == pin['sha256'], 'Tensor bounds changed')


# ---------------------------------------------------------------- adapters
def context(protocol, task):
    gen, rows, correct = hs.context(protocol, task)  # head model pinned in HEAD_LAB
    gen.tensor_bounds = read(ROOT / protocol['tensor_bounds'][task['cohort']]['path'])
    sizes = [int(v.size) for v in arrays_from_export(gen.initial, np=base.np)]
    base.require(sizes == gen.tensor_bounds['sizes'], 'Tensor bound schema mismatch')
    return gen, rows, correct


def gate_state(initial, exports, gen, settings, rows):
    state, arrays = hs.gate_state(initial, exports, gen, settings, rows)
    for c in gen.clients:
        for arm in ARMS:
            # An arm key carries its gate's decision; the operator is applied in numerical().
            state['decisions'][c][arm] = copy.deepcopy(state['decisions'][c][arm.split('+')[0]])
    return state, arrays


def masses_for(gen, state, gate, settings):
    rho = Fraction(str(settings['accepted_downweight_factor']))
    out = {}
    for c in gen.clients:
        d = state['decisions'][c][gate]
        factor = rho if d['status'] == 'accepted_downweighted' else Fraction(int(d['contributes']))
        out[c] = len(gen.rows[c]) * factor
    return out


def numerical(initial, local_arrays, gen, state, settings, policy):
    if '+' not in policy:
        return ORIGINAL_NUMERICAL(initial, local_arrays, gen, state, settings, policy)
    gate, operator = policy.split('+')
    if operator == 'fedavg':
        model, masses, coefficients = ORIGINAL_NUMERICAL(initial, local_arrays, gen, state, settings, gate)
        state.setdefault('factorial', {})[policy] = dict(operator='fedavg', coefficients=coefficients)
        return model, masses, coefficients
    started = time.perf_counter()
    masses = masses_for(gen, state, gate, settings)
    if sum(m > 0 for m in masses.values()) < settings['minimum_contributors']:
        state.setdefault('factorial', {})[policy] = dict(operator=operator, failure='quorum')
        return None, masses, None
    base_arrays = arrays_from_export(initial, np=base.np)
    updates = dict(zip(gen.clients, local_arrays, strict=True))
    if operator == 'bounded':
        params, report = fa.bounded(base_arrays, updates, masses, gen.tensor_bounds['limits'], gen.tensor_bounds,
                                    settings['minimum_contributors'])
        coefficients = report['coefficients'] if params is not None else None
    else:
        params, report = fa.trimmed_mean(base_arrays, updates, {c: masses[c] > 0 for c in gen.clients})
        coefficients = ({c: str(v) for c, v in report['retained_value_share'].items()} if params is not None else None)
    model = base.model_with_arrays(initial, params) if params is not None else None
    report = {k: v for k, v in report.items() if k != 'clipping_factors'} | (
        {'max_clipping': {c: min(v) for c, v in report.get('clipping_factors', {}).items()}} if operator == 'bounded' else {})
    report['seconds'] = time.perf_counter() - started
    state.setdefault('factorial', {})[policy] = report
    return model, masses, coefficients


def configure(phase_dir):
    hs.set_lab(HEAD_LAB)
    hs.configure(Path(phase_dir))
    base.context, base.gate_state, base.numerical, base.assert_locks = context, gate_state, numerical, assert_locks


def worker(task, phase_dir, lab):
    global LAB
    LAB = Path(lab)
    configure(phase_dir)
    return base.run_case(task)


# ---------------------------------------------------------------- prepare
def prepare():
    base.require(not LAB.exists(), 'Preserve existing factorial study')
    head_root = read(HEAD_LAB / 'protocol-before-fitting.json')
    source = ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1'; manifest = read(source / 'manifest.json')
    union, seen = [], set()
    for record in manifest['clients']:
        path = source / record['dataset_path']
        base.require(sha256_file(path) == record['dataset_sha256'], 'Changed source snapshot')
        for row in read(path)['rows']['train']:
            base.require(row['window_id'] not in seen, 'Duplicate'); seen.add(row['window_id']); union.append(row)
    used = {s for rows in head_root['stages'].values() for _, s in rows}
    used |= {s for rows in read(hs.CLEAN_SOURCE / 'protocol-before-clean-fitting.json')['stages'].values() for _, s in rows}
    LAB.mkdir(parents=True); partitions = {}
    for cohort, seed in [v for rows in STAGES.values() for v in rows]:
        base.require(seed not in used, 'Seed reused from an earlier study')
        allocation = (base._iid_assignments(union, client_count=15, seed=seed, np=base.np) if cohort == 'iid' else
                      base._dirichlet_assignments(union, client_count=15, seed=seed, alpha=.3, minimum_rows=32, np=base.np))
        base.require({r['window_id'] for rs in allocation for r in rs} == seen and sum(map(len, allocation)) == len(seen), 'Coverage')
        folder = LAB / 'partitions' / str(seed); clients = []
        for i, rows in enumerate(allocation):
            client = f'client{i+1:02d}'; path = folder / 'clients' / client / 'dataset.json'
            save(path, dict(client_id=client, partition_id=i, class_names=manifest['class_names'], rows={'train': rows}))
            clients.append(dict(client_id=client, partition_id=i, dataset_path=str(path.relative_to(folder)),
                                dataset_sha256=sha256_file(path), train_row_count=len(rows)))
        save(folder / 'manifest.json', dict(profile='gate-aggregation-factorial-allocation-v1', seed=seed, partition_mode=cohort,
             dirichlet_alpha=.3 if cohort == 'non-iid' else None, class_names=manifest['class_names'],
             global_class_weights=manifest['global_class_weights'], clients=clients, training_occurrences=len(seen),
             M3_full_profile_verification_claimed=False))
        partitions[str(seed)] = sha256_file(folder / 'manifest.json')
    bounds = {c: dict(path=str(p.relative_to(ROOT)), sha256=sha256_file(p)) for c, p in BOUNDS.items()}
    for c, p in BOUNDS.items():
        b = read(p); base.require(b['reference_update_count'] == 3675 and b['quantile'] == 0.99, 'Unexpected bounds')
    protocol = dict(
        profile='gate-aggregation-factorial-v1', stages=STAGES, attackers=ATTACKERS, gates=GATES,
        operators=fa.OPERATORS, arms=ARMS, variants=VARIANTS, headfrozen_gates=HEADFROZEN_GATES,
        reference_arm=REFERENCE_ARM, training=head_root['training'], runtime_admission=head_root['runtime_admission'],
        partitions=partitions, source_snapshots=head_root['source_snapshots'], source_locks=source_locks(),
        environment=environment(), head_model_sha256=sha256_file(HEAD_LAB / 'models/head-cusum.json'),
        head_model_source='revision-head-cusum-gate-v1 (frozen clean thresholds, unchanged)', tensor_bounds=bounds,
        operators_contract=dict(
            fedavg='unchanged Flower sample-weighted FedAvg over gate masses',
            bounded='per-tensor L2 clipping to fixed clean 99th-percentile limits (3,675 clean updates), then the '
                    'gate normalized masses (aggregate_bounded); no new fitting',
            trimmed_mean=f'unweighted coordinate-wise trimmed mean, f={fa.TRIM_F} per side, over gate-retained clients; '
                         'downweighted clients enter unweighted; n <= 2f is an availability failure',
            quorum='minimum ten positive-mass contributors for every operator'),
        guard=dict(seeds=STAGES['guard'], arms=ARMS, budgets=BUDGETS,
                   rule=f'An arm is evaluated only if on every guard assignment its clean history completes 15 rounds, '
                        f'quarantine <=5%, pooled nominal mass >=90%, every round >=80%, and validation macro-F1 loss vs '
                        f'paired {REFERENCE_ARM} <=2 points at rounds 10 and 15. {REFERENCE_ARM} is always evaluated. '
                        'No parameter change after guard outcomes.'),
        evaluation_plan=dict(arms='guard-qualified arms (plus reference)', variants=VARIANTS,
                             headfrozen='adaptive-headfrozen for head_cusum arms only', horizon=15,
                             attack_rounds=list(range(1, 11)),
                             adaptive='six-alpha white-box search scored after the complete defence of each arm '
                                      '(gate decisions, CUSUM state, operator); ties prefer larger manipulation'),
        endpoints='Paired worst-trigger peak harm (max over rounds of attacked minus own-clean worst ASR), full/component '
                  'trigger peak and final ASR, clean macro-F1 at rounds 10/15, attacker influence after normalization '
                  '(coefficients; trimmed mean: retained-value share), quorum/precondition failures, detection round, '
                  'runtime per layer. Failures are undefined, never ASR 0.',
        hypotheses=dict(
            H1='Complementarity: head_cusum+bounded has lower paired worst-trigger peak harm than BOTH single-layer arms '
               '(head_cusum+fedavg and tpm_only+bounded) in a majority of defined attacked comparisons.',
            H2='Against DBA (distributed and complete-trigger) and adaptive attacks, head_cusum+bounded reduces paired '
               'peak harm vs tpm_only+fedavg in effective controls (>=20 point ASR increase, <=5 point clean F1 loss).',
            H3='Interactions are reported, not tuned: attacker influence after normalization vs the reference arm; '
               'whether gated_composite downweighting or trimmed-mean selection increases attacker influence; '
               'availability failures.',
            H4='Robustness: under adaptive-headfrozen report whether head_cusum+bounded keeps any benefit over '
               'tpm_only+bounded.'),
        promotion='No automatic promotion. Seed/partition assignment is the repetition unit; one dataset (Data24); '
                  'the test split was inspected in earlier work; ToN-IoT deferred.',
        mandatory_trust='Assumed passed in software; no new TPM Quotes.', new_TPM_Quotes=0)
    save(LAB / 'protocol-before-guard.json', protocol)
    (LAB / 'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print('PREPARED ' + json.dumps(dict(protocol_sha256=sha256_file(LAB / 'protocol-before-guard.json'),
                                        guard_cases=len(make_tasks('guard', protocol)))), flush=True)


# ---------------------------------------------------------------- phases
def make_tasks(phase, root=None):
    tasks = []
    if phase == 'guard':
        for cohort, seed in STAGES['guard']:
            for arm in ARMS:
                tasks.append(dict(name=f'{cohort}-s{seed}-{arm}-clean', cohort=cohort, seed=seed,
                                  attackers=['client01', 'client06', 'client11'], policy=arm, mode='clean', variant='clean'))
        return tasks
    decision = read(LAB / 'guard-decision.json')
    arms = [a for a in ARMS if a == REFERENCE_ARM or a in decision['qualified_arms']]
    for i, (cohort, seed) in enumerate(STAGES['evaluation']):
        for arm in arms:
            variants = list(VARIANTS) + (['adaptive-headfrozen'] if arm.split('+')[0] in HEADFROZEN_GATES else [])
            for v in variants:
                tasks.append(dict(name=f'{cohort}-s{seed}-{arm}-{v}', cohort=cohort, seed=seed, attackers=ATTACKERS[i],
                                  policy=arm, mode='adaptive' if v.startswith('adaptive') else v, variant=v))
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
    base.require((LAB / 'guard/training-complete.json').exists(), 'Guard training has not closed')
    base.require(not (LAB / 'guard-decision.json').exists(), 'Guard decision already recorded')
    closed = run_phase('guard', 1)
    by = {(r['task']['seed'], r['task']['policy']): r for r in closed['results']}
    details, qualified = {}, []
    for arm in ARMS:
        rows = []
        for cohort, seed in STAGES['guard']:
            result, control = by[(seed, arm)], by[(seed, REFERENCE_ARM)]
            entry = dict(cohort=cohort, seed=seed, complete=bool(result['complete'] and control['complete']), qualified=False)
            if entry['complete']:
                part = read(LAB / 'partitions' / str(seed) / 'manifest.json')
                sizes = {r['client_id']: r['train_row_count'] for r in part['clients']}
                summaries, losses = [], []
                for n in range(1, 16):
                    row = read(LAB / 'guard/cases' / result['task']['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json')
                    summaries.append(dict(statuses=row['statuses'], masses=row['masses'], example_counts=sizes))
                    if n in (10, 15):
                        other = read(LAB / 'guard/cases' / control['task']['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'round.json')
                        losses.append(other['validation']['clean']['macro_f1_all_model_classes'] -
                                      row['validation']['clean']['macro_f1_all_model_classes'])
                b = cal.budget_summary(summaries)
                entry.update(budget=b, validation_losses=losses, qualified=bool(
                    b['quarantine_rate'] <= BUDGETS['maximum_quarantine_rate'] and
                    b['nominal_mass_retention'] >= BUDGETS['minimum_nominal_mass_retention'] and
                    b['minimum_round_mass_retention'] >= BUDGETS['minimum_round_mass_retention'] and
                    max(losses) <= BUDGETS['maximum_fixed_endpoint_validation_f1_loss']))
            rows.append(entry)
        details[arm] = rows
        if all(r['qualified'] for r in rows):
            qualified.append(arm)
    decision = dict(qualified_arms=qualified, details=details, uses_attack_or_test_outcomes=False,
                    guard_closure_sha256=sha256_file(LAB / 'guard/training-complete.json'))
    save(LAB / 'guard-decision.json', decision)
    print('GUARD ' + json.dumps(dict(qualified_arms=qualified)), flush=True)
    return decision


# ---------------------------------------------------------------- smoke
def smoke(folder):
    import builtins
    folder = Path(folder); base.require(not folder.exists(), 'Smoke folder must be new')
    root = read(LAB / 'protocol-before-guard.json'); assert_locks(root)
    folder.mkdir(parents=True); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    cohort, seed = STAGES['guard'][2]
    picks = (('head_cusum+bounded', 'adaptive'), ('head_cusum+trimmed_mean', 'distributed'),
             ('gated_composite+trimmed_mean', 'clean'), ('head_cusum+bounded', 'adaptive-headfrozen'),
             ('tpm_only+fedavg', 'complete-trigger'))
    tasks = [dict(name=f'smoke-{a}-{v}', cohort=cohort, seed=seed, attackers=ATTACKERS[0], policy=a,
                  mode='adaptive' if v.startswith('adaptive') else v, variant=v) for a, v in picks]
    save(folder / 'protocol-before-training.json', {**root, 'phase': 'smoke', 'tasks': tasks, 'NOT_EVIDENCE': True})
    base.range = lambda *a: builtins.range(1, 3) if a == (1, 16) else builtins.range(*a)
    try:
        configure(folder)
        for t in tasks:
            r = base.run_case(t)
            st = read(folder / 'cases' / t['name'] / 'evidence/rounds/round-002/gate-state.json')
            rep = st['factorial'][t['policy']]
            row = read(folder / 'cases' / t['name'] / 'evidence/rounds/round-002/round.json')
            coeff = row['coefficients'] or {}
            influence_report = ({'operator': 'trimmed_mean', 'retained_value_share': {c: float(v) for c, v in coeff.items()}}
                                if rep['operator'] == 'trimmed_mean' else {'operator': rep['operator'], 'coefficients': coeff})
            att = fa.attacker_influence(influence_report, set(t['attackers']))
            print('SMOKE ' + json.dumps(dict(task=t['name'], rounds=r['completed_rounds'], operator=rep['operator'],
                  attacker_influence_r2=round(att, 4), quarantined=sum(not v[t['policy']]['contributes'] for v in st['decisions'].values()),
                  min_clip=min(rep['max_clipping'].values()) if rep['operator'] == 'bounded' else None)), flush=True)
    finally:
        del base.range


def main():
    global LAB
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('prepare', 'guard', 'guard-decide', 'evaluation', 'smoke'))
    ap.add_argument('--workers', type=int, default=2)
    ap.add_argument('--lab', type=Path, default=LAB)
    ap.add_argument('--smoke-dir', type=Path)
    a = ap.parse_args(); LAB = a.lab
    {'prepare': prepare, 'guard': lambda: run_phase('guard', a.workers), 'guard-decide': guard_decide,
     'evaluation': lambda: run_phase('evaluation', a.workers), 'smoke': lambda: smoke(a.smoke_dir)}[a.command]()


if __name__ == '__main__':
    main()
