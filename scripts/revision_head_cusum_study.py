"""Predeclared live study of the head-aware CUSUM admission candidate.

Stages (each refuses to overwrite closed evidence):
  prepare     freeze protocol, fresh guard/evaluation partitions, source locks
  fit         references + thresholds from REUSED verified clean TPM-only
              histories of revision-clean-gate-calibration-v1 (no new training)
  guard       clean-only training driven by each candidate on fresh seeds;
              predeclared benign budgets decide which arms enter evaluation
  evaluation  reserved assignments x arms x attack variants, independent
              trajectories; adaptive attacks optimize against each defender
  smoke       2-round developer check in a scratch directory (not evidence)

The v1 gate-trajectory engine is reused through process-local adapters; its code
and all prior evidence are untouched. Prerequisite trust is assumed passed in
software (no new TPM Quotes). Test inference, verification and reporting are
separate later steps and must not start before evaluation training closes.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from statistics import median

import revision_gate_trajectories as base  # establishes numeric environment first
import clean_gate_calibration as cal
import head_cusum_gate as hg
from revision_study_data import read, Generator
from revision_dba_experiment import save, authenticate, environment
from fl_forensics.canonical import sha256_file

ROOT = base.ROOT
LAB = ROOT / 'artifacts/revision-head-cusum-gate-v1'
CLEAN_SOURCE = ROOT / 'artifacts/revision-clean-gate-calibration-v1'
ORIGINAL_CONTEXT, ORIGINAL_STATE = base.context, base.gate_state
ORIGINAL_TRAIN_ALL, ORIGINAL_TRAIN_ONE = base.train_all, base.train_one
ALL_POLICIES = ('tpm_only', 'sequential', 'gated_composite', 'head_max', 'head_cusum')
CANDIDATES = ('head_max', 'head_cusum')
EVAL_ARMS = ('tpm_only', 'gated_composite', 'head_max', 'head_cusum')
VARIANTS = ('clean', 'distributed', 'complete-trigger', 'adaptive', 'adaptive-headfrozen')
TARGET_RATE = '0.02'
STAGES = {
    'guard': [('iid', 2026111011), ('iid', 2026111012), ('non-iid', 2026111013), ('non-iid', 2026111014)],
    'evaluation': [('iid', 2026111021), ('iid', 2026111022), ('iid', 2026111023),
                   ('non-iid', 2026111024), ('non-iid', 2026111025), ('non-iid', 2026111026)],
}
ATTACKERS = [['client02', 'client09', 'client13'], ['client03', 'client06', 'client14'],
             ['client01', 'client10', 'client15'], ['client04', 'client08', 'client12'],
             ['client05', 'client07', 'client11'], ['client02', 'client10', 'client14']]
FIT_SOURCES = {'references': ('fit',), 'thresholds': ('calibration', 'selection')}
K_QUANTILE = '0.90'
BUDGETS = dict(maximum_quarantine_rate=.05, minimum_nominal_mass_retention=.90,
               minimum_round_mass_retention=.80, maximum_fixed_endpoint_validation_f1_loss=.02)


def source_locks():
    paths = sorted((ROOT / 'src/fl_forensics').glob('*.py'))
    paths += [ROOT / 'scripts' / n for n in ('revision_gate_trajectories.py', 'revision_study_data.py',
              'revision_dba_experiment.py', 'clean_gate_calibration.py', 'head_cusum_gate.py',
              'revision_head_cusum_study.py')]
    paths += [ROOT / 'configs/in-round-admission.yaml']
    return {str(p.relative_to(ROOT)): sha256_file(p) for p in paths}


def assert_locks(protocol):
    base.require(source_locks() == protocol['source_locks'], 'Locked head-CUSUM study source changed')
    if protocol.get('head_model_sha256'):
        base.require(sha256_file(LAB / 'models/head-cusum.json') == protocol['head_model_sha256'], 'Bound model changed')


# ---------------------------------------------------------------- adapters
def context(protocol, task):
    gen, rows, correct = ORIGINAL_CONTEXT(protocol, task)
    gen.gate_cohort = task['cohort']; gen.gate_round = None
    gen.case_evidence = base.LAB / 'cases' / task['name'] / 'evidence'
    gen.head_frozen = task.get('variant') == 'adaptive-headfrozen'
    path = LAB / 'models/head-cusum.json'
    base.require(sha256_file(path) == protocol['head_model_sha256'], 'Head model pin mismatch')
    gen.head_model = read(path); gen.head_model_sha256 = protocol['head_model_sha256']
    return gen, rows, correct


def train_all(gen, initial, seed, number, plan=None, distributed=True):
    gen.gate_round = number
    return ORIGINAL_TRAIN_ALL(gen, initial, seed, number, plan, distributed)


def train_one(gen, initial, seed, number, client, plan=None, distributed=True):
    exported, record = ORIGINAL_TRAIN_ONE(gen, initial, seed, number, client, plan, distributed)
    if plan is not None and getattr(gen, 'head_frozen', False):
        # Defender-aware evasion: keep the attacker's classification head equal to
        # its own clean endpoint, so only encoder parameters carry the poison.
        clean, _ = ORIGINAL_TRAIN_ONE(gen, initial, seed, number, client, None, distributed)
        for p, q in zip(exported['parameters'], clean['parameters'], strict=True):
            base.require(p['name'] == q['name'], 'schema mismatch')
            if p['name'].startswith(hg.HEAD_PREFIX):
                p['values'] = q['values']
        record = {**record, 'head_frozen_to_clean_endpoint': True, 'local_model_sha256': base.digest(exported)}
    return exported, record


def previous_cusum(gen):
    number = gen.gate_round
    if number == 1:
        return {}
    path = gen.case_evidence / 'rounds' / f'round-{number-1:03d}' / 'gate-state.json'
    base.require(path.is_file(), 'Committed previous-round state missing')
    state = read(path)['head_gate']
    base.require(state['round'] == number - 1 and state['model_sha256'] == gen.head_model_sha256, 'State chain mismatch')
    return state['cusum']


def gate_state(initial, exports, gen, settings, rows):
    state, arrays = ORIGINAL_STATE(initial, exports, gen, settings, rows)
    started = time.perf_counter()
    cal.stage(gen.gate_round)  # round derives from the controller, never from model contents
    features = hg.compute_features(initial, exports, gen.clients)
    prior = previous_cusum(gen)
    out = hg.decide(gen.head_model, gen.gate_cohort, features, prior, trust_admissible=base.TRUST.admissible)
    for c in gen.clients:
        for policy in hg.POLICIES:
            state['decisions'][c][policy] = out[c]['decisions'][policy]
    state['head_gate'] = dict(round=gen.gate_round, cohort=gen.gate_cohort, model_sha256=gen.head_model_sha256,
        previous_cusum={c: float(prior.get(c, 0.0)) for c in gen.clients}, features=features,
        adverse_z={c: out[c]['adverse_z'] for c in gen.clients}, score={c: out[c]['score'] for c in gen.clients},
        cusum={c: out[c]['cusum'] for c in gen.clients})
    state['timing']['head_gate_seconds'] = time.perf_counter() - started
    return state, arrays


def configure(phase_dir):
    base.LAB = phase_dir
    base.context, base.train_all, base.train_one = context, train_all, train_one
    base.gate_state, base.assert_locks, base.POLICIES = gate_state, assert_locks, ALL_POLICIES


def set_lab(path):
    global LAB
    LAB = Path(path)


def worker(task, phase_dir, lab):
    set_lab(lab)
    configure(Path(phase_dir))
    return base.run_case(task)


# ---------------------------------------------------------------- prepare
def prepare():
    base.require(not LAB.exists(), 'Preserve existing head-CUSUM study')
    clean_root = read(CLEAN_SOURCE / 'protocol-before-clean-fitting.json')
    source = ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1'; manifest = read(source / 'manifest.json')
    union, seen = [], set()
    for record in manifest['clients']:
        path = source / record['dataset_path']
        base.require(sha256_file(path) == record['dataset_sha256'], 'Changed source snapshot')
        for row in read(path)['rows']['train']:
            base.require(row['window_id'] not in seen, 'Duplicate training occurrence'); seen.add(row['window_id']); union.append(row)
    used = {s for rows in read(CLEAN_SOURCE / 'protocol-before-clean-fitting.json')['stages'].values() for _, s in rows}
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
        save(folder / 'manifest.json', dict(profile='head-cusum-training-only-allocation-v1', seed=seed, partition_mode=cohort,
             dirichlet_alpha=.3 if cohort == 'non-iid' else None, class_names=manifest['class_names'],
             global_class_weights=manifest['global_class_weights'], clients=clients, training_occurrences=len(seen),
             M3_full_profile_verification_claimed=False))
        partitions[str(seed)] = sha256_file(folder / 'manifest.json')
    clean_pins = {}
    for phase in [p for phases in FIT_SOURCES.values() for p in phases]:
        clean_pins[phase] = dict(training_complete=sha256_file(CLEAN_SOURCE / phase / 'training-complete.json'),
                                 verified_summary=sha256_file(CLEAN_SOURCE / phase / 'verified/summary.json'))
    protocol = dict(
        profile='head-cusum-admission-live-study-v1', stages=STAGES, attackers=ATTACKERS,
        candidates=CANDIDATES, evaluation_arms=EVAL_ARMS, variants=VARIANTS,
        training=clean_root['training'], runtime_admission=clean_root['runtime_admission'], partitions=partitions,
        source_snapshots=clean_root['source_snapshots'], source_locks=source_locks(), environment=environment(),
        development_evidence='results/admission/revision-tensor-indicators-v1 (offline replay; rule chosen on seeds 342593/343593, '
                             'holdout 344593/345593). The rule below is frozen from that study without change.',
        candidate=dict(features=list(hg.FEATURES), directions=hg.DIRECTIONS, knn=hg.KNN, head_prefix=hg.HEAD_PREFIX,
                       score='maximum adverse robust z over features (non-compensatory, uncapped)',
                       head_max='quarantine when round score > clean (1-target) quantile of scores',
                       head_cusum='per-client one-sided CUSUM S_t=max(0,S_{t-1}+score-k), k=clean 0.90 quantile of '
                                  'round scores (chosen on offline development seeds only: earlier detection than the '
                                  'median, which let persistently heterogeneous benign clients drift); '
                                  'quarantine when S_t > clean (1-target) quantile of S over clean histories; '
                                  'the statistic keeps updating while quarantined (no permanent exclusion state)',
                       target_clean_rate=TARGET_RATE, cohort_specific=True, trust='hard veto unchanged'),
        fitting=dict(sources={k: [str((CLEAN_SOURCE / v).relative_to(ROOT)) for v in vs] for k, vs in FIT_SOURCES.items()},
                     pins=clean_pins, tasks='tpm_only clean histories only', k_quantile=K_QUANTILE,
                     rule='cohort-specific references from the 4 fit histories; k and thresholds from the 8 '
                          'calibration+selection TPM-only histories (4 per cohort). Allowlist: cohort, round, history, '
                          'client, features. Held-out clean behaviour is tested live in the guard stage.'),
        guard=dict(seeds=STAGES['guard'], arms=['tpm_only', *CANDIDATES], budgets=BUDGETS,
                   rule='A candidate enters evaluation only if, on every guard assignment, its own clean history is '
                        'complete (15 rounds, no quorum failure), quarantine rate <=5%, pooled nominal mass retained '
                        '>=90%, every round >=80%, and validation macro-F1 loss vs paired TPM-only <=2 points at '
                        'rounds 10 and 15. No threshold change after guard outcomes; a failed candidate is reported.'),
        evaluation_plan=dict(arms=EVAL_ARMS, variants=VARIANTS, horizon=15, attack_rounds=list(range(1, 11)),
                     adaptive='unchanged six-alpha query search with privileged white-box endpoints and validation '
                              'oracle, optimized against each evaluated defender including CUSUM state',
                     adaptive_headfrozen='same search but attacker classification head fixed to its own clean '
                              'endpoint (defender-aware evasion of head indicators); run for every arm',
                     test='opened only after all evaluation cases are terminal; no parameter change afterwards'),
        endpoints='Paired worst-trigger peak harm (max over rounds of attacked minus own-clean worst ASR), full-trigger '
                  'peak/final ASR, fixed rounds 10/15, clean macro-F1, quarantine/mass budgets, quorum failures, '
                  'attacker retained mass, detection round, runtime per component. Failures are undefined, never ASR 0.',
        hypotheses=dict(
            H1='head_cusum has lower paired worst-trigger peak harm than gated_composite in a majority of defined '
               'attacked comparisons, without exceeding clean budgets on reserved clean assignments.',
            H2='head_cusum reduces paired peak harm vs tpm_only in effective TPM-only controls (>=20 point ASR increase, '
               '<=5 point clean F1 loss).',
            H3='robustness: under adaptive-headfrozen, report whether any benefit over tpm_only remains. A loss of '
               'benefit is a reported limitation, not a reason to retune.'),
        promotion='No automatic promotion. Candidate is reportable as improved only if guard passes, H1 and H2 hold, '
                  'no new quorum failure on reserved clean assignments and <=2 point paired test F1 loss at rounds 10/15. '
                  'Seed/partition assignment is the repetition unit; one dataset; test split previously inspected.',
        independence='Fresh guard/evaluation seeds disjoint from all earlier gate studies; same Data24 rows and warm start.',
        mandatory_trust='Assumed passed in software; no new TPM Quotes or client signature claim.', new_TPM_Quotes=0)
    save(LAB / 'protocol-before-fitting.json', protocol)
    (LAB / 'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print('PREPARED ' + json.dumps(dict(protocol_sha256=sha256_file(LAB / 'protocol-before-fitting.json'))), flush=True)


# ---------------------------------------------------------------- fit
def clean_history_records(phase):
    closed = read(CLEAN_SOURCE / phase / 'training-complete.json')
    receipt = read(CLEAN_SOURCE / phase / 'verified/summary.json')
    base.require(receipt['status'] == 'verified' and not receipt['test_accessed'], 'Unverified or test-observed source')
    base.require(receipt['training_closure_sha256'] == sha256_file(CLEAN_SOURCE / phase / 'training-complete.json'), 'Closure pin')
    records, pins = [], {}
    for result in closed['results']:
        task = result['task']
        if task['policy'] != 'tpm_only' or task.get('candidate'):
            continue  # only clean FedAvg histories; candidate-driven histories are not used
        base.require(result['complete'] and task['mode'] == 'clean', 'Fitting requires complete clean TPM-only histories')
        evidence = CLEAN_SOURCE / phase / 'cases' / task['name'] / 'evidence'
        authenticate(evidence, result['manifest_sha256']); pins[task['name']] = result['manifest_sha256']
        for number in range(1, 16):
            rd = evidence / 'rounds' / f'round-{number:03d}'
            clients = sorted(p.stem for p in (rd / 'updates').glob('client*.json'))
            feats = hg.compute_features(read(rd / 'base-model.json'), [read(rd / 'updates' / f'{c}.json') for c in clients], clients)
            records += [dict(cohort=task['cohort'], round=number, history=task['name'], client=c, features=feats[c]) for c in clients]
    return records, pins


def fit():
    protocol = read(LAB / 'protocol-before-fitting.json'); assert_locks(protocol)
    path = LAB / 'models/head-cusum.json'
    base.require(not path.exists(), 'Model already fitted')
    def gather(phases):
        records, pins = [], {}
        for phase in phases:
            r, p = clean_history_records(phase); records += r; pins.update({f'{phase}/{k}': v for k, v in p.items()})
        return records, pins
    refs_records, ref_pins = gather(FIT_SOURCES['references'])
    thr_records, thr_pins = gather(FIT_SOURCES['thresholds'])
    refs = hg.fit_references(refs_records)
    model = dict(profile='head-cusum-model-v1', references=refs,
                 thresholds=hg.fit_thresholds(refs, thr_records, TARGET_RATE, K_QUANTILE),
                 source_manifests=dict(references=ref_pins, thresholds=thr_pins),
                 observations=dict(references=len(refs_records), thresholds=len(thr_records)))
    save(path, model)
    print('FITTED ' + json.dumps(dict(thresholds=model['thresholds'], observations=model['observations'])), flush=True)


# ---------------------------------------------------------------- phases
def make_tasks(phase):
    tasks = []
    if phase == 'guard':
        for cohort, seed in STAGES['guard']:
            for policy in ('tpm_only', *CANDIDATES):
                tasks.append(dict(name=f'{cohort}-s{seed}-{policy}-clean', cohort=cohort, seed=seed,
                                  attackers=['client01', 'client06', 'client11'], policy=policy, mode='clean', variant='clean'))
    else:
        decision = read(LAB / 'guard-decision.json')
        arms = [a for a in EVAL_ARMS if a not in CANDIDATES or a in decision['qualified_candidates']]
        base.require(any(a in CANDIDATES for a in arms), 'No guard-qualified candidate')
        for i, (cohort, seed) in enumerate(STAGES['evaluation']):
            for policy in arms:
                for variant in VARIANTS:
                    mode = 'adaptive' if variant.startswith('adaptive') else variant
                    tasks.append(dict(name=f'{cohort}-s{seed}-{policy}-{variant}', cohort=cohort, seed=seed,
                                      attackers=ATTACKERS[i], policy=policy, mode=mode, variant=variant))
    return tasks


def phase_protocol(phase):
    folder = LAB / phase; path = folder / 'protocol-before-training.json'
    if path.exists():
        p = read(path); assert_locks(p); return p
    root = read(LAB / 'protocol-before-fitting.json'); assert_locks(root)
    base.require((LAB / 'models/head-cusum.json').exists(), 'Fit the model first')
    folder.mkdir(); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    p = {**root, 'phase': phase, 'tasks': make_tasks(phase), 'head_model_sha256': sha256_file(LAB / 'models/head-cusum.json'),
         'guard_decision_sha256': sha256_file(LAB / 'guard-decision.json') if phase == 'evaluation' else None}
    save(path, p); return p


def run_phase(phase, workers, folder=None, protocol=None):
    folder = folder or LAB / phase
    protocol = protocol or phase_protocol(phase)
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
    closed = run_phase('guard', 1)  # closed phase: authenticates, never retrains
    by = {(r['task']['seed'], r['task']['policy']): r for r in closed['results']}
    details, qualified = {}, []
    for cand in CANDIDATES:
        rows = []
        for cohort, seed in STAGES['guard']:
            result, control = by[(seed, cand)], by[(seed, 'tpm_only')]
            entry = dict(cohort=cohort, seed=seed, complete=bool(result['complete'] and control['complete']))
            if entry['complete']:
                part = read(LAB / 'partitions' / str(seed) / 'manifest.json')
                sizes = {r['client_id']: r['train_row_count'] for r in part['clients']}
                summaries, losses = [], []
                for number in range(1, 16):
                    row = read(LAB / 'guard/cases' / result['task']['name'] / 'evidence/rounds' / f'round-{number:03d}' / 'round.json')
                    summaries.append(dict(statuses=row['statuses'], masses=row['masses'], example_counts=sizes))
                    if number in (10, 15):
                        other = read(LAB / 'guard/cases' / control['task']['name'] / 'evidence/rounds' / f'round-{number:03d}' / 'round.json')
                        losses.append(other['validation']['clean']['macro_f1_all_model_classes'] -
                                      row['validation']['clean']['macro_f1_all_model_classes'])
                b = cal.budget_summary(summaries)
                entry.update(budget=b, validation_losses=losses, qualified=bool(
                    b['quarantine_rate'] <= BUDGETS['maximum_quarantine_rate'] and
                    b['nominal_mass_retention'] >= BUDGETS['minimum_nominal_mass_retention'] and
                    b['minimum_round_mass_retention'] >= BUDGETS['minimum_round_mass_retention'] and
                    max(losses) <= BUDGETS['maximum_fixed_endpoint_validation_f1_loss']))
            else:
                entry['qualified'] = False
            rows.append(entry)
        details[cand] = rows
        if all(r['qualified'] for r in rows):
            qualified.append(cand)
    decision = dict(qualified_candidates=qualified, details=details, uses_attack_or_test_outcomes=False,
                    guard_closure_sha256=sha256_file(LAB / 'guard/training-complete.json'))
    save(LAB / 'guard-decision.json', decision)
    print('GUARD ' + json.dumps(decision), flush=True)
    return decision


# ---------------------------------------------------------------- smoke
def smoke(folder):
    """Two-round developer check of every adapter path; writes only under ``folder``."""
    folder = Path(folder); base.require(not folder.exists(), 'Smoke folder must be new')
    root = read(LAB / 'protocol-before-fitting.json'); assert_locks(root)
    folder.mkdir(parents=True); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    cohort, seed = STAGES['guard'][2]
    tasks = [dict(name=f'smoke-{p}-{v}', cohort=cohort, seed=seed, attackers=ATTACKERS[0], policy=p,
                  mode='adaptive' if v.startswith('adaptive') else v, variant=v)
             for p, v in (('head_cusum', 'clean'), ('head_cusum', 'adaptive'), ('head_max', 'adaptive-headfrozen'),
                          ('gated_composite', 'distributed'))]
    protocol = {**root, 'phase': 'smoke', 'tasks': tasks, 'head_model_sha256': sha256_file(LAB / 'models/head-cusum.json'),
                'NOT_EVIDENCE': True}
    save(folder / 'protocol-before-training.json', protocol)
    original_range = base.range if hasattr(base, 'range') else None
    import builtins
    base.range = lambda *a: builtins.range(1, 3) if a == (1, 16) else builtins.range(*a)  # 2 rounds only
    try:
        configure(folder)
        for t in tasks:
            r = base.run_case(t)
            print('SMOKE ' + json.dumps(dict(task=t['name'], completed_rounds=r['completed_rounds'])), flush=True)
            for n in (1, 2):
                st = read(folder / 'cases' / t['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'gate-state.json')
                hg_state = st['head_gate']
                print(f"   round {n}: score max={max(hg_state['score'].values()):.2f} "
                      f"cusum max={max(hg_state['cusum'].values()):.2f} "
                      f"q_head_cusum={sum(not v['head_cusum']['contributes'] for v in st['decisions'].values())} "
                      f"q_head_max={sum(not v['head_max']['contributes'] for v in st['decisions'].values())}", flush=True)
                if n == 2:
                    prev = read(folder / 'cases' / t['name'] / 'evidence/rounds/round-001/gate-state.json')['head_gate']['cusum']
                    base.require(hg_state['previous_cusum'] == {c: float(v) for c, v in prev.items()}, 'CUSUM chain broken')
            if t['variant'] == 'adaptive-headfrozen':
                rd = folder / 'cases' / t['name'] / 'evidence/rounds/round-001'
                for c in t['attackers']:
                    pois, clean = read(rd / 'attack-endpoints' / f'{c}-poison.json'), read(rd / 'attack-endpoints' / f'{c}-clean.json')
                    for p, q in zip(pois['parameters'], clean['parameters']):
                        if p['name'].startswith(hg.HEAD_PREFIX):
                            base.require(p['values'] == q['values'], 'Head not frozen')
                print('   head-frozen attacker heads equal clean endpoints: OK', flush=True)
    finally:
        if original_range is None:
            del base.range


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'fit', 'guard', 'guard-decide', 'evaluation', 'smoke'))
    parser.add_argument('--workers', type=int, default=3)
    parser.add_argument('--smoke-dir', type=Path)
    parser.add_argument('--lab', type=Path, default=LAB,
                        help='study root; use a scratch path for developer dry runs (prepare/fit/smoke)')
    a = parser.parse_args()
    set_lab(a.lab)
    if a.command == 'prepare':
        prepare()
    elif a.command == 'fit':
        fit()
    elif a.command == 'guard':
        run_phase('guard', a.workers)
    elif a.command == 'guard-decide':
        guard_decide()
    elif a.command == 'evaluation':
        run_phase('evaluation', a.workers)
    else:
        smoke(a.smoke_dir)


if __name__ == '__main__':
    main()
