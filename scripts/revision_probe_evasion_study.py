"""Predeclared live study: trigger probe (+ pair probe) + clipping vs a probe-aware attacker.

Thin wrapper around revision_probe_study.py (same engine, guard rule, closure, failure
handling). Changes, all declared before training:
* Attack plan (all cases, clean included, so paired harm compares the same trigger):
  3 attackers, AND-trigger pairs {3,18} {8,15} {11,22} at 6 std units, rounds 1-10,
  target 'benign'. Component triggers = the pairs; complete trigger = all six features.
* Variants: clean; pair-dba (ordinary distributed DBA on the pairs, 50% rows,
  core poison_local_rows); evasive (probe-aware: per attack round 50% of rows get the
  pair and label 'benign' (attack rows only), 25% get only the first feature and 25%
  only the second, original labels kept: negative augmentation that hides single-feature
  shortcuts; offline prototype scripts/revision_trigger_probe_evasion.py).
* Arms: tpm_only+fedavg (reference), tpm_only+bounded, probe+bounded (unchanged
  single-feature probe, pinned clean-max thresholds), probe2+bounded (single OR pair
  probe; pair thresholds = clean maximum per cohort over the 12 verified clean TPM-only
  histories of revision-clean-gate-calibration-v1, fitted by `calibrate` before `prepare`).
Commands: calibrate OUT_JSON | prepare | smoke --smoke-dir D | guard | guard-decide |
evaluation | test. Software trust assumption; no new TPM Quotes.
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_probe_study as ps
import revision_head_v2_study as v2
import revision_head_cusum_study as hs
import revision_head_cusum_test as ht
import trigger_probe_gate as tp
import pair_probe_gate as pp
from revision_study_data import read, dependencies, Generator
from revision_dba_experiment import save, authenticate, environment
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.federated_model import train_local, export_state
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
LAB = ROOT / 'artifacts/revision-trigger-probe-evasion-live'
RESULTS = ROOT / 'results/revision-trigger-probe-evasion-live'
PAIR_THRESHOLDS_FILE = RESULTS / 'calibration/pair-thresholds.json'
PAIRS = [[3, 18], [8, 15], [11, 22]]
TRIGGER_VALUE = 6.0
ARMS = ('tpm_only+fedavg', 'tpm_only+bounded', 'probe+bounded', 'probe2+bounded')
VARIANTS = ('clean', 'pair-dba', 'evasive')
STAGES = {
    'guard': [('iid', 2027600001), ('iid', 2027601001), ('non-iid', 2027602001), ('non-iid', 2027603001)],
    'evaluation': [('iid', 2027610001 + 1000 * k) for k in range(4)] + [('non-iid', 2027620001 + 1000 * k) for k in range(4)],
}
PRIOR = (*ps.PRIOR, 'revision-trigger-probe-live')
HYPOTHESES = [
    dict(id='E1_single_probe_vs_aware_attacker', a='probe+bounded', b='tpm_only+bounded', variants=['evasive'],
         text='unchanged single-feature probe + clipping: lower paired peak harm than clipping alone against the evasive attacker (majority of defined comparisons)'),
    dict(id='E2_pair_probe_vs_aware_attacker', a='probe2+bounded', b='tpm_only+bounded', variants=['evasive'],
         text='single+pair probe + clipping: lower paired peak harm than clipping alone against the evasive attacker (majority)'),
    dict(id='E3_pair_probe_vs_reference', a='probe2+bounded', b='tpm_only+fedavg', variants=['pair-dba', 'evasive'], only_effective=True,
         text='single+pair probe + clipping: lower paired peak harm than TPM-only FedAvg in effective controls (majority)'),
    dict(id='E4_positive_control_pair_dba', a='probe+bounded', b='tpm_only+bounded', variants=['pair-dba'],
         text='positive control: single probe + clipping beats clipping alone on the ordinary (non-evasive) pair DBA (majority)'),
]
SECONDARY = ('Descriptive, declared before training: (a) attacker cost of evasion = reference-arm (TPM-only FedAvg) '
             'full/worst-trigger peak ASR, evasive vs pair-dba, and number of effective evasive controls; (b) attacker '
             'client-rounds quarantined in rounds 1-10 per arm and variant, and which probe (single/pair) fired, with the '
             'feature(s) reported; (c) honest quarantine rate in attacked runs. Interpretation rule: if fewer than 4 of the 8 '
             'evasive reference controls are effective, E1-E3 are still reported, but the conclusion is that the evasive '
             'attack is weak live, not that the probe is robust.')


# ---------------------------------------------------------------- attack + plan

def make_plan(protocol, task):
    return DistributedBackdoorPlan.model_validate({**protocol['training']['attack_plan'], 'seed': task['seed'],
        'client_components': dict(zip(task['attackers'], PAIRS, strict=True)),
        'trigger_values_decimal': {str(f): f'{TRIGGER_VALUE:g}' for p in PAIRS for f in p}, 'attack_rounds': list(range(1, 11))})


def evasive_rows(rows, pair, value, seed, number, client_index):
    rng = np.random.default_rng(seed + number * 10_000 + client_index)
    idx = rng.permutation(len(rows)); a, b = len(rows) // 2, (3 * len(rows)) // 4
    out = copy.deepcopy(rows); poisoned, neg = [], []
    for i in idx[:a]:
        if out[i]['label'] != 'benign':
            out[i]['features'][pair[0]] = value; out[i]['features'][pair[1]] = value; out[i]['label'] = 'benign'
            poisoned.append(out[i]['window_id'])
    for i in idx[a:b]:
        out[i]['features'][pair[0]] = value; neg.append(out[i]['window_id'])
    for i in idx[b:]:
        out[i]['features'][pair[1]] = value; neg.append(out[i]['window_id'])
    return out, dict(strategy='evasive-and-trigger', feature_indices=list(pair), value=value,
                     poisoned_window_ids=poisoned, negative_augmented_window_ids=neg, executed_rows_sha256=base.digest(out))


ORIG_TRAIN_ONE = base.train_one


def train_one(gen, base_model, seed, number, client, plan=None, distributed=True):
    if plan is None or not getattr(gen, 'evasive', False):
        return ORIG_TRAIN_ONE(gen, base_model, seed, number, client, plan, distributed)
    rows, poisoning = gen.rows[client], None
    if client in plan.client_components and number in plan.attack_rounds:
        rows, poisoning = evasive_rows(rows, plan.client_components[client], TRIGGER_VALUE, plan.seed, number,
                                       sorted(plan.client_components).index(client))
    local_seed = seed + number * 10000 + int(gen.records[client]['partition_id'])
    model = _model_from_export(base_model, torch=gen.torch, np=np)
    train_local(model=model, rows=rows, class_names=base_model['class_names'], class_weights=gen.weights,
                epochs=gen.cfg['local_epochs'], batch_size=gen.cfg['batch_size'], learning_rate=gen.cfg['learning_rate'],
                seed=local_seed, device_name='cpu', torch=gen.torch, np=np)
    exported = export_state(model, architecture=base_model['architecture'], class_names=base_model['class_names'])
    return exported, dict(client_id=client, seed=local_seed, snapshot_sha256=gen.records[client]['dataset_sha256'],
                          executed_rows_sha256=base.digest(rows), local_model_sha256=base.digest(exported), poisoning=poisoning)


# ---------------------------------------------------------------- gate

PS_CONTEXT = ps.context  # single-probe context (thresholds, bounds)


def context(protocol, task):
    gen, rows, correct = PS_CONTEXT(protocol, task)
    gen.evasive = task['variant'] == 'evasive'
    gen.pair_threshold = float(protocol['pair_probe']['thresholds'][task['cohort']])
    gen.pair_stack, gen.pair_keys, gen.pair_n = pp.probe_inputs(rows)
    return gen, rows, correct


def gate_state(initial, exports, gen, settings, rows):
    state, arrays = ps.ORIGINAL_STATE(initial, exports, gen, settings, rows)
    models = {c: _model_from_export(e, torch=gen.torch, np=np) for c, e in zip(gen.clients, exports)}
    single = tp.round_scores({c: tp.shortcuts(m, gen.probe_stack, gen.probe_keys, gen.probe_n, gen.benign_index, gen.torch) for c, m in models.items()})
    pair = pp.round_scores({c: tp.shortcuts(m, gen.pair_stack, gen.pair_keys, gen.pair_n, gen.benign_index, gen.torch) for c, m in models.items()})
    d1 = tp.decide(single, gen.probe_threshold, trust_admissible=base.TRUST.admissible)
    d2 = pp.decide(d1, pair, gen.pair_threshold, trust_admissible=base.TRUST.admissible)
    for c in gen.clients:
        state['decisions'][c][tp.POLICY] = d1[c]; state['decisions'][c][pp.POLICY] = d2[c]
        for arm in ARMS:
            state['decisions'][c][arm] = copy.deepcopy(state['decisions'][c][arm.split('+')[0]])
    state['probe'] = dict(threshold=gen.probe_threshold, cohort=gen.gate_cohort,
                          score={c: single[c][0] for c in gen.clients}, best={c: single[c][1] for c in gen.clients})
    state['pair_probe'] = dict(threshold=gen.pair_threshold, score={c: pair[c][0] for c in gen.clients}, best={c: pair[c][1] for c in gen.clients})
    return state, arrays


def source_locks():
    locks = ps.ORIGINAL_SOURCE_LOCKS()
    for n in ('pair_probe_gate.py', 'revision_probe_evasion_study.py'):
        p = ROOT / 'scripts' / n; locks[str(p.relative_to(ROOT))] = sha256_file(p)
    locks[str(PAIR_THRESHOLDS_FILE.relative_to(ROOT))] = sha256_file(PAIR_THRESHOLDS_FILE)
    return locks


def worker(task, phase_dir, lab):
    ps.LAB = Path(lab); ps.configure(phase_dir)
    return base.run_case(task)


# Module-level wiring so spawned workers (which import this module) get the same behaviour.
ps.ORIGINAL_SOURCE_LOCKS = getattr(ps, 'ORIGINAL_SOURCE_LOCKS', ps.source_locks)
ps.source_locks, ps.context, ps.gate_state, ps.worker = source_locks, context, gate_state, worker
ps.ARMS, ps.VARIANTS, ps.STAGES, ps.HYPOTHESES, ps.PRIOR, ps.LAB = ARMS, VARIANTS, STAGES, HYPOTHESES, PRIOR, LAB
ps.GATE_POLICIES = (*ps.GATE_POLICIES, pp.POLICY)
base.train_one, base.make_plan = train_one, make_plan


def mode_for(variant):
    return {'clean': 'clean', 'pair-dba': 'distributed', 'evasive': 'evasive'}[variant]


def make_tasks(phase):
    tasks = []
    if phase == 'guard':
        for cohort, seed in STAGES['guard']:
            for arm in ARMS:
                tasks.append(dict(name=f'{cohort}-s{seed}-{arm}-clean', cohort=cohort, seed=seed,
                                  attackers=['client01', 'client06', 'client11'], policy=arm, mode='clean', variant='clean'))
        return tasks
    decision = read(LAB / 'guard-decision.json'); arms = [a for a in ARMS if a == ps.REFERENCE_ARM or a in decision['qualified_arms']]
    p = read(LAB / 'protocol-before-guard.json')
    for cohort, seed in STAGES['evaluation']:
        for arm in arms:
            for v in VARIANTS:
                tasks.append(dict(name=f'{cohort}-s{seed}-{arm}-{v}', cohort=cohort, seed=seed, attackers=p['attackers'][str(seed)],
                                  policy=arm, mode=mode_for(v), variant=v))
    return tasks


ps.make_tasks = make_tasks


# ---------------------------------------------------------------- calibration (before prepare)

def _calibration_case(phase, result):
    clean_root = read(hs.CLEAN_SOURCE / 'protocol-before-clean-fitting.json'); cfg = clean_root['training']
    deps = dependencies(); torch = deps[1]; torch.set_num_threads(2)
    val = read(cfg['validation_path'])['rows']['validation']; stack, keys, n = pp.probe_inputs(val)
    bi = read(cfg['base_model_path'])['class_names'].index('benign')
    t = result['task']; ev = hs.CLEAN_SOURCE / phase / 'cases' / t['name'] / 'evidence'; authenticate(ev, result['manifest_sha256'])
    rounds = []
    for r in range(1, 16):
        rd = ev / 'rounds' / f'round-{r:03d}'
        per = {p.stem: tp.shortcuts(_model_from_export(read(p), torch=torch, np=np), stack, keys, n, bi, torch)
               for p in sorted((rd / 'updates').glob('client*.json'))}
        rounds.append({c: v for c, (v, _) in pp.round_scores(per).items()})
    return dict(phase=phase, case=t['name'], cohort=t['cohort'], seed=t['seed'], rounds=rounds)


def calibrate(out, workers):
    out = Path(out); base.require(not out.exists(), 'Pair thresholds exist; preserve them')
    jobs, pins = [], {}
    for phase in ('fit', 'calibration', 'selection'):
        closed_path = hs.CLEAN_SOURCE / phase / 'training-complete.json'
        receipt = read(hs.CLEAN_SOURCE / phase / 'verified/summary.json')
        base.require(receipt['status'] == 'verified' and receipt['training_closure_sha256'] == sha256_file(closed_path), f'{phase} not verified')
        pins[phase] = dict(training_complete=sha256_file(closed_path), verified=sha256_file(hs.CLEAN_SOURCE / phase / 'verified/summary.json'))
        for result in read(closed_path)['results']:
            t = result['task']
            if t['policy'] == 'tpm_only' and not t.get('candidate'):
                base.require(result['complete'], 'incomplete clean history'); jobs.append((phase, result))
    with ProcessPoolExecutor(workers, mp_context=multiprocessing.get_context('spawn')) as pool:
        cases = list(pool.map(_calibration_case, *zip(*jobs)))
    by = {}
    for c in cases:
        by.setdefault(c['cohort'], []).extend(v for rs in c['rounds'] for v in rs.values())

    def quant(v, q):
        v = sorted(v); return v[max(0, math.ceil(Fraction(q) * len(v)) - 1)]
    report = dict(rule='clean maximum per cohort of the peer-relative pair-probe score', thresholds={k: max(v) for k, v in by.items()},
                  q98={k: quant(v, '0.98') for k, v in by.items()}, q995={k: quant(v, '0.995') for k, v in by.items()},
                  n_scores={k: len(v) for k, v in by.items()}, histories=len(cases), source=str(hs.CLEAN_SOURCE.relative_to(ROOT)),
                  source_pins=pins, probe=dict(values=list(pp.VALUES), subset=pp.SUBSET, subset_seed=pp.SUBSET_SEED, pairs=300),
                  pair_probe_gate_sha256=sha256_file(ROOT / 'scripts/pair_probe_gate.py'),
                  uses_evaluation_partitions=False, cases=cases)
    out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(report, indent=1) + '\n')
    print('CALIBRATED ' + json.dumps({k: report[k] for k in ('thresholds', 'q98', 'q995', 'n_scores', 'histories')}), flush=True)


# ---------------------------------------------------------------- prepare

def prepare():
    base.require(not LAB.exists(), 'Preserve existing study')
    base.require(PAIR_THRESHOLDS_FILE.exists(), 'Run calibrate first')
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
            m = dict(profile='probe-evasion-live-allocation', seed=seed, partition_mode=cohort, dirichlet_alpha=.3 if cohort == 'non-iid' else None,
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
    thr = read(ps.THRESHOLDS_FILE)['max']['thresholds']; pair = read(PAIR_THRESHOLDS_FILE)
    bounds = {c: dict(path=str(p.relative_to(ROOT)), sha256=sha256_file(p)) for c, p in v2.BOUNDS.items()}
    protocol = dict(
        profile='trigger-probe-evasion-live-study', stages=STAGES, attackers=attackers, attacker_data_share=share, arms=ARMS,
        reference_arm=ps.REFERENCE_ARM, variants=VARIANTS, hypotheses=HYPOTHESES, secondary_endpoints=SECONDARY, guard_rule=ps.GUARD,
        attack=dict(pairs=PAIRS, trigger_value=TRIGGER_VALUE, attack_rounds=list(range(1, 11)), target='benign',
                    pair_dba='core poison_local_rows, distributed components = pairs, poisoned fraction from the frozen attack plan',
                    evasive='50% of rows: pair set + label benign (attack rows only); 25%: first feature only; 25%: second feature only; original labels',
                    value_choice='6 std units: the more effective value offline (0-15% vs 0% ASR at 12); the clean arm uses the same plan so paired harm compares the same trigger'),
        training=clean_root['training'], runtime_admission=clean_root['runtime_admission'], partitions=partitions,
        source_snapshots=clean_root['source_snapshots'], source_locks=source_locks(), environment=environment(), tensor_bounds=bounds,
        probe=dict(values=list(tp.VALUES), thresholds=thr, threshold_rule='clean maximum per cohort (unchanged from the previous live study)',
                   thresholds_file=str(ps.THRESHOLDS_FILE.relative_to(ROOT)), thresholds_sha256=sha256_file(ps.THRESHOLDS_FILE)),
        pair_probe=dict(values=list(pp.VALUES), subset=pp.SUBSET, subset_seed=pp.SUBSET_SEED, thresholds=pair['thresholds'],
                        threshold_rule=pair['rule'], thresholds_file=str(PAIR_THRESHOLDS_FILE.relative_to(ROOT)),
                        thresholds_sha256=sha256_file(PAIR_THRESHOLDS_FILE), fitted_on='12 verified clean TPM-only histories (revision-clean-gate-calibration-v1); not on study partitions'),
        partition_distinctness='checked within study and against surviving earlier gate studies incl. revision-trigger-probe-live',
        endpoints='Paired worst-trigger peak harm (complete trigger and the three pair components); full peak/final test ASR; clean F1; failures undefined.',
        promotion='No automatic promotion. Seed is the repetition unit; one dataset (Data24).', new_TPM_Quotes=0)
    save(LAB / 'protocol-before-guard.json', protocol)
    (LAB / 'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print('PREPARED ' + json.dumps(dict(protocol_sha256=sha256_file(LAB / 'protocol-before-guard.json'), thresholds=thr,
                                        pair_thresholds=pair['thresholds'], attacker_share=share)), flush=True)


def smoke(folder):
    import builtins
    folder = Path(folder); base.require(not folder.exists(), 'Smoke folder must be new')
    root = read(LAB / 'protocol-before-guard.json'); ps.assert_locks(root)
    folder.mkdir(parents=True); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    cohort, seed = STAGES['evaluation'][0]
    tasks = [dict(name=f'smoke-{a}-{v}', cohort=cohort, seed=seed, attackers=root['attackers'][str(seed)], policy=a, mode=mode_for(v), variant=v)
             for a, v in (('probe2+bounded', 'evasive'), ('probe+bounded', 'pair-dba'), ('tpm_only+fedavg', 'clean'))]
    save(folder / 'protocol-before-training.json', {**root, 'phase': 'smoke', 'tasks': tasks, 'NOT_EVIDENCE': True})
    base.range = lambda *x: builtins.range(1, 3) if x == (1, 16) else builtins.range(*x)
    try:
        ps.configure(folder)
        for t in tasks:
            r = base.run_case(t)
            st = read(folder / 'cases' / t['name'] / 'evidence/rounds/round-002/gate-state.json')
            print('SMOKE ' + json.dumps(dict(task=t['name'], rounds=r['completed_rounds'], attackers=t['attackers'],
                  single={c: [round(st['probe']['score'][c], 3), st['probe']['best'][c]] for c in t['attackers']},
                  pair={c: [round(st['pair_probe']['score'][c], 3), st['pair_probe']['best'][c]] for c in t['attackers']},
                  quarantined=[c for c, d in st['decisions'].items() if not d[t['policy']]['contributes']])), flush=True)
    finally:
        del base.range


# ---------------------------------------------------------------- test (after verification)

def _test_case(lab, result, phase):
    return ht.evaluate_case(lab, result, phase)  # base.make_plan is the pair plan (module wiring above)


def test(workers):
    folder = LAB / 'evaluation'; closure_path = folder / 'training-complete.json'
    base.require(closure_path.exists(), 'Evaluation training has not closed')
    verified = read(folder / 'verified/summary.json')
    base.require(verified['status'] == 'verified' and verified['training_closure_sha256'] == sha256_file(closure_path), 'Not verified')
    out_dir = folder / 'test'; base.require(not out_dir.exists(), 'Test phase already opened; results are write-once')
    protocol = read(folder / 'protocol-before-training.json')
    manifest_path = ht.SOURCE / 'manifest.json'
    base.require(sha256_file(manifest_path) == protocol['source_snapshots'][str(manifest_path)], 'Evaluation manifest pin')
    split = read(manifest_path)['server_evaluation_splits']['test']
    out_dir.mkdir()
    save(out_dir / 'precommit-before-test.json', dict(opened_at=datetime.now(timezone.utc).isoformat(),
         test_split=dict(path=split['path'], sha256=split['sha256']), training_closure_sha256=sha256_file(closure_path),
         verification_sha256=sha256_file(folder / 'verified/summary.json'), evaluator_sha256=sha256_file(Path(ht.__file__)),
         wrapper_sha256=sha256_file(Path(__file__)), no_parameter_change_after_test=True))
    done = []
    with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context('spawn')) as pool:
        futures = [pool.submit(_test_case, str(LAB), r, 'evaluation') for r in read(closure_path)['results']]
        for f in as_completed(futures):
            res = f.result(); save(out_dir / 'cases' / f"{res['task']['name']}.json", res); done.append(res['task']['name'])
            print('TESTED ' + json.dumps(dict(case=res['task']['name'], rounds=len(res['rounds']))), flush=True)
    save(out_dir / 'summary.json', dict(status='tested', cases=sorted(done), evaluator_sha256=sha256_file(Path(ht.__file__)),
                                        training_closure_sha256=sha256_file(closure_path)))


def main():
    global LAB
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('calibrate', 'prepare', 'smoke', 'guard', 'guard-decide', 'evaluation', 'test'))
    ap.add_argument('--workers', type=int, default=2); ap.add_argument('--smoke-dir', type=Path)
    a = ap.parse_args()
    {'calibrate': lambda: calibrate(PAIR_THRESHOLDS_FILE, a.workers), 'prepare': prepare, 'smoke': lambda: smoke(a.smoke_dir),
     'guard': lambda: ps.run_phase('guard', a.workers), 'guard-decide': ps.guard_decide,
     'evaluation': lambda: ps.run_phase('evaluation', a.workers), 'test': lambda: test(a.workers)}[a.command]()


if __name__ == '__main__':
    main()
