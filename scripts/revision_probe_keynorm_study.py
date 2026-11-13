"""Predeclared confirmatory live study: per-key normalised probe ('probek') + clipping.

Wrapper around revision_probe_evasion_study.py / revision_probe_study.py (same engine, pair
attack plan, evasive attack, guard rule, closure, test). Declared before training:
* Rule frozen from development (results/gates-probes/revision-probe-keynorm-dev): per-key scale =
  max(clean maximum of the peer-relative excess, 0.1) per cohort, quarantine when the
  normalised score > 2. Scales refitted by `calibrate` on the 12 verified clean TPM-only
  histories of revision-clean-gate-calibration-v1 (same data the development used).
* Attack plan in every case (clean included): pairs {3,18} {8,15} {11,22} at 6 std units,
  rounds 1-10. Variants: clean, pair-dba, evasive (probe-aware, as in the evasion study),
  adaptive (interpolation-strength search against the complete defence, engine default).
* Arms: tpm_only+fedavg (reference), tpm_only+bounded, probe+bounded (deployed raw rule),
  probek+bounded.
Commands: calibrate | prepare | smoke --smoke-dir D | guard | guard-decide | evaluation | test.
"""
from __future__ import annotations

import argparse
import copy
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_probe_evasion_study as ev   # wires revision_probe_study (pair plan, evasive rows)
import revision_probe_study as ps
import revision_head_v2_study as v2
import revision_head_cusum_study as hs
import trigger_probe_gate as tp
import keynorm_probe_gate as kp
from revision_study_data import read, dependencies
from revision_dba_experiment import save, authenticate, environment
from fl_forensics.canonical import sha256_file
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
LAB = ROOT / 'artifacts/revision-probe-keynorm-confirm'
RESULTS = ROOT / 'results/gates-probes/revision-probe-keynorm-confirm'
SCALES_FILE = RESULTS / 'calibration/key-scales.json'
ARMS = ('tpm_only+fedavg', 'tpm_only+bounded', 'probe+bounded', 'probek+bounded')
VARIANTS = ('clean', 'pair-dba', 'evasive', 'adaptive')
STAGES = {
    'guard': [('iid', 2027700001), ('iid', 2027701001), ('non-iid', 2027702001), ('non-iid', 2027703001)],
    'evaluation': [('iid', 2027710001 + 1000 * k) for k in range(4)] + [('non-iid', 2027720001 + 1000 * k) for k in range(4)],
}
PRIOR = (*ev.PRIOR, 'revision-trigger-probe-evasion-live')
HYPOTHESES = [
    dict(id='K1_probek_adds_to_clipping', a='probek+bounded', b='tpm_only+bounded', variants=['pair-dba', 'evasive', 'adaptive'],
         text='probek+bounded lower paired peak harm than clipping alone, all attacks (majority of defined comparisons)'),
    dict(id='K2_probek_dba_and_evasive', a='probek+bounded', b='tpm_only+bounded', variants=['pair-dba', 'evasive'],
         text='same, restricted to the attacks the probe targets (ordinary and probe-aware pair DBA)'),
    dict(id='K3_probek_vs_reference', a='probek+bounded', b='tpm_only+fedavg', variants=['pair-dba', 'evasive', 'adaptive'], only_effective=True,
         text='probek+bounded lower paired peak harm than TPM-only FedAvg in effective controls (majority)'),
    dict(id='K4_probek_vs_deployed_probe', a='probek+bounded', b='probe+bounded', variants=['pair-dba', 'evasive'],
         text='descriptive: per-key vs deployed raw probe (undefined if probe+bounded fails the guard)'),
]
SECONDARY = ('Declared before training. Primary gate requirement: probek+bounded passes the clean guard (revised rule) on all '
             '4 fresh guard assignments; if it fails, K1-K4 are undefined and the per-key rule is reported as not confirmed. '
             'Descriptive: attacker client-rounds quarantined (rounds 1-10) per arm/variant; honest quarantine rate and longest '
             'consecutive honest exclusion in ATTACKED runs of probek+bounded (target, not a hypothesis: <=5% and no run >=2); '
             'number of effective controls per variant. If fewer than 4 of 8 evasive reference controls are effective, the evasive '
             'part is reported as weak live.')


# ---------------------------------------------------------------- gate

PS_CONTEXT = ps.ORIGINAL_CONTEXT_PS if hasattr(ps, 'ORIGINAL_CONTEXT_PS') else ev.PS_CONTEXT


def load_scales(protocol, cohort):
    return {(int(j), float(v)): float(s) for j, v, s in protocol['probek']['scales'][cohort]}


def context(protocol, task):
    gen, rows, correct = PS_CONTEXT(protocol, task)
    gen.evasive = task['variant'] == 'evasive'
    gen.key_scales = load_scales(protocol, task['cohort']); gen.key_multiplier = float(protocol['probek']['multiplier'])
    return gen, rows, correct


def gate_state(initial, exports, gen, settings, rows):
    state, arrays = ps.ORIGINAL_STATE(initial, exports, gen, settings, rows)
    per = {c: tp.shortcuts(_model_from_export(e, torch=gen.torch, np=np), gen.probe_stack, gen.probe_keys, gen.probe_n, gen.benign_index, gen.torch)
           for c, e in zip(gen.clients, exports)}
    raw = tp.round_scores(per); norm = kp.round_scores(per, gen.key_scales)
    d1 = tp.decide(raw, gen.probe_threshold, trust_admissible=base.TRUST.admissible)
    dk = kp.decide(norm, gen.key_multiplier, trust_admissible=base.TRUST.admissible)
    for c in gen.clients:
        state['decisions'][c][tp.POLICY] = d1[c]; state['decisions'][c][kp.POLICY] = dk[c]
        for arm in ARMS:
            state['decisions'][c][arm] = copy.deepcopy(state['decisions'][c][arm.split('+')[0]])
    state['probe'] = dict(threshold=gen.probe_threshold, cohort=gen.gate_cohort,
                          score={c: raw[c][0] for c in gen.clients}, best={c: raw[c][1] for c in gen.clients})
    state['probek'] = dict(multiplier=gen.key_multiplier, score={c: norm[c][0] for c in gen.clients}, best={c: norm[c][1] for c in gen.clients})
    return state, arrays


def source_locks():
    locks = ps.ORIGINAL_SOURCE_LOCKS()
    for n in ('pair_probe_gate.py', 'revision_probe_evasion_study.py', 'keynorm_probe_gate.py', 'revision_probe_keynorm_study.py'):
        p = ROOT / 'scripts' / n; locks[str(p.relative_to(ROOT))] = sha256_file(p)
    locks[str(SCALES_FILE.relative_to(ROOT))] = sha256_file(SCALES_FILE)
    return locks


def worker(task, phase_dir, lab):
    ps.LAB = Path(lab); ps.configure(phase_dir)
    return base.run_case(task)


def mode_for(variant):
    return {'clean': 'clean', 'pair-dba': 'distributed', 'evasive': 'evasive', 'adaptive': 'adaptive'}[variant]


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


# Module-level wiring (re-applied over the evasion wrapper's wiring) for spawned workers.
ps.source_locks, ps.context, ps.gate_state, ps.worker, ps.make_tasks = source_locks, context, gate_state, worker, make_tasks
ps.ARMS, ps.VARIANTS, ps.STAGES, ps.HYPOTHESES, ps.PRIOR, ps.LAB = ARMS, VARIANTS, STAGES, HYPOTHESES, PRIOR, LAB
ps.GATE_POLICIES = ('tpm_only', 'sequential', 'gated_composite', tp.POLICY, kp.POLICY)
ev.LAB = LAB  # ev.test() reads ev.LAB


# ---------------------------------------------------------------- calibration

def _clean_case(phase, name, manifest_sha):
    cfg = read(hs.CLEAN_SOURCE / 'protocol-before-clean-fitting.json')['training']
    deps = dependencies(); torch = deps[1]; torch.set_num_threads(2)
    val = read(cfg['validation_path'])['rows']['validation']; stack, keys, n = tp.probe_inputs(val)
    bi = read(cfg['base_model_path'])['class_names'].index('benign')
    evd = hs.CLEAN_SOURCE / phase / 'cases' / name / 'evidence'; authenticate(evd, manifest_sha)
    task = read(evd / 'task.json'); rows = []
    for r in range(1, 16):
        rd = evd / 'rounds' / f'round-{r:03d}'
        per = {p.stem: tp.shortcuts(_model_from_export(read(p), torch=torch, np=np), stack, keys, n, bi, torch)
               for p in sorted((rd / 'updates').glob('client*.json'))}
        rows += [[[k[0], k[1], v] for k, v in ex.items()] for ex in kp.excess(per).values()]
    return task['cohort'], rows


def calibrate(workers):
    base.require(not SCALES_FILE.exists(), 'Scales exist; preserve them')
    jobs, pins = [], {}
    for phase in ('fit', 'calibration', 'selection'):
        closed = hs.CLEAN_SOURCE / phase / 'training-complete.json'; receipt = read(hs.CLEAN_SOURCE / phase / 'verified/summary.json')
        base.require(receipt['status'] == 'verified' and receipt['training_closure_sha256'] == sha256_file(closed), f'{phase} not verified')
        pins[phase] = sha256_file(closed)
        for res in read(closed)['results']:
            t = res['task']
            if t['policy'] == 'tpm_only' and not t.get('candidate'):
                base.require(res['complete'], 'incomplete'); jobs.append((phase, t['name'], res['manifest_sha256']))
    with ProcessPoolExecutor(workers, mp_context=multiprocessing.get_context('spawn')) as pool:
        out = list(pool.map(_clean_case, *zip(*jobs)))
    scales = {}
    for cohort in ('iid', 'non-iid'):
        rows = [{(j, v): e for j, v, e in row} for c, rs in out if c == cohort for row in rs]
        keys = list(rows[0]); s = kp.fit_scales(rows, keys)
        scales[cohort] = [[k[0], k[1], s[k]] for k in keys]
    report = dict(rule=f'scale = max(clean max peer-relative excess, {kp.FLOOR}); quarantine when max excess/scale > {kp.MULTIPLIER}',
                  floor=kp.FLOOR, multiplier=kp.MULTIPLIER, scales=scales, histories=len(out), source=str(hs.CLEAN_SOURCE.relative_to(ROOT)),
                  source_training_complete_sha256=pins, gate_sha256=sha256_file(ROOT / 'scripts/keynorm_probe_gate.py'), uses_study_partitions=False)
    SCALES_FILE.parent.mkdir(parents=True, exist_ok=True); SCALES_FILE.write_text(json.dumps(report, indent=1) + '\n')
    top = {c: sorted(v, key=lambda x: -x[2])[:5] for c, v in scales.items()}
    print('CALIBRATED ' + json.dumps(dict(histories=len(out), largest_scales=top)), flush=True)


# ---------------------------------------------------------------- prepare / smoke

def prepare():
    base.require(not LAB.exists(), 'Preserve existing study'); base.require(SCALES_FILE.exists(), 'Run calibrate first')
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
            m = dict(profile='probe-keynorm-confirm-allocation', seed=seed, partition_mode=cohort, dirichlet_alpha=.3 if cohort == 'non-iid' else None,
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
    thr = read(ps.THRESHOLDS_FILE)['max']['thresholds']; sc = read(SCALES_FILE)
    bounds = {c: dict(path=str(p.relative_to(ROOT)), sha256=sha256_file(p)) for c, p in v2.BOUNDS.items()}
    protocol = dict(
        profile='probe-keynorm-confirmatory-study', stages=STAGES, attackers=attackers, attacker_data_share=share, arms=ARMS,
        reference_arm=ps.REFERENCE_ARM, variants=VARIANTS, hypotheses=HYPOTHESES, secondary_endpoints=SECONDARY, guard_rule=ps.GUARD,
        attack=dict(pairs=ev.PAIRS, trigger_value=ev.TRIGGER_VALUE, attack_rounds=list(range(1, 11)), target='benign',
                    pair_dba='core poison_local_rows on the pairs', evasive='as revision-trigger-probe-evasion-live',
                    adaptive='engine default: interpolation-strength search scored after the complete defence (probe decisions + clipping)'),
        training=clean_root['training'], runtime_admission=clean_root['runtime_admission'], partitions=partitions,
        source_snapshots=clean_root['source_snapshots'], source_locks=source_locks(), environment=environment(), tensor_bounds=bounds,
        probe=dict(values=list(tp.VALUES), thresholds=thr, threshold_rule='deployed raw clean maximum (unchanged)',
                   thresholds_file=str(ps.THRESHOLDS_FILE.relative_to(ROOT)), thresholds_sha256=sha256_file(ps.THRESHOLDS_FILE)),
        probek=dict(floor=sc['floor'], multiplier=sc['multiplier'], scales=sc['scales'], rule=sc['rule'],
                    scales_file=str(SCALES_FILE.relative_to(ROOT)), scales_sha256=sha256_file(SCALES_FILE),
                    development='results/gates-probes/revision-probe-keynorm-dev (multiplier chosen there with those data visible; frozen here)'),
        partition_distinctness='checked within study and against surviving earlier gate studies incl. both probe live studies',
        endpoints='Paired worst-trigger peak harm (complete trigger and the three pairs); full peak/final test ASR; clean F1; failures undefined.',
        promotion='No automatic promotion. Seed is the repetition unit; one dataset (Data24).', new_TPM_Quotes=0)
    save(LAB / 'protocol-before-guard.json', protocol)
    (LAB / 'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print('PREPARED ' + json.dumps(dict(protocol_sha256=sha256_file(LAB / 'protocol-before-guard.json'), attacker_share=share)), flush=True)


def smoke(folder):
    import builtins
    folder = Path(folder); base.require(not folder.exists(), 'Smoke folder must be new')
    root = read(LAB / 'protocol-before-guard.json'); ps.assert_locks(root)
    folder.mkdir(parents=True); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    cohort, seed = STAGES['evaluation'][4]
    tasks = [dict(name=f'smoke-{a}-{v}', cohort=cohort, seed=seed, attackers=root['attackers'][str(seed)], policy=a, mode=mode_for(v), variant=v)
             for a, v in (('probek+bounded', 'evasive'), ('probek+bounded', 'adaptive'), ('probek+bounded', 'clean'), ('probe+bounded', 'pair-dba'))]
    save(folder / 'protocol-before-training.json', {**root, 'phase': 'smoke', 'tasks': tasks, 'NOT_EVIDENCE': True})
    base.range = lambda *x: builtins.range(1, 3) if x == (1, 16) else builtins.range(*x)
    try:
        ps.configure(folder)
        for t in tasks:
            r = base.run_case(t)
            st = read(folder / 'cases' / t['name'] / 'evidence/rounds/round-002/gate-state.json')
            print('SMOKE ' + json.dumps(dict(task=t['name'], rounds=r['completed_rounds'], attackers=t['attackers'],
                  probek={c: [round(st['probek']['score'][c], 2), st['probek']['best'][c]] for c in t['attackers']},
                  honest_max=round(max(v for c, v in st['probek']['score'].items() if c not in t['attackers']), 2),
                  quarantined=[c for c, d in st['decisions'].items() if not d[t['policy']]['contributes']])), flush=True)
    finally:
        del base.range


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('calibrate', 'prepare', 'smoke', 'guard', 'guard-decide', 'evaluation', 'test'))
    ap.add_argument('--workers', type=int, default=2); ap.add_argument('--smoke-dir', type=Path)
    a = ap.parse_args()
    {'calibrate': lambda: calibrate(a.workers), 'prepare': prepare, 'smoke': lambda: smoke(a.smoke_dir),
     'guard': lambda: ps.run_phase('guard', a.workers), 'guard-decide': ps.guard_decide,
     'evaluation': lambda: ps.run_phase('evaluation', a.workers), 'test': lambda: ev.test(a.workers)}[a.command]()


if __name__ == '__main__':
    main()
