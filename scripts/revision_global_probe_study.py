"""Predeclared live study: per-key client probe + GLOBAL-model probe with rollback ('probekg').

Wrapper around revision_probe_keynorm_study.py (same engine, pair attack plan, evasive and
adaptive attacks, per-key client gate, clipping, guard rule, closure, test). Declared before training:
* Client gate: unchanged probek (pinned scales of revision-probe-keynorm-confirm, x2).
* Global probe, frozen from development (results/gates-probes/revision-global-probe-dev): after clipping
  aggregation, drift_k = shortcut_k(candidate global) - shortcut_k(initial model of the case);
  scale s_k = max(clean max drift_k per cohort, 0.1) from the 12 verified clean TPM-only histories
  of revision-clean-gate-calibration-v1 (refitted by `calibrate`, pinned). If max_k drift_k/s_k > 1.5
  the round is ROLLED BACK: the new global model equals the previous one (client decisions and
  masses are still recorded). The adaptive attacker's search scores candidates after the complete
  defence, rollback included.
* Arms: tpm_only+fedavg (reference), tpm_only+bounded, probek+bounded, probekg+bounded.
Commands: calibrate | prepare | smoke --smoke-dir D | guard | guard-decide | evaluation | test.
"""
from __future__ import annotations

import argparse
import builtins
import copy
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_probe_keynorm_study as kn  # wires ps (pair plan, evasive rows, probek)
import revision_probe_evasion_study as ev
import revision_probe_study as ps
import revision_head_v2_study as v2
import revision_head_cusum_study as hs
import trigger_probe_gate as tp
import keynorm_probe_gate as kp
from revision_study_data import read, dependencies
from revision_dba_experiment import save, authenticate
from fl_forensics.canonical import sha256_file
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
LAB = ROOT / 'artifacts/revision-global-probe-confirm'
RESULTS = ROOT / 'results/gates-probes/revision-global-probe-confirm'
GSCALES_FILE = RESULTS / 'calibration/global-scales.json'
POLICY = 'probekg'
FLOOR, MULTIPLIER = 0.1, 1.5
ARMS = ('tpm_only+fedavg', 'tpm_only+bounded', 'probek+bounded', 'probekg+bounded')
VARIANTS = kn.VARIANTS
STAGES = {
    'guard': [('iid', 2027800001), ('iid', 2027801001), ('non-iid', 2027802001), ('non-iid', 2027803001)],
    'evaluation': [('iid', 2027810001 + 1000 * k) for k in range(4)] + [('non-iid', 2027820001 + 1000 * k) for k in range(4)],
}
PRIOR = (*kn.PRIOR, 'revision-probe-keynorm-confirm')
HYPOTHESES = [
    dict(id='G1_rollback_vs_adaptive', a='probekg+bounded', b='probek+bounded', variants=['adaptive'],
         text='probekg+bounded lower paired peak harm than probek+bounded under the adaptive attack (majority)'),
    dict(id='G2_full_defence_vs_clipping', a='probekg+bounded', b='tpm_only+bounded', variants=['pair-dba', 'evasive', 'adaptive'],
         text='probekg+bounded lower paired peak harm than clipping alone, all attacks (majority)'),
    dict(id='G3_full_defence_vs_reference', a='probekg+bounded', b='tpm_only+fedavg', variants=['pair-dba', 'evasive', 'adaptive'], only_effective=True,
         text='probekg+bounded lower paired peak harm than TPM-only FedAvg in effective controls (majority)'),
]
ATTACKED_GUARD = dict(arm='probekg+bounded', maximum_honest_quarantine_rate=.05, maximum_consecutive_honest_exclusions=1,
                      text='G4 (attacked guard, predeclared): over all 24 attacked evaluation runs of probekg+bounded, honest client-round '
                           'quarantine <=5% and no honest client excluded in 2 consecutive rounds in any run. Computed from round statuses '
                           '(status not accepted/accepted_downweighted = excluded). Holds only if both conditions hold.')
SECONDARY = ('Declared before training. If probekg+bounded fails the clean guard, G1-G4 are undefined. Descriptive: rollback rounds '
             'per arm/variant/cohort (clean included); attacker client-rounds quarantined; effective controls per variant; final '
             'validation F1 of probekg vs probek in clean runs (cost of false rollbacks).')


# ---------------------------------------------------------------- gate

def drift_score(model, gen):
    v = tp.shortcuts(_model_from_export(model, torch=gen.torch, np=np), gen.probe_stack, gen.probe_keys, gen.probe_n, gen.benign_index, gen.torch)
    z = {k: (v[k] - gen.global_init[k]) / max(gen.global_scales[k], FLOOR) for k in gen.global_scales}
    k = max(z, key=z.get)
    return float(z[k]), [k[0], k[1]]


def context(protocol, task):
    gen, rows, correct = kn.context(protocol, task)
    gen.global_scales = {(int(j), float(v)): float(s) for j, v, s in protocol['global_probe']['scales'][task['cohort']]}
    gen.global_multiplier = float(protocol['global_probe']['multiplier'])
    gen.global_init = tp.shortcuts(_model_from_export(gen.initial, torch=gen.torch, np=np), gen.probe_stack, gen.probe_keys, gen.probe_n,
                                   gen.benign_index, gen.torch)
    return gen, rows, correct


def gate_state(initial, exports, gen, settings, rows):
    kn.ARMS = tuple(a for a in ARMS if a.split('+')[0] != POLICY)  # kn copies only the arms it knows
    try:
        state, arrays = kn.gate_state(initial, exports, gen, settings, rows)
    finally:
        kn.ARMS = ARMS
    for c in gen.clients:
        state['decisions'][c][POLICY] = copy.deepcopy(state['decisions'][c][kp.POLICY])
        state['decisions'][c]['probekg+bounded'] = copy.deepcopy(state['decisions'][c][kp.POLICY])
    return state, arrays


def numerical(initial, local_arrays, gen, state, settings, policy):
    model, masses, coefficients = v2.numerical(initial, local_arrays, gen, state, settings, policy)
    if policy != 'probekg+bounded' or model is None:
        return model, masses, coefficients
    score, key = drift_score(model, gen); alarm = score > gen.global_multiplier
    state['global_probe'] = dict(score=score, key=key, multiplier=gen.global_multiplier, rollback=alarm,
                                 candidate_sha256=base.digest(model))
    return (initial if alarm else model), masses, coefficients


ORIGINAL_CONFIGURE = ps.configure


def configure(phase_dir):
    ORIGINAL_CONFIGURE(phase_dir)
    base.numerical = numerical


def source_locks():
    locks = kn.source_locks()
    for p in (ROOT / 'scripts/revision_global_probe_study.py', GSCALES_FILE):
        locks[str(p.relative_to(ROOT))] = sha256_file(p)
    return locks


def worker(task, phase_dir, lab):
    ps.LAB = Path(lab); configure(phase_dir)
    return base.run_case(task)


# Module-level wiring (over the key-norm wrapper's wiring) for spawned workers.
ps.configure, ps.source_locks, ps.context, ps.gate_state, ps.worker = configure, source_locks, context, gate_state, worker
kn.ARMS, kn.STAGES, kn.PRIOR, kn.LAB, kn.HYPOTHESES, kn.SECONDARY = ARMS, STAGES, PRIOR, LAB, HYPOTHESES, SECONDARY
ps.ARMS, ps.STAGES, ps.HYPOTHESES, ps.PRIOR, ps.LAB = ARMS, STAGES, HYPOTHESES, PRIOR, LAB
ps.make_tasks = kn.make_tasks
ev.LAB = LAB


# ---------------------------------------------------------------- calibration

def _clean_case(phase, name, manifest_sha):
    cfg = read(hs.CLEAN_SOURCE / 'protocol-before-clean-fitting.json')['training']
    deps = dependencies(); torch = deps[1]; torch.set_num_threads(2)
    val = read(cfg['validation_path'])['rows']['validation']; stack, keys, n = tp.probe_inputs(val)
    bi = read(cfg['base_model_path'])['class_names'].index('benign')
    evd = hs.CLEAN_SOURCE / phase / 'cases' / name / 'evidence'; authenticate(evd, manifest_sha)
    sc = lambda p: tp.shortcuts(_model_from_export(read(p), torch=torch, np=np), stack, keys, n, bi, torch)
    init = sc(evd / 'rounds/round-001/base-model.json'); out = []
    for r in range(1, 16):
        g = sc(evd / 'rounds' / f'round-{r:03d}' / 'global-model.json'); out.append([[k[0], k[1], g[k] - init[k]] for k in g])
    return read(evd / 'task.json')['cohort'], out


def calibrate(workers):
    base.require(not GSCALES_FILE.exists(), 'Global scales exist; preserve them')
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
        m = {}
        for c, rounds in out:
            if c == cohort:
                for row in rounds:
                    for j, v, d in row:
                        m[(j, v)] = max(m.get((j, v), -np.inf), d)
        scales[cohort] = [[k[0], k[1], m[k]] for k in m]
    report = dict(rule=f'drift = global shortcut - initial-model shortcut; rollback when max drift/max(clean max drift, {FLOOR}) > {MULTIPLIER}',
                  floor=FLOOR, multiplier=MULTIPLIER, scales=scales, histories=len(out), source=str(hs.CLEAN_SOURCE.relative_to(ROOT)),
                  source_training_complete_sha256=pins, uses_study_partitions=False)
    GSCALES_FILE.parent.mkdir(parents=True, exist_ok=True); GSCALES_FILE.write_text(json.dumps(report, indent=1) + '\n')
    dev = json.loads((ROOT / 'results/gates-probes/revision-global-probe-dev/global-probe.json').read_text())['scales']
    match = all(np.allclose([s for _, _, s in scales[c]], dev[c], atol=1e-5) for c in scales)
    print('CALIBRATED ' + json.dumps(dict(histories=len(out), matches_development=bool(match))), flush=True)


# ---------------------------------------------------------------- prepare / smoke

def prepare():
    base.require(GSCALES_FILE.exists(), 'Run calibrate first')
    kn.prepare()
    p = read(LAB / 'protocol-before-guard.json'); g = read(GSCALES_FILE)
    p.update(profile='global-probe-rollback-confirmatory-study', attacked_guard=ATTACKED_GUARD, source_locks=source_locks(),
             global_probe=dict(floor=g['floor'], multiplier=g['multiplier'], scales=g['scales'], rule=g['rule'],
                               action='rollback: the round global model equals the previous global model',
                               scales_file=str(GSCALES_FILE.relative_to(ROOT)), scales_sha256=sha256_file(GSCALES_FILE),
                               development='results/gates-probes/revision-global-probe-dev (multiplier chosen there with those data visible; frozen here)'))
    (LAB / 'protocol-before-guard.json').unlink(); save(LAB / 'protocol-before-guard.json', p)
    (LAB / 'controller-frozen-global.py').write_bytes(Path(__file__).read_bytes())
    print('PREPARED ' + json.dumps(dict(protocol_sha256=sha256_file(LAB / 'protocol-before-guard.json'))), flush=True)


def smoke(folder):
    folder = Path(folder); base.require(not folder.exists(), 'Smoke folder must be new')
    root = read(LAB / 'protocol-before-guard.json'); ps.assert_locks(root)
    folder.mkdir(parents=True); (folder / 'partitions').symlink_to(LAB / 'partitions', target_is_directory=True)
    cohort, seed = STAGES['evaluation'][4]
    tasks = [dict(name=f'smoke-{a}-{v}', cohort=cohort, seed=seed, attackers=root['attackers'][str(seed)], policy=a, mode=kn.mode_for(v), variant=v)
             for a, v in (('probekg+bounded', 'adaptive'), ('probekg+bounded', 'clean'), ('probekg+bounded', 'pair-dba'))]
    save(folder / 'protocol-before-training.json', {**root, 'phase': 'smoke', 'tasks': tasks, 'NOT_EVIDENCE': True})
    base.range = lambda *x: builtins.range(1, 4) if x == (1, 16) else builtins.range(*x)
    try:
        configure(folder)
        for t in tasks:
            r = base.run_case(t); gp = []
            for n in range(1, 4):
                f = folder / 'cases' / t['name'] / f'evidence/rounds/round-{n:03d}/gate-state.json'
                if f.exists():
                    s = read(f).get('global_probe', {}); gp.append([round(s.get('score', 0), 2), s.get('key'), s.get('rollback')])
            print('SMOKE ' + json.dumps(dict(task=t['name'], rounds=r['completed_rounds'], global_probe=gp)), flush=True)
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
