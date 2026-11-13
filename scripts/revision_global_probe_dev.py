"""Offline development: single-feature probe applied to the GLOBAL model.

DEVELOPMENT ONLY (validation rows, recorded models; no training, no test split).
Motivation (results/gates-probes/revision-probe-keynorm-confirm): the adaptive interpolation attacker
evades the peer-relative probe; once the backdoor reaches the global model, the peer-relative
rule flags honest clients that inherit it on the attacked features. Peer-relative scores cannot
see a shortcut that every client shares, so this script measures the probe on the aggregate.
For each key k: drift_k(r) = shortcut_k(global_r) - shortcut_k(initial model). Scale
s_k = max(clean maximum drift_k in the cohort, FLOOR), from the 12 verified clean TPM-only
histories of revision-clean-gate-calibration-v1 only. A round alarms when
max_k drift_k / s_k > MULT. Evaluated on archived cases of the two latest live studies.
Detection only: a rollback changes the trajectory, which only a live study can measure.
Commands: extract OUT_DIR, analyse OUT_DIR.
"""
from __future__ import annotations

import json
import multiprocessing
import sys
import tarfile
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import revision_head_cusum_study as hs
from revision_study_data import read
from revision_probe_keynorm_dev import vec, _setup

ROOT = base.ROOT
STUDIES = ('revision-probe-keynorm-confirm', 'revision-trigger-probe-evasion-live')
FLOORS = (0.05, 0.1, 0.2)
MULTS = (1.0, 1.5, 2.0, 3.0)


def clean_job(phase, name):
    ev = hs.CLEAN_SOURCE / phase / 'cases' / name / 'evidence'
    task = read(ev / 'task.json')
    init = vec(read(ev / 'rounds/round-001/base-model.json'))
    g = [vec(read(ev / 'rounds' / f'round-{r:03d}' / 'global-model.json')) for r in range(1, 16)]
    return dict(source='clean-calibration', task=task, init=init, rounds=g)


def tar_job(path):
    task, init, g, res = None, None, {}, None
    with tarfile.open(path, 'r:gz') as tar:
        for m in tar:
            if m.name.endswith('evidence/task.json'):
                task = json.load(tar.extractfile(m))
            elif m.name.endswith('/result.json') and m.name.count('/') == 1:
                res = json.load(tar.extractfile(m))
            elif m.name.endswith('round-001/base-model.json'):
                init = vec(json.load(tar.extractfile(m)))
            elif '/rounds/round-' in m.name and m.name.endswith('/global-model.json'):
                g[int(m.name.split('/rounds/round-')[1][:3])] = vec(json.load(tar.extractfile(m)))
    task = task or res['task']
    return dict(source=str(Path(path).relative_to(ROOT)), task=task, init=init, rounds=[g[n] for n in sorted(g)])


def extract(out):
    out.mkdir(parents=True, exist_ok=False)
    cjobs = [(ph, res['task']['name']) for ph in ('fit', 'calibration', 'selection')
             for res in read(hs.CLEAN_SOURCE / ph / 'training-complete.json')['results']
             if res['task']['policy'] == 'tpm_only' and not res['task'].get('candidate')]
    tars = [str(p) for s in STUDIES for p in sorted((ROOT / 'artifacts' / s).glob('*/cases/*.tar.gz'))]
    with ProcessPoolExecutor(2, mp_context=multiprocessing.get_context('spawn')) as pool:
        clean = list(pool.map(clean_job, *zip(*cjobs))); print('CLEAN', len(clean), flush=True)
        cases = []
        for i, c in enumerate(pool.map(tar_job, tars)):
            cases.append(c)
            if i % 20 == 0:
                print('CASES', i, flush=True)
    keys = [list(k) for k in _setup()['inputs'][1] if k is not None]
    (out / 'global-vectors.json').write_text(json.dumps(dict(keys=keys, clean=clean, cases=cases)))
    print('EXTRACTED', len(clean), len(cases), flush=True)


def drifts(h):
    i = np.array(h['init']); return [np.array(g) - i for g in h['rounds']]


def analyse(out):
    data = json.loads((out / 'global-vectors.json').read_text()); keys = data['keys']
    cmax = defaultdict(lambda: np.full(len(keys), -np.inf))
    for h in data['clean']:
        for d in drifts(h):
            cmax[h['task']['cohort']] = np.maximum(cmax[h['task']['cohort']], d)
    report = {}
    for f in FLOORS:
        for m in MULTS:
            name = f'floor {f}, x{m}'; clean_alarm = defaultdict(lambda: [0, 0]); att = defaultdict(lambda: [0, 0, []]); feats = defaultdict(int)
            for case in data['cases']:
                t = case['task']; s = np.maximum(cmax[t['cohort']], f)
                study = 'keynorm' if 'keynorm' in case['source'] else 'evasion'
                al = [int((d / s).max() > m) for d in drifts(case)]
                if t['variant'] == 'clean':
                    k = f"{study}|{t['policy']}|{t['cohort']}"; clean_alarm[k][0] += any(al); clean_alarm[k][1] += 1
                else:
                    k = f"{study}|{t['variant']}|{t['cohort']}|{t['policy']}"; att[k][0] += any(al); att[k][1] += 1
                    att[k][2].append(next((r + 1 for r, a in enumerate(al) if a), None))
                    for d in drifts(case):
                        z = d / s
                        if z.max() > m:
                            feats[keys[int(z.argmax())][0]] += 1
            report[name] = dict(clean_runs_alarmed={k: f'{a}/{b}' for k, (a, b) in sorted(clean_alarm.items())},
                                attacked_runs_alarmed={k: dict(runs=f'{a}/{b}', first_round=fr) for k, (a, b, fr) in sorted(att.items())},
                                alarm_features=dict(sorted(feats.items(), key=lambda x: -x[1])[:8]))
            ca = sum(int(v.split('/')[0]) for v in report[name]['clean_runs_alarmed'].values())
            ad = [v['runs'] for k, v in report[name]['attacked_runs_alarmed'].items() if 'adaptive' in k]
            print(f'{name:16} clean_alarmed={ca} adaptive={ad}', flush=True)
    (out / 'global-probe.json').write_text(json.dumps(dict(scales={c: v.tolist() for c, v in cmax.items()}, report=report), indent=1))


if __name__ == '__main__':
    {'extract': extract, 'analyse': analyse}[sys.argv[1]](Path(sys.argv[2]))
