"""Offline development: per-key normalisation of the single-feature probe.

DEVELOPMENT ONLY (validation rows, recorded models; no training, no test split).
Motivation (results/gates-probes/revision-probe-persistence-dev): 53/65 honest probe flags fall on
feature 12, a 'natural' shortcut whose strength varies across honest clients.
Rule studied: excess_k = shortcut_k - round peer median_k for each key k = (feature, value);
normalised score = max_k excess_k / s_k, with s_k = max(clean maximum of excess_k in the
cohort, FLOOR); quarantine when the normalised score > 1 (i.e. beyond the largest clean
excess ever seen for that key). s_k comes ONLY from the 12 verified clean TPM-only histories
of revision-clean-gate-calibration-v1. Evaluated on the 172 archived cases of the two live
probe studies (now development data). FLOOR variants and the deployed unnormalised rule
are compared. Commands: extract OUT_DIR (writes shortcut vectors), analyse OUT_DIR.
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
import trigger_probe_gate as tp
from revision_study_data import read, dependencies
from revision_dba_experiment import authenticate
from fl_forensics.secure_round import _model_from_export

ROOT = base.ROOT
STUDIES = ('revision-trigger-probe-live', 'revision-trigger-probe-evasion-live')
FLOORS = (0.05, 0.1, 0.2, 0.3)
_S = {}


def _setup():
    if not _S:
        cfg = read(hs.CLEAN_SOURCE / 'protocol-before-clean-fitting.json')['training']
        deps = dependencies(); deps[1].set_num_threads(1)
        val = read(cfg['validation_path'])['rows']['validation']
        _S.update(torch=deps[1], inputs=tp.probe_inputs(val), bi=read(cfg['base_model_path'])['class_names'].index('benign'))
    return _S


def vec(export):
    s = _setup(); stack, keys, n = s['inputs']
    d = tp.shortcuts(_model_from_export(export, torch=s['torch'], np=np), stack, keys, n, s['bi'], s['torch'])
    return [round(d[k], 6) for k in keys if k is not None]


def clean_job(phase, name, manifest_sha):
    ev = hs.CLEAN_SOURCE / phase / 'cases' / name / 'evidence'; authenticate(ev, manifest_sha)
    task = read(ev / 'task.json'); rounds = []
    for r in range(1, 16):
        rd = ev / 'rounds' / f'round-{r:03d}'
        rounds.append({p.stem: vec(read(p)) for p in sorted((rd / 'updates').glob('client*.json'))})
    return dict(source='clean-calibration', task=task, rounds=rounds)


def tar_job(path):
    task, rounds = None, {}
    with tarfile.open(path, 'r:gz') as tar:
        for m in tar:
            if m.name.endswith('evidence/task.json'):
                task = json.load(tar.extractfile(m))
            elif '/rounds/round-' in m.name and '/updates/client' in m.name and m.name.endswith('.json'):
                n = int(m.name.split('/rounds/round-')[1][:3]); c = Path(m.name).stem
                rounds.setdefault(n, {})[c] = vec(json.load(tar.extractfile(m)))
    return dict(source=str(Path(path).relative_to(ROOT)), task=task, rounds=[rounds[n] for n in sorted(rounds)])


def extract(out):
    out.mkdir(parents=True, exist_ok=False)
    cjobs = []
    for phase in ('fit', 'calibration', 'selection'):
        for res in read(hs.CLEAN_SOURCE / phase / 'training-complete.json')['results']:
            t = res['task']
            if t['policy'] == 'tpm_only' and not t.get('candidate'):
                cjobs.append((phase, t['name'], res['manifest_sha256']))
    tars = [str(p) for s in STUDIES for p in sorted((ROOT / 'artifacts' / s).glob('*/cases/*.tar.gz'))]
    with ProcessPoolExecutor(2, mp_context=multiprocessing.get_context('spawn')) as pool:
        clean = list(pool.map(clean_job, *zip(*cjobs)))
        print('CLEAN', len(clean), flush=True)
        cases = []
        for i, c in enumerate(pool.map(tar_job, tars)):
            cases.append(c)
            if i % 20 == 0:
                print('CASES', i, flush=True)
    keys = [list(k) for k in _setup()['inputs'][1] if k is not None]
    (out / 'vectors.json').write_text(json.dumps(dict(keys=keys, clean=clean, cases=cases)))
    print('EXTRACTED', len(clean), len(cases), flush=True)


def excess(rounds):
    out = []
    for rs in rounds:
        cl = sorted(rs); M = np.array([rs[c] for c in cl]); med = np.median(M, axis=0)
        out.append({c: M[i] - med for i, c in enumerate(cl)})
    return out


def analyse(out):
    data = json.loads((out / 'vectors.json').read_text()); keys = data['keys']
    cmax = defaultdict(lambda: np.full(len(keys), -np.inf)); craw = defaultdict(float)
    for h in data['clean']:
        for rs in excess(h['rounds']):
            for v in rs.values():
                cmax[h['task']['cohort']] = np.maximum(cmax[h['task']['cohort']], v); craw[h['task']['cohort']] = max(craw[h['task']['cohort']], float(v.max()))
    rules = {'raw clean-max (deployed)': lambda coh: (np.ones(len(keys)), craw[coh])}
    for f in FLOORS:
        rules[f'per-key, floor {f}'] = (lambda f: lambda coh: (np.maximum(cmax[coh], f), 1.0))(f)
    report = {}
    for name, rule in rules.items():
        hon = [0, 0]; longest = 0; fails = []; att = defaultdict(lambda: [0, 0]); hfeat = defaultdict(int); afeat = defaultdict(int)
        for case in data['cases']:
            t = case['task']; scale, thr = rule(t['cohort']); attacked = t['variant'] != 'clean'
            atk = set(t['attackers']) if attacked else set(); runs = defaultdict(int); case_long = 0
            study = 'evasion' if 'evasion' in case['source'] else 'probe-live'
            for r, rs in enumerate(excess(case['rounds']), start=1):
                for c, v in rs.items():
                    z = v / scale; q = bool(z.max() > thr); k = keys[int(z.argmax())]
                    if c in atk:
                        if r <= 10:
                            kk = f"{study}|{t['variant']}|{t['cohort']}"; att[kk][0] += q; att[kk][1] += 1
                            if q: afeat[f'{k[0]}'] += 1
                        continue
                    hon[0] += q; hon[1] += 1; runs[c] = runs[c] + 1 if q else 0; case_long = max(case_long, runs[c])
                    if q: hfeat[f'{k[0]}'] += 1
            longest = max(longest, case_long)
            if case_long >= 2:
                fails.append(t['name'])
        report[name] = dict(honest=hon[0], honest_rate=hon[0] / hon[1], longest_honest_run=longest, cases_failing=f'{len(fails)}/{len(data["cases"])}',
                            failing=fails, attacker_detection={k: f'{a}/{b}' for k, (a, b) in sorted(att.items())},
                            honest_flag_features=dict(sorted(hfeat.items(), key=lambda x: -x[1])[:6]),
                            attacker_flag_features=dict(sorted(afeat.items(), key=lambda x: -x[1])[:8]))
        r = report[name]
        print(f"{name:26} honest={r['honest']} ({100*r['honest_rate']:.2f}%) longest={longest} fail={r['cases_failing']} hfeat={r['honest_flag_features']}", flush=True)
        print('    ', json.dumps(r['attacker_detection']), flush=True)
    (out / 'keynorm.json').write_text(json.dumps(dict(report=report, clean_key_max={c: v.tolist() for c, v in cmax.items()},
                                                      raw_clean_max=dict(craw), keys=keys), indent=1))


if __name__ == '__main__':
    {'extract': extract, 'analyse': analyse}[sys.argv[1]](Path(sys.argv[2]))
