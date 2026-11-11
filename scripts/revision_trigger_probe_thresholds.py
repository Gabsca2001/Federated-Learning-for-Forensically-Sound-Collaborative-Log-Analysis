"""Threshold check for trigger probing: persistent honest flags vs DBA detection.

Recomputes the unchanged probe scores for (a) the 12 verified clean TPM-only histories
used for calibration and (b) the TPM-only arms of the head-gate v2 exploratory study,
stores them compactly, then evaluates clean-only thresholds of increasing severity:
98th and 99.5th percentile, clean maximum, clean maximum x1.1 (per cohort). For each:
honest flag rate, longest consecutive honest exclusion, and attacker detection per attack.
Development only (validation rows, recorded trajectories). Usage: ... OUT_DIR
"""
from __future__ import annotations

import json
import math
import sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path

import numpy as np

import revision_trigger_probe_dev as probe
import revision_head_cusum_study as hs
from revision_study_data import read
from revision_dba_experiment import authenticate

ROOT = probe.ROOT
V2 = probe.V2


def scores_for_rounds(round_dirs, ptensor, keys, n, bi):
    out = []
    for rd in round_dirs:
        per = {p.stem: probe.shortcuts(read(p), ptensor, keys, n, bi) for p in sorted((rd / 'updates').glob('client*.json'))}
        out.append({c: v for c, (v, _) in probe.round_scores(per).items()})
    return out


def main():
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=False)
    protocol = read(V2 / 'protocol-before-fitting.json'); cfg = protocol['training']
    val = read(cfg['validation_path'])['rows']['validation']; X = probe.attack_matrix(val); n = len(X)
    bi = read(cfg['base_model_path'])['class_names'].index('benign'); ptensor, keys = probe.probe_tensor(X)
    calib = defaultdict(list)
    for phase in ('fit', 'calibration', 'selection'):
        for result in read(hs.CLEAN_SOURCE / phase / 'training-complete.json')['results']:
            t = result['task']
            if t['policy'] != 'tpm_only' or t.get('candidate'):
                continue
            ev = hs.CLEAN_SOURCE / phase / 'cases' / t['name'] / 'evidence'; authenticate(ev, result['manifest_sha256'])
            for rs in scores_for_rounds([ev / 'rounds' / f'round-{r:03d}' for r in range(1, 16)], ptensor, keys, n, bi):
                calib[t['cohort']] += list(rs.values())
    cases = []
    for result in read(V2 / 'evaluation-exploratory/training-complete.json')['results']:
        t = result['task']
        if t['policy'] != 'tpm_only+fedavg':
            continue
        ev = V2 / 'evaluation-exploratory/cases' / t['name'] / 'evidence'
        cases.append(dict(task=t, rounds=scores_for_rounds([ev / 'rounds' / f'round-{r:03d}' for r in range(1, result['completed_rounds'] + 1)],
                                                          ptensor, keys, n, bi)))
    (out / 'scores.json').write_text(json.dumps(dict(calibration=calib, cases=cases)))

    def quant(v, q):
        v = sorted(v); return v[max(0, math.ceil(Fraction(q) * len(v)) - 1)]
    rules = {'q98': lambda v: quant(v, '0.98'), 'q995': lambda v: quant(v, '0.995'), 'max': max, 'max_x1.1': lambda v: 1.1 * max(v)}
    report = {}
    for name, f in rules.items():
        thr = {c: f(v) for c, v in calib.items()}
        clean = dict(n=0, q=0, longest=0); att = defaultdict(lambda: [0, 0]); ben = [0, 0]
        for case in cases:
            t = case['task']; th = thr[t['cohort']]; runs = {}
            for r, rs in enumerate(case['rounds'], start=1):
                for c, v in rs.items():
                    flag = v > th
                    if t['variant'] == 'clean':
                        clean['n'] += 1; clean['q'] += flag; runs[c] = runs.get(c, 0) + 1 if flag else 0; clean['longest'] = max(clean['longest'], runs[c])
                    elif r <= 10 and c in t['attackers']:
                        k = f"{t['cohort']}|{t['variant']}"; att[k][0] += flag; att[k][1] += 1
                    elif r <= 10:
                        ben[0] += flag; ben[1] += 1
        report[name] = dict(thresholds=thr, clean_rate=clean['q'] / clean['n'], clean_longest_consecutive=clean['longest'],
                            benign_rate_attacked_runs=ben[0] / ben[1], attacker_detection={k: f'{a}/{b}' for k, (a, b) in sorted(att.items())})
        print(name, json.dumps(report[name]), flush=True)
    (out / 'thresholds.json').write_text(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()
