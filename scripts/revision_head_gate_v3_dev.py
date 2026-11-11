"""Offline development check of head gate v3: round-relative scale (no training).

v2 scored step-normalized head indicators against FIXED clean references; the
confirmatory guard showed unstable false positives across partitions (an honest IID
client excluded 7 rounds in a row). v3 scores each indicator against the median and
MAD of the same round's 15 clients (robust to a minority of attackers), then takes the
non-compensatory maximum. Threshold: clean 98th percentile per cohort, fitted on the
verified clean TPM-only histories of revision-clean-gate-calibration-v1 (never used to
evaluate). Evaluated on recorded gate states (development use):
  * clean: TPM-only FedAvg arms of the v2 guard, v2 exploratory and confirmation guard
    (incl. the partition that failed), plus the failing head_v2+bounded guard case;
  * attacked: v2 exploratory TPM-only and head_v2 arms (all variants).
Usage: revision_head_gate_v3_dev.py OUTPUT_DIR
"""
from __future__ import annotations

import json
import math
import sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import head_cusum_gate as hg
import head_gate_steps as gs
import revision_head_cusum_study as hs
from revision_study_data import read
from revision_dba_experiment import authenticate

ROOT = base.ROOT
V2 = ROOT / 'artifacts/revision-head-gate-v2'
CONF = ROOT / 'artifacts/revision-head-gate-v2-confirm'
MAD_FLOOR = 1e-9


def round_scores(feats):
    """feats: client -> feature dict (one round). Returns client -> (score, argmax feature)."""
    clients = sorted(feats); out = {}
    stats = {}
    for f in hg.FEATURES:
        v = np.array([hg.DIRECTIONS[f] * feats[c][f] for c in clients])
        med = float(np.median(v)); mad = max(float(1.4826 * np.median(np.abs(v - med))), MAD_FLOOR)
        stats[f] = (med, mad)
    for c in clients:
        z = {f: max(0.0, (hg.DIRECTIONS[f] * feats[c][f] - stats[f][0]) / stats[f][1]) for f in hg.FEATURES}
        k = max(z, key=z.get); out[c] = (z[k], k)
    return out


def clean_calibration(cfg):
    scores = defaultdict(list)
    for phase in ('fit', 'calibration', 'selection'):
        closed = read(hs.CLEAN_SOURCE / phase / 'training-complete.json')
        for result in closed['results']:
            t = result['task']
            if t['policy'] != 'tpm_only' or t.get('candidate'):
                continue
            ev = hs.CLEAN_SOURCE / phase / 'cases' / t['name'] / 'evidence'; authenticate(ev, result['manifest_sha256'])
            sizes = {c['client_id']: c['train_row_count'] for c in read(hs.CLEAN_SOURCE / 'partitions' / str(t['seed']) / 'manifest.json')['clients']}
            clients = sorted(sizes)
            for n in range(1, 16):
                rd = ev / 'rounds' / f'round-{n:03d}'
                f = gs.features(read(rd / 'base-model.json'), [read(rd / 'updates' / f'{c}.json') for c in clients], clients, sizes,
                                cfg['local_epochs'], cfg['batch_size'])
                scores[t['cohort']] += [s for s, _ in round_scores(f).values()]
    q = Fraction(98, 100)
    thr = {}
    for cohort, v in scores.items():
        v = sorted(v); thr[cohort] = dict(threshold=float(v[max(0, math.ceil(q * len(v)) - 1)]), observations=len(v))
    return thr


def replay(lab, phase, select):
    closed = read(lab / phase / 'training-complete.json')
    for result in closed['results']:
        t = result['task']
        if not select(t):
            continue
        sizes = {c['client_id']: c['train_row_count'] for c in read(lab / 'partitions' / str(t['seed']) / 'manifest.json')['clients']}
        for n in range(1, result['completed_rounds'] + 1):
            st = read(lab / phase / 'cases' / t['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'gate-state.json')
            active = set(t['attackers']) if t.get('variant', t['mode']) != 'clean' and n <= 10 else set()
            yield t, n, sizes, st['head_v2']['features'], {c: not d['head_v2']['contributes'] for c, d in st['decisions'].items()}, active


def main():
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=False)
    cfg = read(V2 / 'protocol-before-fitting.json')['training']
    thr = clean_calibration(cfg)
    report = dict(thresholds=thr, clean={}, attacked={})
    sources = (('v2_guard', V2, 'guard', lambda t: t['policy'] == 'tpm_only+fedavg'),
               ('v2_exploratory_clean', V2, 'evaluation-exploratory', lambda t: t['policy'] == 'tpm_only+fedavg' and t['variant'] == 'clean'),
               ('confirm_guard_tpm', CONF, 'guard', lambda t: t['policy'] == 'tpm_only+fedavg'),
               ('confirm_guard_failing_head_v2', CONF, 'guard', lambda t: t['policy'] == 'head_v2+bounded'))
    for label, lab, phase, sel in sources:
        st = defaultdict(lambda: dict(n=0, q2=0, q3=0, worst_mass2=1.0, worst_mass3=1.0, run2=0, run3=0, _r2={}, _r3={}))
        for t, n, sizes, feats, q2, _ in replay(lab, phase, sel):
            s3 = round_scores(feats); th = thr[t['cohort']]['threshold']
            q3 = {c: s3[c][0] > th for c in feats}
            tot = sum(sizes.values()); s = st[f"{t['cohort']}-s{t['seed']}"]
            s['n'] += len(feats); s['q2'] += sum(q2.values()); s['q3'] += sum(q3.values())
            s['worst_mass2'] = min(s['worst_mass2'], 1 - sum(sizes[c] for c in feats if q2[c]) / tot)
            s['worst_mass3'] = min(s['worst_mass3'], 1 - sum(sizes[c] for c in feats if q3[c]) / tot)
            for key, q in (('2', q2), ('3', q3)):
                runs = s['_r' + key]
                for c in feats:
                    runs[c] = runs.get(c, 0) + 1 if q[c] else 0
                    s['run' + key] = max(s['run' + key], runs[c])
        report['clean'][label] = {k: {x: y for x, y in v.items() if not x.startswith('_')} for k, v in st.items()}
    agg = defaultdict(lambda: dict(att=0, att2=0, att3=0, ben=0, ben2=0, ben3=0))
    for t, n, sizes, feats, q2, active in replay(V2, 'evaluation-exploratory',
                                                  lambda t: t['policy'] in ('tpm_only+fedavg', 'head_v2+fedavg') and t['variant'] != 'clean'):
        s3 = round_scores(feats); th = thr[t['cohort']]['threshold']
        a = agg[f"{t['cohort']}|{t['variant']}|{t['policy']}"]
        for c in feats:
            q3 = s3[c][0] > th
            if c in active:
                a['att'] += 1; a['att2'] += q2[c]; a['att3'] += q3
            elif n <= 10:
                a['ben'] += 1; a['ben2'] += q2[c]; a['ben3'] += q3
    report['attacked'] = dict(agg)
    (out / 'dev-report.json').write_text(json.dumps(report, indent=1))
    print('THRESHOLDS', json.dumps(thr))
    for label, rows in report['clean'].items():
        for k, v in sorted(rows.items()):
            print(f"CLEAN {label:30} {k:22} benign q v2 {v['q2']/v['n']:.3f} -> v3 {v['q3']/v['n']:.3f} | worst round mass {v['worst_mass2']:.3f} -> {v['worst_mass3']:.3f} | longest consecutive exclusion {v['run2']} -> {v['run3']}")
    for k, v in sorted(report['attacked'].items()):
        print(f"ATTACK {k:40} attacker slots q v2 {v['att2']}/{v['att']} -> v3 {v['att3']}/{v['att']} | benign q v2 {v['ben2']}/{v['ben']} -> v3 {v['ben3']}/{v['ben']}")


if __name__ == '__main__':
    main()
