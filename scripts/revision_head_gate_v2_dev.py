"""Offline development check of head gate v2 on recorded gate states (no training).

Fits size-conditioned references on verified clean TPM-only histories of
revision-clean-gate-calibration-v1 (fit -> references; calibration+selection ->
threshold), then replays v1 (head_max) and v2 decisions on:
  * clean histories never used for fitting (head-CUSUM guard and factorial guard
    TPM-only arms): benign quarantine and worst-round retained mass;
  * recorded attacked trajectories of the head-CUSUM evaluation (development use:
    these outcomes were already inspected, so this cannot validate v2).
Usage: revision_head_gate_v2_dev.py OUTPUT_DIR
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import head_cusum_gate as hg
import head_gate_v2 as g2
import revision_head_cusum_study as hs
from revision_study_data import read
from revision_dba_experiment import authenticate

ROOT = base.ROOT
HEAD = ROOT / 'artifacts/revision-head-cusum-gate-v1'
FACT = ROOT / 'artifacts/revision-gate-aggregation-factorial-v1'


def clean_source(phase):
    closed = read(hs.CLEAN_SOURCE / phase / 'training-complete.json'); recs = []
    for result in closed['results']:
        t = result['task']
        if t['policy'] != 'tpm_only' or t.get('candidate'):
            continue
        ev = hs.CLEAN_SOURCE / phase / 'cases' / t['name'] / 'evidence'
        authenticate(ev, result['manifest_sha256'])
        part = read(hs.CLEAN_SOURCE / 'partitions' / str(t['seed']) / 'manifest.json')
        sizes = {c['client_id']: c['train_row_count'] for c in part['clients']}; med = float(np.median(list(sizes.values())))
        for n in range(1, 16):
            rd = ev / 'rounds' / f'round-{n:03d}'
            clients = sorted(sizes)
            feats = hg.compute_features(read(rd / 'base-model.json'), [read(rd / 'updates' / f'{c}.json') for c in clients], clients)
            recs += [dict(cohort=t['cohort'], round=n, history=t['name'], client=c,
                          size_ratio=g2.size_ratio(sizes[c], med), features=feats[c]) for c in clients]
    return recs


def recorded(lab, phase, select):
    """Yield (task, round, sizes, features, attackers_active) from recorded gate states."""
    closed = read(lab / phase / 'training-complete.json')
    for result in closed['results']:
        t = result['task']
        if not select(t):
            continue
        part = read(lab / 'partitions' / str(t['seed']) / 'manifest.json')
        sizes = {c['client_id']: c['train_row_count'] for c in part['clients']}
        for n in range(1, result['completed_rounds'] + 1):
            st = read(lab / phase / 'cases' / t['name'] / 'evidence/rounds' / f'round-{n:03d}' / 'gate-state.json')
            active = set(t['attackers']) if t.get('variant', t['mode']) != 'clean' and n <= 10 else set()
            yield t, n, sizes, st['head_gate']['features'], active


def main():
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=False)
    refs = g2.fit_references(clean_source('fit'))
    thr_recs = clean_source('calibration') + clean_source('selection')
    model = dict(references=refs, thresholds=g2.fit_thresholds(refs, thr_recs))
    v1 = read(HEAD / 'models/head-cusum.json')
    report = dict(model_v2=model, clean={}, attacked={})
    # ---- clean replay
    for label, lab, phase, sel in (
            ('head_cusum_guard_tpm_only', HEAD, 'guard', lambda t: t['policy'] == 'tpm_only'),
            ('factorial_guard_tpm_only_fedavg', FACT, 'guard', lambda t: t['policy'] == 'tpm_only+fedavg')):
        stats = defaultdict(lambda: dict(n=0, q1=0, q2=0, worst_mass_v1=1.0, worst_mass_v2=1.0, largest_client_q1=0, largest_client_q2=0, rounds=0))
        for t, n, sizes, feats, _ in recorded(lab, phase, sel):
            d2 = g2.decide(model, t['cohort'], feats, sizes)
            d1 = hg.decide(v1, t['cohort'], feats, {})
            tot = sum(sizes.values()); big = max(sizes, key=sizes.get)
            s = stats[f"{t['cohort']}-s{t['seed']}"]; s['rounds'] += 1
            q1 = [c for c in feats if not d1[c]['decisions']['head_max']['contributes']]
            q2 = [c for c in feats if not d2[c]['decision']['contributes']]
            s['n'] += len(feats); s['q1'] += len(q1); s['q2'] += len(q2)
            s['worst_mass_v1'] = min(s['worst_mass_v1'], 1 - sum(sizes[c] for c in q1) / tot)
            s['worst_mass_v2'] = min(s['worst_mass_v2'], 1 - sum(sizes[c] for c in q2) / tot)
            s['largest_client_q1'] += big in q1; s['largest_client_q2'] += big in q2
        report['clean'][label] = {k: {**v, 'rate_v1': v['q1'] / v['n'], 'rate_v2': v['q2'] / v['n']} for k, v in stats.items()}
    # ---- attacked replay (development only)
    agg = defaultdict(lambda: dict(att=0, att_q1=0, att_q2=0, ben=0, ben_q1=0, ben_q2=0))
    for t, n, sizes, feats, active in recorded(HEAD, 'evaluation', lambda t: t['policy'] in ('tpm_only', 'head_max') and t['variant'] != 'clean'):
        d2 = g2.decide(model, t['cohort'], feats, sizes); d1 = hg.decide(v1, t['cohort'], feats, {})
        a = agg[(t['cohort'], t['variant'], t['policy'])]
        for c in feats:
            q1 = not d1[c]['decisions']['head_max']['contributes']; q2 = not d2[c]['decision']['contributes']
            if c in active:
                a['att'] += 1; a['att_q1'] += q1; a['att_q2'] += q2
            elif n <= 10:
                a['ben'] += 1; a['ben_q1'] += q1; a['ben_q2'] += q2
    report['attacked'] = {'|'.join(k): v for k, v in agg.items()}
    (out / 'dev-report.json').write_text(json.dumps(report, indent=1))
    print('THRESHOLDS', json.dumps({c: {k: v for k, v in t.items()} for c, t in model['thresholds'].items()}))
    print('\nCLEAN (benign quarantine rate v1 -> v2; worst-round mass v1 -> v2; rounds largest client quarantined v1 -> v2)')
    for label, rows in report['clean'].items():
        for k, v in sorted(rows.items()):
            print(f"  {label:32} {k:22} rate {v['rate_v1']:.3f} -> {v['rate_v2']:.3f} | worst mass {v['worst_mass_v1']:.3f} -> {v['worst_mass_v2']:.3f} | largest q {v['largest_client_q1']}/{v['rounds']} -> {v['largest_client_q2']}/{v['rounds']}")
    print('\nATTACKED (dev only; attacker-slot quarantine v1 -> v2 | benign quarantine in attack rounds v1 -> v2)')
    for k, v in sorted(report['attacked'].items()):
        print(f"  {k:42} att {v['att_q1']}/{v['att']} -> {v['att_q2']}/{v['att']} | ben {v['ben_q1']}/{v['ben']} -> {v['ben_q2']}/{v['ben']}")


if __name__ == '__main__':
    main()
