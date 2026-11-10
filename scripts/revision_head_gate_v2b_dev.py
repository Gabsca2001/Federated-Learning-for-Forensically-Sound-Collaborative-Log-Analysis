"""Offline development check: step-normalized head indicators (no training).

Hypothesis from the v2 check: honest large clients look anomalous because they take
proportionally more local SGD steps (steps = epochs * ceil(n / batch)), so their
delta is longer and farther from peers. Here every delta is divided by its local
step count before computing the same round-relative indicators (FedNova-style
normalization; cosine features are scale-invariant and unchanged). Thresholds are
fitted on verified clean TPM-only histories only (v1 protocol split).

Evaluated (development use only, recorded trajectories):
  * clean: head-CUSUM guard and factorial guard TPM-only histories (incl. the
    34%-of-data client that v1 excluded);
  * attacked: head-CUSUM evaluation TPM-only arms (attacker unconstrained) and
    head_max arms, all attack variants.
Usage: revision_head_gate_v2b_dev.py OUTPUT_DIR
"""
from __future__ import annotations

import json
import math
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

import revision_gate_trajectories as base  # numeric environment first
import head_cusum_gate as hg
import revision_head_cusum_study as hs
from revision_study_data import read
from revision_dba_experiment import authenticate

ROOT = base.ROOT
HEAD = ROOT / 'artifacts/revision-head-cusum-gate-v1'
FACT = ROOT / 'artifacts/revision-gate-aggregation-factorial-v1'


def steps(n, cfg):
    return cfg['local_epochs'] * math.ceil(n / cfg['batch_size'])


def scaled_exports(base_export, exports, clients, sizes, cfg):
    """Return exports whose deltas are divided by local steps (times the median, to keep units)."""
    med = float(np.median([steps(sizes[c], cfg) for c in clients]))
    out = []
    for c, e in zip(clients, exports):
        f = med / steps(sizes[c], cfg)
        new = {'parameters': []}
        for p, b in zip(e['parameters'], base_export['parameters']):
            v = np.asarray(p['values'], float); bv = np.asarray(b['values'], float)
            new['parameters'].append({'name': p['name'], 'dtype': 'float64', 'values': (bv + f * (v - bv)).tolist()})
        out.append(new)
    return out


def features_for(rd, clients, sizes, cfg, base_export=None):
    b = base_export or read(rd / 'base-model.json')
    ex = [read(rd / ('updates' if (rd / 'updates').exists() else 'submissions') / f'{c}.json') for c in clients]
    return hg.compute_features(b, scaled_exports(b, ex, clients, sizes, cfg), clients)


def clean_source(phase, cfg):
    closed = read(hs.CLEAN_SOURCE / phase / 'training-complete.json'); recs = []
    for result in closed['results']:
        t = result['task']
        if t['policy'] != 'tpm_only' or t.get('candidate'):
            continue
        ev = hs.CLEAN_SOURCE / phase / 'cases' / t['name'] / 'evidence'; authenticate(ev, result['manifest_sha256'])
        part = read(hs.CLEAN_SOURCE / 'partitions' / str(t['seed']) / 'manifest.json')
        sizes = {c['client_id']: c['train_row_count'] for c in part['clients']}; clients = sorted(sizes)
        for n in range(1, 16):
            feats = features_for(ev / 'rounds' / f'round-{n:03d}', clients, sizes, cfg)
            recs += [dict(cohort=t['cohort'], round=n, history=t['name'], client=c, features=feats[c]) for c in clients]
    return recs


def recorded(lab, phase, select, cfg):
    closed = read(lab / phase / 'training-complete.json')
    for result in closed['results']:
        t = result['task']
        if not select(t):
            continue
        part = read(lab / 'partitions' / str(t['seed']) / 'manifest.json')
        sizes = {c['client_id']: c['train_row_count'] for c in part['clients']}; clients = sorted(sizes)
        for n in range(1, result['completed_rounds'] + 1):
            rd = lab / phase / 'cases' / t['name'] / 'evidence/rounds' / f'round-{n:03d}'
            active = set(t['attackers']) if t.get('variant', t['mode']) != 'clean' and n <= 10 else set()
            yield t, n, sizes, features_for(rd, clients, sizes, cfg), active


def main():
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=False)
    cfg = read(HEAD / 'protocol-before-fitting.json')['training']
    refs = hg.fit_references(clean_source('fit', cfg))
    model = dict(references=refs, thresholds=hg.fit_thresholds(refs, clean_source('calibration', cfg) + clean_source('selection', cfg), '0.02', '0.90'))
    report = dict(model=model, clean={}, attacked={})
    for label, lab, phase, sel in (('head_cusum_guard', HEAD, 'guard', lambda t: t['policy'] == 'tpm_only'),
                                   ('factorial_guard', FACT, 'guard', lambda t: t['policy'] == 'tpm_only+fedavg')):
        st = defaultdict(lambda: dict(n=0, q=0, worst_mass=1.0, largest_q=0, rounds=0))
        for t, n, sizes, feats, _ in recorded(lab, phase, sel, cfg):
            d = hg.decide(model, t['cohort'], feats, {})
            q = [c for c in feats if not d[c]['decisions']['head_max']['contributes']]
            tot = sum(sizes.values()); big = max(sizes, key=sizes.get)
            s = st[f"{t['cohort']}-s{t['seed']}"]; s['rounds'] += 1; s['n'] += len(feats); s['q'] += len(q)
            s['worst_mass'] = min(s['worst_mass'], 1 - sum(sizes[c] for c in q) / tot); s['largest_q'] += big in q
        report['clean'][label] = dict(st)
    agg = defaultdict(lambda: dict(att=0, att_q=0, ben=0, ben_q=0))
    for t, n, sizes, feats, active in recorded(HEAD, 'evaluation', lambda t: t['policy'] in ('tpm_only', 'head_max') and t['variant'] != 'clean', cfg):
        d = hg.decide(model, t['cohort'], feats, {})
        a = agg[f"{t['cohort']}|{t['variant']}|{t['policy']}"]
        for c in feats:
            q = not d[c]['decisions']['head_max']['contributes']
            if c in active:
                a['att'] += 1; a['att_q'] += q
            elif n <= 10:
                a['ben'] += 1; a['ben_q'] += q
    report['attacked'] = dict(agg)
    (out / 'dev-report.json').write_text(json.dumps(report, indent=1))
    print('THRESHOLDS', json.dumps({c: dict(max=v['max_threshold'], calib=v['calibration_rate_max']) for c, v in model['thresholds'].items()}))
    for label, rows in report['clean'].items():
        for k, v in sorted(rows.items()):
            print(f"CLEAN {label:16} {k:22} rate {v['q']/v['n']:.3f} | worst round mass {v['worst_mass']:.3f} | largest client q {v['largest_q']}/{v['rounds']}")
    for k, v in sorted(report['attacked'].items()):
        print(f"ATTACK {k:40} attacker slots q {v['att_q']}/{v['att']} | benign q {v['ben_q']}/{v['ben']}")


if __name__ == '__main__':
    main()
