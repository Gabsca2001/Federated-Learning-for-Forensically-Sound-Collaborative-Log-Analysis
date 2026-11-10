"""Generic report for arm-based gate studies (factorial, head v2).

Reads closed, verified and tested evidence. Metric definitions are those of
report_head_cusum_study.py (paired worst-trigger peak harm vs the arm's own clean
history; effective control relative to the reference arm). Hypotheses come from the
frozen protocol (``hypotheses`` list) or, for studies frozen without one, from
``--hypothesis A,B,variant1|variant2[,effective]`` arguments declared here.
Usage: report_arm_study.py --lab PATH --out PATH [--reference ARM] [--hypothesis ...]
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import report_head_cusum_study as r1

ENDPOINTS = (10, 15)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab', type=Path, required=True); ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--phase', default='evaluation'); ap.add_argument('--reference', default='tpm_only+fedavg'); ap.add_argument('--hypothesis', action='append', default=[])
    a = ap.parse_args(); lab, out = a.lab, a.out
    if (out / 'summary.json').exists():
        raise SystemExit('Report exists; choose a new destination')
    protocol = r1.read(lab / a.phase / 'protocol-before-training.json')
    test = r1.read(lab / a.phase / 'test/summary.json'); assert test['status'] == 'tested'
    declared = protocol.get('hypotheses')
    hyps = list(declared) if isinstance(declared, list) else []  # factorial-v1 froze prose hypotheses (dict), not specs
    for h in a.hypothesis:
        parts = h.split(','); eff = len(parts) > 3 and parts[3] == 'effective'
        hyps.append(dict(id=f'cli:{parts[0]}_vs_{parts[1]}:{parts[2]}' + (':effective' if eff else ''), a=parts[0], b=parts[1],
                                                variants=parts[2].split('|'), only_effective=len(parts) > 3 and parts[3] == 'effective'))
    cases = {}
    for name in test['cases']:
        m = r1.case_metrics(lab, r1.read(lab / a.phase / 'test/cases' / f'{name}.json'), a.phase)
        cases[(m['seed'], m['policy'], m['variant'])] = m
    seeds = sorted({k[0] for k in cases}); share = protocol.get('attacker_data_share', {})
    paired = {}
    for (seed, arm, var), m in cases.items():
        if var == 'clean':
            continue
        clean = cases.get((seed, arm, 'clean')); eff = None
        if arm == a.reference and m['complete'] and clean and clean['complete']:
            eff = any(m['_worst'][e] - clean['_worst'][e] >= .20 and clean['_f1'][e] - m['_f1'][e] <= .05 for e in ENDPOINTS)
        paired[(seed, arm, var)] = dict(seed=seed, cohort=m['cohort'], arm=arm, variant=var, harm=r1.paired_harm(m, clean),
                                        effective_reference=eff, attacker_data_share=share.get(str(seed)))
    results = {}
    for h in hyps:
        c = dict(lower=0, higher=0, equal=0, undefined=0, pairs=[])
        for seed in seeds:
            for v in h['variants']:
                if h.get('only_effective') and not (paired.get((seed, a.reference, v)) or {}).get('effective_reference'):
                    continue
                pa, pb = paired.get((seed, h['a'], v)), paired.get((seed, h['b'], v))
                if not pa or not pb or pa['harm'] is None or pb['harm'] is None:
                    c['undefined'] += 1; continue
                d = pa['harm'] - pb['harm']; c['pairs'].append(dict(seed=seed, variant=v, a=pa['harm'], b=pb['harm']))
                c['lower'] += d < -1e-12; c['higher'] += d > 1e-12; c['equal'] += abs(d) <= 1e-12
        defined = c['lower'] + c['higher'] + c['equal']
        c['holds_majority_lower'] = defined > 0 and c['lower'] > defined / 2
        results[h['id']] = {**c, 'a': h['a'], 'b': h['b'], 'text': h.get('text', '')}
    clean_guard = []
    for seed in seeds:
        ref = cases.get((seed, a.reference, 'clean'))
        for (s, arm, var), m in cases.items():
            if s == seed and var == 'clean' and arm != a.reference:
                ok = bool(m['complete'] and ref and ref['complete'] and all(ref['_f1'][e] - m['_f1'][e] <= .02 for e in ENDPOINTS)
                          and (m['benign_quarantine_rate'] or 0) <= .05)
                clean_guard.append(dict(seed=seed, arm=arm, ok=ok, benign_q=m['benign_quarantine_rate'],
                                        f1_loss=[ref['_f1'][e] - m['_f1'][e] for e in ENDPOINTS] if ok or (m['complete'] and ref and ref['complete']) else None))
    agg = {}
    for (seed, arm, var), m in cases.items():
        agg.setdefault((m['cohort'], var, arm), []).append(m)
    table = []
    for (cohort, var, arm), ms in sorted(agg.items()):
        done = [m for m in ms if m['complete']]
        mean = lambda k: sum(m[k] for m in done) / len(done) if done else None
        table.append(dict(cohort=cohort, variant=var, arm=arm, complete=f'{len(done)}/{len(ms)}', mean_full_peak=mean('full_peak'),
                          mean_full_final=mean('full_final'), mean_worst_peak=mean('worst_peak')))
    out.mkdir(parents=True, exist_ok=True)
    cols = [k for k in next(iter(cases.values())) if not k.startswith('_')]
    with open(out / 'cases.csv', 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=cols); w.writeheader(); [w.writerow({k: m[k] for k in cols}) for m in sorted(cases.values(), key=lambda m: m['name'])]
    with open(out / 'paired-harm.csv', 'w', newline='') as fh:
        rows = list(paired.values()); w = csv.DictWriter(fh, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    json.dump(dict(hypotheses=results, clean_guard=clean_guard, aggregate=table, reference=a.reference, cases=len(cases),
                   attacker_data_share=share, definitions=r1.__doc__), open(out / 'summary.json', 'w'), indent=1)
    for k, v in results.items():
        print(k, {x: v[x] for x in ('lower', 'higher', 'equal', 'undefined', 'holds_majority_lower')})
    print('clean guard ok:', all(g['ok'] for g in clean_guard), [g for g in clean_guard if not g['ok']])
    for t in table:
        print(f"{t['cohort']:8} {t['variant']:20} {t['arm']:26} {t['complete']:5} peak={t['mean_full_peak'] if t['mean_full_peak'] is None else round(100*t['mean_full_peak'],1)} final={t['mean_full_final'] if t['mean_full_final'] is None else round(100*t['mean_full_final'],1)}")


if __name__ == '__main__':
    main()
