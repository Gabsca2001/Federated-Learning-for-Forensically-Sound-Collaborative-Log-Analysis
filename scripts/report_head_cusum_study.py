"""Report for the head-CUSUM live study (reads closed, verified, tested evidence).

Definitions follow docs/HEAD_CUSUM_STUDY_PROTOCOL.md, fixed before training:
* worst-trigger ASR(r) = max(full-trigger ASR, every component-trigger ASR) on test.
* paired peak harm = max over rounds of worst(attacked, r) - worst(own-policy clean, r);
  undefined when either history is incomplete (never treated as zero).
* effective TPM-only control: at round 10 or 15, worst-trigger ASR >= clean + 0.20
  with clean macro-F1 loss <= 0.05 vs the paired TPM-only clean history.
Usage: report_head_cusum_study.py [--lab PATH] [--out PATH]
"""
from __future__ import annotations

import argparse
import csv
import json
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATTACKED = ('distributed', 'complete-trigger', 'adaptive', 'adaptive-headfrozen')
ENDPOINTS = (10, 15)


def read(p):
    return json.loads(Path(p).read_text())


def worst(test):
    return max([test['complete_trigger']['asr'], *[v['asr'] for v in test['component_triggers'].values()]])


def f1(test):
    return test['clean']['macro_f1_all_model_classes']


def case_metrics(lab, tested, phase='evaluation'):
    task = tested['task']
    ev = lab / phase / 'cases' / task['name'] / 'evidence/rounds'
    rounds = {r['round']: r['test'] for r in tested['rounds']}
    att = set(task['attackers'])
    first_q, att_q, ben_q, ben_n, infl = None, 0, 0, 0, []
    for n in sorted(rounds):
        row = read(ev / f'round-{n:03d}' / 'round.json')
        for c, s in row['statuses'].items():
            q = s.endswith('quarantined')
            if c in att and n <= 10 and task['variant'] != 'clean':
                att_q += q
                if q and first_q is None:
                    first_q = n
            elif c not in att or task['variant'] == 'clean':
                ben_q += q; ben_n += 1
        if n <= 10 and task['variant'] != 'clean' and row['coefficients']:
            infl.append(float(sum(Fraction(v) for c, v in row['coefficients'].items() if c in att)))
    full = [rounds[n]['complete_trigger']['asr'] for n in sorted(rounds)]
    return dict(name=task['name'], cohort=task['cohort'], seed=task['seed'], policy=task['policy'], variant=task['variant'],
                complete=tested['complete'], completed_rounds=tested['completed_rounds'],
                failure=(tested.get('failure') or {}).get('reason'),
                full_peak=max(full) if full else None, full_final=full[-1] if tested['complete'] else None,
                worst_peak=max(worst(t) for t in rounds.values()) if rounds else None,
                f1_r10=f1(rounds[10]) if 10 in rounds else None, f1_r15=f1(rounds[15]) if 15 in rounds else None,
                attacker_quarantines_attack_rounds=att_q if task['variant'] != 'clean' else None,
                first_attacker_quarantine_round=first_q,
                benign_quarantine_rate=ben_q / ben_n if ben_n else None,
                mean_attacker_influence_attack_rounds=sum(infl) / len(infl) if infl else None,
                _worst={n: worst(t) for n, t in rounds.items()}, _f1={n: f1(t) for n, t in rounds.items()})


def paired_harm(att, clean):
    if not (att and clean and att['complete'] and clean['complete']):
        return None
    return max(att['_worst'][n] - clean['_worst'][n] for n in att['_worst'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lab', type=Path, default=ROOT / 'artifacts/revision-head-cusum-gate-v1')
    ap.add_argument('--out', type=Path, default=ROOT / 'results/revision-head-cusum-gate-v1')
    a = ap.parse_args(); lab, out = a.lab, a.out
    if (out / 'summary.json').exists():
        raise SystemExit('Report exists; write a new destination')
    test = read(lab / 'evaluation/test/summary.json'); assert test['status'] == 'tested'
    cases = {}
    for name in test['cases']:
        m = case_metrics(lab, read(lab / 'evaluation/test/cases' / f'{name}.json'))
        cases[(m['seed'], m['policy'], m['variant'])] = m
    seeds = sorted({k[0] for k in cases}); policies = sorted({k[1] for k in cases})
    paired = []
    for (seed, pol, var), m in sorted(cases.items()):
        if var == 'clean':
            continue
        clean = cases.get((seed, pol, 'clean')); tpm_clean = cases.get((seed, 'tpm_only', 'clean'))
        effective = None
        if pol == 'tpm_only' and m['complete'] and clean and clean['complete']:
            effective = any(m['_worst'][e] - clean['_worst'][e] >= .20 and clean['_f1'][e] - m['_f1'][e] <= .05 for e in ENDPOINTS)
        paired.append(dict(seed=seed, cohort=m['cohort'], policy=pol, variant=var, harm=paired_harm(m, clean),
                           effective_tpm_control=effective,
                           clean_f1_loss_vs_tpm_r10=(tpm_clean['_f1'][10] - clean['_f1'][10]) if clean and tpm_clean and 10 in clean['_f1'] and 10 in tpm_clean['_f1'] else None))
    P = {(p['seed'], p['policy'], p['variant']): p for p in paired}

    def compare(a_pol, b_pol, variants, only_effective=False):
        lower = higher = equal = undefined = 0
        for seed in seeds:
            for v in variants:
                pa, pb = P.get((seed, a_pol, v)), P.get((seed, b_pol, v))
                if only_effective and not (P.get((seed, 'tpm_only', v)) or {}).get('effective_tpm_control'):
                    continue
                if not pa or not pb or pa['harm'] is None or pb['harm'] is None:
                    undefined += 1; continue
                lower += pa['harm'] < pb['harm'] - 1e-12; higher += pa['harm'] > pb['harm'] + 1e-12
                equal += abs(pa['harm'] - pb['harm']) <= 1e-12
        return dict(lower=lower, higher=higher, equal=equal, undefined=undefined)

    attacked_main = ('distributed', 'complete-trigger', 'adaptive', 'adaptive-headfrozen')
    hyp = {
        'H1_head_cusum_vs_gated_composite': compare('head_cusum', 'gated_composite', attacked_main),
        'H2_head_cusum_vs_tpm_only_effective': compare('head_cusum', 'tpm_only', attacked_main, only_effective=True),
        'H3_headfrozen_head_cusum_vs_tpm_only': compare('head_cusum', 'tpm_only', ('adaptive-headfrozen',)),
        'aux_head_max_vs_gated_composite': compare('head_max', 'gated_composite', attacked_main),
        'aux_head_cusum_vs_head_max': compare('head_cusum', 'head_max', attacked_main),
    }
    h1 = hyp['H1_head_cusum_vs_gated_composite']; defined = h1['lower'] + h1['higher'] + h1['equal']
    hyp['H1_holds'] = defined > 0 and h1['lower'] > defined / 2
    h2 = hyp['H2_head_cusum_vs_tpm_only_effective']; d2 = h2['lower'] + h2['higher'] + h2['equal']
    hyp['H2_holds'] = d2 > 0 and h2['lower'] > d2 / 2
    clean_guard = []
    for seed in seeds:
        hc, tc = cases.get((seed, 'head_cusum', 'clean')), cases.get((seed, 'tpm_only', 'clean'))
        ok = bool(hc and tc and hc['complete'] and tc['complete'] and
                  all(tc['_f1'][e] - hc['_f1'][e] <= .02 for e in ENDPOINTS) and (hc['benign_quarantine_rate'] or 0) <= .05)
        clean_guard.append(dict(seed=seed, ok=ok, benign_q=hc and hc['benign_quarantine_rate'],
                                f1_loss=[tc['_f1'][e] - hc['_f1'][e] for e in ENDPOINTS] if hc and tc and hc['complete'] and tc['complete'] else None))
    hyp['reserved_clean_guard_ok'] = all(g['ok'] for g in clean_guard)
    hyp['reportable_as_improved'] = bool(hyp['H1_holds'] and hyp['H2_holds'] and hyp['reserved_clean_guard_ok'])
    out.mkdir(parents=True, exist_ok=True)
    cols = [k for k in next(iter(cases.values())) if not k.startswith('_')]
    with open(out / 'cases.csv', 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=cols); w.writeheader()
        for m in sorted(cases.values(), key=lambda m: m['name']):
            w.writerow({k: m[k] for k in cols})
    with open(out / 'paired-harm.csv', 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(paired[0])); w.writeheader(); w.writerows(paired)
    table = {}
    for (seed, pol, var), m in cases.items():
        table.setdefault((m['cohort'], var, pol), []).append(m)
    agg = []
    for (cohort, var, pol), ms in sorted(table.items()):
        done = [m for m in ms if m['complete']]
        agg.append(dict(cohort=cohort, variant=var, policy=pol, complete=f'{len(done)}/{len(ms)}',
                        mean_full_peak=sum(m['full_peak'] for m in done) / len(done) if done else None,
                        mean_full_final=sum(m['full_final'] for m in done) / len(done) if done else None,
                        mean_worst_peak=sum(m['worst_peak'] for m in done) / len(done) if done else None,
                        mean_attacker_influence=(lambda v: sum(v) / len(v) if v else None)(
                            [m['mean_attacker_influence_attack_rounds'] for m in done if m['mean_attacker_influence_attack_rounds'] is not None])))
    json.dump(dict(hypotheses=hyp, clean_guard=clean_guard, aggregate=agg, cases=len(cases),
                   definitions=__doc__), open(out / 'summary.json', 'w'), indent=1)
    print(json.dumps(hyp, indent=1))
    for r in agg:
        print(r)


if __name__ == '__main__':
    main()
