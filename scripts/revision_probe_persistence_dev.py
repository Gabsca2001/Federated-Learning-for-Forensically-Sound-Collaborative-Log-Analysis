"""Offline development: does a persistence rule fix the probe's honest-flag runs?

DEVELOPMENT ONLY. Reads the recorded single-probe score and best (feature, value) of every
client in every round from archived gate-state.json files (per-case tar.gz) of the two live
probe studies (revision-trigger-probe-live, revision-trigger-probe-evasion-live; guard and
evaluation, every arm: the probe is computed in all arms). No training, no test split.
These partitions become development data: any rule chosen here needs fresh partitions.

Rules (threshold t per cohort; flag_r = score_r > t, with feature f_r):
* base: quarantine when flagged (deployed rule).
* persist k/w: quarantine at round r when flagged and, within rounds r-w+1..r, the client
  was flagged with the same feature f_r in at least k rounds (value ignored).
Thresholds: pinned clean max (deployed) and q98 of the same calibration
(results/gates-probes/revision-trigger-probe-thresholds/thresholds.json).
Metrics: honest client-rounds quarantined (clean cases and honest clients of attacked
cases), longest consecutive honest exclusion, guard-rule failures per case (>=2
consecutive), attacker client-rounds quarantined in rounds 1-10 per study/attack/cohort.
Note: the trajectory depends on the deployed arm, so this is a replay of decisions on
recorded models, not a counterfactual training run.
Usage: revision_probe_persistence_dev.py OUT_DIR
"""
from __future__ import annotations

import json
import sys
import tarfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STUDIES = ('revision-trigger-probe-live', 'revision-trigger-probe-evasion-live')
THR = json.loads((ROOT / 'results/gates-probes/revision-trigger-probe-thresholds/thresholds.json').read_text())
RULES = [('base', 1, 1), ('persist 2/2', 2, 2), ('persist 2/3', 2, 3), ('persist 3/3', 3, 3), ('persist 3/4', 3, 4)]


def load_case(path):
    task, rounds = None, {}
    with tarfile.open(path, 'r:gz') as tar:
        for m in tar:
            if m.name.endswith('evidence/task.json'):
                task = json.load(tar.extractfile(m))
            elif m.name.endswith('/gate-state.json') and '/rounds/round-' in m.name:
                n = int(m.name.split('/rounds/round-')[1][:3]); st = json.load(tar.extractfile(m))
                rounds[n] = {c: (st['probe']['score'][c], st['probe']['best'][c][0]) for c in st['probe']['score']}
    return task, [rounds[n] for n in sorted(rounds)]


def decide(rounds, t, k, w):
    out, hist = [], defaultdict(list)
    for rs in rounds:
        q = {}
        for c, (s, f) in rs.items():
            hist[c].append(f if s > t else None)
            recent = hist[c][-w:]
            q[c] = s > t and sum(x == f for x in recent) >= k
        out.append(q)
    return out


def main():
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=False)
    cases = []
    for study in STUDIES:
        for tz in sorted((ROOT / 'artifacts' / study).glob('*/cases/*.tar.gz')):
            task, rounds = load_case(tz)
            cases.append(dict(study=study, phase=tz.parts[-3], task=task, rounds=rounds))
            print('LOADED', study, tz.name, len(rounds), flush=True)
    (out / 'probe-trajectories.json').write_text(json.dumps(cases))
    report = {}
    for tname in ('max', 'q98'):
        thr = THR[tname]['thresholds']
        for rname, k, w in RULES:
            hon = [0, 0]; longest = 0; fails = 0; att = defaultdict(lambda: [0, 0]); fail_cases = []
            for case in cases:
                t = case['task']; attacked = t['variant'] != 'clean'; atk = set(t['attackers']) if attacked else set()
                dec = decide(case['rounds'], thr[t['cohort']], k, w); case_long = 0
                for c in case['rounds'][0]:
                    run = 0
                    for r, q in enumerate(dec, start=1):
                        if c in atk:
                            if r <= 10:
                                key = f"{case['study'].split('-')[-2]}|{t['variant']}|{t['cohort']}"; att[key][0] += q[c]; att[key][1] += 1
                            continue
                        hon[0] += q[c]; hon[1] += 1; run = run + 1 if q[c] else 0; case_long = max(case_long, run)
                longest = max(longest, case_long)
                if case_long >= 2:
                    fails += 1; fail_cases.append(t['name'])
            report[f'{tname}|{rname}'] = dict(honest_rate=hon[0] / hon[1], honest_quarantines=hon[0], longest_honest_run=longest,
                                              cases_failing_consecutive_rule=f'{fails}/{len(cases)}', failing_cases=fail_cases,
                                              attacker_detection={k2: f'{a}/{b}' for k2, (a, b) in sorted(att.items())})
            r = report[f'{tname}|{rname}']
            print(f'{tname:4} {rname:12} honest={r["honest_quarantines"]} ({100*r["honest_rate"]:.2f}%) longest={longest} fail={r["cases_failing_consecutive_rule"]}', flush=True)
            print('     ', json.dumps(r['attacker_detection']), flush=True)
    (out / 'persistence.json').write_text(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()
