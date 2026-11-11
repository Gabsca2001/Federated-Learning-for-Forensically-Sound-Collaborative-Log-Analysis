"""Follow-up to revision_probe_keynorm_dev.py (development only, same vectors).

Splits honest flags into clean cases (what the guard rule judges) and honest clients in
attacked cases (which may inherit the backdoor through the poisoned global model), and
tries per-key scale multipliers m (threshold = m x per-key clean max, floor 0.1).
Usage: revision_probe_keynorm_split.py DIR (reads DIR/vectors.json, writes DIR/split.json)
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

from revision_probe_keynorm_dev import excess

MULTS = (1.0, 1.25, 1.5, 2.0)


def main():
    d = Path(sys.argv[1]); data = json.loads((d / 'vectors.json').read_text()); keys = data['keys']
    cmax = defaultdict(lambda: np.full(len(keys), -np.inf)); craw = defaultdict(float)
    for h in data['clean']:
        for rs in excess(h['rounds']):
            for v in rs.values():
                c = h['task']['cohort']; cmax[c] = np.maximum(cmax[c], v); craw[c] = max(craw[c], float(v.max()))
    rules = {'raw (deployed)': lambda c: (np.ones(len(keys)), craw[c])}
    for m in MULTS:
        rules[f'per-key x{m}'] = (lambda m: lambda c: (np.maximum(cmax[c], .1) * m, 1.0))(m)
    report = {}
    for name, rule in rules.items():
        clean = [0, 0, 0, []]; hon_att = [0, 0]; att = defaultdict(lambda: [0, 0]); per_variant_hon = defaultdict(lambda: [0, 0])
        for case in data['cases']:
            t = case['task']; scale, thr = rule(t['cohort']); attacked = t['variant'] != 'clean'
            atk = set(t['attackers']) if attacked else set(); runs = defaultdict(int); long_ = 0
            study = 'evasion' if 'evasion' in case['source'] else 'probe-live'
            for r, rs in enumerate(excess(case['rounds']), start=1):
                for c, v in rs.items():
                    q = bool((v / scale).max() > thr)
                    if c in atk:
                        if r <= 10:
                            k = f"{study}|{t['variant']}|{t['cohort']}"; att[k][0] += q; att[k][1] += 1
                        continue
                    if attacked:
                        hon_att[0] += q; hon_att[1] += 1; pv = per_variant_hon[f"{t['variant']}|{t['policy'].split('+')[0]}"]; pv[0] += q; pv[1] += 1
                    else:
                        clean[0] += q; clean[1] += 1; runs[c] = runs[c] + 1 if q else 0; long_ = max(long_, runs[c])
            if not attacked:
                clean[2] = max(clean[2], long_)
                if long_ >= 2:
                    clean[3].append(t['name'])
        n_clean = sum(c['task']['variant'] == 'clean' for c in data['cases'])
        report[name] = dict(clean_honest=f'{clean[0]}/{clean[1]}', clean_longest=clean[2], clean_cases_failing=f'{len(clean[3])}/{n_clean}',
                            failing=clean[3], attacked_honest=f'{hon_att[0]}/{hon_att[1]}',
                            attacked_honest_by_variant_gate={k: f'{a}/{b}' for k, (a, b) in sorted(per_variant_hon.items())},
                            attacker_detection={k: f'{a}/{b}' for k, (a, b) in sorted(att.items())})
        r = report[name]
        print(f"{name:16} CLEAN honest={r['clean_honest']} longest={r['clean_longest']} failing={r['clean_cases_failing']} | attacked-run honest={r['attacked_honest']}", flush=True)
        print('    det', json.dumps(r['attacker_detection']), flush=True)
        print('    hon', json.dumps(r['attacked_honest_by_variant_gate']), flush=True)
    (d / 'split.json').write_text(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()
