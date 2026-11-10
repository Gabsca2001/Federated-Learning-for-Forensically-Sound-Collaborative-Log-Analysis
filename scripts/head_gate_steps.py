"""Head gate v2: step-normalized, per-round, non-compensatory indicators.

Development evidence (offline, recorded trajectories only): results/revision-head-gate-v2b-dev.
v1 excluded an honest client holding 34% of the data in every round because it
takes proportionally more local SGD steps (epochs * ceil(n / batch)), so its delta
is longer and farther from its peers. v2 divides each delta by its local step
count (scaled by the round median, FedAvg/FedNova-style) before computing the
unchanged v1 indicators; a cosine is invariant to its own client's scale, though
the coordinate median it is compared with moves slightly. The decision is the
per-round maximum adverse z (``head_max`` rule of v1): no CUSUM, no exclusion
state. A linear size correction (``head_gate_v2.py``) was tried first and did not
remove the bias; it is retained as a negative development result.
"""
from __future__ import annotations

import math

import numpy as np

import head_cusum_gate as hg

POLICY = 'head_v2'


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def local_steps(n, epochs, batch_size):
    require(isinstance(n, int) and n > 0 and epochs > 0 and batch_size > 0, 'invalid step inputs')
    return epochs * math.ceil(n / batch_size)


def normalized_exports(base_export, exports, clients, sizes, epochs, batch_size):
    """Deltas divided by local steps, rescaled by the round median step count."""
    require(len(exports) == len(clients) and set(clients) <= set(sizes), 'roster mismatch')
    st = {c: local_steps(sizes[c], epochs, batch_size) for c in clients}
    med = float(np.median(list(st.values())))
    base_vals = [np.asarray(p['values'], dtype=np.float64) for p in base_export['parameters']]
    out = []
    for c, e in zip(clients, exports):
        f = med / st[c]
        params = []
        for p, b, bp in zip(e['parameters'], base_vals, base_export['parameters']):
            require(p['name'] == bp['name'], 'parameter schema mismatch')
            v = np.asarray(p['values'], dtype=np.float64)
            params.append({'name': p['name'], 'dtype': 'float64', 'values': (b + f * (v - b)).tolist()})
        out.append({'parameters': params})
    return out


def features(base_export, exports, clients, sizes, epochs, batch_size):
    return hg.compute_features(base_export, normalized_exports(base_export, exports, clients, sizes, epochs, batch_size), clients)


def fit(reference_records, threshold_records, target_rate='0.02'):
    refs = hg.fit_references(reference_records)
    thr = hg.fit_thresholds(refs, threshold_records, target_rate, '0.90')
    return dict(profile='head-gate-step-normalized-v2', references=refs,
                thresholds={c: dict(threshold=v['max_threshold'], target_rate=v['target_rate'],
                                    observations=v['observations'], calibration_rate=v['calibration_rate_max'])
                            for c, v in thr.items()})


def decide(model, cohort, feats, trust_admissible=True):
    require(cohort in hg.COHORTS and cohort in model['thresholds'], 'unsupported cohort')
    thr = model['thresholds'][cohort]['threshold']
    out = {}
    for c, f in feats.items():
        z = hg.adverse_z(f, model['references'], cohort)
        score = max(z.values()); flagged = score > thr
        quarantine = (not trust_admissible) or flagged
        out[c] = dict(adverse_z=z, score=score, decision=dict(
            policy=POLICY, status='quarantined' if quarantine else 'accepted', contributes=not quarantine,
            reason='trust veto' if not trust_admissible else ('score above clean threshold' if flagged else 'within clean threshold')))
    return out
