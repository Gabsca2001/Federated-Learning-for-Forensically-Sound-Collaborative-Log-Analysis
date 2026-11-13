"""Head-aware non-compensatory admission candidate with per-client CUSUM.

Research adapter primitives, kept outside ``src/`` so locked historical studies
keep their source pins. Development evidence:
``results/admission/revision-tensor-indicators-v1`` (offline, fixed trajectories).

Indicators are round-relative geometry of client deltas (local minus base model):
whole-model relative norm, cosine to the coordinate median, mean distance to
the k nearest peers, and the same norm/cosine restricted to the classification
head. Each is turned into an adverse robust z against clean, cohort-specific
references. The round score is the MAXIMUM adverse z (non-compensatory: one
normal indicator cannot hide another). ``head_max`` quarantines on the round
score; ``head_cusum`` quarantines on a per-client one-sided CUSUM of it
(reference k = clean 0.90 quantile of round scores, chosen on development
seeds 342593/343593 of the offline study only).

Fitting accepts an explicit allowlist (cohort, round, client key, features):
no attacker identity, poisoning label, trigger or test outcome. Empirical
quantiles describe the calibration population only; dependent clients/rounds
give no future false-positive guarantee. Mandatory trust failure is a hard veto.
"""
from __future__ import annotations

import math
from collections import defaultdict
from fractions import Fraction

import numpy as np

FEATURES = ('relative_norm', 'cosine_to_median', 'knn_distance',
            'head_relative_norm', 'head_cosine_to_median')
DIRECTIONS = {'relative_norm': 1, 'cosine_to_median': -1, 'knn_distance': 1,
              'head_relative_norm': 1, 'head_cosine_to_median': -1}
HEAD_PREFIX = 'classification_head.'
KNN = 3
COHORTS = ('iid', 'non-iid')
POLICIES = ('head_max', 'head_cusum')


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def _flat(export, head_only):
    parts = [np.asarray(p['values'], dtype=np.float64).ravel() for p in export['parameters']
             if not head_only or p['name'].startswith(HEAD_PREFIX)]
    require(parts, 'no parameters selected (missing classification head?)')
    return np.concatenate(parts)


def _cos(a, b):
    na, nb = float(np.linalg.norm(a)), float(np.linalg.norm(b))
    return float(a @ b / (na * nb)) if na > 0 and nb > 0 else 0.0


def compute_features(base_export, local_exports, client_ids):
    """Round-relative indicators for each client; deterministic in its inputs."""
    require(len(local_exports) == len(client_ids) and len(set(client_ids)) == len(client_ids), 'client mismatch')
    require(len(client_ids) > KNN, 'too few clients for k-nearest-peer distance')
    names = [p['name'] for p in base_export['parameters']]
    for e in local_exports:
        require([p['name'] for p in e['parameters']] == names, 'parameter schema mismatch')
    base_full, base_head = _flat(base_export, False), _flat(base_export, True)
    D = np.array([_flat(e, False) - base_full for e in local_exports])
    H = np.array([_flat(e, True) - base_head for e in local_exports])
    norms, hnorms = np.linalg.norm(D, axis=1), np.linalg.norm(H, axis=1)
    require(float(np.median(norms)) > 0 and float(np.median(hnorms)) > 0, 'degenerate round: zero median update')
    med, hmed = np.median(D, axis=0), np.median(H, axis=0)
    sq = (D * D).sum(axis=1)
    dist = np.sqrt(np.maximum(sq[:, None] + sq[None, :] - 2 * D @ D.T, 0.0))
    np.fill_diagonal(dist, np.inf)
    knn = np.sort(dist, axis=1)[:, :KNN].mean(axis=1)
    out = {}
    for i, c in enumerate(client_ids):
        out[c] = {
            'relative_norm': float(norms[i] / np.median(norms)),
            'cosine_to_median': _cos(D[i], med),
            'knn_distance': float(knn[i] / np.median(knn)),
            'head_relative_norm': float(hnorms[i] / np.median(hnorms)),
            'head_cosine_to_median': _cos(H[i], hmed),
        }
        require(all(math.isfinite(v) for v in out[c].values()), 'nonfinite indicator')
    return out


def clean_record(record):
    require(set(record) == {'cohort', 'round', 'history', 'client', 'features'}, 'unexpected fitting fields')
    require(record['cohort'] in COHORTS, 'unsupported cohort')
    require(set(record['features']) == set(FEATURES), 'feature schema mismatch')
    require(all(math.isfinite(v) for v in record['features'].values()), 'nonfinite clean feature')
    return record


def _quantile(values, q):
    """Conservative empirical quantile: smallest observed value with CDF >= q."""
    require(values, 'empty quantile population')
    q = Fraction(str(q)); require(0 < q <= 1, 'quantile outside (0,1]')
    v = sorted(values)
    index = max(0, math.ceil(q * len(v)) - 1)
    return float(v[index])


def fit_references(records):
    by = defaultdict(lambda: defaultdict(list))
    for r in map(clean_record, records):
        for f in FEATURES:
            by[r['cohort']][f].append(DIRECTIONS[f] * r['features'][f])
    refs = {}
    for cohort in COHORTS:
        require(cohort in by, f'no clean references for cohort {cohort}')
        refs[cohort] = {}
        for f in FEATURES:
            v = np.array(by[cohort][f]); m = float(np.median(v))
            mad = float(1.4826 * np.median(np.abs(v - m)))
            require(mad > 0, f'zero clean MAD for {cohort}/{f}')
            refs[cohort][f] = dict(median=m, scale=mad, observations=len(v))
    return refs


def adverse_z(features, refs, cohort):
    require(cohort in refs, 'unsupported cohort')
    return {f: max(0.0, (DIRECTIONS[f] * features[f] - refs[cohort][f]['median']) / refs[cohort][f]['scale'])
            for f in FEATURES}


def round_score(features, refs, cohort):
    return max(adverse_z(features, refs, cohort).values())


def cusum_step(previous, score, k):
    require(previous >= 0 and math.isfinite(score), 'invalid CUSUM input')
    return max(0.0, previous + score - k)


def fit_thresholds(refs, records, target_rate='0.02', k_quantile='0.90'):
    """k = clean k_quantile of round scores; thresholds = clean (1-target) quantiles of score / CUSUM.

    k above the clean median keeps persistently heterogeneous benign clients
    (non-IID) from drifting upward; 0.90 was chosen on development seeds only.
    """
    records = [clean_record(r) for r in records]
    thresholds = {}
    for cohort in COHORTS:
        rows = sorted((r for r in records if r['cohort'] == cohort), key=lambda r: (r['history'], r['client'], r['round']))
        require(rows, f'no calibration records for {cohort}')
        scores = [round_score(r['features'], refs, cohort) for r in rows]
        k = _quantile(scores, k_quantile)
        stats, state = [], {}
        for r, s in zip(rows, scores):
            key = (r['history'], r['client'])
            require(state.get(key, (0, 0.0))[0] == r['round'] - 1, 'calibration history must be contiguous from round 1')
            value = cusum_step(state.get(key, (0, 0.0))[1], s, k)
            state[key] = (r['round'], value); stats.append(value)
        q = 1 - Fraction(target_rate)
        thresholds[cohort] = dict(k=k, k_quantile=str(k_quantile), max_threshold=_quantile(scores, q), cusum_threshold=_quantile(stats, q),
                                  observations=len(rows), target_rate=str(target_rate),
                                  calibration_rate_max=float(np.mean(np.array(scores) > _quantile(scores, q))),
                                  calibration_rate_cusum=float(np.mean(np.array(stats) > _quantile(stats, q))))
    return thresholds


def decide(model, cohort, features, previous_cusum, trust_admissible=True):
    """Per-client decisions for both candidate policies.

    ``previous_cusum`` maps client -> committed statistic after the previous
    round (0 for a client's first round). The returned statistics are the
    tentative next state; the caller commits only the selected round's state.
    """
    require(cohort in COHORTS and cohort in model['thresholds'], 'unsupported cohort')
    refs, limits = model['references'], model['thresholds'][cohort]
    out = {}
    for c, f in features.items():
        z = adverse_z(f, refs, cohort)
        score = max(z.values())
        stat = cusum_step(float(previous_cusum.get(c, 0.0)), score, limits['k'])
        flags = {'head_max': score > limits['max_threshold'], 'head_cusum': stat > limits['cusum_threshold']}
        decisions = {}
        for policy, flagged in flags.items():
            quarantine = (not trust_admissible) or flagged
            decisions[policy] = dict(policy=policy, status='quarantined' if quarantine else 'accepted',
                                     contributes=not quarantine,
                                     reason='trust veto' if not trust_admissible else
                                     ('statistic above clean threshold' if flagged else 'within clean threshold'))
        out[c] = dict(adverse_z=z, score=score, cusum=stat, decisions=decisions)
    return out
