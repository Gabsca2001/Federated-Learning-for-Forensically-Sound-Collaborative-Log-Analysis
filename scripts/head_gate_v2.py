"""Head-aware gate v2: size-conditioned, per-round, non-compensatory.

Changes from v1 (``head_cusum_gate.py``), each motivated by a recorded failure:

* Size conditioning. v1 permanently quarantined an honest client holding 34% of
  the data (factorial guard, non-IID): larger clients take more local steps and
  naturally produce larger, more distant deltas. v2 models each indicator as a
  robust linear function of ``log(n_i / median n)`` fitted on clean data
  (Theil-Sen slope, median intercept) and scores the residual against a robust
  residual scale. Size is the bound example count, never a model-derived value.
* No CUSUM. Live, the per-round max was never worse than CUSUM (5 worse, 0 better
  for CUSUM) and CUSUM never released a persistently atypical honest client.
  ``head_v2`` decides each round independently: no exclusion state at all.

Indicators and the non-compensatory max are unchanged (``head_cusum_gate``).
Fitting accepts an allowlist (cohort, round, history, client, size_ratio,
features); no attacker identity, poisoning label, trigger or test outcome.
"""
from __future__ import annotations

import math
from collections import defaultdict
from fractions import Fraction

import numpy as np

import head_cusum_gate as hg

FEATURES, DIRECTIONS, COHORTS = hg.FEATURES, hg.DIRECTIONS, hg.COHORTS
POLICY = 'head_v2'
MAX_PAIRS = 400_000  # deterministic subsample bound for the Theil-Sen slope


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def size_ratio(n, median_n):
    require(isinstance(n, int) and n > 0 and median_n > 0, 'invalid example counts')
    return math.log(n / median_n)


def clean_record(record):
    require(set(record) == {'cohort', 'round', 'history', 'client', 'size_ratio', 'features'}, 'unexpected fitting fields')
    require(record['cohort'] in COHORTS and math.isfinite(record['size_ratio']), 'bad cohort/size')
    require(set(record['features']) == set(FEATURES), 'feature schema mismatch')
    require(all(math.isfinite(v) for v in record['features'].values()), 'nonfinite clean feature')
    return record


def theil_sen(x, y):
    """Median pairwise slope (deterministic subsample of pairs if large) and median intercept."""
    x, y = np.asarray(x, float), np.asarray(y, float)
    n = len(x)
    i, j = np.triu_indices(n, 1)
    if len(i) > MAX_PAIRS:
        step = math.ceil(len(i) / MAX_PAIRS)
        i, j = i[::step], j[::step]
    dx = x[j] - x[i]
    keep = np.abs(dx) > 1e-12
    slope = float(np.median((y[j] - y[i])[keep] / dx[keep])) if keep.any() else 0.0
    intercept = float(np.median(y - slope * x))
    return slope, intercept


def fit_references(records):
    by = defaultdict(list)
    for r in map(clean_record, records):
        by[r['cohort']].append(r)
    refs = {}
    for cohort in COHORTS:
        rows = by.get(cohort)
        require(rows, f'no clean references for {cohort}')
        x = [r['size_ratio'] for r in rows]
        refs[cohort] = {}
        for f in FEATURES:
            y = [DIRECTIONS[f] * r['features'][f] for r in rows]
            slope, intercept = theil_sen(x, y)
            resid = np.asarray(y) - (intercept + slope * np.asarray(x))
            scale = float(1.4826 * np.median(np.abs(resid - np.median(resid))))
            require(scale > 0, f'zero residual scale {cohort}/{f}')
            refs[cohort][f] = dict(slope=slope, intercept=intercept, residual_median=float(np.median(resid)),
                                   scale=scale, observations=len(rows),
                                   size_ratio_range=[float(min(x)), float(max(x))])
    return refs


def adverse_z(features, ratio, refs, cohort):
    require(cohort in refs, 'unsupported cohort')
    out = {}
    for f in FEATURES:
        r = refs[cohort][f]
        expected = r['intercept'] + r['slope'] * ratio + r['residual_median']
        out[f] = max(0.0, (DIRECTIONS[f] * features[f] - expected) / r['scale'])
    return out


def round_score(features, ratio, refs, cohort):
    return max(adverse_z(features, ratio, refs, cohort).values())


def _quantile(values, q):
    v = sorted(values); q = Fraction(str(q)); require(v and 0 < q <= 1, 'bad quantile input')
    return float(v[max(0, math.ceil(q * len(v)) - 1)])


def fit_thresholds(refs, records, target_rate='0.02'):
    records = [clean_record(r) for r in records]
    out = {}
    for cohort in COHORTS:
        rows = [r for r in records if r['cohort'] == cohort]
        require(rows, f'no calibration records for {cohort}')
        scores = [round_score(r['features'], r['size_ratio'], refs, cohort) for r in rows]
        thr = _quantile(scores, 1 - Fraction(target_rate))
        # descriptive: calibration rate by size tercile, to expose residual size bias
        ratios = np.array([r['size_ratio'] for r in rows]); s = np.array(scores)
        cuts = np.quantile(ratios, [1 / 3, 2 / 3])
        by_size = {name: float(np.mean(s[m] > thr)) if m.any() else None for name, m in (
            ('small', ratios <= cuts[0]), ('middle', (ratios > cuts[0]) & (ratios <= cuts[1])), ('large', ratios > cuts[1]))}
        out[cohort] = dict(threshold=thr, target_rate=str(target_rate), observations=len(rows),
                           calibration_rate=float(np.mean(s > thr)), calibration_rate_by_size_tercile=by_size)
    return out


def decide(model, cohort, features, sizes, trust_admissible=True):
    """Per-round decisions; ``sizes`` maps client -> bound example count."""
    require(cohort in COHORTS and cohort in model['thresholds'], 'unsupported cohort')
    require(set(features) == set(sizes), 'feature/size roster mismatch')
    median_n = float(np.median(list(sizes.values())))
    thr = model['thresholds'][cohort]['threshold']
    out = {}
    for c, f in features.items():
        ratio = size_ratio(sizes[c], median_n)
        z = adverse_z(f, ratio, model['references'], cohort)
        score = max(z.values())
        flagged = score > thr
        quarantine = (not trust_admissible) or flagged
        out[c] = dict(size_ratio=ratio, adverse_z=z, score=score, decision=dict(
            policy=POLICY, status='quarantined' if quarantine else 'accepted', contributes=not quarantine,
            reason='trust veto' if not trust_admissible else ('score above clean threshold' if flagged else 'within clean threshold')))
    return out
