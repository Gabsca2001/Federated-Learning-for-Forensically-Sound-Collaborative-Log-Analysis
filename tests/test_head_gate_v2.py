import math
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import head_gate_v2 as g2  # noqa: E402


def synthetic(seed, cohort='iid', histories=4, rounds=6, n=15):
    """Clean clients whose norm/distance grow with log size (as in real non-IID data)."""
    rng = np.random.default_rng(seed); out = []
    sizes = np.exp(rng.normal(0, 1.0, n)).round().astype(int) * 50 + 30
    med = float(np.median(sizes))
    for h in range(histories):
        for r in range(1, rounds + 1):
            for i in range(n):
                x = math.log(sizes[i] / med)
                f = {'relative_norm': 1 + .4 * x + rng.normal(0, .05), 'cosine_to_median': .9 - .05 * abs(x) + rng.normal(0, .01),
                     'knn_distance': 1 + .5 * x + rng.normal(0, .05), 'head_relative_norm': 1 + .3 * x + rng.normal(0, .05),
                     'head_cosine_to_median': .9 + rng.normal(0, .02)}
                out.append(dict(cohort=cohort, round=r, history=f'h{h}', client=f'c{i:02d}', size_ratio=x, features=f))
    return out, sizes


def model():
    a, _ = synthetic(0); b, _ = synthetic(1, 'non-iid')
    refs = g2.fit_references(a + b)
    c, _ = synthetic(2); d, _ = synthetic(3, 'non-iid')
    return dict(references=refs, thresholds=g2.fit_thresholds(refs, c + d))


def test_theil_sen_recovers_slope_with_outliers():
    x = np.linspace(-2, 2, 200); y = 3 + 1.5 * x
    y[:10] += 50
    slope, intercept = g2.theil_sen(x, y)
    assert slope == pytest.approx(1.5, abs=1e-6) and intercept == pytest.approx(3, abs=1e-6)


def test_large_honest_client_is_not_flagged_by_size_alone():
    m = model(); refs = m['references']['iid']
    ratio = math.log(14)  # 14x the median, like the client that v1 excluded
    big = {f: g2.DIRECTIONS[f] * (refs[f]['intercept'] + refs[f]['slope'] * ratio + refs[f]['residual_median'])
           for f in g2.FEATURES}
    assert g2.round_score(big, ratio, m['references'], 'iid') == pytest.approx(0.0, abs=1e-9)


def test_anomaly_at_any_size_is_flagged_non_compensatory():
    m = model(); refs = m['references']['iid']
    for ratio in (math.log(.2), 0.0, math.log(10)):
        f = {k: g2.DIRECTIONS[k] * (refs[k]['intercept'] + refs[k]['slope'] * ratio + refs[k]['residual_median'])
             for k in g2.FEATURES}
        f['head_cosine_to_median'] -= 40 * refs['head_cosine_to_median']['scale']
        assert g2.round_score(f, ratio, m['references'], 'iid') == pytest.approx(40.0)


def test_calibration_rate_within_target_and_by_size_reported():
    m = model()
    for cohort in g2.COHORTS:
        t = m['thresholds'][cohort]
        assert t['calibration_rate'] <= 0.02 and set(t['calibration_rate_by_size_tercile']) == {'small', 'middle', 'large'}


def test_decide_is_stateless_and_trust_veto():
    m = model(); refs = m['references']['iid']
    feats = {c: {k: g2.DIRECTIONS[k] * (refs[k]['intercept'] + refs[k]['residual_median']) for k in g2.FEATURES}
             for c in ('a', 'b', 'c')}
    sizes = {'a': 100, 'b': 100, 'c': 100}
    out1 = g2.decide(m, 'iid', feats, sizes); out2 = g2.decide(m, 'iid', feats, sizes)
    assert out1 == out2 and all(v['decision']['contributes'] for v in out1.values())
    out = g2.decide(m, 'iid', feats, sizes, trust_admissible=False)
    assert all(not v['decision']['contributes'] for v in out.values())


def test_rejects_label_fields_and_bad_rosters():
    recs, _ = synthetic(0)
    with pytest.raises(ValueError):
        g2.fit_references([{**recs[0], 'attacker': True}])
    m = model()
    with pytest.raises(ValueError):
        g2.decide(m, 'iid', {'a': recs[0]['features']}, {'b': 10})
