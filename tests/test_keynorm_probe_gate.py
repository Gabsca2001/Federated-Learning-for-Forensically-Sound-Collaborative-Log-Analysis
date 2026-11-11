import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import keynorm_probe_gate as kp  # noqa: E402

K = [(12, 12.0), (17, 12.0)]


def per(a12, a17, n=6):
    d = {f'h{i}': {K[0]: 0.1, K[1]: 0.0} for i in range(n)}
    d['x'] = {K[0]: a12, K[1]: a17}
    return d


def test_fit_scales_floor_and_max():
    s = kp.fit_scales([{K[0]: .5, K[1]: .01}, {K[0]: .3, K[1]: -.2}], K)
    assert s == {K[0]: .5, K[1]: kp.FLOOR}


def test_natural_feature_needs_larger_excess():
    scales = {K[0]: 0.5, K[1]: 0.1}
    # excess 0.8 on the noisy feature 12 is below 2x its clean max; 0.3 on stable feature 17 is above
    assert kp.decide(kp.round_scores(per(0.9, 0.0), scales))['x']['contributes']
    d = kp.decide(kp.round_scores(per(0.1, 0.3), scales))['x']
    assert not d['contributes'] and 'feature 17' in d['reason']


def test_trust_veto():
    d = kp.decide({'a': (0.0, [0, 3.0])}, trust_admissible=False)
    assert not d['a']['contributes'] and d['a']['reason'] == 'trust veto'
