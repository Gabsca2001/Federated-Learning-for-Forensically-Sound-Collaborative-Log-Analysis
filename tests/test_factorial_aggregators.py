import sys
from fractions import Fraction
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import factorial_aggregators as fa  # noqa: E402
from fl_forensics.byzantine import aggregate_deltas  # noqa: E402


def setup(n=12, seed=0):
    rng = np.random.default_rng(seed)
    base = [rng.normal(size=(3, 4)), rng.normal(size=5)]
    updates = {f'c{i:02d}': [b + rng.normal(scale=.1, size=b.shape) for b in base] for i in range(n)}
    return base, updates


def test_trimmed_mean_matches_reference_implementation():
    base, updates = setup()
    retained = {c: True for c in updates}
    params, rep = fa.trimmed_mean(base, updates, retained, f=3)
    deltas = [[u - b for u, b in zip(updates[c], base)] for c in sorted(updates)]
    ref = aggregate_deltas(deltas, strategy='trimmed_mean', f=3)
    for p, b, r in zip(params, base, ref):
        assert np.allclose(p - b, r)
    assert sum(rep['retained_value_share'].values()) == pytest.approx(1.0)
    assert all(type(v) is float for v in rep['retained_value_share'].values())  # canonical-JSON safe


def test_trimmed_mean_excludes_quarantined_and_checks_precondition():
    base, updates = setup(n=8)
    retained = {c: i >= 2 for i, c in enumerate(sorted(updates))}  # 6 retained, 6 <= 2*3
    params, rep = fa.trimmed_mean(base, updates, retained, f=3)
    assert params is None and 'violated' in rep['failure']
    retained = {c: i >= 1 for i, c in enumerate(sorted(updates))}
    params, rep = fa.trimmed_mean(base, updates, retained, f=3)
    assert params is not None and 'c00' not in rep['retained_value_share']


def test_extreme_client_loses_retained_share():
    base, updates = setup()
    updates['c00'] = [b + 50 for b in base]
    _, rep = fa.trimmed_mean(base, updates, {c: True for c in updates}, f=3)
    assert rep['retained_value_share']['c00'] == 0.0
    assert fa.attacker_influence(rep, {'c00'}) == 0.0


def test_fedavg_and_bounded_coefficients():
    base, updates = setup()
    masses = {c: Fraction(10) for c in updates}; masses['c00'] = Fraction(0)
    p, rep = fa.fedavg(base, updates, masses)
    assert 'c00' not in rep['coefficients']
    assert fa.attacker_influence(rep, {'c01'}) == pytest.approx(1 / 11)
    limits = [1e-3, 1e-3]  # strong clipping
    pb, repb = fa.bounded(base, updates, masses, limits, {'limits': limits}, minimum_contributors=10)
    assert pb is not None and repb['quorum_satisfied']
    assert fa.attacker_influence(repb, {'c01'}) == pytest.approx(1 / 11)
    for c in updates:
        assert all(f <= 1.0 for f in repb['clipping_factors'][c])
    big = [1e6, 1e6]
    pb2, _ = fa.bounded(base, updates, masses, big, {'limits': big}, minimum_contributors=10)
    for x, y in zip(pb2, p):
        assert np.allclose(x, y)  # no clipping -> FedAvg
