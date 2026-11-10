import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import head_gate_steps as gs  # noqa: E402
import head_cusum_gate as hg  # noqa: E402


def exp(enc, head):
    return {'parameters': [{'name': 'encoder.0.weight', 'dtype': 'float32', 'values': list(map(float, enc))},
                           {'name': 'classification_head.weight', 'dtype': 'float32', 'values': list(map(float, head))}]}


def test_local_steps():
    assert gs.local_steps(100, 2, 32) == 8 and gs.local_steps(1, 1, 32) == 1
    with pytest.raises(ValueError):
        gs.local_steps(0, 2, 32)


def test_large_client_with_proportionally_longer_delta_looks_normal_after_normalization():
    rng = np.random.default_rng(0)
    base = exp(np.zeros(30), np.zeros(6))
    clients = [f'c{i:02d}' for i in range(10)]
    sizes = {c: 320 for c in clients}; sizes['c00'] = 320 * 14   # 14x the data -> 14x steps
    direction_e, direction_h = rng.normal(size=30), rng.normal(size=6)
    exports = []
    for c in clients:
        k = 14.0 if c == 'c00' else 1.0
        exports.append(exp(k * (direction_e + rng.normal(0, .05, 30)), k * (direction_h + rng.normal(0, .05, 6))))
    raw = hg.compute_features(base, exports, clients)
    norm = gs.features(base, exports, clients, sizes, epochs=2, batch_size=32)
    assert raw['c00']['relative_norm'] > 10 and raw['c00']['knn_distance'] > 10
    assert norm['c00']['relative_norm'] == pytest.approx(1.0, abs=.1)
    assert norm['c00']['knn_distance'] < 2
    # cosine is invariant to a client's own scale, but the coordinate median moves slightly
    assert norm['c00']['head_cosine_to_median'] == pytest.approx(raw['c00']['head_cosine_to_median'], abs=.01)


def test_decide_is_stateless_and_vetoes():
    refs = {c: {f: dict(median=0.0, scale=1.0, observations=1) for f in hg.FEATURES} for c in hg.COHORTS}
    model = dict(references=refs, thresholds={c: dict(threshold=3.0) for c in hg.COHORTS})
    ok = {f: 0.0 for f in hg.FEATURES}; bad = dict(ok); bad['head_relative_norm'] = 10.0
    out = gs.decide(model, 'iid', {'a': ok, 'b': bad})
    assert out['a']['decision']['contributes'] and not out['b']['decision']['contributes']
    assert out == gs.decide(model, 'iid', {'a': ok, 'b': bad})
    assert not gs.decide(model, 'iid', {'a': ok}, trust_admissible=False)['a']['decision']['contributes']
