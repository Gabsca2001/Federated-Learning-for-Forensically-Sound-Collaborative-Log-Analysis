import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import trigger_probe_gate as tp  # noqa: E402

torch = pytest.importorskip('torch')


class Shortcut(torch.nn.Module):
    """Predicts class 1 ('benign') when feature j > 5, else class 0."""
    def __init__(self, j=None):
        super().__init__(); self.j = j

    def forward(self, x):
        logits = torch.zeros((x.shape[0], 2)); logits[:, 0] = 1.0
        if self.j is not None:
            logits[x[:, self.j] > 5, 1] = 2.0
        return logits


def rows(n=50, seed=0):
    rng = np.random.default_rng(seed)
    return [dict(features=rng.normal(0, 1, 6).tolist(), label='attack') for _ in range(n)] + [dict(features=[0.0] * 6, label='benign')]


def test_probe_inputs_shape():
    X, keys, n = tp.probe_inputs(rows())
    assert n == 50 and len(keys) == 1 + 6 * len(tp.VALUES) and X.shape == (n * len(keys), 6)


def test_poisoned_model_is_found_with_its_feature():
    X, keys, n = tp.probe_inputs(rows())
    models = {f'c{i}': Shortcut() for i in range(6)}; models['c0'] = Shortcut(j=4)
    per = {c: tp.shortcuts(m, X, keys, n, 1, torch) for c, m in models.items()}
    sc = tp.round_scores(per)
    assert sc['c0'][0] == pytest.approx(1.0) and sc['c0'][1][0] == 4
    assert all(sc[c][0] == pytest.approx(0.0) for c in models if c != 'c0')
    d = tp.decide(sc, 0.6)
    assert not d['c0']['contributes'] and 'feature 4' in d['c0']['reason']
    assert all(d[c]['contributes'] for c in models if c != 'c0')


def test_shared_shortcut_is_not_an_anomaly_and_trust_veto():
    X, keys, n = tp.probe_inputs(rows())
    models = {f'c{i}': Shortcut(j=2) for i in range(5)}
    sc = tp.round_scores({c: tp.shortcuts(m, X, keys, n, 1, torch) for c, m in models.items()})
    assert all(v[0] == pytest.approx(0.0) for v in sc.values())
    assert all(not v['contributes'] for v in tp.decide(sc, 0.6, trust_admissible=False).values())
