import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import pair_probe_gate as pp  # noqa: E402
import trigger_probe_gate as tp  # noqa: E402

torch = pytest.importorskip('torch')


class AndShortcut(torch.nn.Module):
    """Predicts 'benign' (class 1) only when BOTH features j and k exceed 5."""
    def __init__(self, pair=None):
        super().__init__(); self.pair = pair

    def forward(self, x):
        logits = torch.zeros((x.shape[0], 2)); logits[:, 0] = 1.0
        if self.pair is not None:
            j, k = self.pair; logits[(x[:, j] > 5) & (x[:, k] > 5), 1] = 2.0
        return logits


def rows(n=60, seed=0):
    rng = np.random.default_rng(seed)
    return [dict(features=rng.normal(0, 1, 6).tolist(), label='attack') for _ in range(n)] + [dict(features=[0.0] * 6, label='benign')]


def test_inputs_shape():
    stack, keys, n = pp.probe_inputs(rows())
    assert n == 60 and len(keys) == 1 + 15 * 2 and stack.shape == (len(keys) * n, 6)


def test_and_trigger_hidden_from_single_probe_but_found_by_pair_probe():
    r = rows(); s_inputs = tp.probe_inputs(r); p_inputs = pp.probe_inputs(r)
    models = {f'c{i}': AndShortcut() for i in range(5)}; models['c9'] = AndShortcut((1, 4))
    single = tp.round_scores({c: tp.shortcuts(m, *s_inputs, 1, torch) for c, m in models.items()})
    pair = pp.round_scores({c: tp.shortcuts(m, *p_inputs, 1, torch) for c, m in models.items()})
    assert single['c9'][0] == 0.0
    assert pair['c9'][0] == 1.0 and pair['c9'][1][:2] == [1, 4]
    d = pp.decide(tp.decide(single, .5), pair, .5)
    assert not d['c9']['contributes'] and d['c9']['pair_flag'] and not d['c9']['single_flag']
    assert all(d[c]['contributes'] for c in models if c != 'c9')


def test_trust_veto_and_single_flag_propagate():
    single = {'a': (0.9, [0, 3.0]), 'b': (0.0, [0, 3.0])}; pair = {'a': (0.0, [0, 1, 6.0]), 'b': (0.0, [0, 1, 6.0])}
    d = pp.decide(tp.decide(single, .5), pair, .5)
    assert not d['a']['contributes'] and d['b']['contributes']
    assert all(not v['contributes'] for v in pp.decide(tp.decide(single, .5, False), pair, .5, False).values())
