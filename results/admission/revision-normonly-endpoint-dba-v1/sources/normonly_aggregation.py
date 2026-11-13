"""Research ablation: retain root-norm normalization, remove cosine weights.

Every nonzero eligible vector has equal weight. The trusted root provides only
the magnitude, never a direction score. This is normalization, not clipping.
"""
import numpy as np
from fltrust_screen_aggregation import tensors


def normonly_delta(local_deltas, root_delta, mandatory_gates):
    clients = sorted(local_deltas)
    if not clients or set(clients) != set(mandatory_gates):
        raise ValueError('inconsistent roster')
    if any(type(mandatory_gates[c]) is not bool for c in clients):
        raise ValueError('invalid gate')
    root = tensors(root_delta)
    shape = [a.shape for a in root]
    root_norm = float(np.linalg.norm(np.concatenate([a.ravel() for a in root])))
    if not np.isfinite(root_norm) or root_norm == 0:
        raise ValueError('zero or invalid root reference')
    values, norms, scores = {}, {}, {}
    for c in clients:
        values[c] = tensors(local_deltas[c])
        if [a.shape for a in values[c]] != shape:
            raise ValueError('changed tensor schema')
        norms[c] = float(np.linalg.norm(np.concatenate([a.ravel() for a in values[c]])))
        if not np.isfinite(norms[c]):
            raise ValueError('invalid delta norm')
        scores[c] = 1. if mandatory_gates[c] and norms[c] else 0.
    total = sum(scores.values())
    if total == 0:
        raise ValueError('no nonzero eligible updates')
    weights = {c: scores[c] / total for c in clients}
    scales = {c: root_norm / norms[c] if scores[c] else 0. for c in clients}
    result = [sum((values[c][k] * (weights[c] * scales[c]) for c in clients),
                  np.zeros_like(a)) for k, a in enumerate(root)]
    aggregate_norm = float(np.linalg.norm(np.concatenate([a.ravel() for a in result])))
    if not np.isfinite(aggregate_norm) or aggregate_norm > root_norm * (1 + 1e-12):
        raise ValueError('invalid normalized aggregate')
    return result, dict(root_norm=root_norm, local_norms=norms, scores=scores,
                        score_sum=total, normalized_scores=weights, norm_scales=scales,
                        effective_raw_delta_coefficients={c: weights[c] * scales[c] for c in clients},
                        positive_contributors=sum(v > 0 for v in scores.values()),
                        aggregate_norm=aggregate_norm, direction_filter=False,
                        coefficient_scope='Uniform weights on root-norm-normalized vectors; raw-delta coefficients need not sum to one.')
