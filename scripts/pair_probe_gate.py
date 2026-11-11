"""Behavioural pair-probe admission gate (feature pairs, peer-relative).

Extension of trigger_probe_gate.py for probe-aware AND-trigger attackers: for each of
the 300 unordered feature pairs (j, k) and v in VALUES, both features are set to v on a
fixed subset of the server's clean validation attack rows (SUBSET rows, permutation
seed SUBSET_SEED); shortcut = increase in the fraction predicted benign. Score = largest
shortcut in excess of the round's peer median for the same (j, k, v). Threshold = clean
maximum per cohort over verified clean histories (fitted before the study, pinned).
The gate 'probe2' quarantines a client flagged by the single-feature probe OR by the
pair probe. No attacker identity or attack-plan feature/value is used.
Development: results/revision-trigger-probe-dev (evasion.json).
"""
from __future__ import annotations

import itertools

import numpy as np

POLICY = 'probe2'
VALUES = (6.0, 12.0)
SUBSET = 400
SUBSET_SEED = 7


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def probe_inputs(validation_rows, benign_label='benign'):
    X = np.array([r['features'] for r in validation_rows if r['label'] != benign_label], dtype=np.float32)
    require(len(X) > 0 and X.ndim == 2, 'no attack rows in validation')
    X = X[np.random.default_rng(SUBSET_SEED).permutation(len(X))[:SUBSET]]
    blocks, keys = [X], [None]
    for j, k in itertools.combinations(range(X.shape[1]), 2):
        for v in VALUES:
            Y = X.copy(); Y[:, j] = v; Y[:, k] = v; blocks.append(Y); keys.append((j, k, v))
    return np.concatenate(blocks), keys, len(X)


def round_scores(per_client):
    clients = sorted(per_client); keys = list(per_client[clients[0]])
    require(all(list(per_client[c]) == keys for c in clients), 'pair probe key mismatch')
    med = {k: float(np.median([per_client[c][k] for c in clients])) for k in keys}
    out = {}
    for c in clients:
        best = max(keys, key=lambda k: per_client[c][k] - med[k])
        out[c] = (float(per_client[c][best] - med[best]), [int(best[0]), int(best[1]), float(best[2])])
    return out


def decide(single_decisions, pair_scores, threshold, trust_admissible=True):
    """Combine single-probe decisions (trigger_probe_gate.decide output) with pair scores."""
    out = {}
    for c, (score, best) in pair_scores.items():
        single_q = not single_decisions[c]['contributes']; pair_q = score > threshold
        q = (not trust_admissible) or single_q or pair_q
        if not trust_admissible:
            reason = 'trust veto'
        elif single_q:
            reason = single_decisions[c]['reason']
        elif pair_q:
            reason = f'pair shortcut: features {best[0]},{best[1]} at {best[2]:g} std units flip attack rows to benign beyond peers'
        else:
            reason = 'no anomalous single or pair shortcut'
        out[c] = dict(policy=POLICY, status='quarantined' if q else 'accepted', contributes=not q, reason=reason,
                      single_flag=bool(single_q), pair_flag=bool(pair_q))
    return out
