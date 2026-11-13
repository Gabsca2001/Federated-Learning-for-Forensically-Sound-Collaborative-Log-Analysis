"""Per-key normalised trigger-probe admission gate ('probek').

Same probe as trigger_probe_gate.py (each single feature j set to v in {3, 6, 12} std units
on the server's clean validation attack rows; shortcut = increase in the benign fraction).
For every key k = (j, v): excess_k = shortcut_k - round peer median_k; normalised score =
max_k excess_k / s_k, where s_k = max(clean maximum of excess_k in the cohort, FLOOR) is
fitted only on verified clean histories. Quarantine when the score exceeds MULTIPLIER.
Rationale and development: results/gates-probes/revision-probe-keynorm-dev (natural shortcuts such as
feature 12 vary across honest clients; one global threshold cannot separate them).
"""
from __future__ import annotations

import numpy as np

POLICY = 'probek'
FLOOR = 0.1
MULTIPLIER = 2.0


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def fit_scales(clean_excess_rows, keys, floor=FLOOR):
    """clean_excess_rows: iterable of {key: excess} dicts (one per client-round)."""
    out = {k: -np.inf for k in keys}
    for row in clean_excess_rows:
        for k in keys:
            out[k] = max(out[k], row[k])
    return {k: float(max(v, floor)) for k, v in out.items()}


def excess(per_client):
    clients = sorted(per_client); keys = list(per_client[clients[0]])
    require(all(list(per_client[c]) == keys for c in clients), 'probe key mismatch')
    med = {k: float(np.median([per_client[c][k] for c in clients])) for k in keys}
    return {c: {k: per_client[c][k] - med[k] for k in keys} for c in clients}


def round_scores(per_client, scales):
    out = {}
    for c, ex in excess(per_client).items():
        best = max(ex, key=lambda k: ex[k] / scales[k])
        out[c] = (float(ex[best] / scales[best]), [int(best[0]), float(best[1])])
    return out


def decide(scores, multiplier=MULTIPLIER, trust_admissible=True):
    out = {}
    for c, (score, best) in scores.items():
        flagged = score > multiplier; q = (not trust_admissible) or flagged
        out[c] = dict(policy=POLICY, status='quarantined' if q else 'accepted', contributes=not q,
                      reason='trust veto' if not trust_admissible else
                      (f'shortcut: feature {best[0]} at {best[1]:g} std units exceeds {multiplier:g}x its clean peer-relative maximum'
                       if flagged else 'no anomalous shortcut'))
    return out
