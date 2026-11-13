"""Behavioural trigger-probe admission gate (single-feature, peer-relative).

For every client model of a round, each single feature j is set to v standard units
(v in VALUES) on the server's clean validation attack rows; shortcut(j, v) = increase in
the fraction predicted as the benign class. A client's score is its largest shortcut in
excess of the same round's peer median for that (j, v); quarantine when the score
exceeds the cohort threshold (clean maximum from verified clean histories). The probe
uses no attacker identity and no attack-plan feature or value. Development evidence:
results/gates-probes/revision-trigger-probe-dev and results/revision-trigger-probe-thresholds.
"""
from __future__ import annotations

import numpy as np

POLICY = 'probe'
VALUES = (3.0, 6.0, 12.0)


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def probe_inputs(validation_rows, benign_label='benign'):
    X = np.array([r['features'] for r in validation_rows if r['label'] != benign_label], dtype=np.float32)
    require(len(X) > 0 and X.ndim == 2, 'no attack rows in validation')
    blocks, keys = [X], [None]
    for j in range(X.shape[1]):
        for v in VALUES:
            Y = X.copy(); Y[:, j] = v; blocks.append(Y); keys.append((j, v))
    return np.concatenate(blocks), keys, len(X)


def shortcuts(model, stacked, keys, n, benign_index, torch):
    model.eval()
    with torch.no_grad():
        pred = model(torch.from_numpy(stacked)).argmax(dim=1).numpy().reshape(len(keys), n)
    rates = (pred == benign_index).mean(axis=1)
    return {k: float(rates[i] - rates[0]) for i, k in enumerate(keys) if k is not None}


def round_scores(per_client):
    clients = sorted(per_client); keys = list(per_client[clients[0]])
    require(all(list(per_client[c]) == keys for c in clients), 'probe key mismatch')
    med = {k: float(np.median([per_client[c][k] for c in clients])) for k in keys}
    out = {}
    for c in clients:
        best = max(keys, key=lambda k: per_client[c][k] - med[k])
        out[c] = (float(per_client[c][best] - med[best]), [int(best[0]), float(best[1])])
    return out


def decide(scores, threshold, trust_admissible=True):
    out = {}
    for c, (score, best) in scores.items():
        flagged = score > threshold; q = (not trust_admissible) or flagged
        out[c] = dict(policy=POLICY, status='quarantined' if q else 'accepted', contributes=not q,
                      reason='trust veto' if not trust_admissible else
                      (f'shortcut: feature {best[0]} at {best[1]:g} std units flips attack rows to benign beyond peers'
                       if flagged else 'no anomalous shortcut'))
    return out
