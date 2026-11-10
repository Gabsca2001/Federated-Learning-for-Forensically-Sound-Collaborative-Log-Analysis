"""Aggregation operators for the gate x aggregation factorial study.

All operators act only on clients the admission gate retained (mass > 0) and
return the new model parameters plus an influence report, so attacker influence
after normalization can be measured for every operator:

* ``fedavg``        sample-weighted mean of deltas (the gate's masses).
* ``bounded``       per-tensor L2 clipping to fixed clean limits, then the
                    gate's normalized masses (reuses ``aggregate_bounded``).
* ``trimmed_mean``  unweighted coordinate-wise trimmed mean with ``f``
                    trimmed per side; influence = share of retained
                    coordinate values contributed by each client.

Downweighted clients enter trimmed mean unweighted (it has no weights); this is
declared, not hidden. A violated precondition (quorum, ``n > 2f``) returns no
aggregate and is recorded as an availability failure.
"""
from __future__ import annotations

from fractions import Fraction

import numpy as np

from fl_forensics.bounded_aggregation import aggregate_bounded, digest as bounded_digest

OPERATORS = ('fedavg', 'bounded', 'trimmed_mean')
TRIM_F = 3


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def _deltas(base, local):
    return [np.asarray(a, dtype=np.float64) - np.asarray(b, dtype=np.float64) for a, b in zip(local, base, strict=True)]


def trimmed_mean(base, updates, retained, f=TRIM_F):
    """Coordinate-wise trimmed mean over retained clients; returns (params, report) or (None, report)."""
    clients = [c for c in sorted(updates) if retained[c]]
    n = len(clients)
    report = dict(operator='trimmed_mean', f=f, retained_clients=clients, n=n, precondition=f'n > 2f ({n} > {2*f})')
    if n <= 2 * f:
        report['failure'] = 'trimmed mean precondition n > 2f violated'
        return None, report
    base = [np.asarray(a, dtype=np.float64) for a in base]
    flat = np.stack([np.concatenate([d.ravel() for d in _deltas(base, updates[c])]) for c in clients])
    order = np.argsort(flat, axis=0, kind='stable')
    keep = order[f:n - f]
    aggregate = np.take_along_axis(flat, keep, axis=0).mean(axis=0)
    counts = np.bincount(keep.ravel(), minlength=n)
    total = int(keep.size)
    report['retained_value_share'] = {c: float(int(counts[i]) / total) for i, c in enumerate(clients)}
    out, start = [], 0
    for b in base:
        out.append(b + aggregate[start:start + b.size].reshape(b.shape)); start += b.size
    return out, report


def fedavg(base, updates, masses):
    clients = [c for c in sorted(updates) if masses[c] > 0]
    total = sum((masses[c] for c in clients), Fraction(0))
    require(total > 0, 'no positive mass')
    base = [np.asarray(a, dtype=np.float64) for a in base]
    acc = [np.zeros_like(b) for b in base]
    for c in clients:
        w = float(masses[c] / total)
        for i, d in enumerate(_deltas(base, updates[c])):
            acc[i] += w * d
    return [b + d for b, d in zip(base, acc, strict=True)], dict(
        operator='fedavg', coefficients={c: str(masses[c] / total) for c in clients})


def bounded(base, updates, masses, limits, reference, minimum_contributors):
    gates = {c: masses[c] > 0 for c in updates}
    params, rep = aggregate_bounded(base, updates, masses={c: str(m) for c, m in masses.items()},
                                    mandatory_gates=gates, limits=limits, reference_digest=bounded_digest(reference),
                                    minimum_contributors=minimum_contributors)
    contrib = rep['contributions']
    report = dict(operator='bounded', derivation_digest=rep['derivation_digest'],
                  coefficients={c: v['normalized_weight'] for c, v in contrib.items() if Fraction(v['normalized_weight']) > 0},
                  clipping_factors={c: v['clipping_factors'] for c, v in contrib.items()},
                  quorum_satisfied=rep['quorum_satisfied'])
    return params, report


def attacker_influence(report, attackers):
    """Share of the aggregate attributable to the given identities (coefficient or retained-value share)."""
    if report.get('operator') == 'trimmed_mean':
        share = report.get('retained_value_share') or {}
        return float(sum(v for c, v in share.items() if c in attackers))
    coeff = report.get('coefficients') or {}
    return float(sum(Fraction(v) for c, v in coeff.items() if c in attackers))
