"""Experimental, reproducible norm containment over original model updates.

Input authentication is the caller's obligation. Derived float64 deltas are
separate from original signed client objects. Bounds concern the pre-export
aggregate; a float32 checkpoint needs its measured rounding allowance.
"""

from __future__ import annotations

import hashlib
import json
from fractions import Fraction

import numpy as np

PROFILE = "bounded-delta-aggregation-v1"


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def arrays(value):
    result = [np.asarray(a, dtype=np.float64) for a in value]
    if not result or any(a.size == 0 or not np.isfinite(a).all() for a in result):
        raise ValueError("empty or nonfinite model tensors")
    return result


def record(values):
    return [{"shape": list(a.shape), "values": a.ravel().tolist()} for a in values]


def aggregate_bounded(
    base, updates, *, masses, mandatory_gates, limits, reference_digest, minimum_contributors=8
):
    """Return float64 parameters and a replayable derivation, or no aggregate."""
    base = arrays(base)
    clients = sorted(updates)
    if not clients or set(masses) != set(clients) or set(mandatory_gates) != set(clients):
        raise ValueError("inconsistent input roster")
    if type(minimum_contributors) is not int or not 1 <= minimum_contributors <= len(clients):
        raise ValueError("invalid quorum")
    if any(type(mandatory_gates[c]) is not bool for c in clients):
        raise ValueError("mandatory gates must be booleans")
    limits = np.asarray(limits, dtype=np.float64)
    if limits.shape != (len(base),) or not np.isfinite(limits).all() or np.any(limits <= 0):
        raise ValueError("invalid tensor limits")
    if (
        not isinstance(reference_digest, str)
        or len(reference_digest) != 64
        or any(c not in "0123456789abcdef" for c in reference_digest)
    ):
        raise ValueError("invalid reference commitment")
    weights = {c: Fraction(str(masses[c])) for c in clients}
    if any(w < 0 for w in weights.values()):
        raise ValueError("negative mass")
    effective = {c: weights[c] if mandatory_gates[c] else Fraction(0) for c in clients}
    total = sum(effective.values(), Fraction(0))
    quorum = sum(w > 0 for w in effective.values()) >= minimum_contributors and total > 0
    normalized = {c: effective[c] / total if total else Fraction(0) for c in clients}
    clipped, contributions = {}, {}
    for c in clients:
        local = arrays(updates[c])
        if len(local) != len(base) or any(
            a.shape != b.shape for a, b in zip(local, base, strict=True)
        ):
            raise ValueError("tensor schema changed")
        delta = [a - b for a, b in zip(local, base, strict=True)]
        norms = np.array([np.linalg.norm(a.ravel()) for a in delta])
        if not np.isfinite(norms).all():
            raise ValueError("overflow in delta norm")
        factors = np.minimum(
            1.0, np.divide(limits, norms, out=np.ones_like(norms), where=norms > 0)
        )
        clipped[c] = [a * f for a, f in zip(delta, factors, strict=True)]
        core = {
            "client_id": c,
            "original_model_digest": digest(record(local)),
            "mandatory_gate": mandatory_gates[c],
            "input_mass": str(weights[c]),
            "effective_mass": str(effective[c]),
            "normalized_weight": str(normalized[c]),
            "original_delta_norms": norms.tolist(),
            "clipping_factors": factors.tolist(),
            "derived_float64_delta": record(clipped[c]),
        }
        contributions[c] = {**core, "derivation_digest": digest(core)}
    delta = [
        sum((clipped[c][i] * float(normalized[c]) for c in clients), np.zeros_like(a))
        for i, a in enumerate(base)
    ]
    parameters = [a + d for a, d in zip(base, delta, strict=True)] if quorum else None
    core = {
        "profile": PROFILE,
        "base_digest": digest(record(base)),
        "reference_digest": reference_digest,
        "limits": limits.tolist(),
        "minimum_contributors": minimum_contributors,
        "quorum_satisfied": bool(quorum),
        "contributions": contributions,
        "pre_export_aggregate_digest": digest(record(parameters))
        if parameters is not None
        else None,
        "semantics": "derived float64 deltas; input signatures are not transferred to derived objects",
    }
    return parameters, {**core, "derivation_digest": digest(core)}


def verify_bounded(
    base,
    updates,
    report,
    *,
    masses,
    mandatory_gates,
    limits,
    reference_digest,
    minimum_contributors=8,
):
    """Reconstruct every transformation and mass from original observations."""
    expected, derived = aggregate_bounded(
        base,
        updates,
        masses=masses,
        mandatory_gates=mandatory_gates,
        limits=limits,
        reference_digest=reference_digest,
        minimum_contributors=minimum_contributors,
    )
    if derived != report:
        raise ValueError("bounded aggregation derivation mismatch")
    return expected


def removal_norm_bound(normalized_weight, limits):
    """Per-tensor 2*a_k*C bound with a fixed clipping map and survivor renormalization."""
    weight = Fraction(str(normalized_weight))
    values = np.asarray(limits, dtype=np.float64)
    if not 0 <= weight < 1 or not np.isfinite(values).all() or np.any(values <= 0):
        raise ValueError("removal needs surviving mass and finite positive limits")
    return 2 * float(weight) * values
