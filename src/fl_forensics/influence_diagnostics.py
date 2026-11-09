"""Separate removal, survivor-policy and model effects without redefining Delta/J."""
from __future__ import annotations

from fractions import Fraction
from typing import Mapping, Sequence

import numpy as np


def _exact(value: Fraction) -> dict[str, str]:
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def influence_diagnostics(
    *,
    before_coefficients: Mapping[str, Fraction] | None,
    frozen_coefficients: Mapping[str, Fraction] | None,
    after_coefficients: Mapping[str, Fraction] | None,
    before_actions: Mapping[str, str],
    after_actions: Mapping[str, str],
    removed_ids: set[str],
    original_model: Sequence[np.ndarray] | None,
    frozen_model: Sequence[np.ndarray] | None,
    after_model: Sequence[np.ndarray] | None,
) -> dict:
    """Exact policy TV compares rescoring against removal-only renormalization.

    Model L2 distances are measured independently: their scalar values do not add.
    A None vector/model denotes an undefined or failed aggregation, never zero.
    """
    population = set(before_actions)
    if not removed_ids <= population or set(after_actions) != population - removed_ids:
        raise ValueError('action populations do not match the intervention')
    survivors = population - removed_ids
    for label, vector, expected in (
        ('before', before_coefficients, population),
        ('frozen', frozen_coefficients, survivors),
        ('after', after_coefficients, survivors),
    ):
        if vector is not None:
            if set(vector) != expected or not all(isinstance(v, Fraction) and v >= 0 for v in vector.values()):
                raise ValueError(f'invalid {label} coefficient vector')
            if sum(vector.values(), Fraction()) != 1:
                raise ValueError(f'unnormalized {label} coefficient vector')
    if before_coefficients is not None and frozen_coefficients is not None:
        remaining_mass = sum((before_coefficients[k] for k in survivors), Fraction())
        if remaining_mass <= 0 or any(
            frozen_coefficients[k] != before_coefficients[k] / remaining_mass for k in survivors
        ):
            raise ValueError('frozen coefficients are not removal-only renormalization')
    changes = sorted(k for k in survivors if before_actions[k] != after_actions[k])
    tv = None if frozen_coefficients is None or after_coefficients is None else sum(
        (abs(after_coefficients[k] - frozen_coefficients[k]) for k in survivors), Fraction()
    ) / 2

    def difference(left, right):
        if left is None or right is None:
            return None
        if len(left) != len(right):
            raise ValueError('model parameter counts differ')
        pieces = []
        for a, b in zip(left, right, strict=True):
            a, b = np.asarray(a, dtype=np.float64), np.asarray(b, dtype=np.float64)
            if a.shape != b.shape or not np.isfinite(a).all() or not np.isfinite(b).all():
                raise ValueError('invalid model parameters')
            pieces.append((b-a).reshape(-1))
        return np.concatenate(pieces) if pieces else np.empty(0, dtype=np.float64)

    direct = difference(original_model, frozen_model)
    policy = difference(frozen_model, after_model)
    total = difference(original_model, after_model)
    residual = float(np.linalg.norm(total - (direct + policy))) if all(
        x is not None for x in (direct, policy, total)
    ) else None
    return {
        'definition_profile': 'separated-removal-policy-model-effects-v1',
        'removed_submission_ids': sorted(removed_ids),
        'removed_original_weight': _exact(sum((before_coefficients[k] for k in removed_ids), Fraction()))
        if before_coefficients is not None else None,
        'survivor_action_changed': bool(changes),
        'survivor_action_changes': changes,
        'survivor_action_change_fraction': _exact(Fraction(len(changes), len(survivors))) if survivors else None,
        'survivor_policy_total_variation': _exact(tv) if tv is not None else None,
        'policy_comparison_defined': tv is not None,
        'policy_comparison_undefined_reason': None if tv is not None else 'A frozen or rescored normalized aggregate is unavailable.',
        'direct_removal_model_l2': float(np.linalg.norm(direct)) if direct is not None else None,
        'additional_policy_model_l2': float(np.linalg.norm(policy)) if policy is not None else None,
        'total_model_l2': float(np.linalg.norm(total)) if total is not None else None,
        'vector_decomposition_residual_l2': residual,
        'interpretation': 'Original Delta/J remain separate. Policy TV excludes removal-only renormalization; zero TV does not exclude statistical-score drift. Model L2 scalars are not additive. No semantic or causal multiround conclusion follows from these round-local diagnostics alone.',
    }
