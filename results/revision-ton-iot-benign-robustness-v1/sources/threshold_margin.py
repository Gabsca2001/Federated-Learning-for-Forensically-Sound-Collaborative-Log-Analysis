"""Center a frozen validation decision plateau without changing its labels."""
import numpy as np


def center_validation_plateau(validation_scores, lower_threshold):
    scores = np.asarray(validation_scores, dtype=np.float64)
    lower = float(lower_threshold)
    if scores.ndim != 1 or not len(scores):
        raise ValueError('Nonempty score vector required')
    if not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError('Finite probability scores required')
    if not np.isfinite(lower) or not -1 <= lower <= 1:
        raise ValueError('Finite probability threshold or all-positive sentinel required')
    positive = scores[scores > lower]
    negative = scores[scores <= lower]
    if not len(positive) or not len(negative):
        return {'threshold': lower, 'changed': False, 'reason': 'No two-sided decision gap'}
    left = float(negative.max())
    right = float(positive.min())
    middle = left + (right - left) / 2
    if not left <= middle < right:
        middle = left
    assert np.array_equal(scores > lower, scores > middle)
    return {'threshold': middle, 'changed': middle != lower,
            'gap_lower_inclusive': left, 'gap_upper_exclusive': right,
            'validation_decisions_preserved': True,
            'fit_scope': 'Supplied validation scores and frozen original threshold only'}
