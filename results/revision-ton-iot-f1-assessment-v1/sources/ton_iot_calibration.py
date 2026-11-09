"""Validation-only binary-score rules with explicit class-wise F1 reporting."""

import numpy as np

from .ton_iot_retraining import binary_metrics


def metrics(labels, scores, threshold=0.5):
    if not np.isin(np.asarray(labels), [0, 1]).all():
        raise ValueError("Binary labels required")
    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    if len(labels) != len(scores) or not np.isfinite(scores).all():
        raise ValueError("Invalid score vector")
    result = binary_metrics(labels, (scores > threshold).astype(int), scores)
    (tn, fp), (fn, _tp) = result["confusion_matrix"]["values"]
    result["benign_f1"] = 2 * tn / (2 * tn + fp + fn) if 2 * tn + fp + fn else None
    result["threshold"] = float(threshold)
    result["decision"] = "attack_score > threshold"
    result["f1_goal_met"] = bool(
        result["macro_f1"] >= 0.85
        and result["benign_f1"] is not None
        and result["benign_f1"] >= 0.8
        and result["attack_f1"] >= 0.8
    )
    result["low_false_alarm_goal_met"] = bool(
        result["false_positive_rate"] is not None
        and result["false_positive_rate"] <= 0.1
        and result["attack_recall"] >= 0.9
    )
    return result


def fit_macro_threshold(validation_labels, validation_scores):
    """Maximize validation macro-F1; retain score ties as indivisible groups.

    Ties prefer fewer false positives and then the higher threshold. The API
    does not accept test values and never fits weights or a probability map.
    """
    if not np.isin(np.asarray(validation_labels), [0, 1]).all():
        raise ValueError("Binary validation labels required")
    y = np.asarray(validation_labels, dtype=int)
    score = np.asarray(validation_scores, dtype=float)
    if y.ndim != 1 or score.shape != y.shape or set(y.tolist()) != {0, 1}:
        raise ValueError("Both validation classes required")
    if not np.isfinite(score).all() or np.any(score < 0) or np.any(score > 1):
        raise ValueError("Finite unit-interval scores required")
    order = np.argsort(score, kind="stable")
    s = score[order]
    labels = y[order]
    ends = np.r_[np.flatnonzero(s[1:] != s[:-1]), len(s) - 1]
    positives = np.cumsum(labels, dtype=np.int64)
    negatives = np.cumsum(1 - labels, dtype=np.int64)
    fn = np.r_[0, positives[ends]]
    tn = np.r_[0, negatives[ends]]
    tp = int(y.sum()) - fn
    fp = len(y) - int(y.sum()) - tn
    f1_attack = np.divide(
        2 * tp, 2 * tp + fp + fn, out=np.zeros(len(tp), dtype=float), where=(2 * tp + fp + fn) != 0
    )
    f1_benign = np.divide(
        2 * tn, 2 * tn + fp + fn, out=np.zeros(len(tn), dtype=float), where=(2 * tn + fp + fn) != 0
    )
    objectives = (f1_attack + f1_benign) / 2
    thresholds = np.r_[-1.0, s[ends]]
    best = max(
        range(len(thresholds)), key=lambda i: (objectives[i], -int(fp[i]), float(thresholds[i]))
    )
    threshold = float(thresholds[best])
    result = metrics(y, score, threshold)
    return {
        "threshold": threshold,
        "validation": result,
        "fit_scope": "Corrected validation only",
        "candidate_thresholds": len(thresholds),
        "objective": "macro-F1, then fewer false positives, then higher threshold",
    }
