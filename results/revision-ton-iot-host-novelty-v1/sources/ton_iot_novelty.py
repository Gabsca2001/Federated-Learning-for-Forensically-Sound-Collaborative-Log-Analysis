"""Benign-only empirical thresholds and explicit host/minute alert support."""

import numpy as np

from fl_forensics.ton_iot_host_windows import pool_host_scores


def calibrate_benign_threshold(benign_scores, false_positive_budget=0.01):
    scores = np.asarray(benign_scores, dtype=np.float64)
    alpha = float(false_positive_budget)
    if scores.ndim != 1 or not len(scores) or not np.isfinite(scores).all():
        raise ValueError("Finite nonempty benign calibration scores required")
    if not np.isfinite(alpha) or not 0 <= alpha < 1:
        raise ValueError("False-positive budget must lie in [0, 1)")
    allowed = int(np.floor(alpha * len(scores)))
    threshold = float(np.sort(scores)[len(scores) - allowed - 1])
    observed = int((scores > threshold).sum())
    assert observed <= allowed
    return {
        "threshold": threshold,
        "decision": "raw anomaly score > threshold",
        "calibration_benign_windows": len(scores),
        "requested_empirical_false_positive_budget": alpha,
        "allowed_false_alerts": allowed,
        "observed_false_alerts": observed,
        "observed_false_positive_rate": observed / len(scores),
        "fit_scope": "Supplied benign validation scores only",
        "qualification": "Empirical calibration constraint, not a future FPR guarantee",
    }


def anomaly_flags(scores, threshold):
    values = np.asarray(scores, dtype=np.float64)
    if values.ndim != 1 or not np.isfinite(values).all() or not np.isfinite(threshold):
        raise ValueError("Finite score vector and threshold required")
    return values > float(threshold)


def combine_flags(classifier_flags, novelty_flags):
    first, second = np.asarray(classifier_flags), np.asarray(novelty_flags)
    if first.ndim != 1 or second.shape != first.shape:
        raise ValueError("Equal one-dimensional decision vectors required")
    if not np.isin(first, [0, 1]).all() or not np.isin(second, [0, 1]).all():
        raise ValueError("Binary decisions required")
    return first.astype(bool) | second.astype(bool)


def minute_alert_support(buckets, labels, predicted):
    labels, predicted = np.asarray(labels), np.asarray(predicted)
    if not np.isin(predicted, [0, 1]).all():
        raise ValueError("Binary predictions required")
    common_bucket, any_alert, actual = pool_host_scores(buckets, predicted, labels)
    _, supported, _ = pool_host_scores(buckets, predicted * labels, labels)
    return {
        "bucket": common_bucket,
        "actual": actual.astype(bool),
        "any_alert": any_alert.astype(bool),
        "attacked_host_alert": supported.astype(bool),
        "benign_host_only_coincidence": actual.astype(bool)
        & any_alert.astype(bool)
        & ~supported.astype(bool),
    }
