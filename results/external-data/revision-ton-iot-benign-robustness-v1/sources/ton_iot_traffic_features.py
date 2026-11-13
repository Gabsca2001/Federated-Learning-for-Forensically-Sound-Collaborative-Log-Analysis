"""Explicit traffic-volume ablations derived from existing window aggregates."""

import numpy as np

MODES = ("fractions", "rates", "augmented")


def derive_features(features, mode):
    x = np.asarray(features, dtype=np.float64)
    if x.ndim != 2 or x.shape[1] != 25 or not len(x):
        raise ValueError("Nonempty 25-feature matrix required")
    if not np.isfinite(x).all() or np.any(x < 0):
        raise ValueError("Finite nonnegative aggregates required")
    if mode not in MODES:
        raise ValueError("Unknown representation")
    if np.any(x[:, 0] < 1):
        raise ValueError("Each window must contain at least one connection")
    fractions = x[:, 10:]
    fraction_names = [f"original_fraction_{i}" for i in range(10, 25)]
    if mode == "fractions":
        return fractions.copy(), fraction_names
    count = x[:, 0]
    rates = np.column_stack(
        [
            x[:, 1] / count,
            x[:, 2] / count,
            x[:, 6] / count,
            x[:, 7] / count,
            x[:, 8] / count,
            x[:, 9] / count,
            x[:, 6] / np.maximum(x[:, 8], 1),
            x[:, 7] / np.maximum(x[:, 9], 1),
        ]
    )
    rate_names = [
        "destinations_per_connection",
        "ports_per_connection",
        "originator_bytes_per_connection",
        "responder_bytes_per_connection",
        "originator_packets_per_connection",
        "responder_packets_per_connection",
        "originator_bytes_per_packet",
        "responder_bytes_per_packet",
    ]
    if mode == "rates":
        return np.column_stack([np.log1p(x[:, 3:6]), np.log1p(rates), fractions]), [
            "log_duration_mean",
            "log_duration_std",
            "log_duration_max",
        ] + ["log_" + n for n in rate_names] + fraction_names
    return np.column_stack([np.log1p(x[:, :10]), fractions, np.log1p(rates)]), [
        "log_original_" + str(i) for i in range(10)
    ] + fraction_names + ["log_" + n for n in rate_names]


def fit_standard(features):
    x = np.asarray(features, dtype=np.float64)
    if x.ndim != 2 or not len(x) or not np.isfinite(x).all():
        raise ValueError("Finite nonempty training matrix required")
    scale = x.std(axis=0)
    return {
        "mean": x.mean(axis=0).tolist(),
        "scale": np.where(scale == 0, 1, scale).tolist(),
        "fit_scope": "Training rows only",
    }


def apply_standard(features, spec):
    result = (np.asarray(features, dtype=np.float64) - np.asarray(spec["mean"])) / np.asarray(
        spec["scale"]
    )
    if not np.isfinite(result).all():
        raise ValueError("Nonfinite transformed features")
    return np.round(result, 12).astype(np.float32)
