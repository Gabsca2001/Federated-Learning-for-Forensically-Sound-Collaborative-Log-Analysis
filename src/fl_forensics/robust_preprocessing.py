"""Training-only feature transforms for controlled M2 robustness experiments."""

from __future__ import annotations

from typing import Any


TRANSFORM_MODES = ("standard", "log1p", "log1p-winsor")

HEAVY_TAILED_FEATURES = (
    "connection_count",
    "unique_destination_count",
    "unique_destination_port_count",
    "duration_mean",
    "duration_std",
    "duration_max",
    "originator_bytes_sum",
    "responder_bytes_sum",
    "originator_packets_sum",
    "responder_packets_sum",
)


def _numpy() -> Any:
    try:
        import numpy as np
    except ImportError as exc:
        raise RuntimeError(
            'robust preprocessing requires: python -m pip install -e ".[m2]"'
        ) from exc
    return np


def _validate_matrix(features: Any, feature_names: list[str], np: Any) -> Any:
    matrix = np.asarray(features, dtype=np.float64)
    if matrix.ndim != 2:
        raise ValueError("features must be a two-dimensional matrix")
    if matrix.shape[0] == 0:
        raise ValueError("features must contain at least one row")
    if matrix.shape[1] != len(feature_names):
        raise ValueError("feature matrix width does not match feature names")
    if len(set(feature_names)) != len(feature_names):
        raise ValueError("feature names must be unique")
    if not np.isfinite(matrix).all():
        raise ValueError("feature matrix contains non-finite values")
    return matrix


def fit_feature_transform(
    *,
    train_features: Any,
    feature_names: list[str],
    mode: str,
    lower_quantile: float = 0.001,
    upper_quantile: float = 0.999,
) -> dict[str, Any]:
    """Fit a JSON-serializable transform using training rows only."""

    np = _numpy()
    if mode not in TRANSFORM_MODES:
        raise ValueError(f"unsupported transform mode: {mode!r}")
    if not 0.0 <= lower_quantile < upper_quantile <= 1.0:
        raise ValueError("winsor quantiles must satisfy 0 <= lower < upper <= 1")

    names = [str(name) for name in feature_names]
    matrix = _validate_matrix(train_features, names, np).copy()
    selected = [name for name in HEAVY_TAILED_FEATURES if name in names]
    if mode != "standard" and not selected:
        raise ValueError("no configured heavy-tailed features exist in the schema")
    indices = [names.index(name) for name in selected]

    if indices:
        selected_values = matrix[:, indices]
        if np.any(selected_values < 0.0):
            raise ValueError("log1p-selected features must be non-negative")
        if mode in {"log1p", "log1p-winsor"}:
            matrix[:, indices] = np.log1p(selected_values)

    lower_bounds: dict[str, float] = {}
    upper_bounds: dict[str, float] = {}
    if mode == "log1p-winsor":
        for name, index in zip(selected, indices, strict=True):
            lower = float(np.quantile(matrix[:, index], lower_quantile))
            upper = float(np.quantile(matrix[:, index], upper_quantile))
            lower_bounds[name] = lower
            upper_bounds[name] = upper
            matrix[:, index] = np.clip(matrix[:, index], lower, upper)

    means = matrix.mean(axis=0)
    scales = matrix.std(axis=0, ddof=0)
    scales = np.where(scales == 0.0, 1.0, scales)
    return {
        "schema_version": "1.0",
        "artifact_type": "m2_training_only_feature_transform",
        "mode": mode,
        "feature_names": names,
        "fitted_on_split": "train",
        "training_row_count": int(matrix.shape[0]),
        "log1p_features": selected if mode != "standard" else [],
        "winsorization": {
            "enabled": mode == "log1p-winsor",
            "lower_quantile": lower_quantile,
            "upper_quantile": upper_quantile,
            "quantile_method": "linear",
            "lower_bounds_after_log1p": lower_bounds,
            "upper_bounds_after_log1p": upper_bounds,
        },
        "mean_after_transform": [float(value) for value in means.tolist()],
        "scale_after_transform": [float(value) for value in scales.tolist()],
    }


def apply_feature_transform(
    *, features: Any, feature_names: list[str], specification: dict[str, Any]
) -> Any:
    """Apply a fitted training-only transform to any dataset split."""

    np = _numpy()
    names = [str(name) for name in feature_names]
    matrix = _validate_matrix(features, names, np).copy()
    if specification.get("fitted_on_split") != "train":
        raise ValueError("feature transform was not fitted on the training split")
    if specification.get("feature_names") != names:
        raise ValueError("feature transform schema does not match the dataset")
    mode = str(specification.get("mode"))
    if mode not in TRANSFORM_MODES:
        raise ValueError(f"unsupported fitted transform mode: {mode!r}")

    selected = [str(name) for name in specification.get("log1p_features", [])]
    indices = [names.index(name) for name in selected]
    if indices:
        values = matrix[:, indices]
        if np.any(values < 0.0):
            raise ValueError("log1p-selected features must be non-negative")
        matrix[:, indices] = np.log1p(values)

    winsor = specification.get("winsorization", {})
    if bool(winsor.get("enabled")):
        lower_bounds = winsor.get("lower_bounds_after_log1p", {})
        upper_bounds = winsor.get("upper_bounds_after_log1p", {})
        for name, index in zip(selected, indices, strict=True):
            matrix[:, index] = np.clip(
                matrix[:, index],
                float(lower_bounds[name]),
                float(upper_bounds[name]),
            )

    means = np.asarray(specification["mean_after_transform"], dtype=np.float64)
    scales = np.asarray(specification["scale_after_transform"], dtype=np.float64)
    if len(means) != matrix.shape[1] or len(scales) != matrix.shape[1]:
        raise ValueError("fitted transform dimensions do not match the dataset")
    if np.any(scales <= 0.0) or not np.isfinite(scales).all():
        raise ValueError("fitted transform contains invalid scales")
    transformed = (matrix - means) / scales
    if not np.isfinite(transformed).all():
        raise ValueError("transformed feature matrix contains non-finite values")
    return transformed
