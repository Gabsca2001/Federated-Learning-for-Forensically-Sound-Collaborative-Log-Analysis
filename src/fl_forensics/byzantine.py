"""Deterministic Byzantine attacks, diagnostics, clipping, and robust aggregation.

M6 deliberately operates on model *deltas*.  A valid M5 signature proves who
produced an update and that its bytes did not change; it does not prove that the
training objective or the resulting numbers are benign.  These primitives keep
that distinction explicit and allow every aggregator to consume the same frozen
delta objects.
"""

from __future__ import annotations

import copy
import hashlib
import math
from collections.abc import Sequence
from typing import Any, Literal

import numpy as np

AggregationName = Literal[
    "fedavg",
    "coordinate_median",
    "trimmed_mean",
    "multikrum",
    "bulyan",
]


class ByzantineConfigurationError(ValueError):
    """Raised when an experiment violates an aggregator's Byzantine bound."""


def _as_arrays(values: Sequence[Any]) -> list[np.ndarray]:
    return [np.asarray(value) for value in values]


def validate_deltas(deltas: Sequence[Sequence[Any]]) -> list[list[np.ndarray]]:
    """Validate a non-empty collection of finite, structurally identical deltas."""

    if not deltas:
        raise ValueError("at least one client delta is required")
    normalized = [_as_arrays(delta) for delta in deltas]
    if not normalized[0]:
        raise ValueError("a client delta cannot be empty")
    reference_shapes = [value.shape for value in normalized[0]]
    for client_index, delta in enumerate(normalized):
        if len(delta) != len(reference_shapes):
            raise ValueError(f"client {client_index} has a different tensor count")
        for tensor_index, (value, shape) in enumerate(
            zip(delta, reference_shapes, strict=True)
        ):
            if value.shape != shape:
                raise ValueError(
                    f"client {client_index} tensor {tensor_index} has a different shape"
                )
            if not np.issubdtype(value.dtype, np.number) or not np.isfinite(value).all():
                raise ValueError(
                    f"client {client_index} tensor {tensor_index} is not finite numeric data"
                )
    return normalized


def flatten_delta(delta: Sequence[Any]) -> np.ndarray:
    arrays = _as_arrays(delta)
    if not arrays:
        raise ValueError("a client delta cannot be empty")
    return np.concatenate([value.astype(np.float64, copy=False).ravel() for value in arrays])


def _restore_delta(vector: np.ndarray, reference: Sequence[np.ndarray]) -> list[np.ndarray]:
    restored: list[np.ndarray] = []
    offset = 0
    for tensor in reference:
        size = int(tensor.size)
        restored.append(
            vector[offset : offset + size].reshape(tensor.shape).astype(tensor.dtype)
        )
        offset += size
    if offset != vector.size:
        raise ValueError("flat delta length does not match the reference tensors")
    return restored


def model_delta(base: Sequence[Any], updated: Sequence[Any]) -> list[np.ndarray]:
    base_arrays = _as_arrays(base)
    updated_arrays = _as_arrays(updated)
    validate_deltas([base_arrays, updated_arrays])
    return [
        new.astype(np.float64) - old.astype(np.float64)
        for old, new in zip(base_arrays, updated_arrays, strict=True)
    ]


def apply_delta(base: Sequence[Any], delta: Sequence[Any]) -> list[np.ndarray]:
    base_arrays = _as_arrays(base)
    delta_arrays = _as_arrays(delta)
    validate_deltas([base_arrays, delta_arrays])
    return [
        (old.astype(np.float64) + change.astype(np.float64)).astype(old.dtype)
        for old, change in zip(base_arrays, delta_arrays, strict=True)
    ]


def delta_l2(delta: Sequence[Any]) -> float:
    vector = flatten_delta(delta)
    return float(np.linalg.norm(vector))


def clip_delta_l2(delta: Sequence[Any], *, max_norm: float) -> tuple[list[np.ndarray], float]:
    """Clip one delta and return both the clipped tensors and applied scale."""

    if not math.isfinite(max_norm) or max_norm <= 0:
        raise ValueError("max_norm must be a finite positive number")
    arrays = _as_arrays(delta)
    vector = flatten_delta(arrays)
    norm = float(np.linalg.norm(vector))
    scale = 1.0 if norm <= max_norm or norm == 0.0 else max_norm / norm
    return [
        (value.astype(np.float64) * scale).astype(value.dtype) for value in arrays
    ], float(scale)


def attack_delta(
    delta: Sequence[Any],
    *,
    attack: Literal["gaussian_noise", "sign_flip", "model_replacement"],
    seed: int,
    scale: float = 1.0,
) -> list[np.ndarray]:
    """Apply a deterministic model-poisoning transformation to one local delta."""

    if not math.isfinite(scale) or scale <= 0:
        raise ValueError("attack scale must be a finite positive number")
    arrays = _as_arrays(delta)
    vector = flatten_delta(arrays)
    if attack == "gaussian_noise":
        rng = np.random.default_rng(seed)
        rms = float(np.linalg.norm(vector)) / math.sqrt(max(1, vector.size))
        standard_deviation = scale * (rms if rms > 0 else 1.0)
        attacked = vector + rng.normal(0.0, standard_deviation, size=vector.shape)
    elif attack == "sign_flip":
        attacked = -scale * vector
    elif attack == "model_replacement":
        attacked = scale * vector
    else:  # pragma: no cover - Literal protects typed callers
        raise ValueError(f"unsupported model-poisoning attack: {attack}")
    return _restore_delta(attacked, arrays)


def label_flip_rows(
    rows: Sequence[dict[str, Any]],
    *,
    source_label: str,
    target_label: str,
) -> tuple[list[dict[str, Any]], int]:
    """Return a copy with every selected source label deterministically flipped."""

    if source_label == target_label:
        raise ValueError("label-flip source and target must differ")
    poisoned = copy.deepcopy(list(rows))
    changed = 0
    for row in poisoned:
        if row.get("label") == source_label:
            row["label"] = target_label
            changed += 1
    return poisoned, changed


def backdoor_rows(
    rows: Sequence[dict[str, Any]],
    *,
    target_label: str,
    feature_indices: Sequence[int],
    trigger_value: float,
    fraction: float,
    seed: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Poison a deterministic hash-ranked fraction of rows with a feature trigger."""

    if not 0 < fraction <= 1:
        raise ValueError("backdoor fraction must be in (0, 1]")
    if not feature_indices or len(set(feature_indices)) != len(feature_indices):
        raise ValueError("backdoor feature indices must be non-empty and unique")
    poisoned = copy.deepcopy(list(rows))
    if not poisoned:
        return poisoned, []
    feature_count = len(poisoned[0].get("features", []))
    if any(index < 0 or index >= feature_count for index in feature_indices):
        raise ValueError("backdoor feature index is outside the frozen feature schema")
    ranked: list[tuple[str, int]] = []
    for index, row in enumerate(poisoned):
        identity = str(row.get("window_id", index))
        rank = hashlib.sha256(f"{seed}:{identity}".encode()).hexdigest()
        ranked.append((rank, index))
    selected_count = max(1, math.ceil(len(poisoned) * fraction))
    selected_indices = sorted(index for _rank, index in sorted(ranked)[:selected_count])
    selected_ids: list[str] = []
    for index in selected_indices:
        row = poisoned[index]
        for feature_index in feature_indices:
            row["features"][feature_index] = float(trigger_value)
        row["label"] = target_label
        selected_ids.append(str(row.get("window_id", index)))
    return poisoned, selected_ids


def poison_prototypes(
    prototypes: dict[str, Any],
    *,
    source_class: str,
    target_class: str,
    scale: float,
) -> dict[str, np.ndarray]:
    """Move one class prototype toward/through a target class prototype."""

    if source_class == target_class:
        raise ValueError("prototype source and target classes must differ")
    if source_class not in prototypes or target_class not in prototypes:
        raise ValueError("prototype poisoning references an unavailable class")
    if not math.isfinite(scale) or scale <= 0:
        raise ValueError("prototype poisoning scale must be finite and positive")
    result = {name: np.asarray(value).copy() for name, value in prototypes.items()}
    source = result[source_class].astype(np.float64)
    target = result[target_class].astype(np.float64)
    if source.shape != target.shape:
        raise ValueError("class prototypes use different embedding dimensions")
    result[source_class] = (source + scale * (target - source)).astype(
        result[source_class].dtype
    )
    return result


def colluding_deltas(
    template: Sequence[Any], *, client_count: int, scale: float = 1.0
) -> list[list[np.ndarray]]:
    """Create byte-equivalent coordinated deltas for a colluding client set."""

    if client_count <= 0:
        raise ValueError("colluding client_count must be positive")
    if not math.isfinite(scale) or scale <= 0:
        raise ValueError("collusion scale must be finite and positive")
    arrays = _as_arrays(template)
    return [
        [(value.astype(np.float64) * scale).astype(value.dtype) for value in arrays]
        for _ in range(client_count)
    ]


def _matrix(deltas: Sequence[Sequence[Any]]) -> tuple[np.ndarray, list[np.ndarray]]:
    normalized = validate_deltas(deltas)
    return np.stack([flatten_delta(delta) for delta in normalized]), normalized[0]


def _validate_f(n: int, f: int) -> None:
    if f < 0:
        raise ByzantineConfigurationError("f must be non-negative")
    if f >= n:
        raise ByzantineConfigurationError("f must be smaller than n")


def _krum_scores(matrix: np.ndarray, *, f: int) -> np.ndarray:
    n = int(matrix.shape[0])
    if n < 2 * f + 3:
        raise ByzantineConfigurationError(
            f"Krum requires n >= 2f + 3; received n={n}, f={f}"
        )
    differences = matrix[:, None, :] - matrix[None, :, :]
    distances = np.einsum("ijk,ijk->ij", differences, differences)
    neighbor_count = n - f - 2
    scores = np.empty(n, dtype=np.float64)
    for index in range(n):
        others = np.delete(distances[index], index)
        scores[index] = float(np.sort(others, kind="stable")[:neighbor_count].sum())
    return scores


def aggregate_deltas(
    deltas: Sequence[Sequence[Any]],
    *,
    strategy: AggregationName,
    f: int = 0,
    weights: Sequence[int | float] | None = None,
    multikrum_m: int | None = None,
) -> list[np.ndarray]:
    """Aggregate the same frozen client deltas with a named M6 strategy."""

    matrix, reference = _matrix(deltas)
    n = int(matrix.shape[0])
    _validate_f(n, f)
    if strategy == "fedavg":
        if weights is None:
            weights_array = np.ones(n, dtype=np.float64)
        else:
            weights_array = np.asarray(weights, dtype=np.float64)
            if weights_array.shape != (n,) or not np.isfinite(weights_array).all():
                raise ValueError("FedAvg weights must contain one finite value per client")
            if (weights_array <= 0).any():
                raise ValueError("FedAvg weights must be positive")
        aggregate = np.average(matrix, axis=0, weights=weights_array)
    elif strategy == "coordinate_median":
        aggregate = np.median(matrix, axis=0)
    elif strategy == "trimmed_mean":
        if n <= 2 * f:
            raise ByzantineConfigurationError(
                f"trimmed mean requires n > 2f; received n={n}, f={f}"
            )
        ordered = np.sort(matrix, axis=0, kind="stable")
        aggregate = ordered[f : n - f].mean(axis=0) if f else ordered.mean(axis=0)
    elif strategy == "multikrum":
        scores = _krum_scores(matrix, f=f)
        maximum_m = n - f - 2
        selected_count = maximum_m if multikrum_m is None else int(multikrum_m)
        if not 1 <= selected_count <= maximum_m:
            raise ByzantineConfigurationError(
                f"MultiKrum requires 1 <= m <= n-f-2 ({maximum_m})"
            )
        selected = np.lexsort((np.arange(n), scores))[:selected_count]
        aggregate = matrix[selected].mean(axis=0)
    elif strategy == "bulyan":
        if n < 4 * f + 3:
            raise ByzantineConfigurationError(
                f"Bulyan requires n >= 4f + 3; received n={n}, f={f}"
            )
        scores = _krum_scores(matrix, f=f)
        candidate_count = n - 2 * f
        selected = np.lexsort((np.arange(n), scores))[:candidate_count]
        candidates = matrix[selected]
        coordinate_median = np.median(candidates, axis=0)
        retained_count = candidate_count - 2 * f
        deviations = np.abs(candidates - coordinate_median)
        closest = np.argsort(deviations, axis=0, kind="stable")[:retained_count]
        aggregate = np.take_along_axis(candidates, closest, axis=0).mean(axis=0)
    else:
        raise ValueError(f"unsupported aggregation strategy: {strategy}")
    return _restore_delta(np.asarray(aggregate), reference)


def update_indicators(
    deltas: Sequence[Sequence[Any]], *, client_ids: Sequence[str] | None = None
) -> list[dict[str, Any]]:
    """Compute deterministic, server-visible anomaly indicators for each delta."""

    matrix, _reference = _matrix(deltas)
    n = int(matrix.shape[0])
    if client_ids is None:
        identities = [f"client{index + 1:02d}" for index in range(n)]
    else:
        identities = [str(value) for value in client_ids]
        if len(identities) != n or len(set(identities)) != n:
            raise ValueError("client_ids must be unique and align with the deltas")
    median = np.median(matrix, axis=0)
    mad = np.median(np.abs(matrix - median), axis=0)
    norms = np.linalg.norm(matrix, axis=1)
    median_norm = float(np.median(norms))
    median_vector_norm = float(np.linalg.norm(median))
    records: list[dict[str, Any]] = []
    for client_id, vector, norm in zip(identities, matrix, norms, strict=True):
        denominator = float(norm) * median_vector_norm
        cosine = 0.0 if denominator == 0 else float(np.dot(vector, median) / denominator)
        distance = float(np.linalg.norm(vector - median))
        standardized = np.abs(vector - median) / np.maximum(mad, 1e-12)
        records.append(
            {
                "client_id": client_id,
                "delta_l2": float(norm),
                "relative_norm": float(norm / median_norm) if median_norm > 0 else 0.0,
                "cosine_to_median": cosine,
                "coordinate_median_distance": distance,
                "mad_score": float(np.median(standardized)),
            }
        )
    return records
