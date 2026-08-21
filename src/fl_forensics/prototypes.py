"""Deterministic class-prototype extraction, poisoning, diagnostics, and aggregation."""

from __future__ import annotations

import copy
from collections.abc import Sequence
from typing import Any, Literal

import numpy as np

from .byzantine import poison_prototypes

PrototypeAggregationName = Literal["support_weighted_mean", "coordinate_median"]


class PrototypeConfigurationError(ValueError):
    """Raised when prototype support, shape, quorum, or aggregation is invalid."""


def _class_names(values: Sequence[str]) -> list[str]:
    names = [str(item) for item in values]
    if not names or len(set(names)) != len(names):
        raise PrototypeConfigurationError("prototype class names must be non-empty and unique")
    return names


def extract_class_prototypes(
    *,
    model: Any,
    rows: Sequence[dict[str, Any]],
    class_names: Sequence[str],
    minimum_support: int,
    batch_size: int,
    torch: Any,
) -> dict[str, Any]:
    """Extract deterministic encoder-centroid prototypes from one client snapshot."""

    names = _class_names(class_names)
    if minimum_support <= 0:
        raise PrototypeConfigurationError("minimum prototype support must be positive")
    if batch_size <= 0:
        raise PrototypeConfigurationError("prototype batch size must be positive")
    frozen_rows = list(rows)
    if not frozen_rows:
        raise PrototypeConfigurationError("prototype extraction requires at least one row")
    if not hasattr(model, "encoder"):
        raise PrototypeConfigurationError("prototype model has no encoder")
    label_indices = {name: index for index, name in enumerate(names)}
    try:
        labels = np.asarray(
            [label_indices[str(row["label"])] for row in frozen_rows],
            dtype=np.int64,
        )
        features = np.asarray(
            [row["features"] for row in frozen_rows], dtype=np.float32
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PrototypeConfigurationError(
            "prototype rows do not match the frozen feature/class schema"
        ) from exc
    if features.ndim != 2 or features.shape[0] != len(labels):
        raise PrototypeConfigurationError(
            "prototype feature rows must form one finite two-dimensional matrix"
        )
    if not np.isfinite(features).all():
        raise PrototypeConfigurationError("prototype feature rows are not finite")

    model.to("cpu")
    model.eval()
    batches: list[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(features), batch_size):
            batch = torch.from_numpy(features[start : start + batch_size])
            encoded = model.encoder(batch).detach().cpu().numpy()
            batches.append(np.asarray(encoded, dtype=np.float64))
    embeddings = np.concatenate(batches, axis=0)
    if embeddings.ndim != 2 or embeddings.shape[0] != len(frozen_rows):
        raise PrototypeConfigurationError(
            "model encoder did not produce one vector per prototype row"
        )
    if embeddings.shape[1] <= 0 or not np.isfinite(embeddings).all():
        raise PrototypeConfigurationError("model encoder produced invalid embeddings")

    supports: dict[str, int] = {}
    prototypes: dict[str, dict[str, Any]] = {}
    for class_index, class_name in enumerate(names):
        selected = embeddings[labels == class_index]
        support = len(selected)
        supports[class_name] = support
        if support >= minimum_support:
            centroid = selected.mean(axis=0, dtype=np.float64)
            prototypes[class_name] = {
                "support": support,
                "values": centroid.tolist(),
            }
    return {
        "embedding_size": int(embeddings.shape[1]),
        "row_count": len(frozen_rows),
        "minimum_local_support": minimum_support,
        "class_supports": supports,
        "eligible_class_count": len(prototypes),
        "prototypes": prototypes,
    }


def poison_prototype_records(
    extraction: dict[str, Any],
    *,
    source_class: str,
    target_class: str,
    scale: float,
) -> dict[str, Any]:
    """Poison one eligible class vector while preserving support and other classes."""

    result = copy.deepcopy(extraction)
    records = result.get("prototypes", {})
    vectors = {
        class_name: np.asarray(record["values"], dtype=np.float64)
        for class_name, record in records.items()
    }
    poisoned = poison_prototypes(
        vectors,
        source_class=source_class,
        target_class=target_class,
        scale=scale,
    )
    before = vectors[source_class]
    after = poisoned[source_class]
    records[source_class]["values"] = after.tolist()
    result["poisoning"] = {
        "source_class": source_class,
        "target_class": target_class,
        "scale": float(scale),
        "source_shift_l2": float(np.linalg.norm(after - before)),
        "support_preserved": int(records[source_class]["support"]),
    }
    return result


def _validated_submissions(
    submissions: Sequence[dict[str, Any]],
    *,
    class_names: Sequence[str],
) -> tuple[list[dict[str, Any]], list[str], int]:
    names = _class_names(class_names)
    values = list(submissions)
    if not values:
        raise PrototypeConfigurationError("at least one prototype submission is required")
    identities = [str(item.get("client_id")) for item in values]
    if len(set(identities)) != len(identities):
        raise PrototypeConfigurationError("prototype client identities must be unique")
    embedding_sizes = {int(item.get("embedding_size", 0)) for item in values}
    if len(embedding_sizes) != 1 or next(iter(embedding_sizes)) <= 0:
        raise PrototypeConfigurationError(
            "prototype submissions must share one positive embedding size"
        )
    embedding_size = next(iter(embedding_sizes))
    for submission in values:
        for class_name, record in submission.get("prototypes", {}).items():
            if class_name not in names:
                raise PrototypeConfigurationError(
                    f"prototype submission contains an unknown class: {class_name}"
                )
            support = int(record.get("support", 0))
            vector = np.asarray(record.get("values", []), dtype=np.float64)
            if support <= 0:
                raise PrototypeConfigurationError("prototype support must be positive")
            if vector.shape != (embedding_size,) or not np.isfinite(vector).all():
                raise PrototypeConfigurationError(
                    "prototype vectors must be finite and match the embedding size"
                )
    return values, names, embedding_size


def aggregate_class_prototypes(
    submissions: Sequence[dict[str, Any]],
    *,
    class_names: Sequence[str],
    minimum_local_support: int,
    class_quorum: int,
    strategy: PrototypeAggregationName,
) -> dict[str, Any]:
    """Aggregate eligible class prototypes without silently bypassing quorum."""

    values, names, embedding_size = _validated_submissions(
        submissions, class_names=class_names
    )
    if minimum_local_support <= 0:
        raise PrototypeConfigurationError("minimum local support must be positive")
    if class_quorum <= 0:
        raise PrototypeConfigurationError("prototype class quorum must be positive")
    if strategy not in {"support_weighted_mean", "coordinate_median"}:
        raise PrototypeConfigurationError(
            f"unsupported prototype aggregation strategy: {strategy}"
        )
    classes: dict[str, dict[str, Any]] = {}
    for class_name in names:
        eligible: list[tuple[str, int, np.ndarray]] = []
        for submission in values:
            record = submission.get("prototypes", {}).get(class_name)
            if record is None:
                continue
            support = int(record["support"])
            if support < minimum_local_support:
                raise PrototypeConfigurationError(
                    "a submitted prototype is below the declared local support"
                )
            eligible.append(
                (
                    str(submission["client_id"]),
                    support,
                    np.asarray(record["values"], dtype=np.float64),
                )
            )
        client_ids = sorted(item[0] for item in eligible)
        total_support = sum(item[1] for item in eligible)
        class_record: dict[str, Any] = {
            "status": "aggregated" if len(eligible) >= class_quorum else "insufficient_quorum",
            "supporting_client_count": len(eligible),
            "supporting_client_ids": client_ids,
            "total_support": total_support,
        }
        if len(eligible) >= class_quorum:
            matrix = np.stack([item[2] for item in eligible])
            if strategy == "support_weighted_mean":
                weights = np.asarray([item[1] for item in eligible], dtype=np.float64)
                aggregate = np.average(matrix, axis=0, weights=weights)
            else:
                aggregate = np.median(matrix, axis=0)
            class_record["values"] = np.asarray(aggregate, dtype=np.float64).tolist()
        classes[class_name] = class_record
    return {
        "strategy": strategy,
        "minimum_local_support": minimum_local_support,
        "class_quorum": class_quorum,
        "embedding_size": embedding_size,
        "classes": classes,
    }


def prototype_distance_indicators(
    submissions: Sequence[dict[str, Any]], *, class_names: Sequence[str]
) -> list[dict[str, Any]]:
    """Measure each available class vector against its coordinate-wise median."""

    values, names, _embedding_size = _validated_submissions(
        submissions, class_names=class_names
    )
    indicators: list[dict[str, Any]] = []
    for class_name in names:
        available = [
            (
                str(item["client_id"]),
                int(item["prototypes"][class_name]["support"]),
                np.asarray(item["prototypes"][class_name]["values"], dtype=np.float64),
            )
            for item in values
            if class_name in item.get("prototypes", {})
        ]
        if not available:
            continue
        matrix = np.stack([item[2] for item in available])
        median = np.median(matrix, axis=0)
        mad = np.median(np.abs(matrix - median), axis=0)
        distances = np.linalg.norm(matrix - median, axis=1)
        median_distance = float(np.median(distances))
        for (client_id, support, vector), distance in zip(
            available, distances, strict=True
        ):
            standardized = np.abs(vector - median) / np.maximum(mad, 1e-12)
            indicators.append(
                {
                    "client_id": client_id,
                    "class_name": class_name,
                    "support": support,
                    "distance_to_coordinate_median": float(distance),
                    "relative_distance": float(
                        distance / max(median_distance, 1e-12)
                    ),
                    "mad_score": float(np.median(standardized)),
                }
            )
    return indicators
