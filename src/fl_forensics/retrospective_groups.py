"""Clean-calibrated exploratory group detection, without adversary identities.

Similarity is evidence of compatible behaviour, not proof of intentional collusion.
Missing or constant series are left undefined rather than called correlated.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any

import numpy as np

from .byzantine import flatten_delta, validate_deltas

INDICATORS = (
    "relative_norm",
    "cosine_to_median",
    "coordinate_median_distance",
    "mad_score",
    "validation_impact",
)
FEATURES = (
    "median_centered_cosine",
    "tensor_deviation_profile_correlation",
    "temporal_indicator_correlation",
)


def _cosine(left, right):
    denominator = float(np.linalg.norm(left) * np.linalg.norm(right))
    return (
        None if denominator <= 1e-15 else float(np.clip(np.dot(left, right) / denominator, -1, 1))
    )


def _correlation(left, right):
    left, right = np.asarray(left, dtype=np.float64), np.asarray(right, dtype=np.float64)
    if len(left) < 3:
        return None
    return _cosine(left - left.mean(), right - right.mean())


def pair_descriptors(rounds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Input contains only observable deltas/indicators, never attack labels."""
    if len(rounds) < 3:
        raise ValueError("temporal group analysis requires at least three rounds")
    numbers = [record["round_number"] for record in rounds]
    if numbers != sorted(set(numbers)):
        raise ValueError("group rounds must be unique and ordered")
    clients = rounds[0]["client_ids"]
    if len(clients) < 3 or len(set(clients)) != len(clients):
        raise ValueError("group analysis requires at least three unique clients")
    centered, profiles, temporal = [], [], []
    schema = None
    for record in rounds:
        if record["client_ids"] != clients:
            raise ValueError("group analysis requires a stable ordered client population")
        tensors = validate_deltas(record["deltas"])
        if len(tensors) != len(clients):
            raise ValueError("delta/client mismatch")
        shapes = [value.shape for value in tensors[0]]
        if schema is not None and shapes != schema:
            raise ValueError("tensor schema changed between rounds")
        schema = shapes
        vectors = np.stack([flatten_delta(delta) for delta in tensors])
        deviations = vectors - np.median(vectors, axis=0)
        centered.append(deviations)
        tensor_norms = []
        position = 0
        for shape in shapes:
            size = int(np.prod(shape))
            tensor_norms.append(np.linalg.norm(deviations[:, position : position + size], axis=1))
            position += size
        profiles.append(np.log1p(np.stack(tensor_norms, axis=1)))
        indicators = record["indicators"]
        if [item["client_id"] for item in indicators] != clients:
            raise ValueError("indicator/client mismatch")
        values = np.asarray(
            [[item[name] for name in INDICATORS] for item in indicators], dtype=np.float64
        )
        if not np.isfinite(values).all():
            raise ValueError("nonfinite group indicators")
        temporal.append(values - np.median(values, axis=0))
    series = np.stack(temporal)
    records = []
    for left, right in combinations(range(len(clients)), 2):
        similarities = [_cosine(value[left], value[right]) for value in centered]
        tensor_similarity = [_correlation(value[left], value[right]) for value in profiles]
        correlations = [
            _correlation(series[:, left, index], series[:, right, index])
            for index in range(len(INDICATORS))
        ]

        def average_defined(values):
            defined = [value for value in values if value is not None]
            return None if not defined else float(np.mean(defined))

        values = [
            average_defined(similarities),
            average_defined(tensor_similarity),
            average_defined(correlations),
        ]
        complete = all(value is not None for value in values)
        records.append(
            {
                "clients": [clients[left], clients[right]],
                **dict(zip(FEATURES, values, strict=True)),
                "score": float(np.mean([max(0.0, value) for value in values]))
                if complete
                else None,
                "defined_round_cosines": sum(value is not None for value in similarities),
                "defined_tensor_profiles": sum(value is not None for value in tensor_similarity),
                "defined_temporal_indicators": sum(value is not None for value in correlations),
            }
        )
    return records


def calibrate_groups(clean_campaigns: list[list[dict[str, Any]]]) -> dict[str, Any]:
    """Calibrate score q.99 and feature q.95 only from declared clean controls."""
    if not clean_campaigns:
        raise ValueError("clean group calibration is empty")
    pairs = [pair for campaign in clean_campaigns for pair in pair_descriptors(campaign)]
    complete = [pair for pair in pairs if pair["score"] is not None]
    if not complete:
        raise ValueError("clean group calibration has no fully defined pairs")
    return {
        "domain": "clean-only-exploratory-group-calibration-v1",
        "clean_campaign_count": len(clean_campaigns),
        "complete_clean_pair_count": len(complete),
        "score_threshold": min(
            1.0,
            float(np.quantile([pair["score"] for pair in complete], 0.99, method="linear")) + 0.01,
        ),
        "feature_thresholds": {
            name: min(
                1.0,
                float(np.quantile([pair[name] for pair in complete], 0.95, method="linear")) + 0.01,
            )
            for name in FEATURES
        },
        "minimum_exceeded_feature_thresholds": 2,
        "attack_identities_used": False,
        "selection_rule": "strict score threshold and at least two strict feature thresholds; connected components of qualifying pair graph",
    }


def detect_groups(rounds: list[dict[str, Any]], calibration: dict[str, Any]) -> dict[str, Any]:
    if (
        calibration.get("domain") != "clean-only-exploratory-group-calibration-v1"
        or calibration.get("attack_identities_used") is not False
    ):
        raise ValueError("unknown or label-informed group calibration")
    if (
        set(calibration["feature_thresholds"]) != set(FEATURES)
        or calibration["minimum_exceeded_feature_thresholds"] != 2
    ):
        raise ValueError("changed group feature protocol")
    thresholds = [calibration["score_threshold"], *calibration["feature_thresholds"].values()]
    if any(not np.isfinite(value) or not -1 <= value <= 1 for value in thresholds):
        raise ValueError("invalid group thresholds")
    pairs = pair_descriptors(rounds)
    edges = []
    for pair in pairs:
        exceeded = [
            name
            for name in FEATURES
            if pair[name] is not None and pair[name] > calibration["feature_thresholds"][name]
        ]
        pair["exceeded_features"] = exceeded
        pair["candidate_edge"] = (
            pair["score"] is not None
            and pair["score"] > calibration["score_threshold"]
            and len(exceeded) >= 2
        )
        if pair["candidate_edge"]:
            edges.append(pair["clients"])
    adjacency = {client: set() for client in rounds[0]["client_ids"]}
    for left, right in edges:
        adjacency[left].add(right)
        adjacency[right].add(left)
    groups, seen = [], set()
    for start in sorted(adjacency):
        if start in seen or not adjacency[start]:
            continue
        stack, component = [start], set()
        while stack:
            node = stack.pop()
            if node in component:
                continue
            component.add(node)
            stack.extend(adjacency[node] - component)
        seen.update(component)
        groups.append(sorted(component))
    return {
        "candidate_groups": groups,
        "pairs": pairs,
        "intentional_collusion_proved": False,
        "interpretation": "Exploratory groups compatible with coordinated updates; similar local data can also explain similarity. Connected groups need not be cliques.",
    }
