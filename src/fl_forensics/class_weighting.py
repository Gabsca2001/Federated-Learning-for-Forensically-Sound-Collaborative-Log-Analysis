"""Shared class-weight policies for centralized and federated training."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from math import sqrt


_ALIASES = {
    "global-balanced-training-only": "balanced",
    "global-sqrt-balanced-training-only": "sqrt-balanced",
}


def compute_class_weights(
    labels: Iterable[str], *, strategy: str
) -> dict[str, float]:
    """Compute deterministic weights from training labels only."""

    normalized_labels = [str(label) for label in labels]
    if not normalized_labels:
        raise ValueError("class weights require at least one training label")

    normalized_strategy = _ALIASES.get(strategy, strategy)
    counts = Counter(normalized_labels)
    class_count = len(counts)
    total = len(normalized_labels)
    balanced = {
        label: total / (class_count * count)
        for label, count in sorted(counts.items())
    }

    if normalized_strategy == "balanced":
        return balanced
    if normalized_strategy == "sqrt-balanced":
        return {label: sqrt(weight) for label, weight in balanced.items()}
    if normalized_strategy == "none":
        return {label: 1.0 for label in sorted(counts)}
    raise ValueError(
        "unsupported class-weighting strategy: "
        f"{strategy!r}; expected balanced, sqrt-balanced, or none"
    )
