"""Explicit paper-level aggregation adapters, with declared ambiguous cases.

FLAME: Nguyen et al., USENIX Security 2022, Algorithm 1 and Appendix E.
WeiDetect: arXiv:2504.04367v1, Eq.9--14 and Algorithm 3.
FedGradTrace: CMC 87(3), 2026, DOI 10.32604/cmc.2026.077388, Eq.2 vs Eq.3.
The latter formulas differ; neither is silently normalized into the other.
"""

from __future__ import annotations

import math
import warnings
from typing import Any, Literal

import numpy as np


def _matrix(base: list[Any], models: list[list[Any]], client_ids: list[str]):
    if (
        not models
        or len(client_ids) != len(models)
        or len(set(client_ids)) != len(client_ids)
        or any(not name.strip() for name in client_ids)
    ):
        raise ValueError("one unique named client per model is required")
    shapes = [np.asarray(value).shape for value in base]
    if not shapes:
        raise ValueError("empty model schema")
    if any(not np.issubdtype(np.asarray(value).dtype, np.floating) for value in base):
        raise ValueError(
            "floating model tensors are required; integer casting would truncate aggregation"
        )
    flat_base = np.concatenate([np.asarray(value, dtype=np.float64).reshape(-1) for value in base])
    if not np.isfinite(flat_base).all():
        raise ValueError("nonfinite base model")
    vectors = []
    for model in models:
        if [np.asarray(value).shape for value in model] != shapes:
            raise ValueError("model tensor schema differs from the base")
        flat = np.concatenate([np.asarray(value, dtype=np.float64).reshape(-1) for value in model])
        if not np.isfinite(flat).all():
            raise ValueError("nonfinite client model/gradient")
        vectors.append(flat)
    return flat_base, np.stack(vectors)


def _restore(vector: np.ndarray, base: list[Any]) -> list[np.ndarray]:
    result, position = [], 0
    for reference in base:
        reference = np.asarray(reference)
        size = reference.size
        value = vector[position : position + size].reshape(reference.shape).astype(reference.dtype)
        if not np.isfinite(value).all():
            raise ValueError("aggregation is not representable in the model dtype")
        result.append(value)
        position += size
    if position != len(vector):
        raise ValueError("unconsumed aggregation coordinates")
    return result


def flame_aggregate(
    *,
    base: list[Any],
    models: list[list[Any]],
    client_ids: list[str],
    noise_factor: float = 0.01,
    seed: int,
) -> tuple[list[np.ndarray] | None, dict[str, Any]]:
    from sklearn.cluster import HDBSCAN

    if not math.isfinite(noise_factor) or noise_factor <= 0:
        raise ValueError("full FLAME requires positive noise_factor; zero is an ablation")
    flat_base, matrix = _matrix(base, models, client_ids)
    count = len(models)
    if count < 3:
        raise ValueError("FLAME majority clustering requires at least three clients")
    norms = np.linalg.norm(matrix, axis=1)
    denominator = np.outer(norms, norms)
    similarity = np.divide(
        matrix @ matrix.T, denominator, out=np.zeros_like(denominator), where=denominator > 0
    )
    distances = np.clip(1.0 - similarity, 0.0, 2.0)
    both_zero = (norms[:, None] == 0) & (norms[None, :] == 0)
    distances[both_zero] = 0.0
    distances = (distances + distances.T) / 2
    np.fill_diagonal(distances, 0.0)
    # sklearn includes the point in min_samples; contrib/hdbscan (paper) does not.
    labels = HDBSCAN(
        metric="precomputed",
        min_cluster_size=count // 2 + 1,
        min_samples=2,
        allow_single_cluster=True,
        copy=True,
        algorithm="brute",
    ).fit_predict(distances)
    selected = [index for index, label in enumerate(labels) if label >= 0]
    deviations = matrix - flat_base
    update_norms = np.linalg.norm(deviations, axis=1)
    clip = float(np.median(update_norms))
    report = {
        "method": "FLAME-Algorithm1-sklearn-HDBSCAN-adapter",
        "client_ids": client_ids,
        "cluster_labels": labels.tolist(),
        "selected_client_ids": [client_ids[index] for index in selected],
        "minimum_cluster_size": count // 2 + 1,
        "sklearn_min_samples": 2,
        "equivalent_contrib_min_samples": 1,
        "clip_bound_all_client_median_l2": clip,
        "noise_factor": noise_factor,
        "noise_sigma": noise_factor * clip,
        "noise_seed": seed,
        "aggregation_weights": "uniform-selected-models-paper-Algorithm1",
        "new_privacy_guarantee_claimed": False,
    }
    if len(selected) < count // 2 + 1:
        return None, {**report, "status": "no_majority_cluster"}
    factors = np.minimum(
        1.0, np.divide(clip, update_norms, out=np.ones_like(update_norms), where=update_norms > 0)
    )
    vector = flat_base + (deviations[selected] * factors[selected, None]).mean(axis=0)
    vector += np.random.default_rng(seed).normal(0.0, noise_factor * clip, size=flat_base.shape)
    return _restore(vector, base), {
        **report,
        "status": "aggregated",
        "clipping_factors": factors.tolist(),
    }


def weidetect_aggregate(
    *,
    models: list[list[Any]],
    client_ids: list[str],
    validation_f1: list[float],
    keep_count: int,
    seed: int,
) -> tuple[list[np.ndarray], dict[str, Any]]:
    from scipy.stats import weibull_min

    _, matrix = _matrix(models[0] if models else [], models, client_ids)
    scores = np.asarray(validation_f1, dtype=np.float64)
    if (
        scores.shape != (len(models),)
        or not np.isfinite(scores).all()
        or (scores < 0).any()
        or (scores > 1).any()
        or not 1 <= keep_count <= len(models)
    ):
        raise ValueError("invalid WeiDetect scores/keep_count")
    positive = scores[scores > 0]
    messages = []
    shape = scale = None
    if len(positive) >= 2 and np.ptp(positive) > 1e-12:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            shape, _location, scale = weibull_min.fit(positive, floc=0)
        messages = [str(item.message) for item in captured]
        if not math.isfinite(shape) or not math.isfinite(scale) or shape <= 0 or scale <= 0:
            raise ValueError("Weibull fit did not yield finite positive parameters")
        cdf = weibull_min.cdf(scores, shape, loc=0, scale=scale)
        fit_status = "fitted_positive_scores_location_zero"
    else:
        # The paper leaves zeros/equal scores unspecified; make the extension visible.
        cdf = np.where(scores > 0, 1.0, 0.0)
        fit_status = "degenerate_declared_neutral_cdf_with_seeded_ties"
    priorities = np.random.default_rng(seed).permutation(len(models))
    selected = np.lexsort((priorities, -scores, -cdf))[:keep_count]
    report = {
        "method": "WeiDetect-Eq9-14-with-declared-zero-tie-policy",
        "status": "aggregated",
        "client_ids": client_ids,
        "validation_f1": scores.tolist(),
        "cdf": cdf.tolist(),
        "shape": float(shape) if shape is not None else None,
        "scale": float(scale) if scale is not None else None,
        "fit_status": fit_status,
        "fit_warnings": messages,
        "keep_count": keep_count,
        "selected_client_ids": [client_ids[index] for index in selected],
        "tie_seed": seed,
        "zero_score_policy": "CDF zero; fit only positive scores, as required by the positive-support density",
        "degenerate_extension": "neutral CDF and score/seed tie ranking; not a successful distribution fit",
        "aggregation_weights": "uniform-selected-models-paper-Eq9",
    }
    return _restore(matrix[selected].mean(axis=0), models[0]), report


def fedgradtrace_global_gradient(
    *,
    base: list[Any],
    gradients: list[list[Any]],
    gradient_histories: list[Any],
    client_ids: list[str],
    sample_counts: list[int],
    learning_rate: float,
    formula: Literal["literal_eq2", "literal_eq3"],
) -> tuple[list[np.ndarray], dict[str, Any]]:
    flat_base, matrix = _matrix(base, gradients, client_ids)
    if (
        len(gradient_histories) != len(gradients)
        or len(sample_counts) != len(gradients)
        or any(count <= 0 for count in sample_counts)
        or not math.isfinite(learning_rate)
        or learning_rate <= 0
    ):
        raise ValueError("invalid live gradient trajectory protocol")
    norms = []
    for history, current in zip(gradient_histories, matrix, strict=True):
        array = np.asarray(history, dtype=np.float64)
        if (
            array.ndim != 2
            or array.shape[1] != matrix.shape[1]
            or array.shape[0] < 1
            or not np.isfinite(array).all()
            or not np.array_equal(array[-1], current)
        ):
            raise ValueError("history must end in the actual current global-model gradient")
        norms.append(float(np.linalg.norm(array, ord="fro")))
    norm = np.asarray(norms)
    if formula == "literal_eq2":
        coefficients = np.asarray(sample_counts, dtype=np.float64) * norm / sum(sample_counts)
        vector = (coefficients[:, None] * (flat_base - learning_rate * matrix)).sum(axis=0)
    elif formula == "literal_eq3":
        if norm.sum() <= 0:
            raise ValueError("literal Eq3 has a zero trajectory denominator")
        coefficients = norm / norm.sum()
        vector = flat_base - learning_rate * (coefficients[:, None] * matrix).sum(axis=0)
    else:
        raise ValueError("unknown FedGradTrace paper formula")
    return _restore(vector, base), {
        "method": f"FedGradTrace-{formula}-global-gradient-history-interpretation",
        "client_ids": client_ids,
        "trajectory_frobenius_norms": norms,
        "coefficients": coefficients.tolist(),
        "coefficient_sum": float(coefficients.sum()),
        "sample_counts": sample_counts,
        "history_lengths": [len(history) for history in gradient_histories],
        "learning_rate": learning_rate,
        "formula_ambiguity": "Eq2 and Eq3 differ in normalization and sample-size weighting; larger norms get larger formula weights despite the contrary prose claim.",
        "local_final_updates_used_as_gradient_substitutes": False,
    }
