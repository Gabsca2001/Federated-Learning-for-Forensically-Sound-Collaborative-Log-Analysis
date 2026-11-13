"""Contracts for a bounded target-domain numerical FedAvg diagnostic."""

from __future__ import annotations

import hashlib
import json
import math

import numpy as np

from .preprocessing import FEATURE_NAMES
from .robust_preprocessing import apply_feature_transform, fit_feature_transform

VALIDATION_START = 1556409600  # 2019-04-28 00:00:00 UTC
TEST_START = 1556496000  # 2019-04-29 00:00:00 UTC
EMBARGO_SECONDS = 3600
MODES = ("source-standard", "target-standard", "target-log1p")
SEEDS = (341593, 342593, 343593)


def split_rows(rows):
    groups = {name: [] for name in ("train", "validation", "test", "embargo")}
    seen = set()
    for row in sorted(rows, key=lambda r: r["window_start_epoch"]):
        start, end = int(row["window_start_epoch"]), int(row["window_end_epoch"])
        if start in seen or start % 60 or end != start + 60:
            raise ValueError("Duplicate or malformed minute window")
        seen.add(start)
        if end <= VALIDATION_START - EMBARGO_SECONDS:
            split = "train"
        elif start >= VALIDATION_START and end <= TEST_START - EMBARGO_SECONDS:
            split = "validation"
        elif start >= TEST_START:
            split = "test"
        else:
            split = "embargo"
        if row["label"] not in ("benign", "attack"):
            raise ValueError("Unknown binary label")
        groups[split].append(row)
    for split in ("train", "validation", "test"):
        if {r["label"] for r in groups[split]} != {"benign", "attack"}:
            raise ValueError(f"Both binary classes required in {split}")
    return groups


def fit_transform(train_features, mode, source_scaler):
    if mode not in MODES:
        raise ValueError("Unknown declared preprocessing mode")
    if mode == "source-standard":
        if source_scaler["feature_names"] != FEATURE_NAMES:
            raise ValueError("Source feature order mismatch")
        return {
            "mode": "standard",
            "feature_names": FEATURE_NAMES,
            "fitted_on_split": "train",
            "fit_dataset": "Data24",
            "training_row_count": None,
            "log1p_features": [],
            "winsorization": {"enabled": False},
            "mean_after_transform": list(source_scaler["mean"]),
            "scale_after_transform": list(source_scaler["scale"]),
        }
    result = fit_feature_transform(
        train_features=train_features,
        feature_names=FEATURE_NAMES,
        mode="standard" if mode == "target-standard" else "log1p",
    )
    result["fit_dataset"] = "ToN-IoT training windows only"
    return result


def transform(features, specification):
    result = apply_feature_transform(
        features=features, feature_names=FEATURE_NAMES, specification=specification
    )
    return np.round(result, 12).astype(np.float32)


def iid_partitions(labels, *, client_count=15, seed=341593):
    labels = np.asarray(labels)
    if set(labels.tolist()) != {0, 1}:
        raise ValueError("Binary training labels required")
    rng = np.random.default_rng(seed)
    groups = [[] for _ in range(client_count)]
    for label in (0, 1):
        indices = np.flatnonzero(labels == label)
        rng.shuffle(indices)
        for offset, index in enumerate(indices):
            groups[offset % client_count].append(int(index))
    groups = [sorted(group) for group in groups]
    if min(map(len, groups)) < 32:
        raise ValueError("Minimum client training size not met")
    if sorted(i for group in groups for i in group) != list(range(len(labels))):
        raise ValueError("Training partition does not cover each input exactly once")
    return groups


def tensor_digest(arrays):
    digest = hashlib.sha256()
    for array in arrays:
        value = np.asarray(array, dtype="<f4", order="C")
        if not np.isfinite(value).all():
            raise ValueError("Nonfinite model tensor")
        header = json.dumps(
            {"shape": list(value.shape), "dtype": "<f4"}, sort_keys=True, separators=(",", ":")
        ).encode()
        digest.update(len(header).to_bytes(4, "big"))
        digest.update(header)
        digest.update(value.tobytes(order="C"))
    return digest.hexdigest()


def select_round(records):
    if not records:
        raise ValueError("No completed rounds")
    for record in records:
        if not math.isfinite(record["validation_macro_f1"]):
            raise ValueError("Invalid selection metric")
    return max(records, key=lambda r: (r["validation_macro_f1"], -r["round"]))


def wilson_interval(successes, total, z=1.959963984540054):
    if not total:
        return None
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return [max(0.0, center - radius), min(1.0, center + radius)]


def binary_metrics(labels, predicted, scores=None):
    from sklearn.metrics import average_precision_score, f1_score, roc_auc_score

    labels = np.asarray(labels, dtype=int)
    predicted = np.asarray(predicted, dtype=int)
    if len(labels) != len(predicted) or not len(labels):
        raise ValueError("Invalid metric inputs")
    tn = int(((labels == 0) & (predicted == 0)).sum())
    fp = int(((labels == 0) & (predicted == 1)).sum())
    fn = int(((labels == 1) & (predicted == 0)).sum())
    tp = int(((labels == 1) & (predicted == 1)).sum())
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    result = {
        "rows": len(labels),
        "confusion_matrix": {"labels": ["benign", "attack"], "values": [[tn, fp], [fn, tp]]},
        "accuracy": (tn + tp) / len(labels),
        "attack_precision": tp / (tp + fp) if tp + fp else None,
        "attack_recall": recall,
        "attack_f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "benign_specificity": specificity,
        "false_positive_rate": fp / (tn + fp) if tn + fp else None,
        "balanced_accuracy": (recall + specificity) / 2
        if recall is not None and specificity is not None
        else None,
        "macro_f1": float(
            f1_score(labels, predicted, labels=[0, 1], average="macro", zero_division=0)
        ),
        "false_positive_rate_wilson95": wilson_interval(fp, tn + fp),
        "interval_scope": "Window-level binomial descriptive interval; temporal dependence is not modeled.",
    }
    if scores is not None:
        both = bool(tp + fn and tn + fp)
        result["auroc"] = float(roc_auc_score(labels, scores)) if both else None
        result["average_precision"] = (
            float(average_precision_score(labels, scores)) if both else None
        )
    return result


def verify_checkpoint(path, expected_tensor_digest):
    with np.load(path, allow_pickle=False) as values:
        arrays = [values[name] for name in sorted(values.files)]
    if tensor_digest(arrays) != expected_tensor_digest:
        raise ValueError("Selected tensor digest mismatch")
    return arrays
