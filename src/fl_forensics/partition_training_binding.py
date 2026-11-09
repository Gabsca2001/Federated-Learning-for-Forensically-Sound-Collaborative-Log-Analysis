"""Explicit training-only changes over an immutable, previously built partition."""

from __future__ import annotations

import copy

from .canonical import sha256_file
from .config import load_yaml
from .storage import load_json

ALLOWED = ("seed", "local_epochs", "rounds")


def partition_training_binding(config, config_digest, manifest, source_path=None):
    if manifest.get("partition_config_sha256") == config_digest:
        return None
    if source_path is None:
        raise ValueError("different federation config requires an explicit partition source config")
    original, original_digest = load_yaml(source_path)
    if original_digest != manifest.get("partition_config_sha256"):
        raise ValueError("partition source config digest mismatch")
    expected, observed = copy.deepcopy(original), copy.deepcopy(config)
    changes = {}
    for field in ALLOWED:
        old, new = expected["training"].pop(field), observed["training"].pop(field)
        if type(new) is not int or new < (0 if field == "seed" else 1):
            raise ValueError("invalid training-only override")
        if old != new:
            changes[field] = {"partition_config": old, "training_config": new}
    if expected != observed:
        raise ValueError(
            "training override changes partitioning, model or another protected setting"
        )
    return {
        "profile": "explicit-partition-training-binding-v1",
        "partition_config_sha256": original_digest,
        "training_config_sha256": config_digest,
        "changed_training_fields": changes,
    }


def verify_public_partition_training_binding(public):
    config, config_digest = load_yaml(public / "federation.yaml")
    manifest = load_json(public / "partition-manifest.json")
    training = load_json(public / "training-contract.json")
    observed = training.get("partition_training_binding")
    source = public / "partition-source-federation.yaml" if observed is not None else None
    expected = partition_training_binding(config, config_digest, manifest, source)
    if observed != expected:
        raise ValueError("signed partition/training binding mismatch")
    if expected is not None and sha256_file(source) != expected["partition_config_sha256"]:
        raise ValueError("changed partition source config")
