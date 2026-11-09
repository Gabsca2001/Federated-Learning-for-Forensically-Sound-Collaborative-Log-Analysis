"""Declared feature-space poisoning before local training, without trust overrides.

The pinned input remains the clean partition. The bound experiment specifies an
additional deterministic transformation; metrics commit both row streams. A TPM
Quote authenticates measured software, not benign training data or intent.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import digest_object, sha256_bytes, sha256_file
from .distributed_backdoor import DistributedBackdoorPlan, poison_local_rows
from .preprocessing import derived_json_bytes
from .storage import load_json


def build_dba_training_binding(config_path: Path, training: dict[str, Any]) -> dict[str, Any]:
    config = load_json(config_path)
    if set(config) != {"profile", "plan"} or config["profile"] != "bound-dba-training-v1":
        raise ValueError("unsupported DBA training experiment")
    plan = DistributedBackdoorPlan.model_validate(config["plan"])
    clients = {item["client_id"] for item in training["clients"]}
    if not set(plan.client_components) <= clients:
        raise ValueError("DBA assignment contains an unknown client")
    if plan.target_label not in training["class_names"]:
        raise ValueError("DBA target is outside the model classes")
    if max(int(i) for i in plan.trigger_values_decimal) >= len(training["feature_names"]):
        raise ValueError("DBA component is outside the feature schema")
    return {
        **config,
        "config_sha256": sha256_file(config_path),
        "plan_digest": digest_object(config["plan"]),
    }


def prepare_dba_training_rows(
    *, training: dict[str, Any], rows: list[dict[str, Any]], client_id: str, round_number: int
):
    binding = training.get("dba_training_experiment")
    if binding is None:
        return rows, None
    if (
        set(binding) != {"profile", "plan", "config_sha256", "plan_digest"}
        or binding["profile"] != "bound-dba-training-v1"
    ):
        raise ValueError("invalid bound DBA training experiment")
    if digest_object(binding["plan"]) != binding["plan_digest"]:
        raise ValueError("DBA plan digest mismatch")
    if client_id not in {item["client_id"] for item in training["clients"]}:
        raise ValueError("DBA training client is outside the signed contract")
    plan = DistributedBackdoorPlan.model_validate(binding["plan"])
    transformed, record = poison_local_rows(
        rows=rows, plan=plan, client_id=client_id, round_number=round_number
    )
    record.update(
        profile=binding["profile"],
        config_sha256=binding["config_sha256"],
        plan_digest=binding["plan_digest"],
        source_rows_sha256=sha256_bytes(derived_json_bytes(rows)),
        training_rows_sha256=sha256_bytes(derived_json_bytes(transformed)),
        semantic_identity_source="predeclared-experiment-only-not-a-detector",
    )
    return transformed, record
