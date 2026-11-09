"""Distributed feature-space triggers with matched poisoned-row budgets."""

from __future__ import annotations

import copy
from decimal import Decimal
from typing import Any, Literal

import numpy as np
from pydantic import Field, model_validator

from .byzantine import backdoor_rows
from .models import StrictModel


class DistributedBackdoorPlan(StrictModel):
    domain: Literal["distributed-feature-space-backdoor-v1"] = (
        "distributed-feature-space-backdoor-v1"
    )
    target_label: str = Field(min_length=1)
    client_components: dict[str, list[int]]
    trigger_values_decimal: dict[str, str]
    poisoned_fraction_decimal: str
    attack_rounds: list[int]
    seed: int = Field(ge=0)
    budget: Literal["replace-hash-ranked-training-rows"] = "replace-hash-ranked-training-rows"
    realizability: Literal["feature-space-only-no-primary-log-realizability-claim"] = (
        "feature-space-only-no-primary-log-realizability-claim"
    )

    @model_validator(mode="after")
    def validate_plan(self) -> DistributedBackdoorPlan:
        if len(self.client_components) < 2 or any(
            not client.strip() or not indices for client, indices in self.client_components.items()
        ):
            raise ValueError("DBA needs at least two named clients with nonempty components")
        indices = [index for component in self.client_components.values() for index in component]
        if any(index < 0 for index in indices) or len(set(indices)) != len(indices):
            raise ValueError(
                "distributed trigger components must be disjoint, unique and nonnegative"
            )
        if set(self.trigger_values_decimal) != {str(index) for index in indices}:
            raise ValueError("trigger value keys must match the complete distributed trigger")
        for value in self.trigger_values_decimal.values():
            numeric = Decimal(value)
            if not numeric.is_finite() or abs(numeric) > Decimal(str(np.finfo(np.float32).max)):
                raise ValueError("trigger values must be finite float32-representable values")
        fraction = Decimal(self.poisoned_fraction_decimal)
        if not fraction.is_finite() or not 0 < fraction <= 1:
            raise ValueError("poisoned fraction must lie in (0,1]")
        if (
            self.attack_rounds != sorted(set(self.attack_rounds))
            or not self.attack_rounds
            or self.attack_rounds[0] < 1
        ):
            raise ValueError("attack rounds must be positive, unique and sorted")
        return self


def _validate_rows(rows: list[dict[str, Any]], indices: list[int]) -> None:
    if not rows:
        raise ValueError("trigger input rows are empty")
    width = len(rows[0]["features"])
    if any(index >= width for index in indices) or any(
        len(row["features"]) != width for row in rows
    ):
        raise ValueError("trigger/schema width mismatch")
    if any(not np.isfinite(np.asarray(row["features"], dtype=np.float64)).all() for row in rows):
        raise ValueError("nonfinite source feature vector")


def poison_local_rows(
    *,
    rows: list[dict[str, Any]],
    plan: DistributedBackdoorPlan,
    client_id: str,
    round_number: int,
    distributed: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Use identical row selection for distributed and complete-trigger attacks."""
    plan = DistributedBackdoorPlan.model_validate(plan.model_dump(mode="json"))
    complete = sorted(int(index) for index in plan.trigger_values_decimal)
    _validate_rows(rows, complete)
    record = {
        "client_id": client_id,
        "round_number": round_number,
        "mode": "distributed" if distributed else "complete-trigger",
        "poisoned_window_ids": [],
        "feature_indices": [],
        "label_flip_count": 0,
        "modified_feature_values": 0,
        "source_row_count": len(rows),
    }
    if client_id not in plan.client_components or round_number not in plan.attack_rounds:
        return copy.deepcopy(rows), record
    indices = plan.client_components[client_id] if distributed else complete
    # Selection depends only on identity/seed, so trigger size cannot change row budget.
    client_index = sorted(plan.client_components).index(client_id)
    selection_seed = plan.seed + round_number * 10_000 + client_index
    poisoned, selected = backdoor_rows(
        rows,
        target_label=plan.target_label,
        feature_indices=indices,
        trigger_value=0.0,
        fraction=float(Decimal(plan.poisoned_fraction_decimal)),
        seed=selection_seed,
    )
    selected_set = set(selected)
    if len({str(row.get("window_id", index)) for index, row in enumerate(rows)}) != len(rows):
        raise ValueError("poisoning requires unique row identities")
    flips = 0
    for index, (original, changed) in enumerate(zip(rows, poisoned, strict=True)):
        if str(original.get("window_id", index)) not in selected_set:
            continue
        flips += original["label"] != plan.target_label
        for feature in indices:
            changed["features"][feature] = float(Decimal(plan.trigger_values_decimal[str(feature)]))
    record.update(
        poisoned_window_ids=selected,
        feature_indices=list(indices),
        label_flip_count=flips,
        modified_feature_values=len(selected) * len(indices),
        selection_seed=selection_seed,
    )
    return poisoned, record


def apply_evaluation_trigger(
    *,
    rows: list[dict[str, Any]],
    plan: DistributedBackdoorPlan,
    component_client_id: str | None = None,
) -> list[dict[str, Any]]:
    """Apply complete/sub-trigger without changing any reference evaluation label."""
    plan = DistributedBackdoorPlan.model_validate(plan.model_dump(mode="json"))
    if component_client_id is not None and component_client_id not in plan.client_components:
        raise ValueError("unknown trigger component")
    indices = (
        plan.client_components[component_client_id]
        if component_client_id is not None
        else sorted(int(index) for index in plan.trigger_values_decimal)
    )
    _validate_rows(rows, indices)
    result = copy.deepcopy(rows)
    for row in result:
        for index in indices:
            row["features"][index] = float(Decimal(plan.trigger_values_decimal[str(index)]))
    return result
