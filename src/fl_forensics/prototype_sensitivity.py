"""Predeclared exploratory sensitivity analysis for M6 prototype poisoning."""

from __future__ import annotations

import copy
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import sha256_bytes, sha256_file
from .config import load_yaml
from .preprocessing import derived_json_bytes
from .prototype_experiment import (
    freeze_prototype_scenario,
    run_prototype_comparison,
    verify_frozen_prototype_scenario,
    verify_prototype_comparison,
)
from .storage import load_json, write_once


class PrototypeSensitivityError(RuntimeError):
    """Raised when the predeclared sensitivity design or evidence is invalid."""


def _write_json(path: Path, value: dict[str, Any]) -> str:
    content = derived_json_bytes(value)
    write_once(path, content)
    return sha256_bytes(content)


def _scale_decimal(value: Any) -> Decimal:
    try:
        scale = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise PrototypeSensitivityError("sensitivity scales must be decimal values") from exc
    if not scale.is_finite() or scale <= 0:
        raise PrototypeSensitivityError("sensitivity scales must be finite and positive")
    return scale.normalize()


def _scale_token(scale: Decimal) -> str:
    value = format(scale, "f")
    if "." not in value:
        value = f"{value}.0"
    return value.replace("-", "m").replace(".", "p")


def _campaign_plan(config: dict[str, Any]) -> list[dict[str, Any]]:
    sensitivity = config.get("sensitivity", {})
    if sensitivity.get("analysis_type") != "exploratory-one-factor-at-a-time":
        raise PrototypeSensitivityError("unexpected sensitivity analysis type")
    if sensitivity.get("report_every_scenario") is not True:
        raise PrototypeSensitivityError("sensitivity analysis must preserve every scenario")
    if sensitivity.get("test_based_selection_permitted") is not False:
        raise PrototypeSensitivityError("test-based sensitivity selection must be disabled")

    client_count = int(config["experiment"]["client_count"])
    valid_clients = {f"client{index:02d}" for index in range(1, client_count + 1)}
    attacker_order = [str(item) for item in sensitivity["attacker_order"]]
    if (
        not attacker_order
        or len(set(attacker_order)) != len(attacker_order)
        or not set(attacker_order).issubset(valid_clients)
    ):
        raise PrototypeSensitivityError("sensitivity attacker order is invalid")

    f_values = [int(item) for item in sensitivity["f_sweep"]["values"]]
    if (
        f_values != sorted(set(f_values))
        or not f_values
        or f_values[0] <= 0
        or f_values[-1] > len(attacker_order)
    ):
        raise PrototypeSensitivityError("f sweep must be sorted, unique, and supported")
    fixed_scale = _scale_decimal(sensitivity["f_sweep"]["fixed_scale"])

    scale_values = [
        _scale_decimal(item) for item in sensitivity["scale_sweep"]["values"]
    ]
    if scale_values != sorted(set(scale_values)) or not scale_values:
        raise PrototypeSensitivityError("scale sweep must be sorted and unique")
    fixed_f = int(sensitivity["scale_sweep"]["fixed_f"])
    if fixed_f <= 0 or fixed_f > len(attacker_order):
        raise PrototypeSensitivityError("scale-sweep fixed f is unsupported")

    primary = sensitivity["primary_anchor"]
    primary_f = int(primary["f"])
    primary_scale = _scale_decimal(primary["scale"])
    cells = {(f, fixed_scale) for f in f_values}
    cells.update((fixed_f, scale) for scale in scale_values)
    if (primary_f, primary_scale) not in cells:
        raise PrototypeSensitivityError("primary anchor is absent from sensitivity cells")

    plan: list[dict[str, Any]] = []
    for f, scale in sorted(cells):
        plan.append(
            {
                "scenario_id": f"f{f}-scale-{_scale_token(scale)}",
                "f": f,
                "scale": float(scale),
                "attacker_ids": attacker_order[:f],
                "primary_anchor": f == primary_f and scale == primary_scale,
            }
        )
    if sum(bool(item["primary_anchor"]) for item in plan) != 1:
        raise PrototypeSensitivityError("sensitivity design must have one primary anchor")
    return plan


def _effective_config(
    campaign_config: dict[str, Any],
    *,
    campaign_config_sha256: str,
    scenario: dict[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(campaign_config)
    result.pop("sensitivity", None)
    result["attack"]["scale"] = float(scenario["scale"])
    result["experiment"]["sensitivity"] = {
        "analysis_type": "exploratory-one-factor-at-a-time",
        "campaign_config_sha256": campaign_config_sha256,
        "scenario_id": str(scenario["scenario_id"]),
        "f": int(scenario["f"]),
        "primary_anchor": bool(scenario["primary_anchor"]),
        "test_based_selection_permitted": False,
    }
    return result


def _profile(
    comparison: dict[str, Any], *, condition: str, strategy: str
) -> dict[str, Any]:
    matches = [
        item
        for item in comparison["outcomes"]
        if item["condition"] == condition
        and item["aggregation_strategy"] == strategy
    ]
    if len(matches) != 1:
        raise PrototypeSensitivityError(
            f"comparison lacks one {condition}/{strategy} profile"
        )
    return matches[0]


def _effect(comparison: dict[str, Any], strategy: str) -> dict[str, Any]:
    matches = [
        item
        for item in comparison["attack_effects"]
        if item["aggregation_strategy"] == strategy
    ]
    if len(matches) != 1:
        raise PrototypeSensitivityError(f"comparison lacks one {strategy} effect")
    return matches[0]


def _strategy_record(
    comparison: dict[str, Any], *, strategy: str
) -> dict[str, Any]:
    effect = _effect(comparison, strategy)
    clean = _profile(comparison, condition="clean", strategy=strategy)
    attacked = _profile(comparison, condition="attacked", strategy=strategy)
    clean_integrity = clean["source_class_integrity"]["test"]
    attacked_integrity = attacked["source_class_integrity"]["test"]
    return {
        "aggregation_strategy": strategy,
        "source_prototype_shift_l2": float(effect["source_prototype_shift_l2"]),
        "validation_macro_f1_delta": float(effect["validation_macro_f1_delta"]),
        "test_macro_f1_delta": float(effect["test_macro_f1_delta"]),
        "validation_source_recall_delta": float(
            effect["validation_source_recall_delta"]
        ),
        "test_source_recall_delta": float(effect["test_source_recall_delta"]),
        "test_source_misclassification_rate_delta": float(
            effect["test_source_misclassification_rate_delta"]
        ),
        "test_targeted_attack_success_rate_delta": float(
            effect["test_attack_success_rate_delta"]
        ),
        "clean_test_macro_f1": float(
            clean["metrics"]["test"]["macro_f1_all_model_classes"]
        ),
        "attacked_test_macro_f1": float(
            attacked["metrics"]["test"]["macro_f1_all_model_classes"]
        ),
        "clean_test_source_recall": float(clean_integrity["source_recall"]),
        "attacked_test_source_recall": float(attacked_integrity["source_recall"]),
        "attacked_test_targeted_attack_success_rate": float(
            attacked_integrity["targeted_attack_success_rate"]
        ),
        "attacked_test_other_class_misclassification_rate": float(
            attacked_integrity["other_class_misclassification_rate"]
        ),
    }


def _scenario_record(
    *,
    scenario: dict[str, Any],
    scenario_root: Path,
    output: Path,
    comparison: dict[str, Any],
) -> dict[str, Any]:
    if comparison.get("schema_version") != "1.1":
        raise PrototypeSensitivityError("sensitivity requires comparison schema 1.1")
    relative_root = scenario_root.relative_to(output)
    config_path = scenario_root / "effective-config.yaml"
    frozen_manifest_path = scenario_root / "frozen" / "manifest.json"
    comparison_path = scenario_root / "comparison" / "comparison.json"
    return {
        **scenario,
        "effective_config_path": (relative_root / "effective-config.yaml").as_posix(),
        "effective_config_sha256": sha256_file(config_path),
        "frozen_manifest_path": (relative_root / "frozen" / "manifest.json").as_posix(),
        "frozen_manifest_sha256": sha256_file(frozen_manifest_path),
        "comparison_path": (
            relative_root / "comparison" / "comparison.json"
        ).as_posix(),
        "comparison_sha256": sha256_file(comparison_path),
        "comparison_schema_version": str(comparison["schema_version"]),
        "baseline": _strategy_record(
            comparison, strategy="support_weighted_mean"
        ),
        "robust": _strategy_record(comparison, strategy="coordinate_median"),
    }


def _summary(
    *,
    campaign_config_sha256: str,
    plan: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    primary_ids = [item["scenario_id"] for item in plan if item["primary_anchor"]]
    return {
        "schema_version": "1.0",
        "artifact_type": "m6_prototype_poisoning_sensitivity",
        "analysis_type": "exploratory-one-factor-at-a-time",
        "campaign_config_sha256": campaign_config_sha256,
        "scenario_count": len(records),
        "primary_scenario_id": primary_ids[0],
        "report_every_scenario": True,
        "test_based_selection_permitted": False,
        "selection_performed": False,
        "test_data_accessed": True,
        "scenarios": records,
    }


def _manifest(
    *,
    campaign_config_sha256: str,
    sensitivity_sha256: str,
    scenario_count: int,
    implementation_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_type": "m6_prototype_poisoning_sensitivity_manifest",
        "code_version": __version__,
        "campaign_config_sha256": campaign_config_sha256,
        "sensitivity_path": "sensitivity.json",
        "sensitivity_sha256": sensitivity_sha256,
        "scenario_count": scenario_count,
        "implementation_sha256": implementation_sha256,
        "report_every_scenario": True,
        "test_based_selection_permitted": False,
        "selection_performed": False,
        "test_data_accessed": True,
    }


def plan_prototype_sensitivity(*, config_path: Path) -> dict[str, Any]:
    """Expose the immutable report-all design without accessing experiment data."""

    config, config_digest = load_yaml(config_path)
    plan = _campaign_plan(config)
    primary = next(item for item in plan if item["primary_anchor"])
    return {
        "status": "planned_exploratory_report_all",
        "analysis_type": "exploratory-one-factor-at-a-time",
        "campaign_config_sha256": config_digest,
        "scenario_count": len(plan),
        "primary_scenario_id": primary["scenario_id"],
        "report_every_scenario": True,
        "selection_performed": False,
        "test_based_selection_permitted": False,
        "test_data_accessed": False,
        "scenarios": plan,
    }


def run_prototype_sensitivity(
    *,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Execute and preserve every predeclared one-factor sensitivity cell."""

    config, config_digest = load_yaml(config_path)
    plan = _campaign_plan(config)
    records: list[dict[str, Any]] = []
    for scenario in plan:
        scenario_root = output / "scenarios" / str(scenario["scenario_id"])
        effective_path = scenario_root / "effective-config.yaml"
        effective = _effective_config(
            config,
            campaign_config_sha256=config_digest,
            scenario=scenario,
        )
        write_once(effective_path, derived_json_bytes(effective))
        freeze_prototype_scenario(
            source_round_workspace=source_round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            output=scenario_root / "frozen",
            f=int(scenario["f"]),
            config_path=effective_path,
            attacker_ids=[str(item) for item in scenario["attacker_ids"]],
        )
        run_prototype_comparison(
            frozen_workspace=scenario_root / "frozen",
            partition_workspace=partition_workspace,
            output=scenario_root / "comparison",
            config_path=effective_path,
        )
        comparison = load_json(scenario_root / "comparison" / "comparison.json")
        records.append(
            _scenario_record(
                scenario=scenario,
                scenario_root=scenario_root,
                output=output,
                comparison=comparison,
            )
        )
    summary = _summary(
        campaign_config_sha256=config_digest, plan=plan, records=records
    )
    sensitivity_digest = _write_json(output / "sensitivity.json", summary)
    manifest = _manifest(
        campaign_config_sha256=config_digest,
        sensitivity_sha256=sensitivity_digest,
        scenario_count=len(records),
        implementation_sha256=sha256_file(Path(__file__)),
    )
    manifest_digest = _write_json(output / "manifest.json", manifest)
    return {
        "status": "completed_exploratory_report_all",
        "analysis_type": summary["analysis_type"],
        "scenario_count": len(records),
        "primary_scenario_id": summary["primary_scenario_id"],
        "selection_performed": False,
        "test_data_accessed": True,
        "sensitivity_sha256": sensitivity_digest,
        "manifest_sha256": manifest_digest,
        "workspace": str(output),
    }


def verify_prototype_sensitivity(
    *,
    source_round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Recompute all six scenario families and the report-all campaign summary."""

    errors: list[str] = []
    stored_summary: dict[str, Any] = {}
    stored_manifest: dict[str, Any] = {}
    summary_path = workspace / "sensitivity.json"
    manifest_path = workspace / "manifest.json"
    try:
        config, config_digest = load_yaml(config_path)
        plan = _campaign_plan(config)
        stored_summary = load_json(summary_path)
        stored_manifest = load_json(manifest_path)
        if stored_manifest.get("artifact_type") != (
            "m6_prototype_poisoning_sensitivity_manifest"
        ):
            raise PrototypeSensitivityError("unexpected sensitivity manifest type")
        if stored_manifest.get("campaign_config_sha256") != config_digest:
            raise PrototypeSensitivityError("sensitivity configuration digest mismatch")

        stored_by_id = {
            str(item["scenario_id"]): item
            for item in stored_summary.get("scenarios", [])
        }
        if sorted(stored_by_id) != sorted(str(item["scenario_id"]) for item in plan):
            raise PrototypeSensitivityError("stored sensitivity scenario set mismatch")
        recomputed_records: list[dict[str, Any]] = []
        for scenario in plan:
            scenario_id = str(scenario["scenario_id"])
            scenario_root = workspace / "scenarios" / scenario_id
            effective_path = scenario_root / "effective-config.yaml"
            expected_effective = _effective_config(
                config,
                campaign_config_sha256=config_digest,
                scenario=scenario,
            )
            if (
                not effective_path.is_file()
                or effective_path.read_bytes() != derived_json_bytes(expected_effective)
            ):
                errors.append(f"effective configuration mismatch: {scenario_id}")
                continue
            frozen_verification = verify_frozen_prototype_scenario(
                workspace=scenario_root / "frozen",
                source_round_workspace=source_round_workspace,
                trust_workspace=trust_workspace,
                partition_workspace=partition_workspace,
                config_path=effective_path,
            )
            if frozen_verification["status"] != "verified":
                errors.append(f"frozen scenario verification failed: {scenario_id}")
                continue
            comparison_verification = verify_prototype_comparison(
                frozen_workspace=scenario_root / "frozen",
                partition_workspace=partition_workspace,
                workspace=scenario_root / "comparison",
                config_path=effective_path,
            )
            if comparison_verification["status"] != "verified":
                errors.append(f"comparison verification failed: {scenario_id}")
                continue
            comparison = load_json(
                scenario_root / "comparison" / "comparison.json"
            )
            recomputed_records.append(
                _scenario_record(
                    scenario=scenario,
                    scenario_root=scenario_root,
                    output=workspace,
                    comparison=comparison,
                )
            )
        if not errors:
            recomputed_summary = _summary(
                campaign_config_sha256=config_digest,
                plan=plan,
                records=recomputed_records,
            )
            if derived_json_bytes(recomputed_summary) != derived_json_bytes(
                stored_summary
            ):
                errors.append("sensitivity summary differs from recomputation")
            expected_manifest = _manifest(
                campaign_config_sha256=config_digest,
                sensitivity_sha256=sha256_file(summary_path),
                scenario_count=len(recomputed_records),
                implementation_sha256=sha256_file(Path(__file__)),
            )
            if derived_json_bytes(expected_manifest) != derived_json_bytes(
                stored_manifest
            ):
                errors.append("sensitivity manifest or summary digest mismatch")
    except (KeyError, OSError, PrototypeSensitivityError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "analysis_type": stored_summary.get("analysis_type"),
        "scenario_count": len(stored_summary.get("scenarios", [])),
        "primary_scenario_id": stored_summary.get("primary_scenario_id"),
        "selection_performed": stored_summary.get("selection_performed"),
        "test_data_accessed": stored_summary.get("test_data_accessed"),
        "sensitivity_sha256": sha256_file(summary_path)
        if summary_path.is_file()
        else None,
        "manifest_sha256": sha256_file(manifest_path)
        if manifest_path.is_file()
        else None,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
