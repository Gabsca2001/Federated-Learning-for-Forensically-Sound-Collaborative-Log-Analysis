"""Deterministic joint admission primitives for M4/M5 trust and M6 statistics.

The module deliberately keeps the two signals independent.  TPM-only and
statistics-only are ablation baselines; sequential and gated-composite are the
integrated policies.  Cryptographic/structural prerequisites remain outside
this policy layer and must already have passed before these functions are used.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

from .composite_admission_models import (
    AdmissionPolicyDecision,
    IndicatorContribution,
    IndicatorDirection,
    IndicatorReference,
    PolicyThresholds,
    StatisticalSignal,
    TrustSignal,
)

TRUST_CHECK_NAMES = (
    "active_enrollment",
    "tpm_esk_signature",
    "fresh_attestation",
)


class CompositeAdmissionError(ValueError):
    """Raised when admission inputs or policy parameters are invalid."""


def _finite(value: Any, *, description: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CompositeAdmissionError(f"{description} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise CompositeAdmissionError(f"{description} must be finite")
    return result


def build_indicator_references(
    clean_indicators: Sequence[Mapping[str, Any]],
    *,
    directions: Mapping[str, IndicatorDirection],
) -> dict[str, IndicatorReference]:
    """Build median/MAD references from a clean calibration population."""

    if not clean_indicators:
        raise CompositeAdmissionError("clean calibration indicators are empty")
    if not directions:
        raise CompositeAdmissionError("at least one indicator direction is required")
    client_ids = [str(item.get("client_id", "")) for item in clean_indicators]
    if any(not client_id for client_id in client_ids) or len(set(client_ids)) != len(
        client_ids
    ):
        raise CompositeAdmissionError(
            "clean calibration client_id values must be present and unique"
        )
    references: dict[str, IndicatorReference] = {}
    for name in sorted(directions):
        direction = directions[name]
        if direction not in {"higher", "lower"}:
            raise CompositeAdmissionError(f"unsupported direction for {name}: {direction}")
        values = np.asarray(
            [
                _finite(item.get(name), description=f"clean indicator {name}")
                for item in clean_indicators
            ],
            dtype=np.float64,
        )
        median = float(np.median(values))
        mad = float(np.median(np.abs(values - median)))
        references[name] = IndicatorReference(
            name=name,
            direction=direction,
            median=median,
            mad=mad,
            sample_count=len(clean_indicators),
        )
    return references


def score_statistical_indicators(
    indicators: Sequence[Mapping[str, Any]],
    *,
    references: Mapping[str, IndicatorReference],
    weights: Mapping[str, float],
    z_cap: float = 3.0,
) -> dict[str, StatisticalSignal]:
    """Score client updates against an immutable clean median/MAD reference."""

    if not indicators:
        raise CompositeAdmissionError("candidate indicators are empty")
    cap = _finite(z_cap, description="z_cap")
    if cap <= 0.0:
        raise CompositeAdmissionError("z_cap must be positive")
    if set(references) != set(weights):
        raise CompositeAdmissionError(
            "indicator weights must match the clean reference names exactly"
        )
    numeric_weights = {
        name: _finite(value, description=f"weight {name}")
        for name, value in weights.items()
    }
    if any(value <= 0.0 for value in numeric_weights.values()):
        raise CompositeAdmissionError("indicator weights must be positive")
    weight_sum = sum(numeric_weights.values())
    normalized_weights = {
        name: value / weight_sum for name, value in numeric_weights.items()
    }
    client_ids = [str(item.get("client_id", "")) for item in indicators]
    if any(not client_id for client_id in client_ids) or len(set(client_ids)) != len(
        client_ids
    ):
        raise CompositeAdmissionError("candidate client_id values must be present and unique")

    signals: dict[str, StatisticalSignal] = {}
    for item, client_id in zip(indicators, client_ids, strict=True):
        components: list[IndicatorContribution] = []
        for name in sorted(references):
            reference = references[name]
            raw = _finite(item.get(name), description=f"{client_id} indicator {name}")
            signed_deviation = (
                raw - reference.median
                if reference.direction == "higher"
                else reference.median - raw
            )
            adverse_deviation = max(0.0, signed_deviation)
            robust_scale = 1.4826 * reference.mad
            if adverse_deviation == 0.0:
                robust_z = 0.0
                component_risk = 0.0
            elif robust_scale <= 1e-12:
                robust_z = cap
                component_risk = 1.0
            else:
                robust_z = adverse_deviation / robust_scale
                component_risk = min(robust_z / cap, 1.0)
            normalized_weight = normalized_weights[name]
            components.append(
                IndicatorContribution(
                    name=name,
                    direction=reference.direction,
                    raw_value=raw,
                    reference_median=reference.median,
                    reference_mad=reference.mad,
                    adverse_deviation=adverse_deviation,
                    robust_z=robust_z,
                    component_risk=component_risk,
                    normalized_weight=normalized_weight,
                    weighted_contribution=component_risk * normalized_weight,
                )
            )
        risk = min(sum(component.weighted_contribution for component in components), 1.0)
        signals[client_id] = StatisticalSignal(
            client_id=client_id,
            risk=risk,
            components=components,
        )
    return signals


def trust_signal_from_checks(
    checks: Sequence[Mapping[str, Any]],
    *,
    raw_status: str,
    passed_with_warning_risk: float = 0.25,
) -> TrustSignal:
    """Extract the M4/M5 trust signal without mixing statistical evidence."""

    warning_risk = _finite(
        passed_with_warning_risk, description="passed_with_warning_risk"
    )
    if not 0.0 <= warning_risk <= 1.0:
        raise CompositeAdmissionError("passed_with_warning_risk must be within [0, 1]")
    by_name: dict[str, Mapping[str, Any]] = {}
    for check in checks:
        name = str(check.get("name", ""))
        if not name or name in by_name:
            raise CompositeAdmissionError("trust check names must be present and unique")
        by_name[name] = check
    missing = [name for name in TRUST_CHECK_NAMES if name not in by_name]
    if missing:
        raise CompositeAdmissionError(
            f"required trust checks are missing: {', '.join(missing)}"
        )
    failed = [
        name for name in TRUST_CHECK_NAMES if by_name[name].get("passed") is not True
    ]
    reasons = [str(by_name[name].get("detail", "")) for name in failed]
    admissible = not failed and raw_status in {"passed", "passed_with_warning"}
    if not admissible:
        risk = 1.0
        if not reasons:
            reasons = [f"attestation status is not admissible: {raw_status}"]
    elif raw_status == "passed_with_warning":
        risk = warning_risk
        reasons = ["attestation passed with warning"]
    else:
        risk = 0.0
    return TrustSignal(
        raw_status=raw_status,
        admissible=admissible,
        risk=risk,
        evaluated_checks=list(TRUST_CHECK_NAMES),
        failed_checks=failed,
        reasons=reasons,
    )


def apply_controlled_trust_failure(
    trust: TrustSignal,
    *,
    failed_check: str,
    reason: str,
) -> TrustSignal:
    """Create an explicit counterfactual trust failure for policy comparison.

    The returned signal is evaluation-only. It does not alter or replace the
    verified M4 attestation referenced by the source M5 contribution.
    """

    if not trust.admissible:
        raise CompositeAdmissionError(
            "controlled trust failure requires an observed admissible signal"
        )
    if failed_check not in trust.evaluated_checks:
        raise CompositeAdmissionError(
            f"controlled failed check is not evaluated: {failed_check}"
        )
    detail = str(reason).strip()
    if not detail:
        raise CompositeAdmissionError("controlled trust failure reason is empty")
    return TrustSignal(
        raw_status="controlled_failed_measurement",
        admissible=False,
        risk=1.0,
        evaluated_checks=list(trust.evaluated_checks),
        failed_checks=[failed_check],
        reasons=[detail],
    )


def calibrate_policy_thresholds(
    clean_statistics: Sequence[StatisticalSignal],
    *,
    trust_weight: float,
    statistical_margin: float,
    composite_margin: float,
    downweight_quantile: float,
) -> PolicyThresholds:
    """Calibrate policy thresholds without observing candidate attack labels."""

    if not clean_statistics:
        raise CompositeAdmissionError("clean statistical signals are empty")
    client_ids = [item.client_id for item in clean_statistics]
    if len(set(client_ids)) != len(client_ids):
        raise CompositeAdmissionError("clean statistical signal clients must be unique")
    trust_fraction = _finite(trust_weight, description="trust_weight")
    stat_margin = _finite(statistical_margin, description="statistical_margin")
    joint_margin = _finite(composite_margin, description="composite_margin")
    quantile = _finite(downweight_quantile, description="downweight_quantile")
    for name, value in (
        ("trust_weight", trust_fraction),
        ("statistical_margin", stat_margin),
        ("composite_margin", joint_margin),
        ("downweight_quantile", quantile),
    ):
        if not 0.0 <= value <= 1.0:
            raise CompositeAdmissionError(f"{name} must be within [0, 1]")
    clean_risks = np.asarray(
        [
            _finite(item.risk, description=f"clean risk {item.client_id}")
            for item in clean_statistics
        ],
        dtype=np.float64,
    )
    statistical_threshold = min(1.0, float(clean_risks.max()) + stat_margin)
    clean_composite = (1.0 - trust_fraction) * clean_risks
    composite_threshold = min(1.0, float(clean_composite.max()) + joint_margin)
    downweight_threshold = float(
        np.quantile(clean_composite, quantile, method="linear")
    )
    return PolicyThresholds(
        clean_sample_count=len(clean_statistics),
        statistical_threshold=statistical_threshold,
        composite_downweight_threshold=min(
            downweight_threshold, composite_threshold
        ),
        composite_threshold=composite_threshold,
        trust_weight=trust_fraction,
    )


def decide_admission_policies(
    *,
    trust: TrustSignal,
    statistics: StatisticalSignal,
    statistical_threshold: float,
    composite_threshold: float,
    composite_downweight_threshold: float,
    trust_weight: float,
) -> list[AdmissionPolicyDecision]:
    """Apply two ablation baselines and two integrated policies."""

    stat_threshold = _finite(statistical_threshold, description="statistical_threshold")
    composite_limit = _finite(composite_threshold, description="composite_threshold")
    downweight_limit = _finite(
        composite_downweight_threshold,
        description="composite_downweight_threshold",
    )
    trust_fraction = _finite(trust_weight, description="trust_weight")
    for name, value in (
        ("statistical_threshold", stat_threshold),
        ("composite_threshold", composite_limit),
        ("composite_downweight_threshold", downweight_limit),
        ("trust_weight", trust_fraction),
    ):
        if not 0.0 <= value <= 1.0:
            raise CompositeAdmissionError(f"{name} must be within [0, 1]")
    if downweight_limit > composite_limit:
        raise CompositeAdmissionError(
            "composite_downweight_threshold cannot exceed composite_threshold"
        )

    statistical_failed = statistics.risk > stat_threshold
    tpm_decision = AdmissionPolicyDecision(
        policy="tpm_only",
        status="accepted" if trust.admissible else "trust_quarantined",
        contributes=trust.admissible,
        score=trust.risk,
        threshold=None,
        reasons=["TPM/M5 trust signal is admissible"]
        if trust.admissible
        else trust.reasons,
    )
    statistics_decision = AdmissionPolicyDecision(
        policy="statistics_only",
        status="statistically_quarantined" if statistical_failed else "accepted",
        contributes=not statistical_failed,
        score=statistics.risk,
        threshold=stat_threshold,
        reasons=[
            "statistical risk exceeds the configured threshold"
            if statistical_failed
            else "statistical risk is within the configured threshold"
        ],
    )
    if not trust.admissible:
        sequential_status = "trust_quarantined"
        sequential_reasons = trust.reasons
    elif statistical_failed:
        sequential_status = "statistically_quarantined"
        sequential_reasons = ["statistical risk exceeds the configured threshold"]
    else:
        sequential_status = "accepted"
        sequential_reasons = ["trust and statistical gates both passed"]
    sequential = AdmissionPolicyDecision(
        policy="sequential",
        status=sequential_status,
        contributes=sequential_status == "accepted",
        score=statistics.risk,
        threshold=stat_threshold,
        reasons=sequential_reasons,
    )

    composite_risk = trust_fraction * trust.risk + (
        1.0 - trust_fraction
    ) * statistics.risk
    if not trust.admissible:
        composite_status = "trust_quarantined"
        composite_reasons = [
            *trust.reasons,
            "the hard trust veto cannot be compensated by statistical normality",
        ]
    elif composite_risk > composite_limit:
        composite_status = "statistically_quarantined"
        composite_reasons = ["gated composite risk exceeds the quarantine threshold"]
    elif composite_risk > downweight_limit:
        composite_status = "accepted_downweighted"
        composite_reasons = ["gated composite risk exceeds the downweight threshold"]
    else:
        composite_status = "accepted"
        composite_reasons = ["gated composite risk is within the acceptance threshold"]
    gated_composite = AdmissionPolicyDecision(
        policy="gated_composite",
        status=composite_status,
        contributes=composite_status in {"accepted", "accepted_downweighted"},
        score=composite_risk,
        threshold=composite_limit,
        reasons=composite_reasons,
    )
    return [tpm_decision, statistics_decision, sequential, gated_composite]
