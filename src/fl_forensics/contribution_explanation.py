"""Forensic explanations for joint admission and robust aggregation decisions."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import numpy as np

from . import __version__
from . import byzantine as byzantine_module
from . import composite_admission as composite_admission_module
from .byzantine import (
    aggregate_deltas,
    clip_delta_l2,
    flatten_delta,
    model_delta,
    validate_deltas,
)
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file
from .composite_admission_artifact import verify_composite_admission_artifact
from .composite_admission_models import CompositeAdmissionArtifact
from .config import load_yaml
from .contribution_explanation_models import (
    AggregationClientTrace,
    AggregationProfileTrace,
    AggregationTracesPayload,
    ContributionDecisionExplanation,
    ContributionExplanationCore,
    ContributionExplanationGate,
    ContributionExplanationManifest,
    ContributionExplanationSource,
    ContributionExplanationsPayload,
    PolicyDecisionExplanation,
    TensorDeviationDriver,
)
from .federated_model import arrays_from_export
from .preprocessing import derived_json_bytes
from .storage import load_json, write_once

POLICIES = ("tpm_only", "statistics_only", "sequential", "gated_composite")
AGGREGATION_PROFILES = (
    "fedavg",
    "coordinate_median",
    "trimmed_mean",
    "multikrum",
    "bulyan",
)


class ContributionExplanationError(RuntimeError):
    """Raised when contribution explanations cannot be safely reconstructed."""


def _validate_config(config: dict[str, Any]) -> dict[str, Any]:
    if str(config.get("schema_version")) != "1.0":
        raise ContributionExplanationError(
            "unsupported contribution-explanation configuration schema"
        )
    settings = config.get("contribution_explanations")
    if not isinstance(settings, dict):
        raise ContributionExplanationError("missing contribution_explanations settings")
    if settings.get("primary_policy") != "gated_composite":
        raise ContributionExplanationError("primary explanation policy must be gated_composite")
    top_k = int(settings.get("top_tensor_drivers", 0))
    if top_k <= 0:
        raise ContributionExplanationError("top_tensor_drivers must be positive")
    profiles = tuple(str(value) for value in settings.get("aggregation_profiles", []))
    if profiles != AGGREGATION_PROFILES:
        raise ContributionExplanationError(
            "aggregation_profiles must contain the canonical ordered profile set"
        )
    interpretation = settings.get("interpretation", {})
    if (
        interpretation.get("attack_labels_used") is not False
        or interpretation.get("primary_evidence") is not False
        or interpretation.get("hard_trust_veto_is_explainable_not_compensable") is not True
    ):
        raise ContributionExplanationError("invalid contribution interpretation boundary")
    return settings


def _matrix(deltas: list[list[np.ndarray]]) -> np.ndarray:
    normalized = validate_deltas(deltas)
    return np.stack([flatten_delta(delta) for delta in normalized])


def _krum_scores(matrix: np.ndarray, *, f: int) -> np.ndarray:
    n = int(matrix.shape[0])
    if n < 2 * f + 3:
        raise ContributionExplanationError(
            f"Krum trace requires n >= 2f + 3; received n={n}, f={f}"
        )
    differences = matrix[:, None, :] - matrix[None, :, :]
    distances = np.einsum("ijk,ijk->ij", differences, differences)
    neighbor_count = n - f - 2
    scores = np.empty(n, dtype=np.float64)
    for index in range(n):
        others = np.delete(distances[index], index)
        scores[index] = float(
            np.sort(others, kind="stable")[:neighbor_count].sum()
        )
    return scores


def _assert_trace_matches(
    *,
    traced: np.ndarray,
    deltas: list[list[np.ndarray]],
    strategy: str,
    f: int,
    weights: list[int],
) -> None:
    expected = flatten_delta(
        aggregate_deltas(
            deltas,
            strategy=strategy,
            f=f,
            weights=weights if strategy == "fedavg" else None,
        )
    )
    if not np.allclose(traced, expected, rtol=1e-12, atol=1e-12):
        raise ContributionExplanationError(
            f"{strategy} explanation trace does not reproduce the implementation"
        )


def _client_traces(
    *,
    client_ids: list[str],
    matrix: np.ndarray,
    aggregate: np.ndarray | None = None,
    clip_scales: np.ndarray | None = None,
    weight_fractions: np.ndarray | None = None,
    krum_scores: np.ndarray | None = None,
    krum_ranks: np.ndarray | None = None,
    selected: np.ndarray | None = None,
    bulyan_candidates: np.ndarray | None = None,
    retained_counts: np.ndarray | None = None,
) -> list[AggregationClientTrace]:
    coordinate_count = int(matrix.shape[1])
    traces: list[AggregationClientTrace] = []
    for index, client_id in enumerate(client_ids):
        count = int(retained_counts[index]) if retained_counts is not None else None
        traces.append(
            AggregationClientTrace(
                client_id=client_id,
                clip_scale=(
                    float(clip_scales[index]) if clip_scales is not None else None
                ),
                fedavg_weight_fraction=(
                    float(weight_fractions[index])
                    if weight_fractions is not None
                    else None
                ),
                krum_score=(
                    float(krum_scores[index]) if krum_scores is not None else None
                ),
                krum_rank=(
                    int(krum_ranks[index]) if krum_ranks is not None else None
                ),
                selected=(bool(selected[index]) if selected is not None else None),
                bulyan_candidate_selected=(
                    bool(bulyan_candidates[index])
                    if bulyan_candidates is not None
                    else None
                ),
                retained_coordinate_count=count,
                retained_coordinate_fraction=(
                    float(count / coordinate_count) if count is not None else None
                ),
                distance_to_aggregate_l2=(
                    float(np.linalg.norm(matrix[index] - aggregate))
                    if aggregate is not None
                    else None
                ),
            )
        )
    return traces


def trace_aggregation_profiles(
    deltas: list[list[np.ndarray]],
    *,
    client_ids: list[str],
    weights: list[int],
    f: int,
    clip_threshold: float,
    expected_clip_scales: dict[str, float] | None = None,
) -> list[AggregationProfileTrace]:
    """Reconstruct client treatment under every configured M6 aggregator."""

    matrix = _matrix(deltas)
    n, coordinate_count = matrix.shape
    if len(client_ids) != n or len(set(client_ids)) != n:
        raise ContributionExplanationError("client IDs do not align with contribution deltas")
    weights_array = np.asarray(weights, dtype=np.float64)
    if weights_array.shape != (n,) or (weights_array <= 0).any():
        raise ContributionExplanationError("positive FedAvg weights must align with clients")
    if not math.isfinite(clip_threshold) or clip_threshold <= 0:
        raise ContributionExplanationError("clip threshold must be finite and positive")

    clip_scales = np.asarray(
        [clip_delta_l2(delta, max_norm=clip_threshold)[1] for delta in deltas],
        dtype=np.float64,
    )
    if expected_clip_scales is not None:
        if set(expected_clip_scales) != set(client_ids):
            raise ContributionExplanationError("stored clipping scale client set differs")
        expected = np.asarray(
            [float(expected_clip_scales[client_id]) for client_id in client_ids],
            dtype=np.float64,
        )
        if not np.allclose(clip_scales, expected, rtol=0.0, atol=1e-15):
            raise ContributionExplanationError("clipping trace differs from M6 comparison")
    traces = [
        AggregationProfileTrace(
            profile_id="l2_clipping",
            decision_semantics=(
                "scale the complete client delta when its L2 norm exceeds the clean threshold"
            ),
            coordinate_count=int(coordinate_count),
            clients=_client_traces(
                client_ids=client_ids,
                matrix=matrix,
                clip_scales=clip_scales,
            ),
        )
    ]

    weight_fractions = weights_array / weights_array.sum()
    fedavg = np.average(matrix, axis=0, weights=weights_array)
    _assert_trace_matches(
        traced=fedavg,
        deltas=deltas,
        strategy="fedavg",
        f=f,
        weights=weights,
    )
    traces.append(
        AggregationProfileTrace(
            profile_id="fedavg",
            decision_semantics="include every admitted client using its example-count weight",
            coordinate_count=int(coordinate_count),
            selected_client_ids=list(client_ids),
            clients=_client_traces(
                client_ids=client_ids,
                matrix=matrix,
                aggregate=fedavg,
                weight_fractions=weight_fractions,
                selected=np.ones(n, dtype=bool),
            ),
        )
    )

    coordinate_median = np.median(matrix, axis=0)
    _assert_trace_matches(
        traced=coordinate_median,
        deltas=deltas,
        strategy="coordinate_median",
        f=f,
        weights=weights,
    )
    traces.append(
        AggregationProfileTrace(
            profile_id="coordinate_median",
            decision_semantics=(
                "take the median independently per coordinate; no client-level selection"
            ),
            coordinate_count=int(coordinate_count),
            clients=_client_traces(
                client_ids=client_ids,
                matrix=matrix,
                aggregate=coordinate_median,
            ),
        )
    )

    if n <= 2 * f:
        raise ContributionExplanationError("trimmed-mean trace violates n > 2f")
    ordered = np.argsort(matrix, axis=0, kind="stable")
    retained = ordered[f : n - f] if f else ordered
    trimmed = np.take_along_axis(matrix, retained, axis=0).mean(axis=0)
    trimmed_counts = np.asarray(
        [(retained == index).sum() for index in range(n)], dtype=np.int64
    )
    _assert_trace_matches(
        traced=trimmed,
        deltas=deltas,
        strategy="trimmed_mean",
        f=f,
        weights=weights,
    )
    traces.append(
        AggregationProfileTrace(
            profile_id="trimmed_mean",
            decision_semantics=(
                "discard the f lowest and f highest clients independently per coordinate"
            ),
            coordinate_count=int(coordinate_count),
            clients=_client_traces(
                client_ids=client_ids,
                matrix=matrix,
                aggregate=trimmed,
                retained_counts=trimmed_counts,
            ),
        )
    )

    scores = _krum_scores(matrix, f=f)
    score_order = np.lexsort((np.arange(n), scores))
    ranks = np.empty(n, dtype=np.int64)
    ranks[score_order] = np.arange(1, n + 1)
    selected_count = n - f - 2
    selected_indices = score_order[:selected_count]
    selected_flags = np.zeros(n, dtype=bool)
    selected_flags[selected_indices] = True
    multikrum = matrix[selected_indices].mean(axis=0)
    _assert_trace_matches(
        traced=multikrum,
        deltas=deltas,
        strategy="multikrum",
        f=f,
        weights=weights,
    )
    traces.append(
        AggregationProfileTrace(
            profile_id="multikrum",
            decision_semantics=(
                "select n-f-2 clients with the smallest deterministic Krum neighbor score"
            ),
            coordinate_count=int(coordinate_count),
            selected_client_ids=[client_ids[index] for index in selected_indices],
            clients=_client_traces(
                client_ids=client_ids,
                matrix=matrix,
                aggregate=multikrum,
                krum_scores=scores,
                krum_ranks=ranks,
                selected=selected_flags,
            ),
        )
    )

    if n < 4 * f + 3:
        raise ContributionExplanationError("Bulyan trace violates n >= 4f + 3")
    candidate_count = n - 2 * f
    candidate_indices = score_order[:candidate_count]
    candidate_flags = np.zeros(n, dtype=bool)
    candidate_flags[candidate_indices] = True
    candidates = matrix[candidate_indices]
    candidate_median = np.median(candidates, axis=0)
    retained_count = candidate_count - 2 * f
    closest = np.argsort(
        np.abs(candidates - candidate_median), axis=0, kind="stable"
    )[:retained_count]
    retained_original = candidate_indices[closest]
    bulyan_counts = np.asarray(
        [(retained_original == index).sum() for index in range(n)], dtype=np.int64
    )
    bulyan = np.take_along_axis(candidates, closest, axis=0).mean(axis=0)
    _assert_trace_matches(
        traced=bulyan,
        deltas=deltas,
        strategy="bulyan",
        f=f,
        weights=weights,
    )
    traces.append(
        AggregationProfileTrace(
            profile_id="bulyan",
            decision_semantics=(
                "select n-2f Krum-ranked candidates, then retain n-4f closest values per coordinate"
            ),
            coordinate_count=int(coordinate_count),
            selected_client_ids=[client_ids[index] for index in candidate_indices],
            clients=_client_traces(
                client_ids=client_ids,
                matrix=matrix,
                aggregate=bulyan,
                krum_scores=scores,
                krum_ranks=ranks,
                selected=candidate_flags,
                bulyan_candidates=candidate_flags,
                retained_counts=bulyan_counts,
            ),
        )
    )
    return traces


def tensor_deviation_drivers(
    deltas: list[list[np.ndarray]],
    *,
    client_ids: list[str],
    tensor_names: list[str],
    top_k: int,
) -> dict[str, list[TensorDeviationDriver]]:
    """Rank named tensors by squared distance from the candidate coordinate median."""

    normalized = validate_deltas(deltas)
    if len(normalized) != len(client_ids) or len(set(client_ids)) != len(client_ids):
        raise ContributionExplanationError("tensor driver clients do not align")
    if len(tensor_names) != len(normalized[0]) or len(set(tensor_names)) != len(
        tensor_names
    ):
        raise ContributionExplanationError("tensor names do not align or are duplicate")
    if top_k <= 0:
        raise ContributionExplanationError("top_k must be positive")
    population_medians = [
        np.median(
            np.stack([delta[index] for delta in normalized]).astype(np.float64),
            axis=0,
        )
        for index in range(len(tensor_names))
    ]
    population_mads = [
        np.median(
            np.abs(
                np.stack([delta[index] for delta in normalized]).astype(np.float64)
                - population_medians[index]
            ),
            axis=0,
        )
        for index in range(len(tensor_names))
    ]
    result: dict[str, list[TensorDeviationDriver]] = {}
    for client_id, delta in zip(client_ids, normalized, strict=True):
        squared_distances = [
            float(
                np.square(
                    value.astype(np.float64) - population_medians[index]
                ).sum()
            )
            for index, value in enumerate(delta)
        ]
        total = sum(squared_distances)
        drivers: list[TensorDeviationDriver] = []
        for index, (name, value) in enumerate(zip(tensor_names, delta, strict=True)):
            numeric = value.astype(np.float64)
            distance = math.sqrt(squared_distances[index])
            standardized = np.abs(numeric - population_medians[index]) / np.maximum(
                population_mads[index], 1e-12
            )
            drivers.append(
                TensorDeviationDriver(
                    tensor_name=name,
                    parameter_count=int(numeric.size),
                    update_l2=float(np.linalg.norm(numeric)),
                    median_distance_l2=distance,
                    squared_median_distance_fraction=(
                        float(squared_distances[index] / total) if total > 0 else 0.0
                    ),
                    median_absolute_standardized_deviation=float(
                        np.median(standardized)
                    ),
                )
            )
        drivers.sort(
            key=lambda item: (-item.squared_median_distance_fraction, item.tensor_name)
        )
        result[client_id] = drivers[: min(top_k, len(drivers))]
    return result


def _safe_relative_file(root: Path, relative_value: Any, *, label: str) -> Path:
    relative = Path(str(relative_value))
    if relative.is_absolute() or ".." in relative.parts:
        raise ContributionExplanationError(f"unsafe {label} path")
    path = root / relative
    if not path.is_file():
        raise ContributionExplanationError(f"missing {label}")
    return path


def _validated_inputs(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    clean_frozen_workspace: Path,
    clean_comparison_workspace: Path,
    candidate_frozen_workspace: Path,
    candidate_comparison_workspace: Path,
    admission_workspace: Path,
    config_path: Path,
    composite_config_path: Path,
    byzantine_config_path: Path,
) -> dict[str, Any]:
    admission_verification = verify_composite_admission_artifact(
        round_workspace=round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        clean_frozen_workspace=clean_frozen_workspace,
        clean_comparison_workspace=clean_comparison_workspace,
        candidate_frozen_workspace=candidate_frozen_workspace,
        candidate_comparison_workspace=candidate_comparison_workspace,
        workspace=admission_workspace,
        config_path=composite_config_path,
        byzantine_config_path=byzantine_config_path,
    )
    if admission_verification.get("status") != "verified":
        raise ContributionExplanationError(
            "source joint-admission artifact does not verify: "
            f"{admission_verification.get('errors', [])}"
        )
    admission_path = admission_workspace / "admission.json"
    admission = CompositeAdmissionArtifact.model_validate(load_json(admission_path))
    manifest_path = candidate_frozen_workspace / "manifest.json"
    comparison_path = candidate_comparison_workspace / "comparison.json"
    if sha256_file(manifest_path) != admission.candidate_frozen_manifest_sha256:
        raise ContributionExplanationError("candidate frozen manifest binding differs")
    if sha256_file(comparison_path) != admission.candidate_comparison_sha256:
        raise ContributionExplanationError("candidate comparison binding differs")
    manifest = load_json(manifest_path)
    comparison = load_json(comparison_path)
    config, config_digest = load_yaml(config_path)
    settings = _validate_config(config)

    base_path = candidate_frozen_workspace / "base-model.json"
    if sha256_file(base_path) != str(manifest.get("base_model_sha256")):
        raise ContributionExplanationError("candidate base-model digest mismatch")
    base = load_json(base_path)
    base_arrays = arrays_from_export(base, np=np)
    tensor_names = [str(item.get("name", "")) for item in base.get("parameters", [])]
    if len(tensor_names) != len(base_arrays) or any(not name for name in tensor_names):
        raise ContributionExplanationError("base-model tensor names do not align")

    client_ids = [record.client_id for record in admission.clients]
    manifest_records = manifest.get("clients", [])
    if [str(item.get("client_id")) for item in manifest_records] != client_ids:
        raise ContributionExplanationError("admission and frozen client orders differ")
    deltas: list[list[np.ndarray]] = []
    weights: list[int] = []
    for record, admission_record in zip(
        manifest_records, admission.clients, strict=True
    ):
        update_path = _safe_relative_file(
            candidate_frozen_workspace,
            record.get("frozen_update_path"),
            label=f"{admission_record.client_id} frozen update",
        )
        digest = sha256_file(update_path)
        if (
            digest != str(record.get("frozen_update_sha256"))
            or digest != admission_record.candidate_update_sha256
        ):
            raise ContributionExplanationError(
                f"frozen update digest differs: {admission_record.client_id}"
            )
        update_arrays = arrays_from_export(load_json(update_path), np=np)
        deltas.append(model_delta(base_arrays, update_arrays))
        weights.append(int(record.get("num_examples", 0)))
    if any(weight <= 0 for weight in weights):
        raise ContributionExplanationError("frozen example counts must be positive")
    return {
        "admission": admission,
        "admission_path": admission_path,
        "manifest_path": manifest_path,
        "comparison_path": comparison_path,
        "comparison": comparison,
        "settings": settings,
        "config_digest": config_digest,
        "deltas": deltas,
        "weights": weights,
        "client_ids": client_ids,
        "tensor_names": tensor_names,
    }


def _policy_explanations(
    record: Any,
    *,
    downweight_threshold: float,
) -> list[PolicyDecisionExplanation]:
    explanations: list[PolicyDecisionExplanation] = []
    for decision in record.decisions:
        threshold = decision.threshold
        is_composite = decision.policy == "gated_composite"
        hard_veto = (
            not record.trust.admissible
            and decision.policy in {"tpm_only", "sequential", "gated_composite"}
        )
        explanations.append(
            PolicyDecisionExplanation(
                policy=decision.policy,
                status=decision.status,
                contributes=decision.contributes,
                score=decision.score,
                quarantine_threshold=threshold,
                signed_margin_to_quarantine=(
                    float(threshold - decision.score)
                    if threshold is not None
                    else None
                ),
                downweight_threshold=(downweight_threshold if is_composite else None),
                signed_margin_to_downweight=(
                    float(downweight_threshold - decision.score)
                    if is_composite
                    else None
                ),
                hard_trust_veto_applied=hard_veto,
                reasons=list(decision.reasons),
            )
        )
    if [item.policy for item in explanations] != list(POLICIES):
        raise ContributionExplanationError("admission policy order is not canonical")
    return explanations


def _contribution_explanations(
    inputs: dict[str, Any],
) -> ContributionExplanationsPayload:
    admission: CompositeAdmissionArtifact = inputs["admission"]
    tensor_drivers = tensor_deviation_drivers(
        inputs["deltas"],
        client_ids=inputs["client_ids"],
        tensor_names=inputs["tensor_names"],
        top_k=int(inputs["settings"]["top_tensor_drivers"]),
    )
    explanations: list[ContributionDecisionExplanation] = []
    for record in admission.clients:
        ranked = sorted(
            record.statistics.components,
            key=lambda item: (-item.weighted_contribution, item.name),
        )
        policies = _policy_explanations(
            record,
            downweight_threshold=admission.thresholds.composite_downweight_threshold,
        )
        primary = next(item for item in policies if item.policy == "gated_composite")
        dominant_indicator = (
            ranked[0].name if ranked and ranked[0].weighted_contribution > 0 else "none"
        )
        dominant_tensor = (
            tensor_drivers[record.client_id][0].tensor_name
            if tensor_drivers[record.client_id]
            else "none"
        )
        summary = (
            f"{primary.status}: trust_admissible={str(record.trust.admissible).lower()}; "
            f"statistical_risk={record.statistics.risk:.6f}; "
            f"dominant_indicator={dominant_indicator}; "
            f"dominant_tensor={dominant_tensor}; "
            f"signed_quarantine_margin={primary.signed_margin_to_quarantine:.6f}"
        )
        explanations.append(
            ContributionDecisionExplanation(
                client_id=record.client_id,
                candidate_update_sha256=record.candidate_update_sha256,
                source_bundle_sha256=record.source_bundle_sha256,
                trust=record.trust,
                statistical_risk=record.statistics.risk,
                statistical_quarantine_threshold=(
                    admission.thresholds.statistical_threshold
                ),
                statistical_signed_margin_to_quarantine=float(
                    admission.thresholds.statistical_threshold
                    - record.statistics.risk
                ),
                primary_status=primary.status,
                ranked_statistical_components=ranked,
                policy_explanations=policies,
                top_tensor_drivers=tensor_drivers[record.client_id],
                summary=summary,
            )
        )
    return ContributionExplanationsPayload(explanations=explanations)


def _aggregation_traces(inputs: dict[str, Any]) -> AggregationTracesPayload:
    comparison = inputs["comparison"]
    profiles = trace_aggregation_profiles(
        inputs["deltas"],
        client_ids=inputs["client_ids"],
        weights=inputs["weights"],
        f=int(comparison["f"]),
        clip_threshold=float(comparison["clip_threshold"]["max_norm"]),
        expected_clip_scales={
            str(key): float(value) for key, value in comparison["clip_scales"].items()
        },
    )
    return AggregationTracesPayload(profiles=profiles)


def _compute_bundle(**source_arguments: Any) -> tuple[
    ContributionExplanationsPayload,
    AggregationTracesPayload,
    ContributionExplanationManifest,
]:
    inputs = _validated_inputs(**source_arguments)
    explanations = _contribution_explanations(inputs)
    traces = _aggregation_traces(inputs)
    explanations_bytes = derived_json_bytes(explanations.model_dump(mode="json"))
    traces_bytes = derived_json_bytes(traces.model_dump(mode="json"))
    admission: CompositeAdmissionArtifact = inputs["admission"]
    implementation_files = {
        "byzantine": Path(str(byzantine_module.__file__)),
        "composite_admission": Path(str(composite_admission_module.__file__)),
        "contribution_explanation": Path(__file__),
        "contribution_explanation_models": Path(__file__).with_name(
            "contribution_explanation_models.py"
        ),
    }
    core = ContributionExplanationCore(
        code_version=__version__,
        implementation_sha256={
            name: sha256_file(path) for name, path in implementation_files.items()
        },
        explanation_config_sha256=inputs["config_digest"],
        composite_config_sha256=admission.composite_config_sha256,
        byzantine_config_sha256=admission.byzantine_config_sha256,
        source=ContributionExplanationSource(
            experiment_id=admission.experiment_id,
            campaign_id=admission.campaign_id,
            round_number=admission.round_number,
            candidate_attack=admission.candidate_attack,
            admission_sha256=sha256_file(inputs["admission_path"]),
            candidate_frozen_manifest_sha256=sha256_file(inputs["manifest_path"]),
            candidate_comparison_sha256=sha256_file(inputs["comparison_path"]),
            source_round_context_sha256=admission.source_round_context_sha256,
            partition_manifest_sha256=admission.partition_manifest_sha256,
        ),
        explanations_sha256=sha256_bytes(explanations_bytes),
        aggregation_traces_sha256=sha256_bytes(traces_bytes),
        gate=ContributionExplanationGate(
            explanation_count=len(explanations.explanations),
            aggregation_profile_count=len(traces.profiles),
        ),
    )
    core_sha256 = sha256_bytes(canonical_json_bytes(core.model_dump(mode="json")))
    manifest = ContributionExplanationManifest(
        explanation_bundle_id=f"m6-contribution-explanations-{core_sha256[:24]}",
        core=core,
        canonical_core_sha256=core_sha256,
    )
    return explanations, traces, manifest


def create_contribution_explanation_bundle(
    *,
    output: Path,
    **source_arguments: Any,
) -> dict[str, Any]:
    """Create an immutable contribution-decision explanation bundle."""

    explanations, traces, manifest = _compute_bundle(**source_arguments)
    explanation_path = output / "explanations.json"
    traces_path = output / "aggregation-traces.json"
    manifest_path = output / "manifest.json"
    write_once(
        explanation_path,
        derived_json_bytes(explanations.model_dump(mode="json")),
    )
    write_once(traces_path, derived_json_bytes(traces.model_dump(mode="json")))
    write_once(manifest_path, derived_json_bytes(manifest.model_dump(mode="json")))
    return {
        "status": "explained_verified_source",
        "explanation_bundle_id": manifest.explanation_bundle_id,
        "campaign_id": manifest.core.source.campaign_id,
        "round_number": manifest.core.source.round_number,
        "candidate_attack": manifest.core.source.candidate_attack,
        "explanation_count": len(explanations.explanations),
        "aggregation_profile_count": len(traces.profiles),
        "manifest_sha256": sha256_file(manifest_path),
        "reportable": manifest.core.gate.reportable,
        "workspace": str(output),
    }


def verify_contribution_explanation_bundle(
    *,
    workspace: Path,
    **source_arguments: Any,
) -> dict[str, Any]:
    """Recompute explanations and every aggregation trace from frozen inputs."""

    errors: list[str] = []
    explanation_path = workspace / "explanations.json"
    traces_path = workspace / "aggregation-traces.json"
    manifest_path = workspace / "manifest.json"
    missing = [
        path.name
        for path in (explanation_path, traces_path, manifest_path)
        if not path.is_file()
    ]
    if missing:
        return {
            "status": "failed",
            "error_count": 1,
            "errors": [f"missing contribution explanation files: {', '.join(missing)}"],
            "workspace": str(workspace),
        }
    stored_manifest: ContributionExplanationManifest | None = None
    try:
        stored_explanations = ContributionExplanationsPayload.model_validate(
            load_json(explanation_path)
        )
        stored_traces = AggregationTracesPayload.model_validate(load_json(traces_path))
        stored_manifest = ContributionExplanationManifest.model_validate(
            load_json(manifest_path)
        )
        explanations, traces, manifest = _compute_bundle(**source_arguments)
        if derived_json_bytes(
            stored_explanations.model_dump(mode="json")
        ) != derived_json_bytes(explanations.model_dump(mode="json")):
            errors.append("stored contribution explanations differ from recomputation")
        if derived_json_bytes(stored_traces.model_dump(mode="json")) != derived_json_bytes(
            traces.model_dump(mode="json")
        ):
            errors.append("stored aggregation traces differ from recomputation")
        if derived_json_bytes(stored_manifest.model_dump(mode="json")) != derived_json_bytes(
            manifest.model_dump(mode="json")
        ):
            errors.append("stored contribution explanation manifest differs from recomputation")
    except (ContributionExplanationError, KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "explanation_bundle_id": (
            stored_manifest.explanation_bundle_id
            if stored_manifest is not None
            else None
        ),
        "campaign_id": (
            stored_manifest.core.source.campaign_id
            if stored_manifest is not None
            else None
        ),
        "round_number": (
            stored_manifest.core.source.round_number
            if stored_manifest is not None
            else None
        ),
        "explanation_count": (
            stored_manifest.core.gate.explanation_count
            if stored_manifest is not None
            else 0
        ),
        "aggregation_profile_count": (
            stored_manifest.core.gate.aggregation_profile_count
            if stored_manifest is not None
            else 0
        ),
        "source_admission_recomputed": not errors,
        "update_tensor_explanations_recomputed": not errors,
        "aggregation_traces_recomputed": not errors,
        "implementation_binding_verified": not errors,
        "manifest_sha256": sha256_file(manifest_path),
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
