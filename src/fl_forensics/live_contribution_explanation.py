"""Independently verifiable explanations for decisions made during live M6 training."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from . import __version__
from . import contribution_explanation as contribution_explanation_module
from . import disagreement_experiment as disagreement_experiment_module
from . import in_round_admission as in_round_admission_module
from . import live_contribution_explanation_models as explanation_models_module
from .byzantine import flatten_delta, model_delta
from .canonical import digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .contribution_explanation import tensor_deviation_drivers
from .disagreement_experiment import (
    load_bound_disagreement_contract,
    verify_disagreement_round,
)
from .federated_model import arrays_from_export
from .in_round_admission_models import (
    InRoundAdmissionContract,
    InRoundContributionDecision,
    InRoundSecureCheckpoint,
)
from .live_contribution_explanation_models import (
    LiveAggregationTreatment,
    LiveClientExplanationIndex,
    LiveContributionDecisionExplanation,
    LiveContributionExplanationCore,
    LiveContributionExplanationGate,
    LiveContributionExplanationIndex,
    LiveContributionExplanationManifest,
    LiveContributionExplanationSource,
    LiveContributionExplanationsPayload,
    LiveDecisionCounterfactual,
    LivePolicyDecisionExplanation,
    LiveRoundExplanationIndex,
)
from .preprocessing import derived_json_bytes
from .secure_campaign import verify_secure_campaign
from .secure_round_models import SecureCampaignManifest, UpdateBundle
from .storage import load_json, write_once

POLICIES = ("tpm_only", "statistics_only", "sequential", "gated_composite")
STATUSES = (
    "accepted",
    "accepted_downweighted",
    "trust_quarantined",
    "statistically_quarantined",
)


class LiveContributionExplanationError(RuntimeError):
    """Raised when a live training-decision explanation cannot be reconstructed."""


def _settings(config_path: Path) -> tuple[dict[str, Any], str]:
    config, config_sha256 = load_yaml(config_path)
    if config.get("schema_version") != "1.0":
        raise LiveContributionExplanationError("unsupported live-explanation schema")
    experiment = config.get("experiment")
    settings = config.get("live_contribution_explanations")
    if not isinstance(experiment, dict) or not isinstance(settings, dict):
        raise LiveContributionExplanationError("live-explanation settings are missing")
    interpretation = settings.get("interpretation")
    if (
        settings.get("primary_policy") != "gated_composite"
        or not settings.get("require_complete_disagreement_verification")
        or not isinstance(interpretation, dict)
        or interpretation.get("attack_labels_used") is not False
        or interpretation.get("test_data_used") is not False
        or interpretation.get("hard_trust_veto_is_explainable_not_compensable")
        is not True
    ):
        raise LiveContributionExplanationError("unsafe live-explanation policy")
    normalized = {
        "bundle_experiment_id": str(experiment.get("id", "")),
        "expected_source_experiment_id": str(
            experiment.get("expected_source_experiment_id", "")
        ),
        "expected_round_count": int(settings.get("expected_round_count", 0)),
        "expected_client_count": int(settings.get("expected_client_count", 0)),
        "top_tensor_drivers": int(settings.get("top_tensor_drivers", 0)),
    }
    if (
        not normalized["bundle_experiment_id"]
        or not normalized["expected_source_experiment_id"]
        or normalized["expected_round_count"] <= 0
        or normalized["expected_client_count"] <= 0
        or normalized["top_tensor_drivers"] <= 0
    ):
        raise LiveContributionExplanationError("invalid live-explanation dimensions")
    return normalized, config_sha256


def _inventory_digest(root: Path, paths: list[Path]) -> str:
    records = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in sorted(paths)
    ]
    return digest_object(records)


def _policy_explanations(
    decision: InRoundContributionDecision,
    *,
    downweight_threshold: float,
) -> list[LivePolicyDecisionExplanation]:
    result: list[LivePolicyDecisionExplanation] = []
    for policy in decision.core.policy_decisions:
        is_composite = policy.policy == "gated_composite"
        threshold = policy.threshold
        result.append(
            LivePolicyDecisionExplanation(
                policy=policy.policy,
                status=policy.status,
                contributes=policy.contributes,
                score=policy.score,
                quarantine_threshold=threshold,
                signed_margin_to_quarantine=(
                    float(threshold - policy.score) if threshold is not None else None
                ),
                downweight_threshold=(downweight_threshold if is_composite else None),
                signed_margin_to_downweight=(
                    float(downweight_threshold - policy.score)
                    if is_composite
                    else None
                ),
                hard_trust_veto_applied=(
                    not decision.core.trust.admissible
                    and policy.policy in {"tpm_only", "sequential", "gated_composite"}
                ),
                reasons=list(policy.reasons),
            )
        )
    if [item.policy for item in result] != list(POLICIES):
        raise LiveContributionExplanationError(
            f"non-canonical policy set: {decision.core.client_id}"
        )
    return result


def _counterfactual(
    decision: InRoundContributionDecision,
    *,
    composite_score: float,
    downweight_threshold: float,
    quarantine_threshold: float,
    trust_weight: float,
) -> LiveDecisionCounterfactual:
    fixed = ["peer updates", "calibration reference", "aggregation policy"]
    if not decision.core.trust.admissible:
        return LiveDecisionCounterfactual(
            trust_remediation_required=True,
            fixed_context=fixed,
            interpretation=(
                "The hard trust gate must first receive admissible fresh evidence; no "
                "statistical-score reduction can compensate for an inadmissible trust signal."
            ),
        )
    statistical_fraction = 1.0 - trust_weight
    if statistical_fraction <= 0.0:
        raise LiveContributionExplanationError("statistical composite weight is zero")
    nonzero = max(0.0, composite_score - quarantine_threshold)
    full = max(0.0, composite_score - downweight_threshold)
    return LiveDecisionCounterfactual(
        trust_remediation_required=False,
        composite_reduction_for_nonzero_weight=nonzero,
        composite_reduction_for_full_weight=full,
        statistical_reduction_for_nonzero_weight=nonzero / statistical_fraction,
        statistical_reduction_for_full_weight=full / statistical_fraction,
        fixed_context=["trust signal", *fixed],
        interpretation=(
            "This is an exact score-level threshold counterfactual; it does not prescribe "
            "one unique tensor or indicator change."
        ),
    )


def _narrative(
    decision: InRoundContributionDecision,
    *,
    composite_score: float,
    downweight_threshold: float,
    quarantine_threshold: float,
    ranked_components: list[Any],
    tensor_drivers: list[Any],
    treatment: LiveAggregationTreatment,
    risk_rank: int,
    peer_count: int,
    counterfactual: LiveDecisionCounterfactual,
) -> list[str]:
    if decision.core.trust.admissible:
        trust_text = (
            "The effective trust gate was admissible and all bound M5 trust checks passed."
        )
    else:
        trust_text = (
            "The bound disagreement contract made the effective trust signal inadmissible; "
            "the preserved observed swtpm appraisal remains separate and passed."
        )
    scalar = ", ".join(
        f"{item.name}={item.weighted_contribution:.6f}"
        for item in ranked_components[:3]
    )
    tensors = ", ".join(
        f"{item.tensor_name}={item.squared_median_distance_fraction:.3%}"
        for item in tensor_drivers
    )
    policies = ", ".join(
        f"{item.policy}={item.status}" for item in decision.core.policy_decisions
    )
    return [
        trust_text,
        (
            f"The live gated-composite decision was {decision.core.final_status} with score "
            f"{composite_score:.6f}; full-weight and quarantine thresholds were "
            f"{downweight_threshold:.6f} and {quarantine_threshold:.6f}."
        ),
        f"Leading statistical-risk contributions: {scalar}.",
        f"Leading named tensor deviations from the round median: {tensors}.",
        (
            f"The statistical risk ranked {risk_rank} of {peer_count} in this round; "
            f"policy outcomes: {policies}."
        ),
        (
            f"FedAvg retained {treatment.retained_weight_fraction:.2%} of nominal weight; "
            f"actual leave-one-out influence was {treatment.admitted_aggregate_influence_l2:.9f} "
            "L2 and restoring full weight would shift the aggregate by "
            f"{treatment.full_weight_counterfactual_aggregate_shift_l2:.9f} L2."
        ),
        counterfactual.interpretation,
        (
            "This explains the configured training-decision mechanism and update geometry. "
            "It does not prove malicious intent and uses neither test data nor attack labels."
        ),
    ]


def _index(
    explanations: list[LiveContributionDecisionExplanation],
) -> LiveContributionExplanationIndex:
    by_round: dict[int, list[LiveContributionDecisionExplanation]] = defaultdict(list)
    by_client: dict[str, list[LiveContributionDecisionExplanation]] = defaultdict(list)
    for item in explanations:
        by_round[item.round_number].append(item)
        by_client[item.client_id].append(item)

    def counts(items: list[LiveContributionDecisionExplanation]) -> Counter[str]:
        return Counter(item.final_status for item in items)

    def risks(items: list[LiveContributionDecisionExplanation]) -> list[float]:
        values = [item.statistical_risk for item in items]
        if any(value is None for value in values):
            raise LiveContributionExplanationError("verified disagreement risk is missing")
        return [float(value) for value in values if value is not None]

    rounds: list[LiveRoundExplanationIndex] = []
    for round_number, items in sorted(by_round.items()):
        status = counts(items)
        values = risks(items)
        rounds.append(
            LiveRoundExplanationIndex(
                round_number=round_number,
                explanation_count=len(items),
                accepted_count=status["accepted"],
                downweighted_count=status["accepted_downweighted"],
                trust_quarantined_count=status["trust_quarantined"],
                statistically_quarantined_count=status["statistically_quarantined"],
                mean_statistical_risk=sum(values) / len(values),
                maximum_statistical_risk=max(values),
            )
        )
    clients: list[LiveClientExplanationIndex] = []
    for client_id, items in sorted(by_client.items()):
        status = counts(items)
        values = risks(items)
        clients.append(
            LiveClientExplanationIndex(
                client_id=client_id,
                explanation_count=len(items),
                accepted_count=status["accepted"],
                downweighted_count=status["accepted_downweighted"],
                trust_quarantined_count=status["trust_quarantined"],
                statistically_quarantined_count=status["statistically_quarantined"],
                mean_statistical_risk=sum(values) / len(values),
                maximum_statistical_risk=max(values),
            )
        )
    return LiveContributionExplanationIndex(rounds=rounds, clients=clients)


def _compute_bundle(
    *,
    campaign_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    config_path: Path,
) -> tuple[
    LiveContributionExplanationsPayload,
    LiveContributionExplanationIndex,
    LiveContributionExplanationManifest,
]:
    settings, config_sha256 = _settings(config_path)
    partition_manifest_path = partition_workspace / "manifest.json"
    validation_split_path = (
        partition_workspace / "server" / "splits" / "validation.json"
    )
    server_evaluation_path = partition_workspace / "server" / "evaluation.json"
    verification = verify_secure_campaign(
        workspace=campaign_workspace,
        trust_workspace=trust_workspace,
        partition_manifest_path=partition_manifest_path,
        server_evaluation_path=server_evaluation_path,
    )
    if verification.get("status") != "verified":
        raise LiveContributionExplanationError(
            f"source campaign does not verify: {verification.get('errors', [])}"
        )
    manifest_path = campaign_workspace / "campaign-manifest.json"
    selected_evaluation_path = (
        campaign_workspace / "evaluation" / "selected-checkpoint-evaluation.json"
    )
    campaign = SecureCampaignManifest.model_validate(load_json(manifest_path))
    if (
        campaign.core.round_count != settings["expected_round_count"]
        or campaign.core.required_client_count != settings["expected_client_count"]
    ):
        raise LiveContributionExplanationError("source campaign dimensions differ")

    decision_paths: list[Path] = []
    update_paths: list[Path] = []
    checkpoint_paths: list[Path] = []
    contract_paths: list[Path] = []
    explanations: list[LiveContributionDecisionExplanation] = []
    prior: dict[str, Counter[str]] = defaultdict(Counter)
    source_experiment_id: str | None = None

    for round_number in range(1, campaign.core.round_count + 1):
        round_root = campaign_workspace / "rounds" / f"round-{round_number:03d}"
        round_verification = verify_disagreement_round(
            workspace=round_root,
            trust_workspace=trust_workspace,
            submissions_root=round_root / "submissions",
            validation_split_path=validation_split_path,
            verify_base=False,
        )
        if round_verification.get("status") != "verified":
            raise LiveContributionExplanationError(
                f"round {round_number} disagreement evidence does not verify: "
                f"{round_verification.get('errors', [])}"
            )
        contract = load_bound_disagreement_contract(round_root / "public")
        if contract is None:
            raise LiveContributionExplanationError("source disagreement contract is missing")
        if source_experiment_id is None:
            source_experiment_id = contract.core.experiment_id
        if contract.core.experiment_id != source_experiment_id:
            raise LiveContributionExplanationError("source experiment changed across rounds")
        contract_path = round_root / "public" / "m6-disagreement-contract.json"
        contract_paths.append(contract_path)

        admission_contract = InRoundAdmissionContract.model_validate(
            load_json(round_root / "public" / "in-round-admission-contract.json")
        )
        thresholds = admission_contract.core.thresholds
        base_path = round_root / "public" / "base-model.json"
        base_export = load_json(base_path)
        base_arrays = arrays_from_export(base_export, np=np)
        tensor_names = [str(item.get("name", "")) for item in base_export["parameters"]]
        if len(tensor_names) != len(base_arrays) or any(not name for name in tensor_names):
            raise LiveContributionExplanationError("source tensor names do not align")

        paths = sorted((round_root / "in-round-decisions").glob("client*.json"))
        if len(paths) != campaign.core.required_client_count:
            raise LiveContributionExplanationError(
                f"round {round_number} explanation coverage is incomplete"
            )
        decisions = [
            InRoundContributionDecision.model_validate(load_json(path)) for path in paths
        ]
        if [item.core.client_id for item in decisions] != sorted(
            item.core.client_id for item in decisions
        ):
            raise LiveContributionExplanationError("source decision order is not canonical")
        if any(item.core.final_status not in STATUSES for item in decisions):
            raise LiveContributionExplanationError(
                "source disagreement decision has an unsupported status"
            )
        decision_paths.extend(paths)

        deltas: list[list[np.ndarray]] = []
        bundles: list[UpdateBundle] = []
        for decision in decisions:
            submission = round_root / "submissions" / decision.core.client_id
            update_path = submission / "update.json"
            bundle_path = submission / "bundle.json"
            bundle = UpdateBundle.model_validate(load_json(bundle_path))
            if (
                decision.core.update_sha256 is None
                or sha256_file(update_path) != decision.core.update_sha256
                or bundle.core.update_sha256 != decision.core.update_sha256
                or sha256_file(bundle_path) != decision.core.bundle_sha256
                or bundle.bundle_id != decision.core.bundle_id
                or bundle.core.base_model_sha256 != sha256_file(base_path)
            ):
                raise LiveContributionExplanationError(
                    f"round {round_number} {decision.core.client_id} source binding differs"
                )
            update_paths.append(update_path)
            bundles.append(bundle)
            deltas.append(
                model_delta(
                    base_arrays,
                    arrays_from_export(load_json(update_path), np=np),
                )
            )

        tensor_drivers = tensor_deviation_drivers(
            deltas,
            client_ids=[item.core.client_id for item in decisions],
            tensor_names=tensor_names,
            top_k=settings["top_tensor_drivers"],
        )
        matrix = np.stack([flatten_delta(delta) for delta in deltas])
        effective_weights = np.asarray(
            [float(item.core.effective_weight_decimal) for item in decisions],
            dtype=np.float64,
        )
        nominal_weights = np.asarray(
            [float(item.core.num_examples) for item in decisions], dtype=np.float64
        )
        total_weight = float(effective_weights.sum())
        if (
            total_weight <= 0.0
            or (effective_weights < 0.0).any()
            or (effective_weights > nominal_weights).any()
        ):
            raise LiveContributionExplanationError("effective FedAvg weights are invalid")
        weighted_sum = np.einsum("i,ij->j", effective_weights, matrix)
        aggregate = weighted_sum / total_weight
        aggregate_norm = float(np.linalg.norm(aggregate))

        checkpoint_path = round_root / "checkpoint" / "manifest.json"
        checkpoint_paths.append(checkpoint_path)
        checkpoint = InRoundSecureCheckpoint.model_validate(load_json(checkpoint_path))
        checkpoint_clients = {item.client_id for item in checkpoint.core.accepted_inputs}
        global_delta = flatten_delta(
            model_delta(
                base_arrays,
                arrays_from_export(
                    load_json(round_root / "checkpoint" / "global-model.json"), np=np
                ),
            )
        )
        if not np.allclose(aggregate, global_delta, rtol=1e-5, atol=1e-6):
            raise LiveContributionExplanationError(
                f"round {round_number} explanation aggregate differs from checkpoint"
            )

        risk_order = sorted(
            decisions,
            key=lambda item: (
                -float(item.core.statistics.risk if item.core.statistics else -1.0),
                item.core.client_id,
            ),
        )
        risk_ranks = {
            item.core.client_id: rank for rank, item in enumerate(risk_order, start=1)
        }
        for index, (decision, bundle) in enumerate(zip(decisions, bundles, strict=True)):
            if decision.core.statistics is None or decision.core.primary_decision is None:
                raise LiveContributionExplanationError(
                    "verified disagreement decision lacks statistical policy evidence"
                )
            client_id = decision.core.client_id
            effective = float(effective_weights[index])
            nominal = float(nominal_weights[index])
            included = client_id in checkpoint_clients
            if included != (effective > 0.0):
                raise LiveContributionExplanationError(
                    f"round {round_number} {client_id} checkpoint treatment differs"
                )
            delta = matrix[index]
            delta_norm = float(np.linalg.norm(delta))
            remaining_weight = total_weight - effective
            if effective > 0.0 and remaining_weight > 0.0:
                aggregate_without = (
                    weighted_sum - effective * delta
                ) / remaining_weight
                admitted_influence = float(np.linalg.norm(aggregate - aggregate_without))
            else:
                admitted_influence = 0.0
            full_total = total_weight - effective + nominal
            full_aggregate = (
                weighted_sum - effective * delta + nominal * delta
            ) / full_total
            full_shift = float(np.linalg.norm(full_aggregate - aggregate))
            cosine = 0.0
            if delta_norm > 0.0 and aggregate_norm > 0.0:
                cosine = float(np.dot(delta, aggregate) / (delta_norm * aggregate_norm))
            treatment = LiveAggregationTreatment(
                nominal_weight_decimal=str(decision.core.num_examples),
                effective_weight_decimal=decision.core.effective_weight_decimal,
                retained_weight_fraction=effective / nominal,
                included_in_checkpoint=included,
                update_l2=delta_norm,
                cosine_to_effective_aggregate=max(-1.0, min(1.0, cosine)),
                admitted_aggregate_influence_l2=admitted_influence,
                full_weight_counterfactual_aggregate_shift_l2=full_shift,
            )
            ranked = sorted(
                decision.core.statistics.components,
                key=lambda item: (-item.weighted_contribution, item.name),
            )
            primary = decision.core.primary_decision
            counterfactual = _counterfactual(
                decision,
                composite_score=primary.score,
                downweight_threshold=thresholds.composite_downweight_threshold,
                quarantine_threshold=thresholds.composite_threshold,
                trust_weight=thresholds.trust_weight,
            )
            validation_component = next(
                item
                for item in decision.core.statistics.components
                if item.name == "validation_impact"
            )
            source_decision_path = paths[index]
            explanations.append(
                LiveContributionDecisionExplanation(
                    round_number=round_number,
                    client_id=client_id,
                    source_decision_id=decision.decision_id,
                    source_decision_sha256=sha256_file(source_decision_path),
                    source_bundle_id=bundle.bundle_id,
                    source_bundle_sha256=decision.core.bundle_sha256,
                    source_update_sha256=decision.core.update_sha256,
                    final_status=decision.core.final_status,
                    m5_checks=list(decision.core.m5_checks),
                    trust=decision.core.trust,
                    statistical_risk=decision.core.statistics.risk,
                    statistical_quarantine_threshold=thresholds.statistical_threshold,
                    composite_score=primary.score,
                    composite_downweight_threshold=(
                        thresholds.composite_downweight_threshold
                    ),
                    composite_quarantine_threshold=thresholds.composite_threshold,
                    signed_headroom_to_quarantine=(
                        thresholds.composite_threshold - primary.score
                    ),
                    signed_headroom_to_full_acceptance=(
                        thresholds.composite_downweight_threshold - primary.score
                    ),
                    policy_explanations=_policy_explanations(
                        decision,
                        downweight_threshold=(
                            thresholds.composite_downweight_threshold
                        ),
                    ),
                    ranked_statistical_components=ranked,
                    top_tensor_drivers=tensor_drivers[client_id],
                    statistical_risk_rank_in_round=risk_ranks[client_id],
                    peer_count=len(decisions),
                    prior_downweight_count=prior[client_id]["accepted_downweighted"],
                    prior_quarantine_count=(
                        prior[client_id]["trust_quarantined"]
                        + prior[client_id]["statistically_quarantined"]
                    ),
                    aggregation_treatment=treatment,
                    counterfactual=counterfactual,
                    validation_base_minus_client_macro_f1=validation_component.raw_value,
                    narrative=_narrative(
                        decision,
                        composite_score=primary.score,
                        downweight_threshold=(
                            thresholds.composite_downweight_threshold
                        ),
                        quarantine_threshold=thresholds.composite_threshold,
                        ranked_components=ranked,
                        tensor_drivers=tensor_drivers[client_id],
                        treatment=treatment,
                        risk_rank=risk_ranks[client_id],
                        peer_count=len(decisions),
                        counterfactual=counterfactual,
                    ),
                )
            )
            prior[client_id][decision.core.final_status] += 1

    if source_experiment_id != settings["expected_source_experiment_id"]:
        raise LiveContributionExplanationError("unexpected source disagreement experiment")
    expected_count = settings["expected_round_count"] * settings["expected_client_count"]
    if len(explanations) != expected_count:
        raise LiveContributionExplanationError("live explanation coverage is incomplete")
    payload = LiveContributionExplanationsPayload(explanations=explanations)
    index = _index(explanations)
    payload_bytes = derived_json_bytes(payload.model_dump(mode="json"))
    index_bytes = derived_json_bytes(index.model_dump(mode="json"))
    status_counts = Counter(item.final_status for item in explanations)
    implementation_files = {
        "contribution_explanation": Path(
            str(contribution_explanation_module.__file__)
        ),
        "disagreement_experiment": Path(str(disagreement_experiment_module.__file__)),
        "in_round_admission": Path(str(in_round_admission_module.__file__)),
        "live_contribution_explanation": Path(__file__),
        "live_contribution_explanation_models": Path(
            str(explanation_models_module.__file__)
        ),
    }
    core = LiveContributionExplanationCore(
        experiment_id=settings["bundle_experiment_id"],
        code_version=__version__,
        implementation_sha256={
            name: sha256_file(path) for name, path in implementation_files.items()
        },
        explanation_config_sha256=config_sha256,
        source=LiveContributionExplanationSource(
            experiment_id=source_experiment_id,
            campaign_id=campaign.core.campaign_id,
            round_count=campaign.core.round_count,
            client_count=campaign.core.required_client_count,
            campaign_manifest_sha256=sha256_file(manifest_path),
            selected_evaluation_sha256=sha256_file(selected_evaluation_path),
            partition_manifest_sha256=sha256_file(partition_manifest_path),
            server_evaluation_sha256=sha256_file(server_evaluation_path),
            decision_inventory_sha256=_inventory_digest(
                campaign_workspace, decision_paths
            ),
            update_inventory_sha256=_inventory_digest(
                campaign_workspace, update_paths
            ),
            checkpoint_inventory_sha256=_inventory_digest(
                campaign_workspace, checkpoint_paths
            ),
            disagreement_contract_inventory_sha256=_inventory_digest(
                campaign_workspace, contract_paths
            ),
        ),
        explanations_sha256=sha256_bytes(payload_bytes),
        index_sha256=sha256_bytes(index_bytes),
        gate=LiveContributionExplanationGate(
            explanation_count=len(explanations),
            round_count=campaign.core.round_count,
            client_count=campaign.core.required_client_count,
            accepted_count=status_counts["accepted"],
            downweighted_count=status_counts["accepted_downweighted"],
            trust_quarantined_count=status_counts["trust_quarantined"],
            statistically_quarantined_count=status_counts[
                "statistically_quarantined"
            ],
        ),
    )
    core_sha256 = digest_object(core.model_dump(mode="json"))
    manifest = LiveContributionExplanationManifest(
        explanation_bundle_id=f"m6-live-contribution-explanations-{core_sha256[:24]}",
        core=core,
        canonical_core_sha256=core_sha256,
    )
    return payload, index, manifest


def create_live_contribution_explanation_bundle(
    *, output: Path, **source_arguments: Any
) -> dict[str, Any]:
    """Create an immutable explanation bundle from decisions made during training."""

    payload, index, manifest = _compute_bundle(**source_arguments)
    explanations_path = output / "explanations.json"
    index_path = output / "index.json"
    manifest_path = output / "manifest.json"
    write_once(explanations_path, derived_json_bytes(payload.model_dump(mode="json")))
    write_once(index_path, derived_json_bytes(index.model_dump(mode="json")))
    write_once(manifest_path, derived_json_bytes(manifest.model_dump(mode="json")))
    return {
        "status": "explained_verified_live_source",
        "explanation_bundle_id": manifest.explanation_bundle_id,
        "campaign_id": manifest.core.source.campaign_id,
        "round_count": manifest.core.gate.round_count,
        "client_count": manifest.core.gate.client_count,
        "explanation_count": manifest.core.gate.explanation_count,
        "accepted_count": manifest.core.gate.accepted_count,
        "downweighted_count": manifest.core.gate.downweighted_count,
        "trust_quarantined_count": manifest.core.gate.trust_quarantined_count,
        "statistically_quarantined_count": (
            manifest.core.gate.statistically_quarantined_count
        ),
        "manifest_sha256": sha256_file(manifest_path),
        "reportable": manifest.core.gate.reportable,
        "workspace": str(output),
    }


def verify_live_contribution_explanation_bundle(
    *, workspace: Path, **source_arguments: Any
) -> dict[str, Any]:
    """Recompute every explanation, index row, source binding, and manifest."""

    errors: list[str] = []
    explanations_path = workspace / "explanations.json"
    index_path = workspace / "index.json"
    manifest_path = workspace / "manifest.json"
    missing = [
        path.name
        for path in (explanations_path, index_path, manifest_path)
        if not path.is_file()
    ]
    if missing:
        return {
            "status": "failed",
            "error_count": 1,
            "errors": [f"missing live explanation files: {', '.join(missing)}"],
            "workspace": str(workspace),
        }
    stored_manifest: LiveContributionExplanationManifest | None = None
    try:
        stored_payload = LiveContributionExplanationsPayload.model_validate(
            load_json(explanations_path)
        )
        stored_index = LiveContributionExplanationIndex.model_validate(
            load_json(index_path)
        )
        stored_manifest = LiveContributionExplanationManifest.model_validate(
            load_json(manifest_path)
        )
        payload, index, manifest = _compute_bundle(**source_arguments)
        comparisons = {
            "stored live explanations differ from recomputation": (
                derived_json_bytes(stored_payload.model_dump(mode="json")),
                derived_json_bytes(payload.model_dump(mode="json")),
            ),
            "stored live explanation index differs from recomputation": (
                derived_json_bytes(stored_index.model_dump(mode="json")),
                derived_json_bytes(index.model_dump(mode="json")),
            ),
            "stored live explanation manifest differs from recomputation": (
                derived_json_bytes(stored_manifest.model_dump(mode="json")),
                derived_json_bytes(manifest.model_dump(mode="json")),
            ),
        }
        for message, (observed, expected) in comparisons.items():
            if observed != expected:
                errors.append(message)
    except (
        FileNotFoundError,
        KeyError,
        LiveContributionExplanationError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
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
        "round_count": (
            stored_manifest.core.gate.round_count
            if stored_manifest is not None
            else 0
        ),
        "explanation_count": (
            stored_manifest.core.gate.explanation_count
            if stored_manifest is not None
            else 0
        ),
        "source_campaign_reverified": not errors,
        "source_disagreement_rounds_reverified": not errors,
        "decision_mechanics_recomputed": not errors,
        "update_tensor_drivers_recomputed": not errors,
        "aggregation_treatments_recomputed": not errors,
        "implementation_binding_verified": not errors,
        "manifest_sha256": sha256_file(manifest_path),
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
