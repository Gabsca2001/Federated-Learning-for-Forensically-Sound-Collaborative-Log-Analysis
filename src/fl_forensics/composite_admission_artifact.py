"""Create and independently verify a digest-linked joint-admission pilot."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .byzantine_experiment import (
    verify_byzantine_comparison,
    verify_frozen_update_set,
)
from .canonical import sha256_file
from .composite_admission import (
    CompositeAdmissionError,
    apply_controlled_trust_failure,
    build_indicator_references,
    calibrate_policy_thresholds,
    decide_admission_policies,
    score_statistical_indicators,
    trust_signal_from_checks,
)
from .composite_admission_models import (
    CompositeAdmissionArtifact,
    CompositeAdmissionClientRecord,
    ControlledDisagreementCase,
    ControlledMatrixSelection,
    PolicyEvaluation,
    PolicyThresholds,
)
from .config import load_yaml
from .preprocessing import derived_json_bytes
from .secure_round import verify_secure_round
from .secure_round_models import (
    ContributionDecision,
    SecureRoundContext,
    UpdateBundle,
)
from .storage import load_json, write_once
from .trust_models import AttestationResultV2

BINDING_SEMANTICS = (
    "controlled M6 derivation from verified M5 identities; attacked candidate bytes "
    "are not covered by the original M5 bundle signatures"
)
POLICIES = ("tpm_only", "statistics_only", "sequential", "gated_composite")


class CompositeAdmissionArtifactError(RuntimeError):
    """Raised when joint-admission sources or lineage do not verify."""


def _require_verified(result: dict[str, Any], *, description: str) -> None:
    if result.get("status") != "verified":
        errors = result.get("errors", [])
        raise CompositeAdmissionArtifactError(
            f"{description} does not verify: {errors}"
        )


def _validate_sources(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    clean_frozen_workspace: Path,
    clean_comparison_workspace: Path,
    candidate_frozen_workspace: Path,
    candidate_comparison_workspace: Path,
    byzantine_config_path: Path,
) -> None:
    _require_verified(
        verify_secure_round(
            workspace=round_workspace,
            trust_workspace=trust_workspace,
            submissions_root=round_workspace / "submissions",
        ),
        description="source M5 round",
    )
    _require_verified(
        verify_frozen_update_set(workspace=clean_frozen_workspace),
        description="clean M6 frozen update set",
    )
    _require_verified(
        verify_byzantine_comparison(
            frozen_workspace=clean_frozen_workspace,
            partition_workspace=partition_workspace,
            workspace=clean_comparison_workspace,
            config_path=byzantine_config_path,
        ),
        description="clean M6 comparison",
    )
    _require_verified(
        verify_frozen_update_set(workspace=candidate_frozen_workspace),
        description="candidate M6 frozen update set",
    )
    _require_verified(
        verify_byzantine_comparison(
            frozen_workspace=candidate_frozen_workspace,
            partition_workspace=partition_workspace,
            workspace=candidate_comparison_workspace,
            config_path=byzantine_config_path,
        ),
        description="candidate M6 comparison",
    )


def _policy_evaluation(
    records: list[CompositeAdmissionClientRecord],
) -> dict[str, PolicyEvaluation]:
    evaluations: dict[str, PolicyEvaluation] = {}
    for policy in POLICIES:
        tp = fp = tn = fn = 0
        for record in records:
            decision = next(item for item in record.decisions if item.policy == policy)
            actual_positive = record.evaluation_label == "anomalous"
            predicted_positive = not decision.contributes
            if actual_positive and predicted_positive:
                tp += 1
            elif not actual_positive and predicted_positive:
                fp += 1
            elif not actual_positive and not predicted_positive:
                tn += 1
            else:
                fn += 1
        evaluations[policy] = PolicyEvaluation(
            true_positive=tp,
            false_positive=fp,
            true_negative=tn,
            false_negative=fn,
        )
    return evaluations


def _controlled_policy_evaluation(
    cases: list[ControlledDisagreementCase],
) -> dict[str, PolicyEvaluation]:
    evaluations: dict[str, PolicyEvaluation] = {}
    for policy in POLICIES:
        tp = fp = tn = fn = 0
        for case in cases:
            decision = next(item for item in case.decisions if item.policy == policy)
            actual_positive = case.security_label == "unsafe"
            predicted_positive = not decision.contributes
            if actual_positive and predicted_positive:
                tp += 1
            elif not actual_positive and predicted_positive:
                fp += 1
            elif not actual_positive and not predicted_positive:
                tn += 1
            else:
                fn += 1
        evaluations[policy] = PolicyEvaluation(
            true_positive=tp,
            false_positive=fp,
            true_negative=tn,
            false_negative=fn,
        )
    return evaluations


def _controlled_disagreement_matrix(
    *,
    records: list[CompositeAdmissionClientRecord],
    attacker_ids: list[str],
    config: dict[str, Any],
    thresholds: PolicyThresholds,
) -> tuple[ControlledMatrixSelection, list[ControlledDisagreementCase]]:
    settings = config.get("disagreement_matrix")
    if not isinstance(settings, dict):
        raise CompositeAdmissionArtifactError(
            "disagreement_matrix configuration is required"
        )
    normal_client_id = str(settings.get("normal_client_id", ""))
    anomalous_client_id = str(settings.get("anomalous_client_id", ""))
    failed_check = str(settings.get("controlled_failed_check", ""))
    by_client = {record.client_id: record for record in records}
    if normal_client_id not in by_client or anomalous_client_id not in by_client:
        raise CompositeAdmissionArtifactError(
            "controlled disagreement source client is not present"
        )
    if normal_client_id in attacker_ids or anomalous_client_id not in attacker_ids:
        raise CompositeAdmissionArtifactError(
            "controlled disagreement clients do not match normal/anomalous labels"
        )
    normal = by_client[normal_client_id]
    anomalous = by_client[anomalous_client_id]
    cases: list[ControlledDisagreementCase] = []
    for source, statistical_condition in (
        (normal, "normal"),
        (anomalous, "anomalous"),
    ):
        if not source.trust.admissible:
            raise CompositeAdmissionArtifactError(
                "observed matrix source trust must be admissible"
            )
        for trust_condition in ("admissible", "inadmissible"):
            intervened = trust_condition == "inadmissible"
            trust = (
                apply_controlled_trust_failure(
                    source.trust,
                    failed_check=failed_check,
                    reason=(
                        "controlled counterfactual failure for the joint-policy "
                        "disagreement matrix; the source M4 attestation remains unchanged"
                    ),
                )
                if intervened
                else source.trust
            )
            decisions = decide_admission_policies(
                trust=trust,
                statistics=source.statistics,
                statistical_threshold=thresholds.statistical_threshold,
                composite_threshold=thresholds.composite_threshold,
                composite_downweight_threshold=(
                    thresholds.composite_downweight_threshold
                ),
                trust_weight=thresholds.trust_weight,
            )
            condition = f"trust_{trust_condition}_statistics_{statistical_condition}"
            cases.append(
                ControlledDisagreementCase(
                    case_id=f"controlled-{condition}",
                    source_client_id=source.client_id,
                    condition=condition,
                    trust_intervention=(
                        "controlled_failed_check" if intervened else "none"
                    ),
                    evidence_semantics=(
                        "verified M6 statistics with a controlled counterfactual "
                        "M4/M5 trust failure"
                        if intervened
                        else "observed verified M4/M5 trust with verified M6 statistics"
                    ),
                    security_label=(
                        "safe"
                        if trust.admissible and statistical_condition == "normal"
                        else "unsafe"
                    ),
                    trust=trust,
                    statistics=source.statistics,
                    decisions=decisions,
                )
            )
    selection = ControlledMatrixSelection(
        normal_client_id=normal_client_id,
        anomalous_client_id=anomalous_client_id,
        controlled_failed_check=failed_check,
    )
    return selection, cases


def _compute_artifact(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    clean_frozen_workspace: Path,
    clean_comparison_workspace: Path,
    candidate_frozen_workspace: Path,
    candidate_comparison_workspace: Path,
    config_path: Path,
    byzantine_config_path: Path,
) -> CompositeAdmissionArtifact:
    _validate_sources(
        round_workspace=round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        clean_frozen_workspace=clean_frozen_workspace,
        clean_comparison_workspace=clean_comparison_workspace,
        candidate_frozen_workspace=candidate_frozen_workspace,
        candidate_comparison_workspace=candidate_comparison_workspace,
        byzantine_config_path=byzantine_config_path,
    )
    config, config_digest = load_yaml(config_path)
    _byzantine_config, byzantine_config_digest = load_yaml(byzantine_config_path)
    if str(config.get("schema_version")) != "1.0":
        raise CompositeAdmissionArtifactError(
            "unsupported composite-admission configuration schema"
        )

    context_path = round_workspace / "public" / "round-context.json"
    checkpoint_path = round_workspace / "checkpoint" / "manifest.json"
    partition_manifest_path = round_workspace / "public" / "partition-manifest.json"
    context = SecureRoundContext.model_validate(load_json(context_path))
    clean_manifest_path = clean_frozen_workspace / "manifest.json"
    candidate_manifest_path = candidate_frozen_workspace / "manifest.json"
    clean_comparison_path = clean_comparison_workspace / "comparison.json"
    candidate_comparison_path = candidate_comparison_workspace / "comparison.json"
    clean_manifest = load_json(clean_manifest_path)
    candidate_manifest = load_json(candidate_manifest_path)
    clean_comparison = load_json(clean_comparison_path)
    candidate_comparison = load_json(candidate_comparison_path)

    context_sha256 = sha256_file(context_path)
    checkpoint_sha256 = sha256_file(checkpoint_path)
    partition_sha256 = sha256_file(partition_manifest_path)
    for name, manifest in (
        ("clean", clean_manifest),
        ("candidate", candidate_manifest),
    ):
        if manifest.get("source_round_context_sha256") != context_sha256:
            raise CompositeAdmissionArtifactError(
                f"{name} M6 source round context differs from the selected M5 round"
            )
        if manifest.get("source_round_checkpoint_sha256") != checkpoint_sha256:
            raise CompositeAdmissionArtifactError(
                f"{name} M6 source checkpoint differs from the selected M5 round"
            )
        if manifest.get("partition_manifest_sha256") != partition_sha256:
            raise CompositeAdmissionArtifactError(
                f"{name} M6 partition differs from the selected M5 round"
            )
        if manifest.get("byzantine_config_sha256") != byzantine_config_digest:
            raise CompositeAdmissionArtifactError(
                f"{name} M6 configuration binding mismatch"
            )
    if clean_manifest.get("attack") != "clean" or int(clean_manifest.get("f", -1)) != 0:
        raise CompositeAdmissionArtifactError(
            "calibration population must be an explicit clean f=0 M6 scenario"
        )
    if clean_manifest.get("attacker_ids"):
        raise CompositeAdmissionArtifactError("clean calibration contains attacker labels")
    if candidate_manifest.get("attack") == "clean":
        raise CompositeAdmissionArtifactError(
            "candidate population must contain one declared M6 attack"
        )
    if clean_comparison.get("frozen_manifest_sha256") != sha256_file(
        clean_manifest_path
    ):
        raise CompositeAdmissionArtifactError("clean comparison/frozen manifest mismatch")
    if candidate_comparison.get("frozen_manifest_sha256") != sha256_file(
        candidate_manifest_path
    ):
        raise CompositeAdmissionArtifactError(
            "candidate comparison/frozen manifest mismatch"
        )

    context_client_ids = [item.client_id for item in context.core.clients]
    clean_order = [str(item) for item in clean_comparison["same_frozen_input_order"]]
    candidate_order = [
        str(item) for item in candidate_comparison["same_frozen_input_order"]
    ]
    if clean_order != context_client_ids or candidate_order != context_client_ids:
        raise CompositeAdmissionArtifactError(
            "M5 context and M6 comparison client orders differ"
        )
    clean_indicators = clean_comparison.get("indicators", [])
    candidate_indicators = candidate_comparison.get("indicators", [])
    if [str(item.get("client_id")) for item in clean_indicators] != context_client_ids:
        raise CompositeAdmissionArtifactError("clean indicator client order mismatch")
    if [str(item.get("client_id")) for item in candidate_indicators] != context_client_ids:
        raise CompositeAdmissionArtifactError("candidate indicator client order mismatch")

    statistics_config = config["statistics"]
    indicator_specs = statistics_config["indicators"]
    directions = {
        str(name): str(spec["direction"]) for name, spec in indicator_specs.items()
    }
    weights = {
        str(name): float(spec["weight"]) for name, spec in indicator_specs.items()
    }
    references = build_indicator_references(
        clean_indicators,
        directions=directions,
    )
    clean_statistics = score_statistical_indicators(
        clean_indicators,
        references=references,
        weights=weights,
        z_cap=float(statistics_config["robust_z_cap"]),
    )
    candidate_statistics = score_statistical_indicators(
        candidate_indicators,
        references=references,
        weights=weights,
        z_cap=float(statistics_config["robust_z_cap"]),
    )
    policies_config = config["policies"]
    calibration = policies_config["calibration"]
    if calibration.get("source") != "clean-reference-only":
        raise CompositeAdmissionArtifactError(
            "policy thresholds must be calibrated from the clean reference only"
        )
    thresholds = calibrate_policy_thresholds(
        list(clean_statistics.values()),
        trust_weight=float(policies_config["composite_trust_weight"]),
        statistical_margin=float(calibration["statistical_max_margin"]),
        composite_margin=float(calibration["composite_max_margin"]),
        downweight_quantile=float(calibration["composite_downweight_quantile"]),
    )

    candidate_records = {
        str(item["client_id"]): item for item in candidate_manifest["clients"]
    }
    attacker_ids = sorted(str(item) for item in candidate_manifest["attacker_ids"])
    if set(candidate_records) != set(context_client_ids):
        raise CompositeAdmissionArtifactError("candidate frozen client set mismatch")
    records: list[CompositeAdmissionClientRecord] = []
    quadrant_counts: Counter[str] = Counter()
    policy_status_counts: dict[str, Counter[str]] = {
        policy: Counter() for policy in POLICIES
    }
    for client_id in context_client_ids:
        submission = round_workspace / "submissions" / client_id
        bundle_path = submission / "bundle.json"
        update_path = submission / "update.json"
        decision_path = round_workspace / "decisions" / f"{client_id}.json"
        bundle = UpdateBundle.model_validate(load_json(bundle_path))
        decision = ContributionDecision.model_validate(load_json(decision_path))
        if decision.core.client_id != client_id or decision.core.bundle_id != bundle.bundle_id:
            raise CompositeAdmissionArtifactError(
                f"M5 decision/bundle identity mismatch: {client_id}"
            )
        if decision.core.bundle_sha256 != sha256_file(bundle_path):
            raise CompositeAdmissionArtifactError(
                f"M5 decision/bundle digest mismatch: {client_id}"
            )
        if bundle.core.update_sha256 != sha256_file(update_path):
            raise CompositeAdmissionArtifactError(
                f"M5 bundle/update digest mismatch: {client_id}"
            )
        frozen_record = candidate_records[client_id]
        if frozen_record.get("source_bundle_sha256") != sha256_file(bundle_path):
            raise CompositeAdmissionArtifactError(
                f"candidate/source bundle digest mismatch: {client_id}"
            )
        if frozen_record.get("source_update_sha256") != sha256_file(update_path):
            raise CompositeAdmissionArtifactError(
                f"candidate/source update digest mismatch: {client_id}"
            )
        attestation_path = (
            trust_workspace / "results" / f"{bundle.core.attestation_result_id}.json"
        )
        attestation = AttestationResultV2.model_validate(load_json(attestation_path))
        if (
            attestation.result_id != bundle.core.attestation_result_id
            or sha256_file(attestation_path) != bundle.core.attestation_result_sha256
            or attestation.core.client_id != client_id
        ):
            raise CompositeAdmissionArtifactError(
                f"M4 attestation/M5 bundle binding mismatch: {client_id}"
            )
        trust = trust_signal_from_checks(
            [item.model_dump(mode="json") for item in decision.core.checks],
            raw_status=attestation.core.status,
            passed_with_warning_risk=float(
                config["trust"]["passed_with_warning_risk"]
            ),
        )
        statistics = candidate_statistics[client_id]
        decisions = decide_admission_policies(
            trust=trust,
            statistics=statistics,
            statistical_threshold=thresholds.statistical_threshold,
            composite_threshold=thresholds.composite_threshold,
            composite_downweight_threshold=thresholds.composite_downweight_threshold,
            trust_weight=thresholds.trust_weight,
        )
        attacked = client_id in attacker_ids
        binding = "controlled-derived-not-resigned" if attacked else "source-bundle-signed"
        record = CompositeAdmissionClientRecord(
            client_id=client_id,
            evaluation_label="anomalous" if attacked else "normal",
            source_bundle_id=bundle.bundle_id,
            source_bundle_sha256=sha256_file(bundle_path),
            source_update_sha256=sha256_file(update_path),
            candidate_update_sha256=str(frozen_record["frozen_update_sha256"]),
            candidate_update_binding=binding,
            attestation_result_id=attestation.result_id,
            attestation_result_sha256=sha256_file(attestation_path),
            trust=trust,
            statistics=statistics,
            decisions=decisions,
        )
        records.append(record)
        statistical_normal = statistics.risk <= thresholds.statistical_threshold
        quadrant = (
            f"trust_{'admissible' if trust.admissible else 'inadmissible'}_"
            f"statistics_{'normal' if statistical_normal else 'anomalous'}"
        )
        quadrant_counts[quadrant] += 1
        for policy_decision in decisions:
            policy_status_counts[policy_decision.policy][policy_decision.status] += 1

    controlled_selection, controlled_cases = _controlled_disagreement_matrix(
        records=records,
        attacker_ids=attacker_ids,
        config=config,
        thresholds=thresholds,
    )

    artifact = CompositeAdmissionArtifact(
        code_version=__version__,
        experiment_id=str(config["experiment"]["id"]),
        campaign_id=context.core.campaign_id,
        round_number=context.core.round_number,
        context_id=context.context_id,
        candidate_attack=str(candidate_manifest["attack"]),
        attacker_ids=attacker_ids,
        candidate_binding_semantics=BINDING_SEMANTICS,
        source_round_context_sha256=context_sha256,
        source_round_checkpoint_sha256=checkpoint_sha256,
        clean_frozen_manifest_sha256=sha256_file(clean_manifest_path),
        clean_comparison_sha256=sha256_file(clean_comparison_path),
        candidate_frozen_manifest_sha256=sha256_file(candidate_manifest_path),
        candidate_comparison_sha256=sha256_file(candidate_comparison_path),
        partition_manifest_sha256=partition_sha256,
        composite_config_sha256=config_digest,
        byzantine_config_sha256=byzantine_config_digest,
        implementation_sha256=sha256_file(Path(__file__)),
        indicator_references=[references[name] for name in sorted(references)],
        thresholds=thresholds,
        clients=records,
        quadrant_counts=dict(sorted(quadrant_counts.items())),
        policy_status_counts={
            policy: dict(sorted(counts.items()))
            for policy, counts in policy_status_counts.items()
        },
        policy_evaluation=_policy_evaluation(records),
        controlled_matrix_selection=controlled_selection,
        controlled_disagreement_cases=controlled_cases,
        controlled_policy_evaluation=_controlled_policy_evaluation(controlled_cases),
    )
    return artifact


def create_composite_admission_artifact(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    clean_frozen_workspace: Path,
    clean_comparison_workspace: Path,
    candidate_frozen_workspace: Path,
    candidate_comparison_workspace: Path,
    output: Path,
    config_path: Path,
    byzantine_config_path: Path,
) -> dict[str, Any]:
    """Create one immutable joint-admission artifact from verified M4-M6 inputs."""

    artifact = _compute_artifact(
        round_workspace=round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        clean_frozen_workspace=clean_frozen_workspace,
        clean_comparison_workspace=clean_comparison_workspace,
        candidate_frozen_workspace=candidate_frozen_workspace,
        candidate_comparison_workspace=candidate_comparison_workspace,
        config_path=config_path,
        byzantine_config_path=byzantine_config_path,
    )
    path = output / "admission.json"
    content = derived_json_bytes(artifact.model_dump(mode="json"))
    write_once(path, content)
    return {
        "status": "admission_compared",
        "experiment_id": artifact.experiment_id,
        "round_number": artifact.round_number,
        "candidate_attack": artifact.candidate_attack,
        "client_count": len(artifact.clients),
        "attacker_count": len(artifact.attacker_ids),
        "statistical_threshold": artifact.thresholds.statistical_threshold,
        "composite_threshold": artifact.thresholds.composite_threshold,
        "quadrant_counts": artifact.quadrant_counts,
        "policy_evaluation": {
            name: value.model_dump(mode="json")
            for name, value in artifact.policy_evaluation.items()
        },
        "controlled_disagreement_case_count": len(
            artifact.controlled_disagreement_cases
        ),
        "controlled_policy_evaluation": {
            name: value.model_dump(mode="json")
            for name, value in artifact.controlled_policy_evaluation.items()
        },
        "admission_sha256": sha256_file(path),
        "workspace": str(output),
    }


def verify_composite_admission_artifact(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    clean_frozen_workspace: Path,
    clean_comparison_workspace: Path,
    candidate_frozen_workspace: Path,
    candidate_comparison_workspace: Path,
    workspace: Path,
    config_path: Path,
    byzantine_config_path: Path,
) -> dict[str, Any]:
    """Recompute the complete artifact and compare canonical bytes."""

    errors: list[str] = []
    path = workspace / "admission.json"
    if not path.is_file():
        return {
            "status": "failed",
            "error_count": 1,
            "errors": ["missing composite admission.json"],
            "workspace": str(workspace),
        }
    try:
        stored = CompositeAdmissionArtifact.model_validate(load_json(path))
        recomputed = _compute_artifact(
            round_workspace=round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            clean_frozen_workspace=clean_frozen_workspace,
            clean_comparison_workspace=clean_comparison_workspace,
            candidate_frozen_workspace=candidate_frozen_workspace,
            candidate_comparison_workspace=candidate_comparison_workspace,
            config_path=config_path,
            byzantine_config_path=byzantine_config_path,
        )
        if derived_json_bytes(stored.model_dump(mode="json")) != derived_json_bytes(
            recomputed.model_dump(mode="json")
        ):
            errors.append("stored composite admission differs from recomputation")
    except (
        CompositeAdmissionArtifactError,
        CompositeAdmissionError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
        stored = None
    return {
        "status": "verified" if not errors else "failed",
        "experiment_id": stored.experiment_id if stored is not None else None,
        "round_number": stored.round_number if stored is not None else None,
        "candidate_attack": stored.candidate_attack if stored is not None else None,
        "client_count": len(stored.clients) if stored is not None else 0,
        "implementation_binding_verified": not errors,
        "sources_recomputed": not errors,
        "decisions_recomputed": not errors,
        "admission_sha256": sha256_file(path),
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
