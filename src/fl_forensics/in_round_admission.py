"""Enforce joint TPM/statistical admission before each FL aggregation.

This module is intentionally separate from the original all-or-nothing M5
checkpoint path.  It consumes the Update Bundles produced by the isolated M5
clients, revalidates their M4/M5 trust evidence, scores the just-produced model
updates, and creates the checkpoint used as the next round's base model.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import numpy as np

from .byzantine import model_delta, update_indicators
from .canonical import digest_object, sha256_bytes, sha256_file
from .composite_admission import (
    TRUST_CHECK_NAMES,
    decide_admission_policies,
    score_statistical_indicators,
    trust_signal_from_checks,
)
from .composite_admission_models import (
    IndicatorReference,
    PolicyThresholds,
    TrustSignal,
)
from .config import load_yaml
from .crypto import public_key_id, verify_digest_signature
from .disagreement_experiment import (
    effective_trust_checks,
    load_bound_disagreement_contract,
)
from .disagreement_experiment_models import DisagreementExperimentContract
from .federated_model import (
    arrays_from_export,
    build_model,
    dependencies,
    evaluate_rows,
    fedavg,
    load_ndarrays,
)
from .in_round_admission_models import (
    InRoundAdmissionContract,
    InRoundAdmissionContractCore,
    InRoundCheckpointInput,
    InRoundContributionDecision,
    InRoundContributionDecisionCore,
    InRoundSecureCheckpoint,
    InRoundSecureCheckpointCore,
)
from .preprocessing import derived_json_bytes
from .secure_round import (
    EXPECTED_CLIENTS,
    SecureRoundError,
    _admission_checks,
    _coordinator_public_key,
    _coordinator_signer,
    _load_context,
    _parse_time,
    _sign_decision,
    _sign_malformed_decision,
    _signature,
    _verify_signed,
)
from .secure_round_models import ContributionDecision, UpdateBundle
from .storage import atomic_json, load_json, write_json_once, write_once


class InRoundAdmissionError(SecureRoundError):
    """Raised when an in-round policy contract or checkpoint is invalid."""


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _decimal(value: int | float | Decimal) -> str:
    return format(Decimal(str(value)).normalize(), "f")


def _implementation_sha256() -> str:
    root = Path(__file__).resolve().parent
    return digest_object(
        {
            name: sha256_file(root / name)
            for name in (
                "byzantine.py",
                "composite_admission.py",
                "composite_admission_models.py",
                "disagreement_experiment.py",
                "disagreement_experiment_models.py",
                "in_round_admission.py",
                "in_round_admission_models.py",
                "secure_round.py",
            )
        }
    )


def _artifact_core_digest(value: Any) -> str:
    """Digest numeric cores with sorted, finite JSON serialization."""

    return sha256_bytes(derived_json_bytes(value))


def verify_in_round_signature(value: Any, public_key: Any) -> bool:
    """Verify identity, core digest, and signature for in-round artifacts."""

    identities = {
        InRoundContributionDecision: ("decision_id", "in-round-decision-"),
        InRoundSecureCheckpoint: ("checkpoint_id", "in-round-checkpoint-"),
    }
    identity = identities.get(type(value))
    if identity is None:
        return False
    digest = _artifact_core_digest(value.core.model_dump(mode="json"))
    return (
        getattr(value, identity[0]) == f"{identity[1]}{digest[:24]}"
        and value.core_digest == digest
        and value.signature.key_id == public_key_id(public_key)
        and verify_digest_signature(public_key, digest, value.signature.value_b64)
    )


def build_in_round_contract(
    *, config_path: Path, partition_manifest: dict[str, Any]
) -> InRoundAdmissionContract:
    """Build the immutable policy contract that the round context will bind."""

    config, config_sha256 = load_yaml(config_path)
    if config.get("schema_version") != "1.0":
        raise InRoundAdmissionError("unsupported in-round admission schema")
    settings = config.get("runtime_admission")
    if not isinstance(settings, dict):
        raise InRoundAdmissionError("runtime_admission configuration is missing")
    calibration = settings.get("calibration")
    if not isinstance(calibration, dict):
        raise InRoundAdmissionError("runtime admission calibration is missing")
    raw_references = calibration.get("indicator_references")
    raw_weights = calibration.get("indicator_weights")
    if not isinstance(raw_references, dict) or not isinstance(raw_weights, dict):
        raise InRoundAdmissionError("indicator references or weights are missing")
    if set(raw_references) != set(raw_weights):
        raise InRoundAdmissionError("indicator references and weights must align")
    references = [
        IndicatorReference(name=name, **raw_references[name])
        for name in sorted(raw_references)
    ]
    weights = {name: float(raw_weights[name]) for name in sorted(raw_weights)}
    if any(value <= 0.0 for value in weights.values()):
        raise InRoundAdmissionError("runtime indicator weights must be positive")
    thresholds = PolicyThresholds.model_validate(calibration.get("thresholds"))
    client_count = int(partition_manifest.get("client_count", 0))
    minimum = int(settings.get("minimum_contributors", 0))
    if not 1 <= minimum <= client_count:
        raise InRoundAdmissionError(
            "minimum_contributors must be within the partition client count"
        )
    split_records = partition_manifest.get("server_evaluation_splits")
    if not isinstance(split_records, dict) or "validation" not in split_records:
        raise InRoundAdmissionError(
            "in-round admission requires an isolated validation split"
        )
    validation = split_records["validation"]
    core = InRoundAdmissionContractCore(
        policy_id=str(settings["policy_id"]),
        primary_policy=str(settings["primary_policy"]),
        policy_config_sha256=config_sha256,
        calibration_source_admission_sha256=str(
            calibration["source_admission_sha256"]
        ),
        calibration_semantics=str(calibration["semantics"]),
        indicator_references=references,
        indicator_weights=weights,
        robust_z_cap=float(settings["robust_z_cap"]),
        passed_with_warning_risk=float(settings["passed_with_warning_risk"]),
        thresholds=thresholds,
        accepted_downweight_factor=float(settings["accepted_downweight_factor"]),
        minimum_contributors=minimum,
        validation_metric=str(settings["validation_metric"]),
        validation_split_sha256=str(validation["sha256"]),
        validation_row_count=int(validation["row_count"]),
        implementation_sha256=_implementation_sha256(),
    )
    digest = _artifact_core_digest(core.model_dump(mode="json"))
    return InRoundAdmissionContract(
        contract_id=f"in-round-contract-{digest[:24]}",
        core=core,
        core_digest=digest,
    )


def install_in_round_contract(
    *,
    public_workspace: Path,
    config_path: Path,
    partition_manifest: dict[str, Any],
) -> tuple[InRoundAdmissionContract, dict[str, Any]]:
    """Publish policy inputs before the signed round context is created."""

    contract = build_in_round_contract(
        config_path=config_path, partition_manifest=partition_manifest
    )
    config_target = public_workspace / "in-round-admission.yaml"
    contract_target = public_workspace / "in-round-admission-contract.json"
    write_once(config_target, config_path.read_bytes())
    write_once(
        contract_target,
        derived_json_bytes(contract.model_dump(mode="json")),
    )
    return contract, {
        "mode": "gated-composite-before-aggregation",
        "policy_config_path": config_target.name,
        "policy_config_sha256": sha256_file(config_target),
        "contract_path": contract_target.name,
        "contract_sha256": sha256_file(contract_target),
        "contract_id": contract.contract_id,
    }


def _load_bound_contract(workspace: Path) -> InRoundAdmissionContract:
    public = workspace / "public"
    training_contract = load_json(public / "training-contract.json")
    binding = training_contract.get("in_round_admission")
    if not isinstance(binding, dict):
        raise InRoundAdmissionError(
            "signed training contract has no in-round admission binding"
        )
    if binding.get("policy_config_path") != "in-round-admission.yaml" or binding.get(
        "contract_path"
    ) != "in-round-admission-contract.json":
        raise InRoundAdmissionError("unsafe in-round admission public path")
    config_path = public / "in-round-admission.yaml"
    contract_path = public / "in-round-admission-contract.json"
    if sha256_file(config_path) != binding.get("policy_config_sha256"):
        raise InRoundAdmissionError("bound in-round policy configuration changed")
    if sha256_file(contract_path) != binding.get("contract_sha256"):
        raise InRoundAdmissionError("bound in-round admission contract changed")
    partition = load_json(public / "partition-manifest.json")
    expected = build_in_round_contract(
        config_path=config_path, partition_manifest=partition
    )
    observed = InRoundAdmissionContract.model_validate(load_json(contract_path))
    if observed.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise InRoundAdmissionError("in-round admission contract does not recompute")
    if observed.contract_id != binding.get("contract_id"):
        raise InRoundAdmissionError("in-round admission contract id mismatch")
    return observed


def _load_validation_rows(
    *, workspace: Path, validation_split_path: Path, contract: InRoundAdmissionContract
) -> list[dict[str, Any]]:
    partition = load_json(workspace / "public" / "partition-manifest.json")
    record = partition["server_evaluation_splits"]["validation"]
    if (
        sha256_file(validation_split_path) != contract.core.validation_split_sha256
        or str(record["sha256"]) != contract.core.validation_split_sha256
    ):
        raise InRoundAdmissionError("isolated validation split digest mismatch")
    snapshot = load_json(validation_split_path)
    rows = snapshot.get("rows", {}).get("validation")
    if (
        snapshot.get("split") != "validation"
        or snapshot.get("class_names") != partition.get("class_names")
        or not isinstance(rows, list)
        or len(rows) != contract.core.validation_row_count
    ):
        raise InRoundAdmissionError("isolated validation split contract mismatch")
    return rows


def _model_from_export(value: dict[str, Any], *, torch: Any) -> Any:
    architecture = value["architecture"]
    model = build_model(
        input_features=int(architecture["input_features"]),
        class_count=int(architecture["classification_head_outputs"]),
        hidden_layers=[int(item) for item in architecture["encoder_hidden_layers"]],
        embedding_size=int(architecture["embedding_size"]),
        dropout=float(architecture["dropout"]),
        torch=torch,
    )
    load_ndarrays(model, arrays_from_export(value, np=np), torch=torch, np=np)
    return model


def _validation_f1(
    *, model_export: dict[str, Any], rows: list[dict[str, Any]], batch_size: int
) -> float:
    (
        _np,
        torch,
        _flwr,
        _sklearn,
        _aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependencies()
    metrics = evaluate_rows(
        model=_model_from_export(model_export, torch=torch),
        rows=rows,
        class_names=[str(item) for item in model_export["class_names"]],
        batch_size=batch_size,
        torch=torch,
        np=np,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )
    return float(metrics["macro_f1_all_model_classes"])


def _attestation_status(trust_workspace: Path, bundle: UpdateBundle | None) -> str:
    if bundle is None:
        return "unavailable"
    path = trust_workspace / "results" / f"{bundle.core.attestation_result_id}.json"
    try:
        return str(load_json(path)["core"]["status"])
    except (FileNotFoundError, KeyError, OSError, TypeError, ValueError):
        return "unavailable"


def _load_or_create_trust_records(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
    now: datetime,
    create: bool,
    coordinator_workspace: Path | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    context = _load_context(workspace / "public")
    base = load_json(workspace / "public" / "base-model.json")
    public_key = _coordinator_public_key(workspace)
    signer = (
        _coordinator_signer(
            workspace,
            create=False,
            coordinator_workspace=coordinator_workspace or workspace.parent.parent,
        )
        if create
        else None
    )
    records: list[dict[str, Any]] = []
    missing: list[str] = []
    state_path = workspace / "state.json"
    state = load_json(state_path)
    if (
        state.get("campaign_id") != context.core.campaign_id
        or state.get("context_id") != context.context_id
    ):
        raise InRoundAdmissionError("in-round replay state/context mismatch")
    for client_id in [item.client_id for item in context.core.clients]:
        submission = submissions_root / client_id
        bundle_path = submission / "bundle.json"
        if not bundle_path.is_file():
            missing.append(client_id)
            continue
        bundle_sha256 = sha256_file(bundle_path)
        slot = f"{context.core.campaign_id}:{context.core.round_number}:{client_id}"
        consumed = state.get("slots", {}).get(slot)
        if consumed is not None and consumed.get("bundle_sha256") != bundle_sha256:
            raise InRoundAdmissionError(
                f"in-round replay slot contains a different bundle: {client_id}"
            )
        bundle: UpdateBundle | None
        try:
            bundle = UpdateBundle.model_validate(load_json(bundle_path))
        except (OSError, TypeError, ValueError):
            bundle = None
        decision_path = workspace / "decisions" / f"{client_id}.json"
        if decision_path.is_file():
            trust_decision = ContributionDecision.model_validate(load_json(decision_path))
            decision_time = _parse_time(trust_decision.core.decided_at)
        else:
            if not create or signer is None:
                raise InRoundAdmissionError(f"missing trust decision: {client_id}")
            decision_time = now
            if bundle is None:
                trust_decision = _sign_malformed_decision(
                    signer=signer,
                    context=context,
                    client_id=client_id,
                    bundle_sha256=bundle_sha256,
                    detail="Update Bundle does not match the signed schema",
                    now=decision_time,
                )
            else:
                checks = _admission_checks(
                    bundle=bundle,
                    submission=submission,
                    context=context,
                    base=base,
                    trust_workspace=trust_workspace,
                    now=decision_time,
                    expected_client_id=client_id,
                )
                trust_decision = _sign_decision(
                    signer=signer,
                    context=context,
                    bundle=bundle,
                    bundle_sha256=bundle_sha256,
                    checks=checks,
                    now=decision_time,
                )
            write_json_once(decision_path, trust_decision.model_dump(mode="json"))
        if consumed is None:
            if not create:
                raise InRoundAdmissionError(
                    f"in-round replay slot is missing: {client_id}"
                )
            state.setdefault("slots", {})[slot] = {
                "bundle_sha256": bundle_sha256,
                "decision_path": str(decision_path.relative_to(workspace)),
            }
            atomic_json(state_path, state)
        elif consumed.get("decision_path") != str(decision_path.relative_to(workspace)):
            raise InRoundAdmissionError(
                f"in-round replay decision path mismatch: {client_id}"
            )
        if not _verify_signed(trust_decision, public_key):
            raise InRoundAdmissionError(f"invalid trust decision signature: {client_id}")
        if trust_decision.core.bundle_sha256 != bundle_sha256:
            raise InRoundAdmissionError(f"trust decision bundle mismatch: {client_id}")
        if bundle is None:
            expected_checks = trust_decision.core.checks
        else:
            expected_checks = _admission_checks(
                bundle=bundle,
                submission=submission,
                context=context,
                base=base,
                trust_workspace=trust_workspace,
                now=decision_time,
                expected_client_id=client_id,
            )
            if [item.model_dump(mode="json") for item in trust_decision.core.checks] != [
                item.model_dump(mode="json") for item in expected_checks
            ]:
                raise InRoundAdmissionError(
                    f"trust decision checks do not recompute: {client_id}"
                )
            expected_status = (
                "accepted" if all(item.passed for item in expected_checks) else "quarantined"
            )
            if trust_decision.core.status != expected_status:
                raise InRoundAdmissionError(
                    f"trust decision status does not recompute: {client_id}"
                )
        records.append(
            {
                "client_id": client_id,
                "submission": submission,
                "bundle_path": bundle_path,
                "bundle_sha256": bundle_sha256,
                "bundle": bundle,
                "trust_decision": trust_decision,
                "trust_decision_path": decision_path,
                "checks": expected_checks,
                "raw_attestation_status": _attestation_status(trust_workspace, bundle),
            }
        )
    return records, missing


def _compute_statistical_state(
    *,
    records: list[dict[str, Any]],
    base: dict[str, Any],
    validation_rows: list[dict[str, Any]],
    batch_size: int,
    contract: InRoundAdmissionContract,
    disagreement_contract: DisagreementExperimentContract | None,
) -> dict[str, dict[str, Any]]:
    eligible = [
        item
        for item in records
        if item["bundle"] is not None
        and item["trust_decision"].core.status == "accepted"
    ]
    if len(eligible) < contract.core.minimum_contributors:
        return {}
    base_arrays = arrays_from_export(base, np=np)
    updates = [load_json(item["submission"] / "update.json") for item in eligible]
    deltas = [
        model_delta(base_arrays, arrays_from_export(update, np=np))
        for update in updates
    ]
    indicators = update_indicators(
        deltas, client_ids=[str(item["client_id"]) for item in eligible]
    )
    base_validation_f1 = _validation_f1(
        model_export=base, rows=validation_rows, batch_size=batch_size
    )
    for indicator, update in zip(indicators, updates, strict=True):
        candidate_f1 = _validation_f1(
            model_export=update, rows=validation_rows, batch_size=batch_size
        )
        indicator["validation_macro_f1"] = candidate_f1
        indicator["validation_impact"] = base_validation_f1 - candidate_f1
    references = {item.name: item for item in contract.core.indicator_references}
    statistical = score_statistical_indicators(
        indicators,
        references=references,
        weights=contract.core.indicator_weights,
        z_cap=contract.core.robust_z_cap,
    )
    result: dict[str, dict[str, Any]] = {}
    for item in eligible:
        client_id = str(item["client_id"])
        policy_checks = effective_trust_checks(
            checks=list(item["checks"]),
            contract=disagreement_contract,
            client_id=client_id,
        )
        trust = trust_signal_from_checks(
            [check.model_dump(mode="json") for check in policy_checks],
            raw_status=str(item["raw_attestation_status"]),
            passed_with_warning_risk=contract.core.passed_with_warning_risk,
        )
        thresholds = contract.core.thresholds
        policies = decide_admission_policies(
            trust=trust,
            statistics=statistical[client_id],
            statistical_threshold=thresholds.statistical_threshold,
            composite_threshold=thresholds.composite_threshold,
            composite_downweight_threshold=thresholds.composite_downweight_threshold,
            trust_weight=thresholds.trust_weight,
        )
        result[client_id] = {
            "trust": trust,
            "statistics": statistical[client_id],
            "policies": policies,
            "primary": next(
                decision for decision in policies if decision.policy == "gated_composite"
            ),
        }
    return result


def _runtime_decision_core(
    *,
    context: Any,
    contract: InRoundAdmissionContract,
    record: dict[str, Any],
    statistical_state: dict[str, dict[str, Any]],
    disagreement_contract: DisagreementExperimentContract | None,
    decided_at: str,
) -> InRoundContributionDecisionCore:
    client_id = str(record["client_id"])
    bundle = record["bundle"]
    trust_decision = record["trust_decision"]
    checks = effective_trust_checks(
        checks=list(record["checks"]),
        contract=disagreement_contract,
        client_id=client_id,
    )
    failed = [item for item in checks if not item.passed]
    check_names = {item.name for item in checks}
    if set(TRUST_CHECK_NAMES).issubset(check_names):
        default_trust = trust_signal_from_checks(
            [item.model_dump(mode="json") for item in checks],
            raw_status=str(record["raw_attestation_status"]),
            passed_with_warning_risk=contract.core.passed_with_warning_risk,
        )
    else:
        default_trust = TrustSignal(
            raw_status=str(record["raw_attestation_status"]),
            admissible=False,
            risk=1.0,
            evaluated_checks=sorted(check_names),
            failed_checks=sorted(check_names),
            reasons=["bundle integrity failed before complete trust evaluation"],
        )
    state = statistical_state.get(client_id)
    integrity_failed = [
        item for item in failed if item.name not in TRUST_CHECK_NAMES
    ]
    if integrity_failed:
        final_status = "integrity_quarantined"
        effective = Decimal("0")
        policies: list[Any] = []
        primary = None
        statistics = None
        trust = default_trust
        reasons = [f"{item.name}: {item.detail}" for item in integrity_failed]
    elif state is None:
        trust_failed = any(item.name in TRUST_CHECK_NAMES for item in failed)
        final_status = "trust_quarantined" if trust_failed else "integrity_quarantined"
        effective = Decimal("0")
        policies = []
        primary = None
        statistics = None
        trust = default_trust
        reasons = ["insufficient trusted candidates for statistical admission"]
    else:
        trust = state["trust"]
        statistics = state["statistics"]
        policies = state["policies"]
        primary = state["primary"]
        final_status = primary.status
        if primary.status == "accepted":
            factor = Decimal("1")
        elif primary.status == "accepted_downweighted":
            factor = Decimal(str(contract.core.accepted_downweight_factor))
        else:
            factor = Decimal("0")
        effective = Decimal(bundle.core.num_examples) * factor
        reasons = list(primary.reasons)
    bundle_id = (
        bundle.bundle_id
        if bundle is not None
        else f"malformed-bundle-{record['bundle_sha256'][:24]}"
    )
    return InRoundContributionDecisionCore(
        campaign_id=context.core.campaign_id,
        context_id=context.context_id,
        context_digest=context.core_digest,
        contract_id=contract.contract_id,
        contract_digest=contract.core_digest,
        round_number=context.core.round_number,
        client_id=client_id,
        bundle_id=bundle_id,
        bundle_sha256=record["bundle_sha256"],
        update_sha256=bundle.core.update_sha256 if bundle is not None else None,
        trust_decision_id=trust_decision.decision_id,
        trust_decision_sha256=sha256_file(record["trust_decision_path"]),
        m5_checks=checks,
        trust=trust,
        statistics=statistics,
        policy_decisions=policies,
        primary_decision=primary,
        final_status=final_status,
        num_examples=bundle.core.num_examples if bundle is not None else 0,
        effective_weight_decimal=_decimal(effective),
        reasons=reasons,
        decided_at=decided_at,
    )


def _load_or_create_runtime_decisions(
    *,
    workspace: Path,
    records: list[dict[str, Any]],
    statistical_state: dict[str, dict[str, Any]],
    contract: InRoundAdmissionContract,
    disagreement_contract: DisagreementExperimentContract | None,
    now: datetime,
    create: bool,
    coordinator_workspace: Path | None = None,
) -> list[tuple[InRoundContributionDecision, Path]]:
    context = _load_context(workspace / "public")
    public_key = _coordinator_public_key(workspace)
    signer = (
        _coordinator_signer(
            workspace,
            create=False,
            coordinator_workspace=coordinator_workspace or workspace.parent.parent,
        )
        if create
        else None
    )
    decisions: list[tuple[InRoundContributionDecision, Path]] = []
    for record in records:
        client_id = str(record["client_id"])
        path = workspace / "in-round-decisions" / f"{client_id}.json"
        if path.is_file():
            decision = InRoundContributionDecision.model_validate(load_json(path))
            decided_at = decision.core.decided_at
        else:
            if not create or signer is None:
                raise InRoundAdmissionError(
                    f"missing in-round contribution decision: {client_id}"
                )
            decided_at = _utc(now)
            core = _runtime_decision_core(
                context=context,
                contract=contract,
                record=record,
                statistical_state=statistical_state,
                disagreement_contract=disagreement_contract,
                decided_at=decided_at,
            )
            digest = _artifact_core_digest(core.model_dump(mode="json"))
            decision = InRoundContributionDecision(
                decision_id=f"in-round-decision-{digest[:24]}",
                core=core,
                core_digest=digest,
                signature=_signature(signer, digest, "software-development"),
            )
            write_once(path, derived_json_bytes(decision.model_dump(mode="json")))
        if not verify_in_round_signature(decision, public_key):
            raise InRoundAdmissionError(
                f"invalid in-round decision signature: {client_id}"
            )
        expected_core = _runtime_decision_core(
            context=context,
            contract=contract,
            record=record,
            statistical_state=statistical_state,
            disagreement_contract=disagreement_contract,
            decided_at=decided_at,
        )
        if decision.core.model_dump(mode="json") != expected_core.model_dump(mode="json"):
            raise InRoundAdmissionError(
                f"in-round contribution decision does not recompute: {client_id}"
            )
        decisions.append((decision, path))
    return decisions


def _aggregate_inputs(
    *,
    base: dict[str, Any],
    decisions: list[tuple[InRoundContributionDecision, Path]],
    records: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[InRoundCheckpointInput], Decimal]:
    by_client = {str(item["client_id"]): item for item in records}
    weighted_updates: list[tuple[list[Any], float]] = []
    inputs: list[InRoundCheckpointInput] = []
    total_weight = Decimal("0")
    for decision, decision_path in decisions:
        if decision.core.final_status not in {"accepted", "accepted_downweighted"}:
            continue
        record = by_client[decision.core.client_id]
        bundle: UpdateBundle = record["bundle"]
        weight = Decimal(decision.core.effective_weight_decimal)
        if weight <= 0:
            raise InRoundAdmissionError("contributing update has non-positive weight")
        update = load_json(record["submission"] / "update.json")
        weighted_updates.append((arrays_from_export(update, np=np), float(weight)))
        total_weight += weight
        inputs.append(
            InRoundCheckpointInput(
                client_id=decision.core.client_id,
                decision_id=decision.decision_id,
                decision_sha256=sha256_file(decision_path),
                trust_decision_id=decision.core.trust_decision_id,
                trust_decision_sha256=decision.core.trust_decision_sha256,
                bundle_id=bundle.bundle_id,
                bundle_sha256=record["bundle_sha256"],
                update_sha256=bundle.core.update_sha256,
                num_examples=bundle.core.num_examples,
                effective_weight_decimal=decision.core.effective_weight_decimal,
                status=decision.core.final_status,
            )
        )
    if not weighted_updates:
        raise InRoundAdmissionError("no contribution remains after in-round admission")
    _np, _torch, _flwr, _sklearn, aggregate, *_metrics = dependencies()
    averaged = fedavg(weighted_updates, aggregate=aggregate)
    result = copy.deepcopy(base)
    for parameter, array in zip(result["parameters"], averaged, strict=True):
        parameter["values"] = np.asarray(
            array, dtype=np.dtype(parameter["dtype"])
        ).tolist()
    return result, inputs, total_weight


def admit_and_aggregate_in_round(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
    validation_split_path: Path,
    coordinator_workspace: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Apply trust and statistical gates after local training, before aggregation."""

    checkpoint_path = workspace / "checkpoint" / "manifest.json"
    if checkpoint_path.is_file():
        verification = verify_in_round_secure_round(
            workspace=workspace,
            trust_workspace=trust_workspace,
            submissions_root=submissions_root,
            validation_split_path=validation_split_path,
        )
        if verification["status"] != "verified":
            raise InRoundAdmissionError(
                f"existing in-round checkpoint does not verify: {verification['errors']}"
            )
        return {
            "status": "aggregated",
            "idempotent": True,
            **{
                key: verification[key]
                for key in (
                    "accepted_count",
                    "downweighted_count",
                    "quarantined_count",
                    "missing_count",
                    "checkpoint_id",
                    "global_model_sha256",
                )
            },
            "workspace": str(workspace),
        }
    now = now or datetime.now(UTC)
    context = _load_context(workspace / "public")
    if not (_parse_time(context.core.issued_at) <= now < _parse_time(context.core.expires_at)):
        raise InRoundAdmissionError("round context expired before in-round admission")
    contract = _load_bound_contract(workspace)
    disagreement_contract = load_bound_disagreement_contract(workspace / "public")
    validation_rows = _load_validation_rows(
        workspace=workspace,
        validation_split_path=validation_split_path,
        contract=contract,
    )
    records, missing = _load_or_create_trust_records(
        workspace=workspace,
        trust_workspace=trust_workspace,
        submissions_root=submissions_root,
        now=now,
        create=True,
        coordinator_workspace=coordinator_workspace,
    )
    base = load_json(workspace / "public" / "base-model.json")
    statistical_state = _compute_statistical_state(
        records=records,
        base=base,
        validation_rows=validation_rows,
        batch_size=context.core.batch_size,
        contract=contract,
        disagreement_contract=disagreement_contract,
    )
    decisions = _load_or_create_runtime_decisions(
        workspace=workspace,
        records=records,
        statistical_state=statistical_state,
        contract=contract,
        disagreement_contract=disagreement_contract,
        now=now,
        create=True,
        coordinator_workspace=coordinator_workspace,
    )
    contributing = [
        item
        for item, _path in decisions
        if item.core.final_status in {"accepted", "accepted_downweighted"}
    ]
    if len(contributing) < contract.core.minimum_contributors:
        return {
            "status": "failed",
            "reason": "minimum contributing client count was not reached",
            "accepted_count": len(contributing),
            "quarantined_count": len(decisions) - len(contributing),
            "missing_count": len(missing),
            "checkpoint_created": False,
            "workspace": str(workspace),
        }
    global_model, inputs, total_weight = _aggregate_inputs(
        base=base, decisions=decisions, records=records
    )
    model_bytes = derived_json_bytes(global_model)
    model_sha256 = sha256_bytes(model_bytes)
    write_once(workspace / "checkpoint" / "global-model.json", model_bytes)
    quarantined = [
        (item, path)
        for item, path in decisions
        if item.core.final_status not in {"accepted", "accepted_downweighted"}
    ]
    trust_accepted_count = sum(
        item["trust_decision"].core.status == "accepted" for item in records
    )
    core = InRoundSecureCheckpointCore(
        campaign_id=context.core.campaign_id,
        context_id=context.context_id,
        context_digest=context.core_digest,
        round_number=context.core.round_number,
        previous_checkpoint_sha256=context.core.previous_checkpoint_sha256,
        base_model_sha256=context.core.base_model_sha256,
        required_client_count=context.core.required_client_count,
        minimum_contributors=contract.core.minimum_contributors,
        evaluated_count=len(decisions),
        trust_accepted_count=trust_accepted_count,
        accepted_count=len(inputs),
        downweighted_count=sum(
            item.status == "accepted_downweighted" for item in inputs
        ),
        quarantined_count=len(quarantined),
        missing_client_ids=missing,
        total_examples=sum(item.num_examples for item in inputs),
        total_effective_weight_decimal=_decimal(total_weight),
        accepted_inputs=inputs,
        quarantined_decision_sha256=[sha256_file(path) for _item, path in quarantined],
        admission_contract_id=contract.contract_id,
        admission_contract_sha256=sha256_file(
            workspace / "public" / "in-round-admission-contract.json"
        ),
        policy_config_sha256=contract.core.policy_config_sha256,
        validation_split_sha256=contract.core.validation_split_sha256,
        implementation_sha256=contract.core.implementation_sha256,
        global_model_sha256=model_sha256,
        created_at=_utc(now),
    )
    digest = _artifact_core_digest(core.model_dump(mode="json"))
    signer = _coordinator_signer(
        workspace,
        create=False,
        coordinator_workspace=coordinator_workspace or workspace.parent.parent,
    )
    checkpoint = InRoundSecureCheckpoint(
        checkpoint_id=f"in-round-checkpoint-{digest[:24]}",
        core=core,
        core_digest=digest,
        signature=_signature(signer, digest, "software-development"),
    )
    write_json_once(checkpoint_path, checkpoint.model_dump(mode="json"))
    state_path = workspace / "state.json"
    state = load_json(state_path)
    state["in_round_checkpoint_id"] = checkpoint.checkpoint_id
    atomic_json(state_path, state)
    return {
        "status": "aggregated",
        "checkpoint_id": checkpoint.checkpoint_id,
        "accepted_count": core.accepted_count,
        "downweighted_count": core.downweighted_count,
        "quarantined_count": core.quarantined_count,
        "missing_count": len(core.missing_client_ids),
        "global_model_sha256": core.global_model_sha256,
        "idempotent": False,
        "workspace": str(workspace),
    }


def verify_in_round_secure_round(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
    validation_split_path: Path,
) -> dict[str, Any]:
    """Recompute all gates and the exact checkpoint from immutable round inputs."""

    errors: list[str] = []
    checkpoint: InRoundSecureCheckpoint | None = None
    aggregate_matches = False
    try:
        context = _load_context(workspace / "public")
        contract = _load_bound_contract(workspace)
        disagreement_contract = load_bound_disagreement_contract(
            workspace / "public"
        )
        validation_rows = _load_validation_rows(
            workspace=workspace,
            validation_split_path=validation_split_path,
            contract=contract,
        )
        checkpoint_path = workspace / "checkpoint" / "manifest.json"
        checkpoint = InRoundSecureCheckpoint.model_validate(load_json(checkpoint_path))
        public_key = _coordinator_public_key(workspace)
        if not verify_in_round_signature(checkpoint, public_key):
            errors.append("invalid coordinator signature on in-round checkpoint")
        records, missing = _load_or_create_trust_records(
            workspace=workspace,
            trust_workspace=trust_workspace,
            submissions_root=submissions_root,
            now=_parse_time(checkpoint.core.created_at),
            create=False,
        )
        base = load_json(workspace / "public" / "base-model.json")
        statistical_state = _compute_statistical_state(
            records=records,
            base=base,
            validation_rows=validation_rows,
            batch_size=context.core.batch_size,
            contract=contract,
            disagreement_contract=disagreement_contract,
        )
        decisions = _load_or_create_runtime_decisions(
            workspace=workspace,
            records=records,
            statistical_state=statistical_state,
            contract=contract,
            disagreement_contract=disagreement_contract,
            now=_parse_time(checkpoint.core.created_at),
            create=False,
        )
        recomputed_model, inputs, total_weight = _aggregate_inputs(
            base=base, decisions=decisions, records=records
        )
        quarantined = [
            (item, path)
            for item, path in decisions
            if item.core.final_status not in {"accepted", "accepted_downweighted"}
        ]
        expected_values = {
            "campaign": (checkpoint.core.campaign_id, context.core.campaign_id),
            "context": (checkpoint.core.context_id, context.context_id),
            "context digest": (checkpoint.core.context_digest, context.core_digest),
            "round": (checkpoint.core.round_number, context.core.round_number),
            "previous checkpoint": (
                checkpoint.core.previous_checkpoint_sha256,
                context.core.previous_checkpoint_sha256,
            ),
            "base model": (
                checkpoint.core.base_model_sha256,
                context.core.base_model_sha256,
            ),
            "required clients": (
                checkpoint.core.required_client_count,
                context.core.required_client_count,
            ),
            "minimum contributors": (
                checkpoint.core.minimum_contributors,
                contract.core.minimum_contributors,
            ),
            "evaluated count": (checkpoint.core.evaluated_count, len(decisions)),
            "accepted count": (checkpoint.core.accepted_count, len(inputs)),
            "downweighted count": (
                checkpoint.core.downweighted_count,
                sum(item.status == "accepted_downweighted" for item in inputs),
            ),
            "quarantined count": (
                checkpoint.core.quarantined_count,
                len(quarantined),
            ),
            "missing clients": (checkpoint.core.missing_client_ids, missing),
            "total examples": (
                checkpoint.core.total_examples,
                sum(item.num_examples for item in inputs),
            ),
            "total effective weight": (
                checkpoint.core.total_effective_weight_decimal,
                _decimal(total_weight),
            ),
            "accepted inputs": (
                [item.model_dump(mode="json") for item in checkpoint.core.accepted_inputs],
                [item.model_dump(mode="json") for item in inputs],
            ),
            "quarantined decisions": (
                checkpoint.core.quarantined_decision_sha256,
                [sha256_file(path) for _item, path in quarantined],
            ),
            "contract id": (
                checkpoint.core.admission_contract_id,
                contract.contract_id,
            ),
            "contract digest": (
                checkpoint.core.admission_contract_sha256,
                sha256_file(workspace / "public" / "in-round-admission-contract.json"),
            ),
            "policy config": (
                checkpoint.core.policy_config_sha256,
                contract.core.policy_config_sha256,
            ),
            "validation split": (
                checkpoint.core.validation_split_sha256,
                contract.core.validation_split_sha256,
            ),
            "implementation": (
                checkpoint.core.implementation_sha256,
                _implementation_sha256(),
            ),
        }
        for name, (observed, expected) in expected_values.items():
            if observed != expected:
                errors.append(f"in-round checkpoint {name} mismatch")
        expected_trust_accepted = sum(
            item["trust_decision"].core.status == "accepted" for item in records
        )
        if checkpoint.core.trust_accepted_count != expected_trust_accepted:
            errors.append("in-round checkpoint trust accepted count mismatch")
        if len(inputs) < contract.core.minimum_contributors:
            errors.append("in-round checkpoint is below minimum contributors")
        recomputed_bytes = derived_json_bytes(recomputed_model)
        recomputed_sha256 = sha256_bytes(recomputed_bytes)
        model_path = workspace / "checkpoint" / "global-model.json"
        aggregate_matches = (
            model_path.is_file()
            and model_path.read_bytes() == recomputed_bytes
            and sha256_file(model_path)
            == checkpoint.core.global_model_sha256
            == recomputed_sha256
        )
        if not aggregate_matches:
            errors.append("in-round checkpoint differs from recomputed weighted FedAvg")
        if not (
            _parse_time(context.core.issued_at)
            <= _parse_time(checkpoint.core.created_at)
            < _parse_time(context.core.expires_at)
        ):
            errors.append("in-round checkpoint was created outside context lifetime")
    except (FileNotFoundError, KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "checkpoint_id": checkpoint.checkpoint_id if checkpoint else None,
        "accepted_count": checkpoint.core.accepted_count if checkpoint else 0,
        "downweighted_count": checkpoint.core.downweighted_count if checkpoint else 0,
        "quarantined_count": checkpoint.core.quarantined_count if checkpoint else 0,
        "missing_count": len(checkpoint.core.missing_client_ids) if checkpoint else 0,
        "global_model_sha256": (
            checkpoint.core.global_model_sha256 if checkpoint else None
        ),
        "trust_recomputed": not errors,
        "statistics_recomputed": not errors,
        "decisions_recomputed": not errors,
        "aggregate_recomputed": aggregate_matches,
        "error_count": len(errors),
        "errors": errors,
    }
