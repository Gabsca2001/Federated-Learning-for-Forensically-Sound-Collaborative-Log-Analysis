"""Live, bound M6 experiment for TPM/statistical disagreement.

The update treatment runs in the isolated client before the Update Bundle is
TPM-signed.  The trust treatment is an explicitly controlled counterfactual at
the policy boundary: observed M4/M5 evidence remains preserved and verifiable.
"""

from __future__ import annotations

import copy
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from .canonical import digest_object, sha256_bytes, sha256_file
from .composite_admission import TRUST_CHECK_NAMES
from .config import load_yaml
from .disagreement_experiment_models import (
    DisagreementCondition,
    DisagreementExperimentContract,
    DisagreementExperimentContractCore,
    DisagreementSubmissionRecord,
)
from .preprocessing import derived_json_bytes
from .secure_round_models import SecureCheck
from .storage import load_json, write_once

CONDITIONS = (
    "trust_admissible_statistics_normal",
    "trust_admissible_statistics_anomalous",
    "trust_inadmissible_statistics_normal",
    "trust_inadmissible_statistics_anomalous",
)

SUPPORTED_LEGACY_DISAGREEMENT_IMPLEMENTATION_SHA256 = frozenset(
    {
        # Published 30-round live trust/statistical disagreement campaign.
        "6d84c7c53d2fb2482d4a097d3dda6fc67f666276b8afd07ee5bba3739e19718a",
    }
)


class DisagreementExperimentError(RuntimeError):
    """Raised when the controlled M6 experiment cannot be reproduced."""


def _implementation_sha256() -> str:
    root = Path(__file__).resolve().parent
    return digest_object(
        {
            name: sha256_file(root / name)
            for name in (
                "disagreement_experiment.py",
                "disagreement_experiment_models.py",
                "in_round_admission.py",
                "secure_round.py",
            )
        }
    )


def _artifact_digest(value: Any) -> str:
    return sha256_bytes(derived_json_bytes(value))


def _condition_flags(condition: str) -> tuple[bool, bool]:
    return condition.startswith("trust_inadmissible"), condition.endswith(
        "statistics_anomalous"
    )


def build_disagreement_contract(
    *, config_path: Path, client_ids: list[str]
) -> DisagreementExperimentContract:
    """Validate and normalize the four-cell controlled experiment contract."""

    config, config_sha256 = load_yaml(config_path)
    if config.get("schema_version") != "1.0":
        raise DisagreementExperimentError("unsupported disagreement schema")
    experiment = config.get("experiment")
    if not isinstance(experiment, dict):
        raise DisagreementExperimentError("disagreement experiment section is missing")
    if len(client_ids) != len(set(client_ids)) or not client_ids:
        raise DisagreementExperimentError("client identifiers must be present and unique")
    raw_assignments = experiment.get("assignments")
    if not isinstance(raw_assignments, dict):
        raise DisagreementExperimentError("controlled assignments are missing")
    assignments = {
        str(client_id): str(condition)
        for client_id, condition in raw_assignments.items()
    }
    unknown_clients = sorted(set(assignments) - set(client_ids))
    if unknown_clients:
        raise DisagreementExperimentError(
            f"controlled assignments contain unknown clients: {unknown_clients}"
        )
    counts = Counter(assignments.values())
    if set(counts) != set(CONDITIONS) or any(counts[item] != 1 for item in CONDITIONS):
        raise DisagreementExperimentError(
            "assignments must contain each disagreement condition exactly once"
        )
    trust_intervention = experiment.get("trust_intervention")
    update_intervention = experiment.get("update_intervention")
    core = DisagreementExperimentContractCore(
        experiment_id=str(experiment["id"]),
        config_sha256=config_sha256,
        client_ids=list(client_ids),
        assignments=assignments,
        background_condition=str(
            experiment.get(
                "background_condition", "trust_admissible_statistics_normal"
            )
        ),
        active_rounds=str(experiment.get("active_rounds", "all")),
        trust_intervention=trust_intervention,
        update_intervention=update_intervention,
        require_observed_attestation_pass=bool(
            experiment.get("require_observed_attestation_pass", True)
        ),
        evaluation_labels_used_for_scoring=bool(
            experiment.get("evaluation_labels_used_for_scoring", False)
        ),
        implementation_sha256=_implementation_sha256(),
    )
    if core.trust_intervention.failed_check not in TRUST_CHECK_NAMES:
        raise DisagreementExperimentError("controlled failure is not a trust check")
    digest = _artifact_digest(core.model_dump(mode="json"))
    return DisagreementExperimentContract(
        contract_id=f"m6-live-disagreement-contract-{digest[:24]}",
        core=core,
        core_digest=digest,
    )


def install_disagreement_contract(
    *, public_workspace: Path, config_path: Path, client_ids: list[str]
) -> tuple[DisagreementExperimentContract, dict[str, Any]]:
    """Publish the experiment inputs before the round context is signed."""

    contract = build_disagreement_contract(
        config_path=config_path, client_ids=client_ids
    )
    config_target = public_workspace / "m6-disagreement-experiment.yaml"
    contract_target = public_workspace / "m6-disagreement-contract.json"
    write_once(config_target, config_path.read_bytes())
    write_once(
        contract_target, derived_json_bytes(contract.model_dump(mode="json"))
    )
    return contract, {
        "mode": "controlled-live-trust-statistical-disagreement",
        "config_path": config_target.name,
        "config_sha256": sha256_file(config_target),
        "contract_path": contract_target.name,
        "contract_sha256": sha256_file(contract_target),
        "contract_id": contract.contract_id,
    }


def load_bound_disagreement_contract(
    public_workspace: Path,
) -> DisagreementExperimentContract | None:
    """Load and independently reconstruct the experiment bound by M5."""

    training = load_json(public_workspace / "training-contract.json")
    binding = training.get("m6_disagreement_experiment")
    if binding is None:
        return None
    if not isinstance(binding, dict):
        raise DisagreementExperimentError("invalid disagreement binding")
    if (
        binding.get("config_path") != "m6-disagreement-experiment.yaml"
        or binding.get("contract_path") != "m6-disagreement-contract.json"
    ):
        raise DisagreementExperimentError("unsafe disagreement public path")
    config_path = public_workspace / str(binding["config_path"])
    contract_path = public_workspace / str(binding["contract_path"])
    if sha256_file(config_path) != binding.get("config_sha256"):
        raise DisagreementExperimentError("bound disagreement config changed")
    if sha256_file(contract_path) != binding.get("contract_sha256"):
        raise DisagreementExperimentError("bound disagreement contract changed")
    client_ids = [str(item["client_id"]) for item in training.get("clients", [])]
    observed = DisagreementExperimentContract.model_validate(load_json(contract_path))
    expected = build_disagreement_contract(
        config_path=config_path, client_ids=client_ids
    )
    if observed.core.implementation_sha256 != expected.core.implementation_sha256:
        if (
            observed.core.implementation_sha256
            not in SUPPORTED_LEGACY_DISAGREEMENT_IMPLEMENTATION_SHA256
        ):
            raise DisagreementExperimentError(
                "unsupported historical disagreement implementation digest"
            )
        legacy_core = expected.core.model_copy(
            update={"implementation_sha256": observed.core.implementation_sha256}
        )
        legacy_digest = _artifact_digest(legacy_core.model_dump(mode="json"))
        expected = DisagreementExperimentContract(
            contract_id=f"m6-live-disagreement-contract-{legacy_digest[:24]}",
            core=legacy_core,
            core_digest=legacy_digest,
        )
    if observed.model_dump(mode="json") != expected.model_dump(mode="json"):
        raise DisagreementExperimentError(
            "bound disagreement contract does not recompute"
        )
    if observed.contract_id != binding.get("contract_id"):
        raise DisagreementExperimentError("bound disagreement contract id mismatch")
    return observed


def condition_for_client(
    contract: DisagreementExperimentContract, client_id: str
) -> DisagreementCondition:
    if client_id not in contract.core.client_ids:
        raise DisagreementExperimentError(f"client is outside the contract: {client_id}")
    return contract.core.assignments.get(
        client_id, contract.core.background_condition
    )


def effective_trust_checks(
    *,
    checks: list[SecureCheck],
    contract: DisagreementExperimentContract | None,
    client_id: str,
) -> list[SecureCheck]:
    """Return policy inputs while preserving observed checks in the M5 decision."""

    copied = [item.model_copy(deep=True) for item in checks]
    if contract is None:
        return copied
    condition = condition_for_client(contract, client_id)
    trust_failed, _update_anomalous = _condition_flags(condition)
    if not trust_failed:
        return copied
    by_name = {item.name: item for item in copied}
    missing = [name for name in TRUST_CHECK_NAMES if name not in by_name]
    if missing:
        raise DisagreementExperimentError(
            f"observed trust checks are incomplete for {client_id}: {missing}"
        )
    if contract.core.require_observed_attestation_pass and any(
        not by_name[name].passed for name in TRUST_CHECK_NAMES
    ):
        raise DisagreementExperimentError(
            f"observed trust evidence did not pass before intervention: {client_id}"
        )
    failed_name = contract.core.trust_intervention.failed_check
    observed_detail = by_name[failed_name].detail
    by_name[failed_name] = SecureCheck(
        name=failed_name,
        passed=False,
        detail=(
            "controlled M6 counterfactual; observed check passed; "
            f"reason={contract.core.trust_intervention.reason}; "
            f"observed_detail={observed_detail}"
        ),
    )
    return [by_name[item.name] for item in copied]


def _sign_flip_amplify_update(
    *, base_export: dict[str, Any], clean_export: dict[str, Any], scale: float
) -> dict[str, Any]:
    if (
        base_export.get("architecture") != clean_export.get("architecture")
        or base_export.get("class_names") != clean_export.get("class_names")
    ):
        raise DisagreementExperimentError("base and clean update contracts differ")
    base_parameters = base_export.get("parameters", [])
    clean_parameters = clean_export.get("parameters", [])
    if len(base_parameters) != len(clean_parameters):
        raise DisagreementExperimentError("base and clean tensor counts differ")
    candidate = copy.deepcopy(clean_export)
    for base, clean, output in zip(
        base_parameters, clean_parameters, candidate["parameters"], strict=True
    ):
        if (
            base.get("name") != clean.get("name")
            or base.get("shape") != clean.get("shape")
            or base.get("dtype") != clean.get("dtype")
        ):
            raise DisagreementExperimentError("base and clean tensor schemas differ")
        dtype = np.dtype(str(clean["dtype"]))
        base_array = np.asarray(base["values"], dtype=dtype)
        clean_array = np.asarray(clean["values"], dtype=dtype)
        transformed = np.asarray(
            base_array - float(scale) * (clean_array - base_array), dtype=dtype
        )
        if not np.isfinite(transformed).all():
            raise DisagreementExperimentError(
                "sign-flip-amplified update contains non-finite values"
            )
        output["values"] = transformed.tolist()
    return candidate


def prepare_submission_intervention(
    *,
    public_workspace: Path,
    submission_workspace: Path,
    client_id: str,
    clean_export: dict[str, Any],
    round_number: int,
) -> tuple[dict[str, Any], DisagreementSubmissionRecord | None]:
    """Apply a bound treatment before the client signs its Update Bundle."""

    contract = load_bound_disagreement_contract(public_workspace)
    if contract is None:
        return clean_export, None
    condition = condition_for_client(contract, client_id)
    trust_failed, update_anomalous = _condition_flags(condition)
    clean_bytes = derived_json_bytes(clean_export)
    clean_sha256 = sha256_bytes(clean_bytes)
    candidate = clean_export
    clean_path: str | None = None
    scale: float | None = None
    if update_anomalous:
        clean_path = "clean-update.json"
        write_once(submission_workspace / clean_path, clean_bytes)
        scale = contract.core.update_intervention.scale
        candidate = _sign_flip_amplify_update(
            base_export=load_json(public_workspace / "base-model.json"),
            clean_export=clean_export,
            scale=scale,
        )
    candidate_sha256 = sha256_bytes(derived_json_bytes(candidate))
    record = DisagreementSubmissionRecord(
        experiment_id=contract.core.experiment_id,
        contract_id=contract.contract_id,
        contract_digest=contract.core_digest,
        round_number=round_number,
        client_id=client_id,
        condition=condition,
        security_label="unsafe" if trust_failed or update_anomalous else "safe",
        controlled_trust_failure=trust_failed,
        update_intervention_applied=update_anomalous,
        update_intervention_type=(
            contract.core.update_intervention.type if update_anomalous else "none"
        ),
        update_intervention_scale=scale,
        clean_update_sha256=clean_sha256,
        candidate_update_sha256=candidate_sha256,
        clean_update_path=clean_path,
    )
    return candidate, record


def verify_submission_intervention(
    *, public_workspace: Path, submission_workspace: Path, client_id: str
) -> DisagreementSubmissionRecord:
    """Recompute one controlled update derivation from signed artifacts."""

    contract = load_bound_disagreement_contract(public_workspace)
    if contract is None:
        raise DisagreementExperimentError("round has no disagreement contract")
    metrics = load_json(submission_workspace / "metrics.json")
    raw_record = metrics.get("m6_disagreement_experiment")
    record = DisagreementSubmissionRecord.model_validate(raw_record)
    condition = condition_for_client(contract, client_id)
    trust_failed, update_anomalous = _condition_flags(condition)
    update_path = submission_workspace / "update.json"
    actual_candidate_sha256 = sha256_file(update_path)
    expected_intervention_type = (
        contract.core.update_intervention.type if update_anomalous else "none"
    )
    expected_intervention_scale = (
        contract.core.update_intervention.scale if update_anomalous else None
    )
    expected_facts = {
        "experiment id": (record.experiment_id, contract.core.experiment_id),
        "contract id": (record.contract_id, contract.contract_id),
        "contract digest": (record.contract_digest, contract.core_digest),
        "client": (record.client_id, client_id),
        "condition": (record.condition, condition),
        "trust treatment": (record.controlled_trust_failure, trust_failed),
        "update treatment": (record.update_intervention_applied, update_anomalous),
        "security label": (
            record.security_label,
            "unsafe" if trust_failed or update_anomalous else "safe",
        ),
        "update intervention type": (
            record.update_intervention_type,
            expected_intervention_type,
        ),
        "update intervention scale": (
            record.update_intervention_scale,
            expected_intervention_scale,
        ),
        "candidate digest": (
            record.candidate_update_sha256,
            actual_candidate_sha256,
        ),
    }
    mismatches = [
        name for name, (observed, expected) in expected_facts.items() if observed != expected
    ]
    if mismatches:
        raise DisagreementExperimentError(
            f"submission experiment facts differ: {mismatches}"
        )
    if update_anomalous:
        clean_path = submission_workspace / "clean-update.json"
        if record.clean_update_path != clean_path.name or not clean_path.is_file():
            raise DisagreementExperimentError("preserved clean update is missing")
        if sha256_file(clean_path) != record.clean_update_sha256:
            raise DisagreementExperimentError("preserved clean update digest mismatch")
        candidate = _sign_flip_amplify_update(
            base_export=load_json(public_workspace / "base-model.json"),
            clean_export=load_json(clean_path),
            scale=contract.core.update_intervention.scale,
        )
        if sha256_bytes(derived_json_bytes(candidate)) != actual_candidate_sha256:
            raise DisagreementExperimentError(
                "controlled sign-flip amplification does not recompute"
            )
    else:
        if record.clean_update_path is not None:
            raise DisagreementExperimentError("normal update declares a clean sidecar")
        if record.clean_update_sha256 != actual_candidate_sha256:
            raise DisagreementExperimentError("normal clean update digest mismatch")
        if record.clean_update_sha256 != actual_candidate_sha256:
            raise DisagreementExperimentError("normal update differs from clean update")
    return record


def verify_disagreement_round(
    *,
    workspace: Path,
    trust_workspace: Path,
    submissions_root: Path,
    validation_split_path: Path,
    verify_base: bool = True,
) -> dict[str, Any]:
    """Verify live treatments, policy inputs, and the resulting aggregation."""

    from .in_round_admission import (
        verify_in_round_secure_round,
        verify_in_round_signature,
    )
    from .in_round_admission_models import InRoundContributionDecision
    from .secure_round import _coordinator_public_key, _load_context, _verify_signed
    from .secure_round_models import ContributionDecision

    errors: list[str] = []
    if verify_base:
        base_verification = verify_in_round_secure_round(
            workspace=workspace,
            trust_workspace=trust_workspace,
            submissions_root=submissions_root,
            validation_split_path=validation_split_path,
        )
        if base_verification["status"] != "verified":
            errors.extend(f"M5: {item}" for item in base_verification["errors"])
    else:
        base_verification = {"status": "skipped", "errors": []}
    context = _load_context(workspace / "public")
    contract = load_bound_disagreement_contract(workspace / "public")
    if contract is None:
        errors.append("round has no bound disagreement contract")
        return {
            "status": "failed",
            "error_count": len(errors),
            "errors": errors,
            "workspace": str(workspace),
        }
    scenario_counts: Counter[str] = Counter()
    policy_status_counts: dict[str, Counter[str]] = {}
    policy_evaluation: dict[str, dict[str, int]] = {}
    controlled_records: list[tuple[DisagreementSubmissionRecord, Any]] = []
    public_key = _coordinator_public_key(workspace)
    observed_attestation_pass_count = 0
    for client in context.core.clients:
        client_id = client.client_id
        try:
            record = verify_submission_intervention(
                public_workspace=workspace / "public",
                submission_workspace=submissions_root / client_id,
                client_id=client_id,
            )
            scenario_counts[record.condition] += 1
            trust_decision = ContributionDecision.model_validate(
                load_json(workspace / "decisions" / f"{client_id}.json")
            )
            if not _verify_signed(trust_decision, public_key):
                raise DisagreementExperimentError("observed trust decision is unsigned")
            observed_trust = {
                item.name: item for item in trust_decision.core.checks
            }
            if all(
                observed_trust.get(name) is not None
                and observed_trust[name].passed
                for name in TRUST_CHECK_NAMES
            ):
                observed_attestation_pass_count += 1
            decision = InRoundContributionDecision.model_validate(
                load_json(workspace / "in-round-decisions" / f"{client_id}.json")
            )
            if not verify_in_round_signature(decision, public_key):
                raise DisagreementExperimentError("in-round decision is unsigned")
            expected_checks = effective_trust_checks(
                checks=trust_decision.core.checks,
                contract=contract,
                client_id=client_id,
            )
            if [item.model_dump(mode="json") for item in decision.core.m5_checks] != [
                item.model_dump(mode="json") for item in expected_checks
            ]:
                raise DisagreementExperimentError(
                    "effective trust checks do not match the controlled treatment"
                )
            if decision.core.statistics is None or len(decision.core.policy_decisions) != 4:
                raise DisagreementExperimentError(
                    "complete statistical and four-policy decisions are missing"
                )
            for policy in decision.core.policy_decisions:
                policy_status_counts.setdefault(policy.policy, Counter())[policy.status] += 1
            if client_id in contract.core.assignments:
                controlled_records.append((record, decision))
        except (OSError, TypeError, ValueError, DisagreementExperimentError) as exc:
            errors.append(f"{client_id}: {exc}")
    if len(controlled_records) != 4:
        errors.append("controlled 2x2 matrix does not contain four verified records")
    for policy_name in ("tpm_only", "statistics_only", "sequential", "gated_composite"):
        counts = Counter({"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0})
        for record, decision in controlled_records:
            policy = next(
                item for item in decision.core.policy_decisions if item.policy == policy_name
            )
            unsafe = record.security_label == "unsafe"
            quarantined = not policy.contributes
            if unsafe and quarantined:
                counts["true_positive"] += 1
            elif not unsafe and quarantined:
                counts["false_positive"] += 1
            elif not unsafe and not quarantined:
                counts["true_negative"] += 1
            else:
                counts["false_negative"] += 1
        policy_evaluation[policy_name] = dict(counts)
    return {
        "status": "verified" if not errors else "failed",
        "error_count": len(errors),
        "errors": errors,
        "experiment_id": contract.core.experiment_id,
        "contract_id": contract.contract_id,
        "campaign_id": context.core.campaign_id,
        "round_number": context.core.round_number,
        "observed_attestation_pass_count": observed_attestation_pass_count,
        "controlled_trust_failure_count": sum(
            item.controlled_trust_failure for item, _decision in controlled_records
        ),
        "controlled_update_intervention_count": sum(
            item.update_intervention_applied for item, _decision in controlled_records
        ),
        "scenario_counts": dict(sorted(scenario_counts.items())),
        "policy_status_counts": {
            name: dict(sorted(counts.items()))
            for name, counts in sorted(policy_status_counts.items())
        },
        "controlled_policy_evaluation": policy_evaluation,
        "m5_aggregation_recomputed": base_verification["status"] == "verified",
        "submission_interventions_recomputed": not any(
            ":" in item and item.split(":", 1)[0].startswith("client")
            for item in errors
        ),
        "workspace": str(workspace),
    }
