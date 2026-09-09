"""M8.5 v2 accounting for a preserved in-round disagreement campaign."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any

from .attestation import verify_attestation_signature
from .campaign_accounting import (
    ATTESTATION_REFRESH_ROUNDS,
    EXPECTED_OUTPUT_FILES,
    EXPECTED_ROUND_COUNT,
    _RecoveryReader,
    _preserved_workspace_root,
    _safe_relative,
    _signed_challenge,
    _source_manifests,
)
from .campaign_accounting_models import (
    ADMISSION_CHECK_NAMES,
    CampaignTrustAccounting,
)
from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .crypto import load_public_key
from .disagreement_experiment import (
    _sign_flip_amplify_update,
    effective_trust_checks,
)
from .disagreement_experiment_models import (
    DisagreementExperimentContract,
    DisagreementSubmissionRecord,
)
from .in_round_admission import verify_in_round_signature
from .in_round_admission_models import (
    InRoundAdmissionContract,
    InRoundContributionDecision,
    InRoundSecureCheckpoint,
)
from .in_round_campaign_accounting_models import (
    CONTRIBUTING_STATUSES,
    IN_ROUND_ACCOUNTING_PROFILE,
    IN_ROUND_ACCOUNTING_STATE,
    POLICY_NAMES,
    InRoundCampaignAccountingCore,
    InRoundCampaignAccountingEnvelope,
    InRoundCampaignAccountingReport,
    InRoundClientAccount,
    InRoundContributionAccount,
    InRoundRoundAccount,
    PolicyOutcomeAccount,
)
from .preservation_models import PreservationManifest
from .preprocessing import derived_json_bytes
from .secure_round import EXPECTED_CLIENTS, GENESIS_DIGEST, _verify_signed
from .secure_round_models import (
    ContributionDecision,
    SecureCampaignManifest,
    SecureRoundContext,
    UpdateBundle,
)
from .storage import load_json, write_json_once, write_once
from .trust import verify_enrollment_record
from .trust_models import (
    AttestationChallenge,
    AttestationResultV2,
    EnrollmentRecord,
)


class InRoundCampaignAccountingError(ValueError):
    """Raised when the preserved in-round ledger is incomplete or inconsistent."""


def _ensure(condition: bool, message: str) -> None:
    if not condition:
        raise InRoundCampaignAccountingError(message)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _decimal(value: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise InRoundCampaignAccountingError("invalid effective-weight decimal") from exc
    _ensure(parsed.is_finite() and parsed >= 0, "invalid effective-weight decimal")
    return parsed


def _settings(config_path: Path) -> tuple[Path, dict[str, Any], str]:
    value, config_sha256 = load_yaml(config_path)
    if value.get("schema_version") != "2.0":
        raise InRoundCampaignAccountingError(
            "unsupported in-round campaign-accounting schema"
        )
    settings = value.get("campaign_accounting")
    if not isinstance(settings, dict):
        raise InRoundCampaignAccountingError(
            "missing in-round campaign-accounting configuration"
        )
    expected = {
        "expected_round_count": EXPECTED_ROUND_COUNT,
        "required_client_count": len(EXPECTED_CLIENTS),
        "attestation_refresh_interval_rounds": ATTESTATION_REFRESH_ROUNDS,
        "source_profile": IN_ROUND_ACCOUNTING_PROFILE,
    }
    for name, expected_value in expected.items():
        if settings.get(name) != expected_value:
            raise InRoundCampaignAccountingError(
                f"in-round campaign-accounting configuration mismatch: {name}"
            )
    if not isinstance(settings.get("recovery_workspace"), str):
        raise InRoundCampaignAccountingError("missing recovery workspace")
    for name in (
        "campaign_relative_path",
        "trust_relative_path",
        "partition_relative_path",
    ):
        configured = settings.get(name)
        if not isinstance(configured, str):
            raise InRoundCampaignAccountingError(f"missing source path: {name}")
        path = PurePosixPath(_safe_relative(configured))
        if len(path.parts) < 2 or path.parts[0] != "artifacts":
            raise InRoundCampaignAccountingError(
                f"accounting source path must be below artifacts/: {name}"
            )
    experiment_id = settings.get("expected_disagreement_experiment_id")
    if not isinstance(experiment_id, str) or not experiment_id:
        raise InRoundCampaignAccountingError(
            "missing expected disagreement experiment id"
        )
    return config_path.resolve().parent.parent, settings, config_sha256


def is_in_round_accounting_config(config_path: Path) -> bool:
    value, _digest = load_yaml(config_path)
    return (
        value.get("schema_version") == "2.0"
        and isinstance(value.get("campaign_accounting"), dict)
        and value["campaign_accounting"].get("source_profile")
        == IN_ROUND_ACCOUNTING_PROFILE
    )


def is_in_round_accounting_workspace(workspace: Path) -> bool:
    path = workspace / "manifest.json"
    if not path.is_file():
        return False
    try:
        value = load_json(path)
    except (OSError, TypeError, ValueError):
        return False
    return (
        value.get("artifact_type")
        == "m8_in_round_campaign_invariant_accounting_envelope"
    )


def _condition_facts(
    contract: DisagreementExperimentContract, client_id: str
) -> tuple[str, str, bool, bool]:
    condition = contract.core.assignments.get(
        client_id, contract.core.background_condition
    )
    trust_failed = condition.startswith("trust_inadmissible")
    update_anomalous = condition.endswith("statistics_anomalous")
    security_label = "unsafe" if trust_failed or update_anomalous else "safe"
    return condition, security_label, trust_failed, update_anomalous


def _verify_contracts(
    *, reader: _RecoveryReader, round_root: str, checkpoint: InRoundSecureCheckpoint
) -> tuple[InRoundAdmissionContract, DisagreementExperimentContract, str]:
    admission_path = f"{round_root}/public/in-round-admission-contract.json"
    admission = InRoundAdmissionContract.model_validate(reader.json(admission_path))
    admission_digest = sha256_bytes(
        derived_json_bytes(admission.core.model_dump(mode="json"))
    )
    _ensure(
        admission.core_digest == admission_digest
        and admission.contract_id == f"in-round-contract-{admission_digest[:24]}"
        and reader.digest(admission_path)
        == checkpoint.core.admission_contract_sha256
        and reader.digest(f"{round_root}/public/in-round-admission.yaml")
        == checkpoint.core.policy_config_sha256
        and checkpoint.core.admission_contract_id == admission.contract_id,
        f"round {checkpoint.core.round_number} in-round contract binding is invalid",
    )
    disagreement_path = f"{round_root}/public/m6-disagreement-contract.json"
    disagreement = DisagreementExperimentContract.model_validate(
        reader.json(disagreement_path)
    )
    disagreement_digest = sha256_bytes(
        derived_json_bytes(disagreement.core.model_dump(mode="json"))
    )
    _ensure(
        disagreement.core_digest == disagreement_digest
        and disagreement.contract_id
        == f"m6-live-disagreement-contract-{disagreement_digest[:24]}"
        and reader.digest(f"{round_root}/public/m6-disagreement-experiment.yaml")
        == disagreement.core.config_sha256,
        f"round {checkpoint.core.round_number} disagreement contract is invalid",
    )
    return admission, disagreement, reader.digest(disagreement_path)


def _verify_disagreement_record(
    *,
    reader: _RecoveryReader,
    round_root: str,
    client_id: str,
    bundle: UpdateBundle,
    metrics: dict[str, Any],
    disagreement: DisagreementExperimentContract,
) -> DisagreementSubmissionRecord:
    record = DisagreementSubmissionRecord.model_validate(
        metrics.get("m6_disagreement_experiment")
    )
    condition, security_label, trust_failed, update_anomalous = _condition_facts(
        disagreement, client_id
    )
    _ensure(
        record.experiment_id == disagreement.core.experiment_id
        and record.contract_id == disagreement.contract_id
        and record.contract_digest == disagreement.core_digest
        and record.round_number == bundle.core.round_number
        and record.client_id == client_id
        and record.condition == condition
        and record.security_label == security_label
        and record.controlled_trust_failure == trust_failed
        and record.update_intervention_applied == update_anomalous
        and record.candidate_update_sha256 == bundle.core.update_sha256,
        f"disagreement record binding is invalid: round {bundle.core.round_number} {client_id}",
    )
    update_path = f"{round_root}/submissions/{client_id}/update.json"
    _ensure(
        reader.digest(update_path) == record.candidate_update_sha256,
        f"candidate update digest mismatch: round {bundle.core.round_number} {client_id}",
    )
    if update_anomalous:
        clean_path = f"{round_root}/submissions/{client_id}/clean-update.json"
        _ensure(
            record.clean_update_path == "clean-update.json"
            and reader.digest(clean_path) == record.clean_update_sha256,
            f"clean update binding is invalid: round {bundle.core.round_number} {client_id}",
        )
        candidate = _sign_flip_amplify_update(
            base_export=reader.json(f"{round_root}/public/base-model.json"),
            clean_export=reader.json(clean_path),
            scale=disagreement.core.update_intervention.scale,
        )
        _ensure(
            sha256_bytes(derived_json_bytes(candidate))
            == record.candidate_update_sha256,
            f"update intervention does not recompute: round {bundle.core.round_number} {client_id}",
        )
    else:
        _ensure(
            record.clean_update_path is None
            and record.clean_update_sha256 == record.candidate_update_sha256,
            f"normal update differs from clean update: round {bundle.core.round_number} {client_id}",
        )
    return record


def _derive_core(
    *,
    recovery_workspace: Path,
    campaign_relative_path: str,
    trust_relative_path: str,
    partition_relative_path: str,
    expected_experiment_id: str,
) -> InRoundCampaignAccountingCore:
    package, recovery = _source_manifests(recovery_workspace)
    archive_path = recovery_workspace / recovery.core.archive_name
    clients = list(EXPECTED_CLIENTS)
    with _RecoveryReader(archive_path, package) as reader:
        preservation = PreservationManifest.model_validate(
            reader.assurance_json("assurance/m8.1/preservation-manifest.json")
        )
        _ensure(
            preservation.preservation_id == package.core.source_preservation_id,
            "recovery package preservation identity mismatch",
        )
        preserved_campaign_root = _preserved_workspace_root(
            paths=[item.relative_path for item in preservation.core.campaign_assurance],
            required_suffix=("campaign-manifest.json",),
            label="campaign",
        )
        preserved_trust_root = _preserved_workspace_root(
            paths=[item.relative_path for item in preservation.core.trust_assurance],
            required_suffix=("registry", "index.json"),
            label="trust",
        )
        campaign_root = _safe_relative(campaign_relative_path)
        trust_root = _safe_relative(trust_relative_path)
        partition_root = _safe_relative(partition_relative_path)
        _ensure(
            campaign_root == preserved_campaign_root,
            "configured campaign workspace differs from preservation inventory",
        )
        _ensure(
            trust_root == preserved_trust_root,
            "configured trust workspace differs from preservation inventory",
        )
        _ensure(
            any(
                item.relative_path == f"{partition_root}/manifest.json"
                for item in preservation.core.derivation_chain
            ),
            "configured partition workspace differs from preservation inventory",
        )

        campaign_path = f"{campaign_root}/campaign-manifest.json"
        campaign_sha256 = reader.digest(campaign_path)
        campaign = SecureCampaignManifest.model_validate(reader.json(campaign_path))
        coordinator_key = load_public_key(
            reader.read(f"{campaign_root}/authority/round-coordinator.public.pem")
        )
        enrollment_key = load_public_key(
            reader.read(f"{trust_root}/authority/enrollment-authority.public.pem")
        )
        attestation_key = load_public_key(
            reader.read(f"{trust_root}/authority/attestation-verifier.public.pem")
        )
        registry = reader.json(f"{trust_root}/registry/index.json")
        _ensure(_verify_signed(campaign, coordinator_key), "invalid campaign signature")
        _ensure(
            campaign.core.round_count == EXPECTED_ROUND_COUNT
            and campaign.core.required_client_count == len(clients)
            and [item.round_number for item in campaign.core.rounds]
            == list(range(1, EXPECTED_ROUND_COUNT + 1)),
            "signed campaign contract differs from the M8.5 v2 profile",
        )
        _ensure(
            preservation.core.selected_derivation_round == campaign.core.selected_round,
            "M8.1 selected derivation round differs from the campaign",
        )

        enrollment_cache: dict[str, EnrollmentRecord] = {}
        result_cache: dict[str, AttestationResultV2] = {}
        challenge_cache: dict[str, AttestationChallenge] = {}
        attestation_rounds: dict[tuple[str, str], list[int]] = defaultdict(list)
        contributions: list[InRoundContributionAccount] = []
        rounds: list[InRoundRoundAccount] = []
        policy_status_counts = {name: Counter() for name in POLICY_NAMES}
        policy_confusion = {name: Counter() for name in POLICY_NAMES}
        previous_checkpoint_sha256 = GENESIS_DIGEST
        previous_model_sha256: str | None = None
        coordinator_signature_count = 1
        disagreement_contract_id: str | None = None
        disagreement_contract_sha256: str | None = None
        disagreement_experiment_id: str | None = None

        partition = reader.json(f"{partition_root}/manifest.json")
        validation_entry = partition.get("server_evaluation_splits", {}).get(
            "validation", {}
        )
        validation_relative_path = _safe_relative(str(validation_entry.get("path", "")))
        validation_path = f"{partition_root}/{validation_relative_path}"

        for round_number in range(1, EXPECTED_ROUND_COUNT + 1):
            round_root = f"{campaign_root}/rounds/round-{round_number:03d}"
            context_path = f"{round_root}/public/round-context.json"
            checkpoint_path = f"{round_root}/checkpoint/manifest.json"
            context = SecureRoundContext.model_validate(reader.json(context_path))
            checkpoint = InRoundSecureCheckpoint.model_validate(
                reader.json(checkpoint_path)
            )
            context_sha256 = reader.digest(context_path)
            checkpoint_sha256 = reader.digest(checkpoint_path)
            _ensure(
                _verify_signed(context, coordinator_key)
                and verify_in_round_signature(checkpoint, coordinator_key),
                f"round {round_number} coordinator signature is invalid",
            )
            coordinator_signature_count += 2
            admission, disagreement, disagreement_sha256 = _verify_contracts(
                reader=reader, round_root=round_root, checkpoint=checkpoint
            )
            _ensure(
                disagreement.core.experiment_id == expected_experiment_id,
                f"round {round_number} disagreement experiment id mismatch",
            )
            if disagreement_contract_id is None:
                disagreement_contract_id = disagreement.contract_id
                disagreement_contract_sha256 = disagreement_sha256
                disagreement_experiment_id = disagreement.core.experiment_id
            else:
                _ensure(
                    disagreement.contract_id == disagreement_contract_id
                    and disagreement_sha256 == disagreement_contract_sha256,
                    "disagreement contract changed during the campaign",
                )
            _ensure(
                checkpoint.core.validation_split_sha256
                == admission.core.validation_split_sha256
                == reader.digest(validation_path),
                f"round {round_number} validation split binding is invalid",
            )
            context_clients = [item.client_id for item in context.core.clients]
            _ensure(
                context.core.campaign_id == campaign.core.campaign_id
                and checkpoint.core.campaign_id == campaign.core.campaign_id
                and context.core.round_number == round_number
                and checkpoint.core.round_number == round_number
                and context_clients == clients
                and context.core.required_client_count == len(clients)
                and checkpoint.core.required_client_count == len(clients)
                and checkpoint.core.context_id == context.context_id
                and checkpoint.core.context_digest == context.core_digest
                and context.core.previous_checkpoint_sha256
                == previous_checkpoint_sha256
                and checkpoint.core.previous_checkpoint_sha256
                == previous_checkpoint_sha256
                and checkpoint.core.base_model_sha256
                == context.core.base_model_sha256
                and (
                    previous_model_sha256 is None
                    or context.core.base_model_sha256 == previous_model_sha256
                ),
                f"round {round_number} breaks the signed checkpoint/model chain",
            )
            _ensure(
                reader.digest(f"{round_root}/public/base-model.json")
                == context.core.base_model_sha256
                and reader.digest(f"{round_root}/public/training-contract.json")
                == context.core.training_contract_sha256
                and reader.digest(f"{round_root}/public/partition-manifest.json")
                == context.core.partition_manifest_sha256
                and reader.digest(f"{round_root}/public/federation.yaml")
                == context.core.federation_config_sha256
                and reader.digest(f"{round_root}/checkpoint/global-model.json")
                == checkpoint.core.global_model_sha256,
                f"round {round_number} public/checkpoint binding is invalid",
            )
            reference = campaign.core.rounds[round_number - 1]
            round_validation_path = (
                f"{campaign_root}/evaluation/round-{round_number:03d}-validation.json"
            )
            _ensure(
                reference.context_id == context.context_id
                and reference.context_sha256 == context_sha256
                and reference.checkpoint_id == checkpoint.checkpoint_id
                and reference.checkpoint_sha256 == checkpoint_sha256
                and reference.base_model_sha256 == context.core.base_model_sha256
                and reference.global_model_sha256 == checkpoint.core.global_model_sha256
                and reference.validation_metrics_sha256
                == reader.digest(round_validation_path)
                and reference.accepted_count == checkpoint.core.accepted_count,
                f"round {round_number} differs from the signed campaign reference",
            )
            _ensure(
                checkpoint.core.evaluated_count == len(clients)
                and checkpoint.core.trust_accepted_count == len(clients)
                and checkpoint.core.missing_client_ids == [],
                f"round {round_number} submission coverage is incomplete",
            )
            issued_at = _parse_time(context.core.issued_at)
            expires_at = _parse_time(context.core.expires_at)
            checkpoint_at = _parse_time(checkpoint.core.created_at)
            _ensure(
                issued_at <= checkpoint_at < expires_at,
                f"round {round_number} checkpoint is outside the signed context",
            )
            contracts = {item.client_id: item for item in context.core.clients}
            checkpoint_inputs = {
                item.client_id: item for item in checkpoint.core.accepted_inputs
            }
            round_contributions: list[InRoundContributionAccount] = []
            expected_quarantined_sha256: list[str] = []
            expected_input_clients: list[str] = []

            for client_id in clients:
                client_contract = contracts[client_id]
                enrollment = enrollment_cache.get(client_id)
                if enrollment is None:
                    entry = registry.get("enrollments", {}).get(client_id)
                    _ensure(isinstance(entry, dict), f"missing registry entry: {client_id}")
                    enrollment_path = f"{trust_root}/{_safe_relative(str(entry['record_path']))}"
                    enrollment = EnrollmentRecord.model_validate(
                        reader.json(enrollment_path)
                    )
                    _ensure(
                        digest_object(enrollment.model_dump(mode="json"))
                        == entry.get("record_digest")
                        and entry.get("enrollment_id") == enrollment.core.enrollment_id
                        and verify_enrollment_record(enrollment, enrollment_key)
                        and enrollment.core.client_id == client_id
                        and enrollment.core.enrollment_id
                        == client_contract.enrollment_id
                    and enrollment.core.node_id == client_contract.node_id
                    and enrollment.core.status == "active",
                        f"invalid enrollment binding: {client_id}",
                    )
                    enrollment_cache[client_id] = enrollment

                submission_root = f"{round_root}/submissions/{client_id}"
                bundle_path = f"{submission_root}/bundle.json"
                metrics_path = f"{submission_root}/metrics.json"
                trust_decision_path = f"{round_root}/decisions/{client_id}.json"
                in_round_decision_path = (
                    f"{round_root}/in-round-decisions/{client_id}.json"
                )
                bundle = UpdateBundle.model_validate(reader.json(bundle_path))
                metrics = reader.json(metrics_path)
                trust_decision = ContributionDecision.model_validate(
                    reader.json(trust_decision_path)
                )
                in_round_decision = InRoundContributionDecision.model_validate(
                    reader.json(in_round_decision_path)
                )
                bundle_sha256 = reader.digest(bundle_path)
                trust_decision_sha256 = reader.digest(trust_decision_path)
                in_round_decision_sha256 = reader.digest(in_round_decision_path)
                esk_key = load_public_key(enrollment.core.esk_public_key_pem.encode())
                _ensure(
                    _verify_signed(bundle, esk_key),
                    f"invalid bundle signature: round {round_number} {client_id}",
                )
                _ensure(
                    _verify_signed(trust_decision, coordinator_key)
                    and verify_in_round_signature(in_round_decision, coordinator_key),
                    f"invalid decision signature: round {round_number} {client_id}",
                )
                coordinator_signature_count += 2
                check_names = [item.name for item in trust_decision.core.checks]
                _ensure(
                    trust_decision.core.status == "accepted"
                    and check_names == list(ADMISSION_CHECK_NAMES)
                    and all(item.passed for item in trust_decision.core.checks),
                    f"observed M5 admission failed: round {round_number} {client_id}",
                )
                _ensure(
                    reader.digest(metrics_path) == bundle.core.metrics_sha256
                    and reader.digest(f"{submission_root}/update.json")
                    == bundle.core.update_sha256,
                    f"signed submission digest mismatch: round {round_number} {client_id}",
                )
                record = _verify_disagreement_record(
                    reader=reader,
                    round_root=round_root,
                    client_id=client_id,
                    bundle=bundle,
                    metrics=metrics,
                    disagreement=disagreement,
                )

                result_id = client_contract.attestation_result_id
                result = result_cache.get(result_id)
                if result is None:
                    result_path = f"{trust_root}/results/{result_id}.json"
                    result = AttestationResultV2.model_validate(reader.json(result_path))
                    _ensure(
                        reader.digest(result_path)
                        == client_contract.attestation_result_sha256
                        and result.result_id == result_id
                        and verify_attestation_signature(result, attestation_key),
                        f"invalid attestation result: {result_id}",
                    )
                    result_cache[result_id] = result
                challenge_id = result.core.challenge_id
                challenge = challenge_cache.get(challenge_id)
                if challenge is None:
                    challenge_path = f"{trust_root}/challenges/{challenge_id}.json"
                    challenge = AttestationChallenge.model_validate(
                        reader.json(challenge_path)
                    )
                    _ensure(
                        _signed_challenge(challenge, attestation_key),
                        f"invalid attestation challenge: {challenge_id}",
                    )
                    challenge_cache[challenge_id] = challenge
                _ensure(
                    result.core.status in {"passed", "passed_with_warning"}
                    and result.core.client_id == client_id
                    and result.core.node_id == client_contract.node_id
                    and result.core.enrollment_id == client_contract.enrollment_id
                    and result.core.transport_peer_fingerprint
                    == enrollment.core.tls_certificate_sha256
                    and result.signature.trust_level == enrollment.core.trust_level
                    and challenge.core.challenge_id == challenge_id
                    and challenge.core.client_id == client_id
                    and challenge.core.node_id == client_contract.node_id
                    and challenge.core.enrollment_id == client_contract.enrollment_id
                    and challenge.core.nonce == result.core.nonce
                    and challenge.core.pcr_bank == result.core.pcr_bank
                    and challenge.core.pcr_selection == result.core.pcr_selection
                    and challenge.core.policy_id == result.core.policy_id
                    and challenge.core.policy_version == result.core.policy_version
                    and challenge.core.baseline_id == result.core.baseline_id
                    and challenge.core.baseline_version == result.core.baseline_version,
                    f"attestation identity binding is invalid: {result_id}",
                )
                _ensure(
                    bundle.core.campaign_id == campaign.core.campaign_id
                    and bundle.core.context_id == context.context_id
                    and bundle.core.context_digest == context.core_digest
                    and bundle.core.round_number == round_number
                    and bundle.core.client_id == client_id
                    and bundle.core.node_id == client_contract.node_id
                    and bundle.core.enrollment_id == client_contract.enrollment_id
                    and bundle.core.attestation_result_id == result_id
                    and bundle.core.attestation_result_sha256
                    == client_contract.attestation_result_sha256
                    and bundle.core.base_model_sha256
                    == context.core.base_model_sha256
                    and bundle.core.snapshot_sha256 == client_contract.snapshot_sha256
                    and bundle.core.num_examples == client_contract.train_row_count
                    and bundle.signature.key_id == enrollment.core.esk_key_id
                    and bundle.signature.trust_level == enrollment.core.trust_level,
                    f"bundle/context binding is invalid: round {round_number} {client_id}",
                )
                _ensure(
                    trust_decision.core.bundle_id == bundle.bundle_id
                    and trust_decision.core.bundle_sha256 == bundle_sha256
                    and trust_decision.core.client_id == client_id
                    and trust_decision.core.round_number == round_number,
                    f"trust decision binding is invalid: round {round_number} {client_id}",
                )
                expected_effective_checks = effective_trust_checks(
                    checks=trust_decision.core.checks,
                    contract=disagreement,
                    client_id=client_id,
                )
                _ensure(
                    [item.model_dump(mode="json") for item in in_round_decision.core.m5_checks]
                    == [item.model_dump(mode="json") for item in expected_effective_checks]
                    and in_round_decision.core.campaign_id == campaign.core.campaign_id
                    and in_round_decision.core.context_id == context.context_id
                    and in_round_decision.core.context_digest == context.core_digest
                    and in_round_decision.core.contract_id == admission.contract_id
                    and in_round_decision.core.contract_digest == admission.core_digest
                    and in_round_decision.core.round_number == round_number
                    and in_round_decision.core.client_id == client_id
                    and in_round_decision.core.bundle_id == bundle.bundle_id
                    and in_round_decision.core.bundle_sha256 == bundle_sha256
                    and in_round_decision.core.update_sha256 == bundle.core.update_sha256
                    and in_round_decision.core.trust_decision_id
                    == trust_decision.decision_id
                    and in_round_decision.core.trust_decision_sha256
                    == trust_decision_sha256,
                    f"in-round decision binding is invalid: round {round_number} {client_id}",
                )
                policies = in_round_decision.core.policy_decisions
                _ensure(
                    [item.policy for item in policies] == list(POLICY_NAMES)
                    and in_round_decision.core.primary_decision is not None
                    and in_round_decision.core.primary_decision.model_dump(mode="json")
                    == policies[-1].model_dump(mode="json")
                    and in_round_decision.core.final_status == policies[-1].status,
                    f"policy decision set is invalid: round {round_number} {client_id}",
                )
                contributes = in_round_decision.core.final_status in CONTRIBUTING_STATUSES
                downweighted = (
                    in_round_decision.core.final_status == "accepted_downweighted"
                )
                expected_weight = (
                    Decimal(in_round_decision.core.num_examples)
                    if in_round_decision.core.final_status == "accepted"
                    else Decimal(in_round_decision.core.num_examples)
                    * Decimal(str(admission.core.accepted_downweight_factor))
                    if downweighted
                    else Decimal(0)
                )
                _ensure(
                    _decimal(in_round_decision.core.effective_weight_decimal)
                    == expected_weight,
                    f"effective weight is invalid: round {round_number} {client_id}",
                )
                if contributes:
                    expected_input_clients.append(client_id)
                    checkpoint_input = checkpoint_inputs.get(client_id)
                    _ensure(
                        checkpoint_input is not None
                        and checkpoint_input.decision_id
                        == in_round_decision.decision_id
                        and checkpoint_input.decision_sha256
                        == in_round_decision_sha256
                        and checkpoint_input.trust_decision_id
                        == trust_decision.decision_id
                        and checkpoint_input.trust_decision_sha256
                        == trust_decision_sha256
                        and checkpoint_input.bundle_id == bundle.bundle_id
                        and checkpoint_input.bundle_sha256 == bundle_sha256
                        and checkpoint_input.update_sha256 == bundle.core.update_sha256
                        and checkpoint_input.num_examples == bundle.core.num_examples
                        and _decimal(checkpoint_input.effective_weight_decimal)
                        == expected_weight
                        and checkpoint_input.status
                        == in_round_decision.core.final_status,
                        f"checkpoint input is invalid: round {round_number} {client_id}",
                    )
                else:
                    expected_quarantined_sha256.append(in_round_decision_sha256)
                    _ensure(
                        client_id not in checkpoint_inputs,
                        f"quarantined client entered checkpoint: round {round_number} {client_id}",
                    )

                generated_at = _parse_time(bundle.core.generated_at)
                trust_decided_at = _parse_time(trust_decision.core.decided_at)
                in_round_decided_at = _parse_time(in_round_decision.core.decided_at)
                _ensure(
                    issued_at
                    <= generated_at
                    <= trust_decided_at
                    <= in_round_decided_at
                    <= checkpoint_at
                    < expires_at
                    and _parse_time(enrollment.core.valid_from)
                    <= in_round_decided_at
                    < _parse_time(enrollment.core.valid_until)
                    and _parse_time(challenge.core.issued_at)
                    <= _parse_time(result.core.evaluated_at)
                    < _parse_time(challenge.core.expires_at)
                    and in_round_decided_at < _parse_time(result.core.expires_at),
                    f"historical time binding is invalid: round {round_number} {client_id}",
                )
                policy_statuses = {item.policy: item.status for item in policies}
                for policy in policies:
                    policy_status_counts[policy.policy][policy.status] += 1
                    if client_id in disagreement.core.assignments:
                        unsafe = record.security_label == "unsafe"
                        quarantined = not policy.contributes
                        outcome = (
                            "true_positive"
                            if unsafe and quarantined
                            else "false_positive"
                            if not unsafe and quarantined
                            else "true_negative"
                            if not unsafe
                            else "false_negative"
                        )
                        policy_confusion[policy.policy][outcome] += 1
                contribution = InRoundContributionAccount(
                    round_number=round_number,
                    client_id=client_id,
                    node_id=client_contract.node_id,
                    enrollment_id=client_contract.enrollment_id,
                    attestation_result_id=result_id,
                    attestation_result_sha256=client_contract.attestation_result_sha256,
                    challenge_id=challenge_id,
                    context_id=context.context_id,
                    context_digest=context.core_digest,
                    bundle_id=bundle.bundle_id,
                    bundle_sha256=bundle_sha256,
                    trust_decision_id=trust_decision.decision_id,
                    trust_decision_sha256=trust_decision_sha256,
                    in_round_decision_id=in_round_decision.decision_id,
                    in_round_decision_sha256=in_round_decision_sha256,
                    snapshot_sha256=client_contract.snapshot_sha256,
                    snapshot_manifest_sha256=client_contract.snapshot_manifest_sha256,
                    update_sha256=bundle.core.update_sha256,
                    metrics_sha256=bundle.core.metrics_sha256,
                    tensor_schema_sha256=bundle.core.tensor_schema_sha256,
                    num_examples=bundle.core.num_examples,
                    effective_weight_decimal=in_round_decision.core.effective_weight_decimal,
                    generated_at=bundle.core.generated_at,
                    trust_decided_at=trust_decision.core.decided_at,
                    in_round_decided_at=in_round_decision.core.decided_at,
                    observed_admission_checks=check_names,
                    primary_policy="gated_composite",
                    final_status=in_round_decision.core.final_status,
                    contributes=contributes,
                    downweighted=downweighted,
                    policy_statuses=policy_statuses,
                    disagreement_condition=record.condition,
                    controlled_assignment=(
                        client_id in disagreement.core.assignments
                    ),
                    security_label=record.security_label,
                    controlled_trust_failure=record.controlled_trust_failure,
                    update_intervention_applied=record.update_intervention_applied,
                    clean_update_sha256=record.clean_update_sha256,
                    candidate_update_sha256=record.candidate_update_sha256,
                )
                contributions.append(contribution)
                round_contributions.append(contribution)
                attestation_rounds[(client_id, result_id)].append(round_number)

            contributing_items = [item for item in round_contributions if item.contributes]
            _ensure(
                [item.client_id for item in checkpoint.core.accepted_inputs]
                == expected_input_clients
                and checkpoint.core.quarantined_decision_sha256
                == expected_quarantined_sha256
                and checkpoint.core.accepted_count == len(contributing_items)
                and checkpoint.core.downweighted_count
                == sum(item.downweighted for item in round_contributions)
                and checkpoint.core.quarantined_count
                == sum(not item.contributes for item in round_contributions)
                and checkpoint.core.total_examples
                == sum(item.num_examples for item in contributing_items)
                and _decimal(checkpoint.core.total_effective_weight_decimal)
                == sum(
                    (_decimal(item.effective_weight_decimal) for item in contributing_items),
                    Decimal(0),
                ),
                f"round {round_number} checkpoint totals are invalid",
            )
            rounds.append(
                InRoundRoundAccount(
                    round_number=round_number,
                    context_id=context.context_id,
                    context_sha256=context_sha256,
                    checkpoint_id=checkpoint.checkpoint_id,
                    checkpoint_sha256=checkpoint_sha256,
                    previous_checkpoint_sha256=previous_checkpoint_sha256,
                    base_model_sha256=context.core.base_model_sha256,
                    global_model_sha256=checkpoint.core.global_model_sha256,
                    required_client_count=len(clients),
                    submitted_count=len(round_contributions),
                    observed_trust_accepted_count=len(round_contributions),
                    fully_accepted_count=sum(
                        item.final_status == "accepted" for item in round_contributions
                    ),
                    downweighted_count=sum(
                        item.downweighted for item in round_contributions
                    ),
                    contributing_count=len(contributing_items),
                    quarantined_count=sum(
                        not item.contributes for item in round_contributions
                    ),
                    submitted_example_count=sum(
                        item.num_examples for item in round_contributions
                    ),
                    contributing_example_count=sum(
                        item.num_examples for item in contributing_items
                    ),
                    total_effective_weight_decimal=(
                        checkpoint.core.total_effective_weight_decimal
                    ),
                    unique_attestation_count=len(
                        {item.attestation_result_id for item in round_contributions}
                    ),
                    contribution_inventory_sha256=digest_object(
                        [item.model_dump(mode="json") for item in round_contributions]
                    ),
                )
            )
            previous_checkpoint_sha256 = checkpoint_sha256
            previous_model_sha256 = checkpoint.core.global_model_sha256

        _ensure(
            reader.digest(
                f"{campaign_root}/evaluation/selected-checkpoint-evaluation.json"
            )
            == campaign.core.final_evaluation_sha256,
            "selected checkpoint evaluation digest mismatch",
        )
        selected = campaign.core.rounds[campaign.core.selected_round - 1]
        _ensure(
            selected.checkpoint_sha256 == campaign.core.selected_checkpoint_sha256
            and selected.global_model_sha256 == campaign.core.selected_model_sha256,
            "selected checkpoint/model differs from the selected campaign round",
        )
        contributing = [item for item in contributions if item.contributes]
        _ensure(
            campaign.core.total_accepted_contributions == len(contributing),
            "campaign contributing count differs from in-round ledger",
        )
        expected_attestations = EXPECTED_ROUND_COUNT // ATTESTATION_REFRESH_ROUNDS
        for client_id in clients:
            usages = sorted(
                (
                    values
                    for (usage_client, _result_id), values in attestation_rounds.items()
                    if usage_client == client_id
                ),
                key=lambda values: values[0],
            )
            _ensure(
                len(usages) == expected_attestations
                and [item for group in usages for item in group]
                == list(range(1, EXPECTED_ROUND_COUNT + 1))
                and all(
                    len(group) == ATTESTATION_REFRESH_ROUNDS
                    and group == list(range(group[0], group[0] + len(group)))
                    for group in usages
                ),
                f"attestation refresh accounting mismatch: {client_id}",
            )

        client_accounts: list[InRoundClientAccount] = []
        for client_id in clients:
            items = [item for item in contributions if item.client_id == client_id]
            contributing_items = [item for item in items if item.contributes]
            node_ids = {item.node_id for item in items}
            enrollment_ids = {item.enrollment_id for item in items}
            _ensure(
                len(node_ids) == 1 and len(enrollment_ids) == 1,
                f"client identity changed during campaign: {client_id}",
            )
            attestation_ids = sorted({item.attestation_result_id for item in items})
            challenge_ids = sorted({item.challenge_id for item in items})
            client_accounts.append(
                InRoundClientAccount(
                    client_id=client_id,
                    node_id=next(iter(node_ids)),
                    enrollment_id=next(iter(enrollment_ids)),
                    contracted_round_count=EXPECTED_ROUND_COUNT,
                    submitted_count=len(items),
                    observed_trust_accepted_count=len(items),
                    fully_accepted_count=sum(
                        item.final_status == "accepted" for item in items
                    ),
                    downweighted_count=sum(item.downweighted for item in items),
                    contributing_count=len(contributing_items),
                    quarantined_count=sum(not item.contributes for item in items),
                    submitted_example_count=sum(item.num_examples for item in items),
                    contributing_example_count=sum(
                        item.num_examples for item in contributing_items
                    ),
                    attestation_result_ids=attestation_ids,
                    challenge_ids=challenge_ids,
                    attestation_count=len(attestation_ids),
                    challenge_count=len(challenge_ids),
                )
            )
        unique_attestations = {item.attestation_result_id for item in contributions}
        unique_challenges = {item.challenge_id for item in contributions}
        unique_enrollments = {item.enrollment_id for item in contributions}
        _ensure(
            len(unique_enrollments) == len(clients)
            and len(unique_attestations) == len(clients) * expected_attestations
            and len(unique_challenges) == len(unique_attestations),
            "campaign trust identity totals are inconsistent",
        )
        trust_accounting = CampaignTrustAccounting(
            enrollment_count=len(unique_enrollments),
            attestation_count=len(unique_attestations),
            challenge_count=len(unique_challenges),
            attestation_usage_count=len(contributions),
            attestations_per_client=expected_attestations,
            rounds_per_attestation=ATTESTATION_REFRESH_ROUNDS,
            verified_enrollment_signature_count=len(enrollment_cache),
            verified_attestation_signature_count=len(result_cache),
            verified_challenge_signature_count=len(challenge_cache),
            verified_bundle_signature_count=len(contributions),
            verified_coordinator_signature_count=coordinator_signature_count,
        )
        policy_outcomes = []
        for name in POLICY_NAMES:
            statuses = policy_status_counts[name]
            confusion = policy_confusion[name]
            policy_outcomes.append(
                PolicyOutcomeAccount(
                    policy=name,
                    accepted_count=statuses["accepted"],
                    downweighted_count=statuses["accepted_downweighted"],
                    quarantined_count=(
                        len(contributions)
                        - statuses["accepted"]
                        - statuses["accepted_downweighted"]
                    ),
                    controlled_true_positive=confusion["true_positive"],
                    controlled_false_positive=confusion["false_positive"],
                    controlled_true_negative=confusion["true_negative"],
                    controlled_false_negative=confusion["false_negative"],
                )
            )
        contribution_inventory_sha256 = digest_object(
            [item.model_dump(mode="json") for item in contributions]
        )
        _ensure(
            disagreement_contract_id is not None
            and disagreement_contract_sha256 is not None
            and disagreement_experiment_id is not None,
            "campaign contains no disagreement contract",
        )
        return InRoundCampaignAccountingCore(
            source_recovery_id=recovery.recovery_id,
            source_package_id=package.package_id,
            source_recovery_archive_sha256=recovery.core.archive_sha256,
            source_preservation_id=package.core.source_preservation_id,
            source_merkle_tree_id=package.core.source_merkle_tree_id,
            source_merkle_root_sha256=package.core.source_merkle_root_sha256,
            source_timestamp_id=package.core.source_timestamp_id,
            source_campaign_id=campaign.core.campaign_id,
            source_campaign_manifest_sha256=campaign_sha256,
            source_disagreement_experiment_id=disagreement_experiment_id,
            source_disagreement_contract_id=disagreement_contract_id,
            source_disagreement_contract_sha256=disagreement_contract_sha256,
            selected_round=campaign.core.selected_round,
            selected_checkpoint_sha256=campaign.core.selected_checkpoint_sha256,
            selected_model_sha256=campaign.core.selected_model_sha256,
            round_count=EXPECTED_ROUND_COUNT,
            required_client_count=len(clients),
            submission_count=len(contributions),
            observed_trust_accepted_count=len(contributions),
            fully_accepted_count=sum(
                item.final_status == "accepted" for item in contributions
            ),
            downweighted_count=sum(item.downweighted for item in contributions),
            contributing_count=len(contributing),
            quarantined_count=sum(not item.contributes for item in contributions),
            safe_submission_count=sum(
                item.security_label == "safe" for item in contributions
            ),
            unsafe_submission_count=sum(
                item.security_label == "unsafe" for item in contributions
            ),
            safe_quarantined_count=sum(
                item.security_label == "safe" and not item.contributes
                for item in contributions
            ),
            unsafe_quarantined_count=sum(
                item.security_label == "unsafe" and not item.contributes
                for item in contributions
            ),
            controlled_trust_failure_count=sum(
                item.controlled_trust_failure for item in contributions
            ),
            controlled_update_intervention_count=sum(
                item.update_intervention_applied for item in contributions
            ),
            submitted_example_count=sum(item.num_examples for item in contributions),
            contributing_example_count=sum(
                item.num_examples for item in contributing
            ),
            observed_admission_check_names=list(ADMISSION_CHECK_NAMES),
            observed_admission_check_count=len(contributions)
            * len(ADMISSION_CHECK_NAMES),
            passed_observed_admission_check_count=len(contributions)
            * len(ADMISSION_CHECK_NAMES),
            unique_bundle_count=len({item.bundle_id for item in contributions}),
            unique_trust_decision_count=len(
                {item.trust_decision_id for item in contributions}
            ),
            unique_in_round_decision_count=len(
                {item.in_round_decision_id for item in contributions}
            ),
            unique_update_count=len({item.update_sha256 for item in contributions}),
            contribution_inventory_sha256=contribution_inventory_sha256,
            trust_accounting=trust_accounting,
            policy_outcomes=policy_outcomes,
            rounds=rounds,
            clients=client_accounts,
            contributions=contributions,
        )


def _report(
    *, core: InRoundCampaignAccountingCore, config_sha256: str
) -> InRoundCampaignAccountingReport:
    core_digest = digest_object(core.model_dump(mode="json"))
    return InRoundCampaignAccountingReport(
        accounting_id=f"m8-in-round-campaign-accounting-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
        implementation_sha256=sha256_file(Path(__file__)),
        config_sha256=config_sha256,
    )


def _envelope(
    *, report: InRoundCampaignAccountingReport, report_bytes: bytes
) -> InRoundCampaignAccountingEnvelope:
    return InRoundCampaignAccountingEnvelope(
        accounting_id=report.accounting_id,
        campaign_accounting_sha256=sha256_bytes(report_bytes),
        contribution_inventory_sha256=report.core.contribution_inventory_sha256,
        source_recovery_id=report.core.source_recovery_id,
        source_recovery_archive_sha256=report.core.source_recovery_archive_sha256,
        source_merkle_root_sha256=report.core.source_merkle_root_sha256,
    )


def create_in_round_campaign_accounting(
    *, output: Path, config_path: Path
) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"campaign-accounting workspace is not empty: {output}")
    root, settings, config_sha256 = _settings(config_path)
    recovery_value = Path(str(settings["recovery_workspace"]))
    recovery_workspace = (
        recovery_value if recovery_value.is_absolute() else root / recovery_value
    )
    core = _derive_core(
        recovery_workspace=recovery_workspace,
        campaign_relative_path=str(settings["campaign_relative_path"]),
        trust_relative_path=str(settings["trust_relative_path"]),
        partition_relative_path=str(settings["partition_relative_path"]),
        expected_experiment_id=str(settings["expected_disagreement_experiment_id"]),
    )
    report = _report(core=core, config_sha256=config_sha256)
    report_bytes = canonical_json_bytes(report.model_dump(mode="json")) + b"\n"
    envelope = _envelope(report=report, report_bytes=report_bytes)
    write_once(output / "campaign-accounting.json", report_bytes)
    write_json_once(output / "manifest.json", envelope.model_dump(mode="json"))
    return {
        "status": "in_round_campaign_accounted",
        "accounting_id": report.accounting_id,
        "campaign_id": core.source_campaign_id,
        "round_count": core.round_count,
        "submission_count": core.submission_count,
        "observed_trust_accepted_count": core.observed_trust_accepted_count,
        "fully_accepted_count": core.fully_accepted_count,
        "downweighted_count": core.downweighted_count,
        "contributing_count": core.contributing_count,
        "quarantined_count": core.quarantined_count,
        "safe_quarantined_count": core.safe_quarantined_count,
        "unsafe_quarantined_count": core.unsafe_quarantined_count,
        "workspace": str(output),
    }


def verify_in_round_campaign_accounting(
    *, workspace: Path, recovery_workspace: Path
) -> dict[str, Any]:
    errors: list[str] = []
    report: InRoundCampaignAccountingReport | None = None
    try:
        paths = [
            path
            for path in workspace.rglob("*")
            if path.is_file() or path.is_symlink()
        ]
        names = sorted(path.relative_to(workspace).as_posix() for path in paths)
        if (
            names != EXPECTED_OUTPUT_FILES
            or any(path.is_symlink() or not path.is_file() for path in paths)
        ):
            raise InRoundCampaignAccountingError(
                "unexpected or non-regular M8.5 v2 workspace artifact set"
            )
        report_path = workspace / "campaign-accounting.json"
        report_bytes = report_path.read_bytes()
        report = InRoundCampaignAccountingReport.model_validate(load_json(report_path))
        canonical_report = canonical_json_bytes(report.model_dump(mode="json")) + b"\n"
        core_digest = digest_object(report.core.model_dump(mode="json"))
        if (
            report_bytes != canonical_report
            or report.canonical_core_sha256 != core_digest
            or report.accounting_id
            != f"m8-in-round-campaign-accounting-{core_digest[:24]}"
        ):
            raise InRoundCampaignAccountingError(
                "M8.5 v2 report is non-canonical or content identity differs"
            )
        envelope = InRoundCampaignAccountingEnvelope.model_validate(
            load_json(workspace / "manifest.json")
        )
        expected_envelope = _envelope(report=report, report_bytes=report_bytes)
        if envelope.model_dump(mode="json") != expected_envelope.model_dump(mode="json"):
            raise InRoundCampaignAccountingError("M8.5 v2 envelope binding mismatch")
        preservation = _source_preservation(recovery_workspace)
        recomputed = _derive_core(
            recovery_workspace=recovery_workspace,
            campaign_relative_path=_preserved_workspace_root(
                paths=[
                    item.relative_path
                    for item in preservation.core.campaign_assurance
                ],
                required_suffix=("campaign-manifest.json",),
                label="campaign",
            ),
            trust_relative_path=_preserved_workspace_root(
                paths=[
                    item.relative_path
                    for item in preservation.core.trust_assurance
                ],
                required_suffix=("registry", "index.json"),
                label="trust",
            ),
            partition_relative_path=_partition_root(preservation),
            expected_experiment_id=report.core.source_disagreement_experiment_id,
        )
        if recomputed.model_dump(mode="json") != report.core.model_dump(mode="json"):
            raise InRoundCampaignAccountingError(
                "M8.5 v2 accounting differs from recomputed offline sources"
            )
    except (FileNotFoundError, KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "accounting_id": report.accounting_id if report else None,
        "campaign_id": report.core.source_campaign_id if report else None,
        "round_count": report.core.round_count if report else 0,
        "submission_count": report.core.submission_count if report else 0,
        "observed_trust_accepted_count": (
            report.core.observed_trust_accepted_count if report else 0
        ),
        "contributing_count": report.core.contributing_count if report else 0,
        "downweighted_count": report.core.downweighted_count if report else 0,
        "quarantined_count": report.core.quarantined_count if report else 0,
        "safe_quarantined_count": report.core.safe_quarantined_count if report else 0,
        "unsafe_quarantined_count": (
            report.core.unsafe_quarantined_count if report else 0
        ),
        "source_recovery_verified": not errors,
        "verification_recomputed_accounting": not errors,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }


def _source_preservation(recovery_workspace: Path) -> PreservationManifest:
    package, recovery = _source_manifests(recovery_workspace)
    with _RecoveryReader(
        recovery_workspace / recovery.core.archive_name, package
    ) as reader:
        return PreservationManifest.model_validate(
            reader.assurance_json("assurance/m8.1/preservation-manifest.json")
        )


def _partition_root(preservation: PreservationManifest) -> str:
    partition_paths = sorted(
        item.relative_path
        for item in preservation.core.derivation_chain
        if item.artifact_role == "federated-data-derivation"
    )
    candidates = {
        PurePosixPath(item.relative_path).parent.as_posix()
        for item in preservation.core.derivation_chain
        if item.artifact_role == "federated-data-derivation"
        and PurePosixPath(item.relative_path).name == "manifest.json"
    }
    roots = sorted(
        candidate
        for candidate in candidates
        if all(path.startswith(f"{candidate}/") for path in partition_paths)
    )
    if len(roots) != 1:
        raise InRoundCampaignAccountingError(
            "preservation inventory does not identify one partition workspace"
        )
    return roots[0]
