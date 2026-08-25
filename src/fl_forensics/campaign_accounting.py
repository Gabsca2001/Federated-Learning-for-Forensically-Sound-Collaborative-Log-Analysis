"""M8.5 deterministic accounting over the offline M8.4 recovery package."""

from __future__ import annotations

import json
import tarfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Self

from .attestation import verify_attestation_signature
from .campaign_accounting_models import (
    ACCOUNTING_STATE,
    ADMISSION_CHECK_NAMES,
    CampaignAccountingCore,
    CampaignAccountingEnvelope,
    CampaignAccountingReport,
    CampaignClientAccount,
    CampaignContributionAccount,
    CampaignRoundAccount,
    CampaignTrustAccounting,
)
from .canonical import canonical_json_bytes, digest_object, sha256_bytes, sha256_file
from .config import load_yaml
from .crypto import load_public_key, public_key_id, verify_digest_signature
from .preservation_models import PreservationManifest
from .recovery import verify_recovery_export
from .recovery_models import RecoveryManifest, RecoveryPackageInventory
from .secure_round import EXPECTED_CLIENTS, GENESIS_DIGEST, _verify_signed
from .secure_round_models import (
    ContributionDecision,
    SecureCampaignManifest,
    SecureCheckpoint,
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

SOURCE_PROFILE = "recovery-tar-offline-campaign-accounting-v1"
CAMPAIGN_RELATIVE_PATH = "artifacts/m5-secure-multiround-v2"
TRUST_RELATIVE_PATH = "artifacts/m4-trust"
EXPECTED_ROUND_COUNT = 30
ATTESTATION_REFRESH_ROUNDS = 5
EXPECTED_OUTPUT_FILES = ["campaign-accounting.json", "manifest.json"]
MAX_JSON_MEMBER_BYTES = 8 * 1024 * 1024


class CampaignAccountingError(ValueError):
    """Raised when the preserved campaign cannot satisfy an M8.5 invariant."""


def _ensure(condition: bool, message: str) -> None:
    if not condition:
        raise CampaignAccountingError(message)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or value == "."
        or value.startswith("./")
        or path.is_absolute()
        or ".." in path.parts
        or value != path.as_posix()
    ):
        raise CampaignAccountingError(f"unsafe accounting source path: {value}")
    return value


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _settings(config_path: Path) -> tuple[Path, dict[str, Any], str]:
    value, config_sha256 = load_yaml(config_path)
    if value.get("schema_version") != "1.0":
        raise CampaignAccountingError("unsupported campaign-accounting schema")
    settings = value.get("campaign_accounting")
    if not isinstance(settings, dict):
        raise CampaignAccountingError("missing campaign-accounting configuration")
    expected = {
        "campaign_relative_path": CAMPAIGN_RELATIVE_PATH,
        "trust_relative_path": TRUST_RELATIVE_PATH,
        "expected_round_count": EXPECTED_ROUND_COUNT,
        "required_client_count": len(EXPECTED_CLIENTS),
        "attestation_refresh_interval_rounds": ATTESTATION_REFRESH_ROUNDS,
        "source_profile": SOURCE_PROFILE,
    }
    for name, expected_value in expected.items():
        if settings.get(name) != expected_value:
            raise CampaignAccountingError(
                f"campaign-accounting configuration mismatch: {name}"
            )
    if not isinstance(settings.get("recovery_workspace"), str):
        raise CampaignAccountingError("missing recovery workspace")
    _safe_relative(str(settings["campaign_relative_path"]))
    _safe_relative(str(settings["trust_relative_path"]))
    return config_path.resolve().parent.parent, settings, config_sha256


class _RecoveryReader:
    def __init__(
        self,
        archive_path: Path,
        package: RecoveryPackageInventory,
    ) -> None:
        self._archive = tarfile.open(archive_path, mode="r:")  # noqa: SIM115
        self._members = {item.name: item for item in self._archive.getmembers()}
        self._entries = {item.archive_path: item for item in package.core.entries}

    def close(self) -> None:
        self._archive.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def digest(self, relative_path: str) -> str:
        archive_path = f"payload/{_safe_relative(relative_path)}"
        entry = self._entries.get(archive_path)
        if entry is None or entry.entry_class != "preserved-payload":
            raise CampaignAccountingError(
                f"preserved payload entry is missing: {relative_path}"
            )
        return entry.sha256

    def read_archive(self, archive_path: str) -> bytes:
        entry = self._entries.get(archive_path)
        member = self._members.get(archive_path)
        if entry is None or member is None or not member.isfile():
            raise CampaignAccountingError(
                f"recovery member is missing or non-regular: {archive_path}"
            )
        if entry.size_bytes > MAX_JSON_MEMBER_BYTES:
            raise CampaignAccountingError(
                f"accounting member exceeds safe JSON limit: {archive_path}"
            )
        source = self._archive.extractfile(member)
        if source is None:
            raise CampaignAccountingError(f"recovery member is unreadable: {archive_path}")
        value = source.read()
        if len(value) != entry.size_bytes or sha256_bytes(value) != entry.sha256:
            raise CampaignAccountingError(
                f"recovery member differs from package inventory: {archive_path}"
            )
        return value

    def read(self, relative_path: str) -> bytes:
        return self.read_archive(f"payload/{_safe_relative(relative_path)}")

    def json(self, relative_path: str) -> Any:
        return json.loads(self.read(relative_path))

    def assurance_json(self, archive_path: str) -> Any:
        return json.loads(self.read_archive(archive_path))


def _signed_challenge(challenge: AttestationChallenge, public_key: Any) -> bool:
    digest = digest_object(challenge.core.model_dump(mode="json"))
    return (
        digest == challenge.core_digest
        and challenge.signature.key_id == public_key_id(public_key)
        and verify_digest_signature(
            public_key,
            challenge.core_digest,
            challenge.signature.value_b64,
        )
    )


def _source_manifests(
    recovery_workspace: Path,
) -> tuple[RecoveryPackageInventory, RecoveryManifest]:
    verification = verify_recovery_export(workspace=recovery_workspace)
    if verification.get("status") != "verified":
        raise CampaignAccountingError(
            f"source recovery verification failed: {verification.get('errors', [])}"
        )
    package = RecoveryPackageInventory.model_validate(
        load_json(recovery_workspace / "package-inventory.json")
    )
    recovery = RecoveryManifest.model_validate(
        load_json(recovery_workspace / "recovery-manifest.json")
    )
    return package, recovery


def _derive_core(
    *,
    recovery_workspace: Path,
    campaign_relative_path: str = CAMPAIGN_RELATIVE_PATH,
    trust_relative_path: str = TRUST_RELATIVE_PATH,
    expected_round_count: int = EXPECTED_ROUND_COUNT,
    expected_clients: list[str] | None = None,
    attestation_refresh_rounds: int = ATTESTATION_REFRESH_ROUNDS,
) -> CampaignAccountingCore:
    clients = list(expected_clients or EXPECTED_CLIENTS)
    _ensure(clients == EXPECTED_CLIENTS, "M8.5 requires the ordered 15-client contract")
    _ensure(
        expected_round_count == EXPECTED_ROUND_COUNT,
        "M8.5 requires exactly 30 campaign rounds",
    )
    _ensure(
        attestation_refresh_rounds == ATTESTATION_REFRESH_ROUNDS,
        "M8.5 requires the five-round attestation refresh interval",
    )
    campaign_root = _safe_relative(campaign_relative_path)
    trust_root = _safe_relative(trust_relative_path)
    package, recovery = _source_manifests(recovery_workspace)
    archive_path = recovery_workspace / recovery.core.archive_name

    with _RecoveryReader(archive_path, package) as reader:
        preservation = PreservationManifest.model_validate(
            reader.assurance_json("assurance/m8.1/preservation-manifest.json")
        )
        _ensure(
            preservation.preservation_id == package.core.source_preservation_id,
            "recovery package preservation identity mismatch",
        )
        campaign_manifest_path = f"{campaign_root}/campaign-manifest.json"
        campaign_manifest_sha256 = reader.digest(campaign_manifest_path)
        campaign = SecureCampaignManifest.model_validate(
            reader.json(campaign_manifest_path)
        )
        coordinator_key = load_public_key(
            reader.read(f"{campaign_root}/authority/round-coordinator.public.pem")
        )
        enrollment_authority_key = load_public_key(
            reader.read(f"{trust_root}/authority/enrollment-authority.public.pem")
        )
        attestation_verifier_key = load_public_key(
            reader.read(f"{trust_root}/authority/attestation-verifier.public.pem")
        )
        registry_index = reader.json(f"{trust_root}/registry/index.json")
        _ensure(
            _verify_signed(campaign, coordinator_key),
            "campaign manifest coordinator signature is invalid",
        )
        _ensure(
            campaign.core.round_count == expected_round_count
            and campaign.core.required_client_count == len(clients)
            and campaign.core.total_accepted_contributions
            == expected_round_count * len(clients)
            and [item.round_number for item in campaign.core.rounds]
            == list(range(1, expected_round_count + 1)),
            "signed campaign contract differs from the M8.5 profile",
        )
        _ensure(
            preservation.core.selected_derivation_round == campaign.core.selected_round,
            "M8.1 selected derivation round differs from the M5 campaign",
        )

        enrollment_cache: dict[str, EnrollmentRecord] = {}
        result_cache: dict[str, AttestationResultV2] = {}
        challenge_cache: dict[str, AttestationChallenge] = {}
        attestation_rounds: dict[tuple[str, str], list[int]] = defaultdict(list)
        contributions: list[CampaignContributionAccount] = []
        rounds: list[CampaignRoundAccount] = []
        previous_checkpoint_sha256 = GENESIS_DIGEST
        previous_model_sha256: str | None = None
        coordinator_signature_count = 1

        for round_number in range(1, expected_round_count + 1):
            round_root = f"{campaign_root}/rounds/round-{round_number:03d}"
            context_path = f"{round_root}/public/round-context.json"
            checkpoint_path = f"{round_root}/checkpoint/manifest.json"
            context = SecureRoundContext.model_validate(reader.json(context_path))
            checkpoint = SecureCheckpoint.model_validate(reader.json(checkpoint_path))
            context_sha256 = reader.digest(context_path)
            checkpoint_sha256 = reader.digest(checkpoint_path)
            _ensure(
                _verify_signed(context, coordinator_key)
                and _verify_signed(checkpoint, coordinator_key),
                f"round {round_number} coordinator signature is invalid",
            )
            coordinator_signature_count += 2
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
                f"round {round_number} public/checkpoint artifact binding is invalid",
            )
            reference = campaign.core.rounds[round_number - 1]
            validation_path = (
                f"{campaign_root}/evaluation/round-{round_number:03d}-validation.json"
            )
            _ensure(
                reference.context_id == context.context_id
                and reference.context_sha256 == context_sha256
                and reference.checkpoint_id == checkpoint.checkpoint_id
                and reference.checkpoint_sha256 == checkpoint_sha256
                and reference.base_model_sha256 == context.core.base_model_sha256
                and reference.global_model_sha256
                == checkpoint.core.global_model_sha256
                and reference.validation_metrics_sha256
                == reader.digest(validation_path)
                and reference.accepted_count == len(clients),
                f"round {round_number} differs from the signed campaign reference",
            )
            _ensure(
                checkpoint.core.accepted_count == len(clients)
                and checkpoint.core.quarantined_count == 0
                and checkpoint.core.quarantined_decision_sha256 == []
                and [item.client_id for item in checkpoint.core.accepted_inputs]
                == clients,
                f"round {round_number} checkpoint contribution set is invalid",
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
            round_contributions: list[CampaignContributionAccount] = []

            for client_id in clients:
                contract = contracts[client_id]
                enrollment = enrollment_cache.get(client_id)
                if enrollment is None:
                    registry_entry = registry_index.get("enrollments", {}).get(
                        client_id
                    )
                    _ensure(
                        isinstance(registry_entry, dict),
                        f"missing preserved registry entry: {client_id}",
                    )
                    enrollment_path = (
                        f"{trust_root}/"
                        f"{_safe_relative(str(registry_entry['record_path']))}"
                    )
                    enrollment = EnrollmentRecord.model_validate(
                        reader.json(enrollment_path)
                    )
                    _ensure(
                        digest_object(enrollment.model_dump(mode="json"))
                        == registry_entry.get("record_digest")
                        and registry_entry.get("enrollment_id")
                        == enrollment.core.enrollment_id
                        and verify_enrollment_record(
                            enrollment, enrollment_authority_key
                        )
                        and enrollment.core.client_id == client_id
                        and enrollment.core.enrollment_id == contract.enrollment_id
                        and enrollment.core.node_id == contract.node_id
                        and enrollment.core.status == "active",
                        f"invalid preserved enrollment binding: {client_id}",
                    )
                    enrollment_cache[client_id] = enrollment

                bundle_path = f"{round_root}/submissions/{client_id}/bundle.json"
                decision_path = f"{round_root}/decisions/{client_id}.json"
                bundle = UpdateBundle.model_validate(reader.json(bundle_path))
                decision = ContributionDecision.model_validate(
                    reader.json(decision_path)
                )
                bundle_sha256 = reader.digest(bundle_path)
                decision_sha256 = reader.digest(decision_path)
                esk_key = load_public_key(enrollment.core.esk_public_key_pem.encode())
                _ensure(
                    _verify_signed(bundle, esk_key),
                    f"invalid preserved bundle signature: round {round_number} {client_id}",
                )
                _ensure(
                    _verify_signed(decision, coordinator_key),
                    f"invalid preserved decision signature: round {round_number} {client_id}",
                )
                coordinator_signature_count += 1
                check_names = [item.name for item in decision.core.checks]
                _ensure(
                    decision.core.status == "accepted"
                    and check_names == list(ADMISSION_CHECK_NAMES)
                    and all(item.passed for item in decision.core.checks),
                    f"failed or incomplete admission checks: round {round_number} {client_id}",
                )

                result_id = contract.attestation_result_id
                result = result_cache.get(result_id)
                if result is None:
                    result_path = f"{trust_root}/results/{result_id}.json"
                    result = AttestationResultV2.model_validate(reader.json(result_path))
                    _ensure(
                        reader.digest(result_path) == contract.attestation_result_sha256
                        and result.result_id == result_id
                        and verify_attestation_signature(
                            result, attestation_verifier_key
                        ),
                        f"invalid preserved attestation result: {result_id}",
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
                        _signed_challenge(challenge, attestation_verifier_key),
                        f"invalid preserved attestation challenge: {challenge_id}",
                    )
                    challenge_cache[challenge_id] = challenge

                _ensure(
                    result.core.status in {"passed", "passed_with_warning"}
                    and result.core.client_id == client_id
                    and result.core.node_id == contract.node_id
                    and result.core.enrollment_id == contract.enrollment_id
                    and result.core.transport_peer_fingerprint
                    == enrollment.core.tls_certificate_sha256
                    and result.signature.trust_level == enrollment.core.trust_level
                    and challenge.core.challenge_id == challenge_id
                    and challenge.core.client_id == client_id
                    and challenge.core.node_id == contract.node_id
                    and challenge.core.enrollment_id == contract.enrollment_id
                    and challenge.core.nonce == result.core.nonce
                    and challenge.core.pcr_bank == result.core.pcr_bank
                    and challenge.core.pcr_selection == result.core.pcr_selection
                    and challenge.core.policy_id == result.core.policy_id
                    and challenge.core.policy_version == result.core.policy_version
                    and challenge.core.baseline_id == result.core.baseline_id
                    and challenge.core.baseline_version == result.core.baseline_version
                    and _parse_time(challenge.core.issued_at)
                    <= _parse_time(result.core.evaluated_at)
                    < _parse_time(challenge.core.expires_at),
                    f"attestation/challenge identity binding is invalid: {result_id}",
                )
                _ensure(
                    bundle.core.campaign_id == campaign.core.campaign_id
                    and bundle.core.context_id == context.context_id
                    and bundle.core.context_digest == context.core_digest
                    and bundle.core.round_number == round_number
                    and bundle.core.client_id == client_id
                    and bundle.core.node_id == contract.node_id
                    and bundle.core.enrollment_id == contract.enrollment_id
                    and bundle.core.attestation_result_id == result_id
                    and bundle.core.attestation_result_sha256
                    == contract.attestation_result_sha256
                    and bundle.core.base_model_sha256
                    == context.core.base_model_sha256
                    and bundle.core.snapshot_sha256 == contract.snapshot_sha256
                    and bundle.core.num_examples == contract.train_row_count
                    and bundle.signature.key_id == enrollment.core.esk_key_id
                    and bundle.signature.trust_level == enrollment.core.trust_level,
                    f"bundle/context/client binding is invalid: round {round_number} {client_id}",
                )
                generated_at = _parse_time(bundle.core.generated_at)
                decided_at = _parse_time(decision.core.decided_at)
                _ensure(
                    issued_at <= generated_at <= decided_at <= checkpoint_at < expires_at
                    and _parse_time(enrollment.core.valid_from)
                    <= decided_at
                    < _parse_time(enrollment.core.valid_until)
                    and decided_at < _parse_time(result.core.expires_at),
                    f"historical trust/context time binding is invalid: round {round_number} {client_id}",
                )
                _ensure(
                    decision.core.campaign_id == campaign.core.campaign_id
                    and decision.core.context_id == context.context_id
                    and decision.core.round_number == round_number
                    and decision.core.client_id == client_id
                    and decision.core.bundle_id == bundle.bundle_id
                    and decision.core.bundle_sha256 == bundle_sha256,
                    f"decision/bundle binding is invalid: round {round_number} {client_id}",
                )
                checkpoint_input = checkpoint_inputs[client_id]
                _ensure(
                    checkpoint_input.decision_id == decision.decision_id
                    and checkpoint_input.decision_sha256 == decision_sha256
                    and checkpoint_input.bundle_id == bundle.bundle_id
                    and checkpoint_input.bundle_sha256 == bundle_sha256
                    and checkpoint_input.update_sha256 == bundle.core.update_sha256
                    and checkpoint_input.num_examples == bundle.core.num_examples
                    and reader.digest(
                        f"{round_root}/submissions/{client_id}/update.json"
                    )
                    == bundle.core.update_sha256
                    and reader.digest(
                        f"{round_root}/submissions/{client_id}/metrics.json"
                    )
                    == bundle.core.metrics_sha256,
                    f"checkpoint/submission binding is invalid: round {round_number} {client_id}",
                )
                contribution = CampaignContributionAccount(
                    round_number=round_number,
                    client_id=client_id,
                    node_id=contract.node_id,
                    enrollment_id=contract.enrollment_id,
                    attestation_result_id=result_id,
                    attestation_result_sha256=contract.attestation_result_sha256,
                    challenge_id=challenge_id,
                    context_id=context.context_id,
                    context_digest=context.core_digest,
                    bundle_id=bundle.bundle_id,
                    bundle_sha256=bundle_sha256,
                    decision_id=decision.decision_id,
                    decision_sha256=decision_sha256,
                    snapshot_sha256=contract.snapshot_sha256,
                    snapshot_manifest_sha256=contract.snapshot_manifest_sha256,
                    update_sha256=bundle.core.update_sha256,
                    metrics_sha256=bundle.core.metrics_sha256,
                    tensor_schema_sha256=bundle.core.tensor_schema_sha256,
                    num_examples=bundle.core.num_examples,
                    generated_at=bundle.core.generated_at,
                    decided_at=decision.core.decided_at,
                    admission_checks=check_names,
                    all_checks_passed=True,
                )
                contributions.append(contribution)
                round_contributions.append(contribution)
                attestation_rounds[(client_id, result_id)].append(round_number)

            _ensure(
                checkpoint.core.total_examples
                == sum(item.num_examples for item in round_contributions),
                f"round {round_number} checkpoint example count mismatch",
            )
            rounds.append(
                CampaignRoundAccount(
                    round_number=round_number,
                    context_id=context.context_id,
                    context_sha256=context_sha256,
                    checkpoint_id=checkpoint.checkpoint_id,
                    checkpoint_sha256=checkpoint_sha256,
                    previous_checkpoint_sha256=previous_checkpoint_sha256,
                    base_model_sha256=context.core.base_model_sha256,
                    global_model_sha256=checkpoint.core.global_model_sha256,
                    required_client_count=len(clients),
                    contribution_count=len(round_contributions),
                    accepted_count=checkpoint.core.accepted_count,
                    quarantined_count=0,
                    missing_count=0,
                    total_examples=checkpoint.core.total_examples,
                    passed_check_count=len(round_contributions)
                    * len(ADMISSION_CHECK_NAMES),
                    unique_attestation_count=len(
                        {item.attestation_result_id for item in round_contributions}
                    ),
                    contribution_inventory_sha256=digest_object(
                        [item.model_dump(mode="json") for item in round_contributions]
                    ),
                    checkpoint_chain_valid=True,
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
        selected_reference = campaign.core.rounds[campaign.core.selected_round - 1]
        _ensure(
            selected_reference.checkpoint_sha256
            == campaign.core.selected_checkpoint_sha256
            and selected_reference.global_model_sha256
            == campaign.core.selected_model_sha256,
            "selected checkpoint/model differs from the selected campaign round",
        )
        _ensure(
            len({item.bundle_id for item in contributions}) == len(contributions)
            and len({item.decision_id for item in contributions}) == len(contributions)
            and len({item.update_sha256 for item in contributions})
            == len(contributions),
            "campaign contains duplicate bundle, decision, or update identities",
        )

        expected_attestations_per_client = (
            expected_round_count // attestation_refresh_rounds
        )
        _ensure(
            expected_round_count % attestation_refresh_rounds == 0,
            "campaign rounds are not divisible by the attestation refresh interval",
        )
        for client_id in clients:
            usages = sorted(
                (
                    round_numbers
                    for (usage_client, _result_id), round_numbers in attestation_rounds.items()
                    if usage_client == client_id
                ),
                key=lambda values: values[0],
            )
            _ensure(
                len(usages) == expected_attestations_per_client
                and [item for group in usages for item in group]
                == list(range(1, expected_round_count + 1))
                and all(
                    len(group) == attestation_refresh_rounds
                    and group == list(range(group[0], group[0] + len(group)))
                    for group in usages
                ),
                f"attestation refresh accounting mismatch: {client_id}",
            )

        client_accounts: list[CampaignClientAccount] = []
        for client_id in clients:
            items = [item for item in contributions if item.client_id == client_id]
            node_ids = {item.node_id for item in items}
            enrollment_ids = {item.enrollment_id for item in items}
            _ensure(
                len(node_ids) == 1 and len(enrollment_ids) == 1,
                f"client identity changed during the campaign: {client_id}",
            )
            attestation_ids = sorted(
                {item.attestation_result_id for item in items}
            )
            challenge_ids = sorted({item.challenge_id for item in items})
            client_accounts.append(
                CampaignClientAccount(
                    client_id=client_id,
                    node_id=next(iter(node_ids)),
                    enrollment_id=next(iter(enrollment_ids)),
                    contracted_round_count=expected_round_count,
                    submitted_count=len(items),
                    accepted_count=len(items),
                    quarantined_count=0,
                    total_examples=sum(item.num_examples for item in items),
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
            and len(unique_attestations)
            == len(clients) * expected_attestations_per_client
            and len(unique_challenges) == len(unique_attestations)
            and len(result_cache) == len(unique_attestations)
            and len(challenge_cache) == len(unique_challenges),
            "campaign trust identity totals are inconsistent",
        )
        trust_accounting = CampaignTrustAccounting(
            enrollment_count=len(unique_enrollments),
            attestation_count=len(unique_attestations),
            challenge_count=len(unique_challenges),
            attestation_usage_count=len(contributions),
            attestations_per_client=expected_attestations_per_client,
            rounds_per_attestation=attestation_refresh_rounds,
            verified_enrollment_signature_count=len(enrollment_cache),
            verified_attestation_signature_count=len(result_cache),
            verified_challenge_signature_count=len(challenge_cache),
            verified_bundle_signature_count=len(contributions),
            verified_coordinator_signature_count=coordinator_signature_count,
            trust_binding_valid=True,
        )
        contribution_inventory_sha256 = digest_object(
            [item.model_dump(mode="json") for item in contributions]
        )
        return CampaignAccountingCore(
            source_profile=SOURCE_PROFILE,
            source_recovery_id=recovery.recovery_id,
            source_package_id=package.package_id,
            source_recovery_archive_sha256=recovery.core.archive_sha256,
            source_preservation_id=package.core.source_preservation_id,
            source_merkle_tree_id=package.core.source_merkle_tree_id,
            source_merkle_root_sha256=package.core.source_merkle_root_sha256,
            source_timestamp_id=package.core.source_timestamp_id,
            source_campaign_id=campaign.core.campaign_id,
            source_campaign_manifest_sha256=campaign_manifest_sha256,
            selected_round=campaign.core.selected_round,
            selected_checkpoint_sha256=campaign.core.selected_checkpoint_sha256,
            selected_model_sha256=campaign.core.selected_model_sha256,
            round_count=expected_round_count,
            required_client_count=len(clients),
            contribution_count=len(contributions),
            accepted_contribution_count=len(contributions),
            quarantined_contribution_count=0,
            missing_contribution_count=0,
            total_example_count=sum(item.num_examples for item in contributions),
            admission_check_names=list(ADMISSION_CHECK_NAMES),
            admission_check_count=len(contributions) * len(ADMISSION_CHECK_NAMES),
            passed_admission_check_count=len(contributions)
            * len(ADMISSION_CHECK_NAMES),
            failed_admission_check_count=0,
            unique_bundle_count=len({item.bundle_id for item in contributions}),
            unique_decision_count=len({item.decision_id for item in contributions}),
            unique_update_count=len({item.update_sha256 for item in contributions}),
            contribution_inventory_sha256=contribution_inventory_sha256,
            trust_accounting=trust_accounting,
            rounds=rounds,
            clients=client_accounts,
            contributions=contributions,
            assurance_state=ACCOUNTING_STATE,
        )


def _report(
    *, core: CampaignAccountingCore, config_sha256: str
) -> CampaignAccountingReport:
    core_digest = digest_object(core.model_dump(mode="json"))
    return CampaignAccountingReport(
        accounting_id=f"m8-campaign-accounting-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
        implementation_sha256=sha256_file(Path(__file__)),
        config_sha256=config_sha256,
    )


def _envelope(
    *, report: CampaignAccountingReport, report_bytes: bytes
) -> CampaignAccountingEnvelope:
    return CampaignAccountingEnvelope(
        accounting_id=report.accounting_id,
        campaign_accounting_sha256=sha256_bytes(report_bytes),
        contribution_inventory_sha256=report.core.contribution_inventory_sha256,
        source_recovery_id=report.core.source_recovery_id,
        source_recovery_archive_sha256=report.core.source_recovery_archive_sha256,
        source_merkle_root_sha256=report.core.source_merkle_root_sha256,
        assurance_state=ACCOUNTING_STATE,
    )


def create_campaign_accounting(
    *, output: Path, config_path: Path
) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"campaign-accounting workspace is not empty: {output}")
    root, settings, config_sha256 = _settings(config_path)
    recovery_workspace = _resolve(root, str(settings["recovery_workspace"]))
    core = _derive_core(
        recovery_workspace=recovery_workspace,
        campaign_relative_path=str(settings["campaign_relative_path"]),
        trust_relative_path=str(settings["trust_relative_path"]),
        expected_round_count=int(settings["expected_round_count"]),
        expected_clients=EXPECTED_CLIENTS,
        attestation_refresh_rounds=int(
            settings["attestation_refresh_interval_rounds"]
        ),
    )
    report = _report(core=core, config_sha256=config_sha256)
    report_bytes = canonical_json_bytes(report.model_dump(mode="json")) + b"\n"
    envelope = _envelope(report=report, report_bytes=report_bytes)
    write_once(output / "campaign-accounting.json", report_bytes)
    write_json_once(output / "manifest.json", envelope.model_dump(mode="json"))
    return {
        "status": "campaign_accounted",
        "accounting_id": report.accounting_id,
        "campaign_id": core.source_campaign_id,
        "round_count": core.round_count,
        "contribution_count": core.contribution_count,
        "passed_admission_check_count": core.passed_admission_check_count,
        "unique_attestation_count": core.trust_accounting.attestation_count,
        "unique_challenge_count": core.trust_accounting.challenge_count,
        "workspace": str(output),
    }


def verify_campaign_accounting(
    *, workspace: Path, recovery_workspace: Path
) -> dict[str, Any]:
    errors: list[str] = []
    report: CampaignAccountingReport | None = None
    try:
        paths = [path for path in workspace.rglob("*") if path.is_file() or path.is_symlink()]
        names = sorted(path.relative_to(workspace).as_posix() for path in paths)
        if (
            names != EXPECTED_OUTPUT_FILES
            or any(path.is_symlink() or not path.is_file() for path in paths)
        ):
            raise CampaignAccountingError(
                "unexpected or non-regular M8.5 workspace artifact set"
            )
        report_path = workspace / "campaign-accounting.json"
        report_bytes = report_path.read_bytes()
        report = CampaignAccountingReport.model_validate(load_json(report_path))
        canonical_report = (
            canonical_json_bytes(report.model_dump(mode="json")) + b"\n"
        )
        core_digest = digest_object(report.core.model_dump(mode="json"))
        if (
            report_bytes != canonical_report
            or report.canonical_core_sha256 != core_digest
            or report.accounting_id != f"m8-campaign-accounting-{core_digest[:24]}"
        ):
            raise CampaignAccountingError(
                "campaign-accounting report identity is invalid"
            )
        expected_core = _derive_core(recovery_workspace=recovery_workspace)
        if report.core != expected_core:
            raise CampaignAccountingError(
                "campaign-accounting report differs from offline reconstruction"
            )
        envelope_path = workspace / "manifest.json"
        envelope_bytes = envelope_path.read_bytes()
        CampaignAccountingEnvelope.model_validate(load_json(envelope_path))
        expected_envelope = _envelope(report=report, report_bytes=report_bytes)
        if envelope_bytes != (
            canonical_json_bytes(expected_envelope.model_dump(mode="json")) + b"\n"
        ):
            raise CampaignAccountingError(
                "campaign-accounting envelope differs from reconstruction"
            )
    except (
        CampaignAccountingError,
        FileNotFoundError,
        KeyError,
        OSError,
        tarfile.TarError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    core = report.core if report is not None else None
    return {
        "status": "verified" if not errors else "failed",
        "accounting_id": report.accounting_id if report is not None else None,
        "campaign_id": core.source_campaign_id if core is not None else None,
        "round_count": core.round_count if core is not None else 0,
        "contribution_count": core.contribution_count if core is not None else 0,
        "passed_admission_check_count": (
            core.passed_admission_check_count if core is not None else 0
        ),
        "unique_attestation_count": (
            core.trust_accounting.attestation_count if core is not None else 0
        ),
        "source_recovery_verified": not errors,
        "verification_recomputed_accounting": not errors,
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }
