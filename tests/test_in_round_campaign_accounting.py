from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fl_forensics.campaign_accounting_models import (
    ADMISSION_CHECK_NAMES,
    CampaignTrustAccounting,
)
from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_bytes
from fl_forensics.disagreement_experiment import build_disagreement_contract
from fl_forensics.in_round_admission import build_in_round_contract
from fl_forensics.in_round_campaign_accounting import _partition_root, _verify_contracts
from fl_forensics.in_round_campaign_accounting_models import (
    POLICY_NAMES,
    InRoundCampaignAccountingCore,
    InRoundClientAccount,
    InRoundContributionAccount,
    InRoundRoundAccount,
    PolicyOutcomeAccount,
)
from fl_forensics.preprocessing import derived_json_bytes


def _sha(index: int) -> str:
    return f"{index:064x}"


def _contribution(
    client_index: int,
    *,
    condition: str,
    security_label: str,
    trust_failed: bool,
    update_anomalous: bool,
    policies: dict[str, str],
) -> InRoundContributionAccount:
    client_id = f"client{client_index:02d}"
    final_status = policies["gated_composite"]
    contributes = final_status in {"accepted", "accepted_downweighted"}
    return InRoundContributionAccount(
        round_number=1,
        client_id=client_id,
        node_id=f"node{client_index:02d}",
        enrollment_id=f"enrollment-{client_index}",
        attestation_result_id=f"attestation-{client_index}",
        attestation_result_sha256=_sha(10 + client_index),
        challenge_id=f"challenge-{client_index}",
        context_id="context-1",
        context_digest=_sha(20),
        bundle_id=f"bundle-{client_index}",
        bundle_sha256=_sha(30 + client_index),
        trust_decision_id=f"trust-decision-{client_index}",
        trust_decision_sha256=_sha(40 + client_index),
        in_round_decision_id=f"in-round-decision-{client_index}",
        in_round_decision_sha256=_sha(50 + client_index),
        snapshot_sha256=_sha(60 + client_index),
        snapshot_manifest_sha256=_sha(70 + client_index),
        update_sha256=_sha(80 + client_index),
        metrics_sha256=_sha(90 + client_index),
        tensor_schema_sha256=_sha(100),
        num_examples=10,
        effective_weight_decimal="10" if contributes else "0",
        generated_at="2026-09-01T10:01:00Z",
        trust_decided_at="2026-09-01T10:02:00Z",
        in_round_decided_at="2026-09-01T10:03:00Z",
        observed_admission_checks=list(ADMISSION_CHECK_NAMES),
        final_status=final_status,
        contributes=contributes,
        downweighted=final_status == "accepted_downweighted",
        policy_statuses=policies,
        disagreement_condition=condition,
        controlled_assignment=True,
        security_label=security_label,
        controlled_trust_failure=trust_failed,
        update_intervention_applied=update_anomalous,
        clean_update_sha256=(
            _sha(180 + client_index)
            if update_anomalous
            else _sha(80 + client_index)
        ),
        candidate_update_sha256=_sha(80 + client_index),
    )


def _core() -> InRoundCampaignAccountingCore:
    contributions = [
        _contribution(
            1,
            condition="trust_admissible_statistics_normal",
            security_label="safe",
            trust_failed=False,
            update_anomalous=False,
            policies={name: "accepted" for name in POLICY_NAMES},
        ),
        _contribution(
            2,
            condition="trust_admissible_statistics_anomalous",
            security_label="unsafe",
            trust_failed=False,
            update_anomalous=True,
            policies={
                "tpm_only": "accepted",
                "statistics_only": "statistically_quarantined",
                "sequential": "statistically_quarantined",
                "gated_composite": "statistically_quarantined",
            },
        ),
        _contribution(
            3,
            condition="trust_inadmissible_statistics_normal",
            security_label="unsafe",
            trust_failed=True,
            update_anomalous=False,
            policies={
                "tpm_only": "trust_quarantined",
                "statistics_only": "accepted",
                "sequential": "trust_quarantined",
                "gated_composite": "trust_quarantined",
            },
        ),
        _contribution(
            4,
            condition="trust_inadmissible_statistics_anomalous",
            security_label="unsafe",
            trust_failed=True,
            update_anomalous=True,
            policies={
                "tpm_only": "trust_quarantined",
                "statistics_only": "statistically_quarantined",
                "sequential": "trust_quarantined",
                "gated_composite": "trust_quarantined",
            },
        ),
    ]
    inventory = digest_object(
        [item.model_dump(mode="json") for item in contributions]
    )
    clients = []
    for contribution in contributions:
        contributing = int(contribution.contributes)
        clients.append(
            InRoundClientAccount(
                client_id=contribution.client_id,
                node_id=contribution.node_id,
                enrollment_id=contribution.enrollment_id,
                contracted_round_count=1,
                submitted_count=1,
                observed_trust_accepted_count=1,
                fully_accepted_count=contributing,
                downweighted_count=0,
                contributing_count=contributing,
                quarantined_count=1 - contributing,
                submitted_example_count=10,
                contributing_example_count=10 * contributing,
                attestation_result_ids=[contribution.attestation_result_id],
                challenge_ids=[contribution.challenge_id],
                attestation_count=1,
                challenge_count=1,
            )
        )
    return InRoundCampaignAccountingCore(
        source_recovery_id="recovery-1",
        source_package_id="package-1",
        source_recovery_archive_sha256=_sha(1),
        source_preservation_id="preservation-1",
        source_merkle_tree_id="tree-1",
        source_merkle_root_sha256=_sha(2),
        source_timestamp_id="timestamp-1",
        source_campaign_id="campaign-1",
        source_campaign_manifest_sha256=_sha(3),
        source_disagreement_experiment_id="experiment-1",
        source_disagreement_contract_id="contract-1",
        source_disagreement_contract_sha256=_sha(4),
        selected_round=1,
        selected_checkpoint_sha256=_sha(5),
        selected_model_sha256=_sha(6),
        round_count=1,
        required_client_count=4,
        submission_count=4,
        observed_trust_accepted_count=4,
        fully_accepted_count=1,
        downweighted_count=0,
        contributing_count=1,
        quarantined_count=3,
        safe_submission_count=1,
        unsafe_submission_count=3,
        safe_quarantined_count=0,
        unsafe_quarantined_count=3,
        controlled_trust_failure_count=2,
        controlled_update_intervention_count=2,
        submitted_example_count=40,
        contributing_example_count=10,
        observed_admission_check_names=list(ADMISSION_CHECK_NAMES),
        observed_admission_check_count=4 * len(ADMISSION_CHECK_NAMES),
        passed_observed_admission_check_count=4 * len(ADMISSION_CHECK_NAMES),
        unique_bundle_count=4,
        unique_trust_decision_count=4,
        unique_in_round_decision_count=4,
        unique_update_count=4,
        contribution_inventory_sha256=inventory,
        trust_accounting=CampaignTrustAccounting(
            enrollment_count=4,
            attestation_count=4,
            challenge_count=4,
            attestation_usage_count=4,
            attestations_per_client=1,
            rounds_per_attestation=1,
            verified_enrollment_signature_count=4,
            verified_attestation_signature_count=4,
            verified_challenge_signature_count=4,
            verified_bundle_signature_count=4,
            verified_coordinator_signature_count=11,
        ),
        policy_outcomes=[
            PolicyOutcomeAccount(
                policy="tpm_only",
                accepted_count=2,
                downweighted_count=0,
                quarantined_count=2,
                controlled_true_positive=2,
                controlled_false_positive=0,
                controlled_true_negative=1,
                controlled_false_negative=1,
            ),
            PolicyOutcomeAccount(
                policy="statistics_only",
                accepted_count=2,
                downweighted_count=0,
                quarantined_count=2,
                controlled_true_positive=2,
                controlled_false_positive=0,
                controlled_true_negative=1,
                controlled_false_negative=1,
            ),
            PolicyOutcomeAccount(
                policy="sequential",
                accepted_count=1,
                downweighted_count=0,
                quarantined_count=3,
                controlled_true_positive=3,
                controlled_false_positive=0,
                controlled_true_negative=1,
                controlled_false_negative=0,
            ),
            PolicyOutcomeAccount(
                policy="gated_composite",
                accepted_count=1,
                downweighted_count=0,
                quarantined_count=3,
                controlled_true_positive=3,
                controlled_false_positive=0,
                controlled_true_negative=1,
                controlled_false_negative=0,
            ),
        ],
        rounds=[
            InRoundRoundAccount(
                round_number=1,
                context_id="context-1",
                context_sha256=_sha(20),
                checkpoint_id="checkpoint-1",
                checkpoint_sha256=_sha(21),
                previous_checkpoint_sha256=_sha(22),
                base_model_sha256=_sha(23),
                global_model_sha256=_sha(24),
                required_client_count=4,
                submitted_count=4,
                observed_trust_accepted_count=4,
                fully_accepted_count=1,
                downweighted_count=0,
                contributing_count=1,
                quarantined_count=3,
                submitted_example_count=40,
                contributing_example_count=10,
                total_effective_weight_decimal="10",
                unique_attestation_count=4,
                contribution_inventory_sha256=inventory,
            )
        ],
        clients=clients,
        contributions=contributions,
    )


def test_in_round_accounting_distinguishes_submission_and_aggregation() -> None:
    core = _core()
    assert core.submission_count == 4
    assert core.observed_trust_accepted_count == 4
    assert core.contributing_count == 1
    assert core.quarantined_count == 3


def test_in_round_accounting_survives_canonical_json_round_trip() -> None:
    core = _core()
    serialized = canonical_json_bytes(core.model_dump(mode="json"))
    restored = InRoundCampaignAccountingCore.model_validate(json.loads(serialized))
    assert restored == core


def test_in_round_accounting_rejects_policy_totals_not_derived_from_ledger() -> None:
    value = deepcopy(_core().model_dump(mode="json"))
    value["policy_outcomes"][0]["controlled_false_negative"] = 0
    with pytest.raises(ValueError, match="policy outcome differs"):
        InRoundCampaignAccountingCore.model_validate(value)


def test_in_round_accounting_rejects_inconsistent_security_label() -> None:
    value = _core().contributions[0].model_dump(mode="json")
    value["security_label"] = "unsafe"
    with pytest.raises(ValueError, match="security label"):
        InRoundContributionAccount.model_validate(value)


def test_numeric_contract_digests_use_the_artifact_serializer() -> None:
    admission = build_in_round_contract(
        config_path=Path("configs/in-round-admission.yaml"),
        partition_manifest={
            "client_count": 15,
            "server_evaluation_splits": {
                "validation": {"sha256": _sha(200), "row_count": 10}
            },
        },
    )
    disagreement = build_disagreement_contract(
        config_path=Path("configs/trust-statistical-disagreement.yaml"),
        client_ids=[f"client{index:02d}" for index in range(1, 16)],
    )
    admission_file_sha256 = sha256_bytes(
        derived_json_bytes(admission.model_dump(mode="json"))
    )

    class _Reader:
        @staticmethod
        def json(path: str) -> dict[str, object]:
            value = disagreement if path.endswith("m6-disagreement-contract.json") else admission
            return value.model_dump(mode="json")

        @staticmethod
        def digest(path: str) -> str:
            if path.endswith("in-round-admission-contract.json"):
                return admission_file_sha256
            if path.endswith("in-round-admission.yaml"):
                return admission.core.policy_config_sha256
            if path.endswith("m6-disagreement-experiment.yaml"):
                return disagreement.core.config_sha256
            if path.endswith("m6-disagreement-contract.json"):
                return sha256_bytes(
                    derived_json_bytes(disagreement.model_dump(mode="json"))
                )
            raise AssertionError(path)

    checkpoint = SimpleNamespace(
        core=SimpleNamespace(
            round_number=1,
            admission_contract_id=admission.contract_id,
            admission_contract_sha256=admission_file_sha256,
            policy_config_sha256=admission.core.policy_config_sha256,
        )
    )
    observed_admission, observed_disagreement, _digest = _verify_contracts(
        reader=_Reader(),
        round_root="artifacts/campaign/rounds/round-001",
        checkpoint=checkpoint,
    )
    assert observed_admission == admission
    assert observed_disagreement == disagreement


def test_partition_root_ignores_nested_client_manifests() -> None:
    artifacts = [
        SimpleNamespace(
            relative_path="artifacts/partition/manifest.json",
            artifact_role="federated-data-derivation",
        ),
        SimpleNamespace(
            relative_path="artifacts/partition/server/evaluation.json",
            artifact_role="federated-data-derivation",
        ),
        SimpleNamespace(
            relative_path="artifacts/partition/clients/client01/manifest.json",
            artifact_role="federated-data-derivation",
        ),
        SimpleNamespace(
            relative_path="artifacts/partition/clients/client01/dataset.json",
            artifact_role="federated-data-derivation",
        ),
    ]
    preservation = SimpleNamespace(
        core=SimpleNamespace(derivation_chain=artifacts)
    )
    assert _partition_root(preservation) == "artifacts/partition"
