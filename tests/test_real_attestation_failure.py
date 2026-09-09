from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from fl_forensics.attestation import create_attestation_result_v2
from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.in_round_admission import _load_or_create_trust_records
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.real_attestation_failure import (
    RealAttestationFailureError,
    active_target_for_round,
    build_real_attestation_failure_contract,
    install_real_attestation_failure_contract,
    refresh_update_bundle_attestation,
)
from fl_forensics.secure_round import _admission_checks
from fl_forensics.secure_round_models import (
    RoundClientContract,
    SecureRoundContext,
    SecureRoundContextCore,
    UpdateBundle,
    UpdateBundleCore,
    tensor_schema,
)
from fl_forensics.storage import atomic_json, load_json, write_json_once, write_once
from fl_forensics.trust import (
    _load_signer,
    create_enrollment_request,
    create_software_quote_evidence,
    enroll_nodes,
    initialize_trust_workspace,
    issue_challenges,
    verify_quote_evidence,
    verify_software_quote,
)
from fl_forensics.trust_models import AttestationResultCoreV2, MeasurementLog


ROOT = Path(__file__).resolve().parents[1]
CLIENT_IDS = [f"client{index:02d}" for index in range(1, 16)]


class RealAttestationFailureContractTests(unittest.TestCase):
    def test_contract_is_explicitly_bound_to_client03_round30(self) -> None:
        contract = build_real_attestation_failure_contract(
            config_path=ROOT / "configs" / "real-attestation-failure.yaml",
            client_ids=CLIENT_IDS,
        )
        self.assertEqual(contract.core.target_client_id, "client03")
        self.assertEqual(contract.core.active_rounds, [30])
        self.assertEqual(contract.core.expected_post_status, "failed_measurement")
        self.assertTrue(contract.core.local_update_is_probe_only)
        self.assertFalse(contract.core.evaluation_labels_used_for_admission)

    def test_unknown_target_fails_closed(self) -> None:
        source = yaml.safe_load(
            (ROOT / "configs" / "real-attestation-failure.yaml").read_text(
                encoding="utf-8"
            )
        )
        source["experiment"]["target_client_id"] = "client99"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "invalid.yaml"
            path.write_text(yaml.safe_dump(source), encoding="utf-8")
            with self.assertRaisesRegex(
                RealAttestationFailureError, "not a contracted client"
            ):
                build_real_attestation_failure_contract(
                    config_path=path, client_ids=CLIENT_IDS
                )


class RealPostTrainingReattestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.trust = root / "trust"
        self.node_root = root / "nodes"
        self.node = self.node_root / "client01"
        self.round = root / "round"
        self.public = self.round / "public"
        self.submission = self.round / "submissions" / "client01"
        initialize_trust_workspace(
            workspace=self.trust,
            project_root=ROOT,
            trust_config_path=ROOT / "configs" / "trust.yaml",
            clients_config_path=ROOT / "configs" / "clients.yaml",
        )
        measurement = MeasurementLog.model_validate(
            load_json(self.trust / "baseline" / "measurement_log.json")
        )
        write_json_once(
            self.node / "measurement_log.json", measurement.model_dump(mode="json")
        )
        self.ak = SoftwareECDSASigner.generate()
        self.esk = SoftwareECDSASigner.generate()
        create_enrollment_request(
            node_workspace=self.node,
            client_id="client01",
            node_id="node01",
            tpm_instance_id="tpm01",
            trust_level="swtpm",
            ek_public_bytes=b"real-failure-test-ek",
            ak_public_pem=self.ak.public_pem(),
            esk_public_pem=self.esk.public_pem(),
            esk_signer=self.esk,
            measurement_log=measurement,
        )
        enroll_nodes(
            workspace=self.trust,
            node_root=self.node_root,
            trust_config_path=ROOT / "configs" / "trust.yaml",
            clients_config_path=ROOT / "configs" / "clients.yaml",
            require_all=False,
        )
        issue_challenges(
            workspace=self.trust,
            node_root=self.node_root,
            trust_config_path=ROOT / "configs" / "trust.yaml",
            client_ids=["client01"],
        )
        create_software_quote_evidence(node_workspace=self.node, ak_signer=self.ak)
        initial, _ = verify_quote_evidence(
            workspace=self.trust,
            node_workspace=self.node,
            quote_verifier=verify_software_quote,
        )
        initial_path = self.trust / "results" / f"{initial.result_id}.json"
        enrollment = load_json(self.node / "enrollment_record.json")
        client_contract = RoundClientContract(
            client_id="client01",
            node_id="node01",
            enrollment_id=enrollment["core"]["enrollment_id"],
            attestation_result_id=initial.result_id,
            attestation_result_sha256=sha256_file(initial_path),
            snapshot_sha256="1" * 64,
            snapshot_manifest_sha256="2" * 64,
            train_row_count=3,
        )
        config = yaml.safe_load(
            (ROOT / "configs" / "real-attestation-failure.yaml").read_text(
                encoding="utf-8"
            )
        )
        config["experiment"]["target_client_id"] = "client01"
        config["experiment"]["active_rounds"] = [1]
        config_path = root / "real-failure-test.yaml"
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
        _experiment, binding = install_real_attestation_failure_contract(
            public_workspace=self.public,
            config_path=config_path,
            client_ids=["client01"],
        )
        training_bytes = derived_json_bytes(
            {
                "clients": [client_contract.model_dump(mode="json")],
                "m4_m6_real_attestation_failure": binding,
            }
        )
        base = {
            "schema_version": "1.0",
            "artifact_type": "pytorch_model_state",
            "architecture": {
                "input_features": 1,
                "encoder_hidden_layers": [1, 1],
                "embedding_size": 1,
                "classification_head_outputs": 1,
                "activation": "relu",
                "dropout": 0.0,
                "backend": "PyTorch",
            },
            "class_names": ["benign"],
            "parameters": [
                {
                    "name": "weight",
                    "shape": [1],
                    "dtype": "float32",
                    "values": [0.0],
                }
            ],
        }
        self.base = base
        base_bytes = derived_json_bytes(base)
        now = datetime.now(UTC) + timedelta(seconds=10)
        self.now = now
        coordinator = SoftwareECDSASigner.generate()
        context_core = SecureRoundContextCore(
            campaign_id="campaign-real-failure-test",
            round_number=1,
            previous_checkpoint_sha256="0" * 64,
            base_model_sha256=sha256_bytes(base_bytes),
            training_contract_sha256=sha256_bytes(training_bytes),
            partition_manifest_sha256="3" * 64,
            federation_config_sha256="4" * 64,
            seed=7,
            local_epochs=1,
            batch_size=4,
            learning_rate_decimal="0.001",
            required_client_count=1,
            clients=[client_contract],
            issued_at=(now - timedelta(seconds=20)).isoformat(),
            expires_at=(now + timedelta(minutes=5)).isoformat(),
        )
        context_digest = digest_object(context_core.model_dump(mode="json"))
        self.context = SecureRoundContext(
            context_id=f"round-context-{context_digest[:24]}",
            core=context_core,
            core_digest=context_digest,
            signature={
                "key_id": coordinator.key_id,
                "value_b64": coordinator.sign_digest(context_digest),
                "trust_level": "software-development",
            },
        )
        write_once(self.public / "round-coordinator.public.pem", coordinator.public_pem())
        write_once(
            self.round / "authority" / "round-coordinator.private.pem",
            coordinator.private_pem(),
        )
        write_once(
            self.round / "authority" / "round-coordinator.public.pem",
            coordinator.public_pem(),
        )
        write_json_once(
            self.public / "round-context.json", self.context.model_dump(mode="json")
        )
        write_once(self.public / "training-contract.json", training_bytes)
        write_once(self.public / "base-model.json", base_bytes)
        write_once(self.node / "tpm-objects" / "esk.public.pem", self.esk.public_pem())
        atomic_json(
            self.round / "state.json",
            {
                "schema_version": "1.0",
                "campaign_id": self.context.core.campaign_id,
                "context_id": self.context.context_id,
                "slots": {},
            },
        )

        update = {
            **base,
            "parameters": [
                {
                    "name": "weight",
                    "shape": [1],
                    "dtype": "float32",
                    "values": [0.5],
                }
            ],
        }
        update_bytes = derived_json_bytes(update)
        metrics_bytes = derived_json_bytes({"train_loss": 0.5})
        write_once(self.submission / "update.json", update_bytes)
        write_once(self.submission / "metrics.json", metrics_bytes)
        original_core = UpdateBundleCore(
            campaign_id=self.context.core.campaign_id,
            context_id=self.context.context_id,
            context_digest=self.context.core_digest,
            round_number=1,
            client_id="client01",
            node_id="node01",
            enrollment_id=client_contract.enrollment_id,
            attestation_result_id=initial.result_id,
            attestation_result_sha256=sha256_file(initial_path),
            base_model_sha256=self.context.core.base_model_sha256,
            snapshot_sha256=client_contract.snapshot_sha256,
            update_sha256=sha256_bytes(update_bytes),
            metrics_sha256=sha256_bytes(metrics_bytes),
            tensor_schema_sha256=digest_object(tensor_schema(update)),
            num_examples=3,
            generated_at=(now - timedelta(seconds=5)).isoformat(),
        )
        original_digest = digest_object(original_core.model_dump(mode="json"))
        original = UpdateBundle(
            bundle_id=f"update-bundle-{original_digest[:24]}",
            core=original_core,
            core_digest=original_digest,
            signature={
                "key_id": self.esk.key_id,
                "value_b64": self.esk.sign_digest(original_digest),
                "trust_level": "swtpm",
            },
        )
        write_json_once(self.submission / "bundle.json", original.model_dump(mode="json"))

        failed_core = AttestationResultCoreV2.model_validate(
            {
                **initial.core.model_dump(mode="json"),
                "challenge_id": "challenge-post-training-test",
                "status": "failed_measurement",
                "evaluated_at": (now - timedelta(seconds=2)).isoformat(),
                "expires_at": (now + timedelta(minutes=4)).isoformat(),
                "reasons": ["tpm2_checkquote rejected the non-baseline PCR value"],
            }
        )
        failed = create_attestation_result_v2(
            failed_core,
            _load_signer(self.trust, "attestation-verifier"),
            trust_level="swtpm",
        )
        self.failed_path = self.trust / "results" / f"{failed.result_id}.json"
        write_json_once(self.failed_path, failed.model_dump(mode="json"))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_real_failed_result_is_rebound_and_only_trust_gate_fails(self) -> None:
        before_update = sha256_file(self.submission / "update.json")
        result = refresh_update_bundle_attestation(
            public_workspace=self.public,
            node_workspace=self.node,
            submission_workspace=self.submission,
            attestation_result_path=self.failed_path,
            client_id="client01",
            tcti="unused-in-software-test",
            now=self.now,
            signer=self.esk,
        )
        self.assertEqual(result["status"], "rebound_post_training_attestation")
        self.assertTrue((self.submission / "pre-reattestation-bundle.json").is_file())
        self.assertEqual(sha256_file(self.submission / "update.json"), before_update)
        final = UpdateBundle.model_validate(load_json(self.submission / "bundle.json"))
        checks = _admission_checks(
            bundle=final,
            submission=self.submission,
            context=self.context,
            base=self.base,
            trust_workspace=self.trust,
            now=self.now,
            post_training_attestation_client_id="client01",
        )
        failed = [item for item in checks if not item.passed]
        self.assertEqual([item.name for item in failed], ["fresh_attestation"])
        self.assertIn("status=failed_measurement", failed[0].detail)
        self.assertEqual(active_target_for_round(self.public, 1), "client01")

        created, missing = _load_or_create_trust_records(
            workspace=self.round,
            trust_workspace=self.trust,
            submissions_root=self.round / "submissions",
            now=self.now,
            create=True,
            coordinator_workspace=self.round,
        )
        replayed, replay_missing = _load_or_create_trust_records(
            workspace=self.round,
            trust_workspace=self.trust,
            submissions_root=self.round / "submissions",
            now=self.now,
            create=False,
        )
        self.assertEqual(missing, [])
        self.assertEqual(replay_missing, [])
        self.assertEqual(created[0]["trust_decision"].core.status, "quarantined")
        self.assertEqual(replayed[0]["trust_decision"], created[0]["trust_decision"])


if __name__ == "__main__":
    unittest.main()
