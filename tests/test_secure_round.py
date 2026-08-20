from __future__ import annotations

import tempfile
import unittest
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import yaml

from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import (
    _admission_checks,
    _tensor_validation,
    _verify_signed,
    admit_and_aggregate,
    verify_secure_round,
)
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
    create_enrollment_request,
    create_software_quote_evidence,
    enroll_nodes,
    initialize_trust_workspace,
    issue_challenges,
    revoke_enrollment,
    verify_quote_evidence,
    verify_software_quote,
)
from fl_forensics.trust_models import MeasurementLog


ROOT = Path(__file__).resolve().parents[1]


class SecureRoundAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.trust = root / "trust"
        self.node_root = root / "nodes"
        self.node = self.node_root / "client01"
        self.submissions_root = root / "submissions"
        self.submission = self.submissions_root / "client01"
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
            ek_public_bytes=b"m5-test-ek",
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
        self.result, _ = verify_quote_evidence(
            workspace=self.trust,
            node_workspace=self.node,
            quote_verifier=verify_software_quote,
        )
        result_path = self.trust / "results" / f"{self.result.result_id}.json"
        enrollment = load_json(self.node / "enrollment_record.json")
        self.contract = RoundClientContract(
            client_id="client01",
            node_id="node01",
            enrollment_id=enrollment["core"]["enrollment_id"],
            attestation_result_id=self.result.result_id,
            attestation_result_sha256=sha256_file(result_path),
            snapshot_sha256="1" * 64,
            snapshot_manifest_sha256="2" * 64,
            train_row_count=3,
        )
        now = datetime.now(UTC)
        self.now = now
        self.coordinator = SoftwareECDSASigner.generate()
        core = SecureRoundContextCore(
            campaign_id="campaign-test",
            round_number=1,
            previous_checkpoint_sha256="0" * 64,
            base_model_sha256="3" * 64,
            training_contract_sha256="4" * 64,
            partition_manifest_sha256="5" * 64,
            federation_config_sha256="6" * 64,
            seed=7,
            local_epochs=2,
            batch_size=4,
            learning_rate_decimal="0.001",
            required_client_count=1,
            clients=[self.contract],
            issued_at=(now - timedelta(seconds=10)).isoformat(),
            expires_at=(now + timedelta(minutes=5)).isoformat(),
        )
        context_digest = digest_object(core.model_dump(mode="json"))
        self.context = SecureRoundContext(
            context_id=f"round-context-{context_digest[:24]}",
            core=core,
            core_digest=context_digest,
            signature={
                "key_id": self.coordinator.key_id,
                "value_b64": self.coordinator.sign_digest(context_digest),
                "trust_level": "software-development",
            },
        )
        self.base = {
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
                {"name": "weight", "shape": [1], "dtype": "float32", "values": [0.0]}
            ],
        }
        self.training_contract_bytes = derived_json_bytes({"test_contract": True})
        self.partition_manifest_bytes = derived_json_bytes({"test_manifest": True})
        self.federation_config_bytes = b"test: federation\n"
        core = self.context.core.model_copy(
            update={
                "base_model_sha256": sha256_bytes(derived_json_bytes(self.base)),
                "training_contract_sha256": sha256_bytes(self.training_contract_bytes),
                "partition_manifest_sha256": sha256_bytes(
                    self.partition_manifest_bytes
                ),
                "federation_config_sha256": sha256_bytes(
                    self.federation_config_bytes
                ),
            }
        )
        context_digest = digest_object(core.model_dump(mode="json"))
        self.context = SecureRoundContext(
            context_id=f"round-context-{context_digest[:24]}",
            core=core,
            core_digest=context_digest,
            signature={
                "key_id": self.coordinator.key_id,
                "value_b64": self.coordinator.sign_digest(context_digest),
                "trust_level": "software-development",
            },
        )
        self.update = {
            **self.base,
            "parameters": [
                {"name": "weight", "shape": [1], "dtype": "float32", "values": [0.5]}
            ],
        }
        update_bytes = derived_json_bytes(self.update)
        metrics_bytes = derived_json_bytes({"train_loss": 0.5})
        write_once(self.submission / "update.json", update_bytes)
        write_once(self.submission / "metrics.json", metrics_bytes)
        bundle_core = UpdateBundleCore(
            campaign_id=self.context.core.campaign_id,
            context_id=self.context.context_id,
            context_digest=self.context.core_digest,
            round_number=1,
            client_id="client01",
            node_id="node01",
            enrollment_id=self.contract.enrollment_id,
            attestation_result_id=self.result.result_id,
            attestation_result_sha256=self.contract.attestation_result_sha256,
            base_model_sha256=self.context.core.base_model_sha256,
            snapshot_sha256=self.contract.snapshot_sha256,
            update_sha256=sha256_bytes(update_bytes),
            metrics_sha256=sha256_bytes(metrics_bytes),
            tensor_schema_sha256=digest_object(tensor_schema(self.update)),
            num_examples=3,
            generated_at=now.isoformat(),
        )
        self.bundle = self._signed_bundle(bundle_core)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _signed_bundle(self, core: UpdateBundleCore) -> UpdateBundle:
        digest = digest_object(core.model_dump(mode="json"))
        return UpdateBundle(
            bundle_id=f"update-bundle-{digest[:24]}",
            core=core,
            core_digest=digest,
            signature={
                "key_id": self.esk.key_id,
                "value_b64": self.esk.sign_digest(digest),
                "trust_level": "swtpm",
            },
        )

    def _checks(self, bundle: UpdateBundle | None = None):
        return _admission_checks(
            bundle=bundle or self.bundle,
            submission=self.submission,
            context=self.context,
            base=self.base,
            trust_workspace=self.trust,
            now=datetime.now(UTC),
        )

    def _aggregation_workspace(self) -> Path:
        workspace = Path(self.temporary.name) / "campaign"
        write_once(
            workspace / "authority" / "round-coordinator.private.pem",
            self.coordinator.private_pem(),
        )
        write_once(
            workspace / "authority" / "round-coordinator.public.pem",
            self.coordinator.public_pem(),
        )
        write_once(
            workspace / "public" / "round-coordinator.public.pem",
            self.coordinator.public_pem(),
        )
        write_json_once(
            workspace / "public" / "round-context.json",
            self.context.model_dump(mode="json"),
        )
        write_once(
            workspace / "public" / "base-model.json", derived_json_bytes(self.base)
        )
        write_once(
            workspace / "public" / "training-contract.json",
            self.training_contract_bytes,
        )
        write_once(
            workspace / "public" / "partition-manifest.json",
            self.partition_manifest_bytes,
        )
        write_once(
            workspace / "public" / "federation.yaml",
            self.federation_config_bytes,
        )
        atomic_json(
            workspace / "state.json",
            {
                "schema_version": "1.0",
                "campaign_id": self.context.core.campaign_id,
                "context_id": self.context.context_id,
                "slots": {},
            },
        )
        write_json_once(
            self.submission / "bundle.json", self.bundle.model_dump(mode="json")
        )
        return workspace

    def test_nominal_bundle_passes_every_admission_check(self) -> None:
        self.assertTrue(_verify_signed(self.context, self.coordinator.private_key.public_key()))
        checks = self._checks()
        self.assertTrue(checks)
        self.assertTrue(all(item.passed for item in checks), checks)

    def test_wrong_base_model_is_rejected(self) -> None:
        changed = self.bundle.core.model_copy(update={"base_model_sha256": "f" * 64})
        failed = {
            item.name
            for item in self._checks(self._signed_bundle(changed))
            if not item.passed
        }
        self.assertIn("round_context_binding", failed)

    def test_changed_unsigned_bundle_identifier_is_rejected(self) -> None:
        changed = self.bundle.model_copy(update={"bundle_id": "update-bundle-forged"})
        enrollment = load_json(self.node / "enrollment_record.json")
        key = load_public_key(enrollment["core"]["esk_public_key_pem"].encode())
        self.assertFalse(_verify_signed(changed, key))

    def test_tampered_update_is_rejected(self) -> None:
        path = self.submission / "update.json"
        path.chmod(path.stat().st_mode | stat.S_IWUSR)
        path.write_bytes(derived_json_bytes(self.base))
        failed = {item.name for item in self._checks() if not item.passed}
        self.assertIn("artifact_digests", failed)

    def test_revoked_client_is_rejected(self) -> None:
        revoke_enrollment(
            workspace=self.trust, client_id="client01", reason="M5 negative test"
        )
        failed = {item.name for item in self._checks() if not item.passed}
        self.assertIn("active_enrollment", failed)

    def test_non_finite_tensor_is_rejected(self) -> None:
        changed = {
            **self.update,
            "parameters": [
                {"name": "weight", "shape": [1], "dtype": "float32", "values": [float("nan")]}
            ],
        }
        valid, detail = _tensor_validation(changed, self.base)
        self.assertFalse(valid)
        self.assertIn("non-finite", detail)

    def test_tensor_value_shape_mismatch_is_rejected(self) -> None:
        changed = {
            **self.update,
            "parameters": [
                {
                    "name": "weight",
                    "shape": [1],
                    "dtype": "float32",
                    "values": [0.1, 0.2],
                }
            ],
        }
        valid, detail = _tensor_validation(changed, self.base)
        self.assertFalse(valid)
        self.assertIn("declared shape", detail)

    def test_identical_retry_is_idempotent_and_changed_bundle_is_quarantined(self) -> None:
        import numpy as np

        workspace = self._aggregation_workspace()

        def aggregate(updates):
            total = sum(weight for _arrays, weight in updates)
            return [
                sum(arrays[index] * weight for arrays, weight in updates) / total
                for index in range(len(updates[0][0]))
            ]

        dependency_values = (np, None, None, None, aggregate, None, None, None)
        with (
            patch("fl_forensics.secure_round.dependencies", return_value=dependency_values),
            patch("fl_forensics.secure_round.EXPECTED_CLIENTS", ["client01"]),
        ):
            first = admit_and_aggregate(
                workspace=workspace,
                trust_workspace=self.trust,
                submissions_root=self.submissions_root,
                now=self.now,
            )
            first_decision_sha = sha256_file(workspace / "decisions" / "client01.json")
            retry = admit_and_aggregate(
                workspace=workspace,
                trust_workspace=self.trust,
                submissions_root=self.submissions_root,
                now=self.now,
            )
        self.assertEqual(first["status"], "aggregated")
        self.assertEqual(retry["status"], "aggregated")
        self.assertEqual(
            first_decision_sha, sha256_file(workspace / "decisions" / "client01.json")
        )
        with (
            patch("fl_forensics.secure_round.dependencies", return_value=dependency_values),
            patch("fl_forensics.secure_round.EXPECTED_CLIENTS", ["client01"]),
        ):
            verification = verify_secure_round(
                workspace=workspace,
                trust_workspace=self.trust,
                submissions_root=self.submissions_root,
            )
        self.assertEqual(verification["status"], "verified", verification)
        self.assertTrue(verification["matches_reference_checkpoint"])

        changed_core = self.bundle.core.model_copy(
            update={"generated_at": (self.now + timedelta(seconds=1)).isoformat()}
        )
        changed = self._signed_bundle(changed_core)
        bundle_path = self.submission / "bundle.json"
        bundle_path.chmod(bundle_path.stat().st_mode | stat.S_IWUSR)
        bundle_path.write_bytes(derived_json_bytes(changed.model_dump(mode="json")))
        with (
            patch("fl_forensics.secure_round.dependencies", return_value=dependency_values),
            patch("fl_forensics.secure_round.EXPECTED_CLIENTS", ["client01"]),
        ):
            conflict = admit_and_aggregate(
                workspace=workspace,
                trust_workspace=self.trust,
                submissions_root=self.submissions_root,
                now=self.now + timedelta(seconds=1),
            )
        self.assertEqual(conflict["status"], "failed")
        self.assertEqual(conflict["quarantined_count"], 1)
        quarantine = list((workspace / "quarantine").glob("*.json"))
        self.assertEqual(len(quarantine), 1)
        decision = load_json(quarantine[0])
        self.assertEqual(decision["core"]["checks"][0]["name"], "replay_slot")


class SecureRoundDeploymentTests(unittest.TestCase):
    def test_compose_isolates_fifteen_client_tpm_snapshot_pairs(self) -> None:
        compose = yaml.safe_load((ROOT / "compose.m5.yaml").read_text(encoding="utf-8"))
        services = compose["services"]
        clients = [f"client{index:02d}" for index in range(1, 16)]
        self.assertTrue(all(client in services for client in clients))
        runtime_image = services["coordinator"]["image"]
        self.assertIn("build", services["coordinator"])
        for index, client in enumerate(clients, start=1):
            self.assertEqual(services[client]["image"], runtime_image)
            self.assertNotIn("build", services[client])
            volumes = "\n".join(services[client]["volumes"])
            expected = f"tpm{index:02d}_socket:/run/swtpm"
            self.assertIn(expected, volumes)
            self.assertIn(f"/clients/{client}/dataset.json:/client/dataset.json:ro", volumes)
            for other in clients:
                if other != client:
                    self.assertNotIn(f"/clients/{other}/dataset.json", volumes)
            self.assertEqual(services[client]["network_mode"], "none")
        coordinator_volumes = "\n".join(services["coordinator"]["volumes"])
        self.assertNotIn("m4-trust:/trust:ro", coordinator_volumes)
        self.assertNotIn("private.pem", coordinator_volumes)
        self.assertIn("enrollment-authority.public.pem", coordinator_volumes)
        self.assertIn("attestation-verifier.public.pem", coordinator_volumes)


if __name__ == "__main__":
    unittest.main()
