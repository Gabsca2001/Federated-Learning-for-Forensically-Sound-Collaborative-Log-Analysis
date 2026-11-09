from __future__ import annotations

import copy
import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import numpy as np
import test_secure_round as secure_round_tests
import yaml

from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.in_round_admission import (
    admit_and_aggregate_in_round,
    install_in_round_contract,
    verify_in_round_secure_round,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round_models import (
    RoundClientContract,
    SecureRoundContext,
    UpdateBundle,
    UpdateBundleCore,
    tensor_schema,
)
from fl_forensics.storage import atomic_json, load_json, write_json_once, write_once
from fl_forensics.submission_evidence import ensure_submission_receipt
from fl_forensics.submission_evidence_workspace import create_submission_inventory_workspace
from fl_forensics.trust import (
    create_enrollment_request,
    create_software_quote_evidence,
    enroll_nodes,
    issue_challenges,
    revoke_enrollment,
    verify_quote_evidence,
    verify_software_quote,
)
from fl_forensics.trust_models import MeasurementLog


def aggregate_fixture(updates):
    """A transparent, deterministic weighted backend, not model training."""
    total = sum(weight for _arrays, weight in updates)
    return [
        sum(arrays[index] * weight for arrays, weight in updates) / total
        for index in range(len(updates[0][0]))
    ]


def validation_fixture(*, model_export, rows, batch_size):
    del rows, batch_size
    value = float(model_export["parameters"][0]["values"][0])
    return 1.0 if value == 0.0 else (0.0 if value >= 2.0 else 0.8)


class RoundDerivationTests(unittest.TestCase):
    """Real signed fixtures; only the numerical/validation backend is simulated."""

    def setUp(self) -> None:
        self.fixture = secure_round_tests.SecureRoundAdmissionTests(
            "test_nominal_bundle_passes_every_admission_check"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = Path(self.fixture.temporary.name)
        self.signers = {"client01": self.fixture.esk}
        self.contracts = {"client01": self.fixture.contract}
        self._add_second_client()
        self.now = datetime.now(UTC)
        self.workspace = self.fixture._aggregation_workspace()
        self.client_receipts = self.root / "independent-client-copies"
        self.inventory_path = self.root / "input-inventory.json"
        self.validation_path = self.root / "validation.json"
        self.context: SecureRoundContext | None = None
        self.receipts = {}
        values = (np, None, None, None, aggregate_fixture, None, None, None)
        self.backend_patch = patch(
            "fl_forensics.in_round_admission.dependencies", return_value=values
        )
        self.backend_patch.start()
        self.addCleanup(self.backend_patch.stop)
        self.validation_patch = patch(
            "fl_forensics.in_round_admission._validation_f1", side_effect=validation_fixture
        )
        self.validation_patch.start()
        self.addCleanup(self.validation_patch.stop)
        expected_patch = patch(
            "fl_forensics.secure_round.EXPECTED_CLIENTS", ["client01", "client02"]
        )
        expected_patch.start()
        self.addCleanup(expected_patch.stop)

    def _add_second_client(self) -> None:
        node = self.fixture.node_root / "client02"
        measurement = MeasurementLog.model_validate(
            load_json(self.fixture.trust / "baseline" / "measurement_log.json")
        )
        write_json_once(node / "measurement_log.json", measurement.model_dump(mode="json"))
        ak = SoftwareECDSASigner.generate()
        esk = SoftwareECDSASigner.generate()
        self.signers["client02"] = esk
        create_enrollment_request(
            node_workspace=node,
            client_id="client02",
            node_id="node02",
            tpm_instance_id="tpm02",
            trust_level="swtpm",
            ek_public_bytes=b"round-derivation-test-ek-client02",
            ak_public_pem=ak.public_pem(),
            esk_public_pem=esk.public_pem(),
            esk_signer=esk,
            measurement_log=measurement,
        )
        # Enrolling only client02 preserves the fixture's client01 enrollment.
        client_config = self.root / "client02.yaml"
        client_config.write_text(
            yaml.safe_dump(
                {
                    "schema_version": "1.0",
                    "clients": [{"client_id": "client02", "node_id": "node02", "tpm": "tpm02"}],
                }
            ),
            encoding="utf-8",
        )
        enrolled = enroll_nodes(
            workspace=self.fixture.trust,
            node_root=self.fixture.node_root,
            trust_config_path=secure_round_tests.ROOT / "configs" / "trust.yaml",
            clients_config_path=client_config,
            require_all=True,
        )
        self.assertEqual(enrolled["status"], "enrolled", enrolled)
        issue_challenges(
            workspace=self.fixture.trust,
            node_root=self.fixture.node_root,
            trust_config_path=secure_round_tests.ROOT / "configs" / "trust.yaml",
            client_ids=["client02"],
        )
        create_software_quote_evidence(node_workspace=node, ak_signer=ak)
        result, _ = verify_quote_evidence(
            workspace=self.fixture.trust,
            node_workspace=node,
            quote_verifier=verify_software_quote,
        )
        enrollment = load_json(node / "enrollment_record.json")
        self.contracts["client02"] = RoundClientContract(
            client_id="client02",
            node_id="node02",
            enrollment_id=enrollment["core"]["enrollment_id"],
            attestation_result_id=result.result_id,
            attestation_result_sha256=sha256_file(
                self.fixture.trust / "results" / f"{result.result_id}.json"
            ),
            snapshot_sha256="3" * 64,
            snapshot_manifest_sha256="4" * 64,
            train_row_count=3,
        )

    @staticmethod
    def _replace(path: Path, data: bytes) -> None:
        if path.exists():
            path.chmod(0o600)
            path.write_bytes(data)
        else:
            write_once(path, data)

    @staticmethod
    def _remove(path: Path) -> None:
        path.chmod(0o600)
        path.unlink()

    def _prepare(self, *, minimum: int = 1, second_value: float = 0.5) -> None:
        self.assertIsNone(self.context, "a fixture must be prepared only once")
        validation = {
            "schema_version": "1.0",
            "artifact_type": "federated_server_evaluation_split",
            "dataset": "test",
            "split": "validation",
            "class_names": ["benign"],
            "rows": {
                "validation": [{"window_id": "validation-1", "features": [0.0], "label": "benign"}]
            },
        }
        validation_bytes = derived_json_bytes(validation)
        write_once(self.validation_path, validation_bytes)
        partition = {
            "client_count": 2,
            "class_names": ["benign"],
            "server_evaluation_splits": {
                "validation": {
                    "path": "server/splits/validation.json",
                    "sha256": sha256_bytes(validation_bytes),
                    "row_count": 1,
                }
            },
        }
        partition_bytes = derived_json_bytes(partition)
        self._replace(self.workspace / "public" / "partition-manifest.json", partition_bytes)
        config_path = self.root / "runtime-admission.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "schema_version": "1.0",
                    "runtime_admission": {
                        "policy_id": "derivation-test",
                        "primary_policy": "gated_composite",
                        "minimum_contributors": minimum,
                        "accepted_downweight_factor": 0.5,
                        "passed_with_warning_risk": 0.25,
                        "robust_z_cap": 3.0,
                        "validation_metric": "macro_f1_all_model_classes",
                        "calibration": {
                            "semantics": "verified-clean-development-reference",
                            "source_admission_sha256": "a" * 64,
                            "indicator_references": {
                                "validation_impact": {
                                    "direction": "higher",
                                    "median": 0.0,
                                    "mad": 0.1,
                                    "sample_count": 2,
                                }
                            },
                            "indicator_weights": {"validation_impact": 1.0},
                            "thresholds": {
                                "clean_sample_count": 2,
                                "statistical_threshold": 0.6,
                                "composite_downweight_threshold": 0.01,
                                "composite_threshold": 0.3,
                                "trust_weight": 0.5,
                            },
                        },
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        _contract, binding = install_in_round_contract(
            public_workspace=self.workspace / "public",
            config_path=config_path,
            partition_manifest=partition,
        )
        training_bytes = derived_json_bytes({"test_contract": True, "in_round_admission": binding})
        self._replace(self.workspace / "public" / "training-contract.json", training_bytes)
        core = self.fixture.context.core.model_copy(
            update={
                "required_client_count": 2,
                "clients": list(self.contracts.values()),
                "training_contract_sha256": sha256_bytes(training_bytes),
                "partition_manifest_sha256": sha256_bytes(partition_bytes),
            }
        )
        digest = digest_object(core.model_dump(mode="json"))
        self.context = SecureRoundContext(
            context_id=f"round-context-{digest[:24]}",
            core=core,
            core_digest=digest,
            signature={
                "key_id": self.fixture.coordinator.key_id,
                "value_b64": self.fixture.coordinator.sign_digest(digest),
                "trust_level": "software-development",
            },
        )
        self._replace(
            self.workspace / "public" / "round-context.json",
            derived_json_bytes(self.context.model_dump(mode="json")),
        )
        atomic_json(
            self.workspace / "state.json",
            {
                "schema_version": "1.0",
                "campaign_id": self.context.core.campaign_id,
                "context_id": self.context.context_id,
                "slots": {},
            },
        )
        for client_id, value in (("client01", 0.5), ("client02", second_value)):
            bundle_path = self._write_bundle(client_id, value)
            self.receipts[client_id] = ensure_submission_receipt(
                bundle_path=bundle_path,
                context=self.context,
                signer=self.signers[client_id],
                client_public_key=load_public_key(self.signers[client_id].public_pem()),
                trust_level="swtpm",
                client_receipt_root=self.client_receipts,
                submitted_at=self.now,
            )

    def _write_bundle(self, client_id: str, value: float, *, directory: Path | None = None) -> Path:
        assert self.context is not None
        contract = self.contracts[client_id]
        directory = directory or self.fixture.submissions_root / client_id
        model = copy.deepcopy(self.fixture.update)
        model["parameters"][0]["values"] = [value]
        model_bytes = derived_json_bytes(model)
        metrics_bytes = derived_json_bytes({"train_loss": 0.5})
        self._replace(directory / "update.json", model_bytes)
        self._replace(directory / "metrics.json", metrics_bytes)
        core = UpdateBundleCore(
            campaign_id=self.context.core.campaign_id,
            context_id=self.context.context_id,
            context_digest=self.context.core_digest,
            round_number=self.context.core.round_number,
            client_id=client_id,
            node_id=contract.node_id,
            enrollment_id=contract.enrollment_id,
            attestation_result_id=contract.attestation_result_id,
            attestation_result_sha256=contract.attestation_result_sha256,
            base_model_sha256=self.context.core.base_model_sha256,
            snapshot_sha256=contract.snapshot_sha256,
            update_sha256=sha256_bytes(model_bytes),
            metrics_sha256=sha256_bytes(metrics_bytes),
            tensor_schema_sha256=digest_object(tensor_schema(model)),
            num_examples=contract.train_row_count,
            generated_at=self.now.isoformat(),
        )
        digest = digest_object(core.model_dump(mode="json"))
        signer = self.signers[client_id]
        bundle = UpdateBundle(
            bundle_id=f"update-bundle-{digest[:24]}",
            core=core,
            core_digest=digest,
            signature={
                "key_id": signer.key_id,
                "value_b64": signer.sign_digest(digest),
                "trust_level": "swtpm",
            },
        )
        self._replace(directory / "bundle.json", derived_json_bytes(bundle.model_dump(mode="json")))
        return directory / "bundle.json"

    def _options(self):
        return {
            "workspace": self.workspace,
            "trust_workspace": self.fixture.trust,
            "submissions_root": self.fixture.submissions_root,
            "validation_split_path": self.validation_path,
        }

    def _inventory(self) -> None:
        if self.context is None:
            self._prepare()
        report = create_submission_inventory_workspace(
            workspace=self.workspace,
            trust_workspace=self.fixture.trust,
            client_receipts=self.client_receipts,
            submissions_root=self.fixture.submissions_root,
            inventory_path=self.inventory_path,
            now=self.now,
        )
        self.assertEqual(report["status"], "verified_for_evidence_set", report)

    def _run(self):
        if not self.inventory_path.is_file():
            self._inventory()
        return admit_and_aggregate_in_round(
            **self._options(),
            coordinator_workspace=self.workspace,
            input_inventory_path=self.inventory_path,
            client_receipts=self.client_receipts,
            now=self.now,
        )

    def _verify(self, **overrides):
        arguments = {
            **self._options(),
            "client_receipts": self.client_receipts,
            "require_derivation": True,
            **overrides,
        }
        return verify_in_round_secure_round(**arguments)

    @property
    def manifest_path(self) -> Path:
        return self.workspace / "derivation" / "manifest.json"

    def _manifest(self):
        return load_json(self.manifest_path)

    def _resign(self, path: Path, *, id_field: str, prefix: str, change):
        document = load_json(path)
        change(document["core"])
        digest = digest_object(document["core"])
        document["core_digest"] = digest
        document[id_field] = prefix + digest
        document["signature"]["value_b64"] = self.fixture.coordinator.sign_digest(digest)
        atomic_json(path, document)

    def _change_manifest(self, change):
        self._resign(
            self.manifest_path,
            id_field="manifest_id",
            prefix="round-derivation-",
            change=change,
        )

    def test_nominal_derivation_binds_receipts_decisions_scoring_and_checkpoint(self) -> None:
        result = self._run()
        self.assertEqual(result["status"], "aggregated", result)
        report = self._verify()
        self.assertEqual(report["status"], "verified", report)
        self.assertTrue(report["admission_decisions_verified"])
        self.assertFalse(report["deadline_verified"])
        self.assertFalse(report["delivery_verified"])
        manifest = self._manifest()["core"]
        self.assertEqual(manifest["round_status"], "aggregated")
        self.assertEqual(len(manifest["dispositions"]), 2)
        for disposition in manifest["dispositions"]:
            self.assertEqual(disposition["kind"], "runtime_admission")
            self.assertTrue(disposition["mandatory_gate_passed"])
            self.assertTrue(disposition["participated_in_scoring"])
            self.assertEqual(disposition["alpha_numerator"], "1")
            self.assertEqual(disposition["alpha_denominator"], "2")
            self.assertIsNotNone(disposition["decision_sha256"])
            self.assertIsNotNone(disposition["runtime_weight_hex"])
        checkpoint = self.workspace / "checkpoint" / "manifest.json"
        self.assertEqual(manifest["checkpoint_sha256"], sha256_file(checkpoint))

    def test_retry_preserves_all_signed_derivation_bytes(self) -> None:
        self._run()
        files = list((self.workspace / "derivation").glob("*.json"))
        before = {path.name: path.read_bytes() for path in files}
        retried = admit_and_aggregate_in_round(
            **self._options(),
            coordinator_workspace=self.workspace,
            client_receipts=self.client_receipts,
            now=self.now,
        )
        self.assertTrue(retried["idempotent"])
        self.assertEqual(before, {path.name: path.read_bytes() for path in files})
        self.assertEqual(self._verify()["status"], "verified")

    def test_resigned_wrong_coefficient_fails_even_for_identical_updates(self) -> None:
        self._run()
        checkpoint = self.workspace / "checkpoint" / "global-model.json"
        original = checkpoint.read_bytes()
        self._change_manifest(
            lambda core: core["dispositions"][0].update(
                {"alpha_numerator": "3", "alpha_denominator": "4"}
            )
        )
        self.assertEqual(self._verify()["status"], "failed")
        self.assertEqual(checkpoint.read_bytes(), original)

    def test_resigned_runtime_weight_change_is_rejected(self) -> None:
        self._run()
        self._change_manifest(
            lambda core: core["dispositions"][0].update({"runtime_weight_hex": float(7).hex()})
        )
        self.assertEqual(self._verify()["status"], "failed")

    def test_resigned_wrong_decision_hash_is_rejected(self) -> None:
        self._run()
        self._change_manifest(
            lambda core: core["dispositions"][0].update({"decision_sha256": "f" * 64})
        )
        self.assertEqual(self._verify()["status"], "failed")

    def test_resigned_manifest_omitting_a_disposition_is_rejected(self) -> None:
        self._run()
        self._change_manifest(lambda core: core["dispositions"].pop())
        self.assertEqual(self._verify()["status"], "failed")

    def test_resigned_manifest_omitting_a_required_edge_is_rejected(self) -> None:
        self._run()
        self.assertTrue(self._manifest()["core"]["edges"])
        self._change_manifest(lambda core: core["edges"].pop())
        self.assertEqual(self._verify()["status"], "failed")

    def test_resigned_scoring_population_is_independently_recomputed(self) -> None:
        self._run()
        scoring_path = self.workspace / "derivation" / "scoring-state.json"
        old_hash = sha256_file(scoring_path)
        self._resign(
            scoring_path,
            id_field="scoring_id",
            prefix="round-scoring-",
            change=lambda core: core.update({"scored_client_ids": []}),
        )
        new_hash = sha256_file(scoring_path)

        def change(core):
            core["scoring_state_sha256"] = new_hash
            for node in core["nodes"]:
                if node["kind"] == "round_scoring_state":
                    node["sha256"] = new_hash
                    node["node_id"] = "scoring:" + new_hash
            for edge in core["edges"]:
                for endpoint in ("source", "target"):
                    if edge[endpoint] == "scoring:" + old_hash:
                        edge[endpoint] = "scoring:" + new_hash

        self._change_manifest(change)
        self.assertEqual(self._verify()["status"], "failed")

    def test_missing_manifest_cannot_downgrade_to_legacy_verification(self) -> None:
        self._run()
        self._remove(self.manifest_path)
        self.assertEqual(self._verify()["status"], "failed")

    def test_explicit_derivation_requirement_rejects_missing_binding(self) -> None:
        self._run()
        for path in (self.workspace / "derivation").glob("*.json"):
            self._remove(path)
        self.assertEqual(self._verify()["status"], "failed")

    def test_bound_round_without_external_receipts_is_not_fully_verified(self) -> None:
        self._run()
        self.assertEqual(self._verify(client_receipts=None)["status"], "failed")

    def test_partial_external_evidence_cannot_certify_full_derivation(self) -> None:
        self._run()
        receipt = self.receipts["client02"]
        self._remove(self.client_receipts / f"{receipt.core.submission_id}.json")
        self.assertEqual(self._verify()["status"], "failed")

    def test_uninventoried_live_bundle_is_rejected_before_scoring(self) -> None:
        self._prepare()
        receipt = self.receipts["client02"]
        self._remove(self.client_receipts / f"{receipt.core.submission_id}.json")
        self._inventory()
        with self.assertRaises(ValueError):
            self._run()
        self.assertFalse((self.workspace / "checkpoint" / "manifest.json").exists())

    def _assert_public_tamper_rejected(self, filename: str, data: bytes) -> None:
        path = self.workspace / "public" / filename
        original = path.read_bytes()
        try:
            self._replace(path, data)
            with self.assertRaises(ValueError):
                self._run()
            self.assertFalse((self.workspace / "derivation" / "scoring-state.json").exists())
            self.assertFalse((self.workspace / "checkpoint" / "manifest.json").exists())
        finally:
            self._replace(path, original)

    def test_base_model_must_match_the_authenticated_context_before_scoring(self) -> None:
        self._prepare()
        self._inventory()
        changed = copy.deepcopy(self.fixture.base)
        changed["parameters"][0]["values"] = [0.25]
        self._assert_public_tamper_rejected("base-model.json", derived_json_bytes(changed))

    def test_training_contract_bytes_are_bound_before_scoring(self) -> None:
        self._prepare()
        self._inventory()
        changed = load_json(self.workspace / "public" / "training-contract.json")
        changed["uncommitted_change"] = True
        self._assert_public_tamper_rejected("training-contract.json", derived_json_bytes(changed))

    def test_partition_and_federation_bytes_are_bound_before_scoring(self) -> None:
        self._prepare()
        self._inventory()
        partition = load_json(self.workspace / "public" / "partition-manifest.json")
        partition["uncommitted_change"] = True
        changes = {
            "partition-manifest.json": derived_json_bytes(partition),
            "federation.yaml": (self.workspace / "public" / "federation.yaml").read_bytes()
            + b"# uncommitted byte change\n",
        }
        for filename, data in changes.items():
            with self.subTest(public_artifact=filename):
                self._assert_public_tamper_rejected(filename, data)

    def test_missing_payload_has_negative_final_disposition_and_no_scoring(self) -> None:
        self._prepare()
        self._remove(self.fixture.submissions_root / "client02" / "bundle.json")
        self._run()
        dispositions = {
            item["client_id"]: item for item in self._manifest()["core"]["dispositions"]
        }
        rejected = dispositions["client02"]
        self.assertEqual(rejected["kind"], "protocol_rejection")
        self.assertEqual(rejected["intake_outcome"], "rejected_missing_payload")
        self.assertIsNone(rejected["decision_sha256"])
        self.assertFalse(rejected["participated_in_scoring"])
        self.assertEqual(rejected["effective_weight_decimal"], "0")
        scoring = load_json(self.workspace / "derivation" / "scoring-state.json")["core"]
        self.assertEqual(scoring["scored_client_ids"], ["client01"])
        self.assertEqual(self._verify()["status"], "verified")

    def test_conflicting_submissions_are_both_rejected_before_scoring(self) -> None:
        self._prepare()
        conflict_path = self._write_bundle(
            "client01", 0.7, directory=self.root / "client01-second-submission"
        )
        ensure_submission_receipt(
            bundle_path=conflict_path,
            context=self.context,
            signer=self.signers["client01"],
            client_public_key=load_public_key(self.signers["client01"].public_pem()),
            trust_level="swtpm",
            client_receipt_root=self.client_receipts,
            submitted_at=self.now,
        )
        self._run()
        dispositions = self._manifest()["core"]["dispositions"]
        rejected = [item for item in dispositions if item["client_id"] == "client01"]
        self.assertEqual(len(rejected), 2)
        self.assertEqual(len({item["bundle_sha256"] for item in rejected}), 2)
        for item in rejected:
            self.assertEqual(item["kind"], "protocol_rejection")
            self.assertEqual(item["intake_outcome"], "rejected_conflict")
            self.assertIsNone(item["decision_sha256"])
            self.assertFalse(item["participated_in_scoring"])
            self.assertEqual(item["effective_weight_decimal"], "0")
        scoring = load_json(self.workspace / "derivation" / "scoring-state.json")["core"]
        self.assertEqual(scoring["scored_client_ids"], ["client02"])
        manifest = self._manifest()["core"]
        conflict_node = next(
            node
            for node in manifest["nodes"]
            if node["kind"] == "update_bundle" and node["sha256"] == sha256_file(conflict_path)
        )
        self.assertEqual(conflict_node["availability"], "commitment_only")
        self.assertFalse(
            any(
                edge["source"] == conflict_node["node_id"] and edge["kind"] == "num"
                for edge in manifest["edges"]
            )
        )
        self.assertEqual(self._verify()["status"], "verified")

    def test_zero_weight_can_preserve_scoring_participation_and_decision_edges(self) -> None:
        self._prepare(second_value=2.0)
        self._run()
        manifest = self._manifest()["core"]
        rejected = next(
            item for item in manifest["dispositions"] if item["client_id"] == "client02"
        )
        self.assertEqual(rejected["kind"], "runtime_admission")
        self.assertEqual(rejected["final_status"], "statistically_quarantined")
        self.assertTrue(rejected["participated_in_scoring"])
        self.assertEqual(rejected["alpha_numerator"], "0")
        self.assertTrue(any(edge["kind"] == "dec" for edge in manifest["edges"]))
        positive = next(
            item for item in manifest["dispositions"] if item["client_id"] == "client01"
        )

        def node_id(kind, digest=None):
            return next(
                node["node_id"]
                for node in manifest["nodes"]
                if node["kind"] == kind and (digest is None or node["sha256"] == digest)
            )

        excluded_bundle = node_id("update_bundle", rejected["bundle_sha256"])
        score_node = node_id("round_scoring_state")
        accepted_decision = node_id("admission_decision", positive["decision_sha256"])
        checkpoint_node = node_id("checkpoint", manifest["checkpoint_sha256"])
        edges = {(edge["source"], edge["target"], edge["kind"]) for edge in manifest["edges"]}
        self.assertIn((excluded_bundle, score_node, "num"), edges)
        self.assertIn((score_node, accepted_decision, "dec"), edges)
        self.assertIn((accepted_decision, checkpoint_node, "dec"), edges)
        self.assertNotIn((excluded_bundle, checkpoint_node, "num"), edges)
        scoring = load_json(self.workspace / "derivation" / "scoring-state.json")["core"]
        self.assertEqual(scoring["scored_client_ids"], ["client01", "client02"])
        self.assertEqual(self._verify()["status"], "verified")

    def test_failed_gate_has_zero_mass_despite_benign_numeric_update(self) -> None:
        self._prepare()
        revoke_enrollment(
            workspace=self.fixture.trust,
            client_id="client02",
            reason="test mandatory gate",
            revoked_at=self.now.isoformat(),
        )
        self._run()
        rejected = next(
            item
            for item in self._manifest()["core"]["dispositions"]
            if item["client_id"] == "client02"
        )
        self.assertFalse(rejected["mandatory_gate_passed"])
        self.assertEqual(rejected["policy_factor_decimal"], "0")
        self.assertEqual(rejected["effective_weight_decimal"], "0")
        self.assertFalse(rejected["participated_in_scoring"])
        self.assertEqual(rejected["alpha_numerator"], "0")
        self.assertEqual(self._verify()["status"], "verified")

    def test_quorum_loss_has_manifest_without_checkpoint_or_artificial_alpha(self) -> None:
        self._prepare(minimum=2)
        revoke_enrollment(
            workspace=self.fixture.trust,
            client_id="client02",
            reason="test quorum loss",
            revoked_at=self.now.isoformat(),
        )
        result = self._run()
        self.assertEqual(result["status"], "failed", result)
        self.assertFalse((self.workspace / "checkpoint" / "manifest.json").exists())
        manifest = self._manifest()["core"]
        self.assertEqual(manifest["round_status"], "failed_without_checkpoint")
        self.assertIsNone(manifest["checkpoint_sha256"])
        for disposition in manifest["dispositions"]:
            self.assertIsNone(disposition["alpha_numerator"])
            self.assertIsNone(disposition["alpha_denominator"])
        scoring = load_json(self.workspace / "derivation" / "scoring-state.json")["core"]
        self.assertEqual(scoring["trust_eligible_client_ids"], ["client01"])
        self.assertEqual(scoring["scored_client_ids"], [])
        report = self._verify()
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(report["round_status"], "failed_without_checkpoint")

    def test_failed_round_retry_preserves_the_closed_history_without_checkpoint(self) -> None:
        self._prepare(minimum=2)
        revoke_enrollment(
            workspace=self.fixture.trust,
            client_id="client02",
            reason="test immutable failed closure",
            revoked_at=self.now.isoformat(),
        )
        first = self._run()
        self.assertEqual(first["status"], "failed", first)
        paths = list((self.workspace / "derivation").glob("*.json"))
        original = {path.name: path.read_bytes() for path in paths}
        retried = admit_and_aggregate_in_round(
            **self._options(),
            coordinator_workspace=self.workspace,
            client_receipts=self.client_receipts,
            now=self.now,
        )
        self.assertEqual(retried["status"], "failed", retried)
        self.assertEqual(original, {path.name: path.read_bytes() for path in paths})
        self.assertFalse((self.workspace / "checkpoint" / "manifest.json").exists())
        self.assertEqual(self._verify()["status"], "verified")

    def test_cli_derivation_verification_never_silently_downgrades(self) -> None:
        from fl_forensics.cli import main

        self._run()
        arguments = [
            "m5-verify-round-derivation",
            "--workspace",
            str(self.workspace),
            "--trust-workspace",
            str(self.fixture.trust),
            "--submissions",
            str(self.fixture.submissions_root),
            "--validation-split",
            str(self.validation_path),
            "--client-receipts",
            str(self.client_receipts),
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(arguments)
        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0, report)
        self.assertEqual(report["status"], "verified", report)
        self.assertTrue(report["admission_decisions_verified"])
        self._remove(self.manifest_path)
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(arguments)
        report = json.loads(output.getvalue())
        self.assertNotEqual(exit_code, 0)
        self.assertEqual(report["status"], "failed", report)

    def test_actual_flower_backend_reconstructs_the_signed_tensor_checkpoint(self) -> None:
        from flwr.server.strategy.aggregate import aggregate

        self._prepare()
        dependencies = (np, None, None, None, aggregate, None, None, None)
        with patch("fl_forensics.in_round_admission.dependencies", return_value=dependencies):
            result = self._run()
            self.assertEqual(result["status"], "aggregated", result)
            checkpoint_path = self.workspace / "checkpoint" / "global-model.json"
            original_bytes = checkpoint_path.read_bytes()
            report = self._verify()
        self.assertEqual(report["status"], "verified", report)
        self.assertTrue(report["derivation_verified"])
        self.assertTrue(report["aggregate_recomputed"])
        self.assertEqual(checkpoint_path.read_bytes(), original_bytes)
        manifest = self._manifest()["core"]
        self.assertIn("flwr.", manifest["backend_profile"]["callable"])
        self.assertEqual(len(manifest["backend_profile"]["source_sha256"]), 64)

    def test_legacy_round_remains_verifiable_without_claiming_derivation(self) -> None:
        self._prepare()
        result = admit_and_aggregate_in_round(
            **self._options(), coordinator_workspace=self.workspace, now=self.now
        )
        self.assertEqual(result["status"], "aggregated", result)
        report = verify_in_round_secure_round(**self._options())
        self.assertEqual(report["status"], "verified", report)
        self.assertTrue(report["aggregate_recomputed"])
        self.assertFalse(report["derivation_verified"])
        self.assertFalse((self.workspace / "derivation" / "binding.json").exists())


if __name__ == "__main__":
    unittest.main()
