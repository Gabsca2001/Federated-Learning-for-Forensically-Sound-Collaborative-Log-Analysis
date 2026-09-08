from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from fl_forensics.composite_admission import (
    decide_admission_policies,
    trust_signal_from_checks,
)
from fl_forensics.composite_admission_models import StatisticalSignal
from fl_forensics.config import load_yaml
from fl_forensics.disagreement_experiment import (
    DisagreementExperimentError,
    build_disagreement_contract,
    condition_for_client,
    effective_trust_checks,
    install_disagreement_contract,
    load_bound_disagreement_contract,
    prepare_submission_intervention,
    verify_submission_intervention,
)
from fl_forensics.in_round_admission import (
    _runtime_decision_core,
    build_in_round_contract,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round_models import SecureCheck
from fl_forensics.storage import write_once

ROOT = Path(__file__).resolve().parents[1]
CLIENT_IDS = [f"client{index:02d}" for index in range(1, 16)]


def model(value: float) -> dict:
    return {
        "schema_version": "1.0",
        "artifact_type": "pytorch_model_state",
        "architecture": {
            "input_features": 1,
            "encoder_hidden_layers": [1],
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
                "values": [value],
            }
        ],
    }


class LiveDisagreementContractTests(unittest.TestCase):
    def test_contract_contains_each_controlled_condition_once(self) -> None:
        contract = build_disagreement_contract(
            config_path=ROOT / "configs" / "trust-statistical-disagreement.yaml",
            client_ids=CLIENT_IDS,
        )
        self.assertEqual(len(contract.core.assignments), 4)
        self.assertEqual(len(set(contract.core.assignments.values())), 4)
        self.assertEqual(
            condition_for_client(contract, "client15"),
            "trust_admissible_statistics_normal",
        )
        self.assertFalse(contract.core.evaluation_labels_used_for_scoring)

    def test_unknown_assigned_client_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source, _digest = load_yaml(
                ROOT / "configs" / "trust-statistical-disagreement.yaml"
            )
            source["experiment"]["assignments"]["client99"] = source[
                "experiment"
            ]["assignments"].pop("client04")
            path = Path(temporary) / "invalid.yaml"
            import yaml

            path.write_text(yaml.safe_dump(source), encoding="utf-8")
            with self.assertRaisesRegex(
                DisagreementExperimentError, "unknown clients"
            ):
                build_disagreement_contract(
                    config_path=path, client_ids=CLIENT_IDS
                )


class LiveDisagreementTreatmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.public = root / "public"
        self.submission = root / "submission"
        write_once(self.public / "base-model.json", derived_json_bytes(model(1.0)))
        _contract, binding = install_disagreement_contract(
            public_workspace=self.public,
            config_path=ROOT / "configs" / "trust-statistical-disagreement.yaml",
            client_ids=CLIENT_IDS,
        )
        write_once(
            self.public / "training-contract.json",
            derived_json_bytes(
                {
                    "clients": [{"client_id": item} for item in CLIENT_IDS],
                    "m6_disagreement_experiment": binding,
                }
            ),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def observed_checks() -> list[SecureCheck]:
        return [
            SecureCheck(name="active_enrollment", passed=True, detail="active"),
            SecureCheck(name="tpm_esk_signature", passed=True, detail="valid"),
            SecureCheck(name="fresh_attestation", passed=True, detail="fresh"),
            SecureCheck(name="artifact_digests", passed=True, detail="valid"),
        ]

    def _write_metrics(self, record) -> None:
        write_once(
            self.submission / "metrics.json",
            derived_json_bytes(
                {"m6_disagreement_experiment": record.model_dump(mode="json")}
            ),
        )

    def test_anomalous_update_is_directionally_transformed_and_recomputes(self) -> None:
        candidate, record = prepare_submission_intervention(
            public_workspace=self.public,
            submission_workspace=self.submission,
            client_id="client02",
            clean_export=model(2.0),
            round_number=1,
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(candidate["parameters"][0]["values"], [-14.0])
        self.assertTrue(record.update_intervention_applied)
        self.assertEqual(record.update_intervention_type, "sign_flip_amplification")
        self.assertEqual(record.update_intervention_scale, 15.0)
        self.assertTrue((self.submission / "clean-update.json").is_file())
        write_once(self.submission / "update.json", derived_json_bytes(candidate))
        self._write_metrics(record)
        verified = verify_submission_intervention(
            public_workspace=self.public,
            submission_workspace=self.submission,
            client_id="client02",
        )
        self.assertEqual(
            verified.condition, "trust_admissible_statistics_anomalous"
        )

    def test_tampered_transformed_update_does_not_verify(self) -> None:
        candidate, record = prepare_submission_intervention(
            public_workspace=self.public,
            submission_workspace=self.submission,
            client_id="client04",
            clean_export=model(2.0),
            round_number=1,
        )
        assert record is not None
        write_once(self.submission / "update.json", derived_json_bytes(candidate))
        self._write_metrics(record)
        path = self.submission / "update.json"
        path.chmod(path.stat().st_mode | stat.S_IWUSR)
        path.write_bytes(derived_json_bytes(model(99.0)))
        with self.assertRaisesRegex(
            DisagreementExperimentError, "candidate digest"
        ):
            verify_submission_intervention(
                public_workspace=self.public,
                submission_workspace=self.submission,
                client_id="client04",
            )

    def test_tampered_intervention_scale_does_not_verify(self) -> None:
        candidate, record = prepare_submission_intervention(
            public_workspace=self.public,
            submission_workspace=self.submission,
            client_id="client02",
            clean_export=model(2.0),
            round_number=1,
        )
        assert record is not None
        write_once(self.submission / "update.json", derived_json_bytes(candidate))
        self._write_metrics(record.model_copy(update={"update_intervention_scale": 99.0}))
        with self.assertRaisesRegex(
            DisagreementExperimentError, "update intervention scale"
        ):
            verify_submission_intervention(
                public_workspace=self.public,
                submission_workspace=self.submission,
                client_id="client02",
            )

    def test_normal_update_is_unchanged_and_has_no_sidecar(self) -> None:
        clean = model(2.0)
        candidate, record = prepare_submission_intervention(
            public_workspace=self.public,
            submission_workspace=self.submission,
            client_id="client01",
            clean_export=clean,
            round_number=1,
        )
        assert record is not None
        self.assertEqual(candidate, clean)
        self.assertFalse(record.update_intervention_applied)
        self.assertFalse((self.submission / "clean-update.json").exists())

    def test_controlled_trust_failure_preserves_observed_pass(self) -> None:
        contract = load_bound_disagreement_contract(self.public)
        assert contract is not None
        observed = self.observed_checks()
        effective = effective_trust_checks(
            checks=observed, contract=contract, client_id="client03"
        )
        self.assertTrue(all(item.passed for item in observed))
        failed = [item for item in effective if not item.passed]
        self.assertEqual([item.name for item in failed], ["fresh_attestation"])
        self.assertIn("controlled M6 counterfactual", failed[0].detail)

    def test_controlled_trust_failure_is_decided_inside_the_live_policy(self) -> None:
        disagreement = load_bound_disagreement_contract(self.public)
        assert disagreement is not None
        admission = build_in_round_contract(
            config_path=ROOT / "configs" / "in-round-admission.yaml",
            partition_manifest={
                "client_count": 15,
                "server_evaluation_splits": {
                    "validation": {"sha256": "a" * 64, "row_count": 1}
                },
            },
        )
        observed = self.observed_checks()
        effective = effective_trust_checks(
            checks=observed, contract=disagreement, client_id="client03"
        )
        trust = trust_signal_from_checks(
            [item.model_dump(mode="json") for item in effective],
            raw_status="passed",
        )
        statistics = StatisticalSignal(client_id="client03", risk=0.0, components=[])
        thresholds = admission.core.thresholds
        policies = decide_admission_policies(
            trust=trust,
            statistics=statistics,
            statistical_threshold=thresholds.statistical_threshold,
            composite_threshold=thresholds.composite_threshold,
            composite_downweight_threshold=thresholds.composite_downweight_threshold,
            trust_weight=thresholds.trust_weight,
        )
        decision_path = self.submission / "observed-trust-decision.json"
        write_once(decision_path, b"{}")
        bundle = SimpleNamespace(
            bundle_id="update-bundle-test",
            core=SimpleNamespace(
                update_sha256="b" * 64,
                num_examples=100,
            ),
        )
        record = {
            "client_id": "client03",
            "bundle": bundle,
            "bundle_sha256": "c" * 64,
            "trust_decision": SimpleNamespace(decision_id="observed-decision"),
            "trust_decision_path": decision_path,
            "checks": observed,
            "raw_attestation_status": "passed",
        }
        state = {
            "client03": {
                "trust": trust,
                "statistics": statistics,
                "policies": policies,
                "primary": next(
                    item for item in policies if item.policy == "gated_composite"
                ),
            }
        }
        context = SimpleNamespace(
            context_id="round-context-test",
            core_digest="d" * 64,
            core=SimpleNamespace(
                campaign_id="campaign-test",
                round_number=1,
            ),
        )
        decision = _runtime_decision_core(
            context=context,
            contract=admission,
            record=record,
            statistical_state=state,
            disagreement_contract=disagreement,
            decided_at="2026-09-08T12:00:00Z",
        )
        self.assertEqual(decision.final_status, "trust_quarantined")
        self.assertEqual(decision.effective_weight_decimal, "0")
        self.assertIsNotNone(decision.statistics)
        self.assertEqual(len(decision.policy_decisions), 4)
        self.assertTrue(all(item.passed for item in observed))


if __name__ == "__main__":
    unittest.main()
