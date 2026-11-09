from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import test_campaign_derivation as campaign_tests
import test_round_derivation as round_tests
import yaml

from fl_forensics.canonical import sha256_file
from fl_forensics.counterfactual_round import (
    CounterfactualError,
    create_counterfactual_round,
    verify_counterfactual_round,
)


class CounterfactualRoundTests(unittest.TestCase):
    def setUp(self):
        self.fixture = campaign_tests.CampaignDerivationTests(
            "test_two_rounds_reach_predictions_explanations_and_report"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.case = self.fixture.first
        self.authority = self.fixture.authority
        self.output = self.case.root / "counterfactual"

    def _source(self, case=None):
        case = case or self.case
        return {
            "round_workspace": case.workspace,
            "submissions_root": case.fixture.submissions_root,
            "validation_split_path": case.validation_path,
            "coordinator_public_key": case.fixture.coordinator.private_key.public_key(),
            "authority_public_key": self.authority.private_key.public_key(),
        }

    @staticmethod
    def _sid(case, client):
        return next(
            item["submission_id"]
            for item in case._manifest()["core"]["dispositions"]
            if item["client_id"] == client
        )

    def _create(self, *, case=None, mode="frozen_decisions", remove=None, output=None):
        case = case or self.case
        result = create_counterfactual_round(
            **self._source(case),
            output=output or self.output,
            expected_source_manifest_sha256=sha256_file(case.manifest_path),
            signer=self.authority,
            mode=mode,
            removed_submission_ids=remove or [],
        )
        self.pin = result["manifest_sha256"]
        return result

    def _verify(self, **changes):
        return verify_counterfactual_round(
            **{**self._source(), "workspace": self.output, "expected_sha256": self.pin, **changes}
        )

    def test_no_removal_reproduces_historical_aggregate_and_zero_deltas(self):
        result = self._create()
        self.assertTrue(result["historical_aggregate_reproduced"])
        self.assertTrue(result["model_bytes_equal"])
        self.assertEqual(result["model_l2_delta"], "0")
        self.assertEqual(
            result["survivor_coefficient_l1_delta"], {"numerator": "0", "denominator": "1"}
        )
        self.assertEqual(result["survivor_action_changes"], [])
        self.assertEqual(self._verify()["status"], "verified")

    def test_original_fixed_population_delta_and_binary_j_include_removal(self):
        result = self._create(remove=[self._sid(self.case, "client02")])
        metrics = result["proposal_metrics"]
        self.assertEqual(metrics["expected_client_ids"], ["client01", "client02"])
        self.assertEqual(metrics["delta_l1"], {"numerator": "1", "denominator": "1"})
        self.assertEqual(metrics["j_any_action_change"], 1)
        self.assertEqual(metrics["changed_client_ids"], ["client02"])
        self.assertEqual(
            metrics["coefficients_after"]["client02"], {"numerator": "0", "denominator": "1"}
        )
        self.assertEqual(metrics["actions_after"]["client02"], {"kind": "not_submitted"})
        self.assertEqual(
            result["survivor_action_change_fraction"], {"numerator": "0", "denominator": "1"}
        )
        self.assertEqual(self._verify()["status"], "verified")

    def test_original_metrics_are_zero_without_removal(self):
        result = self._create()
        self.assertEqual(
            result["proposal_metrics"]["delta_l1"], {"numerator": "0", "denominator": "1"}
        )
        self.assertEqual(result["proposal_metrics"]["j_any_action_change"], 0)

    def test_original_delta_is_undefined_if_quorum_is_lost_but_j_remains_defined(self):
        case = self.fixture._round(minimum=2)
        result = self._create(case=case, remove=[self._sid(case, "client02")])
        self.assertIsNone(result["proposal_metrics"]["delta_l1"])
        self.assertIsNone(result["proposal_metrics"]["coefficients_after"])
        self.assertEqual(result["proposal_metrics"]["j_any_action_change"], 1)

    def test_fixed_population_pads_missing_clients_and_preserves_protocol_rejections(self):
        from fractions import Fraction
        from types import SimpleNamespace

        from fl_forensics.counterfactual_round import _proposal_metrics

        entry = {
            "client_id": "A",
            "submission_id": "sid-A",
            "runtime": SimpleNamespace(core=SimpleNamespace(final_status="accepted")),
        }
        disposition = SimpleNamespace(
            client_id="B", kind="protocol_rejection", final_status="missing_payload"
        )
        result = _proposal_metrics(
            ["A", "B", "C"],
            [disposition],
            [entry],
            set(),
            {"sid-A": Fraction(1)},
            {"sid-A": Fraction(1)},
            {"sid-A": "accepted"},
        )
        self.assertEqual(result["delta_l1"], {"numerator": "0", "denominator": "1"})
        self.assertEqual(result["j_any_action_change"], 0)
        self.assertEqual(result["coefficients_before"]["C"], {"numerator": "0", "denominator": "1"})
        self.assertEqual(result["actions_before"]["C"], {"kind": "not_submitted"})
        self.assertEqual(
            result["actions_before"]["B"],
            {"kind": "protocol_rejection", "statuses": ["missing_payload"]},
        )
        with self.assertRaisesRegex(CounterfactualError, "only runtime"):
            _proposal_metrics(
                ["A", "B", "C"],
                [disposition],
                [entry],
                {"sid-B"},
                {"sid-A": Fraction(1)},
                {"sid-A": Fraction(1)},
                {"sid-A": "accepted"},
            )

    def test_frozen_removal_renormalizes_only_survivors(self):
        remove = self._sid(self.case, "client02")
        survivor = self._sid(self.case, "client01")
        result = self._create(remove=[remove])
        self.assertNotIn(remove, result["coefficients"])
        self.assertEqual(result["coefficients"][survivor], {"numerator": "1", "denominator": "1"})
        self.assertEqual(
            result["survivor_coefficient_l1_delta"], {"numerator": "1", "denominator": "2"}
        )
        self.assertEqual(
            result["additional_coefficient_l1_delta_from_rescoring"],
            {"numerator": "0", "denominator": "1"},
        )
        self.assertEqual(result["survivor_action_changes"], [])
        self.assertTrue(result["model_bytes_equal"])

    def test_removal_losing_quorum_has_no_model_or_coefficients(self):
        case = self.fixture._round(minimum=2)
        result = self._create(case=case, remove=[self._sid(case, "client02")])
        self.assertEqual(result["status"], "failed_without_model")
        self.assertIsNone(result["coefficients"])
        self.assertIsNone(result["model_l2_delta"])
        self.assertFalse((self.output / "model.json").exists())
        self.assertEqual(self._verify(**self._source(case))["status"], "verified")

    def test_round_replay_recomputes_scores_and_policy_without_new_client_signatures(self):
        result = self._create(mode="rescore_round", remove=[self._sid(self.case, "client02")])
        self.assertEqual(len(result["counterfactual_decision_cores"]), 1)
        self.assertFalse(result["new_attestation_performed"])
        self.assertFalse(result["subsequent_client_training_performed"])
        self.assertEqual(self._verify()["status"], "verified")

    def test_zero_weight_removed_input_can_change_survivor_policy(self):
        original = round_tests.install_in_round_contract

        def install(**arguments):
            path = arguments["config_path"]
            config = yaml.safe_load(path.read_text())
            calibration = config["runtime_admission"]["calibration"]
            calibration["indicator_references"]["coordinate_median_distance"] = {
                "direction": "higher",
                "median": 0.0,
                "mad": 1.0,
                "sample_count": 2,
            }
            calibration["indicator_weights"] = {
                "validation_impact": 0.5,
                "coordinate_median_distance": 0.5,
            }
            calibration["thresholds"].update(
                composite_downweight_threshold=0.13, composite_threshold=0.25
            )
            path.write_text(yaml.safe_dump(config))
            return original(**arguments)

        with patch.object(round_tests, "install_in_round_contract", side_effect=install):
            case = self.fixture._round(value=2.0)
        remove = self._sid(case, "client02")
        disposition = next(
            item
            for item in case._manifest()["core"]["dispositions"]
            if item["submission_id"] == remove
        )
        self.assertEqual(disposition["alpha_numerator"], "0")
        self.assertTrue(disposition["participated_in_scoring"])
        frozen = self._create(case=case, remove=[remove], output=self.case.root / "frozen-zero")
        replay = self._create(case=case, mode="rescore_round", remove=[remove])
        survivor = self._sid(case, "client01")
        self.assertEqual(frozen["actions"][survivor], "accepted_downweighted")
        self.assertEqual(replay["actions"][survivor], "accepted")
        self.assertEqual(
            replay["survivor_action_change_fraction"], {"numerator": "1", "denominator": "1"}
        )
        self.assertTrue(replay["model_bytes_equal"])
        diagnostics = replay["separated_influence_diagnostics"]
        self.assertTrue(diagnostics["survivor_action_changed"])
        self.assertEqual(diagnostics["removed_original_weight"]["numerator"], "0")
        # A single survivor changes action but retains normalized weight one.
        self.assertEqual(diagnostics["survivor_policy_total_variation"]["numerator"], "0")
        self.assertEqual(diagnostics["total_model_l2"], 0)
        self.assertEqual(self._verify(**self._source(case))["status"], "verified")

    def test_all_removed_is_a_failed_intervention_not_zero_model(self):
        remove = [item["submission_id"] for item in self.case._manifest()["core"]["dispositions"]]
        result = self._create(mode="rescore_round", remove=remove)
        self.assertEqual(result["status"], "failed_without_model")
        self.assertIsNone(result["survivor_action_change_fraction"])

    def test_unknown_and_duplicate_removals_are_rejected(self):
        with self.assertRaisesRegex(CounterfactualError, "unknown removed"):
            self._create(remove=["unknown"])
        sid = self._sid(self.case, "client01")
        with self.assertRaisesRegex(CounterfactualError, "duplicate"):
            self._create(remove=[sid, sid])

    def test_changed_update_is_detected_before_aggregation(self):
        self.case._replace(self.case.fixture.submissions_root / "client01/update.json", b"changed")
        with self.assertRaisesRegex(CounterfactualError, "update bytes"):
            self._create()

    def test_resigned_wrong_coefficient_is_rejected_even_with_identical_updates(self):
        self.case._change_manifest(
            lambda core: core["dispositions"][0].update(alpha_numerator="3", alpha_denominator="4")
        )
        with self.assertRaisesRegex(CounterfactualError, "coefficient"):
            self._create()

    def test_changed_analysis_and_model_are_rejected(self):
        self._create()
        self.case._replace(self.output / "model.json", b"changed")
        self.assertEqual(self._verify()["status"], "failed")

    def test_signature_and_root_pin_are_required(self):
        self._create()
        self.assertEqual(self._verify(expected_sha256="f" * 64)["status"], "failed")
        from fl_forensics.crypto import SoftwareECDSASigner

        key = SoftwareECDSASigner.generate()
        self.assertEqual(
            self._verify(authority_public_key=key.private_key.public_key())["status"], "failed"
        )

    def test_source_and_decision_bytes_are_preserved(self):
        paths = [
            path
            for root in (self.case.workspace, self.case.fixture.submissions_root)
            for path in root.rglob("*")
            if path.is_file()
        ]
        before = {str(path): path.read_bytes() for path in paths}
        self._create(mode="rescore_round", remove=[self._sid(self.case, "client02")])
        self.assertEqual(self._verify()["status"], "verified")
        self.assertEqual(before, {str(path): path.read_bytes() for path in paths})

    def test_retry_is_immutable_and_another_intervention_cannot_replace_it(self):
        self._create()
        before = (self.output / "manifest.json").read_bytes()
        self._create()
        self.assertEqual((self.output / "manifest.json").read_bytes(), before)
        with self.assertRaisesRegex(CounterfactualError, "different inputs"):
            self._create(remove=[self._sid(self.case, "client02")])

    def test_output_inside_history_is_rejected(self):
        with self.assertRaisesRegex(CounterfactualError, "outside"):
            self._create(output=self.case.workspace / "counterfactual")

    def test_cli_creates_and_recomputes_a_pinned_intervention(self):
        import io
        from contextlib import redirect_stdout

        from fl_forensics.cli import main
        from fl_forensics.storage import write_once

        public, private = self.case.root / "cf.public.pem", self.case.root / "cf.private.pem"
        write_once(public, self.authority.public_pem())
        write_once(private, self.authority.private_pem())
        common = [
            "--workspace",
            str(self.output),
            "--round-workspace",
            str(self.case.workspace),
            "--submissions",
            str(self.case.fixture.submissions_root),
            "--validation-split",
            str(self.case.validation_path),
            "--coordinator-public-key",
            str(self.case.workspace / "public/round-coordinator.public.pem"),
            "--authority-public-key",
            str(public),
        ]
        with redirect_stdout(io.StringIO()) as stdout:
            code = main(
                [
                    "counterfactual-create",
                    *common,
                    "--expected-source-manifest-sha256",
                    sha256_file(self.case.manifest_path),
                    "--authority-private-key",
                    str(private),
                    "--mode",
                    "rescore_round",
                ]
            )
        self.assertEqual(code, 0, stdout.getvalue())
        pin = json.loads(stdout.getvalue())["manifest_sha256"]
        with redirect_stdout(io.StringIO()) as stdout:
            code = main(["counterfactual-verify", *common, "--expected-sha256", pin])
        self.assertEqual(code, 0, stdout.getvalue())
        self.assertTrue(json.loads(stdout.getvalue())["intervention_recomputed"])
