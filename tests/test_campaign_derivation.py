from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

import test_round_derivation as round_tests

from fl_forensics.campaign_derivation import (
    CampaignDerivationError,
    _acyclic,
    create_campaign_derivation,
    structural_blast_radius,
    structural_blast_radius_set,
    verify_campaign_derivation,
)
from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.investigation_models import (
    AttackMappingBundleManifest,
    ExplanationBundleManifest,
    InvestigationReportBundleManifest,
    PredictionBundleManifest,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.storage import write_json_once, write_once
from fl_forensics.submission_evidence import submission_identity


class CampaignDerivationTests(unittest.TestCase):
    """Real signed round fixtures; product bodies are structural schema fixtures."""

    def setUp(self) -> None:
        self.cases = []
        self.rounds = {}
        self.products = {}
        self.authority = SoftwareECDSASigner.generate()
        self.first = self._round()
        self.root = self.first.root
        self.output = self.root / "campaign-graph"

    def _round(self, parent=None, *, value=0.5, minimum=1, wrong_base=False,
               replay_bundle_from=None, borrowed_client=None):
        case = round_tests.RoundDerivationTests(
            "test_nominal_derivation_binds_receipts_decisions_scoring_and_checkpoint"
        )
        case.setUp()
        self.addCleanup(case.doCleanups)
        if self.cases:
            case.fixture.coordinator = self.cases[0].fixture.coordinator
            for path in (
                "authority/round-coordinator.private.pem",
                "authority/round-coordinator.public.pem",
                "public/round-coordinator.public.pem",
            ):
                data = (
                    case.fixture.coordinator.private_pem()
                    if "private" in path
                    else case.fixture.coordinator.public_pem()
                )
                case._replace(case.workspace / path, data)
        self.cases.append(case)
        if parent is not None:
            checkpoint = json.loads(
                (parent.workspace / "checkpoint" / "manifest.json").read_bytes()
            )
            base = (
                parent.workspace / "public" / "base-model.json"
                if wrong_base
                else parent.workspace / "checkpoint" / "global-model.json"
            ).read_bytes()
            case._replace(case.workspace / "public" / "base-model.json", base)
            core = case.fixture.context.core.model_copy(
                update={
                    "round_number": parent.context.core.round_number + 1,
                    "previous_checkpoint_sha256": sha256_file(
                        parent.workspace / "checkpoint" / "manifest.json"
                    ),
                    "base_model_sha256": sha256_bytes(base),
                }
            )
            case.fixture.context = case.fixture.context.model_copy(update={"core": core})
            self.assertEqual(checkpoint["core"]["campaign_id"], core.campaign_id)
        case._prepare(second_value=value, minimum=minimum)
        if replay_bundle_from is not None:
            self._claim_bundle(case, replay_bundle_from, "client01", "client01")
        if borrowed_client is not None:
            self._claim_bundle(case, case, "client01", borrowed_client)
        result = case._run()
        self.assertIn(result["status"], {"aggregated", "failed"}, result)
        self.rounds[sha256_file(case.manifest_path)] = case.workspace
        return case

    def _claim_bundle(self, case, source, source_client, claim_client):
        """A legitimate signer claims bytes which must fail bundle admission."""
        source_path = source.fixture.submissions_root / source_client / "bundle.json"
        raw = source_path.read_bytes()
        bundle = json.loads(raw)
        previous = case.receipts[claim_client]
        signer = case.signers[claim_client]
        core = previous.core.model_copy(update={
            "submission_id": submission_identity(case.context, claim_client, sha256_bytes(raw)),
            "bundle_id": bundle["bundle_id"], "bundle_sha256": sha256_bytes(raw),
            "bundle_core_digest": bundle["core_digest"],
        })
        digest = digest_object(core.model_dump(mode="json"))
        receipt = previous.model_copy(update={
            "core": core, "core_digest": digest, "receipt_id": "submission-receipt-" + digest,
            "signature": previous.signature.model_copy(update={
                "key_id": signer.key_id, "value_b64": signer.sign_digest(digest),
            }),
        })
        case._remove(case.client_receipts / f"{previous.core.submission_id}.json")
        case._replace(case.fixture.submissions_root / claim_client / "bundle.json", raw)
        data = derived_json_bytes(receipt.model_dump(mode="json"))
        case._replace(case.fixture.submissions_root / claim_client / "submission-receipt.json", data)
        case._replace(case.client_receipts / f"{receipt.core.submission_id}.json", data)
        case.receipts[claim_client] = receipt

    def _assert_separate_bundle_origins(self, case, accepted_case):
        self.assertEqual(accepted_case._verify()["status"], "verified")
        self.assertEqual(case._verify()["status"], "verified")
        rejected = next(x for x in case._manifest()["core"]["dispositions"]
                        if x["client_id"] == ("client02" if case is accepted_case else "client01"))
        self.assertEqual(rejected["kind"], "protocol_rejection")
        self._create()
        graph = json.loads((self.output / "manifest.json").read_bytes())["core"]
        contexts = {r["context_digest"]: r for r in graph["rounds"]}
        accepted_sid = accepted_case.receipts["client01"].core.submission_id
        accepted_node = contexts[accepted_case.context.core_digest]["submissions"][accepted_sid]
        rejected_node = contexts[case.context.core_digest]["submissions"][rejected["submission_id"]]
        self.assertNotEqual(accepted_node, rejected_node)
        nodes = {n["node_id"]: n for n in graph["nodes"]}
        self.assertEqual(nodes[accepted_node]["sha256"], nodes[rejected_node]["sha256"])
        self.assertEqual(len(nodes[accepted_node]["contexts"]), 1)
        self.assertEqual(len(nodes[rejected_node]["contexts"]), 1)
        radius = self._blast(case, client=rejected["client_id"])
        self.assertEqual(radius["status"], "verified", radius)
        self.assertFalse(any(n["kind"] in {"checkpoint", "checkpoint_model", "round_scoring_state"}
                             for n in radius["reachable"]))
        self.assertEqual(self._verify()["status"], "verified")

    def test_replayed_rejected_bundle_keeps_its_own_round_occurrence(self):
        second = self._round(self.first, replay_bundle_from=self.first)
        self._assert_separate_bundle_origins(second, self.first)

    def test_borrowed_bundle_keeps_its_own_client_occurrence(self):
        case = self._round(borrowed_client="client02")
        self._assert_separate_bundle_origins(case, case)

    def _common(self):
        return {
            "round_workspaces": self.rounds,
            "product_workspaces": self.products,
            "coordinator_public_key": self.first.fixture.coordinator.private_key.public_key(),
            "authority_public_key": self.authority.private_key.public_key(),
        }

    def _create(self):
        result = create_campaign_derivation(
            output=self.output, signer=self.authority, **self._common()
        )
        self.pin = result["manifest_sha256"]
        return result

    def _verify(self, **changes):
        return verify_campaign_derivation(
            **{**self._common(), "workspace": self.output, "expected_sha256": self.pin, **changes}
        )

    def _blast(self, case=None, client="client01", **changes):
        case = case or self.first
        submission = next(
            item["submission_id"]
            for item in case._manifest()["core"]["dispositions"]
            if item["client_id"] == client
        )
        return structural_blast_radius(
            **{
                **self._common(),
                "workspace": self.output,
                "expected_sha256": self.pin,
                "submission_id": submission,
                **changes,
            }
        )

    def test_explicit_submission_set_deduplicates_descendants_and_retains_each_origin(self):
        second = self._round(self.first)
        self._product(second)
        self._create()
        singles = [self._blast(case) for case in (self.first, second)]
        ids = [r["submission_id"] for r in singles]
        result = structural_blast_radius_set(
            submission_ids=ids, workspace=self.output, expected_sha256=self.pin, **self._common()
        )
        self.assertEqual(result["status"], "verified", result)
        expected = {n["node_id"] for r in singles for n in r["reachable"]}
        self.assertEqual({n["node_id"] for n in result["reachable"]}, expected)
        self.assertLess(result["unique_reachable_count"], result["sum_of_per_origin_counts"])
        self.assertFalse(result["numerical_effect_demonstrated"])
        for node in result["reachable"]:
            self.assertTrue(all(p["origin_submission_id"] in ids for p in node["paths"]))

    def test_explicit_submission_set_rejects_empty_duplicate_and_unknown_sources(self):
        self._create()
        sid = self._blast()["submission_id"]
        for selection in ([], [sid, sid], [sid, "unknown"]):
            result = structural_blast_radius_set(
                submission_ids=selection,
                workspace=self.output,
                expected_sha256=self.pin,
                **self._common(),
            )
            self.assertEqual(result["status"], "failed", result)

    def _product(self, case, kind="prediction", *, prediction=None, explanation=None, attack=None):
        index = len(self.products)
        workspace = self.root / "products" / f"{kind}-{index}"
        cp_path = case.workspace / "checkpoint" / "manifest.json"
        cp = json.loads(cp_path.read_bytes())
        common = {
            "campaign_id": case.context.core.campaign_id,
            "round_number": case.context.core.round_number,
            "global_model_sha256": cp["core"]["global_model_sha256"],
            "partition_manifest_sha256": case.context.core.partition_manifest_sha256,
        }
        hashes = {}
        payload_names = {
            "prediction": ["predictions.json", "lineage.json"],
            "explanation": [
                "integrated-gradients.json",
                "prototype-reference.json",
                "prototype-distances.json",
            ],
            "attack_mapping": ["attack-mappings.json"],
            "investigation_report": ["investigation-report.json", "report.md"],
        }[kind]
        for filename in payload_names:
            data = json.dumps({"fixture": filename, "case": index}).encode()
            write_once(workspace / filename, data)
            hashes[filename] = sha256_bytes(data)
        if prediction:
            pred_hash, pred = prediction
            source = {
                **common,
                "prediction_bundle_id": pred.bundle_id,
                "prediction_manifest_sha256": pred_hash,
                "predictions_sha256": pred.core.predictions_sha256,
                "lineage_sha256": pred.core.lineage_sha256,
            }
        if explanation:
            expl_hash, expl = explanation
            source.update(
                explanation_bundle_id=expl.explanation_bundle_id,
                explanation_manifest_sha256=expl_hash,
                integrated_gradients_sha256=expl.core.integrated_gradients_sha256,
                prototype_reference_sha256=expl.core.prototype_reference_sha256,
                prototype_distances_sha256=expl.core.prototype_distances_sha256,
            )
        if attack:
            attack_hash, attack_value = attack
            source.update(
                attack_mapping_bundle_id=attack_value.attack_mapping_bundle_id,
                attack_manifest_sha256=attack_hash,
                attack_mappings_sha256=attack_value.core.attack_mappings_sha256,
            )
        if kind == "prediction":
            model, id_field, prefix = PredictionBundleManifest, "bundle_id", "m7-prediction-bundle-"
            core = {
                "code_version": "fixture",
                "implementation_sha256": "1" * 64,
                "investigation_config_sha256": "2" * 64,
                "prediction_count": 1,
                "source_event_count": 1,
                "source_record_count": 1,
                "sources": {
                    **common,
                    "context_id": case.context.context_id,
                    "checkpoint_id": cp["checkpoint_id"],
                    "round_context_sha256": sha256_file(
                        case.workspace / "public" / "round-context.json"
                    ),
                    "checkpoint_manifest_sha256": sha256_file(cp_path),
                    **dict.fromkeys(
                        [
                            "server_evaluation_sha256",
                            "m2_manifest_sha256",
                            "m2_dataset_sha256",
                            "m2_scaler_sha256",
                            "m2_lineage_sha256",
                        ],
                        "3" * 64,
                    ),
                },
                "selection": {
                    "split": "validation",
                    "method": "explicit-window-ids",
                    "selection_provenance": "investigator-supplied-basis-not-assessed",
                    "window_ids": ["fixture-1"],
                    "row_count": 1,
                },
                "predictions_sha256": hashes["predictions.json"],
                "lineage_sha256": hashes["lineage.json"],
                "reportability_gate": {"complete_window_count": 1},
            }
        elif kind == "explanation":
            model, id_field, prefix = (
                ExplanationBundleManifest,
                "explanation_bundle_id",
                "m7-explanation-bundle-",
            )
            core = {
                "code_version": "fixture",
                "implementation_sha256": dict.fromkeys(
                    ["explanation_bundle", "prediction_bundle", "prototype_core"], "1" * 64
                ),
                "explanation_config_sha256": "2" * 64,
                "source": source,
                "prediction_count": 1,
                "feature_count": 1,
                "class_count": 2,
                "integrated_gradients_sha256": hashes["integrated-gradients.json"],
                "prototype_reference_sha256": hashes["prototype-reference.json"],
                "prototype_distances_sha256": hashes["prototype-distances.json"],
                "maximum_absolute_completeness_error_scaled_1e12": 0,
                "reportability_gate": {"complete_prediction_count": 1},
            }
        elif kind == "attack_mapping":
            model, id_field, prefix = (
                AttackMappingBundleManifest,
                "attack_mapping_bundle_id",
                "m7-attack-mapping-bundle-",
            )
            core = {
                "code_version": "fixture",
                "implementation_sha256": "1" * 64,
                "attack_config_sha256": "2" * 64,
                "model_class_names": ["benign"],
                "source": source,
                "mapping_count": 1,
                "candidate_tactic_mapping_count": 0,
                "not_applicable_mapping_count": 1,
                "unresolved_mapping_count": 0,
                "attack_mappings_sha256": hashes["attack-mappings.json"],
                "reportability_gate": {
                    "complete_prediction_count": 1,
                    "unresolved_prediction_count": 0,
                },
            }
        else:
            model, id_field, prefix = (
                InvestigationReportBundleManifest,
                "investigation_report_bundle_id",
                "m7-investigation-report-bundle-",
            )
            core = {
                "code_version": "fixture",
                "implementation_sha256": "1" * 64,
                "report_config_sha256": "2" * 64,
                "source": source,
                "case_count": 1,
                "source_event_count": 1,
                "source_record_count": 1,
                "candidate_tactic_case_count": 0,
                "not_applicable_attack_case_count": 1,
                "unresolved_attack_case_count": 0,
                "investigation_report_sha256": hashes["investigation-report.json"],
                "report_markdown_sha256": hashes["report.md"],
                "reportability_gate": {"complete_case_count": 1},
            }
        # Materialize defaults before computing the canonical identity.
        core_model = model.model_fields["core"].annotation.model_validate(core)
        if kind in {"attack_mapping", "investigation_report"}:
            from fl_forensics.attack_mapping import _canonical_json_bytes

            digest = sha256_bytes(_canonical_json_bytes(core_model.model_dump(mode="json")))
        else:
            digest = digest_object(core_model.model_dump(mode="json"))
        value = model.model_validate(
            {id_field: prefix + digest[:24], "core": core_model, "canonical_core_sha256": digest}
        )
        write_json_once(workspace / "manifest.json", value.model_dump(mode="json"))
        pin = sha256_file(workspace / "manifest.json")
        self.products[pin] = workspace
        return pin, value

    def _all_products(self, case):
        prediction = self._product(case)
        explanation = self._product(case, "explanation", prediction=prediction)
        attack = self._product(
            case, "attack_mapping", prediction=prediction, explanation=explanation
        )
        report = self._product(
            case,
            "investigation_report",
            prediction=prediction,
            explanation=explanation,
            attack=attack,
        )
        return prediction, explanation, attack, report

    def _reject_wrong_product_serialization(self, kind):
        products = self._all_products(self.first)
        old_pin, value = products[2 if kind == "attack_mapping" else 3]
        workspace = self.products.pop(old_pin)
        # This hash and ID are mutually consistent, but violate the producer's
        # original profile by stripping the final newline from its core bytes.
        wrong_digest = digest_object(value.core.model_dump(mode="json"))
        document = value.model_dump(mode="json")
        field = (
            "attack_mapping_bundle_id"
            if kind == "attack_mapping"
            else "investigation_report_bundle_id"
        )
        document[field] = document[field][:-24] + wrong_digest[:24]
        document["canonical_core_sha256"] = wrong_digest
        self.first._replace(workspace / "manifest.json", derived_json_bytes(document))
        self.products[sha256_file(workspace / "manifest.json")] = workspace
        with self.assertRaisesRegex(CampaignDerivationError, "invalid content-addressed"):
            self._create()

    def test_mapping_identity_requires_its_original_newline_profile(self):
        self._reject_wrong_product_serialization("attack_mapping")

    def test_report_identity_requires_its_original_newline_profile(self):
        self._reject_wrong_product_serialization("investigation_report")

    def test_two_rounds_reach_predictions_explanations_and_report(self):
        second = self._round(self.first)
        self._all_products(second)
        self._create()
        report = self._blast()
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(report["counts_by_kind"]["checkpoint"], 2)
        for kind in ("prediction", "explanation", "attack_mapping", "investigation_report"):
            self.assertEqual(report["counts_by_kind"][kind], 1)
        self.assertFalse(report["numerical_effect_demonstrated"])
        self.assertFalse(report["historical_rounds_numerically_recomputed"])
        self.assertFalse(report["product_payloads_recomputed"])
        self.assertFalse(report["global_artifact_completeness_verified"])

    def test_zero_weight_scoring_participant_has_decision_dependency(self):
        case = self._round(value=2.0)
        disposition = next(
            item
            for item in case._manifest()["core"]["dispositions"]
            if item["client_id"] == "client02"
        )
        self.assertEqual(disposition["alpha_numerator"], "0")
        self.assertTrue(disposition["participated_in_scoring"])
        self._create()
        report = self._blast(case, "client02")
        checkpoint = next(item for item in report["reachable"] if item["kind"] == "checkpoint")
        categories = {path["category"] for path in checkpoint["paths"]}
        self.assertIn("decision_dependency", categories)
        self.assertNotIn("numerical_dependency", categories)

    def test_missing_intermediate_round_is_not_a_new_genesis(self):
        second = self._round(self.first)
        self.rounds = {sha256_file(second.manifest_path): second.workspace}
        with self.assertRaisesRegex(CampaignDerivationError, "missing parent"):
            self._create()

    def test_parent_checkpoint_requires_identical_base_model_bytes(self):
        self._round(self.first, wrong_base=True)
        with self.assertRaisesRegex(CampaignDerivationError, "base model"):
            self._create()

    def test_same_model_bytes_on_sibling_branches_do_not_merge_occurrences(self):
        left = self._round(self.first)
        right = self._round(self.first)
        self.assertEqual(
            (left.workspace / "checkpoint/global-model.json").read_bytes(),
            (right.workspace / "checkpoint/global-model.json").read_bytes(),
        )
        pred_left = self._product(left)
        pred_right = self._product(right)
        self._create()
        reachable = {item["node_id"] for item in self._blast(left)["reachable"]}
        self.assertIn(f"prediction:{pred_left[0]}", reachable)
        self.assertNotIn(f"prediction:{pred_right[0]}", reachable)

    def test_deleted_product_payload_remains_reachable_as_missing(self):
        prediction = self._product(self.first)
        self._create()
        path = self.products[prediction[0]] / "predictions.json"
        path.chmod(0o600)
        path.unlink()
        report = self._blast()
        self.assertEqual(report["status"], "verified", report)
        self.assertFalse(report["supplied_product_payloads_complete"])
        payload = next(
            item for item in report["reachable"] if item["node_id"].endswith(":predictions.json")
        )
        self.assertEqual(payload["availability"], "missing")
        self.assertEqual(payload["snapshot_availability"], "available")

    def test_modified_product_payload_fails(self):
        prediction = self._product(self.first)
        self._create()
        self.first._replace(self.products[prediction[0]] / "predictions.json", b"changed")
        self.assertEqual(self._verify()["status"], "failed")

    def test_changed_product_manifest_fails_the_pin(self):
        prediction = self._product(self.first)
        self._create()
        path = self.products[prediction[0]] / "manifest.json"
        self.first._replace(path, path.read_bytes() + b" ")
        self.assertEqual(self._verify()["status"], "failed")

    def test_snapshot_detects_omitted_product_in_verification_inputs(self):
        self._product(self.first)
        self._create()
        self.assertEqual(self._verify(product_workspaces={})["status"], "failed")

    def test_explanation_requires_its_pinned_prediction_manifest(self):
        prediction = self._product(self.first)
        self._product(self.first, "explanation", prediction=prediction)
        self.products.pop(prediction[0])
        with self.assertRaisesRegex(CampaignDerivationError, "missing prediction"):
            self._create()

    def test_report_cannot_mix_equal_model_sibling_sources(self):
        left, right = self._round(self.first), self._round(self.first)
        pred_left = self._product(left)
        pred_right = self._product(right)
        explanation = self._product(right, "explanation", prediction=pred_right)
        attack = self._product(
            left, "attack_mapping", prediction=pred_left, explanation=explanation
        )
        self._product(
            left,
            "investigation_report",
            prediction=pred_left,
            explanation=explanation,
            attack=attack,
        )
        with self.assertRaisesRegex(CampaignDerivationError, "different derivation branches"):
            self._create()

    def test_resigned_snapshot_with_omitted_edge_fails_reconstruction(self):
        self._create()
        path = self.output / "manifest.json"
        value = json.loads(path.read_bytes())
        value["core"]["edges"].pop()
        digest = digest_object(value["core"])
        value.update(core_digest=digest, manifest_id="campaign-derivation-" + digest)
        value["signature"]["value_b64"] = self.authority.sign_digest(digest)
        self.first._replace(path, derived_json_bytes(value))
        self.pin = sha256_file(path)
        self.assertEqual(self._verify()["status"], "failed")

    def test_wrong_snapshot_pin_and_wrong_signer_fail(self):
        self._create()
        self.assertEqual(self._verify(expected_sha256="f" * 64)["status"], "failed")
        other = SoftwareECDSASigner.generate()
        self.assertEqual(
            self._verify(authority_public_key=other.private_key.public_key())["status"], "failed"
        )

    def test_retry_reuses_signed_snapshot_bytes(self):
        self._create()
        before = (self.output / "manifest.json").read_bytes()
        self._create()
        self.assertEqual((self.output / "manifest.json").read_bytes(), before)

    def test_historical_round_mutation_fails_authentication(self):
        self._create()
        self.first._replace(self.first.workspace / "checkpoint/global-model.json", b"changed")
        self.assertEqual(self._verify()["status"], "failed")

    def test_unknown_submission_fails_instead_of_empty_radius(self):
        self._create()
        self.assertEqual(self._blast(submission_id="unknown")["status"], "failed")

    def test_cycles_and_missing_endpoints_fail(self):
        with self.assertRaisesRegex(CampaignDerivationError, "cycle"):
            _acyclic({"a": None, "b": None}, {("a", "b", "num"), ("b", "a", "audit")})
        with self.assertRaisesRegex(CampaignDerivationError, "endpoint"):
            _acyclic({"a": None}, {("a", "b", "num")})

    def test_graph_cannot_write_inside_historical_round(self):
        with self.assertRaisesRegex(CampaignDerivationError, "outside"):
            create_campaign_derivation(
                output=self.first.workspace / "graph", signer=self.authority, **self._common()
            )

    def test_verification_does_not_change_historical_or_snapshot_files(self):
        self._all_products(self._round(self.first))
        self._create()
        paths = [
            path for case in self.cases for path in case.workspace.rglob("*") if path.is_file()
        ] + [self.output / "manifest.json"]
        before = {str(path): path.read_bytes() for path in paths}
        self.assertEqual(self._blast()["status"], "verified")
        self.assertEqual(before, {str(path): path.read_bytes() for path in paths})

    def test_failed_round_is_an_outcome_without_fictitious_checkpoint(self):
        failed = self._round(value=2.0, minimum=2)
        self.assertIsNone(failed._manifest()["core"]["checkpoint_sha256"])
        self._create()
        report = self._blast(failed)
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(report["counts_by_kind"].get("checkpoint", 0), 0)
        self.assertEqual(report["counts_by_kind"]["round_outcome"], 1)

    def test_cli_uses_explicit_manifest_pins_and_existing_entrypoint(self):
        from fl_forensics.cli import main

        spec = self.root / "sources.json"
        write_json_once(
            spec,
            {
                "rounds": [
                    {"manifest_sha256": pin, "workspace": str(path)}
                    for pin, path in self.rounds.items()
                ],
                "products": [],
            },
        )
        public, private = self.root / "graph.public.pem", self.root / "graph.private.pem"
        write_once(public, self.authority.public_pem())
        write_once(private, self.authority.private_pem())
        common = [
            "--workspace",
            str(self.output),
            "--sources",
            str(spec),
            "--coordinator-public-key",
            str(self.first.workspace / "public/round-coordinator.public.pem"),
            "--authority-public-key",
            str(public),
        ]
        with redirect_stdout(io.StringIO()) as stdout:
            code = main(["campaign-derive", *common, "--authority-private-key", str(private)])
        self.assertEqual(code, 0, stdout.getvalue())
        pin = json.loads(stdout.getvalue())["manifest_sha256"]
        sid = self.first._manifest()["core"]["dispositions"][0]["submission_id"]
        with redirect_stdout(io.StringIO()) as stdout:
            code = main(
                ["campaign-blast-radius", *common, "--expected-sha256", pin, "--submission-id", sid]
            )
        self.assertEqual(code, 0, stdout.getvalue())
        self.assertEqual(json.loads(stdout.getvalue())["status"], "verified")
        self.assertEqual(json.loads(stdout.getvalue())["submission_id"], sid)
        other = self.first._manifest()["core"]["dispositions"][1]["submission_id"]
        with redirect_stdout(io.StringIO()) as stdout:
            code = main(
                [
                    "campaign-blast-radius",
                    *common,
                    "--expected-sha256",
                    pin,
                    "--submission-id",
                    sid,
                    "--submission-id",
                    other,
                ]
            )
        self.assertEqual(code, 0, stdout.getvalue())
        self.assertEqual(
            json.loads(stdout.getvalue())["selected_submission_ids"], sorted([sid, other])
        )
