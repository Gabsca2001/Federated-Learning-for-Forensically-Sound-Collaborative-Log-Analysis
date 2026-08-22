from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fl_forensics.investigation_report import (
    InvestigationReportError,
    _build_report_artifacts,
    create_investigation_report_bundle,
    verify_investigation_report_bundle,
)

HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64
HEX_F = "f" * 64
HEX_1 = "1" * 64
HEX_2 = "2" * 64
HEX_3 = "3" * 64
HEX_4 = "4" * 64
HEX_5 = "5" * 64
HEX_6 = "6" * 64
HEX_7 = "7" * 64
HEX_8 = "8" * 64
HEX_9 = "9" * 64


class InvestigationReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

        self.attack_manifest_path = (
            self.root / "attack-manifest.json"
        )
        self.attack_manifest_path.write_text(
            "{}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _inputs(self) -> dict:
        prediction_id = (
            "m7-prediction-000000000000000000000001"
        )
        explanation_id = (
            "m7-explanation-000000000000000000000001"
        )
        mapping_id = (
            "m7-attack-mapping-000000000000000000000001"
        )
        window_id = (
            "window-central-00000000000000000001"
        )
        event_id = (
            "event-central-00000000000000000001"
        )

        relative_path = (
            "2024-03-17 - 2024-03-24/"
            "part-test.snappy.parquet"
        )

        attack_source = SimpleNamespace(
            explanation_bundle_id=(
                "m7-explanation-bundle-test"
            ),
            explanation_manifest_sha256=HEX_A,
            integrated_gradients_sha256=HEX_B,
            prototype_reference_sha256=HEX_C,
            prototype_distances_sha256=HEX_D,
            prediction_bundle_id=(
                "m7-prediction-bundle-test"
            ),
            prediction_manifest_sha256=HEX_E,
            predictions_sha256=HEX_F,
            lineage_sha256=HEX_1,
            campaign_id="campaign-test",
            round_number=11,
            global_model_sha256=HEX_2,
            partition_manifest_sha256=HEX_3,
        )

        attack_manifest = SimpleNamespace(
            attack_mapping_bundle_id=(
                "m7-attack-mapping-bundle-test"
            ),
            core=SimpleNamespace(
                code_version="test",
                source=attack_source,
                attack_mappings_sha256=HEX_4,
            ),
        )

        prediction = {
            "prediction_id": prediction_id,
            "window_id": window_id,
            "capture_id": "2024-03-23",
            "split": "test",
            "predicted_class": "multi_tactic",
            "confidence": 0.75,
            "probability_margin": 0.25,
            "inference_input_sha256": HEX_5,
            # Evaluation-only field. M7.4 must ignore it.
            "reference_label": "multi_tactic",
        }

        window = {
            "prediction_id": prediction_id,
            "window_id": window_id,
            "capture_id": "2024-03-23",
            "split": "test",
            "lineage_complete": True,
            "inference_input_sha256": HEX_5,
            "m2_window_lineage_record_sha256": HEX_6,
            "m2_window_row_sha256": HEX_7,
            "m3_evaluation_row_sha256": HEX_8,
            "source_event_count": 1,
            "source_event_ids": [event_id],
        }

        integrated_gradients = {
            "prediction_id": prediction_id,
            "explanation_id": explanation_id,
            "window_id": window_id,
            "target_class": "multi_tactic",
            "inference_input_sha256": HEX_5,
            "absolute_completeness_error": 0.0001,
            "feature_attributions": [
                {
                    "absolute_rank": 1,
                    "feature_name": (
                        "unique_destination_port_count"
                    ),
                    "attribution": 0.5,
                    "direction_for_target_logit": (
                        "supports-target"
                    ),
                },
                {
                    "absolute_rank": 2,
                    "feature_name": (
                        "service_other_fraction"
                    ),
                    "attribution": -0.25,
                    "direction_for_target_logit": (
                        "opposes-target"
                    ),
                },
            ],
        }

        prototype_distance = {
            "prediction_id": prediction_id,
            "explanation_id": explanation_id,
            "window_id": window_id,
            "predicted_class": "multi_tactic",
            "inference_input_sha256": HEX_5,
            # Deliberately conflicts with model prediction.
            "nearest_prototype_class": "reconnaissance",
            "nearest_prototype_distance": 0.1,
            "second_nearest_prototype_class": (
                "multi_tactic"
            ),
            "second_nearest_prototype_distance": 0.2,
            "nearest_prototype_margin": 0.1,
            "predicted_class_prototype_distance": 0.2,
            "predicted_class_prototype_rank": 2,
            "prediction_matches_nearest_prototype": False,
        }

        attack_mapping = {
            "mapping_id": mapping_id,
            "prediction_id": prediction_id,
            "explanation_id": explanation_id,
            "window_id": window_id,
            "predicted_class": "multi_tactic",
            "attack_framework": "MITRE ATT&CK",
            "attack_domain": "enterprise",
            "attack_version": "19.2",
            "mapping_status": "unresolved-multi-tactic",
            "rule_id": "multi-tactic-unresolved-v1",
            "tactic_candidates": [],
            "technique_candidates": [],
            "primary_evidence": False,
            "explanation_context": {
                "used_for_rule_selection": False,
            },
        }

        source_record = {
            "relative_path": relative_path,
            "row_number": 123,
            "source_record_sha256": HEX_9,
            "source_file_sha256": HEX_A,
            "source_file_size_bytes": 123456,
            # Dataset ground truth. These must never be
            # copied into the investigation report.
            "label_binary": "true",
            "label_tactic": "reconnaissance",
            "label_technique": "T1595",
        }

        event = {
            "event_id": event_id,
            "lineage_record_sha256": HEX_B,
            "source_identity_sha256": HEX_C,
            "source_records": [source_record],
        }

        source_file = {
            "relative_path": relative_path,
            "sha256": HEX_A,
            "size_bytes": 123456,
            "source_url": (
                "https://example.invalid/"
                "part-test.snappy.parquet"
            ),
        }

        config = {
            "case_order": "prediction-id-lexicographic",
            "integrated_gradients_top_features": 5,
            "primary_evidence": {
                "include_source_file_url": False,
                "source_record_fields": [
                    "relative_path",
                    "row_number",
                    "source_record_sha256",
                    "source_file_sha256",
                    "source_file_size_bytes",
                ],
            },
            "label_policy": {
                "include_reference_labels": False,
                "include_dataset_attack_labels": False,
                "use_dataset_labels_for_reporting": False,
            },
            "interpretation": {
                "primary_evidence_role": (
                    "source-record-digest-reference"
                ),
                "model_measurement_role": (
                    "model-derived-measurement"
                ),
                "derived_interpretation_role": (
                    "model-derived-interpretation"
                ),
                "allow_report_to_resolve_multi_tactic": False,
            },
        }

        return {
            "config": config,
            "config_sha256": HEX_D,
            "prediction_manifest": None,
            "prediction_manifest_path": (
                self.root / "prediction-manifest.json"
            ),
            "predictions_by_id": {
                prediction_id: prediction,
            },
            "predictions_path": (
                self.root / "predictions.json"
            ),
            "lineage": {},
            "lineage_path": self.root / "lineage.json",
            "windows_by_prediction": {
                prediction_id: window,
            },
            "events_by_id": {
                event_id: event,
            },
            "source_files_by_path": {
                relative_path: source_file,
            },
            "explanation_manifest": None,
            "explanation_manifest_path": (
                self.root / "explanation-manifest.json"
            ),
            "integrated_gradients_path": (
                self.root / "integrated-gradients.json"
            ),
            "prototype_reference_path": (
                self.root / "prototype-reference.json"
            ),
            "prototype_distances_path": (
                self.root / "prototype-distances.json"
            ),
            "ig_by_prediction": {
                prediction_id: integrated_gradients,
            },
            "distances_by_prediction": {
                prediction_id: prototype_distance,
            },
            "attack_manifest": attack_manifest,
            "attack_manifest_path": (
                self.attack_manifest_path
            ),
            "attack_mappings_path": (
                self.root / "attack-mappings.json"
            ),
            "mappings_by_prediction": {
                prediction_id: attack_mapping,
            },
            "source_event_count": 1,
            "source_record_count": 1,
        }

    def _write_bundle(
        self,
        workspace: Path,
        inputs: dict,
    ) -> None:
        workspace.mkdir()

        artifacts = _build_report_artifacts(inputs)

        for name, content in artifacts.items():
            (workspace / name).write_bytes(content)

    def _verify(
        self,
        workspace: Path,
        inputs: dict,
    ) -> dict:
        with (
            patch(
                "fl_forensics.investigation_report."
                "_verified_attack_source",
                return_value={
                    "status": "verified",
                    "reportable": True,
                },
            ),
            patch(
                "fl_forensics.investigation_report."
                "_prepare_report_inputs",
                return_value=inputs,
            ),
        ):
            return verify_investigation_report_bundle(
                round_workspace=self.root / "round",
                trust_workspace=self.root / "trust",
                partition_workspace=self.root / "partition",
                dataset_workspace=self.root / "dataset",
                prediction_workspace=(
                    self.root / "prediction"
                ),
                explanation_workspace=(
                    self.root / "explanation"
                ),
                attack_workspace=self.root / "attack",
                workspace=workspace,
                prediction_config_path=(
                    self.root / "prediction.yaml"
                ),
                explanation_config_path=(
                    self.root / "explanation.yaml"
                ),
                attack_config_path=(
                    self.root / "attack.yaml"
                ),
                config_path=self.root / "report.yaml",
            )

    def test_report_is_byte_deterministic_and_label_independent(
        self,
    ) -> None:
        first_inputs = self._inputs()
        first = _build_report_artifacts(first_inputs)

        second_inputs = copy.deepcopy(first_inputs)

        prediction = next(
            iter(second_inputs["predictions_by_id"].values())
        )
        prediction["reference_label"] = "benign"

        event = next(
            iter(second_inputs["events_by_id"].values())
        )
        source_record = event["source_records"][0]

        source_record["label_binary"] = "false"
        source_record["label_tactic"] = "exfiltration"
        source_record["label_technique"] = "T1041"

        second = _build_report_artifacts(second_inputs)

        self.assertEqual(first, second)

        report_text = first[
            "investigation-report.json"
        ].decode()

        markdown_text = first["report.md"].decode()

        for forbidden in (
            "reference_label",
            "label_binary",
            "label_tactic",
            "label_technique",
        ):
            self.assertNotIn(
                f'"{forbidden}"',
                report_text,
            )
            self.assertNotIn(
                forbidden,
                markdown_text,
            )

        report = json.loads(
            first["investigation-report.json"]
        )

        self.assertFalse(
            report["reference_labels_included"]
        )
        self.assertFalse(
            report["dataset_attack_labels_included"]
        )
        self.assertFalse(
            report["dataset_labels_used_for_reporting"]
        )

    def test_multi_tactic_stays_unresolved_despite_reconnaissance_prototype(
        self,
    ) -> None:
        artifacts = _build_report_artifacts(
            self._inputs()
        )
        report = json.loads(
            artifacts["investigation-report.json"]
        )

        case = report["cases"][0]

        self.assertEqual(
            case["model_measurement"]["predicted_class"],
            "multi_tactic",
        )
        self.assertEqual(
            case["explanation"]["prototype_geometry"][
                "nearest_prototype_class"
            ],
            "reconnaissance",
        )
        self.assertFalse(
            case["explanation"]["prototype_geometry"][
                "prediction_matches_nearest_prototype"
            ]
        )
        self.assertEqual(
            case["attack_interpretation"][
                "mapping_status"
            ],
            "unresolved-multi-tactic",
        )
        self.assertEqual(
            case["attack_interpretation"][
                "tactic_candidates"
            ],
            [],
        )
        self.assertEqual(
            case["attack_interpretation"][
                "technique_candidates"
            ],
            [],
        )

    def test_failed_attack_verification_prevents_publication(
        self,
    ) -> None:
        output = self.root / "report-output"

        with patch(
            "fl_forensics.investigation_report."
            "_verified_attack_source",
            side_effect=InvestigationReportError(
                "ATT&CK Mapping Bundle did not pass "
                "verification"
            ),
        ), self.assertRaisesRegex(
            InvestigationReportError,
            "did not pass verification",
        ):
            create_investigation_report_bundle(
                round_workspace=(
                    self.root / "round"
                ),
                trust_workspace=(
                    self.root / "trust"
                ),
                partition_workspace=(
                    self.root / "partition"
                ),
                dataset_workspace=(
                    self.root / "dataset"
                ),
                prediction_workspace=(
                    self.root / "prediction"
                ),
                explanation_workspace=(
                    self.root / "explanation"
                ),
                attack_workspace=(
                    self.root / "attack"
                ),
                output=output,
                prediction_config_path=(
                    self.root / "prediction.yaml"
                ),
                explanation_config_path=(
                    self.root / "explanation.yaml"
                ),
                attack_config_path=(
                    self.root / "attack.yaml"
                ),
                config_path=(
                    self.root / "report.yaml"
                ),
            )

        self.assertFalse(output.exists())

    def test_verifier_accepts_clean_bundle(
        self,
    ) -> None:
        inputs = self._inputs()
        workspace = self.root / "clean-bundle"

        self._write_bundle(workspace, inputs)

        result = self._verify(
            workspace,
            inputs,
        )

        self.assertEqual(
            result["status"],
            "verified",
        )
        self.assertTrue(result["reportable"])
        self.assertTrue(
            result["source_attack_verified"]
        )
        self.assertTrue(
            result["verification_recomputed_report"]
        )
        self.assertEqual(result["error_count"], 0)
        self.assertEqual(result["case_count"], 1)
        self.assertEqual(
            result["unresolved_attack_case_count"],
            1,
        )

    def test_verifier_rejects_report_json_tampering(
        self,
    ) -> None:
        inputs = self._inputs()
        workspace = self.root / "json-tampering"

        self._write_bundle(workspace, inputs)

        report_path = (
            workspace / "investigation-report.json"
        )
        report = json.loads(report_path.read_text())
        report["cases"][0]["model_measurement"][
            "confidence"
        ] = 0.99

        report_path.write_text(
            json.dumps(
                report,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )

        result = self._verify(
            workspace,
            inputs,
        )

        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["reportable"])
        self.assertTrue(
            any(
                "investigation-report.json"
                in error
                for error in result["errors"]
            )
        )

    def test_verifier_rejects_markdown_tampering(
        self,
    ) -> None:
        inputs = self._inputs()
        workspace = self.root / "markdown-tampering"

        self._write_bundle(workspace, inputs)

        report_path = workspace / "report.md"
        report_path.write_text(
            report_path.read_text()
            + "\nTAMPERED\n"
        )

        result = self._verify(
            workspace,
            inputs,
        )

        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["reportable"])
        self.assertTrue(
            any(
                "report.md" in error
                for error in result["errors"]
            )
        )

    def test_verifier_rejects_unexpected_bundle_entry(
        self,
    ) -> None:
        inputs = self._inputs()
        workspace = self.root / "unexpected-entry"

        self._write_bundle(workspace, inputs)

        # Directory rather than a file on purpose:
        # verifier must reject either kind of unexpected entry.
        (workspace / "extra").mkdir()

        result = self._verify(
            workspace,
            inputs,
        )

        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["reportable"])
        self.assertTrue(
            any(
                "unexpected investigation report files"
                in error
                for error in result["errors"]
            )
        )


if __name__ == "__main__":
    unittest.main()
