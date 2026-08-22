from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fl_forensics.attack_mapping import (
    AttackMappingError,
    _load_attack_config,
    create_attack_mapping_bundle,
    verify_attack_mapping_bundle,
)

MODEL_CLASSES = [
    "benign",
    "credential_access",
    "exfiltration",
    "initial_access",
    "multi_tactic",
    "reconnaissance",
]


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical_json_bytes(value))


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AttackMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

        self.prediction_workspace = self.root / "predictions"
        self.explanation_workspace = self.root / "explanations"
        self.attack_workspace = self.root / "attack"

        self.prediction_workspace.mkdir()
        self.explanation_workspace.mkdir()

        self.round_workspace = self.root / "round"
        self.trust_workspace = self.root / "trust"
        self.partition_workspace = self.root / "partition"
        self.dataset_workspace = self.root / "dataset"

        for workspace in (
            self.round_workspace,
            self.trust_workspace,
            self.partition_workspace,
            self.dataset_workspace,
        ):
            workspace.mkdir()

        self.prediction_config = self.root / "investigation.yaml"
        self.explanation_config = (
            self.root / "investigation-explanations.yaml"
        )

        self.prediction_config.write_text(
            "test: prediction\n",
            encoding="utf-8",
        )
        self.explanation_config.write_text(
            "test: explanation\n",
            encoding="utf-8",
        )

        self.attack_config = Path(
            "configs/investigation-attack.yaml"
        )

        self._write_upstream_bundles()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_upstream_bundles(
        self,
        *,
        multi_reference_label: str = "multi_tactic",
        multi_nearest_prototype: str = "reconnaissance",
        first_predicted_class: str = "multi_tactic",
    ) -> None:
        predictions = {
            "schema_version": "1.0",
            "artifact_type": "m7_predictions",
            "class_names": MODEL_CLASSES,
            "prediction_count": 2,
            "reference_labels_used_for_inference": False,
            "predictions": [
                {
                    "prediction_id": "m7-prediction-001",
                    "window_id": "window-001",
                    "predicted_class": first_predicted_class,
                    "inference_input_sha256": "1" * 64,
                    "reference_label": multi_reference_label,
                    "reference_label_role": (
                        "evaluation-only-not-an-inference-input"
                    ),
                },
                {
                    "prediction_id": "m7-prediction-002",
                    "window_id": "window-002",
                    "predicted_class": "reconnaissance",
                    "inference_input_sha256": "2" * 64,
                    "reference_label": "reconnaissance",
                    "reference_label_role": (
                        "evaluation-only-not-an-inference-input"
                    ),
                },
            ],
        }

        lineage = {
            "schema_version": "1.0",
            "artifact_type": "m7_prediction_lineage",
            "records": [
                {
                    "prediction_id": "m7-prediction-001",
                    "window_id": "window-001",
                },
                {
                    "prediction_id": "m7-prediction-002",
                    "window_id": "window-002",
                },
            ],
        }

        predictions_path = (
            self.prediction_workspace / "predictions.json"
        )
        lineage_path = self.prediction_workspace / "lineage.json"

        _write_json(predictions_path, predictions)
        _write_json(lineage_path, lineage)

        predictions_sha256 = _sha256_file(predictions_path)
        lineage_sha256 = _sha256_file(lineage_path)

        prediction_manifest = {
            "schema_version": "1.0",
            "artifact_type": "m7_prediction_bundle_manifest",
            "bundle_id": "m7-prediction-bundle-test",
            "core": {
                "code_version": "0.5.1",
                "implementation_sha256": "a" * 64,
                "investigation_config_sha256": "b" * 64,
                "inference_method": (
                    "classification-head-softmax-argmax"
                ),
                "inference_device": "cpu",
                "prediction_count": 2,
                "source_event_count": 2,
                "source_record_count": 2,
                "sources": {
                    "campaign_id": "campaign-test",
                    "round_number": 11,
                    "context_id": "context-test",
                    "checkpoint_id": "checkpoint-test",
                    "round_context_sha256": "c" * 64,
                    "checkpoint_manifest_sha256": "d" * 64,
                    "global_model_sha256": "e" * 64,
                    "partition_manifest_sha256": "f" * 64,
                    "server_evaluation_sha256": "0" * 64,
                    "m2_manifest_sha256": "1" * 64,
                    "m2_dataset_sha256": "2" * 64,
                    "m2_scaler_sha256": "3" * 64,
                    "m2_lineage_sha256": "4" * 64,
                },
                "selection": {
                    "split": "test",
                    "method": "lexicographic-first-window-ids",
                    "selection_provenance": (
                        "window-id-only-no-label-prediction-or-metric"
                    ),
                    "window_ids": [
                        "window-001",
                        "window-002",
                    ],
                    "row_count": 2,
                },
                "predictions_sha256": predictions_sha256,
                "lineage_sha256": lineage_sha256,
                "reportability_gate": {
                    "policy": (
                        "complete-digest-valid-lineage-required"
                    ),
                    "checkpoint_verified": True,
                    "partition_verified": True,
                    "m2_snapshot_verified": True,
                    "model_inference_completed": True,
                    "complete_window_count": 2,
                    "incomplete_window_count": 0,
                    "invariant_violation_count": 0,
                    "reportable": True,
                },
            },
            "canonical_core_sha256": "5" * 64,
            "integrity_assurance": (
                "content-addressed-unanchored"
            ),
        }

        prediction_manifest_path = (
            self.prediction_workspace / "manifest.json"
        )
        _write_json(
            prediction_manifest_path,
            prediction_manifest,
        )

        integrated_gradients = {
            "schema_version": "1.0",
            "artifact_type": "m7_integrated_gradients",
            "explanations": [
                {
                    "prediction_id": "m7-prediction-001",
                    "explanation_id": "m7-explanation-001",
                    "window_id": "window-001",
                    "target_class": first_predicted_class,
                    "inference_input_sha256": "1" * 64,
                },
                {
                    "prediction_id": "m7-prediction-002",
                    "explanation_id": "m7-explanation-002",
                    "window_id": "window-002",
                    "target_class": "reconnaissance",
                    "inference_input_sha256": "2" * 64,
                },
            ],
        }

        prototype_reference = {
            "schema_version": "1.0",
            "artifact_type": "m7_prototype_reference",
            "row_embeddings_preserved": False,
        }

        prototype_distances = {
            "schema_version": "1.0",
            "artifact_type": "m7_prototype_distances",
            "class_names": MODEL_CLASSES,
            "explanations": [
                {
                    "prediction_id": "m7-prediction-001",
                    "explanation_id": "m7-explanation-001",
                    "window_id": "window-001",
                    "predicted_class": first_predicted_class,
                    "inference_input_sha256": "1" * 64,
                    "nearest_prototype_class": (
                        multi_nearest_prototype
                    ),
                    "row_embedding_preserved": False,
                },
                {
                    "prediction_id": "m7-prediction-002",
                    "explanation_id": "m7-explanation-002",
                    "window_id": "window-002",
                    "predicted_class": "reconnaissance",
                    "inference_input_sha256": "2" * 64,
                    "nearest_prototype_class": "reconnaissance",
                    "row_embedding_preserved": False,
                },
            ],
        }

        ig_path = (
            self.explanation_workspace
            / "integrated-gradients.json"
        )
        prototype_reference_path = (
            self.explanation_workspace
            / "prototype-reference.json"
        )
        prototype_distances_path = (
            self.explanation_workspace
            / "prototype-distances.json"
        )

        _write_json(ig_path, integrated_gradients)
        _write_json(
            prototype_reference_path,
            prototype_reference,
        )
        _write_json(
            prototype_distances_path,
            prototype_distances,
        )

        explanation_manifest = {
            "schema_version": "1.0",
            "artifact_type": "m7_explanation_bundle_manifest",
            "explanation_bundle_id": (
                "m7-explanation-bundle-test"
            ),
            "core": {
                "code_version": "0.5.1",
                "implementation_sha256": {
                    "explanation_bundle": "6" * 64,
                    "prediction_bundle": "7" * 64,
                    "prototype_core": "8" * 64,
                },
                "explanation_config_sha256": "9" * 64,
                "source": {
                    "prediction_bundle_id": (
                        "m7-prediction-bundle-test"
                    ),
                    "prediction_manifest_sha256": (
                        _sha256_file(prediction_manifest_path)
                    ),
                    "predictions_sha256": predictions_sha256,
                    "lineage_sha256": lineage_sha256,
                    "campaign_id": "campaign-test",
                    "round_number": 11,
                    "global_model_sha256": "e" * 64,
                    "partition_manifest_sha256": "f" * 64,
                },
                "prediction_count": 2,
                "feature_count": 25,
                "class_count": 6,
                "integrated_gradients_sha256": (
                    _sha256_file(ig_path)
                ),
                "prototype_reference_sha256": (
                    _sha256_file(prototype_reference_path)
                ),
                "prototype_distances_sha256": (
                    _sha256_file(prototype_distances_path)
                ),
                "maximum_absolute_completeness_error_scaled_1e12": (
                    500000000
                ),
                "reportability_gate": {
                    "policy": (
                        "verified-prediction-and-complete-explanation-required"
                    ),
                    "prediction_bundle_verified": True,
                    "training_only_baseline": True,
                    "training_only_prototypes": True,
                    "integrated_gradients_complete": True,
                    "prototype_distances_complete": True,
                    "row_embeddings_preserved": False,
                    "complete_prediction_count": 2,
                    "incomplete_prediction_count": 0,
                    "invariant_violation_count": 0,
                    "reportable": True,
                },
            },
            "canonical_core_sha256": "a" * 64,
            "interpretation_boundary": (
                "model-derived-interpretation-not-primary-zeek-evidence"
            ),
            "integrity_assurance": (
                "content-addressed-unanchored"
            ),
        }

        _write_json(
            self.explanation_workspace / "manifest.json",
            explanation_manifest,
        )

    @staticmethod
    def _verified_source() -> dict[str, object]:
        return {
            "status": "verified",
            "reportable": True,
            "source_prediction_verified": True,
            "verification_recomputed_integrated_gradients": True,
            "verification_recomputed_prototype_distances": True,
            "verification_recomputed_training_prototypes": True,
        }

    def _create(
        self,
        *,
        output: Path | None = None,
    ) -> dict[str, object]:
        output = output or self.attack_workspace

        with patch(
            "fl_forensics.attack_mapping."
            "_verified_explanation_source",
            return_value=self._verified_source(),
        ):
            return create_attack_mapping_bundle(
                round_workspace=self.round_workspace,
                trust_workspace=self.trust_workspace,
                partition_workspace=self.partition_workspace,
                dataset_workspace=self.dataset_workspace,
                prediction_workspace=self.prediction_workspace,
                explanation_workspace=self.explanation_workspace,
                output=output,
                prediction_config_path=self.prediction_config,
                explanation_config_path=self.explanation_config,
                config_path=self.attack_config,
            )

    def _verify(self) -> dict[str, object]:
        with patch(
            "fl_forensics.attack_mapping."
            "_verified_explanation_source",
            return_value=self._verified_source(),
        ):
            return verify_attack_mapping_bundle(
                round_workspace=self.round_workspace,
                trust_workspace=self.trust_workspace,
                partition_workspace=self.partition_workspace,
                dataset_workspace=self.dataset_workspace,
                prediction_workspace=self.prediction_workspace,
                explanation_workspace=self.explanation_workspace,
                workspace=self.attack_workspace,
                prediction_config_path=self.prediction_config,
                explanation_config_path=self.explanation_config,
                config_path=self.attack_config,
            )

    def test_configuration_freezes_attack_v19_2_and_model_contract(
        self,
    ) -> None:
        config, digest = _load_attack_config(
            self.attack_config
        )

        self.assertEqual(config["version"], "19.2")
        self.assertEqual(
            config["framework"],
            "MITRE ATT&CK",
        )
        self.assertEqual(
            config["domain"],
            "enterprise",
        )
        self.assertEqual(
            config["model_taxonomy"]["class_names"],
            MODEL_CLASSES,
        )
        self.assertEqual(len(digest), 64)

        interpretation = config["interpretation"]

        self.assertFalse(
            interpretation["use_reference_labels"]
        )
        self.assertFalse(
            interpretation["use_dataset_attack_labels"]
        )
        self.assertFalse(
            interpretation[
                "use_integrated_gradients_for_rule_selection"
            ]
        )
        self.assertFalse(
            interpretation[
                "use_prototype_distances_for_rule_selection"
            ]
        )
        self.assertFalse(
            interpretation["allow_technique_claims"]
        )

    def test_multi_tactic_remains_unresolved_despite_reconnaissance_prototype(
        self,
    ) -> None:
        result = self._create()

        self.assertTrue(result["reportable"])
        self.assertEqual(result["mapping_count"], 2)
        self.assertEqual(
            result["candidate_tactic_mapping_count"],
            1,
        )
        self.assertEqual(
            result["unresolved_mapping_count"],
            1,
        )

        artifact = json.loads(
            (
                self.attack_workspace
                / "attack-mappings.json"
            ).read_text(encoding="utf-8")
        )

        by_prediction = {
            row["prediction_id"]: row
            for row in artifact["mappings"]
        }

        multi = by_prediction["m7-prediction-001"]

        self.assertEqual(
            multi["mapping_status"],
            "unresolved-multi-tactic",
        )
        self.assertEqual(
            multi["tactic_candidates"],
            [],
        )
        self.assertEqual(
            multi["technique_candidates"],
            [],
        )
        self.assertFalse(
            multi["explanation_context"][
                "used_for_rule_selection"
            ]
        )

        reconnaissance = by_prediction[
            "m7-prediction-002"
        ]

        self.assertEqual(
            reconnaissance["mapping_status"],
            "candidate-tactic",
        )
        self.assertEqual(
            reconnaissance["tactic_candidates"],
            [
                {
                    "tactic_id": "TA0043",
                    "tactic_name": "Reconnaissance",
                }
            ],
        )

    def test_reference_label_does_not_change_attack_mapping(
        self,
    ) -> None:
        first_output = self.root / "attack-first"
        second_output = self.root / "attack-second"

        self._create(output=first_output)

        first_mapping = (
            first_output / "attack-mappings.json"
        ).read_bytes()

        self._write_upstream_bundles(
            multi_reference_label="reconnaissance",
        )

        self._create(output=second_output)

        second_mapping = (
            second_output / "attack-mappings.json"
        ).read_bytes()

        self.assertEqual(
            first_mapping,
            second_mapping,
        )

    def test_unknown_model_class_fails_closed(self) -> None:
        self._write_upstream_bundles(
            first_predicted_class="unknown_class",
        )

        with patch(
            "fl_forensics.attack_mapping."
            "_verified_explanation_source",
            return_value=self._verified_source(),
        ), self.assertRaises(AttackMappingError):
            create_attack_mapping_bundle(
                round_workspace=self.round_workspace,
                trust_workspace=self.trust_workspace,
                partition_workspace=self.partition_workspace,
                dataset_workspace=self.dataset_workspace,
                prediction_workspace=self.prediction_workspace,
                explanation_workspace=self.explanation_workspace,
                output=self.attack_workspace,
                prediction_config_path=self.prediction_config,
                explanation_config_path=self.explanation_config,
                config_path=self.attack_config,
            )

        self.assertFalse(self.attack_workspace.exists())

    def test_failed_explanation_gate_prevents_publication(
        self,
    ) -> None:
        with patch(
            "fl_forensics.attack_mapping."
            "_verified_explanation_source",
            side_effect=AttackMappingError(
                "upstream explanation verification failed"
            ),
        ), self.assertRaises(AttackMappingError):
            create_attack_mapping_bundle(
                round_workspace=self.round_workspace,
                trust_workspace=self.trust_workspace,
                partition_workspace=self.partition_workspace,
                dataset_workspace=self.dataset_workspace,
                prediction_workspace=self.prediction_workspace,
                explanation_workspace=self.explanation_workspace,
                output=self.attack_workspace,
                prediction_config_path=self.prediction_config,
                explanation_config_path=self.explanation_config,
                config_path=self.attack_config,
            )

        self.assertFalse(self.attack_workspace.exists())

    def test_recomputation_is_deterministic_and_tampering_is_rejected(
        self,
    ) -> None:
        second_output = self.root / "attack-second"

        self._create()
        self._create(output=second_output)

        for name in (
            "attack-mappings.json",
            "manifest.json",
        ):
            self.assertEqual(
                (self.attack_workspace / name).read_bytes(),
                (second_output / name).read_bytes(),
            )

        verified = self._verify()

        self.assertEqual(
            verified["status"],
            "verified",
        )
        self.assertTrue(verified["reportable"])
        self.assertTrue(
            verified[
                "verification_recomputed_attack_mapping"
            ]
        )

        attack_path = (
            self.attack_workspace / "attack-mappings.json"
        )

        attack_path.write_bytes(
            attack_path.read_bytes() + b"\n"
        )

        failed = self._verify()

        self.assertEqual(
            failed["status"],
            "failed",
        )
        self.assertFalse(
            failed["reportable"],
        )
        self.assertTrue(
            any(
                "differs from recomputation" in error
                for error in failed["errors"]
            )
        )

    def test_unexpected_bundle_entry_is_rejected(self) -> None:
        self._create()

        (self.attack_workspace / "unexpected").mkdir()

        result = self._verify()

        self.assertEqual(
            result["status"],
            "failed",
        )
        self.assertFalse(
            result["reportable"],
        )
        self.assertTrue(
            any(
                "unexpected ATT&CK bundle files" in error
                for error in result["errors"]
            )
        )


if __name__ == "__main__":
    unittest.main()