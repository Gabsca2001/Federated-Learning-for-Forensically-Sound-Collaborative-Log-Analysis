from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fl_forensics.canonical import canonical_json_bytes, sha256_bytes, sha256_file
from fl_forensics.explanation_bundle import (
    ExplanationBundleError,
    _build_explanation_artifacts,
    _validate_explanation_config,
    _validated_explanation_inputs,
    create_explanation_bundle,
    verify_explanation_bundle,
)
from fl_forensics.federated_model import architecture_record, build_model, export_state
from fl_forensics.investigation_models import (
    ExplanationBundleManifest,
    PredictionBundleCore,
    PredictionBundleManifest,
    PredictionReportabilityGate,
    PredictionSelection,
    PredictionSourceReferences,
)
from fl_forensics.prediction_bundle import _inference_rows, _ml_dependencies
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.storage import write_once


class ExplanationBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.partition = self.root / "partition"
        self.output = self.root / "explanations"
        self.inputs = self._inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _model_export(self) -> dict[str, object]:
        _np, torch = _ml_dependencies()
        architecture = architecture_record(
            input_features=2,
            class_count=2,
            hidden_layers=[2, 2],
            embedding_size=2,
            dropout=0.0,
        )
        model = build_model(
            input_features=2,
            class_count=2,
            hidden_layers=[2, 2],
            embedding_size=2,
            dropout=0.0,
            torch=torch,
        )
        with torch.no_grad():
            for module in model.modules():
                if isinstance(module, torch.nn.Linear):
                    module.weight.copy_(torch.eye(2, dtype=torch.float32))
                    module.bias.zero_()
        return export_state(
            model,
            architecture=architecture,
            class_names=["benign", "reconnaissance"],
        )

    def _prediction_manifest(
        self, *, sources: PredictionSourceReferences, selection: PredictionSelection
    ) -> PredictionBundleManifest:
        core = PredictionBundleCore(
            code_version="test",
            implementation_sha256="a" * 64,
            investigation_config_sha256="b" * 64,
            prediction_count=1,
            source_event_count=1,
            source_record_count=1,
            sources=sources,
            selection=selection,
            predictions_sha256="c" * 64,
            lineage_sha256="d" * 64,
            reportability_gate=PredictionReportabilityGate(
                complete_window_count=1
            ),
        )
        return PredictionBundleManifest(
            bundle_id="m7-prediction-bundle-test",
            core=core,
            canonical_core_sha256=sha256_bytes(
                canonical_json_bytes(core.model_dump(mode="json"))
            ),
        )

    def _inputs(self) -> dict[str, object]:
        np, torch = _ml_dependencies()
        class_names = ["benign", "reconnaissance"]
        feature_names = ["feature-a", "feature-b"]
        clients = []
        for index in range(1, 4):
            client_id = f"client{index:02d}"
            rows = [
                {
                    "window_id": f"{client_id}-a1",
                    "capture_id": "train",
                    "label": "benign",
                    "features": [1.0, 0.0],
                },
                {
                    "window_id": f"{client_id}-a2",
                    "capture_id": "train",
                    "label": "benign",
                    "features": [2.0, 0.0],
                },
                {
                    "window_id": f"{client_id}-b1",
                    "capture_id": "train",
                    "label": "reconnaissance",
                    "features": [0.0, 1.0],
                },
                {
                    "window_id": f"{client_id}-b2",
                    "capture_id": "train",
                    "label": "reconnaissance",
                    "features": [0.0, 2.0],
                },
            ]
            path = self.partition / "clients" / client_id / "dataset.json"
            write_once(
                path,
                derived_json_bytes(
                    {
                        "feature_names": feature_names,
                        "class_names": class_names,
                        "rows": {"train": rows},
                    }
                ),
            )
            clients.append(
                {
                    "client_id": client_id,
                    "dataset_path": path.relative_to(self.partition).as_posix(),
                    "dataset_sha256": sha256_file(path),
                    "train_row_count": len(rows),
                }
            )
        sources = PredictionSourceReferences(
            campaign_id="campaign-test",
            round_number=11,
            context_id="context-test",
            checkpoint_id="checkpoint-test",
            round_context_sha256="0" * 64,
            checkpoint_manifest_sha256="1" * 64,
            global_model_sha256="2" * 64,
            partition_manifest_sha256="3" * 64,
            server_evaluation_sha256="4" * 64,
            m2_manifest_sha256="5" * 64,
            m2_dataset_sha256="6" * 64,
            m2_scaler_sha256="7" * 64,
            m2_lineage_sha256="8" * 64,
        )
        selection = PredictionSelection(
            split="test",
            method="explicit-window-ids",
            selection_provenance="investigator-supplied-basis-not-assessed",
            window_ids=["window-test"],
            row_count=1,
        )
        selected = [
            {
                "m3_row": {
                    "window_id": "window-test",
                    "capture_id": "capture-test",
                    "label": "benign",
                    "features": [2.0, 0.5],
                },
                "m2_row": {},
                "m3_evaluation_row_sha256": "9" * 64,
                "inference_input_sha256": "e" * 64,
                "m2_window_row_sha256": "f" * 64,
                "source_event_ids": ["event-test"],
            }
        ]
        result: dict[str, object] = {
            "config_digest": "a" * 64,
            "explanation_config_digest": "b" * 64,
            "investigation": {},
            "selection": selection,
            "selected": selected,
            "sources": sources,
            "partition_workspace": self.partition,
            "partition_manifest": {
                "feature_names": feature_names,
                "class_names": class_names,
                "clients": clients,
            },
            "model_export": self._model_export(),
            "np": np,
            "torch": torch,
            "explanation_config": {
                "integrated_gradients": {
                    "target": "predicted-class-logit",
                    "baseline": "training-feature-coordinate-median",
                    "integration_rule": "trapezoidal",
                    "initial_steps": 8,
                    "maximum_steps": 64,
                    "absolute_completeness_tolerance": 0.001,
                },
                "prototypes": {
                    "source_split": "train",
                    "embedding": "verified-m5-global-encoder",
                    "aggregation": "coordinate_median",
                    "minimum_local_support": 1,
                    "class_quorum": 3,
                    "batch_size": 16,
                    "distance": "euclidean",
                    "preserve_row_embeddings": False,
                },
                "interpretation": {
                    "require_verified_prediction_bundle": True,
                    "primary_evidence": False,
                },
            },
            "prediction_manifest_sha256": "0" * 64,
        }
        result["prediction_rows"] = _inference_rows(result)
        result["prediction_manifest"] = self._prediction_manifest(
            sources=sources, selection=selection
        )
        return result

    def test_configuration_freezes_training_only_explanation_contract(self) -> None:
        from fl_forensics.config import load_yaml

        config, _digest = load_yaml(
            Path(__file__).resolve().parents[1]
            / "configs"
            / "investigation-explanations.yaml"
        )
        explanations = _validate_explanation_config(config)
        self.assertEqual(
            explanations["integrated_gradients"]["baseline"],
            "training-feature-coordinate-median",
        )
        self.assertEqual(explanations["prototypes"]["source_split"], "train")
        self.assertFalse(explanations["prototypes"]["preserve_row_embeddings"])

    def test_explanations_are_complete_and_use_training_only_prototypes(self) -> None:
        artifacts = _build_explanation_artifacts(self.inputs)
        manifest = ExplanationBundleManifest.model_validate_json(
            artifacts["manifest.json"]
        )
        self.assertEqual(manifest.core.prediction_count, 1)
        self.assertLessEqual(
            manifest.core.maximum_absolute_completeness_error_scaled_1e12,
            1_000_000_000,
        )
        integrated = load_json_bytes(artifacts["integrated-gradients.json"])
        explanation = integrated["explanations"][0]
        self.assertEqual(explanation["target_class"], "benign")
        self.assertEqual(
            [item["feature_name"] for item in explanation["feature_attributions"]],
            ["feature-a", "feature-b"],
        )
        reference = load_json_bytes(artifacts["prototype-reference.json"])
        self.assertEqual(reference["source_split"], "train")
        self.assertEqual(reference["training_client_count"], 3)
        self.assertEqual(reference["training_row_count"], 12)
        self.assertFalse(reference["row_embeddings_preserved"])
        distances = load_json_bytes(artifacts["prototype-distances.json"])
        self.assertTrue(
            distances["explanations"][0]["prediction_matches_nearest_prototype"]
        )

    def test_recomputation_is_repeatable_and_tampering_is_rejected(self) -> None:
        with patch(
            "fl_forensics.explanation_bundle._validated_explanation_inputs",
            return_value=self.inputs,
        ):
            created = create_explanation_bundle(
                round_workspace=Path("round"),
                trust_workspace=Path("trust"),
                partition_workspace=Path("partition"),
                dataset_workspace=Path("dataset"),
                prediction_workspace=Path("predictions"),
                output=self.output,
                prediction_config_path=Path("prediction-config"),
                config_path=Path("config"),
            )
            self.assertEqual(created["status"], "explained_verified_source")
            verified = verify_explanation_bundle(
                round_workspace=Path("round"),
                trust_workspace=Path("trust"),
                partition_workspace=Path("partition"),
                dataset_workspace=Path("dataset"),
                prediction_workspace=Path("predictions"),
                workspace=self.output,
                prediction_config_path=Path("prediction-config"),
                config_path=Path("config"),
            )
            self.assertEqual(verified["status"], "verified")
            path = self.output / "integrated-gradients.json"
            path.chmod(0o640)
            path.write_bytes(path.read_bytes() + b"tampered\n")
            rejected = verify_explanation_bundle(
                round_workspace=Path("round"),
                trust_workspace=Path("trust"),
                partition_workspace=Path("partition"),
                dataset_workspace=Path("dataset"),
                prediction_workspace=Path("predictions"),
                workspace=self.output,
                prediction_config_path=Path("prediction-config"),
                config_path=Path("config"),
            )
        self.assertEqual(rejected["status"], "failed")
        self.assertFalse(rejected["reportable"])

    def test_failed_prediction_bundle_is_not_explainable(self) -> None:
        with patch(
            "fl_forensics.explanation_bundle.verify_prediction_bundle",
            return_value={"status": "failed", "errors": ["tampered lineage"]},
        ), self.assertRaisesRegex(
            ExplanationBundleError, "source Prediction Bundle verification failed"
        ):
            _validated_explanation_inputs(
                round_workspace=Path("round"),
                trust_workspace=Path("trust"),
                partition_workspace=Path("partition"),
                dataset_workspace=Path("dataset"),
                prediction_workspace=Path("predictions"),
                prediction_config_path=Path("prediction-config"),
                config_path=Path("config"),
            )


def load_json_bytes(content: bytes) -> dict[str, object]:
    import json

    return json.loads(content)


if __name__ == "__main__":
    unittest.main()
