from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fl_forensics.federated_model import architecture_record, build_model, export_state
from fl_forensics.investigation_models import (
    PredictionSelection,
    PredictionSourceReferences,
)
from fl_forensics.prediction_bundle import (
    PredictionBundleError,
    _build_artifacts,
    _ml_dependencies,
    _selected_rows,
    _validate_config,
    create_prediction_bundle,
    verify_prediction_bundle,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.storage import load_json, write_once


class PredictionBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "bundle"
        self.lineage_path = self.root / "lineage.jsonl"
        self.event_identity = "1" * 64
        self.event_id = f"event-central-{self.event_identity[:20]}"
        self.source_relative = "week/source.parquet"
        event_line = derived_json_bytes(
            {
                "record_type": "event",
                "event_id": self.event_id,
                "source_identity_sha256": self.event_identity,
                "source_records": [
                    {
                        "relative_path": self.source_relative,
                        "row_number": 7,
                        "source_record_sha256": "2" * 64,
                        "label_binary": "true",
                        "label_tactic": "reconnaissance",
                        "label_technique": "T1595",
                    }
                ],
            }
        )
        window_line = derived_json_bytes(
            {
                "record_type": "window",
                "window_id": "window-central-test",
                "feature_schema": "zeek-window-v1",
                "source_event_ids": [self.event_id],
            }
        )
        write_once(self.lineage_path, event_line + window_line)
        self.inputs = self._inputs(reference_label="benign")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _model_export(self) -> dict[str, object]:
        np, torch = _ml_dependencies()
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
            for parameter in model.parameters():
                parameter.zero_()
            model.classification_head.bias.copy_(
                torch.tensor([0.0, 2.0], dtype=torch.float32)
            )
        export = export_state(
            model,
            architecture=architecture,
            class_names=["benign", "reconnaissance"],
        )
        self.assertEqual(export["parameters"][0]["dtype"], str(np.dtype("float32")))
        return export

    def test_configuration_enables_every_reportability_gate(self) -> None:
        from fl_forensics.config import load_yaml

        root = Path(__file__).resolve().parents[1]
        config, _digest = load_yaml(root / "configs" / "investigation.yaml")
        investigation = _validate_config(config)
        self.assertEqual(investigation["maximum_windows_per_bundle"], 16)
        self.assertEqual(investigation["inference"]["device"], "cpu")

    def _inputs(self, *, reference_label: str) -> dict[str, object]:
        np, torch = _ml_dependencies()
        window_id = "window-central-test"
        m3_row = {
            "window_id": window_id,
            "capture_id": "capture-1",
            "label": reference_label,
            "features": [0.5, -0.25],
        }
        m2_row = {
            "window_id": window_id,
            "capture_id": "capture-1",
            "split": "test",
            "label": reference_label,
            "features": [0.5, -0.25],
            "source_event_ids": [self.event_id],
        }
        from fl_forensics.canonical import sha256_bytes

        evaluation_digest = sha256_bytes(derived_json_bytes(m3_row))
        inference_digest = sha256_bytes(
            derived_json_bytes(
                {"window_id": window_id, "features": m3_row["features"]}
            )
        )
        sources = PredictionSourceReferences(
            campaign_id="campaign-test",
            round_number=11,
            context_id="context-test",
            checkpoint_id="checkpoint-test",
            round_context_sha256="a" * 64,
            checkpoint_manifest_sha256="b" * 64,
            global_model_sha256="c" * 64,
            partition_manifest_sha256="d" * 64,
            server_evaluation_sha256="e" * 64,
            m2_manifest_sha256="f" * 64,
            m2_dataset_sha256="0" * 64,
            m2_scaler_sha256="1" * 64,
            m2_lineage_sha256="2" * 64,
        )
        return {
            "config_digest": "3" * 64,
            "selection": PredictionSelection(
                split="test",
                method="explicit-window-ids",
                selection_provenance="investigator-supplied-basis-not-assessed",
                window_ids=[window_id],
                row_count=1,
            ),
            "selected": [
                {
                    "m3_row": m3_row,
                    "m2_row": m2_row,
                    "m3_evaluation_row_sha256": evaluation_digest,
                    "inference_input_sha256": inference_digest,
                    "m2_window_row_sha256": "4" * 64,
                    "source_event_ids": [self.event_id],
                }
            ],
            "sources": sources,
            "source_file_index": {
                self.source_relative: {
                    "relative_path": self.source_relative,
                    "sha256": "5" * 64,
                    "size_bytes": 1234,
                    "source_url": "https://example.invalid/source.parquet",
                }
            },
            "lineage_path": self.lineage_path,
            "model_export": self._model_export(),
            "np": np,
            "torch": torch,
        }

    def _create(self) -> dict[str, object]:
        with patch(
            "fl_forensics.prediction_bundle._validated_inputs",
            return_value=self.inputs,
        ):
            return create_prediction_bundle(
                round_workspace=Path("round"),
                trust_workspace=Path("trust"),
                partition_workspace=Path("partition"),
                dataset_workspace=Path("dataset"),
                output=self.output,
                config_path=Path("config"),
                split="test",
                window_ids=["window-central-test"],
            )

    def _verify(self) -> dict[str, object]:
        with patch(
            "fl_forensics.prediction_bundle._validated_inputs",
            return_value=self.inputs,
        ):
            return verify_prediction_bundle(
                round_workspace=Path("round"),
                trust_workspace=Path("trust"),
                partition_workspace=Path("partition"),
                dataset_workspace=Path("dataset"),
                workspace=self.output,
                config_path=Path("config"),
            )

    def test_bundle_is_reportable_only_with_complete_digest_lineage(self) -> None:
        result = self._create()
        self.assertEqual(result["status"], "reportable")
        self.assertTrue(result["lineage_complete"])
        predictions = load_json(self.output / "predictions.json")
        prediction = predictions["predictions"][0]
        self.assertEqual(prediction["predicted_class"], "reconnaissance")
        self.assertFalse(predictions["reference_labels_used_for_inference"])
        lineage = load_json(self.output / "lineage.json")
        self.assertEqual(lineage["complete_window_count"], 1)
        self.assertEqual(lineage["events"][0]["event_id"], self.event_id)
        self.assertEqual(
            lineage["events"][0]["source_records"][0]["source_file_sha256"],
            "5" * 64,
        )
        verification = self._verify()
        self.assertEqual(verification["status"], "verified")
        self.assertTrue(verification["verification_recomputed_model_inference"])
        self.assertTrue(verification["verification_recomputed_lineage"])

    def test_reference_label_is_not_an_inference_input(self) -> None:
        benign = load_json_bytes(_build_artifacts(self.inputs)["predictions.json"])
        changed = self._inputs(reference_label="reconnaissance")
        attack = load_json_bytes(_build_artifacts(changed)["predictions.json"])
        benign_row = benign["predictions"][0]
        attack_row = attack["predictions"][0]
        for key in (
            "prediction_id",
            "predicted_class",
            "confidence",
            "probability_margin",
            "class_probabilities",
            "logits",
            "inference_input_sha256",
        ):
            self.assertEqual(benign_row[key], attack_row[key])
        self.assertNotEqual(
            benign_row["evaluation_row_sha256"],
            attack_row["evaluation_row_sha256"],
        )

    def test_missing_lineage_and_tampering_fail_closed(self) -> None:
        missing = dict(self.inputs)
        missing["selected"] = copy.deepcopy(self.inputs["selected"])
        missing["selected"][0]["source_event_ids"] = ["event-central-missing"]
        with self.assertRaises(PredictionBundleError):
            _build_artifacts(missing)

        self._create()
        prediction_path = self.output / "predictions.json"
        prediction_path.chmod(0o640)
        prediction_path.write_bytes(prediction_path.read_bytes() + b"tampered\n")
        verification = self._verify()
        self.assertEqual(verification["status"], "failed")
        self.assertFalse(verification["reportable"])
        self.assertTrue(
            any("predictions.json" in error for error in verification["errors"])
        )

    def test_selection_is_label_independent_and_bounded(self) -> None:
        server = {
            "rows": {
                "test": [
                    {"window_id": "window-b", "label": "benign"},
                    {"window_id": "window-a", "label": "reconnaissance"},
                ]
            }
        }
        rows, selection = _selected_rows(
            server=server,
            split="test",
            window_ids=None,
            first=1,
            maximum=2,
        )
        self.assertEqual([row["window_id"] for row in rows], ["window-a"])
        self.assertEqual(
            selection.selection_provenance,
            "window-id-only-no-label-prediction-or-metric",
        )
        with self.assertRaises(PredictionBundleError):
            _selected_rows(
                server=server,
                split="test",
                window_ids=None,
                first=3,
                maximum=2,
            )


def load_json_bytes(content: bytes) -> dict[str, object]:
    import json

    return json.loads(content)


if __name__ == "__main__":
    unittest.main()
