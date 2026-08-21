from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import numpy as np

from fl_forensics.byzantine_experiment import (
    _compute_comparison,
    run_byzantine_comparison,
    verify_byzantine_comparison,
    verify_frozen_update_set,
)
from fl_forensics.canonical import sha256_file
from fl_forensics.config import load_yaml
from fl_forensics.federated_model import (
    FederatedDependencyError,
    arrays_from_export,
    dependencies,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.storage import load_json, write_once

ROOT = Path(__file__).resolve().parents[1]


class ByzantineExperimentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.frozen = root / "frozen"
        self.partition = root / "partition"
        self.output = root / "comparison"
        architecture = {
            "input_features": 1,
            "encoder_hidden_layers": [2, 2],
            "embedding_size": 2,
            "classification_head_outputs": 2,
            "activation": "relu",
            "dropout": 0.0,
            "backend": "PyTorch",
        }
        shapes = [
            ("encoder.0.weight", [2, 1]),
            ("encoder.0.bias", [2]),
            ("encoder.2.weight", [2, 2]),
            ("encoder.2.bias", [2]),
            ("encoder.4.weight", [2, 2]),
            ("encoder.4.bias", [2]),
            ("classification_head.weight", [2, 2]),
            ("classification_head.bias", [2]),
        ]
        self.base = {
            "schema_version": "1.0",
            "artifact_type": "pytorch_model_state",
            "architecture": architecture,
            "class_names": ["benign", "attack"],
            "parameters": [
                {
                    "name": name,
                    "shape": shape,
                    "dtype": "float32",
                    "values": np.zeros(shape, dtype=np.float32).tolist(),
                }
                for name, shape in shapes
            ],
        }
        write_once(self.frozen / "base-model.json", derived_json_bytes(self.base))
        base_arrays = arrays_from_export(self.base, np=np)
        records = []
        for index in range(15):
            client_id = f"client{index + 1:02d}"
            updated_arrays = [
                array + np.asarray((50.0 if index == 0 else index / 1000), dtype=array.dtype)
                for array in base_arrays
            ]
            update = copy.deepcopy(self.base)
            for parameter, array in zip(
                update["parameters"], updated_arrays, strict=True
            ):
                parameter["values"] = array.tolist()
            relative = Path("updates") / client_id / "model-update.json"
            write_once(self.frozen / relative, derived_json_bytes(update))
            records.append(
                {
                    "client_id": client_id,
                    "attacker": index == 0,
                    "derivation": {"attack": "model_replacement" if index == 0 else "clean"},
                    "source_bundle_sha256": str(index + 1).zfill(64),
                    "source_update_sha256": str(index + 101).zfill(64),
                    "frozen_update_path": relative.as_posix(),
                    "frozen_update_sha256": sha256_file(self.frozen / relative),
                    "num_examples": 10,
                }
            )
        _config, config_digest = load_yaml(ROOT / "configs" / "byzantine.yaml")
        server = {
            "schema_version": "1.0",
            "artifact_type": "m3_server_feature_evaluation_snapshot",
            "feature_names": ["x"],
            "class_names": ["benign", "attack"],
            "rows": {
                "validation": [
                    {"features": [0.0], "label": "benign"},
                    {"features": [1.0], "label": "attack"},
                ],
                "test": [
                    {"features": [0.2], "label": "benign"},
                    {"features": [0.8], "label": "attack"},
                ],
                "temporal_holdout": [{"features": [0.1], "label": "benign"}],
            },
        }
        server_path = self.partition / "server" / "evaluation.json"
        write_once(server_path, derived_json_bytes(server))
        partition_manifest = {
            "server_evaluation_path": "server/evaluation.json",
            "server_evaluation_sha256": sha256_file(server_path),
        }
        write_once(
            self.partition / "manifest.json", derived_json_bytes(partition_manifest)
        )
        manifest = {
            "schema_version": "1.0",
            "artifact_type": "m6_frozen_byzantine_update_set",
            "code_version": "test",
            "attack": "model_replacement",
            "f": 1,
            "seed": 341593,
            "attacker_ids": ["client01"],
            "source_semantics": "test",
            "source_round_context_sha256": "1" * 64,
            "source_round_checkpoint_sha256": "2" * 64,
            "base_model_sha256": sha256_file(self.frozen / "base-model.json"),
            "partition_manifest_sha256": sha256_file(
                self.partition / "manifest.json"
            ),
            "byzantine_config_sha256": config_digest,
            "implementation_sha256": "3" * 64,
            "clip_threshold": {
                "method": "test-clean-reference",
                "median_l2": 0.1,
                "mad_l2": 0.01,
                "max_norm": 0.2,
            },
            "clients": records,
        }
        write_once(self.frozen / "manifest.json", derived_json_bytes(manifest))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_frozen_tampering_is_detected(self) -> None:
        verification = verify_frozen_update_set(workspace=self.frozen)
        self.assertEqual(verification["status"], "verified")
        path = self.frozen / "updates" / "client01" / "model-update.json"
        path.chmod(0o644)
        path.write_text("{}", encoding="utf-8")
        verification = verify_frozen_update_set(workspace=self.frozen)
        self.assertEqual(verification["status"], "failed")
        self.assertIn("frozen update digest mismatch: client01", verification["errors"])

    def test_comparison_is_recomputed_from_the_same_frozen_bytes(self) -> None:
        try:
            dependencies()
        except FederatedDependencyError as exc:
            self.skipTest(str(exc))
        result = run_byzantine_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            output=self.output,
            config_path=ROOT / "configs" / "byzantine.yaml",
        )
        self.assertEqual(result["status"], "compared")
        self.assertEqual(result["profile_count"], 10)
        comparison = load_json(self.output / "comparison.json")
        self.assertEqual(comparison["schema_version"], "1.1")
        self.assertIn("validation_impact_reference", comparison)
        for indicator in comparison["indicators"]:
            self.assertIn("validation_macro_f1", indicator)
            self.assertIn("validation_impact", indicator)
        legacy, _models = _compute_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            config_path=ROOT / "configs" / "byzantine.yaml",
            include_validation_impact=False,
        )
        self.assertEqual(legacy["schema_version"], "1.0")
        self.assertNotIn("validation_impact_reference", legacy)
        for indicator in legacy["indicators"]:
            self.assertNotIn("validation_macro_f1", indicator)
            self.assertNotIn("validation_impact", indicator)
        verification = verify_byzantine_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            workspace=self.output,
            config_path=ROOT / "configs" / "byzantine.yaml",
        )
        self.assertEqual(verification["status"], "verified")

    def test_backdoor_comparison_records_triggered_asr_and_lineage(self) -> None:
        try:
            dependencies()
        except FederatedDependencyError as exc:
            self.skipTest(str(exc))
        manifest_path = self.frozen / "manifest.json"
        manifest = load_json(manifest_path)
        manifest["attack"] = "backdoor"
        manifest["clients"][0]["derivation"] = {
            "attack": "backdoor",
            "poisoned_row_count": 1,
            "selected_window_ids_sha256": "4" * 64,
            "target_label": "benign",
            "feature_indices": [0],
            "trigger_value": 12.0,
            "fraction": 0.1,
        }
        manifest_path.chmod(0o644)
        manifest_path.write_bytes(derived_json_bytes(manifest))

        result = run_byzantine_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            output=self.output,
            config_path=ROOT / "configs" / "byzantine.yaml",
        )
        self.assertEqual(result["status"], "compared")
        comparison = load_json(self.output / "comparison.json")
        self.assertEqual(comparison["schema_version"], "1.3")
        contract = comparison["backdoor_evaluation"]
        self.assertEqual(contract["target_label"], "benign")
        self.assertEqual(contract["feature_indices"], [0])
        self.assertEqual(contract["trigger_value"], 12.0)
        self.assertEqual(contract["triggered_row_count"], 1)
        self.assertEqual(contract["original_label_counts"], {"attack": 1})
        self.assertEqual(len(contract["eligible_source_rows_sha256"]), 64)
        self.assertEqual(len(contract["triggered_rows_sha256"]), 64)
        baseline = contract["base_model_attack_success_rate"]
        for indicator in comparison["indicators"]:
            client_asr = indicator["backdoor_attack_success_rate"]
            self.assertGreaterEqual(client_asr, 0.0)
            self.assertLessEqual(client_asr, 1.0)
            self.assertAlmostEqual(
                indicator["backdoor_attack_success_rate_lift"],
                client_asr - baseline,
            )
        aggregate_only, _models = _compute_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            config_path=ROOT / "configs" / "byzantine.yaml",
            include_backdoor_client_impact=False,
        )
        self.assertEqual(aggregate_only["schema_version"], "1.2")
        for indicator in aggregate_only["indicators"]:
            self.assertNotIn("backdoor_attack_success_rate", indicator)
            self.assertNotIn("backdoor_attack_success_rate_lift", indicator)
        for outcome in comparison["outcomes"]:
            attack_success_rate = outcome["backdoor_attack_success_rate"]
            self.assertGreaterEqual(attack_success_rate, 0.0)
            self.assertLessEqual(attack_success_rate, 1.0)
            self.assertAlmostEqual(
                outcome["backdoor_attack_success_rate_lift"],
                attack_success_rate - baseline,
            )
            self.assertIn("backdoor_targeted_evaluation", outcome)
        verification = verify_byzantine_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            workspace=self.output,
            config_path=ROOT / "configs" / "byzantine.yaml",
        )
        self.assertEqual(verification["status"], "verified")


if __name__ == "__main__":
    unittest.main()
