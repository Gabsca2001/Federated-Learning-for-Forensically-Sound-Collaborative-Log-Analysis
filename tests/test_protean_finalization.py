from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
import torch

from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.protean_finalization import (
    _check_metric_consistency,
    _gradient_x_input_explainability,
    finalize_protean_endpoints,
    verify_protean_finalization,
)


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(derived_json_bytes(value))


class _TinyModel(torch.nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.encoder = torch.nn.Identity()
        self.classification_head = torch.nn.Linear(2, 2, bias=False)
        with torch.no_grad():
            self.classification_head.weight.copy_(
                torch.tensor([[2.0, 0.0], [0.0, 3.0]])
            )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.classification_head(self.encoder(features))


class ProteanFinalizationTests(unittest.TestCase):
    def test_gradient_x_input_is_aggregate_deterministic_and_private(self) -> None:
        rows = [
            {"features": [2.0, 0.0], "label": "benign"},
            {"features": [1.0, 0.0], "label": "benign"},
            {"features": [0.0, 2.0], "label": "attack"},
            {"features": [0.0, 1.0], "label": "attack"},
        ]
        arguments = {
            "model": _TinyModel(),
            "rows": rows,
            "class_names": ["benign", "attack"],
            "feature_names": ["feature_a", "feature_b"],
            "batch_size": 2,
            "np": np,
            "torch": torch,
            "minimum_group_rows": 1,
        }
        first = _gradient_x_input_explainability(**arguments)
        arguments["model"] = _TinyModel()
        second = _gradient_x_input_explainability(**arguments)

        self.assertEqual(first, second)
        self.assertEqual(first["overall"]["row_count"], 4)
        self.assertEqual(
            first["by_predicted_class"]["benign"]["features"][0]["feature"],
            "feature_a",
        )
        self.assertEqual(
            first["by_predicted_class"]["attack"]["features"][0]["feature"],
            "feature_b",
        )
        forbidden = {"rows", "row_attributions", "row_embeddings", "window_id"}

        def keys(value: object) -> set[str]:
            if isinstance(value, dict):
                return set(value) | set().union(*(keys(item) for item in value.values()))
            if isinstance(value, list):
                return set().union(*(keys(item) for item in value))
            return set()

        self.assertFalse(forbidden.intersection(keys(first)))

    def test_finalizer_rejects_unverified_lock_before_partition_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "final"
            with (
                patch(
                    "fl_forensics.protean_finalization.verify_protean_selection_lock",
                    return_value={"status": "failed", "errors": ["tampered"]},
                ),
                patch(
                    "fl_forensics.protean_finalization.verify_partitions"
                ) as partition_verification,
                self.assertRaisesRegex(ValueError, "must verify before final"),
            ):
                finalize_protean_endpoints(
                    candidate_workspaces=[Path("candidate")],
                    fedavg_workspace=Path("fedavg"),
                    report_workspace=Path("report"),
                    selection_lock_workspace=Path("lock"),
                    partition_workspace=Path("partition"),
                    dataset_workspace=Path("dataset"),
                    output=output,
                    config_path=Path("config.yaml"),
                )
            partition_verification.assert_not_called()
            self.assertFalse(output.exists())

    def test_metric_consistency_detects_accuracy_tampering(self) -> None:
        metrics = {
            "row_count": 4,
            "accuracy": 0.5,
            "per_class": {
                "benign": {"support": 2},
                "attack": {"support": 2},
            },
            "confusion_matrix": {
                "labels": ["benign", "attack"],
                "values": [[2, 0], [0, 2]],
            },
        }
        errors = _check_metric_consistency(metrics)
        self.assertIn("accuracy does not match confusion matrix", errors)

    def test_final_verifier_detects_artifact_tampering_without_inference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock_workspace = root / "lock"
            partition_workspace = root / "partition"
            dataset_workspace = root / "dataset"
            final_workspace = root / "final"
            _write(
                lock_workspace / "selection_lock.json",
                {
                    "primary_endpoint": {
                        "round": 1,
                        "model_sha256": "primary-model",
                        "global_prototypes_sha256": "primary-prototypes",
                    },
                    "secondary_endpoint": {
                        "round": 2,
                        "model_sha256": "secondary-model",
                        "global_prototypes_sha256": "secondary-prototypes",
                    },
                },
            )
            _write(lock_workspace / "manifest.json", {"artifact_type": "lock"})
            _write(
                partition_workspace / "manifest.json",
                {
                    "partition": "non-iid",
                    "server_evaluation_path": "server/evaluation.json",
                    "split_counts": {"test": 1, "temporal_holdout": 1},
                },
            )
            _write(partition_workspace / "server/evaluation.json", {"rows": {}})
            _write(dataset_workspace / "manifest.json", {"dataset": "test"})
            selection_digest = sha256_file(lock_workspace / "selection_lock.json")
            evaluation = {
                "selection_lock_sha256": selection_digest,
                "test_data_accessed": True,
                "selection_changed_after_test_access": False,
                "endpoints": {},
            }
            _write(final_workspace / "evaluation.json", evaluation)
            _write(
                final_workspace / "explainability.json",
                {
                    "selection_lock_sha256": selection_digest,
                    "evaluation_sha256": sha256_file(
                        final_workspace / "evaluation.json"
                    ),
                },
            )
            _write(
                final_workspace / "test_access_receipt.json",
                {"selection_lock_sha256": selection_digest},
            )
            artifact_files = {
                path.relative_to(final_workspace).as_posix(): sha256_file(path)
                for path in sorted(final_workspace.iterdir())
            }
            _write(
                final_workspace / "manifest.json",
                {
                    "artifact_type": "protean_final_evaluation_manifest",
                    "selection_lock_sha256": selection_digest,
                    "selection_lock_manifest_sha256": sha256_file(
                        lock_workspace / "manifest.json"
                    ),
                    "partition_manifest_sha256": sha256_file(
                        partition_workspace / "manifest.json"
                    ),
                    "dataset_manifest_sha256": sha256_file(
                        dataset_workspace / "manifest.json"
                    ),
                    "implementation_files": {
                        "protean_finalization.py": sha256_file(
                            Path(__file__).parents[1]
                            / "src"
                            / "fl_forensics"
                            / "protean_finalization.py"
                        )
                    },
                    "artifact_files": artifact_files,
                },
            )
            with (final_workspace / "evaluation.json").open("ab") as stream:
                stream.write(b" ")

            with (
                patch(
                    "fl_forensics.protean_finalization.verify_protean_selection_lock",
                    return_value={"status": "verified", "errors": []},
                ),
                patch(
                    "fl_forensics.protean_finalization.verify_partitions",
                    return_value={"status": "verified", "errors": []},
                ),
                patch(
                    "fl_forensics.protean_finalization._candidate_sources",
                    return_value={},
                ),
                patch(
                    "fl_forensics.protean_finalization._endpoint_source",
                    side_effect=(
                        {
                            "manifest_sha256": "primary-manifest",
                            "round_record_path": "round-primary.json",
                            "round_record_sha256": "primary-round",
                            "model_path": "primary-model.json",
                            "prototype_path": "primary-prototypes.json",
                        },
                        {
                            "manifest_sha256": "secondary-manifest",
                            "round_record_path": "round-secondary.json",
                            "round_record_sha256": "secondary-round",
                            "model_path": "secondary-model.json",
                            "prototype_path": "secondary-prototypes.json",
                        },
                    ),
                ),
                patch(
                    "fl_forensics.protean_finalization._validated_fedavg",
                    return_value={"source_digests": {"manifest_sha256": "fedavg"}},
                ),
            ):
                result = verify_protean_finalization(
                    candidate_workspaces=[],
                    fedavg_workspace=root / "fedavg",
                    report_workspace=root / "report",
                    selection_lock_workspace=lock_workspace,
                    partition_workspace=partition_workspace,
                    dataset_workspace=dataset_workspace,
                    workspace=final_workspace,
                    config_path=root / "config.yaml",
                )

            self.assertEqual(result["status"], "failed")
            self.assertTrue(
                any("artifact digest mismatch" in error for error in result["errors"])
            )
            self.assertFalse(result["verification_recomputed_model_inference"])


if __name__ == "__main__":
    unittest.main()
