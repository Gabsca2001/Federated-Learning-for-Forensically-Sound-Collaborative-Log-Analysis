from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from fl_forensics.canonical import sha256_file
from fl_forensics.config import load_yaml
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.protean_reporting import (
    generate_protean_validation_report,
    verify_protean_validation_report,
)
from fl_forensics.protean_selection_lock import (
    create_protean_selection_lock,
    verify_protean_selection_lock,
)

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ["benign", "attack"]


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(derived_json_bytes(value))


def _evaluation(score: float) -> dict[str, object]:
    return {
        "row_count": 10,
        "observed_labels": CLASSES,
        "observed_class_count": 2,
        "loss": None,
        "accuracy": score,
        "balanced_accuracy_observed_classes": score,
        "macro_precision_all_model_classes": score,
        "macro_recall_all_model_classes": score,
        "macro_f1_all_model_classes": score,
        "per_class": {
            "benign": {"precision": score, "recall": score, "f1": score, "support": 5},
            "attack": {"precision": score, "recall": score, "f1": score, "support": 5},
        },
        "confusion_matrix": {
            "labels": CLASSES,
            "values": [[4, 1], [1, 4]],
        },
        "prototype_distance": {
            "metric": "euclidean",
            "available_classes": CLASSES,
            "unavailable_classes": [],
            "mean_nearest_distance": 0.2,
            "maximum_nearest_distance": 0.4,
            "mean_distance_margin": 0.8,
        },
    }


def _build_candidate(
    root: Path,
    *,
    weight: float,
    prototype_scores: tuple[float, float],
    head_scores: tuple[float, float],
    config_digest: str,
) -> Path:
    workspace = root / f"lambda-{weight:g}"
    prototype_object = {
        "schema_version": "1.0",
        "artifact_type": "protean_global_class_prototypes",
        "class_quorum": 2,
        "classes": {
            "benign": {
                "status": "aggregated",
                "eligible_client_count": 2,
                "total_support": 20,
            },
            "attack": {
                "status": "aggregated",
                "eligible_client_count": 2,
                "total_support": 10,
            },
        },
    }
    prototype_path = workspace / "objects" / "selected-prototypes.json"
    _write(prototype_path, prototype_object)
    rounds = []
    for number in (1, 2):
        prototype_score = prototype_scores[number - 1]
        head_score = head_scores[number - 1]
        rounds.append(
            {
                "round": number,
                "global_model_sha256": f"model-{weight}-{number}",
                "global_prototypes_sha256": f"prototypes-{weight}-{number}",
                "weighted_training": {
                    "objective_loss": 1.0 / number,
                    "supervised_loss": 0.8 / number,
                    "prototype_alignment_loss": 0.2 / number,
                    "proximal_penalty": 0.1 / number,
                },
                "validation": {
                    "nearest_global_prototype": _evaluation(prototype_score),
                    "classification_head": _evaluation(head_score),
                },
                "communication": {
                    "client_upload_model_bytes": 10000,
                    "client_upload_prototype_bytes": 100,
                    "server_broadcast_model_bytes": 10000,
                    "server_broadcast_prototype_bytes": 100,
                    "total_bytes": 20200,
                },
            }
        )
    selected_round = max(
        range(2), key=lambda index: (prototype_scores[index], -index)
    )
    selected_metric = rounds[selected_round]
    selected_metric["global_prototypes_sha256"] = sha256_file(prototype_path)
    selected = {
        "round": selected_round + 1,
        "model_sha256": selected_metric["global_model_sha256"],
        "global_prototypes_path": prototype_path.relative_to(workspace).as_posix(),
        "global_prototypes_sha256": sha256_file(prototype_path),
        "validation": selected_metric["validation"],
    }
    metrics = {
        "schema_version": "1.0",
        "artifact_type": "protean_candidate_validation_metrics",
        "dataset": "UWF-ZeekData24",
        "partition_mode": "non-iid",
        "prototype_alignment_weight": weight,
        "rounds": rounds,
        "selected": selected,
        "test_data_accessed": False,
    }
    _write(workspace / "metrics.json", metrics)
    clients = {
        "schema_version": "1.0",
        "artifact_type": "protean_selected_client_validation",
        "selected_round": selected_round + 1,
        "clients": [
            {
                "client_id": "client01",
                "training_class_support": {"benign": 10},
                "validation": {
                    "nearest_global_prototype": _evaluation(prototype_scores[selected_round]),
                    "classification_head": _evaluation(head_scores[selected_round]),
                },
            },
            {
                "client_id": "client02",
                "training_class_support": {"benign": 2, "attack": 10},
                "validation": {
                    "nearest_global_prototype": _evaluation(prototype_scores[selected_round]),
                    "classification_head": _evaluation(head_scores[selected_round]),
                },
            },
        ],
    }
    _write(workspace / "selected_client_validation.json", clients)
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "protean_candidate_run_manifest",
        "dataset": "UWF-ZeekData24",
        "partition_manifest_sha256": "partition-digest",
        "dataset_manifest_sha256": "dataset-digest",
        "protean_config_sha256": config_digest,
        "initial_model_sha256": "initial-model",
        "implementation_files": {"protean.py": "implementation"},
        "training": {
            "rounds": 2,
            "local_epochs": 1,
            "device": "cpu",
            "device_override": None,
            "prototype_alignment_weight": weight,
        },
        "metrics_sha256": sha256_file(workspace / "metrics.json"),
        "selected_client_validation_sha256": sha256_file(
            workspace / "selected_client_validation.json"
        ),
        "test_data_accessed": False,
    }
    _write(workspace / "manifest.json", manifest)
    return workspace


def _build_fedavg(root: Path) -> Path:
    workspace = root / "fedavg"
    validation = _evaluation(0.76)
    comparison = {
        "schema_version": "2.0",
        "artifact_type": "m3_local_fedavg_comparison",
        "fedavg_selected": {"validation": validation},
        "selected_global_client_validation": [
            {"client_id": "client01", "validation": validation},
            {"client_id": "client02", "validation": validation},
        ],
    }
    _write(workspace / "comparison.json", comparison)
    _write(
        workspace / "manifest.json",
        {
            "schema_version": "2.0",
            "artifact_type": "m3_fedavg_run_manifest",
            "dataset": "UWF-ZeekData24",
            "partition_manifest_sha256": "partition-digest",
            "comparison_sha256": sha256_file(workspace / "comparison.json"),
        },
    )
    return workspace


@unittest.skipUnless(
    importlib.util.find_spec("matplotlib"),
    "optional reporting dependency is not installed",
)
class ProteanReportingTests(unittest.TestCase):
    def _sources(self, root: Path) -> tuple[list[Path], Path]:
        _config, config_digest = load_yaml(ROOT / "configs" / "federation-protean.yaml")
        definitions = (
            (0.001, (0.60, 0.70), (0.65, 0.72)),
            (0.01, (0.70, 0.80), (0.72, 0.78)),
            (0.1, (0.68, 0.77), (0.75, 0.85)),
            (1.0, (0.55, 0.65), (0.45, 0.50)),
        )
        candidates = [
            _build_candidate(
                root,
                weight=weight,
                prototype_scores=prototype_scores,
                head_scores=head_scores,
                config_digest=config_digest,
            )
            for weight, prototype_scores, head_scores in definitions
        ]
        return candidates, _build_fedavg(root)

    def test_report_selects_validation_winner_and_is_repeatable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidates, fedavg = self._sources(root)
            output = root / "report"
            first = generate_protean_validation_report(
                candidate_workspaces=candidates,
                fedavg_workspace=fedavg,
                output=output,
                config_path=ROOT / "configs" / "federation-protean.yaml",
            )
            first_digest = sha256_file(output / "summary.json")
            second = generate_protean_validation_report(
                candidate_workspaces=candidates,
                fedavg_workspace=fedavg,
                output=output,
                config_path=ROOT / "configs" / "federation-protean.yaml",
            )

            self.assertEqual(first["status"], "reported_validation_only")
            self.assertEqual(first["selected_prototype_alignment_weight"], 0.01)
            self.assertEqual(first["head_diagnostic_alignment_weight"], 0.1)
            self.assertEqual(first["figure_count"], 7)
            self.assertFalse(first["test_data_accessed"])
            self.assertEqual(first_digest, second["summary_sha256"])
            selection = json.loads((output / "selection.json").read_text())
            self.assertEqual(selection["selected"]["prototype_alignment_weight"], 0.01)
            self.assertFalse(selection["test_data_accessed"])
            summary = json.loads((output / "summary.json").read_text())
            for figure in summary["figures"]:
                self.assertEqual(
                    sha256_file(output / figure["path"]), figure["sha256"]
                )

    def test_report_and_pretest_lock_verify_and_detect_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidates, fedavg = self._sources(root)
            report = root / "report"
            generate_protean_validation_report(
                candidate_workspaces=candidates,
                fedavg_workspace=fedavg,
                output=report,
                config_path=ROOT / "configs" / "federation-protean.yaml",
            )
            report_verification = verify_protean_validation_report(
                candidate_workspaces=candidates,
                fedavg_workspace=fedavg,
                workspace=report,
                config_path=ROOT / "configs" / "federation-protean.yaml",
            )
            self.assertEqual(report_verification["status"], "verified")
            self.assertEqual(report_verification["error_count"], 0)

            lock_workspace = root / "selection-lock"
            result = create_protean_selection_lock(
                candidate_workspaces=candidates,
                fedavg_workspace=fedavg,
                report_workspace=report,
                output=lock_workspace,
                config_path=ROOT / "configs" / "federation-protean.yaml",
            )
            self.assertEqual(result["status"], "locked_pretest")
            self.assertFalse(result["test_data_accessed"])
            lock = json.loads((lock_workspace / "selection_lock.json").read_text())
            self.assertEqual(
                lock["primary_endpoint"]["prototype_alignment_weight"], 0.01
            )
            self.assertEqual(
                lock["secondary_endpoint"]["prototype_alignment_weight"], 0.1
            )
            self.assertEqual(lock["test_gate"]["state"], "locked")

            verification = verify_protean_selection_lock(
                candidate_workspaces=candidates,
                fedavg_workspace=fedavg,
                report_workspace=report,
                workspace=lock_workspace,
                config_path=ROOT / "configs" / "federation-protean.yaml",
            )
            self.assertEqual(verification["status"], "verified")
            self.assertEqual(verification["error_count"], 0)

            lock_path = lock_workspace / "selection_lock.json"
            lock_path.chmod(0o600)
            with lock_path.open("ab") as stream:
                stream.write(b" ")
            tampered = verify_protean_selection_lock(
                candidate_workspaces=candidates,
                fedavg_workspace=fedavg,
                report_workspace=report,
                workspace=lock_workspace,
                config_path=ROOT / "configs" / "federation-protean.yaml",
            )
            self.assertEqual(tampered["status"], "failed")
            self.assertGreater(tampered["error_count"], 0)

    def test_candidate_metrics_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidates, fedavg = self._sources(root)
            with (candidates[0] / "metrics.json").open("ab") as stream:
                stream.write(b" ")
            with self.assertRaisesRegex(ValueError, "metrics digest"):
                generate_protean_validation_report(
                    candidate_workspaces=candidates,
                    fedavg_workspace=fedavg,
                    output=root / "report",
                    config_path=ROOT / "configs" / "federation-protean.yaml",
                )


if __name__ == "__main__":
    unittest.main()
