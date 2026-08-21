from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from fl_forensics.canonical import sha256_file
from fl_forensics.config import load_yaml
from fl_forensics.federated_model import (
    FederatedDependencyError,
    architecture_record,
    build_model,
    dependencies,
    export_state,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.prototype_experiment import (
    PrototypeExperimentError,
    _compute_comparison,
    _select_attackers,
    run_prototype_comparison,
    verify_prototype_comparison,
)
from fl_forensics.storage import load_json, write_once

ROOT = Path(__file__).resolve().parents[1]


class PrototypeExperimentTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            dependency_values = dependencies()
        except FederatedDependencyError as exc:
            self.skipTest(str(exc))
        _np, self.torch, *_rest = dependency_values
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.frozen = root / "frozen"
        self.partition = root / "partition"
        self.output = root / "comparison"
        self.config_path = ROOT / "configs" / "byzantine-prototype-poisoning.yaml"
        self._prepare_model()
        self._prepare_partition()
        self._prepare_frozen()

    def tearDown(self) -> None:
        if hasattr(self, "temporary"):
            self.temporary.cleanup()

    def _prepare_model(self) -> None:
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
            torch=self.torch,
        )
        with self.torch.no_grad():
            for index in (0, 2, 4):
                model.encoder[index].weight.copy_(self.torch.eye(2))
                model.encoder[index].bias.zero_()
            model.classification_head.weight.copy_(self.torch.eye(2))
            model.classification_head.bias.zero_()
        self.model_export = export_state(
            model,
            architecture=architecture,
            class_names=["benign", "reconnaissance"],
        )

    def _prepare_partition(self) -> None:
        client_records = []
        for index in range(1, 16):
            client_id = f"client{index:02d}"
            dataset_relative = Path("clients") / client_id / "dataset.json"
            manifest_relative = Path("clients") / client_id / "manifest.json"
            write_once(self.partition / dataset_relative, derived_json_bytes({}))
            write_once(self.partition / manifest_relative, derived_json_bytes({}))
            client_records.append(
                {
                    "client_id": client_id,
                    "dataset_path": dataset_relative.as_posix(),
                    "dataset_sha256": sha256_file(self.partition / dataset_relative),
                    "manifest_path": manifest_relative.as_posix(),
                    "manifest_sha256": sha256_file(self.partition / manifest_relative),
                }
            )
        rows = [
            {"features": [0.0, 0.0], "label": "benign"},
            {"features": [10.0, 10.0], "label": "reconnaissance"},
        ]
        server = {
            "class_names": ["benign", "reconnaissance"],
            "rows": {
                "validation": copy.deepcopy(rows),
                "test": copy.deepcopy(rows),
                "temporal_holdout": copy.deepcopy(rows),
            },
        }
        server_relative = Path("server") / "evaluation.json"
        write_once(self.partition / server_relative, derived_json_bytes(server))
        self.partition_manifest = {
            "class_names": ["benign", "reconnaissance"],
            "clients": client_records,
            "server_evaluation_path": server_relative.as_posix(),
            "server_evaluation_sha256": sha256_file(
                self.partition / server_relative
            ),
        }
        write_once(
            self.partition / "manifest.json",
            derived_json_bytes(self.partition_manifest),
        )

    @staticmethod
    def _prototype_record(*, poisoned: bool, high_support: bool) -> dict[str, object]:
        reconnaissance = [-5.0, -5.0] if poisoned else [10.0, 10.0]
        support = 1000 if high_support else 10
        return {
            "embedding_size": 2,
            "row_count": 20,
            "minimum_local_support": 5,
            "class_supports": {"benign": support, "reconnaissance": support},
            "eligible_class_count": 2,
            "prototypes": {
                "benign": {"support": support, "values": [0.0, 0.0]},
                "reconnaissance": {
                    "support": support,
                    "values": reconnaissance,
                },
            },
        }

    def _prepare_frozen(self) -> None:
        global_relative = Path("source") / "global-model.json"
        partition_relative = Path("source") / "partition-manifest.json"
        write_once(self.frozen / global_relative, derived_json_bytes(self.model_export))
        write_once(
            self.frozen / partition_relative,
            (self.partition / "manifest.json").read_bytes(),
        )
        attackers = {"client02", "client05", "client14"}
        records = []
        for index in range(1, 16):
            client_id = f"client{index:02d}"
            attacked = client_id in attackers
            clean = self._prototype_record(poisoned=False, high_support=attacked)
            submitted = self._prototype_record(
                poisoned=attacked, high_support=attacked
            )
            value = {
                "client_id": client_id,
                "attacker": attacked,
                "privacy": {"row_embeddings_preserved": False},
                "clean": clean,
                "submitted": submitted,
            }
            relative = Path("submissions") / f"{client_id}.json"
            write_once(self.frozen / relative, derived_json_bytes(value))
            records.append(
                {
                    "client_id": client_id,
                    "attacker": attacked,
                    "submission_path": relative.as_posix(),
                    "submission_sha256": sha256_file(self.frozen / relative),
                }
            )
        _config, config_digest = load_yaml(self.config_path)
        manifest = {
            "schema_version": "1.0",
            "artifact_type": "m6_frozen_prototype_poisoning_scenario",
            "attack": "prototype_poisoning",
            "f": 3,
            "attacker_ids": sorted(attackers),
            "source_semantics": "test-post-training-overlay",
            "prototype_config_sha256": config_digest,
            "source_files": {
                "global_model": {
                    "path": global_relative.as_posix(),
                    "sha256": sha256_file(self.frozen / global_relative),
                },
                "partition_manifest": {
                    "path": partition_relative.as_posix(),
                    "sha256": sha256_file(self.frozen / partition_relative),
                },
            },
            "clients": records,
        }
        write_once(self.frozen / "manifest.json", derived_json_bytes(manifest))

    def test_attacker_selection_is_deterministic_and_fail_closed(self) -> None:
        clients = [f"client{index:02d}" for index in range(1, 16)]
        self.assertEqual(
            _select_attackers(clients, f=3, seed=341593),
            _select_attackers(clients, f=3, seed=341593),
        )
        with self.assertRaises(PrototypeExperimentError):
            _select_attackers(clients, f=0, seed=341593)

    def test_comparison_detects_poisoning_and_recomputes_evidence(self) -> None:
        result = run_prototype_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            output=self.output,
            config_path=self.config_path,
        )
        self.assertEqual(result["status"], "compared")
        self.assertEqual(result["profile_count"], 4)
        comparison = load_json(self.output / "comparison.json")
        self.assertEqual(comparison["schema_version"], "1.1")
        effects = {
            item["aggregation_strategy"]: item
            for item in comparison["attack_effects"]
        }
        self.assertGreater(
            effects["support_weighted_mean"]["source_prototype_shift_l2"], 0.0
        )
        self.assertEqual(
            effects["coordinate_median"]["source_prototype_shift_l2"], 0.0
        )
        self.assertGreater(
            effects["support_weighted_mean"]["test_attack_success_rate_delta"],
            effects["coordinate_median"]["test_attack_success_rate_delta"],
        )
        self.assertLess(
            effects["support_weighted_mean"]["test_source_recall_delta"], 0.0
        )
        self.assertEqual(
            effects["coordinate_median"]["test_source_recall_delta"], 0.0
        )
        for outcome in comparison["outcomes"]:
            integrity = outcome["source_class_integrity"]["test"]
            self.assertEqual(
                integrity["source_row_count"],
                integrity["correct_source_prediction_count"]
                + integrity["target_class_prediction_count"]
                + integrity["other_class_prediction_count"],
            )
        verification = verify_prototype_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            workspace=self.output,
            config_path=self.config_path,
        )
        self.assertEqual(verification["status"], "verified")

        legacy, _aggregates = _compute_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            config_path=self.config_path,
            include_source_integrity=False,
        )
        self.assertEqual(legacy["schema_version"], "1.0")
        self.assertNotIn("comparison_implementation_sha256", legacy)
        for outcome in legacy["outcomes"]:
            self.assertNotIn("source_class_integrity", outcome)
        legacy["aggregates"] = comparison["aggregates"]
        comparison_path = self.output / "comparison.json"
        comparison_path.chmod(0o644)
        comparison_path.write_bytes(derived_json_bytes(legacy))
        verification = verify_prototype_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            workspace=self.output,
            config_path=self.config_path,
        )
        self.assertEqual(verification["status"], "verified")

        aggregate_path = self.output / "aggregates" / (
            "attacked-baseline-support_weighted_mean.json"
        )
        aggregate_path.chmod(0o644)
        aggregate_path.write_text("{}", encoding="utf-8")
        verification = verify_prototype_comparison(
            frozen_workspace=self.frozen,
            partition_workspace=self.partition,
            workspace=self.output,
            config_path=self.config_path,
        )
        self.assertEqual(verification["status"], "failed")


if __name__ == "__main__":
    unittest.main()
