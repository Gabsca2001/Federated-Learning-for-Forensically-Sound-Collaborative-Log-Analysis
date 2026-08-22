from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from fl_forensics.byzantine_experiment import (
    ByzantineExperimentError,
    _verify_partition_snapshot_files,
    verify_frozen_update_set,
)
from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.storage import write_once


class ByzantinePartitionBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.partition = self.root / "partition"
        clients = []
        for index in range(15):
            client_id = f"client{index + 1:02d}"
            dataset_path = self.partition / "clients" / client_id / "dataset.json"
            manifest_path = self.partition / "clients" / client_id / "manifest.json"
            write_once(
                dataset_path,
                derived_json_bytes({"client_id": client_id, "rows": {"train": []}}),
            )
            write_once(
                manifest_path,
                derived_json_bytes({"client_id": client_id, "partition_id": index}),
            )
            clients.append(
                {
                    "client_id": client_id,
                    "dataset_path": dataset_path.relative_to(self.partition).as_posix(),
                    "dataset_sha256": sha256_file(dataset_path),
                    "manifest_path": manifest_path.relative_to(
                        self.partition
                    ).as_posix(),
                    "manifest_sha256": sha256_file(manifest_path),
                }
            )
        server_path = self.partition / "server" / "evaluation.json"
        write_once(server_path, derived_json_bytes({"rows": {}}))
        self.signed_manifest = {
            "code_version": "signed-M5-version",
            "clients": clients,
            "server_evaluation_path": "server/evaluation.json",
            "server_evaluation_sha256": sha256_file(server_path),
        }
        self.signed_manifest_path = self.root / "signed-partition-manifest.json"
        write_once(
            self.signed_manifest_path,
            derived_json_bytes(self.signed_manifest),
        )
        current_manifest = {
            **self.signed_manifest,
            "code_version": "regenerated-current-version",
            "partition_config_sha256": "9" * 64,
        }
        write_once(
            self.partition / "manifest.json",
            derived_json_bytes(current_manifest),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_signed_manifest_accepts_identical_files_with_new_metadata(self) -> None:
        self.assertNotEqual(
            sha256_file(self.signed_manifest_path),
            sha256_file(self.partition / "manifest.json"),
        )
        server_path = _verify_partition_snapshot_files(
            partition_workspace=self.partition,
            partition_manifest=self.signed_manifest,
        )
        self.assertEqual(server_path, self.partition / "server" / "evaluation.json")

    def test_client_snapshot_tampering_is_rejected(self) -> None:
        path = self.partition / "clients" / "client01" / "dataset.json"
        path.chmod(0o644)
        path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(
            ByzantineExperimentError,
            "partition snapshot digest mismatch: client01 dataset",
        ):
            _verify_partition_snapshot_files(
                partition_workspace=self.partition,
                partition_manifest=self.signed_manifest,
            )

    def test_frozen_source_manifest_tampering_is_rejected(self) -> None:
        frozen = self.root / "frozen"
        base_path = frozen / "base-model.json"
        write_once(base_path, derived_json_bytes({"parameters": []}))
        clients = []
        for index in range(15):
            client_id = f"client{index + 1:02d}"
            relative = Path("updates") / client_id / "model-update.json"
            update_path = frozen / relative
            write_once(update_path, derived_json_bytes({"parameters": []}))
            clients.append(
                {
                    "client_id": client_id,
                    "attacker": index == 0,
                    "frozen_update_path": relative.as_posix(),
                    "frozen_update_sha256": sha256_file(update_path),
                }
            )
        source_path = frozen / "source-partition-manifest.json"
        write_once(source_path, self.signed_manifest_path.read_bytes())
        frozen_manifest = {
            "artifact_type": "m6_frozen_byzantine_update_set",
            "attack": "model_replacement",
            "f": 1,
            "attacker_ids": ["client01"],
            "base_model_sha256": sha256_file(base_path),
            "partition_manifest_path": "source-partition-manifest.json",
            "partition_manifest_sha256": sha256_file(source_path),
            "clients": clients,
        }
        write_once(frozen / "manifest.json", derived_json_bytes(frozen_manifest))
        self.assertEqual(verify_frozen_update_set(workspace=frozen)["status"], "verified")
        source_path.chmod(0o644)
        source_path.write_bytes(b"{}")
        verification = verify_frozen_update_set(workspace=frozen)
        self.assertEqual(verification["status"], "failed")
        self.assertIn(
            "partition snapshot digest mismatch: frozen source partition manifest",
            verification["errors"],
        )

    def test_unsafe_snapshot_path_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.signed_manifest)
        manifest["clients"][0]["dataset_path"] = "../outside.json"
        with self.assertRaisesRegex(
            ByzantineExperimentError,
            "partition snapshot contains an unsafe path: client01 dataset",
        ):
            _verify_partition_snapshot_files(
                partition_workspace=self.partition,
                partition_manifest=manifest,
            )


if __name__ == "__main__":
    unittest.main()
