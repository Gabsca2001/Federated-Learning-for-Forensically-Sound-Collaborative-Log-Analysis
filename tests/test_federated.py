from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

import yaml

from fl_forensics.config import load_yaml
from fl_forensics.dataset24 import prepare_dataset
from fl_forensics.federated_partitioning import prepare_partitions, verify_partitions

from test_dataset24 import _build_fixture

ROOT = Path(__file__).resolve().parents[1]


class FederatedPartitionTests(unittest.TestCase):
    def _prepare_m2(self, root: Path) -> Path:
        source = root / "source"
        _build_fixture(source)
        base, _digest = load_yaml(ROOT / "configs" / "base.yaml")
        workspace = root / "m2"
        prepare_dataset(
            source_root=source,
            output=workspace,
            preprocessing_config=base["preprocessing"],
        )
        return workspace

    def _test_config(self, root: Path) -> Path:
        config, _digest = load_yaml(ROOT / "configs" / "federation.yaml")
        config["partitioning"]["minimum_train_rows_per_client"] = 0
        path = root / "federation-test.yaml"
        path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        return path

    def test_iid_and_non_iid_snapshots_are_complete_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            m2 = self._prepare_m2(root)
            config = self._test_config(root)
            digests = {}
            for mode in ("iid", "non-iid"):
                workspace = root / mode
                result = prepare_partitions(
                    dataset_workspace=m2,
                    output=workspace,
                    mode=mode,
                    config_path=config,
                )
                self.assertEqual(result["client_count"], 15)
                verification = verify_partitions(
                    workspace=workspace, dataset_workspace=m2
                )
                self.assertEqual(verification["status"], "verified")
                manifest = json.loads((workspace / "manifest.json").read_text())
                self.assertEqual(len(manifest["clients"]), 15)
                self.assertEqual(
                    manifest["class_weighting"],
                    "global-sqrt-balanced-training-only",
                )
                digests[mode] = verification["manifest_sha256"]
            self.assertNotEqual(digests["iid"], digests["non-iid"])

    def test_client_snapshot_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            m2 = self._prepare_m2(root)
            workspace = root / "iid"
            prepare_partitions(
                dataset_workspace=m2,
                output=workspace,
                mode="iid",
                config_path=self._test_config(root),
            )
            manifest = json.loads((workspace / "manifest.json").read_text())
            target = workspace / manifest["clients"][0]["dataset_path"]
            # The partition artifact is intentionally read-only. Clear that
            # protection explicitly to model an attacker who gained enough
            # privileges to alter the file; Windows otherwise rejects append.
            target.chmod(target.stat().st_mode | stat.S_IWUSR)
            with target.open("a", encoding="utf-8") as stream:
                stream.write(" ")
            verification = verify_partitions(
                workspace=workspace, dataset_workspace=m2
            )
            self.assertEqual(verification["status"], "failed")
            self.assertTrue(
                any("client artifact digest mismatch" in error for error in verification["errors"])
            )


if __name__ == "__main__":
    unittest.main()
