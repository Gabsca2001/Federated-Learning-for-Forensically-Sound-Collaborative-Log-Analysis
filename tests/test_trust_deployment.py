from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from fl_forensics.trust_deployment import verify_m4_deployment


ROOT = Path(__file__).resolve().parents[1]


class TrustDeploymentTests(unittest.TestCase):
    def test_compose_has_fifteen_isolated_client_tpm_pairs(self) -> None:
        result = verify_m4_deployment(
            compose_path=ROOT / "compose.m4.yaml",
            clients_config_path=ROOT / "configs" / "clients.yaml",
        )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["pair_count"], 15)

    def test_foreign_tpm_socket_mount_is_rejected(self) -> None:
        compose = yaml.safe_load((ROOT / "compose.m4.yaml").read_text(encoding="utf-8"))
        compose["services"]["client01"]["volumes"].append("tpm02_socket:/foreign")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "compose.yaml"
            path.write_text(yaml.safe_dump(compose), encoding="utf-8")
            result = verify_m4_deployment(
                compose_path=path,
                clients_config_path=ROOT / "configs" / "clients.yaml",
            )
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any("foreign TPM sockets" in item for item in result["errors"]))


if __name__ == "__main__":
    unittest.main()
