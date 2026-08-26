from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from fl_forensics.trust_deployment import verify_m4_deployment

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load script: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TrustDeploymentTests(unittest.TestCase):
    def test_compose_has_fifteen_isolated_client_tpm_pairs(self) -> None:
        result = verify_m4_deployment(
            compose_path=ROOT / "compose.m4.yaml",
            clients_config_path=ROOT / "configs" / "clients.yaml",
        )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["pair_count"], 15)

    def test_compose_mounts_accept_versioned_m4_workspaces(self) -> None:
        compose = yaml.safe_load((ROOT / "compose.m4.yaml").read_text(encoding="utf-8"))
        for index in range(1, 16):
            client_id = f"client{index:02d}"
            expected = (
                "${M4_NODE_ROOT:-./artifacts/m4-nodes}/"
                f"{client_id}:/runtime"
            )
            self.assertIn(expected, compose["services"][client_id]["volumes"])
        self.assertIn(
            "${M4_TRUST_WORKSPACE:-./artifacts/m4-trust}:/trust",
            compose["services"]["verifier"]["volumes"],
        )
        self.assertIn(
            "${M4_NODE_ROOT:-./artifacts/m4-nodes}:/nodes:ro",
            compose["services"]["verifier"]["volumes"],
        )

    def test_swtpm_runner_passes_custom_workspace_mounts(self) -> None:
        runner = load_script("run_m4_swtpm")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compose = root / "compose.m4.yaml"
            trust_workspace = root / "trust-v1"
            node_root = root / "nodes-v1"
            argv = [
                "run_m4_swtpm.py",
                "provision",
                "--compose",
                str(compose),
                "--trust-workspace",
                str(trust_workspace),
                "--node-root",
                str(node_root),
            ]
            with patch.object(sys, "argv", argv), patch.object(
                runner.subprocess, "run"
            ) as subprocess_run:
                self.assertEqual(runner.main(), 0)
            self.assertTrue(trust_workspace.is_dir())
            self.assertTrue((node_root / "client15").is_dir())

        self.assertEqual(subprocess_run.call_count, 16)
        environment = subprocess_run.call_args_list[0].kwargs["env"]
        self.assertEqual(environment["M4_TRUST_WORKSPACE"], str(trust_workspace))
        self.assertEqual(environment["M4_NODE_ROOT"], str(node_root))

    def test_multiround_refresh_accepts_versioned_m4_workspaces(self) -> None:
        runner = load_script("run_m5_secure_multiround")
        trust_workspace = ROOT / "artifacts" / "m4-trust-v1"
        node_root = ROOT / "artifacts" / "m4-nodes-v1"
        compose_m4 = ROOT / "compose.m4.yaml"
        with patch.object(runner, "run") as run:
            runner.refresh_attestations(
                root=ROOT,
                environment={"COMPOSE_PROJECT_NAME": "test"},
                trust_workspace=trust_workspace,
                node_root=node_root,
                compose_m4=compose_m4,
            )

        self.assertEqual(run.call_count, 3)
        quote_command = run.call_args_list[1].args[0]
        self.assertIn(str(trust_workspace), quote_command)
        self.assertIn(str(node_root), quote_command)
        verify_command = run.call_args_list[2].args[0]
        self.assertIn("verifier", verify_command)

    def test_multiround_verification_uses_post_selection_finalizer(self) -> None:
        runner = load_script("run_m5_secure_multiround")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compose = root / "compose.m5.yaml"
            partition = root / "partition"
            campaign = root / "campaign"
            trust = root / "trust"
            nodes = root / "nodes"
            (partition / "server").mkdir(parents=True)
            (trust / "registry").mkdir(parents=True)
            (partition / "manifest.json").write_text("{}", encoding="utf-8")
            (partition / "server" / "evaluation.json").write_text(
                "{}", encoding="utf-8"
            )
            (trust / "registry" / "index.json").write_text("{}", encoding="utf-8")
            for index in range(1, 16):
                (nodes / f"client{index:02d}").mkdir(parents=True)
            argv = [
                "run_m5_secure_multiround.py",
                "verify",
                "--compose",
                str(compose),
                "--partition-workspace",
                str(partition),
                "--workspace",
                str(campaign),
                "--trust-workspace",
                str(trust),
                "--node-root",
                str(nodes),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(runner, "run") as run,
                patch.object(runner, "require_running_tpms"),
            ):
                self.assertEqual(runner.main(), 0)

        verification_command = run.call_args_list[-1].args[0]
        self.assertIn("finalize", verification_command)
        self.assertIn("finalizer", verification_command)
        self.assertNotIn("coordinator", verification_command)
        self.assertIn("/partition/server/evaluation.json", verification_command)

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
