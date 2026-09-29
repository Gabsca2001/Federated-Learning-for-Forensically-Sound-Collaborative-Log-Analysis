"""Ensure paired runs pass the requested seed config into actual M5 initialization."""
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("config_name", ["federation.yaml", "federation-m6-policy-seed-342593.yaml"])
def test_runner_passes_selected_federation_to_container(tmp_path, monkeypatch, config_name):
    spec = importlib.util.spec_from_file_location("m5_runner_test", ROOT / "scripts/run_m5_secure_multiround.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / config_name).write_text("test fixture")
    partition = tmp_path / "partition"
    (partition / "server").mkdir(parents=True)
    (partition / "manifest.json").write_text("{}")
    (partition / "server/evaluation.json").write_text("{}")
    trust = tmp_path / "trust"
    (trust / "registry").mkdir(parents=True)
    (trust / "registry/index.json").write_text("{}")
    nodes = tmp_path / "nodes"
    for client in module.CLIENT_IDS:
        (nodes / client).mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    argv = ["runner", "run", "--compose", str(tmp_path / "compose.m5.yaml"),
            "--partition-workspace", str(partition), "--trust-workspace", str(trust),
            "--node-root", str(nodes), "--workspace", str(tmp_path / "campaign"),
            "--rounds", "1", "--attestation-refresh-interval", "0"]
    if config_name != "federation.yaml":
        argv += ["--federation-config", "configs/" + config_name]
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(module, "require_running_tpms", lambda *args, **kwargs: None)
    captured = []

    class InitializationReached(Exception):
        pass

    def capture(command, **kwargs):
        if "m5-init" in command:
            captured.append(command)
            raise InitializationReached

    monkeypatch.setattr(module, "run", capture)
    with pytest.raises(InitializationReached):
        module.main()
    command = captured[0]
    assert command[command.index("--config") + 1] == "/app/configs/" + config_name
