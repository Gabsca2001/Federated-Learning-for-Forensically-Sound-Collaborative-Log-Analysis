"""Static validation of the 15 client-to-swtpm Compose deployment."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import load_yaml


def _volume_source(item: str | dict[str, Any]) -> str:
    if isinstance(item, str):
        return item.split(":", 1)[0]
    return str(item.get("source", ""))


def verify_m4_deployment(
    *, compose_path: Path, clients_config_path: Path
) -> dict[str, Any]:
    compose, _ = load_yaml(compose_path)
    clients_config, _ = load_yaml(clients_config_path)
    services = compose.get("services", {})
    errors: list[str] = []
    pairs: list[dict[str, str]] = []

    for pair in clients_config["clients"]:
        client_id = pair["client_id"]
        tpm_id = pair["tpm"]
        client = services.get(client_id)
        tpm = services.get(tpm_id)
        if client is None:
            errors.append(f"missing client service {client_id}")
            continue
        if tpm is None:
            errors.append(f"missing TPM service {tpm_id}")
            continue
        expected_socket = f"{tpm_id}_socket"
        expected_state = f"{tpm_id}_state"
        client_volumes = {_volume_source(item) for item in client.get("volumes", [])}
        tpm_volumes = {_volume_source(item) for item in tpm.get("volumes", [])}
        if expected_socket not in client_volumes:
            errors.append(f"{client_id} does not mount its paired TPM socket")
        foreign_sockets = {
            source
            for source in client_volumes
            if source.endswith("_socket") and source != expected_socket
        }
        if foreign_sockets:
            errors.append(f"{client_id} mounts foreign TPM sockets: {sorted(foreign_sockets)}")
        if any(source.endswith("_state") for source in client_volumes):
            errors.append(f"{client_id} mounts TPM persistent state")
        if expected_socket not in tpm_volumes or expected_state not in tpm_volumes:
            errors.append(f"{tpm_id} lacks its dedicated socket/state volumes")
        if client.get("user") in {None, "0", "0:0", "root"}:
            errors.append(f"{client_id} is not configured as an unprivileged user")
        if not client.get("read_only", False):
            errors.append(f"{client_id} root filesystem is not read-only")
        if "ALL" not in client.get("cap_drop", []):
            errors.append(f"{client_id} does not drop all Linux capabilities")
        if "no-new-privileges:true" not in client.get("security_opt", []):
            errors.append(f"{client_id} does not enforce no-new-privileges")
        if any("docker.sock" in str(item) for item in client.get("volumes", [])):
            errors.append(f"{client_id} mounts the Docker control socket")
        depends = client.get("depends_on", {})
        if tpm_id not in depends:
            errors.append(f"{client_id} does not declare its paired TPM dependency")
        pairs.append(
            {
                "client_id": client_id,
                "node_id": pair["node_id"],
                "tpm_id": tpm_id,
                "socket_volume": expected_socket,
                "state_volume": expected_state,
            }
        )

    declared_tpm_services = {name for name in services if name.startswith("tpm")}
    expected_tpm_services = {pair["tpm"] for pair in clients_config["clients"]}
    if declared_tpm_services != expected_tpm_services:
        errors.append("Compose TPM service set differs from configs/clients.yaml")
    declared_clients = {name for name in services if name.startswith("client")}
    expected_clients = {pair["client_id"] for pair in clients_config["clients"]}
    if declared_clients != expected_clients:
        errors.append("Compose client service set differs from configs/clients.yaml")

    return {
        "status": "verified" if not errors else "failed",
        "compose": str(compose_path),
        "pair_count": len(pairs),
        "error_count": len(errors),
        "errors": errors,
        "pairs": pairs,
    }
