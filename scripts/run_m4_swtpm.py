"""Cross-platform helper for the 15 isolated swtpm client pairs."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

CLIENT_IDS = [f"client{index:02d}" for index in range(1, 16)]
TPM_IDS = [f"tpm{index:02d}" for index in range(1, 16)]


def run(command: list[str], *, root: Path, environment: dict[str, str]) -> None:
    print(" ".join(command), flush=True)
    subprocess.run(command, cwd=root, env=environment, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("provision", "quote", "stop"))
    parser.add_argument("--compose", type=Path, default=Path("compose.m4.yaml"))
    parser.add_argument(
        "--trust-workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    parser.add_argument("--node-root", type=Path, default=Path("artifacts/m4-nodes"))
    arguments = parser.parse_args()
    root = arguments.compose.resolve().parent
    trust_workspace = arguments.trust_workspace.resolve()
    node_root = arguments.node_root.resolve()
    compose = ["docker", "compose", "-f", str(arguments.compose.resolve())]
    environment = os.environ.copy()
    environment.update(
        {
            "M4_UID": str(os.getuid()),
            "M4_GID": str(os.getgid()),
            "M4_TRUST_WORKSPACE": str(trust_workspace),
            "M4_NODE_ROOT": str(node_root),
        }
    )

    if arguments.action == "stop":
        run([*compose, "down"], root=root, environment=environment)
        return 0

    for client_id in CLIENT_IDS:
        (node_root / client_id).mkdir(parents=True, exist_ok=True)
    trust_workspace.mkdir(parents=True, exist_ok=True)
    # run([*compose, "up", "-d", "--build", *TPM_IDS], root=root)
    if arguments.action == "provision":
        run(
            [*compose, "up", "-d", "--build", *TPM_IDS],
            root=root,
            environment=environment,
        )
    else:
        run([*compose, "up", "-d", *TPM_IDS], root=root, environment=environment)

    for index, client_id in enumerate(CLIENT_IDS, start=1):
        if arguments.action == "provision":
            run(
                [
                    *compose,
                    "--profile",
                    "provision",
                    "run",
                    "--build",
                    "--rm",
                    client_id,
                ],
                root=root,
                environment=environment,
            )
        else:
            run(
                [
                    *compose,
                    "--profile",
                    "provision",
                    "run",
                    "--rm",
                    client_id,
                    "m4-tpm-quote",
                    "--workspace",
                    "/runtime",
                    "--tcti",
                    "swtpm:path=/run/swtpm/swtpm.sock",
                ],
                root=root,
                environment=environment,
            )
        print(f"[{index:02d}/15] {client_id} {arguments.action} completed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
