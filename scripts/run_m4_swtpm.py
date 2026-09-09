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
    parser.add_argument("action", choices=("provision", "quote", "extend", "stop"))
    parser.add_argument("--compose", type=Path, default=Path("compose.m4.yaml"))
    parser.add_argument(
        "--trust-workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    parser.add_argument("--node-root", type=Path, default=Path("artifacts/m4-nodes"))
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="reuse prebuilt Compose images (used by runtime latency experiments)",
    )
    parser.add_argument("--client-id", choices=CLIENT_IDS)
    parser.add_argument("--pcr-index", type=int)
    parser.add_argument("--measurement-sha256")
    parser.add_argument("--event-id")
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

    selected_clients = [arguments.client_id] if arguments.client_id else CLIENT_IDS
    selected_tpms = [
        f"tpm{int(client_id.removeprefix('client')):02d}"
        for client_id in selected_clients
    ]
    for client_id in selected_clients:
        (node_root / client_id).mkdir(parents=True, exist_ok=True)
    trust_workspace.mkdir(parents=True, exist_ok=True)
    # run([*compose, "up", "-d", "--build", *TPM_IDS], root=root)
    if arguments.action == "provision":
        build_flag = [] if arguments.skip_build else ["--build"]
        run(
            [*compose, "up", "-d", *build_flag, *selected_tpms],
            root=root,
            environment=environment,
        )
    else:
        run(
            [*compose, "up", "-d", *selected_tpms],
            root=root,
            environment=environment,
        )

    if arguments.action == "extend":
        if arguments.client_id is None:
            parser.error("extend requires --client-id")
        if arguments.pcr_index is None:
            parser.error("extend requires --pcr-index")
        if arguments.measurement_sha256 is None:
            parser.error("extend requires --measurement-sha256")
        if arguments.event_id is None:
            parser.error("extend requires --event-id")
        build_flag = [] if arguments.skip_build else ["--build"]
        run(
            [
                *compose,
                "--profile",
                "provision",
                "run",
                *build_flag,
                "--rm",
                arguments.client_id,
                "m4-tpm-extend-pcr",
                "--workspace",
                "/runtime",
                "--tcti",
                "swtpm:path=/run/swtpm/swtpm.sock",
                "--client-id",
                arguments.client_id,
                "--pcr-index",
                str(arguments.pcr_index),
                "--measurement-sha256",
                arguments.measurement_sha256,
                "--event-id",
                arguments.event_id,
            ],
            root=root,
            environment=environment,
        )
        return 0

    for index, client_id in enumerate(selected_clients, start=1):
        if arguments.action == "provision":
            build_flag = [] if arguments.skip_build else ["--build"]
            run(
                [
                    *compose,
                    "--profile",
                    "provision",
                    "run",
                    *build_flag,
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
        print(
            f"[{index:02d}/{len(selected_clients):02d}] "
            f"{client_id} {arguments.action} completed",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
