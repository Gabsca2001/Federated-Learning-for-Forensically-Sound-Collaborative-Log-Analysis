"""Orchestrate the 15-container M5 secure round without deleting TPM state."""

from __future__ import annotations

import argparse
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


CLIENT_IDS = [f"client{index:02d}" for index in range(1, 16)]
TPM_IDS = [f"tpm{index:02d}" for index in range(1, 16)]


def run(command: list[str], *, root: Path, environment: dict[str, str]) -> None:
    print(" ".join(command), flush=True)
    subprocess.run(command, cwd=root, env=environment, check=True)


def require_running_tpms(
    compose: list[str], *, root: Path, environment: dict[str, str]
) -> None:
    result = subprocess.run(
        [*compose, "ps", "--services", "--status", "running"],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    running = set(result.stdout.splitlines())
    missing = [service for service in TPM_IDS if service not in running]
    if missing:
        raise RuntimeError(
            "M5 will not start or restart attested TPM services. "
            f"Missing running services: {missing}. Start them first, then issue fresh "
            "M4 challenges/quotes and verification before retrying M5."
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=("build", "prepare", "clients", "aggregate", "verify", "run", "stop"),
    )
    parser.add_argument("--compose", type=Path, default=Path("compose.m5.yaml"))
    parser.add_argument(
        "--partition-workspace",
        type=Path,
        default=Path("artifacts/m3-data24-parquet-iid"),
    )
    parser.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m5-secure-round")
    )
    parser.add_argument(
        "--trust-workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    parser.add_argument("--node-root", type=Path, default=Path("artifacts/m4-nodes"))
    parser.add_argument("--workers", type=int, default=4)
    arguments = parser.parse_args()
    root = arguments.compose.resolve().parent
    partition = arguments.partition_workspace.resolve()
    workspace = arguments.workspace.resolve()
    trust_workspace = arguments.trust_workspace.resolve()
    node_root = arguments.node_root.resolve()
    compose = ["docker", "compose", "-f", str(arguments.compose.resolve())]
    environment = os.environ.copy()
    environment.update(
        {
            "M5_UID": str(os.getuid()),
            "M5_GID": str(os.getgid()),
            "M5_PARTITION_WORKSPACE": str(partition),
            "M5_WORKSPACE": str(workspace),
            "M4_TRUST_WORKSPACE": str(trust_workspace),
            "M4_NODE_ROOT": str(node_root),
        }
    )

    if arguments.action == "stop":
        run([*compose, "down"], root=root, environment=environment)
        return 0
    build_command = [
        *compose,
        "--profile",
        "coordinator",
        "build",
        "coordinator",
    ]
    if arguments.action == "build":
        run(build_command, root=root, environment=environment)
        return 0
    if not (partition / "manifest.json").is_file():
        raise FileNotFoundError(f"missing M3 partition manifest: {partition / 'manifest.json'}")
    if not (trust_workspace / "registry" / "index.json").is_file():
        raise FileNotFoundError("missing M4 trust registry; complete M4 enrollment first")
    missing_nodes = [
        client_id for client_id in CLIENT_IDS if not (node_root / client_id).is_dir()
    ]
    if missing_nodes:
        raise FileNotFoundError(f"missing M4 node workspaces: {missing_nodes}")
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "submissions").mkdir(parents=True, exist_ok=True)
    for client_id in CLIENT_IDS:
        (workspace / "submissions" / client_id).mkdir(parents=True, exist_ok=True)

    if arguments.action in {"prepare", "run"}:
        run(build_command, root=root, environment=environment)
        require_running_tpms(compose, root=root, environment=environment)
        run(
            [*compose, "--profile", "coordinator", "run", "--rm", "coordinator"],
            root=root,
            environment=environment,
        )

    if arguments.action in {"clients", "run"}:
        require_running_tpms(compose, root=root, environment=environment)

        def launch(client_id: str) -> None:
            run(
                [
                    *compose,
                    "--profile",
                    "secure-round",
                    "run",
                    "--rm",
                    client_id,
                ],
                root=root,
                environment=environment,
            )

        with ThreadPoolExecutor(max_workers=max(1, arguments.workers)) as executor:
            list(executor.map(launch, CLIENT_IDS))

    if arguments.action in {"aggregate", "run"}:
        run(
            [
                *compose,
                "--profile",
                "coordinator",
                "run",
                "--rm",
                "coordinator",
                "m5-admit-aggregate",
                "--workspace",
                "/campaign",
                "--trust-workspace",
                "/trust",
                "--submissions",
                "/submissions",
            ],
            root=root,
            environment=environment,
        )

    if arguments.action in {"verify", "run"}:
        run(
            [
                *compose,
                "--profile",
                "coordinator",
                "run",
                "--rm",
                "coordinator",
                "m5-verify",
                "--workspace",
                "/campaign",
                "--trust-workspace",
                "/trust",
                "--submissions",
                "/submissions",
            ],
            root=root,
            environment=environment,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
