"""Run or resume a chained 15-client M5 secure federated campaign."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
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
            "The secure campaign never starts or resets TPM state. "
            f"Start the existing M5 TPM services first; missing: {missing}"
        )


def refresh_attestations(
    *,
    root: Path,
    environment: dict[str, str],
    trust_workspace: Path,
    node_root: Path,
    compose_m4: Path,
) -> None:
    run(
        [
            "fl-forensics",
            "m4-challenge",
            "--workspace",
            str(trust_workspace),
            "--node-root",
            str(node_root),
        ],
        root=root,
        environment=environment,
    )
    run(
        [
            sys.executable,
            str(root / "scripts" / "run_m4_swtpm.py"),
            "quote",
            "--compose",
            str(compose_m4),
            "--trust-workspace",
            str(trust_workspace),
            "--node-root",
            str(node_root),
        ],
        root=root,
        environment=environment,
    )
    run(
        [
            "docker",
            "compose",
            "-f",
            str(compose_m4),
            "--profile",
            "verify",
            "run",
            "--rm",
            "verifier",
        ],
        root=root,
        environment=environment,
    )


def _campaign_id(first_round: Path) -> str:
    context = json.loads(
        (first_round / "public" / "round-context.json").read_text(encoding="utf-8")
    )
    return str(context["core"]["campaign_id"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "verify", "stop"))
    parser.add_argument("--compose", type=Path, default=Path("compose.m5.yaml"))
    parser.add_argument("--compose-m4", type=Path, default=Path("compose.m4.yaml"))
    parser.add_argument(
        "--partition-workspace",
        type=Path,
        default=Path("artifacts/m3-data24-parquet-iid"),
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("artifacts/m5-secure-multiround"),
    )
    parser.add_argument(
        "--trust-workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    parser.add_argument("--node-root", type=Path, default=Path("artifacts/m4-nodes"))
    parser.add_argument("--rounds", type=int, default=30)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--attestation-refresh-interval",
        type=int,
        default=5,
        help="issue fresh M4 evidence before round 1 and then every N rounds; 0 disables",
    )
    arguments = parser.parse_args()
    if arguments.rounds < 1:
        raise ValueError("--rounds must be positive")
    if arguments.attestation_refresh_interval < 0:
        raise ValueError("--attestation-refresh-interval cannot be negative")

    root = arguments.compose.resolve().parent
    compose_path = arguments.compose.resolve()
    compose_m4 = arguments.compose_m4.resolve()
    partition = arguments.partition_workspace.resolve()
    campaign = arguments.workspace.resolve()
    trust_workspace = arguments.trust_workspace.resolve()
    node_root = arguments.node_root.resolve()
    compose = ["docker", "compose", "-f", str(compose_path)]
    environment = os.environ.copy()
    environment.update(
        {
            "M5_UID": str(os.getuid()),
            "M5_GID": str(os.getgid()),
            "M4_UID": str(os.getuid()),
            "M4_GID": str(os.getgid()),
            "M5_PARTITION_WORKSPACE": str(partition),
            "M5_COORDINATOR_WORKSPACE": str(campaign),
            "M4_TRUST_WORKSPACE": str(trust_workspace),
            "M4_NODE_ROOT": str(node_root),
        }
    )
    if arguments.action == "stop":
        run([*compose, "down"], root=root, environment=environment)
        return 0
    for required in (
        partition / "manifest.json",
        partition / "server" / "evaluation.json",
        trust_workspace / "registry" / "index.json",
    ):
        if not required.is_file():
            raise FileNotFoundError(f"required campaign input is missing: {required}")
    missing_nodes = [
        client_id for client_id in CLIENT_IDS if not (node_root / client_id).is_dir()
    ]
    if missing_nodes:
        raise FileNotFoundError(f"missing M4 node workspaces: {missing_nodes}")

    build_command = [
        *compose,
        "--profile",
        "coordinator",
        "build",
        "coordinator",
    ]
    run(build_command, root=root, environment=environment)
    require_running_tpms(compose, root=root, environment=environment)

    if arguments.action == "run":
        campaign.mkdir(parents=True, exist_ok=True)
        for round_number in range(1, arguments.rounds + 1):
            round_workspace = campaign / "rounds" / f"round-{round_number:03d}"
            checkpoint_path = round_workspace / "checkpoint" / "manifest.json"
            environment["M5_WORKSPACE"] = str(round_workspace)
            if checkpoint_path.is_file():
                print(f"round {round_number:03d}: checkpoint exists; verifying", flush=True)
            else:
                context_path = round_workspace / "public" / "round-context.json"
                if not context_path.is_file():
                    interval = arguments.attestation_refresh_interval
                    if interval and (round_number - 1) % interval == 0:
                        refresh_attestations(
                            root=root,
                            environment=environment,
                            trust_workspace=trust_workspace,
                            node_root=node_root,
                            compose_m4=compose_m4,
                        )
                    for client_id in CLIENT_IDS:
                        (
                            round_workspace / "submissions" / client_id
                        ).mkdir(parents=True, exist_ok=True)
                    init_command = [
                        *compose,
                        "--profile",
                        "coordinator",
                        "run",
                        "--rm",
                        "coordinator",
                        "m5-init",
                        "--workspace",
                        "/campaign",
                        "--coordinator-workspace",
                        "/coordinator",
                        "--trust-workspace",
                        "/trust",
                        "--partition-manifest",
                        "/partition/manifest.json",
                        "--config",
                        "/app/configs/federation.yaml",
                        "--secure-config",
                        "/app/configs/secure-round.yaml",
                        "--round-number",
                        str(round_number),
                    ]
                    if round_number > 1:
                        init_command.extend(
                            [
                                "--campaign-id",
                                _campaign_id(campaign / "rounds" / "round-001"),
                                "--previous-round-workspace",
                                f"/coordinator/rounds/round-{round_number - 1:03d}",
                            ]
                        )
                    run(init_command, root=root, environment=environment)

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

                with ThreadPoolExecutor(
                    max_workers=max(1, arguments.workers)
                ) as executor:
                    list(executor.map(launch, CLIENT_IDS))
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
                        "--coordinator-workspace",
                        "/coordinator",
                        "--trust-workspace",
                        "/trust",
                        "--submissions",
                        "/submissions",
                    ],
                    root=root,
                    environment=environment,
                )
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
            print(f"round {round_number:03d}/{arguments.rounds:03d}: verified", flush=True)

        environment["M5_WORKSPACE"] = str(
            campaign / "rounds" / f"round-{arguments.rounds:03d}"
        )
        if not (campaign / "campaign-manifest.json").is_file():
            run(
                [
                    *compose,
                    "--profile",
                    "finalize",
                    "run",
                    "--rm",
                    "finalizer",
                    "m5-finalize-campaign",
                    "--workspace",
                    "/coordinator",
                    "--trust-workspace",
                    "/trust",
                    "--partition-manifest",
                    "/partition/manifest.json",
                    "--server-evaluation",
                    "/partition/server/evaluation.json",
                    "--rounds",
                    str(arguments.rounds),
                ],
                root=root,
                environment=environment,
            )

    final_round = campaign / "rounds" / f"round-{arguments.rounds:03d}"
    environment["M5_WORKSPACE"] = str(final_round)
    run(
        [
            *compose,
            "--profile",
            "finalize",
            "run",
            "--rm",
            "finalizer",
            "m5-verify-campaign",
            "--workspace",
            "/coordinator",
            "--trust-workspace",
            "/trust",
            "--partition-manifest",
            "/partition/manifest.json",
            "--server-evaluation",
            "/partition/server/evaluation.json",
        ],
        root=root,
        environment=environment,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
