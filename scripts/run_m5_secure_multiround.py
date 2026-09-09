"""Run or resume a chained 15-client M5 secure federated campaign."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fl_forensics.real_attestation_failure import (
    build_real_attestation_failure_contract,
)

CLIENT_IDS = [f"client{index:02d}" for index in range(1, 16)]
TPM_IDS = [f"tpm{index:02d}" for index in range(1, 16)]


def run(command: list[str], *, root: Path, environment: dict[str, str]) -> None:
    print(" ".join(command), flush=True)
    subprocess.run(command, cwd=root, env=environment, check=True)


def run_expected_exit(
    command: list[str],
    *,
    root: Path,
    environment: dict[str, str],
    expected_exit: int,
) -> None:
    print(" ".join(command), flush=True)
    result = subprocess.run(command, cwd=root, env=environment, check=False)
    if result.returncode != expected_exit:
        raise RuntimeError(
            f"command returned {result.returncode}; expected {expected_exit}: "
            f"{' '.join(command)}"
        )


def _latest_attestation_result(trust_workspace: Path, client_id: str) -> Path:
    candidates: list[tuple[str, Path]] = []
    for path in (trust_workspace / "results").glob("attestation-*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        core = value.get("core", {})
        if core.get("client_id") == client_id:
            candidates.append((str(core.get("evaluated_at", "")), path))
    if not candidates:
        raise RuntimeError(f"no attestation result exists for {client_id}")
    return max(candidates, key=lambda item: item[0])[1]


def _copy_once_or_verify(source: Path, target: Path) -> None:
    payload = source.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file():
        if target.read_bytes() != payload:
            raise RuntimeError(f"preserved experiment evidence changed: {target}")
        return
    with target.open("xb") as stream:
        stream.write(payload)


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


def execute_real_attestation_failure(
    *,
    root: Path,
    environment: dict[str, str],
    compose: list[str],
    compose_m4: Path,
    trust_workspace: Path,
    node_root: Path,
    round_workspace: Path,
    round_number: int,
    contract,
) -> None:
    """Create one authentic post-training failed Quote and rebind its probe."""

    target = contract.core.target_client_id
    event_id = (
        f"{contract.core.experiment_id}-round-{round_number:03d}-{target}"
    )
    evidence_root = round_workspace / "real-attestation-evidence"
    preserved_result = evidence_root / "attestation-result.json"
    preserved_paths = (
        evidence_root / "pcr-mutation.json",
        evidence_root / "quote-evidence.json",
        preserved_result,
    )
    if all(path.is_file() for path in preserved_paths):
        transport_result = (
            node_root / target / "post-training-attestation-result.json"
        )
        transport_result.write_bytes(preserved_result.read_bytes())
        run(
            [
                *compose,
                "--profile",
                "secure-round",
                "run",
                "--rm",
                target,
                "m5-refresh-bundle-attestation",
                "--public-workspace",
                "/campaign/public",
                "--node-workspace",
                "/runtime",
                "--submission-workspace",
                "/submission",
                "--attestation-result",
                "/runtime/post-training-attestation-result.json",
                "--client-id",
                target,
                "--tcti",
                "swtpm:path=/run/swtpm/swtpm.sock",
            ],
            root=root,
            environment=environment,
        )
        return
    if any(path.exists() for path in preserved_paths):
        raise RuntimeError(
            "real-attestation evidence is incomplete; preserve or remove the "
            "unfinished round before resuming"
        )
    run(
        [
            sys.executable,
            str(root / "scripts" / "run_m4_swtpm.py"),
            "extend",
            "--compose",
            str(compose_m4),
            "--trust-workspace",
            str(trust_workspace),
            "--node-root",
            str(node_root),
            "--client-id",
            target,
            "--pcr-index",
            str(contract.core.pcr_index),
            "--measurement-sha256",
            contract.core.measurement_sha256,
            "--event-id",
            event_id,
        ],
        root=root,
        environment=environment,
    )
    run(
        [
            "fl-forensics",
            "m4-challenge",
            "--workspace",
            str(trust_workspace),
            "--node-root",
            str(node_root),
            "--client-id",
            target,
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
            "--client-id",
            target,
        ],
        root=root,
        environment=environment,
    )
    run_expected_exit(
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
        expected_exit=1,
    )
    result_path = _latest_attestation_result(trust_workspace, target)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("core", {}).get("status") != contract.core.expected_post_status:
        raise RuntimeError(
            "real PCR mutation did not produce the expected failed_measurement appraisal"
        )
    transport_result = node_root / target / "post-training-attestation-result.json"
    transport_result.write_bytes(result_path.read_bytes())
    _copy_once_or_verify(
        node_root / target / "quote_evidence.json",
        evidence_root / "quote-evidence.json",
    )
    _copy_once_or_verify(
        node_root / target / "pcr-mutations" / f"{event_id}.json",
        evidence_root / "pcr-mutation.json",
    )
    _copy_once_or_verify(
        result_path,
        evidence_root / "attestation-result.json",
    )
    run(
        [
            *compose,
            "--profile",
            "secure-round",
            "run",
            "--rm",
            target,
            "m5-refresh-bundle-attestation",
            "--public-workspace",
            "/campaign/public",
            "--node-workspace",
            "/runtime",
            "--submission-workspace",
            "/submission",
            "--attestation-result",
            "/runtime/post-training-attestation-result.json",
            "--client-id",
            target,
            "--tcti",
            "swtpm:path=/run/swtpm/swtpm.sock",
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
        "--in-round-admission-config",
        type=Path,
        help=(
            "enable trust/statistical admission before every aggregation using "
            "a configuration copied into the runtime image"
        ),
    )
    parser.add_argument(
        "--disagreement-experiment-config",
        type=Path,
        help=(
            "bind controlled M6 trust/statistical disagreement treatments "
            "before local training"
        ),
    )
    parser.add_argument(
        "--real-attestation-failure-config",
        type=Path,
        help=(
            "perform the bound real PCR/Quote failure after local training in "
            "the configured round"
        ),
    )
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
    in_round_config = (
        arguments.in_round_admission_config.resolve()
        if arguments.in_round_admission_config is not None
        else None
    )
    in_round_container_config: str | None = None
    if in_round_config is not None:
        if not in_round_config.is_file():
            raise FileNotFoundError(
                f"in-round admission configuration is missing: {in_round_config}"
            )
        try:
            relative_config = in_round_config.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                "in-round admission configuration must be inside the project root"
            ) from exc
        in_round_container_config = f"/app/{relative_config.as_posix()}"
    disagreement_config = (
        arguments.disagreement_experiment_config.resolve()
        if arguments.disagreement_experiment_config is not None
        else None
    )
    disagreement_container_config: str | None = None
    if disagreement_config is not None:
        if in_round_config is None:
            raise ValueError(
                "--disagreement-experiment-config requires "
                "--in-round-admission-config"
            )
        if not disagreement_config.is_file():
            raise FileNotFoundError(
                f"disagreement experiment configuration is missing: "
                f"{disagreement_config}"
            )
        try:
            relative_disagreement = disagreement_config.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                "disagreement experiment configuration must be inside "
                "the project root"
            ) from exc
        disagreement_container_config = (
            f"/app/{relative_disagreement.as_posix()}"
        )
    real_failure_config = (
        arguments.real_attestation_failure_config.resolve()
        if arguments.real_attestation_failure_config is not None
        else None
    )
    real_failure_container_config: str | None = None
    real_failure_contract = None
    if real_failure_config is not None:
        if in_round_config is None:
            raise ValueError(
                "--real-attestation-failure-config requires "
                "--in-round-admission-config"
            )
        if disagreement_config is not None:
            raise ValueError(
                "real and controlled trust-failure experiments require separate campaigns"
            )
        if not real_failure_config.is_file():
            raise FileNotFoundError(
                f"real attestation-failure configuration is missing: "
                f"{real_failure_config}"
            )
        try:
            relative_real_failure = real_failure_config.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                "real attestation-failure configuration must be inside "
                "the project root"
            ) from exc
        real_failure_container_config = (
            f"/app/{relative_real_failure.as_posix()}"
        )
        real_failure_contract = build_real_attestation_failure_contract(
            config_path=real_failure_config,
            client_ids=CLIENT_IDS,
        )
        if any(item > arguments.rounds for item in real_failure_contract.core.active_rounds):
            raise ValueError(
                "real attestation-failure active round exceeds --rounds"
            )
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
    if in_round_config is not None:
        validation_path = partition / "server" / "splits" / "validation.json"
        if not validation_path.is_file():
            raise FileNotFoundError(
                f"isolated validation split is missing: {validation_path}"
            )
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

    def verify_disagreement_round(round_workspace: Path) -> None:
        environment["M5_WORKSPACE"] = str(round_workspace)
        run(
            [
                *compose,
                "--profile",
                "coordinator",
                "run",
                "--rm",
                "coordinator",
                "m6-verify-live-disagreement-round",
                "--workspace",
                "/campaign",
                "--trust-workspace",
                "/trust",
                "--submissions",
                "/submissions",
                "--validation-split",
                "/partition/server/splits/validation.json",
            ],
            root=root,
            environment=environment,
        )

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
                    if in_round_container_config is not None:
                        init_command.extend(
                            [
                                "--in-round-admission-config",
                                in_round_container_config,
                            ]
                        )
                    if disagreement_container_config is not None:
                        init_command.extend(
                            [
                                "--disagreement-experiment-config",
                                disagreement_container_config,
                            ]
                        )
                    if real_failure_container_config is not None:
                        init_command.extend(
                            [
                                "--real-attestation-failure-config",
                                real_failure_container_config,
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
                if (
                    real_failure_contract is not None
                    and round_number in real_failure_contract.core.active_rounds
                ):
                    execute_real_attestation_failure(
                        root=root,
                        environment=environment,
                        compose=compose,
                        compose_m4=compose_m4,
                        trust_workspace=trust_workspace,
                        node_root=node_root,
                        round_workspace=round_workspace,
                        round_number=round_number,
                        contract=real_failure_contract,
                    )
                aggregate_command = [
                    *compose,
                    "--profile",
                    "coordinator",
                    "run",
                    "--rm",
                    "coordinator",
                    (
                        "m5-admit-composite-aggregate"
                        if in_round_config is not None
                        else "m5-admit-aggregate"
                    ),
                    "--workspace",
                    "/campaign",
                    "--coordinator-workspace",
                    "/coordinator",
                    "--trust-workspace",
                    "/trust",
                    "--submissions",
                    "/submissions",
                ]
                if in_round_config is not None:
                    aggregate_command.extend(
                        [
                            "--validation-split",
                            "/partition/server/splits/validation.json",
                        ]
                    )
                run(
                    aggregate_command,
                    root=root,
                    environment=environment,
                )
            verify_command = [
                *compose,
                "--profile",
                "coordinator",
                "run",
                "--rm",
                "coordinator",
                (
                    "m5-verify-composite-round"
                    if in_round_config is not None
                    else "m5-verify"
                ),
                "--workspace",
                "/campaign",
                "--trust-workspace",
                "/trust",
                "--submissions",
                "/submissions",
            ]
            if in_round_config is not None:
                verify_command.extend(
                    [
                        "--validation-split",
                        "/partition/server/splits/validation.json",
                    ]
                )
            run(
                verify_command,
                root=root,
                environment=environment,
            )
            if disagreement_container_config is not None:
                verify_disagreement_round(round_workspace)
            if (
                real_failure_contract is not None
                and round_number in real_failure_contract.core.active_rounds
            ):
                run(
                    [
                        *compose,
                        "--profile",
                        "coordinator",
                        "run",
                        "--rm",
                        "coordinator",
                        "m6-verify-real-attestation-failure-round",
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

    elif disagreement_container_config is not None:
        for round_number in range(1, arguments.rounds + 1):
            round_workspace = campaign / "rounds" / f"round-{round_number:03d}"
            if not (round_workspace / "checkpoint" / "manifest.json").is_file():
                raise FileNotFoundError(
                    f"required disagreement round is missing: {round_workspace}"
                )
            verify_disagreement_round(round_workspace)
            print(
                f"round {round_number:03d}/{arguments.rounds:03d}: "
                "M6 disagreement verified",
                flush=True,
            )
    elif real_failure_contract is not None:
        for round_number in real_failure_contract.core.active_rounds:
            round_workspace = campaign / "rounds" / f"round-{round_number:03d}"
            if not (round_workspace / "checkpoint" / "manifest.json").is_file():
                raise FileNotFoundError(
                    f"required real-attestation round is missing: {round_workspace}"
                )
            environment["M5_WORKSPACE"] = str(round_workspace)
            run(
                [
                    *compose,
                    "--profile",
                    "coordinator",
                    "run",
                    "--rm",
                    "coordinator",
                    "m6-verify-real-attestation-failure-round",
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
