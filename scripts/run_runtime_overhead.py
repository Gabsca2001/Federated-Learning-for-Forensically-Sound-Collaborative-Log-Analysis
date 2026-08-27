#!/usr/bin/env python3
"""Run fresh, isolated M4/M5 runtime-overhead trials under Docker Compose."""

from __future__ import annotations

import argparse
import json
import os
import resource
import subprocess
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from fl_forensics.canonical import sha256_bytes
from fl_forensics.runtime_overhead import (
    RUNTIME_STAGE_IDS,
    SPAN_STAGE_IDS,
    RuntimeOverheadError,
    create_runtime_overhead_receipt,
    load_runtime_overhead_contract,
    project_root,
    resolve_contract_path,
    runtime_environment,
)
from fl_forensics.storage import utc_now, write_once

CLIENT_IDS = [f"client{index:02d}" for index in range(1, 16)]
TPM_IDS = [f"tpm{index:02d}" for index in range(1, 16)]


def _cpu_time_ns() -> int:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    children = usage.ru_utime + usage.ru_stime
    return time.process_time_ns() + round(children * 1_000_000_000)


def _last_json_object(output: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    starts = [index for index, value in enumerate(output) if value == "{"]
    for start in reversed(starts):
        try:
            value, end = decoder.raw_decode(output[start:])
        except json.JSONDecodeError:
            continue
        if not output[start + end :].strip() and isinstance(value, dict):
            return value
    raise RuntimeOverheadError("command output does not end with a JSON object")


class CommandExecutor:
    def __init__(self, *, root: Path, environment: dict[str, str], logs: Path) -> None:
        self.root = root
        self.environment = environment
        self.logs = logs

    def run(self, name: str, command: list[str]) -> dict[str, Any]:
        print(f"[runtime-overhead] command: {name}", flush=True)
        result = subprocess.run(
            command,
            cwd=self.root,
            env=self.environment,
            check=False,
            capture_output=True,
            text=True,
        )
        document = {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        write_once(
            self.logs / f"{name}.json",
            (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(),
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"runtime command failed ({name}): {detail}")
        return _last_json_object(result.stdout)

    def run_no_json(self, name: str, command: list[str]) -> None:
        print(f"[runtime-overhead] command: {name}", flush=True)
        result = subprocess.run(
            command,
            cwd=self.root,
            env=self.environment,
            check=False,
            capture_output=True,
            text=True,
        )
        document = {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        write_once(
            self.logs / f"{name}.json",
            (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(),
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"runtime command failed ({name}): {detail}")


def _measure(
    stage_id: str,
    operation: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    print(f"[runtime-overhead] starting {stage_id}", flush=True)
    wall_start = time.perf_counter_ns()
    cpu_start = _cpu_time_ns()
    outcome = operation()
    cpu_time = _cpu_time_ns() - cpu_start
    wall_time = time.perf_counter_ns() - wall_start
    print(
        f"[runtime-overhead] completed {stage_id} "
        f"({wall_time / 1_000_000_000:.3f} s)",
        flush=True,
    )
    return {
        "stage_id": stage_id,
        "wall_time_ns": wall_time,
        "cpu_time_ns": cpu_time,
        "outcome": outcome,
    }


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError as exc:
        raise RuntimeOverheadError(f"workspace escapes project root: {path}") from exc


def _compose_environment(
    *,
    root: Path,
    namespace: str,
    trust_workspace: Path,
    node_root: Path,
    partition: Path,
    round_workspace: Path,
    coordinator_workspace: Path,
) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "COMPOSE_PROJECT_NAME": namespace,
            "M4_UID": str(os.getuid()),
            "M4_GID": str(os.getgid()),
            "M5_UID": str(os.getuid()),
            "M5_GID": str(os.getgid()),
            "M4_TRUST_WORKSPACE": str(trust_workspace),
            "M4_NODE_ROOT": str(node_root),
            "M5_PARTITION_WORKSPACE": str(partition),
            "M5_WORKSPACE": str(round_workspace),
            "M5_COORDINATOR_WORKSPACE": str(coordinator_workspace),
            "PYTHONPATH": str(root / "src"),
        }
    )
    return environment


def _build_images(
    *,
    root: Path,
    compose_m4: Path,
    compose_m5: Path,
    environment: dict[str, str],
    logs: Path,
) -> None:
    executor = CommandExecutor(root=root, environment=environment, logs=logs)
    executor.run_no_json(
        "prebuild-m4-runtime-image",
        [
            "docker",
            "compose",
            "-f",
            str(compose_m4),
            "--profile",
            "provision",
            "--profile",
            "verify",
            "build",
        ],
    )
    executor.run_no_json(
        "prebuild-m5-runtime-image",
        [
            "docker",
            "compose",
            "-f",
            str(compose_m5),
            "--profile",
            "coordinator",
            "build",
            "coordinator",
        ],
    )


def _docker_environment(root: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    image = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            "flforensics-m5-runtime:latest",
            "--format",
            "{{.Id}}",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        "docker_server_version": result.stdout.strip(),
        "m5_runtime_image_id": image.stdout.strip(),
    }


def _run_trial(
    *,
    trial_index: int,
    root: Path,
    contract: dict[str, Any],
    compose_m4: Path,
    compose_m5: Path,
    partition: Path,
    work_root: Path,
) -> dict[str, Any]:
    namespace = f"{contract['project_namespace']}_{trial_index:03d}"
    trial_root = work_root / f"trial-{trial_index:03d}"
    trust_workspace = trial_root / "m4-trust"
    node_root = trial_root / "m4-nodes"
    round_workspace = trial_root / "m5-secure-round"
    coordinator_workspace = trial_root / "m5-coordinator"
    logs = trial_root / "logs"
    for path in (logs, round_workspace / "submissions", coordinator_workspace):
        path.mkdir(parents=True, exist_ok=True)
    for client_id in CLIENT_IDS:
        (round_workspace / "submissions" / client_id).mkdir(parents=True, exist_ok=True)

    environment = _compose_environment(
        root=root,
        namespace=namespace,
        trust_workspace=trust_workspace,
        node_root=node_root,
        partition=partition,
        round_workspace=round_workspace,
        coordinator_workspace=coordinator_workspace,
    )
    executor = CommandExecutor(root=root, environment=environment, logs=logs)
    python = sys.executable
    cli = [python, "-m", "fl_forensics.cli"]
    compose4 = ["docker", "compose", "-f", str(compose_m4)]
    compose5 = ["docker", "compose", "-f", str(compose_m5)]
    trust_config = resolve_contract_path(root, contract["trust_config"])
    clients_config = resolve_contract_path(root, contract["clients_config"])

    # Compose image names are project-scoped for M4. Build once per fresh namespace,
    # deliberately before starting the timed lifecycle.
    _build_images(
        root=root,
        compose_m4=compose_m4,
        compose_m5=compose_m5,
        environment=environment,
        logs=logs,
    )

    stages: list[dict[str, Any]] = []
    try:
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[0],
                lambda: executor.run(
                    "m4-init",
                    [
                        *cli,
                        "m4-init",
                        "--workspace",
                        str(trust_workspace),
                        "--project-root",
                        str(root),
                        "--config",
                        str(trust_config),
                        "--clients",
                        str(clients_config),
                    ],
                ),
            )
        )

        def provision() -> dict[str, Any]:
            executor.run_no_json(
                "m4-provision",
                [
                    python,
                    str(root / "scripts" / "run_m4_swtpm.py"),
                    "provision",
                    "--skip-build",
                    "--compose",
                    str(compose_m4),
                    "--trust-workspace",
                    str(trust_workspace),
                    "--node-root",
                    str(node_root),
                ],
            )
            count = sum(
                (node_root / client_id / "provisioning_summary.json").is_file()
                for client_id in CLIENT_IDS
            )
            return {"status": "provisioned", "client_count": count}

        stages.append(_measure(RUNTIME_STAGE_IDS[1], provision))
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[2],
                lambda: executor.run(
                    "m4-enroll",
                    [
                        *cli,
                        "m4-enroll",
                        "--workspace",
                        str(trust_workspace),
                        "--node-root",
                        str(node_root),
                        "--config",
                        str(trust_config),
                        "--clients",
                        str(clients_config),
                    ],
                ),
            )
        )
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[3],
                lambda: executor.run(
                    "m4-mtls",
                    [
                        *cli,
                        "m4-mtls-test",
                        "--workspace",
                        str(trust_workspace),
                        "--node-root",
                        str(node_root),
                    ],
                ),
            )
        )

        probe = contract["tpm_sign_probe"]
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[4],
                lambda: executor.run(
                    "m4-esk-sign-probe",
                    [
                        *compose4,
                        "--profile",
                        "provision",
                        "run",
                        "--rm",
                        "client01",
                        "runtime-tpm-sign-probe",
                        "--node-workspace",
                        "/runtime",
                        "--tcti",
                        "swtpm:path=/run/swtpm/swtpm.sock",
                        "--warmup-runs",
                        str(probe["warmup_runs"]),
                        "--repetitions",
                        str(probe["repetitions"]),
                    ],
                ),
            )
        )
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[5],
                lambda: executor.run(
                    "m4-challenge",
                    [
                        *cli,
                        "m4-challenge",
                        "--workspace",
                        str(trust_workspace),
                        "--node-root",
                        str(node_root),
                        "--config",
                        str(trust_config),
                    ],
                ),
            )
        )

        def quote() -> dict[str, Any]:
            executor.run_no_json(
                "m4-quote",
                [
                    python,
                    str(root / "scripts" / "run_m4_swtpm.py"),
                    "quote",
                    "--compose",
                    str(compose_m4),
                    "--trust-workspace",
                    str(trust_workspace),
                    "--node-root",
                    str(node_root),
                ],
            )
            count = sum(
                (node_root / client_id / "quote_evidence.json").is_file()
                for client_id in CLIENT_IDS
            )
            return {"status": "quoted", "client_count": count}

        stages.append(_measure(RUNTIME_STAGE_IDS[6], quote))
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[7],
                lambda: executor.run(
                    "m4-appraise",
                    [
                        *compose4,
                        "--profile",
                        "verify",
                        "run",
                        "--rm",
                        "verifier",
                    ],
                ),
            )
        )
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[8],
                lambda: executor.run(
                    "m5-context",
                    [
                        *compose5,
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
                    ],
                ),
            )
        )

        def clients() -> dict[str, Any]:
            def launch(client_id: str) -> dict[str, Any]:
                return executor.run(
                    f"m5-client-{client_id}",
                    [
                        *compose5,
                        "--profile",
                        "secure-round",
                        "run",
                        "--rm",
                        client_id,
                    ],
                )

            with ThreadPoolExecutor(max_workers=int(contract["workers"])) as pool:
                results = list(pool.map(launch, CLIENT_IDS))
            submitted = sum(item.get("status") == "submitted" for item in results)
            signed = sum(
                (round_workspace / "submissions" / client_id / "bundle.json").is_file()
                for client_id in CLIENT_IDS
            )
            return {
                "status": "submitted",
                "client_count": len(results),
                "submitted_count": submitted,
                "tpm_signed_bundle_count": signed,
                "workers": int(contract["workers"]),
            }

        stages.append(_measure(RUNTIME_STAGE_IDS[9], clients))
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[10],
                lambda: executor.run(
                    "m5-aggregate",
                    [
                        *compose5,
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
                ),
            )
        )
        stages.append(
            _measure(
                RUNTIME_STAGE_IDS[11],
                lambda: executor.run(
                    "m5-verify",
                    [
                        *compose5,
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
                ),
            )
        )
    finally:
        subprocess.run(
            [*compose4, "down"],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    if [item["stage_id"] for item in stages] != list(RUNTIME_STAGE_IDS):
        raise RuntimeOverheadError("runtime trial did not complete every required stage")
    spans = {
        name: sum(
            int(stage["wall_time_ns"])
            for stage in stages
            if stage["stage_id"] in stage_ids
        )
        for name, stage_ids in SPAN_STAGE_IDS.items()
    }
    spans["measured-total"] = sum(int(stage["wall_time_ns"]) for stage in stages)
    return {
        "trial_index": trial_index,
        "compose_project": namespace,
        "workspaces": {
            "trust_workspace": _relative(trust_workspace, root),
            "node_root": _relative(node_root, root),
            "round_workspace": _relative(round_workspace, root),
            "coordinator_workspace": _relative(coordinator_workspace, root),
        },
        "stage_order_sha256": sha256_bytes("\n".join(RUNTIME_STAGE_IDS).encode()),
        "stages": stages,
        "spans": spans,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "build", "run"))
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/runtime-overhead-local-test-v1.yaml"),
    )
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    contract, _digest = load_runtime_overhead_contract(arguments.config)
    root = project_root(arguments.config, contract)
    compose_m4 = resolve_contract_path(root, contract["compose_m4"])
    compose_m5 = resolve_contract_path(root, contract["compose_m5"])
    partition = resolve_contract_path(root, contract["partition_workspace"])
    work_root = resolve_contract_path(root, contract["work_root"])
    if not (partition / "manifest.json").is_file():
        raise FileNotFoundError(f"partition manifest is missing: {partition}")

    if arguments.action == "plan":
        trials = [
            {
                "trial_index": index,
                "compose_project": f"{contract['project_namespace']}_{index:03d}",
                "workspace": _relative(work_root / f"trial-{index:03d}", root),
            }
            for index in range(1, int(contract["repetitions"]) + 1)
        ]
        print(
            json.dumps(
                {
                    "status": "planned",
                    "benchmark_id": contract["benchmark_id"],
                    "trial_count": len(trials),
                    "stage_count_per_trial": len(RUNTIME_STAGE_IDS),
                    "stage_order": list(RUNTIME_STAGE_IDS),
                    "trials": trials,
                    "docker_image_build_timed": False,
                    "docker_volumes_deleted": False,
                    "canonical_reference_workspaces_modified": False,
                    "submission_transport": "isolated-bind-mounted-directories",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if arguments.action == "build":
        build_logs = root / "artifacts" / "runtime-overhead-build-logs"
        build_logs.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment["COMPOSE_PROJECT_NAME"] = f"{contract['project_namespace']}_build"
        _build_images(
            root=root,
            compose_m4=compose_m4,
            compose_m5=compose_m5,
            environment=environment,
            logs=build_logs,
        )
        print(json.dumps({"status": "built", "workspace": str(build_logs)}, indent=2))
        return 0

    if arguments.output is None:
        parser.error("--output is required for the run action")
    output = arguments.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeOverheadError(f"runtime receipt output must be new or empty: {output}")
    if work_root.exists() and any(work_root.iterdir()):
        raise RuntimeOverheadError(f"runtime work root must be new or empty: {work_root}")
    work_root.mkdir(parents=True, exist_ok=True)

    started_at = utc_now()
    trials = []
    for trial_index in range(1, int(contract["repetitions"]) + 1):
        print(
            f"[runtime-overhead] trial {trial_index}/{contract['repetitions']}",
            flush=True,
        )
        trials.append(
            _run_trial(
                trial_index=trial_index,
                root=root,
                contract=contract,
                compose_m4=compose_m4,
                compose_m5=compose_m5,
                partition=partition,
                work_root=work_root,
            )
        )
    completed_at = utc_now()
    environment = {**runtime_environment(), **_docker_environment(root)}
    result = create_runtime_overhead_receipt(
        output=output,
        config_path=arguments.config,
        trials=trials,
        environment=environment,
        started_at=started_at,
        completed_at=completed_at,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
