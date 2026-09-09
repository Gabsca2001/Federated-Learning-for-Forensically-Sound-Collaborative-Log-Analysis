#!/usr/bin/env python3
"""Run the authentic post-training TPM failure through the M5/M6 runtime."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "verify", "stop"))
    parser.add_argument("--compose", type=Path, default=Path("compose.m5.yaml"))
    parser.add_argument("--compose-m4", type=Path, default=Path("compose.m4.yaml"))
    parser.add_argument(
        "--partition-workspace",
        type=Path,
        default=Path("artifacts/m3-data24-parquet-iid-local-test-v1"),
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path("artifacts/m6-real-attestation-failure-local-test-v1"),
    )
    parser.add_argument(
        "--trust-workspace",
        type=Path,
        default=Path("artifacts/m4-trust-real-attestation-failure-v1"),
    )
    parser.add_argument(
        "--node-root",
        type=Path,
        default=Path("artifacts/m4-nodes-real-attestation-failure-v1"),
    )
    parser.add_argument(
        "--admission-config",
        type=Path,
        default=Path("configs/in-round-admission.yaml"),
    )
    parser.add_argument(
        "--experiment-config",
        type=Path,
        default=Path("configs/real-attestation-failure.yaml"),
    )
    parser.add_argument("--rounds", type=int, default=30)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--attestation-refresh-interval", type=int, default=5)
    arguments = parser.parse_args()

    root = arguments.compose.resolve().parent
    command = [
        sys.executable,
        str(root / "scripts" / "run_m5_secure_multiround.py"),
        arguments.action,
        "--compose",
        str(arguments.compose),
        "--compose-m4",
        str(arguments.compose_m4),
        "--partition-workspace",
        str(arguments.partition_workspace),
        "--workspace",
        str(arguments.workspace),
        "--trust-workspace",
        str(arguments.trust_workspace),
        "--node-root",
        str(arguments.node_root),
        "--in-round-admission-config",
        str(arguments.admission_config),
        "--real-attestation-failure-config",
        str(arguments.experiment_config),
        "--rounds",
        str(arguments.rounds),
        "--workers",
        str(arguments.workers),
        "--attestation-refresh-interval",
        str(arguments.attestation_refresh_interval),
    ]
    subprocess.run(command, cwd=root, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
