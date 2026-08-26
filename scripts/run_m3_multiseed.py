"""Plan, run, or verify repeated IID/non-IID M3 FedAvg experiments."""

from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml

from fl_forensics.canonical import sha256_bytes, sha256_file
from fl_forensics.multiseed import load_multiseed_contract
from fl_forensics.preprocessing import derived_json_bytes


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write_or_require_equal(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content:
            raise FileExistsError(f"existing protected file differs: {path}")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _persist_plan_file(path: Path, content: bytes, *, create: bool) -> None:
    if create:
        _write_or_require_equal(path, content)
        return
    if not path.is_file():
        raise FileNotFoundError(f"required execution-plan file is missing: {path}")
    if path.read_bytes() != content:
        raise ValueError(f"execution-plan file differs from the contract: {path}")


def _run(command: list[str], *, root: Path, timing_path: Path | None) -> None:
    print(" ".join(command), flush=True)
    started_at = _utc_now()
    started = time.perf_counter()
    subprocess.run(command, cwd=root, check=True)
    elapsed = time.perf_counter() - started
    finished_at = _utc_now()
    if timing_path is not None:
        receipt = {
            "schema_version": "1.0",
            "artifact_type": "m3_multiseed_stage_timing",
            "command": command,
            "started_at": started_at,
            "finished_at": finished_at,
            "wall_seconds": elapsed,
        }
        _write_or_require_equal(timing_path, derived_json_bytes(receipt))
    print(f"completed in {elapsed:.3f} seconds", flush=True)


def _workspace_state(path: Path) -> str:
    if (path / "manifest.json").is_file():
        return "complete"
    if path.exists() and any(path.iterdir()):
        return "partial"
    return "absent"


def _generated_config(base: dict, *, seed: int, device: str) -> bytes:
    generated = copy.deepcopy(base)
    generated["partitioning"]["seed"] = seed
    generated["training"]["seed"] = seed
    generated["training"]["device"] = device
    return yaml.safe_dump(generated, sort_keys=False).encode("utf-8")


def _selected(values: list, requested: list | None, *, label: str) -> list:
    if requested is None:
        return list(values)
    unexpected = sorted(set(requested) - set(values))
    if unexpected:
        raise ValueError(f"unknown {label} values: {unexpected}")
    return [value for value in values if value in requested]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "run", "verify"))
    parser.add_argument(
        "--config", type=Path, default=Path("configs/m3-multiseed.yaml")
    )
    parser.add_argument(
        "--dataset-workspace",
        type=Path,
        default=Path("artifacts/m2-data24-parquet"),
    )
    parser.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m3-multiseed-v1")
    )
    parser.add_argument("--seed", action="append", type=int)
    parser.add_argument("--mode", action="append", choices=("iid", "non-iid"))
    parser.add_argument(
        "--report",
        action="store_true",
        help="also generate the full per-run M3 figure bundle",
    )
    arguments = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    config_path = (root / arguments.config).resolve()
    dataset_workspace = (root / arguments.dataset_workspace).resolve()
    runs_workspace = (root / arguments.workspace).resolve()
    contract, contract_sha256 = load_multiseed_contract(config_path)
    base_config_path = (root / contract["base_federation_config"]).resolve()
    base = yaml.safe_load(base_config_path.read_bytes())
    if not isinstance(base, dict):
        raise TypeError("base federation configuration must be an object")
    if not (dataset_workspace / "manifest.json").is_file():
        raise FileNotFoundError("M2 dataset workspace is missing manifest.json")

    seeds = _selected(contract["seeds"], arguments.seed, label="seed")
    modes = _selected(contract["modes"], arguments.mode, label="mode")
    device = str(contract["execution"]["device"])
    create_plan = arguments.action != "verify"
    config_records = []
    for seed in contract["seeds"]:
        content = _generated_config(base, seed=int(seed), device=device)
        generated_path = runs_workspace / "configs" / f"federation-seed-{seed}.yaml"
        _persist_plan_file(
            generated_path,
            content,
            create=create_plan,
        )
        config_records.append(
            {
                "seed": int(seed),
                "path": generated_path.relative_to(runs_workspace).as_posix(),
                "sha256": sha256_bytes(content),
            }
        )
    plan = {
        "schema_version": "1.0",
        "artifact_type": "m3_multiseed_execution_plan",
        "experiment_id": contract["experiment_id"],
        "contract_sha256": contract_sha256,
        "base_federation_config": contract["base_federation_config"],
        "base_federation_config_sha256": sha256_file(base_config_path),
        "dataset_manifest_sha256": sha256_file(dataset_workspace / "manifest.json"),
        "device": device,
        "seeds": contract["seeds"],
        "modes": contract["modes"],
        "generated_configs": config_records,
        "workspace_layout": "seed-<seed>/<mode>/{partition,run,report}",
    }
    _persist_plan_file(
        runs_workspace / "plan.json",
        derived_json_bytes(plan),
        create=create_plan,
    )
    if arguments.action == "plan":
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    python_cli = [sys.executable, "-m", "fl_forensics.cli"]
    for seed in seeds:
        generated_config = runs_workspace / "configs" / f"federation-seed-{seed}.yaml"
        for mode in modes:
            base_path = runs_workspace / f"seed-{seed}" / mode
            partition_workspace = base_path / "partition"
            run_workspace = base_path / "run"
            timing_root = runs_workspace / "timings" / f"seed-{seed}" / mode

            partition_state = _workspace_state(partition_workspace)
            if partition_state == "partial":
                raise RuntimeError(
                    f"partial partition workspace requires investigation: {partition_workspace}"
                )
            if arguments.action == "run" and partition_state == "absent":
                _run(
                    [
                        *python_cli,
                        "m3-partition",
                        "--dataset-workspace",
                        str(dataset_workspace),
                        "--output",
                        str(partition_workspace),
                        "--mode",
                        mode,
                        "--config",
                        str(generated_config),
                    ],
                    root=root,
                    timing_path=timing_root / "partition-create.json",
                )
            if _workspace_state(partition_workspace) != "complete":
                raise FileNotFoundError(f"partition workspace is absent: {partition_workspace}")
            _run(
                [
                    *python_cli,
                    "m3-verify-partitions",
                    "--workspace",
                    str(partition_workspace),
                    "--dataset-workspace",
                    str(dataset_workspace),
                ],
                root=root,
                timing_path=(
                    timing_root / "partition-verify.json"
                    if arguments.action == "run"
                    and not (timing_root / "partition-verify.json").exists()
                    else None
                ),
            )

            run_state = _workspace_state(run_workspace)
            if run_state == "partial":
                raise RuntimeError(
                    f"partial training workspace requires investigation: {run_workspace}"
                )
            if arguments.action == "run" and run_state == "absent":
                _run(
                    [
                        *python_cli,
                        "m3-train",
                        "--partition-workspace",
                        str(partition_workspace),
                        "--dataset-workspace",
                        str(dataset_workspace),
                        "--output",
                        str(run_workspace),
                        "--config",
                        str(generated_config),
                    ],
                    root=root,
                    timing_path=timing_root / "training.json",
                )
            if _workspace_state(run_workspace) != "complete":
                raise FileNotFoundError(f"training workspace is absent: {run_workspace}")
            _run(
                [
                    *python_cli,
                    "m3-verify",
                    "--workspace",
                    str(run_workspace),
                    "--partition-workspace",
                    str(partition_workspace),
                    "--dataset-workspace",
                    str(dataset_workspace),
                ],
                root=root,
                timing_path=(
                    timing_root / "run-verify.json"
                    if arguments.action == "run"
                    and not (timing_root / "run-verify.json").exists()
                    else None
                ),
            )
            if arguments.action == "run" and arguments.report:
                report_workspace = base_path / "report"
                if _workspace_state(report_workspace) == "partial":
                    raise RuntimeError(
                        f"partial report workspace requires investigation: {report_workspace}"
                    )
                if _workspace_state(report_workspace) == "absent":
                    _run(
                        [
                            *python_cli,
                            "m3-report",
                            "--workspace",
                            str(run_workspace),
                            "--output",
                            str(report_workspace),
                        ],
                        root=root,
                        timing_path=timing_root / "report.json",
                    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
