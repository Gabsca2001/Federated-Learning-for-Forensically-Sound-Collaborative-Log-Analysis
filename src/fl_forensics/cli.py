"""Command-line interface for incremental experimental milestones."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .central_baseline import train_central_baseline, verify_central_baseline
from .config import load_yaml
from .dataset24 import prepare_dataset, write_audit
from .dataset24 import verify_workspace as verify_m2_workspace
from .demo import run_demo
from .federated_partitioning import prepare_partitions, verify_partitions
from .federated_training import run_federated_baseline, verify_federated_baseline
from .reporting import generate_m3_report
from .verification import verify_workspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fl-forensics")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="run the phase-1 evidence vertical slice")
    demo.add_argument("--input", type=Path, required=True, help="Zeek JSONL file")
    demo.add_argument("--output", type=Path, required=True, help="new output directory")
    demo.add_argument(
        "--config",
        type=Path,
        default=Path("configs/base.yaml"),
        help="base YAML configuration",
    )

    verify = subparsers.add_parser("verify", help="verify a phase-1 workspace read-only")
    verify.add_argument("--workspace", type=Path, required=True)

    m2_audit = subparsers.add_parser(
        "m2-audit", help="audit the controlled-ingestion UWF-ZeekData24 CSV release"
    )
    m2_audit.add_argument(
        "--input",
        type=Path,
        default=Path("data/raw/uwf-zeekdata24/csv"),
        help="Data24 CSV root containing download_manifest.json",
    )
    m2_audit.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/m2-data24-audit.json"),
    )

    m2_prepare = subparsers.add_parser(
        "m2-prepare", help="build the deterministic Data24 M2 feature snapshot"
    )
    m2_prepare.add_argument(
        "--input",
        type=Path,
        default=Path("data/raw/uwf-zeekdata24/csv"),
    )
    m2_prepare.add_argument(
        "--output", type=Path, default=Path("artifacts/m2-data24")
    )
    m2_prepare.add_argument(
        "--config", type=Path, default=Path("configs/base.yaml")
    )

    m2_verify = subparsers.add_parser(
        "m2-verify", help="verify an M2 Data24 workspace read-only"
    )
    m2_verify.add_argument("--workspace", type=Path, required=True)

    m2_train = subparsers.add_parser(
        "m2-train", help="train and evaluate the centralized MLP baseline"
    )
    m2_train.add_argument("--workspace", type=Path, required=True)
    m2_train.add_argument(
        "--output", type=Path, default=Path("artifacts/m2-data24-central")
    )
    m2_train.add_argument(
        "--config", type=Path, default=Path("configs/base.yaml")
    )

    m2_verify_baseline = subparsers.add_parser(
        "m2-verify-baseline",
        help="verify baseline outputs and their referenced M2 dataset inputs",
    )
    m2_verify_baseline.add_argument("--workspace", type=Path, required=True)
    m2_verify_baseline.add_argument(
        "--dataset-workspace", type=Path, required=True
    )

    m3_partition = subparsers.add_parser(
        "m3-partition", help="prepare deterministic IID or non-IID Data24 client snapshots"
    )
    m3_partition.add_argument("--dataset-workspace", type=Path, required=True)
    m3_partition.add_argument("--output", type=Path, required=True)
    m3_partition.add_argument("--mode", choices=("iid", "non-iid"), required=True)
    m3_partition.add_argument(
        "--config", type=Path, default=Path("configs/federation.yaml")
    )

    m3_verify_partitions = subparsers.add_parser(
        "m3-verify-partitions", help="verify M3 client snapshots and their M2 lineage"
    )
    m3_verify_partitions.add_argument("--workspace", type=Path, required=True)
    m3_verify_partitions.add_argument("--dataset-workspace", type=Path, required=True)

    m3_train = subparsers.add_parser(
        "m3-train", help="run the auditable 15-client PyTorch/Flower FedAvg baseline"
    )
    m3_train.add_argument("--partition-workspace", type=Path, required=True)
    m3_train.add_argument("--dataset-workspace", type=Path, required=True)
    m3_train.add_argument("--output", type=Path, required=True)
    m3_train.add_argument(
        "--config", type=Path, default=Path("configs/federation.yaml")
    )

    m3_verify = subparsers.add_parser(
        "m3-verify", help="verify the M3 round chain, updates, checkpoints, and FedAvg"
    )
    m3_verify.add_argument("--workspace", type=Path, required=True)
    m3_verify.add_argument("--partition-workspace", type=Path, required=True)
    m3_verify.add_argument("--dataset-workspace", type=Path, required=True)

    m3_report = subparsers.add_parser(
        "m3-report", help="generate deterministic plots from an M3 metrics workspace"
    )
    m3_report.add_argument("--workspace", type=Path, required=True)
    m3_report.add_argument(
        "--output",
        type=Path,
        help="report directory; defaults to <workspace>/reports",
    )
    m3_report.add_argument(
        "--central-workspace",
        type=Path,
        help="optional verified M2 centralized baseline for the comparison chart",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "demo":
        result = run_demo(
            input_path=arguments.input,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "verify":
        result = verify_workspace(arguments.workspace)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m2-audit":
        result = write_audit(arguments.input, arguments.output)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m2-prepare":
        config, _digest = load_yaml(arguments.config)
        result = prepare_dataset(
            source_root=arguments.input,
            output=arguments.output,
            preprocessing_config=config["preprocessing"],
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m2-verify":
        result = verify_m2_workspace(arguments.workspace)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m2-verify-baseline":
        result = verify_central_baseline(
            workspace=arguments.workspace,
            dataset_workspace=arguments.dataset_workspace,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m2-train":
        result = train_central_baseline(
            workspace=arguments.workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m3-partition":
        result = prepare_partitions(
            dataset_workspace=arguments.dataset_workspace,
            output=arguments.output,
            mode=arguments.mode,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m3-verify-partitions":
        result = verify_partitions(
            workspace=arguments.workspace,
            dataset_workspace=arguments.dataset_workspace,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m3-train":
        result = run_federated_baseline(
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m3-report":
        result = generate_m3_report(
            workspace=arguments.workspace,
            output=arguments.output,
            central_workspace=arguments.central_workspace,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    result = verify_federated_baseline(
        workspace=arguments.workspace,
        partition_workspace=arguments.partition_workspace,
        dataset_workspace=arguments.dataset_workspace,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
