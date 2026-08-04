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
    result = train_central_baseline(
        workspace=arguments.workspace,
        output=arguments.output,
        config_path=arguments.config,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
