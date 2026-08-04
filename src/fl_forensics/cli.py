"""Command-line interface for incremental experimental milestones."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

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
    result = verify_workspace(arguments.workspace)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())

