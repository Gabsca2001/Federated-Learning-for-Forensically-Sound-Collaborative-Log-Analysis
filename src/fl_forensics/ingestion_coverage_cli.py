"""Commands for authenticated per-record coverage and transformation replay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import load_yaml
from .crypto import SoftwareECDSASigner, load_public_key
from .ingestion_coverage import create_ingestion_coverage, verify_ingestion_coverage


def add_ingestion_commands(subparsers: Any) -> None:
    for name in ("ingestion-create", "ingestion-verify"):
        command = subparsers.add_parser(
            name, help="per-record coverage relative to pinned input bytes"
        )
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--authority-public-key", type=Path, required=True)
        if name == "ingestion-create":
            command.add_argument("--source", type=Path, required=True)
            command.add_argument(
                "--profile",
                choices=("zeek-jsonl-v1", "data24-csv-v1", "data24-parquet-v1"),
                required=True,
            )
            command.add_argument("--expected-source-sha256", required=True)
            command.add_argument("--config", type=Path, required=True)
            command.add_argument("--authority-private-key", type=Path, required=True)
        else:
            command.add_argument("--expected-inventory-sha256", required=True)
            command.add_argument("--expected-manifest-sha256", required=True)


def run_ingestion_command(arguments: Any) -> tuple[dict[str, Any], int]:
    try:
        common = {
            "authority_public_key": load_public_key(arguments.authority_public_key.read_bytes())
        }
        if arguments.command == "ingestion-create":
            config, _ = load_yaml(arguments.config)
            result = create_ingestion_coverage(
                output=arguments.workspace,
                source=arguments.source,
                profile=arguments.profile,
                expected_source_sha256=arguments.expected_source_sha256,
                preprocessing_config=dict(config.get("preprocessing", config)),
                signer=SoftwareECDSASigner.load(arguments.authority_private_key),
                **common,
            )
        else:
            result = verify_ingestion_coverage(
                workspace=arguments.workspace,
                expected_inventory_sha256=arguments.expected_inventory_sha256,
                expected_manifest_sha256=arguments.expected_manifest_sha256,
                **common,
            )
        return result, int(result["status"] == "failed")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return {"status": "failed", "errors": [str(exc)]}, 1
