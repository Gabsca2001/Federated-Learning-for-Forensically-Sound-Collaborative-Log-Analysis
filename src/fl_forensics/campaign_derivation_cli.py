"""CLI for a pinned multiround graph and its structural blast radius."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .campaign_derivation import (
    create_campaign_derivation,
    structural_blast_radius,
    structural_blast_radius_set,
    verify_campaign_derivation,
)
from .crypto import SoftwareECDSASigner, load_public_key


def add_campaign_graph_commands(subparsers: Any) -> None:
    for name in ("campaign-derive", "campaign-verify", "campaign-blast-radius"):
        command = subparsers.add_parser(
            name, help="pinned multiround dependencies; numerical effects require a replay"
        )
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--sources", type=Path, required=True)
        command.add_argument("--coordinator-public-key", type=Path, required=True)
        command.add_argument("--authority-public-key", type=Path, required=True)
        if name == "campaign-derive":
            command.add_argument("--authority-private-key", type=Path, required=True)
        else:
            command.add_argument("--expected-sha256", required=True)
        if name == "campaign-blast-radius":
            command.add_argument("--submission-id", action="append", required=True)
    for name in (
        "counterfactual-create",
        "counterfactual-verify",
        "retraining-create",
        "retraining-verify",
    ):
        command = subparsers.add_parser(
            name, help="separate experimental derivation; preserve historical artifacts"
        )
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--authority-public-key", type=Path, required=True)
        command.add_argument("--validation-split", type=Path, required=True)
        if name.endswith("create"):
            command.add_argument("--authority-private-key", type=Path, required=True)
        else:
            command.add_argument("--expected-sha256", required=True)
        if name.startswith("counterfactual"):
            command.add_argument("--round-workspace", type=Path, required=True)
            command.add_argument("--submissions", type=Path, required=True)
            command.add_argument("--coordinator-public-key", type=Path, required=True)
            if name.endswith("create"):
                command.add_argument("--expected-source-manifest-sha256", required=True)
                command.add_argument(
                    "--mode", choices=("frozen_decisions", "rescore_round"), required=True
                )
                command.add_argument("--remove-submission-id", action="append", default=[])
        else:
            command.add_argument("--base-model", type=Path, required=True)
            command.add_argument("--partition-workspace", type=Path, required=True)
            if name.endswith("create"):
                command.add_argument("--plan", type=Path, required=True)
                command.add_argument("--expected-base-sha256", required=True)
                command.add_argument("--expected-partition-sha256", required=True)
                command.add_argument("--expected-validation-sha256", required=True)


def run_campaign_graph_command(arguments: Any) -> tuple[dict[str, Any], int]:
    try:
        if arguments.command.startswith(("counterfactual-", "retraining-")):
            report = _run_intervention(arguments)
            return report, int(report["status"] == "failed")
        spec = json.loads(arguments.sources.read_bytes())
        if set(spec) != {"rounds", "products"}:
            raise ValueError("source spec must contain rounds and products")
        sources = {}
        for name in ("rounds", "products"):
            locations = {}
            for item in spec[name]:
                if set(item) != {"manifest_sha256", "workspace"}:
                    raise ValueError("source location requires manifest_sha256 and workspace")
                digest = item["manifest_sha256"]
                if digest in locations:
                    raise ValueError("duplicate source manifest pin")
                path = Path(item["workspace"])
                locations[digest] = path if path.is_absolute() else arguments.sources.parent / path
            sources[name] = locations
        common = {
            "round_workspaces": sources["rounds"],
            "product_workspaces": sources["products"],
            "coordinator_public_key": load_public_key(
                arguments.coordinator_public_key.read_bytes()
            ),
            "authority_public_key": load_public_key(arguments.authority_public_key.read_bytes()),
        }
        if arguments.command == "campaign-derive":
            report = create_campaign_derivation(
                output=arguments.workspace,
                signer=SoftwareECDSASigner.load(arguments.authority_private_key),
                **common,
            )
        elif arguments.command == "campaign-verify":
            report = verify_campaign_derivation(
                workspace=arguments.workspace, expected_sha256=arguments.expected_sha256, **common
            )
        else:
            selection = arguments.submission_id
            query = structural_blast_radius if len(selection) == 1 else structural_blast_radius_set
            query_args = (
                {"submission_id": selection[0]}
                if len(selection) == 1
                else {"submission_ids": selection}
            )
            report = query(
                workspace=arguments.workspace,
                expected_sha256=arguments.expected_sha256,
                **query_args,
                **common,
            )
        return report, int(report["status"] == "failed")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ArithmeticError) as exc:
        return {"status": "failed", "errors": [str(exc)]}, 1


def _run_intervention(arguments: Any) -> dict[str, Any]:
    common = {
        "authority_public_key": load_public_key(arguments.authority_public_key.read_bytes()),
        "validation_split_path": arguments.validation_split,
    }
    if arguments.command.startswith("counterfactual-"):
        from .counterfactual_round import create_counterfactual_round, verify_counterfactual_round

        common.update(
            round_workspace=arguments.round_workspace,
            submissions_root=arguments.submissions,
            coordinator_public_key=load_public_key(arguments.coordinator_public_key.read_bytes()),
        )
        if arguments.command.endswith("create"):
            return create_counterfactual_round(
                **common,
                output=arguments.workspace,
                expected_source_manifest_sha256=arguments.expected_source_manifest_sha256,
                mode=arguments.mode,
                removed_submission_ids=arguments.remove_submission_id,
                signer=SoftwareECDSASigner.load(arguments.authority_private_key),
            )
        return verify_counterfactual_round(
            **common, workspace=arguments.workspace, expected_sha256=arguments.expected_sha256
        )
    from .retraining_replay import (
        RetrainingPlan,
        create_retraining_replay,
        verify_retraining_replay,
    )

    common.update(
        base_model_path=arguments.base_model, partition_workspace=arguments.partition_workspace
    )
    if arguments.command.endswith("create"):
        return create_retraining_replay(
            **common,
            output=arguments.workspace,
            plan=RetrainingPlan.model_validate_json(arguments.plan.read_bytes()),
            expected_base_sha256=arguments.expected_base_sha256,
            expected_partition_sha256=arguments.expected_partition_sha256,
            expected_validation_sha256=arguments.expected_validation_sha256,
            signer=SoftwareECDSASigner.load(arguments.authority_private_key),
        )
    return verify_retraining_replay(
        **common, workspace=arguments.workspace, expected_sha256=arguments.expected_sha256
    )
