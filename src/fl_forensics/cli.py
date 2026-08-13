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
from .tpm_adapter import (
    create_tpm_quote_evidence,
    physical_tpm_preflight,
    provision_tpm_node,
    verify_tpm2_quote,
)
from .trust import (
    enroll_nodes,
    initialize_trust_workspace,
    issue_challenges,
    revoke_enrollment,
    test_mtls_bindings,
    verify_attestation_campaign,
)
from .trust_deployment import verify_m4_deployment
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

    m4_deployment = subparsers.add_parser(
        "m4-verify-deployment",
        help="verify the one-to-one 15 client/swtpm Compose topology",
    )
    m4_deployment.add_argument(
        "--compose", type=Path, default=Path("compose.m4.yaml")
    )
    m4_deployment.add_argument(
        "--clients", type=Path, default=Path("configs/clients.yaml")
    )

    m4_init = subparsers.add_parser(
        "m4-init", help="initialize M4 authorities, PKI, and approved PCR baseline"
    )
    m4_init.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    m4_init.add_argument("--project-root", type=Path, default=Path("."))
    m4_init.add_argument(
        "--config", type=Path, default=Path("configs/trust.yaml")
    )
    m4_init.add_argument(
        "--clients", type=Path, default=Path("configs/clients.yaml")
    )

    m4_provision = subparsers.add_parser(
        "m4-tpm-provision", help="provision EK/AK/ESK and create a signed enrollment request"
    )
    m4_provision.add_argument("--workspace", type=Path, required=True)
    m4_provision.add_argument("--project-root", type=Path, required=True)
    m4_provision.add_argument(
        "--config", type=Path, default=Path("configs/trust.yaml")
    )
    m4_provision.add_argument("--client-id", required=True)
    m4_provision.add_argument("--node-id", required=True)
    m4_provision.add_argument("--tpm-instance", required=True)
    m4_provision.add_argument("--tcti", required=True)
    m4_provision.add_argument("--trust-level", choices=("swtpm", "tpm2"), required=True)

    m4_enroll = subparsers.add_parser(
        "m4-enroll", help="validate and sign all M4 enrollment requests"
    )
    m4_enroll.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    m4_enroll.add_argument(
        "--node-root", type=Path, default=Path("artifacts/m4-nodes")
    )
    m4_enroll.add_argument(
        "--config", type=Path, default=Path("configs/trust.yaml")
    )
    m4_enroll.add_argument(
        "--clients", type=Path, default=Path("configs/clients.yaml")
    )

    m4_challenge = subparsers.add_parser(
        "m4-challenge", help="issue signed, short-lived, one-use attestation challenges"
    )
    m4_challenge.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    m4_challenge.add_argument(
        "--node-root", type=Path, default=Path("artifacts/m4-nodes")
    )
    m4_challenge.add_argument(
        "--config", type=Path, default=Path("configs/trust.yaml")
    )

    m4_quote = subparsers.add_parser(
        "m4-tpm-quote", help="produce Quote evidence with the enrolled AK"
    )
    m4_quote.add_argument("--workspace", type=Path, required=True)
    m4_quote.add_argument("--tcti", required=True)

    m4_verify = subparsers.add_parser(
        "m4-verify-attestations",
        help="verify and preserve all Quote appraisal results",
    )
    m4_verify.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    m4_verify.add_argument(
        "--node-root", type=Path, default=Path("artifacts/m4-nodes")
    )

    m4_mtls = subparsers.add_parser(
        "m4-mtls-test", help="exercise TLS 1.3 mutual authentication for all enrolled clients"
    )
    m4_mtls.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    m4_mtls.add_argument(
        "--node-root", type=Path, default=Path("artifacts/m4-nodes")
    )

    m4_revoke = subparsers.add_parser(
        "m4-revoke", help="append a signed enrollment revocation"
    )
    m4_revoke.add_argument(
        "--workspace", type=Path, default=Path("artifacts/m4-trust")
    )
    m4_revoke.add_argument("--client-id", required=True)
    m4_revoke.add_argument("--reason", required=True)

    m4_physical = subparsers.add_parser(
        "m4-physical-preflight", help="check the physical TPM adapter without changing TPM state"
    )
    m4_physical.add_argument("--tcti", default="device:/dev/tpmrm0")
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
    if arguments.command == "m3-verify":
        result = verify_federated_baseline(
            workspace=arguments.workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m4-verify-deployment":
        result = verify_m4_deployment(
            compose_path=arguments.compose, clients_config_path=arguments.clients
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m4-init":
        result = initialize_trust_workspace(
            workspace=arguments.workspace,
            project_root=arguments.project_root,
            trust_config_path=arguments.config,
            clients_config_path=arguments.clients,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m4-tpm-provision":
        result = provision_tpm_node(
            node_workspace=arguments.workspace,
            project_root=arguments.project_root,
            trust_config_path=arguments.config,
            client_id=arguments.client_id,
            node_id=arguments.node_id,
            tpm_instance_id=arguments.tpm_instance,
            tcti=arguments.tcti,
            trust_level=arguments.trust_level,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m4-enroll":
        result = enroll_nodes(
            workspace=arguments.workspace,
            node_root=arguments.node_root,
            trust_config_path=arguments.config,
            clients_config_path=arguments.clients,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "enrolled" else 1
    if arguments.command == "m4-challenge":
        result = issue_challenges(
            workspace=arguments.workspace,
            node_root=arguments.node_root,
            trust_config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m4-tpm-quote":
        result = create_tpm_quote_evidence(
            node_workspace=arguments.workspace, tcti=arguments.tcti
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m4-verify-attestations":
        result = verify_attestation_campaign(
            workspace=arguments.workspace,
            node_root=arguments.node_root,
            quote_verifier=verify_tpm2_quote,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m4-mtls-test":
        result = test_mtls_bindings(
            workspace=arguments.workspace, node_root=arguments.node_root
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m4-revoke":
        result = revoke_enrollment(
            workspace=arguments.workspace,
            client_id=arguments.client_id,
            reason=arguments.reason,
        )
        print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    result = physical_tpm_preflight(tcti=arguments.tcti)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
