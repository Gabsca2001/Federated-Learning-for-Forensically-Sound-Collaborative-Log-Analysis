"""Command-line interface for incremental experimental milestones."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .attack_mapping import (
    create_attack_mapping_bundle,
    verify_attack_mapping_bundle,
)
from .byzantine_experiment import (
    freeze_byzantine_scenario,
    run_byzantine_comparison,
    verify_byzantine_comparison,
    verify_frozen_update_set,
)
from .central_baseline import train_central_baseline, verify_central_baseline
from .config import load_yaml
from .dataset24 import prepare_dataset, write_audit
from .dataset24 import verify_workspace as verify_m2_workspace
from .demo import run_demo
from .explanation_bundle import create_explanation_bundle, verify_explanation_bundle
from .federated_partitioning import prepare_partitions, verify_partitions
from .federated_training import run_federated_baseline, verify_federated_baseline
from .investigation_report import (
    create_investigation_report_bundle,
    verify_investigation_report_bundle,
)
from .merkle import create_merkle_tree, verify_merkle_tree
from .prediction_bundle import create_prediction_bundle, verify_prediction_bundle
from .preservation import (
    create_preservation_manifest,
    verify_preservation_manifest,
)
from .protean_finalization import (
    finalize_protean_endpoints,
    verify_protean_finalization,
)
from .protean_reporting import (
    generate_protean_validation_report,
    verify_protean_validation_report,
)
from .protean_selection_lock import (
    create_protean_selection_lock,
    verify_protean_selection_lock,
)
from .protean_training import (
    run_protean_candidate,
    verify_protean_candidate,
)
from .prototype_experiment import (
    freeze_prototype_scenario,
    run_prototype_comparison,
    verify_frozen_prototype_scenario,
    verify_prototype_comparison,
)
from .prototype_sensitivity import (
    plan_prototype_sensitivity,
    run_prototype_sensitivity,
    verify_prototype_sensitivity,
)
from .prototype_sensitivity_reporting import (
    generate_prototype_sensitivity_report,
    verify_prototype_sensitivity_report,
)
from .recovery import create_recovery_export, verify_recovery_export
from .reporting import generate_m3_report
from .secure_campaign import finalize_secure_campaign, verify_secure_campaign
from .secure_round import (
    admit_and_aggregate,
    create_secure_update,
    initialize_secure_round,
    verify_secure_round,
)
from .timestamp_anchor import (
    create_timestamp_anchor,
    verify_timestamp_anchor,
)
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
        "m2-audit", help="audit a controlled-ingestion UWF-ZeekData24 release"
    )
    m2_audit.add_argument(
        "--input",
        type=Path,
        default=Path("data/raw/uwf-zeekdata24/csv"),
        help="Data24 CSV or Parquet root containing download_manifest.json",
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
        help="Data24 CSV or Parquet root containing download_manifest.json",
    )
    m2_prepare.add_argument(
        "--output", type=Path, default=Path("artifacts/m2-data24")
    )
    m2_prepare.add_argument(
        "--config",
        type=Path,
        default=Path("configs/base.yaml"),
        help="preprocessing configuration; use configs/m2-parquet.yaml for the Parquet experiment",
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

    m3_protean_train = subparsers.add_parser(
        "m3-protean-train",
        help="run one validation-only auditable PROTEAN lambda candidate",
    )
    m3_protean_train.add_argument("--partition-workspace", type=Path, required=True)
    m3_protean_train.add_argument("--dataset-workspace", type=Path, required=True)
    m3_protean_train.add_argument("--output", type=Path, required=True)
    m3_protean_train.add_argument(
        "--prototype-alignment-weight", type=float, required=True
    )
    m3_protean_train.add_argument("--device", choices=("cpu", "cuda"))
    m3_protean_train.add_argument(
        "--config", type=Path, default=Path("configs/federation-protean.yaml")
    )

    m3_protean_verify = subparsers.add_parser(
        "m3-protean-verify",
        help="verify a PROTEAN candidate without accessing test data",
    )
    m3_protean_verify.add_argument("--workspace", type=Path, required=True)
    m3_protean_verify.add_argument("--partition-workspace", type=Path, required=True)
    m3_protean_verify.add_argument("--dataset-workspace", type=Path, required=True)
    m3_protean_verify.add_argument(
        "--config", type=Path, default=Path("configs/federation-protean.yaml")
    )

    m3_protean_report = subparsers.add_parser(
        "m3-protean-report",
        help="select and plot verified PROTEAN candidates using validation only",
    )
    m3_protean_report.add_argument(
        "--candidate-workspace",
        action="append",
        type=Path,
        required=True,
        help="repeat once for every configured lambda candidate",
    )
    m3_protean_report.add_argument("--fedavg-workspace", type=Path, required=True)
    m3_protean_report.add_argument("--output", type=Path, required=True)
    m3_protean_report.add_argument(
        "--config", type=Path, default=Path("configs/federation-protean.yaml")
    )

    m3_protean_verify_report = subparsers.add_parser(
        "m3-protean-verify-report",
        help="rebuild and verify the complete validation-only PROTEAN report",
    )
    m3_protean_verify_report.add_argument(
        "--candidate-workspace", action="append", type=Path, required=True
    )
    m3_protean_verify_report.add_argument(
        "--fedavg-workspace", type=Path, required=True
    )
    m3_protean_verify_report.add_argument("--workspace", type=Path, required=True)
    m3_protean_verify_report.add_argument(
        "--config", type=Path, default=Path("configs/federation-protean.yaml")
    )

    m3_protean_lock = subparsers.add_parser(
        "m3-protean-lock",
        help="freeze paper-faithful and operational endpoints before test access",
    )
    m3_protean_lock.add_argument(
        "--candidate-workspace", action="append", type=Path, required=True
    )
    m3_protean_lock.add_argument("--fedavg-workspace", type=Path, required=True)
    m3_protean_lock.add_argument("--report-workspace", type=Path, required=True)
    m3_protean_lock.add_argument("--output", type=Path, required=True)
    m3_protean_lock.add_argument(
        "--config", type=Path, default=Path("configs/federation-protean.yaml")
    )

    m3_protean_verify_lock = subparsers.add_parser(
        "m3-protean-verify-lock",
        help="recreate and verify the PROTEAN pre-test selection lock",
    )
    m3_protean_verify_lock.add_argument(
        "--candidate-workspace", action="append", type=Path, required=True
    )
    m3_protean_verify_lock.add_argument(
        "--fedavg-workspace", type=Path, required=True
    )
    m3_protean_verify_lock.add_argument(
        "--report-workspace", type=Path, required=True
    )
    m3_protean_verify_lock.add_argument("--workspace", type=Path, required=True)
    m3_protean_verify_lock.add_argument(
        "--config", type=Path, default=Path("configs/federation-protean.yaml")
    )

    m3_protean_finalize = subparsers.add_parser(
        "m3-protean-finalize",
        help="evaluate the two locked PROTEAN endpoints once on final splits",
    )
    m3_protean_finalize.add_argument(
        "--candidate-workspace", action="append", type=Path, required=True
    )
    m3_protean_finalize.add_argument("--fedavg-workspace", type=Path, required=True)
    m3_protean_finalize.add_argument("--report-workspace", type=Path, required=True)
    m3_protean_finalize.add_argument(
        "--selection-lock-workspace", type=Path, required=True
    )
    m3_protean_finalize.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m3_protean_finalize.add_argument("--dataset-workspace", type=Path, required=True)
    m3_protean_finalize.add_argument("--output", type=Path, required=True)
    m3_protean_finalize.add_argument(
        "--config", type=Path, default=Path("configs/federation-protean.yaml")
    )

    m3_protean_verify_final = subparsers.add_parser(
        "m3-protean-verify-final",
        help="verify final PROTEAN evidence without rerunning model inference",
    )
    m3_protean_verify_final.add_argument(
        "--candidate-workspace", action="append", type=Path, required=True
    )
    m3_protean_verify_final.add_argument(
        "--fedavg-workspace", type=Path, required=True
    )
    m3_protean_verify_final.add_argument(
        "--report-workspace", type=Path, required=True
    )
    m3_protean_verify_final.add_argument(
        "--selection-lock-workspace", type=Path, required=True
    )
    m3_protean_verify_final.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m3_protean_verify_final.add_argument(
        "--dataset-workspace", type=Path, required=True
    )
    m3_protean_verify_final.add_argument("--workspace", type=Path, required=True)
    m3_protean_verify_final.add_argument(
        "--config", type=Path, default=Path("configs/federation-protean.yaml")
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

    m5_init = subparsers.add_parser(
        "m5-init", help="create an attestation-gated signed secure-round context"
    )
    m5_init.add_argument("--workspace", type=Path, required=True)
    m5_init.add_argument("--trust-workspace", type=Path, required=True)
    m5_init.add_argument("--partition-manifest", type=Path, required=True)
    m5_init.add_argument(
        "--config", type=Path, default=Path("configs/federation.yaml")
    )
    m5_init.add_argument(
        "--secure-config", type=Path, default=Path("configs/secure-round.yaml")
    )
    m5_init.add_argument(
        "--coordinator-workspace",
        type=Path,
        help="shared campaign workspace containing the coordinator authority",
    )
    m5_init.add_argument("--campaign-id")
    m5_init.add_argument("--round-number", type=int, default=1)
    m5_init.add_argument(
        "--previous-round-workspace",
        type=Path,
        help="verified previous round used to chain the next base model",
    )

    m5_client = subparsers.add_parser(
        "m5-client-update", help="train one isolated client and TPM-sign its Update Bundle"
    )
    m5_client.add_argument("--public-workspace", type=Path, required=True)
    m5_client.add_argument("--client-dataset", type=Path, required=True)
    m5_client.add_argument("--client-manifest", type=Path, required=True)
    m5_client.add_argument("--node-workspace", type=Path, required=True)
    m5_client.add_argument("--submission-workspace", type=Path, required=True)
    m5_client.add_argument("--client-id", required=True)
    m5_client.add_argument("--tcti", required=True)

    m5_aggregate = subparsers.add_parser(
        "m5-admit-aggregate", help="admit 15 bundles and create a signed FedAvg checkpoint"
    )
    m5_aggregate.add_argument("--workspace", type=Path, required=True)
    m5_aggregate.add_argument("--trust-workspace", type=Path, required=True)
    m5_aggregate.add_argument("--submissions", type=Path, required=True)
    m5_aggregate.add_argument(
        "--coordinator-workspace",
        type=Path,
        help="shared campaign workspace containing the coordinator authority",
    )

    m5_verify = subparsers.add_parser(
        "m5-verify", help="revalidate M5 inputs and independently recompute FedAvg"
    )
    m5_verify.add_argument("--workspace", type=Path, required=True)
    m5_verify.add_argument("--trust-workspace", type=Path, required=True)
    m5_verify.add_argument("--submissions", type=Path, required=True)

    m5_finalize = subparsers.add_parser(
        "m5-finalize-campaign",
        help="select a secure checkpoint on validation and evaluate the test split",
    )
    m5_finalize.add_argument("--workspace", type=Path, required=True)
    m5_finalize.add_argument("--trust-workspace", type=Path, required=True)
    m5_finalize.add_argument("--partition-manifest", type=Path, required=True)
    m5_finalize.add_argument("--server-evaluation", type=Path, required=True)
    m5_finalize.add_argument("--rounds", type=int, required=True)

    m5_verify_campaign = subparsers.add_parser(
        "m5-verify-campaign",
        help="verify every secure round, the checkpoint chain, and final selection",
    )
    m5_verify_campaign.add_argument("--workspace", type=Path, required=True)
    m5_verify_campaign.add_argument("--trust-workspace", type=Path, required=True)
    m5_verify_campaign.add_argument("--partition-manifest", type=Path, required=True)
    m5_verify_campaign.add_argument("--server-evaluation", type=Path, required=True)

    m6_freeze = subparsers.add_parser(
        "m6-freeze", help="freeze one deterministic attack set from a verified M5 round"
    )
    m6_freeze.add_argument("--source-round-workspace", type=Path, required=True)
    m6_freeze.add_argument("--trust-workspace", type=Path, required=True)
    m6_freeze.add_argument("--partition-workspace", type=Path, required=True)
    m6_freeze.add_argument("--output", type=Path, required=True)
    m6_freeze.add_argument(
        "--attack",
        choices=(
            "clean",
            "label_flip",
            "gaussian_noise",
            "sign_flip",
            "update_amplification",
            "model_replacement",
            "backdoor",
            "colluding",
        ),
        required=True,
    )
    m6_freeze.add_argument("--f", type=int, required=True)
    m6_freeze.add_argument(
        "--attacker-id",
        action="append",
        dest="attacker_ids",
        help="explicit attacker identity; repeat exactly f times",
    )
    m6_freeze.add_argument(
        "--config", type=Path, default=Path("configs/byzantine.yaml")
    )

    m6_verify_frozen = subparsers.add_parser(
        "m6-verify-frozen", help="verify every digest in a frozen M6 update set"
    )
    m6_verify_frozen.add_argument("--workspace", type=Path, required=True)

    m6_compare = subparsers.add_parser(
        "m6-compare", help="compare every M6 aggregator on one frozen update set"
    )
    m6_compare.add_argument("--frozen-workspace", type=Path, required=True)
    m6_compare.add_argument("--partition-workspace", type=Path, required=True)
    m6_compare.add_argument("--output", type=Path, required=True)
    m6_compare.add_argument(
        "--config", type=Path, default=Path("configs/byzantine.yaml")
    )

    m6_verify = subparsers.add_parser(
        "m6-verify", help="independently recompute an M6 aggregator comparison"
    )
    m6_verify.add_argument("--frozen-workspace", type=Path, required=True)
    m6_verify.add_argument("--partition-workspace", type=Path, required=True)
    m6_verify.add_argument("--workspace", type=Path, required=True)
    m6_verify.add_argument(
        "--config", type=Path, default=Path("configs/byzantine.yaml")
    )

    m6_prototype_freeze = subparsers.add_parser(
        "m6-prototype-freeze",
        help="freeze class prototypes from a verified M5 global checkpoint",
    )
    m6_prototype_freeze.add_argument(
        "--source-round-workspace", type=Path, required=True
    )
    m6_prototype_freeze.add_argument("--trust-workspace", type=Path, required=True)
    m6_prototype_freeze.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m6_prototype_freeze.add_argument("--output", type=Path, required=True)
    m6_prototype_freeze.add_argument("--f", type=int, required=True)
    m6_prototype_freeze.add_argument(
        "--attacker-id",
        action="append",
        dest="attacker_ids",
        help="explicit attacker identity; repeat exactly f times",
    )
    m6_prototype_freeze.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-poisoning.yaml"),
    )

    m6_prototype_verify_frozen = subparsers.add_parser(
        "m6-prototype-verify-frozen",
        help="re-extract and verify every frozen prototype submission",
    )
    m6_prototype_verify_frozen.add_argument("--workspace", type=Path, required=True)
    m6_prototype_verify_frozen.add_argument(
        "--source-round-workspace", type=Path, required=True
    )
    m6_prototype_verify_frozen.add_argument(
        "--trust-workspace", type=Path, required=True
    )
    m6_prototype_verify_frozen.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m6_prototype_verify_frozen.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-poisoning.yaml"),
    )

    m6_prototype_compare = subparsers.add_parser(
        "m6-prototype-compare",
        help="compare baseline and robust aggregation on frozen prototypes",
    )
    m6_prototype_compare.add_argument(
        "--frozen-workspace", type=Path, required=True
    )
    m6_prototype_compare.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m6_prototype_compare.add_argument("--output", type=Path, required=True)
    m6_prototype_compare.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-poisoning.yaml"),
    )

    m6_prototype_verify = subparsers.add_parser(
        "m6-prototype-verify",
        help="recompute and verify the M6 prototype comparison",
    )
    m6_prototype_verify.add_argument(
        "--frozen-workspace", type=Path, required=True
    )
    m6_prototype_verify.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m6_prototype_verify.add_argument("--workspace", type=Path, required=True)
    m6_prototype_verify.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-poisoning.yaml"),
    )

    m6_prototype_sensitivity_plan = subparsers.add_parser(
        "m6-prototype-sensitivity-plan",
        help="show the predeclared sensitivity cells without accessing data",
    )
    m6_prototype_sensitivity_plan.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-sensitivity.yaml"),
    )

    m6_prototype_sensitivity = subparsers.add_parser(
        "m6-prototype-sensitivity",
        help="run every predeclared exploratory prototype sensitivity scenario",
    )
    m6_prototype_sensitivity.add_argument(
        "--source-round-workspace", type=Path, required=True
    )
    m6_prototype_sensitivity.add_argument(
        "--trust-workspace", type=Path, required=True
    )
    m6_prototype_sensitivity.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m6_prototype_sensitivity.add_argument("--output", type=Path, required=True)
    m6_prototype_sensitivity.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-sensitivity.yaml"),
    )

    m6_prototype_verify_sensitivity = subparsers.add_parser(
        "m6-prototype-verify-sensitivity",
        help="recompute and verify every prototype sensitivity scenario",
    )
    m6_prototype_verify_sensitivity.add_argument(
        "--source-round-workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity.add_argument(
        "--trust-workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity.add_argument(
        "--workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-sensitivity.yaml"),
    )

    m6_prototype_sensitivity_report = subparsers.add_parser(
        "m6-prototype-sensitivity-report",
        help="render deterministic tables and curves from verified sensitivity evidence",
    )
    m6_prototype_sensitivity_report.add_argument(
        "--source-round-workspace", type=Path, required=True
    )
    m6_prototype_sensitivity_report.add_argument(
        "--trust-workspace", type=Path, required=True
    )
    m6_prototype_sensitivity_report.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m6_prototype_sensitivity_report.add_argument(
        "--sensitivity-workspace", type=Path, required=True
    )
    m6_prototype_sensitivity_report.add_argument("--output", type=Path, required=True)
    m6_prototype_sensitivity_report.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-sensitivity.yaml"),
    )

    m6_prototype_verify_sensitivity_report = subparsers.add_parser(
        "m6-prototype-verify-sensitivity-report",
        help="recompute and verify every M6 prototype sensitivity report artifact",
    )
    m6_prototype_verify_sensitivity_report.add_argument(
        "--source-round-workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity_report.add_argument(
        "--trust-workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity_report.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity_report.add_argument(
        "--sensitivity-workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity_report.add_argument(
        "--report-workspace", type=Path, required=True
    )
    m6_prototype_verify_sensitivity_report.add_argument(
        "--config",
        type=Path,
        default=Path("configs/byzantine-prototype-sensitivity.yaml"),
    )

    m7_predict = subparsers.add_parser(
        "m7-predict",
        help="create reportable predictions with complete Zeek-event lineage",
    )
    m7_predict.add_argument("--round-workspace", type=Path, required=True)
    m7_predict.add_argument("--trust-workspace", type=Path, required=True)
    m7_predict.add_argument("--partition-workspace", type=Path, required=True)
    m7_predict.add_argument("--dataset-workspace", type=Path, required=True)
    m7_predict.add_argument("--output", type=Path, required=True)
    m7_predict.add_argument(
        "--split",
        choices=("validation", "test", "temporal_holdout"),
        required=True,
    )
    m7_selection = m7_predict.add_mutually_exclusive_group(required=True)
    m7_selection.add_argument("--window-id", action="append", dest="window_ids")
    m7_selection.add_argument("--first", type=int)
    m7_predict.add_argument(
        "--config", type=Path, default=Path("configs/investigation.yaml")
    )

    m7_verify_predictions = subparsers.add_parser(
        "m7-verify-predictions",
        help="recompute M7 inference and verify complete source-event lineage",
    )
    m7_verify_predictions.add_argument("--round-workspace", type=Path, required=True)
    m7_verify_predictions.add_argument("--trust-workspace", type=Path, required=True)
    m7_verify_predictions.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m7_verify_predictions.add_argument("--dataset-workspace", type=Path, required=True)
    m7_verify_predictions.add_argument("--workspace", type=Path, required=True)
    m7_verify_predictions.add_argument(
        "--config", type=Path, default=Path("configs/investigation.yaml")
    )

    m7_explain = subparsers.add_parser(
        "m7-explain",
        help="explain a verified Prediction Bundle with IG and prototype distances",
    )
    m7_explain.add_argument("--round-workspace", type=Path, required=True)
    m7_explain.add_argument("--trust-workspace", type=Path, required=True)
    m7_explain.add_argument("--partition-workspace", type=Path, required=True)
    m7_explain.add_argument("--dataset-workspace", type=Path, required=True)
    m7_explain.add_argument("--prediction-workspace", type=Path, required=True)
    m7_explain.add_argument("--output", type=Path, required=True)
    m7_explain.add_argument(
        "--prediction-config",
        type=Path,
        default=Path("configs/investigation.yaml"),
    )
    m7_explain.add_argument(
        "--config",
        type=Path,
        default=Path("configs/investigation-explanations.yaml"),
    )

    m7_verify_explanations = subparsers.add_parser(
        "m7-verify-explanations",
        help="recompute and verify M7 IG and prototype-distance explanations",
    )
    m7_verify_explanations.add_argument("--round-workspace", type=Path, required=True)
    m7_verify_explanations.add_argument("--trust-workspace", type=Path, required=True)
    m7_verify_explanations.add_argument(
        "--partition-workspace", type=Path, required=True
    )
    m7_verify_explanations.add_argument("--dataset-workspace", type=Path, required=True)
    m7_verify_explanations.add_argument(
        "--prediction-workspace", type=Path, required=True
    )
    m7_verify_explanations.add_argument("--workspace", type=Path, required=True)
    m7_verify_explanations.add_argument(
        "--prediction-config",
        type=Path,
        default=Path("configs/investigation.yaml"),
    )
    m7_verify_explanations.add_argument(
        "--config",
        type=Path,
        default=Path("configs/investigation-explanations.yaml"),
    )

    m7_map_attack = subparsers.add_parser(
        "m7-map-attack",
        help="map verified M7 explanations to versioned ATT&CK hypotheses",
    )
    m7_map_attack.add_argument(
        "--round-workspace",
        type=Path,
        required=True,
    )
    m7_map_attack.add_argument(
        "--trust-workspace",
        type=Path,
        required=True,
    )
    m7_map_attack.add_argument(
        "--partition-workspace",
        type=Path,
        required=True,
    )
    m7_map_attack.add_argument(
        "--dataset-workspace",
        type=Path,
        required=True,
    )
    m7_map_attack.add_argument(
        "--prediction-workspace",
        type=Path,
        required=True,
    )
    m7_map_attack.add_argument(
        "--explanation-workspace",
        type=Path,
        required=True,
    )
    m7_map_attack.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    m7_map_attack.add_argument(
        "--prediction-config",
        type=Path,
        default=Path("configs/investigation.yaml"),
    )
    m7_map_attack.add_argument(
        "--explanation-config",
        type=Path,
        default=Path("configs/investigation-explanations.yaml"),
    )
    m7_map_attack.add_argument(
        "--config",
        type=Path,
        default=Path("configs/investigation-attack.yaml"),
    )

    m7_verify_attack = subparsers.add_parser(
        "m7-verify-attack",
        help="recompute and verify versioned M7 ATT&CK hypotheses",
    )
    m7_verify_attack.add_argument(
        "--round-workspace",
        type=Path,
        required=True,
    )
    m7_verify_attack.add_argument(
        "--trust-workspace",
        type=Path,
        required=True,
    )
    m7_verify_attack.add_argument(
        "--partition-workspace",
        type=Path,
        required=True,
    )
    m7_verify_attack.add_argument(
        "--dataset-workspace",
        type=Path,
        required=True,
    )
    m7_verify_attack.add_argument(
        "--prediction-workspace",
        type=Path,
        required=True,
    )
    m7_verify_attack.add_argument(
        "--explanation-workspace",
        type=Path,
        required=True,
    )
    m7_verify_attack.add_argument(
        "--workspace",
        type=Path,
        required=True,
    )
    m7_verify_attack.add_argument(
        "--prediction-config",
        type=Path,
        default=Path("configs/investigation.yaml"),
    )
    m7_verify_attack.add_argument(
        "--explanation-config",
        type=Path,
        default=Path("configs/investigation-explanations.yaml"),
    )
    m7_verify_attack.add_argument(
        "--config",
        type=Path,
        default=Path("configs/investigation-attack.yaml"),
    )
    m7_report = subparsers.add_parser(
        "m7-report",
        help="create a deterministic verified M7 investigation report",
    )
    m7_report.add_argument(
        "--round-workspace",
        type=Path,
        required=True,
    )
    m7_report.add_argument(
        "--trust-workspace",
        type=Path,
        required=True,
    )
    m7_report.add_argument(
        "--partition-workspace",
        type=Path,
        required=True,
    )
    m7_report.add_argument(
        "--dataset-workspace",
        type=Path,
        required=True,
    )
    m7_report.add_argument(
        "--prediction-workspace",
        type=Path,
        required=True,
    )
    m7_report.add_argument(
        "--explanation-workspace",
        type=Path,
        required=True,
    )
    m7_report.add_argument(
        "--attack-workspace",
        type=Path,
        required=True,
    )
    m7_report.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    m7_report.add_argument(
        "--prediction-config",
        type=Path,
        default=Path("configs/investigation.yaml"),
    )
    m7_report.add_argument(
        "--explanation-config",
        type=Path,
        default=Path(
            "configs/investigation-explanations.yaml"
        ),
    )
    m7_report.add_argument(
        "--attack-config",
        type=Path,
        default=Path("configs/investigation-attack.yaml"),
    )
    m7_report.add_argument(
        "--config",
        type=Path,
        default=Path("configs/investigation-report.yaml"),
    )

    m7_verify_report = subparsers.add_parser(
        "m7-verify-report",
        help="recompute and verify an M7 investigation report",
    )
    m7_verify_report.add_argument(
        "--round-workspace",
        type=Path,
        required=True,
    )
    m7_verify_report.add_argument(
        "--trust-workspace",
        type=Path,
        required=True,
    )
    m7_verify_report.add_argument(
        "--partition-workspace",
        type=Path,
        required=True,
    )
    m7_verify_report.add_argument(
        "--dataset-workspace",
        type=Path,
        required=True,
    )
    m7_verify_report.add_argument(
        "--prediction-workspace",
        type=Path,
        required=True,
    )
    m7_verify_report.add_argument(
        "--explanation-workspace",
        type=Path,
        required=True,
    )
    m7_verify_report.add_argument(
        "--attack-workspace",
        type=Path,
        required=True,
    )
    m7_verify_report.add_argument(
        "--workspace",
        type=Path,
        required=True,
    )
    m7_verify_report.add_argument(
        "--prediction-config",
        type=Path,
        default=Path("configs/investigation.yaml"),
    )
    m7_verify_report.add_argument(
        "--explanation-config",
        type=Path,
        default=Path(
            "configs/investigation-explanations.yaml"
        ),
    )
    m7_verify_report.add_argument(
        "--attack-config",
        type=Path,
        default=Path("configs/investigation-attack.yaml"),
    )
    m7_verify_report.add_argument(
        "--config",
        type=Path,
        default=Path("configs/investigation-report.yaml"),
    )

    m8_preserve = subparsers.add_parser(
        "m8-preserve", help="publish the deterministic M8.1 preservation inventory"
    )
    m8_preserve.add_argument(
        "--config", type=Path, default=Path("configs/preservation.yaml")
    )
    m8_preserve.add_argument(
        "--output", type=Path, default=Path("artifacts/m8-preservation-manifest-v1")
    )

    m8_verify = subparsers.add_parser(
        "m8-verify-preservation", help="reconstruct and verify an M8.1 inventory"
    )
    m8_verify.add_argument(
        "--config", type=Path, default=Path("configs/preservation.yaml")
    )
    m8_verify.add_argument(
        "--workspace",
        type=Path,
        default=Path("artifacts/m8-preservation-manifest-v1"),
    )

    m8_merkle = subparsers.add_parser(
        "m8-build-merkle", help="commit the M8.1 inventory in a deterministic Merkle tree"
    )
    m8_merkle.add_argument(
        "--config", type=Path, default=Path("configs/merkle.yaml")
    )
    m8_merkle.add_argument(
        "--output", type=Path, default=Path("artifacts/m8-merkle-tree-v1")
    )

    m8_verify_merkle = subparsers.add_parser(
        "m8-verify-merkle", help="reconstruct and verify the M8.2 Merkle commitment"
    )
    m8_verify_merkle.add_argument(
        "--config", type=Path, default=Path("configs/merkle.yaml")
    )
    m8_verify_merkle.add_argument(
        "--workspace",
        type=Path,
        default=Path("artifacts/m8-merkle-tree-v1"),
    )

    m8_timestamp = subparsers.add_parser(
        "m8-anchor-time", help="obtain and verify an RFC 3161 timestamp for M8.2"
    )
    m8_timestamp.add_argument(
        "--config", type=Path, default=Path("configs/timestamp.yaml")
    )
    m8_timestamp.add_argument(
        "--output", type=Path, default=Path("artifacts/m8-timestamp-anchor-v1")
    )

    m8_verify_timestamp = subparsers.add_parser(
        "m8-verify-timestamp", help="offline-verify the M8.3 RFC 3161 proof"
    )
    m8_verify_timestamp.add_argument(
        "--config", type=Path, default=Path("configs/timestamp.yaml")
    )
    m8_verify_timestamp.add_argument(
        "--workspace",
        type=Path,
        default=Path("artifacts/m8-timestamp-anchor-v1"),
    )

    m8_recovery = subparsers.add_parser(
        "m8-export-recovery", help="create the deterministic M8.4 offline recovery TAR"
    )
    m8_recovery.add_argument(
        "--config", type=Path, default=Path("configs/recovery.yaml")
    )
    m8_recovery.add_argument(
        "--output", type=Path, default=Path("artifacts/m8-recovery-export-v1")
    )

    m8_verify_recovery = subparsers.add_parser(
        "m8-verify-recovery", help="verify M8.4 entirely from the recovery package"
    )
    m8_verify_recovery.add_argument(
        "--workspace",
        type=Path,
        default=Path("artifacts/m8-recovery-export-v1"),
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
    if arguments.command == "m3-protean-train":
        result = run_protean_candidate(
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            output=arguments.output,
            config_path=arguments.config,
            prototype_alignment_weight=arguments.prototype_alignment_weight,
            device_override=arguments.device,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m3-protean-verify":
        result = verify_protean_candidate(
            workspace=arguments.workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m3-protean-report":
        result = generate_protean_validation_report(
            candidate_workspaces=arguments.candidate_workspace,
            fedavg_workspace=arguments.fedavg_workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m3-protean-verify-report":
        result = verify_protean_validation_report(
            candidate_workspaces=arguments.candidate_workspace,
            fedavg_workspace=arguments.fedavg_workspace,
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m3-protean-lock":
        result = create_protean_selection_lock(
            candidate_workspaces=arguments.candidate_workspace,
            fedavg_workspace=arguments.fedavg_workspace,
            report_workspace=arguments.report_workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m3-protean-verify-lock":
        result = verify_protean_selection_lock(
            candidate_workspaces=arguments.candidate_workspace,
            fedavg_workspace=arguments.fedavg_workspace,
            report_workspace=arguments.report_workspace,
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m3-protean-finalize":
        result = finalize_protean_endpoints(
            candidate_workspaces=arguments.candidate_workspace,
            fedavg_workspace=arguments.fedavg_workspace,
            report_workspace=arguments.report_workspace,
            selection_lock_workspace=arguments.selection_lock_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m3-protean-verify-final":
        result = verify_protean_finalization(
            candidate_workspaces=arguments.candidate_workspace,
            fedavg_workspace=arguments.fedavg_workspace,
            report_workspace=arguments.report_workspace,
            selection_lock_workspace=arguments.selection_lock_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
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
    if arguments.command == "m5-init":
        result = initialize_secure_round(
            workspace=arguments.workspace,
            trust_workspace=arguments.trust_workspace,
            partition_manifest_path=arguments.partition_manifest,
            config_path=arguments.config,
            secure_config_path=arguments.secure_config,
            coordinator_workspace=arguments.coordinator_workspace,
            campaign_id=arguments.campaign_id,
            round_number=arguments.round_number,
            previous_round_workspace=arguments.previous_round_workspace,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m5-client-update":
        result = create_secure_update(
            public_workspace=arguments.public_workspace,
            client_dataset_path=arguments.client_dataset,
            client_manifest_path=arguments.client_manifest,
            node_workspace=arguments.node_workspace,
            submission_workspace=arguments.submission_workspace,
            tcti=arguments.tcti,
            client_id=arguments.client_id,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m5-admit-aggregate":
        result = admit_and_aggregate(
            workspace=arguments.workspace,
            trust_workspace=arguments.trust_workspace,
            submissions_root=arguments.submissions,
            coordinator_workspace=arguments.coordinator_workspace,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "aggregated" else 1
    if arguments.command == "m5-verify":
        result = verify_secure_round(
            workspace=arguments.workspace,
            trust_workspace=arguments.trust_workspace,
            submissions_root=arguments.submissions,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m5-finalize-campaign":
        result = finalize_secure_campaign(
            workspace=arguments.workspace,
            trust_workspace=arguments.trust_workspace,
            partition_manifest_path=arguments.partition_manifest,
            server_evaluation_path=arguments.server_evaluation,
            expected_rounds=arguments.rounds,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m5-verify-campaign":
        result = verify_secure_campaign(
            workspace=arguments.workspace,
            trust_workspace=arguments.trust_workspace,
            partition_manifest_path=arguments.partition_manifest,
            server_evaluation_path=arguments.server_evaluation,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m6-freeze":
        result = freeze_byzantine_scenario(
            source_round_workspace=arguments.source_round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            output=arguments.output,
            attack=arguments.attack,
            f=arguments.f,
            config_path=arguments.config,
            attacker_ids=arguments.attacker_ids,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m6-verify-frozen":
        result = verify_frozen_update_set(workspace=arguments.workspace)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m6-compare":
        result = run_byzantine_comparison(
            frozen_workspace=arguments.frozen_workspace,
            partition_workspace=arguments.partition_workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m6-verify":
        result = verify_byzantine_comparison(
            frozen_workspace=arguments.frozen_workspace,
            partition_workspace=arguments.partition_workspace,
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m6-prototype-freeze":
        result = freeze_prototype_scenario(
            source_round_workspace=arguments.source_round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            output=arguments.output,
            f=arguments.f,
            config_path=arguments.config,
            attacker_ids=arguments.attacker_ids,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m6-prototype-verify-frozen":
        result = verify_frozen_prototype_scenario(
            workspace=arguments.workspace,
            source_round_workspace=arguments.source_round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m6-prototype-compare":
        result = run_prototype_comparison(
            frozen_workspace=arguments.frozen_workspace,
            partition_workspace=arguments.partition_workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m6-prototype-verify":
        result = verify_prototype_comparison(
            frozen_workspace=arguments.frozen_workspace,
            partition_workspace=arguments.partition_workspace,
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m6-prototype-sensitivity-plan":
        result = plan_prototype_sensitivity(config_path=arguments.config)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m6-prototype-sensitivity":
        result = run_prototype_sensitivity(
            source_round_workspace=arguments.source_round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m6-prototype-verify-sensitivity":
        result = verify_prototype_sensitivity(
            source_round_workspace=arguments.source_round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m6-prototype-sensitivity-report":
        result = generate_prototype_sensitivity_report(
            source_round_workspace=arguments.source_round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            sensitivity_workspace=arguments.sensitivity_workspace,
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m6-prototype-verify-sensitivity-report":
        result = verify_prototype_sensitivity_report(
            source_round_workspace=arguments.source_round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            sensitivity_workspace=arguments.sensitivity_workspace,
            report_workspace=arguments.report_workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m7-predict":
        result = create_prediction_bundle(
            round_workspace=arguments.round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            output=arguments.output,
            config_path=arguments.config,
            split=arguments.split,
            window_ids=arguments.window_ids,
            first=arguments.first,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m7-verify-predictions":
        result = verify_prediction_bundle(
            round_workspace=arguments.round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1
    if arguments.command == "m7-explain":
        result = create_explanation_bundle(
            round_workspace=arguments.round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            prediction_workspace=arguments.prediction_workspace,
            output=arguments.output,
            prediction_config_path=arguments.prediction_config,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments.command == "m7-verify-explanations":
        result = verify_explanation_bundle(
            round_workspace=arguments.round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            prediction_workspace=arguments.prediction_workspace,
            workspace=arguments.workspace,
            prediction_config_path=arguments.prediction_config,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1

    if arguments.command == "m7-map-attack":
        result = create_attack_mapping_bundle(
            round_workspace=arguments.round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            prediction_workspace=arguments.prediction_workspace,
            explanation_workspace=arguments.explanation_workspace,
            output=arguments.output,
            prediction_config_path=arguments.prediction_config,
            explanation_config_path=arguments.explanation_config,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if arguments.command == "m7-verify-attack":
        result = verify_attack_mapping_bundle(
            round_workspace=arguments.round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            prediction_workspace=arguments.prediction_workspace,
            explanation_workspace=arguments.explanation_workspace,
            workspace=arguments.workspace,
            prediction_config_path=arguments.prediction_config,
            explanation_config_path=arguments.explanation_config,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1

    if arguments.command == "m7-report":
        result = create_investigation_report_bundle(
            round_workspace=arguments.round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            prediction_workspace=arguments.prediction_workspace,
            explanation_workspace=arguments.explanation_workspace,
            attack_workspace=arguments.attack_workspace,
            output=arguments.output,
            prediction_config_path=arguments.prediction_config,
            explanation_config_path=arguments.explanation_config,
            attack_config_path=arguments.attack_config,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if arguments.command == "m7-verify-report":
        result = verify_investigation_report_bundle(
            round_workspace=arguments.round_workspace,
            trust_workspace=arguments.trust_workspace,
            partition_workspace=arguments.partition_workspace,
            dataset_workspace=arguments.dataset_workspace,
            prediction_workspace=arguments.prediction_workspace,
            explanation_workspace=arguments.explanation_workspace,
            attack_workspace=arguments.attack_workspace,
            workspace=arguments.workspace,
            prediction_config_path=arguments.prediction_config,
            explanation_config_path=arguments.explanation_config,
            attack_config_path=arguments.attack_config,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1

    if arguments.command == "m8-preserve":
        result = create_preservation_manifest(
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if arguments.command == "m8-verify-preservation":
        result = verify_preservation_manifest(
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1

    if arguments.command == "m8-build-merkle":
        result = create_merkle_tree(
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if arguments.command == "m8-verify-merkle":
        result = verify_merkle_tree(
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1

    if arguments.command == "m8-anchor-time":
        result = create_timestamp_anchor(
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if arguments.command == "m8-verify-timestamp":
        result = verify_timestamp_anchor(
            workspace=arguments.workspace,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1

    if arguments.command == "m8-export-recovery":
        result = create_recovery_export(
            output=arguments.output,
            config_path=arguments.config,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if arguments.command == "m8-verify-recovery":
        result = verify_recovery_export(workspace=arguments.workspace)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1

    result = physical_tpm_preflight(tcti=arguments.tcti)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
