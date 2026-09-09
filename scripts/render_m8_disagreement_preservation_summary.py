#!/usr/bin/env python3
"""Publish a thesis-facing summary of the M6-linked M8 preservation closure."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_bytes
from fl_forensics.final_preservation import _derive_core, _receipt
from fl_forensics.in_round_campaign_accounting_models import (
    InRoundCampaignAccountingReport,
)
from fl_forensics.in_round_final_preservation_models import (
    InRoundFinalPreservationReceipt,
)


SNAPSHOT_TYPE = "published_m8_m6_disagreement_preservation_snapshot_manifest"
POLICY_LABELS = {
    "tpm_only": "TPM only",
    "statistics_only": "Statistics only",
    "sequential": "Sequential",
    "gated_composite": "Gated composite",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _figure_bytes(figure: plt.Figure) -> bytes:
    output = io.BytesIO()
    figure.savefig(output, format="png", dpi=180, bbox_inches="tight")
    plt.close(figure)
    return output.getvalue()


def _write_once(path: Path, content: bytes, *, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != content and not replace:
        raise RuntimeError(
            "refusing to overwrite different published bytes without "
            f"--replace-existing-snapshot: {path}"
        )
    if not path.exists() or replace:
        path.write_bytes(content)


def _authorize_replacement(
    output: Path, *, enabled: bool, verification_id: str
) -> bool:
    if not output.exists() or not any(output.iterdir()):
        return False
    if not enabled:
        return False
    manifest_path = output / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("existing snapshot has no manifest; replacement is unsafe")
    manifest = _load(manifest_path)
    if (
        manifest.get("artifact_type") != SNAPSHOT_TYPE
        or manifest.get("verification_id") != verification_id
    ):
        raise RuntimeError("existing snapshot belongs to a different final receipt")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError("existing snapshot manifest has no file inventory")
    for name, metadata in files.items():
        relative = Path(str(name))
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("existing snapshot manifest contains an unsafe path")
        path = output / relative
        if (
            not path.is_file()
            or not isinstance(metadata, dict)
            or _sha256(path) != str(metadata.get("sha256"))
        ):
            raise RuntimeError(f"existing snapshot file changed after publication: {name}")
    return True


def _canonical_accounting(path: Path) -> InRoundCampaignAccountingReport:
    value = path.read_bytes()
    report = InRoundCampaignAccountingReport.model_validate_json(value)
    if value != canonical_json_bytes(report.model_dump(mode="json")) + b"\n":
        raise ValueError("campaign accounting report is not canonical")
    if report.canonical_core_sha256 != digest_object(report.core.model_dump(mode="json")):
        raise ValueError("campaign accounting canonical core digest mismatch")
    return report


def _validate_public_sources(
    *,
    receipt: InRoundFinalPreservationReceipt,
    m6_summary: dict[str, Any],
    m7_summary: dict[str, Any],
) -> None:
    campaign = receipt.core.campaign_accounting
    if (
        m6_summary.get("artifact_type")
        != "published_m6_live_disagreement_snapshot"
        or m6_summary.get("campaign_id") != campaign.source_campaign_id
        or m6_summary.get("experiment_id")
        != campaign.source_disagreement_experiment_id
        or m6_summary.get("contract_id") != campaign.source_disagreement_contract_id
        or m6_summary.get("source_campaign_manifest_sha256")
        != campaign.source_campaign_manifest_sha256
        or int(m6_summary.get("selected_round", 0)) != campaign.selected_round
    ):
        raise ValueError("published M6 summary does not match the final M8 receipt")
    if (
        m7_summary.get("artifact_type")
        != "published_m7_m6_investigation_summary"
        or m7_summary.get("campaign_id") != campaign.source_campaign_id
        or int(m7_summary.get("round_number", 0)) != campaign.selected_round
        or m7_summary.get("global_model_sha256") != campaign.selected_model_sha256
    ):
        raise ValueError("published M7 summary does not match the final M8 receipt")


def _verify_published_summary(
    *, manifest_path: Path, summary_path: Path, expected_artifact_type: str
) -> dict[str, Any]:
    manifest = _load(manifest_path)
    if manifest.get("artifact_type") != expected_artifact_type:
        raise ValueError(f"unexpected published result manifest: {manifest_path}")
    metadata = manifest.get("files", {}).get("summary.json")
    if (
        not isinstance(metadata, dict)
        or metadata.get("sha256") != _sha256(summary_path)
        or metadata.get("size_bytes") != summary_path.stat().st_size
    ):
        raise ValueError(f"published summary differs from its manifest: {summary_path}")
    return manifest


def _policy_rows(report: InRoundCampaignAccountingReport) -> list[dict[str, Any]]:
    rows = []
    for item in report.core.policy_outcomes:
        unsafe_total = item.controlled_true_positive + item.controlled_false_negative
        safe_total = item.controlled_true_negative + item.controlled_false_positive
        rows.append(
            {
                "policy": item.policy,
                "policy_label": POLICY_LABELS[item.policy],
                "deployed_for_training": item.policy == "gated_composite",
                "accepted_count": item.accepted_count,
                "downweighted_count": item.downweighted_count,
                "contributing_count": item.accepted_count + item.downweighted_count,
                "quarantined_count": item.quarantined_count,
                "controlled_true_positive": item.controlled_true_positive,
                "controlled_false_positive": item.controlled_false_positive,
                "controlled_true_negative": item.controlled_true_negative,
                "controlled_false_negative": item.controlled_false_negative,
                "controlled_unsafe_recall": (
                    item.controlled_true_positive / unsafe_total
                    if unsafe_total
                    else 0.0
                ),
                "controlled_safe_false_positive_rate": (
                    item.controlled_false_positive / safe_total if safe_total else 0.0
                ),
            }
        )
    return rows


def _round_rows(report: InRoundCampaignAccountingReport) -> list[dict[str, Any]]:
    return [
        {
            "round": item.round_number,
            "submitted": item.submitted_count,
            "observed_trust_accepted": item.observed_trust_accepted_count,
            "fully_accepted": item.fully_accepted_count,
            "downweighted": item.downweighted_count,
            "contributing": item.contributing_count,
            "quarantined": item.quarantined_count,
            "missing": item.missing_count,
            "submitted_examples": item.submitted_example_count,
            "contributing_examples": item.contributing_example_count,
            "effective_weight": item.total_effective_weight_decimal,
            "unique_attestations": item.unique_attestation_count,
            "checkpoint_chain_valid": item.checkpoint_chain_valid,
            "checkpoint_id": item.checkpoint_id,
            "checkpoint_sha256": item.checkpoint_sha256,
            "global_model_sha256": item.global_model_sha256,
            "contribution_inventory_sha256": item.contribution_inventory_sha256,
        }
        for item in report.core.rounds
    ]


def _client_rows(report: InRoundCampaignAccountingReport) -> list[dict[str, Any]]:
    return [
        {
            "client_id": item.client_id,
            "node_id": item.node_id,
            "enrollment_id": item.enrollment_id,
            "contracted_rounds": item.contracted_round_count,
            "submitted": item.submitted_count,
            "observed_trust_accepted": item.observed_trust_accepted_count,
            "fully_accepted": item.fully_accepted_count,
            "downweighted": item.downweighted_count,
            "contributing": item.contributing_count,
            "quarantined": item.quarantined_count,
            "submitted_examples": item.submitted_example_count,
            "contributing_examples": item.contributing_example_count,
            "attestations": item.attestation_count,
            "challenges": item.challenge_count,
        }
        for item in report.core.clients
    ]


def _stage_rows(receipt: InRoundFinalPreservationReceipt) -> list[dict[str, Any]]:
    core = receipt.core
    return [
        {
            "stage": "M8.1 preservation inventory",
            "status": "verified",
            "identifier": core.preservation.preservation_id,
            "primary_sha256": core.preservation.inventory_sha256,
            "item_count": core.preservation.artifact_count,
            "meaning": "content-addressed payload inventory",
        },
        {
            "stage": "M8.2 Merkle commitment",
            "status": "verified",
            "identifier": core.merkle.tree_id,
            "primary_sha256": core.merkle.root_sha256,
            "item_count": core.merkle.leaf_count,
            "meaning": "single commitment to artifacts and external bindings",
        },
        {
            "stage": "M8.3 RFC 3161 timestamp",
            "status": "verified",
            "identifier": core.timestamp.timestamp_id,
            "primary_sha256": core.timestamp.timestamp_response_sha256,
            "item_count": 1,
            "meaning": f"trusted time anchor at {core.timestamp.gen_time}",
        },
        {
            "stage": "M8.4 offline recovery",
            "status": "verified",
            "identifier": core.recovery.recovery_id,
            "primary_sha256": core.recovery.archive_sha256,
            "item_count": core.recovery.archived_entry_count,
            "meaning": "self-verifying deterministic recovery package",
        },
        {
            "stage": "M8.5 campaign accounting",
            "status": "verified",
            "identifier": core.campaign_accounting.accounting_id,
            "primary_sha256": core.campaign_accounting.contribution_inventory_sha256,
            "item_count": core.campaign_accounting.submission_count,
            "meaning": "round/client/policy ledger reconstructed offline",
        },
        {
            "stage": "M8.6 final lineage",
            "status": "verified",
            "identifier": receipt.verification_id,
            "primary_sha256": receipt.canonical_core_sha256,
            "item_count": len(core.verified_stages),
            "meaning": "cross-stage identifiers and digests jointly verified",
        },
    ]


def _thesis_metric_rows(
    *,
    receipt: InRoundFinalPreservationReceipt,
    report: InRoundCampaignAccountingReport,
    m6_summary: dict[str, Any],
    m7_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    core = receipt.core
    accounting = report.core
    metrics: list[tuple[str, str, Any, str, str]] = [
        ("experiment", "federated rounds", accounting.round_count, "rounds", "observed"),
        ("experiment", "clients per round", accounting.required_client_count, "clients", "observed"),
        ("trust", "observed TPM admission passes", accounting.observed_trust_accepted_count, "contributions", "observed"),
        ("trust", "verified attestations", accounting.trust_accounting.attestation_count, "attestations", "observed"),
        ("training", "submitted contributions", accounting.submission_count, "contributions", "observed"),
        ("training", "fully accepted contributions", accounting.fully_accepted_count, "contributions", "observed"),
        ("training", "downweighted contributions", accounting.downweighted_count, "contributions", "observed"),
        ("training", "quarantined contributions", accounting.quarantined_count, "contributions", "observed"),
        ("controlled experiment", "unsafe quarantined", accounting.unsafe_quarantined_count, "contributions", "controlled"),
        ("controlled experiment", "safe quarantined", accounting.safe_quarantined_count, "contributions", "controlled"),
        ("controlled experiment", "unsafe recall", m6_summary["unsafe_recall"], "fraction", "controlled"),
        ("model", "selected round", accounting.selected_round, "round", "observed"),
        ("model", "validation macro-F1", m6_summary["validation_macro_f1"], "score", "observed"),
        ("model", "isolated test macro-F1", m6_summary["test_macro_f1"], "score", "post-selection"),
        ("model", "test macro-F1 delta from clean", m6_summary["test_macro_f1_delta_from_clean"], "score", "descriptive comparison"),
        ("M7", "investigation cases", m7_summary["selection"]["case_count"], "cases", "descriptive"),
        ("M7", "source events resolved", m7_summary["lineage"]["source_event_count"], "events", "verified lineage"),
        ("M7", "source records resolved", m7_summary["lineage"]["source_record_count"], "records", "verified lineage"),
        ("preservation", "preserved payload", core.preservation.artifact_count, "files", "verified"),
        ("preservation", "Merkle leaves", core.merkle.leaf_count, "leaves", "verified"),
        ("preservation", "recovery archive size", core.recovery.archive_size_bytes, "bytes", "verified"),
    ]
    return [
        {
            "domain": domain,
            "metric": metric,
            "value": value,
            "unit": unit,
            "evidence_type": evidence_type,
        }
        for domain, metric, value, unit, evidence_type in metrics
    ]


def _assurance_figure(receipt: InRoundFinalPreservationReceipt) -> bytes:
    core = receipt.core
    labels = ("Inventory", "Merkle", "Timestamp", "Recovery", "Accounting", "Final")
    counts = (
        core.preservation.artifact_count,
        core.merkle.leaf_count,
        1,
        core.recovery.archived_entry_count,
        core.campaign_accounting.submission_count,
        len(core.verified_stages),
    )
    identifiers = (
        core.preservation.preservation_id,
        core.merkle.tree_id,
        core.timestamp.timestamp_id,
        core.recovery.recovery_id,
        core.campaign_accounting.accounting_id,
        receipt.verification_id,
    )
    figure, axis = plt.subplots(figsize=(13.5, 3.4))
    axis.set_xlim(-0.5, len(labels) - 0.5)
    axis.set_ylim(-0.4, 1.2)
    axis.axis("off")
    for position, (label, count, identifier) in enumerate(
        zip(labels, counts, identifiers, strict=True)
    ):
        if position:
            axis.annotate(
                "",
                xy=(position - 0.42, 0.55),
                xytext=(position - 0.58, 0.55),
                arrowprops={"arrowstyle": "->", "color": "#546e7a", "lw": 1.8},
            )
        axis.text(
            position,
            0.55,
            f"{label}\nVERIFIED\ncount={count}\n{identifier[-12:]}",
            ha="center",
            va="center",
            fontsize=8.4,
            bbox={
                "boxstyle": "round,pad=0.55",
                "facecolor": "#e8f5e9",
                "edgecolor": "#2e7d32",
                "linewidth": 1.5,
            },
        )
    axis.set_title("M6-linked M8 offline assurance chain", fontsize=13, pad=12)
    figure.tight_layout()
    return _figure_bytes(figure)


def _accounting_figure(
    *, report: InRoundCampaignAccountingReport, policy_rows: list[dict[str, Any]]
) -> bytes:
    core = report.core
    figure, axes = plt.subplots(1, 2, figsize=(12.4, 5.0))
    treatment_labels = ("Fully accepted", "Downweighted", "Quarantined")
    treatment_values = (
        core.fully_accepted_count,
        core.downweighted_count,
        core.quarantined_count,
    )
    bars = axes[0].bar(
        treatment_labels,
        treatment_values,
        color=("#43a047", "#f9a825", "#c62828"),
    )
    axes[0].set_ylabel("Contributions across 30 rounds")
    axes[0].set_title("Deployed gated-composite treatment")
    axes[0].grid(axis="y", alpha=0.25)
    axes[0].bar_label(bars, padding=3)

    labels = [row["policy_label"] for row in policy_rows]
    recall = np.asarray([row["controlled_unsafe_recall"] for row in policy_rows])
    bars = axes[1].bar(
        labels,
        recall * 100.0,
        color=("#78909c", "#42a5f5", "#7e57c2", "#26a69a"),
    )
    axes[1].set_ylim(0.0, 108.0)
    axes[1].set_ylabel("Controlled unsafe-update recall (%)")
    axes[1].set_title("Same submissions, four admission policies")
    axes[1].tick_params(axis="x", rotation=20)
    axes[1].grid(axis="y", alpha=0.25)
    for bar, value in zip(bars, recall, strict=True):
        axes[1].text(
            bar.get_x() + bar.get_width() / 2.0,
            value * 100.0 + 2.0,
            f"{value * 100.0:.0f}%",
            ha="center",
            va="bottom",
        )
    figure.suptitle("Offline-reconstructed contribution and policy accounting")
    figure.tight_layout()
    return _figure_bytes(figure)


def render(
    *,
    recovery_workspace: Path,
    accounting_workspace: Path,
    m6_results: Path,
    m7_results: Path,
    output: Path,
    replace_existing_snapshot: bool = False,
) -> dict[str, Any]:
    recovery_workspace = recovery_workspace.resolve()
    accounting_workspace = accounting_workspace.resolve()
    m6_results = m6_results.resolve()
    m7_results = m7_results.resolve()
    output = output.resolve()

    receipt = _receipt(
        _derive_core(
            recovery_workspace=recovery_workspace,
            accounting_workspace=accounting_workspace,
        )
    )
    if not isinstance(receipt, InRoundFinalPreservationReceipt):
        raise ValueError("final receipt is not the M8 in-round disagreement profile")
    accounting_path = accounting_workspace / "campaign-accounting.json"
    report = _canonical_accounting(accounting_path)
    m6_summary_path = m6_results / "summary.json"
    m7_summary_path = m7_results / "summary.json"
    m6_manifest_path = m6_results / "manifest.json"
    m7_manifest_path = m7_results / "manifest.json"
    if not m6_manifest_path.is_file() or not m7_manifest_path.is_file():
        raise FileNotFoundError("published M6/M7 source manifest is missing")
    _verify_published_summary(
        manifest_path=m6_manifest_path,
        summary_path=m6_summary_path,
        expected_artifact_type="published_m6_live_disagreement_snapshot_manifest",
    )
    _verify_published_summary(
        manifest_path=m7_manifest_path,
        summary_path=m7_summary_path,
        expected_artifact_type="published_m7_m6_investigation_snapshot_manifest",
    )
    m6_summary = _load(m6_summary_path)
    m7_summary = _load(m7_summary_path)
    _validate_public_sources(
        receipt=receipt,
        m6_summary=m6_summary,
        m7_summary=m7_summary,
    )

    core = receipt.core
    accounting = report.core
    policy_rows = _policy_rows(report)
    round_rows = _round_rows(report)
    client_rows = _client_rows(report)
    stage_rows = _stage_rows(receipt)
    metric_rows = _thesis_metric_rows(
        receipt=receipt,
        report=report,
        m6_summary=m6_summary,
        m7_summary=m7_summary,
    )
    receipt_bytes = canonical_json_bytes(receipt.model_dump(mode="json")) + b"\n"
    receipt_sha256 = sha256_bytes(receipt_bytes)
    summary = {
        "schema_version": "1.0",
        "artifact_type": "published_m8_m6_disagreement_preservation_summary",
        "status": "verified-source-sanitized-summary",
        "campaign_id": accounting.source_campaign_id,
        "experiment_id": accounting.source_disagreement_experiment_id,
        "contract_id": accounting.source_disagreement_contract_id,
        "selected_round": accounting.selected_round,
        "selected_model_sha256": accounting.selected_model_sha256,
        "final_verification": {
            "verification_id": receipt.verification_id,
            "canonical_core_sha256": receipt.canonical_core_sha256,
            "receipt_sha256": receipt_sha256,
            "assurance_state": core.assurance_state,
            "verified_stage_count": len(core.verified_stages),
            "final_lineage_verified": core.final_lineage_verified,
            "offline_inputs_only": True,
        },
        "preservation": {
            "preservation_id": core.preservation.preservation_id,
            "artifact_count": core.preservation.artifact_count,
            "external_evidence_binding_count": (
                core.preservation.external_evidence_binding_count
            ),
            "inventory_sha256": core.preservation.inventory_sha256,
            "selected_checkpoint_sha256": core.preservation.selected_checkpoint_sha256,
            "private_cryptographic_material_exported": False,
        },
        "merkle": {
            "tree_id": core.merkle.tree_id,
            "root_sha256": core.merkle.root_sha256,
            "artifact_leaf_count": core.merkle.artifact_leaf_count,
            "external_evidence_leaf_count": core.merkle.external_evidence_leaf_count,
            "leaf_count": core.merkle.leaf_count,
            "level_count": math.ceil(math.log2(core.merkle.leaf_count)) + 1,
        },
        "timestamp": {
            "timestamp_id": core.timestamp.timestamp_id,
            "protocol": "RFC3161",
            "gen_time": core.timestamp.gen_time,
            "policy_oid": core.timestamp.policy_oid,
            "serial_number": core.timestamp.serial_number,
            "timestamp_response_sha256": core.timestamp.timestamp_response_sha256,
        },
        "recovery": {
            "recovery_id": core.recovery.recovery_id,
            "package_id": core.recovery.package_id,
            "archive_sha256": core.recovery.archive_sha256,
            "archive_size_bytes": core.recovery.archive_size_bytes,
            "archived_entry_count": core.recovery.archived_entry_count,
            "payload_entry_count": core.recovery.payload_entry_count,
            "assurance_entry_count": core.recovery.assurance_entry_count,
            "external_evidence_binding_count": (
                core.recovery.external_evidence_binding_count
            ),
        },
        "campaign_accounting": {
            "accounting_id": report.accounting_id,
            "source_workspace_name": accounting_workspace.name,
            "round_count": accounting.round_count,
            "client_count": accounting.required_client_count,
            "submission_count": accounting.submission_count,
            "observed_trust_accepted_count": accounting.observed_trust_accepted_count,
            "fully_accepted_count": accounting.fully_accepted_count,
            "downweighted_count": accounting.downweighted_count,
            "contributing_count": accounting.contributing_count,
            "quarantined_count": accounting.quarantined_count,
            "missing_count": accounting.missing_count,
            "safe_submission_count": accounting.safe_submission_count,
            "unsafe_submission_count": accounting.unsafe_submission_count,
            "safe_quarantined_count": accounting.safe_quarantined_count,
            "unsafe_quarantined_count": accounting.unsafe_quarantined_count,
            "observed_admission_check_count": accounting.observed_admission_check_count,
            "passed_observed_admission_check_count": (
                accounting.passed_observed_admission_check_count
            ),
            "unique_bundle_count": accounting.unique_bundle_count,
            "unique_update_count": accounting.unique_update_count,
            "contribution_inventory_sha256": accounting.contribution_inventory_sha256,
        },
        "trust_accounting": accounting.trust_accounting.model_dump(mode="json"),
        "policy_outcomes": policy_rows,
        "model_evaluation": {
            "validation_macro_f1": m6_summary["validation_macro_f1"],
            "test_macro_f1": m6_summary["test_macro_f1"],
            "test_accuracy": m6_summary["test_accuracy"],
            "test_macro_f1_delta_from_clean": m6_summary[
                "test_macro_f1_delta_from_clean"
            ],
            "client_local_test_macro_f1": m6_summary[
                "client_local_test_macro_f1"
            ],
            "performance_source": "verified published M6 result; authenticated by M8 preservation",
        },
        "m7_investigation": {
            "case_count": m7_summary["selection"]["case_count"],
            "selection_method": m7_summary["selection"]["method"],
            "correct_case_count": m7_summary["descriptive_evaluation"]["correct_count"],
            "performance_estimate": m7_summary["descriptive_evaluation"][
                "performance_estimate"
            ],
            "source_event_count": m7_summary["lineage"]["source_event_count"],
            "source_record_count": m7_summary["lineage"]["source_record_count"],
            "prototype_match_count": m7_summary["explanation"][
                "prototype_match_count"
            ],
            "candidate_tactic_count": m7_summary["attack_mapping"][
                "candidate_tactic_count"
            ],
            "unresolved_mapping_count": m7_summary["attack_mapping"][
                "unresolved_count"
            ],
        },
        "source_bindings": {
            "campaign_manifest_sha256": accounting.source_campaign_manifest_sha256,
            "accounting_report_sha256": _sha256(accounting_path),
            "m6_summary_sha256": _sha256(m6_summary_path),
            "m6_manifest_sha256": _sha256(m6_manifest_path),
            "m7_summary_sha256": _sha256(m7_summary_path),
            "m7_manifest_sha256": _sha256(m7_manifest_path),
        },
        "interpretation_boundaries": [
            "all 450 observed swTPM-backed M4 admission decisions passed; controlled trust-inadmissible cells are counterfactual policy inputs, not failed Quotes",
            "gated-composite alone controlled the published training trajectory; the other three policies are paired shadow decisions over the same submissions",
            "the 24 downweighted contributions remain part of the 358 contributors and are not quarantines",
            "M8 authenticates and reconstructs the preserved results; it does not repeat model training or turn a single deterministic campaign into a population estimate",
            "the 16 M7 cases are a deterministic investigation bundle, not an independent performance sample",
            "the RFC 3161 token proves existence of the committed root no later than its signed time; it does not prove semantic correctness or legal admissibility",
            "the recovery archive excludes private keys and requires external storage encryption, access control, retention, and backup policy",
        ],
    }

    readme = f"""# M6-linked M8 verified preservation closure

This snapshot is the compact, Git-trackable view of the final thesis experiment. It closes the
same 30-round campaign used by the M6 trust/statistics disagreement study and the linked M7
investigation. The multi-gigabyte source evidence remains under `artifacts/`; this directory
publishes only sanitized measurements, identifiers, cryptographic bindings, and figures.

## What was verified

The final receipt `{receipt.verification_id}` was rebuilt from the offline recovery package and
the M8.5 accounting workspace. All {len(core.verified_stages)} assurance stages passed with final
state `{core.assurance_state}`. The canonical final core is
`{receipt.canonical_core_sha256}` and the published receipt bytes hash to
`{receipt_sha256}`.

| Stage | Verified result |
|---|---|
| M8.1 inventory | {core.preservation.artifact_count:,} payload files and {core.preservation.external_evidence_binding_count} external digest bindings |
| M8.2 commitment | {core.merkle.leaf_count:,} leaves; root `{core.merkle.root_sha256}` |
| M8.3 time anchor | RFC 3161 at `{core.timestamp.gen_time}`; timestamp `{core.timestamp.timestamp_id}` |
| M8.4 recovery | {core.recovery.payload_entry_count:,} payload + {core.recovery.assurance_entry_count} assurance entries; {core.recovery.archive_size_bytes / (1024 ** 3):.3f} GiB TAR |
| M8.5 accounting | {accounting.round_count} rounds × {accounting.required_client_count} clients = {accounting.submission_count} unique submissions reconstructed offline |
| M8.6 final lineage | zero missing contributions; cross-stage identifiers, digests, selected checkpoint, and campaign lineage agree |

## Training-time admission result

Every submitted bundle passed the seven admission checks actually observed by M5, including
active enrollment, TPM ESK signature, and fresh attestation: {accounting.passed_observed_admission_check_count:,}/
{accounting.observed_admission_check_count:,} checks and {accounting.observed_trust_accepted_count}/
{accounting.submission_count} trust decisions. Across the deployed gated-composite trajectory:

- {accounting.fully_accepted_count} contributions were accepted at full weight;
- {accounting.downweighted_count} were accepted at reduced weight;
- {accounting.quarantined_count} were excluded from aggregation;
- {accounting.contributing_count} therefore contributed non-zero weight, because downweighted
  contributions are contributors rather than quarantines.

Within the controlled 2×2 disagreement design, all {accounting.unsafe_submission_count} unsafe
cells were quarantined and {accounting.safe_quarantined_count} of
{accounting.safe_submission_count} safe cells were quarantined. This yields unsafe recall
`{m6_summary['unsafe_recall']:.3f}` and strict safe false-positive rate
`{m6_summary['safe_strict_false_positive_rate']:.4f}` for the deployed policy. These labels are
experimental ground truth for the controlled treatments, not claims about malicious intent.

The four policies were evaluated on the same signed submissions. TPM-only and statistics-only
each missed one disagreement direction (30 false negatives each); sequential and
gated-composite detected all 90 unsafe controlled cells. Only gated-composite controlled this
model trajectory. The other three outcomes are paired shadow decisions, which is why they can
be compared without pretending that four independent campaigns were trained.

## Learning and investigation outcomes

Validation-only selection chose round {accounting.selected_round}. The isolated post-selection
test macro-F1 is `{m6_summary['test_macro_f1']:.6f}` with accuracy
`{m6_summary['test_accuracy']:.6f}`. Compared descriptively with the clean reference campaign,
test macro-F1 changed by `{m6_summary['test_macro_f1_delta_from_clean']:+.6f}`. The unweighted
mean of the 15 client-local isolated test macro-F1 values is
`{m6_summary['client_local_test_macro_f1']['mean']:.6f}` with population standard deviation
`{m6_summary['client_local_test_macro_f1']['population_stddev']:.6f}`. These are measurements of
one deterministic campaign, not a multi-seed confidence interval.

The linked M7 chain investigates {m7_summary['selection']['case_count']} label-independent test
cases from the same selected checkpoint, resolves {m7_summary['lineage']['source_event_count']}
events and {m7_summary['lineage']['source_record_count']} source records, and preserves verified
Integrated Gradients, prototype geometry, ATT&CK hypotheses, and a human-readable report. Its
{m7_summary['descriptive_evaluation']['correct_count']}/{m7_summary['selection']['case_count']}
correct-case count is descriptive only; the fixed bundle is not a performance estimate.

## What M8 proves — and what it does not

M8 proves that the retained bytes, inventory, Merkle commitment, trusted timestamp, recovery
package, contribution ledger, selected model, and published experiment identifiers form one
internally consistent chain. It can detect later byte changes and reconstruct the declared
round/client/policy totals without consulting the live M2–M7 workspaces.

It does not prove that every source event is true, that a statistical quarantine identifies a
malicious client, or that the model generalizes outside the evaluated data. All 450 real
`swtpm` appraisals passed. The trust-inadmissible cells used to measure disagreement are
explicit controlled counterfactuals, not observed Quote failures. The timestamp establishes
existence of the root no later than the signed time; legal admissibility and long-term storage
controls remain organizational responsibilities.

## Files intended for thesis analysis

- `summary.json`: compact machine-readable M6→M7→M8 result and interpretation boundaries;
- `thesis-metrics.csv`: one citation-oriented table of the principal observed, controlled,
  post-selection, and verified measurements;
- `policy-outcomes.csv`: paired treatment and confusion counts for all four admission policies;
- `rounds.csv`: per-round contribution, example, attestation, and checkpoint accounting;
- `clients.csv`: per-client submissions, treatments, example counts, and trust refresh counts;
- `stages.csv`: the six assurance stages with identifiers, commitments, and meanings;
- `final-verification-receipt.json`: the canonical final M8.6 receipt;
- `assurance-chain.png`: visual M8 stage chain;
- `intervention-accounting.png`: deployed treatment totals and paired policy recall;
- `manifest.json`: SHA-256 and size of every file in this published snapshot.

Contribution-level decision explanations remain in the M6 result snapshot; prediction-level
explanations remain in the linked M7 snapshot. They are referenced rather than duplicated here.

## Reproduction

After `m8-verify-final-preservation` succeeds, regenerate this public view with:

```bash
python scripts/render_m8_disagreement_preservation_summary.py \\
  --recovery-workspace artifacts/m8-recovery-m6-disagreement-local-test-v1 \\
  --accounting-workspace artifacts/m8-campaign-accounting-m6-disagreement-local-test-v1 \\
  --m6-results results/m6-trust-statistical-disagreement-local-test-v1 \\
  --m7-results results/m7-m6-disagreement-investigation-local-test-v1 \\
  --output results/m8-m6-disagreement-preservation-local-test-v1
```

The renderer intentionally reruns the offline recovery, accounting, and final-lineage checks
before publishing. Use `--replace-existing-snapshot` only when regenerating the same verified
receipt and only if the existing snapshot still matches its own manifest.
"""

    files = {
        "README.md": readme.encode("utf-8"),
        "summary.json": _json_bytes(summary),
        "final-verification-receipt.json": receipt_bytes,
        "stages.csv": _csv_bytes(list(stage_rows[0]), stage_rows),
        "policy-outcomes.csv": _csv_bytes(list(policy_rows[0]), policy_rows),
        "rounds.csv": _csv_bytes(list(round_rows[0]), round_rows),
        "clients.csv": _csv_bytes(list(client_rows[0]), client_rows),
        "thesis-metrics.csv": _csv_bytes(list(metric_rows[0]), metric_rows),
        "assurance-chain.png": _assurance_figure(receipt),
        "intervention-accounting.png": _accounting_figure(
            report=report, policy_rows=policy_rows
        ),
    }
    replace = _authorize_replacement(
        output,
        enabled=replace_existing_snapshot,
        verification_id=receipt.verification_id,
    )
    for name, content in files.items():
        _write_once(output / name, content, replace=replace)
    manifest = {
        "schema_version": "1.0",
        "artifact_type": SNAPSHOT_TYPE,
        "verification_id": receipt.verification_id,
        "canonical_final_core_sha256": receipt.canonical_core_sha256,
        "source_recovery_archive_sha256": core.recovery.archive_sha256,
        "source_accounting_report_sha256": _sha256(accounting_path),
        "source_m6_manifest_sha256": _sha256(m6_manifest_path),
        "source_m7_manifest_sha256": _sha256(m7_manifest_path),
        "renderer_sha256": _sha256(Path(__file__).resolve()),
        "files": {
            name: {
                "sha256": _sha256(output / name),
                "size_bytes": (output / name).stat().st_size,
            }
            for name in sorted(files)
        },
        "publication_boundary": (
            "sanitized derived summary; no datasets, source records, model parameters, "
            "client updates, private keys, TPM state, or recovery archive"
        ),
    }
    _write_once(output / "manifest.json", _json_bytes(manifest), replace=replace)
    return {
        "status": "published",
        "verification_id": receipt.verification_id,
        "campaign_id": accounting.source_campaign_id,
        "round_count": accounting.round_count,
        "submission_count": accounting.submission_count,
        "contributing_count": accounting.contributing_count,
        "quarantined_count": accounting.quarantined_count,
        "artifact_count": core.preservation.artifact_count,
        "merkle_root_sha256": core.merkle.root_sha256,
        "file_count": len(files) + 1,
        "workspace": str(output),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recovery-workspace", type=Path, required=True)
    parser.add_argument("--accounting-workspace", type=Path, required=True)
    parser.add_argument("--m6-results", type=Path, required=True)
    parser.add_argument("--m7-results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replace-existing-snapshot", action="store_true")
    arguments = parser.parse_args()
    print(
        json.dumps(
            render(
                recovery_workspace=arguments.recovery_workspace,
                accounting_workspace=arguments.accounting_workspace,
                m6_results=arguments.m6_results,
                m7_results=arguments.m7_results,
                output=arguments.output,
                replace_existing_snapshot=arguments.replace_existing_snapshot,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
