#!/usr/bin/env python3
"""Publish thesis-facing results for the verified live M6 explanation bundle."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import fmean, median
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from fl_forensics.live_contribution_explanation import (  # noqa: E402
    verify_live_contribution_explanation_bundle,
)


STATUSES = (
    "accepted",
    "accepted_downweighted",
    "statistically_quarantined",
    "trust_quarantined",
)
STATUS_LABELS = {
    "accepted": "Accepted",
    "accepted_downweighted": "Downweighted",
    "statistically_quarantined": "Statistical quarantine",
    "trust_quarantined": "Trust quarantine",
}
STATUS_COLORS = {
    "accepted": "#2e7d32",
    "accepted_downweighted": "#f9a825",
    "statistically_quarantined": "#ef6c00",
    "trust_quarantined": "#c62828",
}
POLICIES = ("tpm_only", "statistics_only", "sequential", "gated_composite")


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
    output: Path,
    *,
    enabled: bool,
    source_bundle_id: str,
    source_manifest_sha256: str,
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
        manifest.get("artifact_type")
        != "published_m6_live_contribution_explanations_manifest"
        or manifest.get("source_explanation_bundle_id") != source_bundle_id
        or manifest.get("source_explanation_manifest_sha256")
        != source_manifest_sha256
    ):
        raise RuntimeError("existing snapshot belongs to a different source bundle")
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
            raise RuntimeError(f"existing snapshot changed after publication: {name}")
    return True


def _portable_verification_receipt(
    verification: dict[str, Any], *, source_workspace: Path
) -> dict[str, Any]:
    """Remove host-specific paths from the thesis-facing verifier receipt."""
    receipt = {
        key: value for key, value in verification.items() if key != "workspace"
    }
    receipt["source_workspace_name"] = source_workspace.name
    return receipt


def _figure_bytes(figure: plt.Figure) -> bytes:
    output = io.BytesIO()
    figure.savefig(
        output,
        format="png",
        dpi=180,
        bbox_inches="tight",
        metadata={"Software": "fl-forensics"},
    )
    plt.close(figure)
    return output.getvalue()


def _status_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item["final_status"]) for item in items)
    return {status: counts[status] for status in STATUSES}


def _decision_rows(explanations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in explanations:
        treatment = item["aggregation_treatment"]
        counterfactual = item["counterfactual"]
        rows.append(
            {
                "round": item["round_number"],
                "client_id": item["client_id"],
                "source_decision_id": item["source_decision_id"],
                "source_decision_sha256": item["source_decision_sha256"],
                "source_bundle_id": item["source_bundle_id"],
                "source_bundle_sha256": item["source_bundle_sha256"],
                "source_update_sha256": item["source_update_sha256"],
                "final_status": item["final_status"],
                "trust_raw_status": item["trust"]["raw_status"],
                "trust_admissible": item["trust"]["admissible"],
                "trust_risk": item["trust"]["risk"],
                "failed_checks": ";".join(item["trust"]["failed_checks"]),
                "statistical_risk": item["statistical_risk"],
                "statistical_risk_rank": item["statistical_risk_rank_in_round"],
                "composite_score": item["composite_score"],
                "downweight_threshold": item["composite_downweight_threshold"],
                "quarantine_threshold": item["composite_quarantine_threshold"],
                "headroom_to_full_acceptance": item[
                    "signed_headroom_to_full_acceptance"
                ],
                "headroom_to_quarantine": item["signed_headroom_to_quarantine"],
                "validation_base_minus_client_macro_f1": item[
                    "validation_base_minus_client_macro_f1"
                ],
                "nominal_weight": treatment["nominal_weight_decimal"],
                "effective_weight": treatment["effective_weight_decimal"],
                "retained_weight_fraction": treatment["retained_weight_fraction"],
                "included_in_checkpoint": treatment["included_in_checkpoint"],
                "update_l2": treatment["update_l2"],
                "cosine_to_effective_aggregate": treatment[
                    "cosine_to_effective_aggregate"
                ],
                "admitted_aggregate_influence_l2": treatment[
                    "admitted_aggregate_influence_l2"
                ],
                "full_weight_counterfactual_shift_l2": treatment[
                    "full_weight_counterfactual_aggregate_shift_l2"
                ],
                "prior_downweight_count": item["prior_downweight_count"],
                "prior_quarantine_count": item["prior_quarantine_count"],
                "trust_remediation_required": counterfactual[
                    "trust_remediation_required"
                ],
                "composite_reduction_for_nonzero_weight": counterfactual[
                    "composite_reduction_for_nonzero_weight"
                ],
                "composite_reduction_for_full_weight": counterfactual[
                    "composite_reduction_for_full_weight"
                ],
                "statistical_reduction_for_nonzero_weight": counterfactual[
                    "statistical_reduction_for_nonzero_weight"
                ],
                "statistical_reduction_for_full_weight": counterfactual[
                    "statistical_reduction_for_full_weight"
                ],
            }
        )
    return rows


def _policy_rows(explanations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in explanations:
        for decision in item["policy_explanations"]:
            grouped[str(decision["policy"])].append(decision)
    rows: list[dict[str, Any]] = []
    for policy in POLICIES:
        items = grouped[policy]
        counts = Counter(str(item["status"]) for item in items)
        scores = [float(item["score"]) for item in items]
        rows.append(
            {
                "policy": policy,
                "decision_count": len(items),
                "contributing_count": sum(bool(item["contributes"]) for item in items),
                "accepted": counts["accepted"],
                "accepted_downweighted": counts["accepted_downweighted"],
                "statistically_quarantined": counts["statistically_quarantined"],
                "trust_quarantined": counts["trust_quarantined"],
                "hard_trust_veto_count": sum(
                    bool(item["hard_trust_veto_applied"]) for item in items
                ),
                "mean_score": fmean(scores),
                "minimum_score": min(scores),
                "maximum_score": max(scores),
            }
        )
    return rows


def _tensor_rows(explanations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in explanations:
        for rank, driver in enumerate(item["top_tensor_drivers"], start=1):
            rows.append(
                {
                    "round": item["round_number"],
                    "client_id": item["client_id"],
                    "final_status": item["final_status"],
                    "rank": rank,
                    "tensor_name": driver["tensor_name"],
                    "parameter_count": driver["parameter_count"],
                    "update_l2": driver["update_l2"],
                    "median_distance_l2": driver["median_distance_l2"],
                    "squared_median_distance_fraction": driver[
                        "squared_median_distance_fraction"
                    ],
                    "median_absolute_standardized_deviation": driver[
                        "median_absolute_standardized_deviation"
                    ],
                }
            )
    return rows


def _representative_cases(
    explanations: list[dict[str, Any]],
) -> list[tuple[str, str, dict[str, Any]]]:
    grouped = {
        status: [item for item in explanations if item["final_status"] == status]
        for status in STATUSES
    }
    selections = [
        (
            "accepted-nearest-quarantine",
            "Highest composite score among full-weight accepted contributions",
            max(grouped["accepted"], key=lambda item: (item["composite_score"], -item["round_number"], item["client_id"])),
        ),
        (
            "downweighted-nearest-full-weight",
            "Smallest score excess above the full-weight threshold",
            min(
                grouped["accepted_downweighted"],
                key=lambda item: (
                    -item["signed_headroom_to_full_acceptance"],
                    item["round_number"],
                    item["client_id"],
                ),
            ),
        ),
        (
            "statistical-quarantine-nearest-boundary",
            "Smallest score excess above the quarantine threshold with admissible trust",
            max(
                grouped["statistically_quarantined"],
                key=lambda item: (
                    item["signed_headroom_to_quarantine"],
                    -item["round_number"],
                    item["client_id"],
                ),
            ),
        ),
        (
            "trust-statistics-disagreement",
            "Lowest statistical risk among hard trust quarantines",
            min(
                grouped["trust_quarantined"],
                key=lambda item: (
                    item["statistical_risk"],
                    item["round_number"],
                    item["client_id"],
                ),
            ),
        ),
    ]
    return selections


def _case_studies_bytes(
    cases: list[tuple[str, str, dict[str, Any]]],
) -> bytes:
    lines = [
        "# Deterministic live M6 decision case studies",
        "",
        "These cases are selected by declared rules over the verified explanation payload;",
        "they are not hand-picked after inspecting attack labels or test performance.",
        "",
    ]
    for case_id, rule, item in cases:
        treatment = item["aggregation_treatment"]
        counterfactual = item["counterfactual"]
        lines.extend(
            [
                f"## {case_id}",
                "",
                f"Selection rule: {rule}.",
                "",
                f"- Slot: round {item['round_number']}, `{item['client_id']}`",
                f"- Final status: `{item['final_status']}`",
                f"- Trust admissible: `{str(item['trust']['admissible']).lower()}`",
                f"- Statistical risk: `{float(item['statistical_risk']):.9f}`",
                f"- Composite score: `{float(item['composite_score']):.9f}`",
                f"- Full-weight / quarantine thresholds: `{float(item['composite_downweight_threshold']):.9f}` / `{float(item['composite_quarantine_threshold']):.9f}`",
                f"- Retained FedAvg weight: `{float(treatment['retained_weight_fraction']):.2%}`",
                f"- Actual / full-weight-counterfactual aggregate shift L2: `{float(treatment['admitted_aggregate_influence_l2']):.9f}` / `{float(treatment['full_weight_counterfactual_aggregate_shift_l2']):.9f}`",
                f"- Trust remediation required: `{str(counterfactual['trust_remediation_required']).lower()}`",
                f"- Decision digest: `{item['source_decision_sha256']}`",
                "",
                "Mechanism explanation:",
                "",
            ]
        )
        lines.extend(f"- {sentence}" for sentence in item["narrative"])
        lines.append("")
    lines.extend(
        [
            "## Interpretation boundary",
            "",
            "These records explain the configured decision mechanism and the measured update",
            "geometry. They do not prove that a client was malicious.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _trajectory_figure(explanations: list[dict[str, Any]]) -> bytes:
    rounds = sorted({int(item["round_number"]) for item in explanations})
    by_round = {
        round_number: [
            item for item in explanations if int(item["round_number"]) == round_number
        ]
        for round_number in rounds
    }
    figure, axes = plt.subplots(2, 1, figsize=(12.0, 8.0), sharex=True)
    bottoms = np.zeros(len(rounds))
    for status in STATUSES:
        values = np.asarray(
            [
                sum(item["final_status"] == status for item in by_round[round_number])
                for round_number in rounds
            ]
        )
        axes[0].bar(
            rounds,
            values,
            bottom=bottoms,
            color=STATUS_COLORS[status],
            label=STATUS_LABELS[status],
        )
        bottoms += values
    axes[0].set_ylabel("Contributions")
    axes[0].set_title("Live M6 deployed decisions by round")
    axes[0].set_yticks(range(0, 16, 3))
    axes[0].grid(axis="y", alpha=0.25)
    axes[0].legend(ncol=2, loc="lower center", bbox_to_anchor=(0.5, -0.28))

    for status in STATUSES:
        items = [item for item in explanations if item["final_status"] == status]
        axes[1].scatter(
            [item["round_number"] for item in items],
            [item["composite_score"] for item in items],
            s=20,
            alpha=0.72,
            color=STATUS_COLORS[status],
            label=STATUS_LABELS[status],
        )
    threshold_by_round = {
        round_number: by_round[round_number][0] for round_number in rounds
    }
    axes[1].plot(
        rounds,
        [
            threshold_by_round[round_number]["composite_downweight_threshold"]
            for round_number in rounds
        ],
        color="#263238",
        linestyle="--",
        linewidth=1.4,
        label="Full-weight threshold",
    )
    axes[1].plot(
        rounds,
        [
            threshold_by_round[round_number]["composite_quarantine_threshold"]
            for round_number in rounds
        ],
        color="#6a1b9a",
        linestyle=":",
        linewidth=1.8,
        label="Quarantine threshold",
    )
    axes[1].set_xlabel("Federated round")
    axes[1].set_ylabel("Gated-composite score")
    axes[1].grid(alpha=0.25)
    axes[1].legend(ncol=3, loc="lower center", bbox_to_anchor=(0.5, -0.36))
    figure.tight_layout()
    return _figure_bytes(figure)


def _client_figure(explanations: list[dict[str, Any]]) -> bytes:
    clients = sorted({str(item["client_id"]) for item in explanations})
    by_client = {
        client: [item for item in explanations if item["client_id"] == client]
        for client in clients
    }
    figure, axes = plt.subplots(2, 1, figsize=(12.5, 8.0), sharex=True)
    bottoms = np.zeros(len(clients))
    for status in STATUSES:
        values = np.asarray(
            [
                sum(item["final_status"] == status for item in by_client[client])
                for client in clients
            ]
        )
        axes[0].bar(
            clients,
            values,
            bottom=bottoms,
            color=STATUS_COLORS[status],
            label=STATUS_LABELS[status],
        )
        bottoms += values
    axes[0].set_ylabel("Decisions across 30 rounds")
    axes[0].set_title("Per-client decision history")
    axes[0].grid(axis="y", alpha=0.25)
    axes[0].legend(ncol=2, loc="lower center", bbox_to_anchor=(0.5, -0.28))

    x = np.arange(len(clients))
    admitted = [
        [
            float(item["aggregation_treatment"]["admitted_aggregate_influence_l2"])
            for item in by_client[client]
            if item["aggregation_treatment"]["included_in_checkpoint"]
        ]
        for client in clients
    ]
    counterfactual = [
        median(
            float(
                item["aggregation_treatment"][
                    "full_weight_counterfactual_aggregate_shift_l2"
                ]
            )
            for item in by_client[client]
        )
        for client in clients
    ]
    axes[1].bar(
        x - 0.2,
        [median(values) if values else 0.0 for values in admitted],
        width=0.4,
        color="#1565c0",
        label="Median actual leave-one-out influence",
    )
    axes[1].bar(
        x + 0.2,
        counterfactual,
        width=0.4,
        color="#8e24aa",
        label="Median full-weight counterfactual shift",
    )
    axes[1].set_ylabel("Aggregate displacement (L2)")
    axes[1].set_xlabel("Client pseudonym")
    axes[1].set_xticks(x, clients, rotation=45, ha="right")
    axes[1].grid(axis="y", alpha=0.25)
    axes[1].legend(loc="lower center", bbox_to_anchor=(0.5, -0.42))
    figure.tight_layout()
    return _figure_bytes(figure)


def _summary(
    *,
    source_manifest: dict[str, Any],
    explanations: list[dict[str, Any]],
    policy_rows: list[dict[str, Any]],
    tensor_rows: list[dict[str, Any]],
    verification: dict[str, Any],
    source_manifest_sha256: str,
) -> dict[str, Any]:
    gate = source_manifest["core"]["gate"]
    counts = _status_counts(explanations)
    nominal = sum(
        float(item["aggregation_treatment"]["nominal_weight_decimal"])
        for item in explanations
    )
    effective = sum(
        float(item["aggregation_treatment"]["effective_weight_decimal"])
        for item in explanations
    )
    tensor_counts = Counter(row["tensor_name"] for row in tensor_rows if row["rank"] == 1)
    risk_by_status: dict[str, dict[str, float | int]] = {}
    influence_by_status: dict[str, dict[str, float | int]] = {}
    for status in STATUSES:
        items = [item for item in explanations if item["final_status"] == status]
        risks = [float(item["statistical_risk"]) for item in items]
        shifts = [
            float(
                item["aggregation_treatment"][
                    "full_weight_counterfactual_aggregate_shift_l2"
                ]
            )
            for item in items
        ]
        risk_by_status[status] = {
            "count": len(items),
            "mean": fmean(risks),
            "median": median(risks),
            "maximum": max(risks),
        }
        influence_by_status[status] = {
            "count": len(items),
            "mean_full_weight_counterfactual_shift_l2": fmean(shifts),
            "median_full_weight_counterfactual_shift_l2": median(shifts),
            "maximum_full_weight_counterfactual_shift_l2": max(shifts),
        }
    return {
        "schema_version": "1.0",
        "artifact_type": "published_m6_live_contribution_explanations_summary",
        "source": {
            "explanation_bundle_id": source_manifest["explanation_bundle_id"],
            "explanation_manifest_sha256": source_manifest_sha256,
            "campaign_id": source_manifest["core"]["source"]["campaign_id"],
            "source_experiment_id": source_manifest["core"]["source"][
                "experiment_id"
            ],
            "decision_inventory_sha256": source_manifest["core"]["source"][
                "decision_inventory_sha256"
            ],
            "update_inventory_sha256": source_manifest["core"]["source"][
                "update_inventory_sha256"
            ],
            "checkpoint_inventory_sha256": source_manifest["core"]["source"][
                "checkpoint_inventory_sha256"
            ],
        },
        "verification": verification,
        "coverage": {
            "round_count": gate["round_count"],
            "client_count": gate["client_count"],
            "explanation_count": gate["explanation_count"],
            "complete_round_client_coverage": gate[
                "complete_round_client_coverage"
            ],
        },
        "deployed_gated_composite": {
            **counts,
            "contributing_count": counts["accepted"]
            + counts["accepted_downweighted"],
            "hard_trust_veto_count": sum(
                bool(item["counterfactual"]["trust_remediation_required"])
                for item in explanations
            ),
            "total_nominal_example_weight": nominal,
            "total_effective_example_weight": effective,
            "overall_retained_example_weight_fraction": effective / nominal,
        },
        "policy_outcomes": policy_rows,
        "statistical_risk_by_deployed_status": risk_by_status,
        "aggregate_influence_by_deployed_status": influence_by_status,
        "most_frequent_top_ranked_tensors": [
            {"tensor_name": name, "top_rank_count": count}
            for name, count in tensor_counts.most_common()
        ],
        "interpretation": {
            "test_data_used_for_explanations": False,
            "attack_labels_used_for_explanations": False,
            "hard_trust_veto_compensable_by_statistics": False,
            "proves_malicious_intent": False,
        },
    }


def _readme_bytes(summary: dict[str, Any]) -> bytes:
    deployed = summary["deployed_gated_composite"]
    verification = summary["verification"]
    source = summary["source"]
    text = f"""# M6 live contribution-decision explanations — verified local test v1

This sanitized snapshot publishes explanations for all **450 contributions** that drove the
30-round live trust/statistical-disagreement campaign `{source['campaign_id']}`. It explains
the training decision itself—acceptance, downweighting, or quarantine—and is distinct from M7
Integrated Gradients, which explains a model prediction for one log window.

## Main result

The deployed `gated_composite` policy produced:

| Treatment | Count | Share |
|---|---:|---:|
| Full-weight accepted | {deployed['accepted']} | {deployed['accepted'] / 450:.2%} |
| Accepted with reduced weight | {deployed['accepted_downweighted']} | {deployed['accepted_downweighted'] / 450:.2%} |
| Statistical quarantine | {deployed['statistically_quarantined']} | {deployed['statistically_quarantined'] / 450:.2%} |
| Hard trust quarantine | {deployed['trust_quarantined']} | {deployed['trust_quarantined'] / 450:.2%} |

Thus {deployed['contributing_count']}/450 updates contributed to FedAvg. Across all rounds, the
effective example weight retained {deployed['overall_retained_example_weight_fraction']:.2%}
of the nominal submitted weight. All {deployed['hard_trust_veto_count']} trust-inadmissible
decisions require trust remediation: the explanation deliberately provides no fictitious
statistical-score reduction that could bypass the TPM prerequisite.

![Decision trajectory and policy thresholds](decision-trajectories.png)

## What one explanation contains

Each row binds the signed decision, Update Bundle, and update digests, then reports:

1. the effective M5 trust checks and all four policy outcomes over the same signals;
2. exact statistical/composite scores and signed distance from full-weight and quarantine
   thresholds;
3. ranked scalar indicators and the three named tensors contributing most to distance from the
   round median;
4. nominal and effective FedAvg weight, leave-one-out influence, and the aggregate shift that
   restoring full weight would produce;
5. prior interventions for that client and an explicit counterfactual boundary.

The four deterministic examples in `case-studies.md` make these fields readable without hiding
the complete 450-row table. In particular, the trust/statistics-disagreement case has a normal
statistical score but zero deployed weight because the hard trust gate fails.

![Client history and aggregate influence](client-treatment-and-influence.png)

## Independent verification

The publication was generated only after the source verifier returned `{verification['status']}`
with `error_count={verification['error_count']}`. It independently reverified the source
campaign and every M6 disagreement round, then recomputed decision mechanics, named tensor
drivers, actual aggregation treatments, and implementation bindings. The content-addressed
source bundle is `{source['explanation_bundle_id']}` with manifest SHA-256
`{source['explanation_manifest_sha256']}`.

## Files

- `summary.json`: compact source bindings, coverage, policy totals, risk, influence, and tensor
  summaries.
- `verification-receipt.json`: successful independent-verification result used before
  publication, with the host-specific workspace path reduced to its portable directory name.
- `decisions.csv`: all 450 deployed decisions with provenance, scores, margins, weights,
  influence, and counterfactual quantities.
- `policy-outcomes.csv`: paired totals for TPM-only, statistics-only, sequential, and deployed
  gated-composite policies.
- `rounds.csv`: decision/risk summary for each of the 30 rounds.
- `clients.csv`: 30-round decision/risk summary for each client pseudonym.
- `tensor-drivers.csv`: the three leading named tensor deviations for every contribution.
- `case-studies.md`: four deterministically selected, human-readable mechanism explanations.
- `decision-trajectories.png`: deployed outcomes and composite scores against both thresholds.
- `client-treatment-and-influence.png`: per-client treatment history and aggregate displacement.
- `manifest.json`: SHA-256 inventory of every published file.

## Scope and limitations

These explanations reconstruct why the configured mechanism acted as it did; they do not prove
malicious intent. Test rows and attack labels never enter explanation generation. The 60 hard
trust failures in this particular source campaign remain declared contract-bound
counterfactuals over otherwise passing observed `swtpm` evidence; the separate real-attestation
campaign is the evidence for an authentic PCR/Quote failure. Models, update tensors, signed
bundles, TPM state, and private keys remain only in ignored `artifacts/` workspaces.
"""
    return text.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--campaign-workspace", type=Path, required=True)
    parser.add_argument("--trust-workspace", type=Path, required=True)
    parser.add_argument("--partition-workspace", type=Path, required=True)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/live-contribution-explanations.yaml"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replace-existing-snapshot", action="store_true")
    arguments = parser.parse_args()

    verification = verify_live_contribution_explanation_bundle(
        workspace=arguments.workspace,
        campaign_workspace=arguments.campaign_workspace,
        trust_workspace=arguments.trust_workspace,
        partition_workspace=arguments.partition_workspace,
        config_path=arguments.config,
    )
    if verification["status"] != "verified":
        raise RuntimeError(
            f"refusing to publish an unverified explanation bundle: {verification['errors']}"
        )
    publication_verification = _portable_verification_receipt(
        verification, source_workspace=arguments.workspace
    )

    source_manifest_path = arguments.workspace / "manifest.json"
    source_manifest = _load(source_manifest_path)
    source_manifest_sha256 = _sha256(source_manifest_path)
    replacement = _authorize_replacement(
        arguments.output,
        enabled=arguments.replace_existing_snapshot,
        source_bundle_id=source_manifest["explanation_bundle_id"],
        source_manifest_sha256=source_manifest_sha256,
    )
    payload = _load(arguments.workspace / "explanations.json")
    index = _load(arguments.workspace / "index.json")
    explanations = list(payload["explanations"])
    if len(explanations) != 450:
        raise RuntimeError("reference live explanation coverage is not 450")

    decision_rows = _decision_rows(explanations)
    policy_rows = _policy_rows(explanations)
    tensor_rows = _tensor_rows(explanations)
    cases = _representative_cases(explanations)
    summary = _summary(
        source_manifest=source_manifest,
        explanations=explanations,
        policy_rows=policy_rows,
        tensor_rows=tensor_rows,
        verification=publication_verification,
        source_manifest_sha256=source_manifest_sha256,
    )

    outputs: dict[str, bytes] = {
        "README.md": _readme_bytes(summary),
        "summary.json": _json_bytes(summary),
        "verification-receipt.json": _json_bytes(publication_verification),
        "decisions.csv": _csv_bytes(list(decision_rows[0]), decision_rows),
        "policy-outcomes.csv": _csv_bytes(list(policy_rows[0]), policy_rows),
        "rounds.csv": _csv_bytes(list(index["rounds"][0]), index["rounds"]),
        "clients.csv": _csv_bytes(list(index["clients"][0]), index["clients"]),
        "tensor-drivers.csv": _csv_bytes(list(tensor_rows[0]), tensor_rows),
        "case-studies.md": _case_studies_bytes(cases),
        "decision-trajectories.png": _trajectory_figure(explanations),
        "client-treatment-and-influence.png": _client_figure(explanations),
    }
    for name, content in outputs.items():
        _write_once(arguments.output / name, content, replace=replacement)

    published_manifest = {
        "schema_version": "1.0",
        "artifact_type": "published_m6_live_contribution_explanations_manifest",
        "source_explanation_bundle_id": source_manifest["explanation_bundle_id"],
        "source_explanation_manifest_sha256": source_manifest_sha256,
        "source_explanations_sha256": source_manifest["core"]["explanations_sha256"],
        "source_index_sha256": source_manifest["core"]["index_sha256"],
        "verification_status": verification["status"],
        "privacy_boundary": (
            "sanitized-derived-results-only-no-models-updates-quotes-or-private-keys"
        ),
        "files": {
            name: {"sha256": _sha256(arguments.output / name), "size_bytes": len(content)}
            for name, content in sorted(outputs.items())
        },
    }
    _write_once(
        arguments.output / "manifest.json",
        _json_bytes(published_manifest),
        replace=replacement,
    )
    print(
        json.dumps(
            {
                "status": "published",
                "workspace": str(arguments.output),
                "source_explanation_bundle_id": source_manifest[
                    "explanation_bundle_id"
                ],
                "round_count": source_manifest["core"]["gate"]["round_count"],
                "client_count": source_manifest["core"]["gate"]["client_count"],
                "explanation_count": len(explanations),
                "file_count": len(outputs) + 1,
                "manifest_sha256": _sha256(arguments.output / "manifest.json"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
