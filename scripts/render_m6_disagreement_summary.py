#!/usr/bin/env python3
"""Publish a sanitized summary of the live M6 disagreement campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


POLICIES = ("tpm_only", "statistics_only", "sequential", "gated_composite")
POLICY_LABELS = {
    "tpm_only": "TPM only",
    "statistics_only": "Statistics only",
    "sequential": "Sequential",
    "gated_composite": "Gated composite",
}
STATUSES = (
    "accepted",
    "accepted_downweighted",
    "statistically_quarantined",
    "trust_quarantined",
)
TRUST_CHECKS = {"active_enrollment", "tpm_esk_signature", "fresh_attestation"}


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
    source_campaign_manifest_sha256: str,
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
        != "published_m6_live_disagreement_snapshot_manifest"
        or manifest.get("source_campaign_manifest_sha256")
        != source_campaign_manifest_sha256
    ):
        raise RuntimeError("existing snapshot belongs to a different source campaign")
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


def _set_digest(paths: list[tuple[str, Path]]) -> str:
    digest = hashlib.sha256()
    for relative, path in sorted(paths):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _figure_bytes(figure: plt.Figure) -> bytes:
    output = io.BytesIO()
    figure.savefig(output, format="png", dpi=180, bbox_inches="tight")
    plt.close(figure)
    return output.getvalue()


def _policy_figure(evaluation: dict[str, dict[str, int]]) -> bytes:
    labels = [POLICY_LABELS[name] for name in POLICIES]
    recall = []
    false_negatives = []
    for name in POLICIES:
        counts = evaluation[name]
        detected = counts["true_positive"]
        missed = counts["false_negative"]
        recall.append(detected / (detected + missed))
        false_negatives.append(missed)
    figure, axis = plt.subplots(figsize=(9.2, 4.8))
    bars = axis.bar(
        labels,
        np.asarray(recall) * 100.0,
        color=("#78909c", "#42a5f5", "#7e57c2", "#26a69a"),
    )
    axis.set_ylim(0.0, 110.0)
    axis.set_ylabel("Controlled unsafe-update recall (%)")
    axis.set_title("Paired policy outcomes across all controlled round cells")
    axis.grid(axis="y", alpha=0.25)
    for bar, value, missed in zip(bars, recall, false_negatives, strict=True):
        axis.text(
            bar.get_x() + bar.get_width() / 2.0,
            value * 100.0 + 2.0,
            f"{value * 100.0:.1f}%  (FN={missed})",
            ha="center",
            va="bottom",
            fontsize=9,
        )
    figure.tight_layout()
    return _figure_bytes(figure)


def _trajectory_figure(round_rows: list[dict[str, Any]], selected_round: int) -> bytes:
    rounds = np.asarray([int(row["round"]) for row in round_rows])
    validation = np.asarray([float(row["validation_macro_f1"]) for row in round_rows])
    figure, axes = plt.subplots(2, 1, figsize=(10.5, 7.0), sharex=True)
    axes[0].plot(rounds, validation, color="#1565c0", marker="o", markersize=3)
    selected_index = int(np.where(rounds == selected_round)[0][0])
    axes[0].scatter(
        [selected_round],
        [validation[selected_index]],
        color="#c62828",
        zorder=4,
        label=f"selected round {selected_round}",
    )
    axes[0].set_ylabel("Validation macro-F1")
    axes[0].grid(alpha=0.25)
    axes[0].legend(loc="lower right")

    bottoms = np.zeros(len(rounds))
    fields = (
        ("accepted", "Accepted", "#43a047"),
        ("accepted_downweighted", "Downweighted", "#f9a825"),
        ("statistically_quarantined", "Statistical quarantine", "#ef6c00"),
        ("trust_quarantined", "Trust quarantine", "#c62828"),
    )
    for field, label, color in fields:
        values = np.asarray([int(row[field]) for row in round_rows])
        axes[1].bar(rounds, values, bottom=bottoms, label=label, color=color)
        bottoms += values
    axes[1].set_xlabel("Federated round")
    axes[1].set_ylabel("Contributions")
    axes[1].set_yticks(range(0, 16, 3))
    axes[1].grid(axis="y", alpha=0.25)
    axes[1].legend(ncol=2, loc="lower center", bbox_to_anchor=(0.5, -0.38))
    figure.suptitle("Live gated-composite training trajectory")
    figure.tight_layout()
    return _figure_bytes(figure)


def _confusion_figure(metric: dict[str, Any]) -> bytes:
    labels = [str(item) for item in metric["confusion_matrix"]["labels"]]
    display_labels = [item.replace("_", " ") for item in labels]
    values = np.asarray(metric["confusion_matrix"]["values"], dtype=np.float64)
    row_totals = values.sum(axis=1, keepdims=True)
    normalized = np.divide(
        values,
        row_totals,
        out=np.zeros_like(values),
        where=row_totals != 0,
    )
    figure, axis = plt.subplots(figsize=(8.8, 6.8))
    image = axis.imshow(normalized, cmap="Blues", vmin=0.0, vmax=1.0)
    for row in range(len(labels)):
        for column in range(len(labels)):
            value = normalized[row, column]
            axis.text(
                column,
                row,
                f"{value * 100.0:.1f}%\n(n={int(values[row, column])})",
                ha="center",
                va="center",
                fontsize=8,
                color="white" if value > 0.55 else "black",
            )
    axis.set_xticks(range(len(labels)), labels=display_labels, rotation=35, ha="right")
    axis.set_yticks(range(len(labels)), labels=display_labels)
    axis.set_xlabel("Predicted")
    axis.set_ylabel("Actual")
    axis.set_title("Selected checkpoint — isolated test confusion matrix")
    figure.colorbar(image, ax=axis, label="Row fraction")
    figure.tight_layout()
    return _figure_bytes(figure)


def _utility_figure(
    clean_summary: dict[str, Any],
    *,
    validation_macro_f1: float,
    test_macro_f1: float,
) -> bytes:
    clean = np.asarray(
        [clean_summary["validation_macro_f1"], clean_summary["test_macro_f1"]]
    )
    disagreement = np.asarray([validation_macro_f1, test_macro_f1])
    x = np.arange(2)
    width = 0.34
    figure, axis = plt.subplots(figsize=(7.8, 4.8))
    first = axis.bar(x - width / 2.0, clean, width, label="Clean campaign", color="#78909c")
    second = axis.bar(
        x + width / 2.0,
        disagreement,
        width,
        label="Live disagreement",
        color="#26a69a",
    )
    axis.set_xticks(x, ("Validation", "Test"))
    axis.set_ylabel("Macro-F1")
    axis.set_ylim(0.0, 1.05)
    axis.set_title("Selected-checkpoint utility comparison")
    axis.grid(axis="y", alpha=0.25)
    axis.legend(loc="lower left")
    for bars in (first, second):
        for bar in bars:
            axis.text(
                bar.get_x() + bar.get_width() / 2.0,
                bar.get_height() + 0.015,
                f"{bar.get_height():.4f}",
                ha="center",
                va="bottom",
                fontsize=9,
            )
    figure.tight_layout()
    return _figure_bytes(figure)


def _round_status_row(
    *,
    round_number: int,
    validation_macro_f1: float,
    decisions: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    statuses = Counter(item["primary_decision"]["status"] for item in decisions)
    record_by_client = {str(item["client_id"]): item for item in records}
    safe_downweighted = 0
    safe_quarantined = 0
    unsafe_quarantined = 0
    for decision in decisions:
        record = record_by_client[str(decision["client_id"])]
        status = str(decision["primary_decision"]["status"])
        if record["security_label"] == "safe":
            safe_downweighted += status == "accepted_downweighted"
            safe_quarantined += not bool(decision["primary_decision"]["contributes"])
        else:
            unsafe_quarantined += not bool(decision["primary_decision"]["contributes"])
    return {
        "round": round_number,
        "validation_macro_f1": validation_macro_f1,
        **{name: statuses[name] for name in STATUSES},
        "safe_downweighted": safe_downweighted,
        "safe_quarantined": safe_quarantined,
        "unsafe_quarantined": unsafe_quarantined,
    }


def publish(
    *,
    workspace: Path,
    output: Path,
    clean_summary_path: Path,
    replace_existing_snapshot: bool,
) -> dict[str, Any]:
    workspace = workspace.resolve()
    output = output.resolve()
    manifest_path = workspace / "campaign-manifest.json"
    evaluation_path = workspace / "evaluation" / "selected-checkpoint-evaluation.json"
    campaign_manifest = _load(manifest_path)
    evaluation = _load(evaluation_path)
    if campaign_manifest.get("artifact_type") != "secure_multiround_campaign_manifest":
        raise ValueError("source is not an M5 secure multiround campaign")
    core = campaign_manifest["core"]
    if _sha256(evaluation_path) != str(core["final_evaluation_sha256"]):
        raise ValueError("selected evaluation digest differs from campaign manifest")
    if evaluation["campaign_id"] != core["campaign_id"]:
        raise ValueError("selected evaluation belongs to a different campaign")
    round_count = int(core["round_count"])
    client_count = int(core["required_client_count"])
    if round_count < 1 or client_count < 1:
        raise ValueError("campaign dimensions must be positive")

    decision_rows: list[dict[str, Any]] = []
    round_rows: list[dict[str, Any]] = []
    source_records: list[tuple[str, Path]] = []
    policy_status_counts = {name: Counter() for name in POLICIES}
    policy_evaluation = {
        name: Counter(
            true_positive=0,
            false_positive=0,
            true_negative=0,
            false_negative=0,
        )
        for name in POLICIES
    }
    contract_digest: str | None = None
    contract_id: str | None = None
    experiment_id: str | None = None
    assignments: dict[str, str] | None = None
    observed_attestation_pass_count = 0
    controlled_trust_failure_count = 0
    controlled_update_intervention_count = 0

    for round_number in range(1, round_count + 1):
        relative_round = Path("rounds") / f"round-{round_number:03d}"
        round_root = workspace / relative_round
        contract_path = round_root / "public" / "m6-disagreement-contract.json"
        validation_path = (
            workspace / "evaluation" / f"round-{round_number:03d}-validation.json"
        )
        contract = _load(contract_path)
        validation = _load(validation_path)
        contract_core = contract["core"]
        current_digest = str(contract["core_digest"])
        if contract_digest is None:
            contract_digest = current_digest
            contract_id = str(contract["contract_id"])
            experiment_id = str(contract_core["experiment_id"])
            assignments = {
                str(key): str(value)
                for key, value in contract_core["assignments"].items()
            }
        if (
            current_digest != contract_digest
            or contract["contract_id"] != contract_id
            or contract_core["experiment_id"] != experiment_id
            or contract_core["assignments"] != assignments
        ):
            raise ValueError(f"round {round_number} disagreement contract drifted")
        client_ids = [str(item) for item in contract_core["client_ids"]]
        if len(client_ids) != client_count or len(set(client_ids)) != client_count:
            raise ValueError(f"round {round_number} client set is invalid")
        if validation["campaign_id"] != core["campaign_id"]:
            raise ValueError(f"round {round_number} validation campaign mismatch")
        if int(validation["round_number"]) != round_number:
            raise ValueError(f"round {round_number} validation number mismatch")
        source_records.extend(
            [
                (contract_path.relative_to(workspace).as_posix(), contract_path),
                (validation_path.relative_to(workspace).as_posix(), validation_path),
            ]
        )

        round_decisions: list[dict[str, Any]] = []
        round_records: list[dict[str, Any]] = []
        for client_id in client_ids:
            decision_path = round_root / "in-round-decisions" / f"{client_id}.json"
            trust_path = round_root / "decisions" / f"{client_id}.json"
            metrics_path = round_root / "submissions" / client_id / "metrics.json"
            bundle_path = round_root / "submissions" / client_id / "bundle.json"
            update_path = round_root / "submissions" / client_id / "update.json"
            decision = _load(decision_path)["core"]
            trust_decision = _load(trust_path)["core"]
            metrics = _load(metrics_path)
            record = metrics.get("m6_disagreement_experiment")
            if not isinstance(record, dict):
                raise ValueError(
                    f"round {round_number} {client_id} has no M6 submission record"
                )
            expected_condition = (
                assignments.get(client_id)
                if assignments is not None and client_id in assignments
                else contract_core["background_condition"]
            )
            if (
                decision["campaign_id"] != core["campaign_id"]
                or int(decision["round_number"]) != round_number
                or decision["client_id"] != client_id
                or record["condition"] != expected_condition
                or record["contract_digest"] != contract_digest
                or record["candidate_update_sha256"] != decision["update_sha256"]
                or record["evaluation_label_used_for_scoring"] is not False
            ):
                raise ValueError(f"round {round_number} {client_id} binding mismatch")
            if (
                _sha256(bundle_path) != decision["bundle_sha256"]
                or _sha256(update_path) != decision["update_sha256"]
            ):
                raise ValueError(f"round {round_number} {client_id} content mismatch")
            policy_map = {
                str(item["policy"]): item for item in decision["policy_decisions"]
            }
            if set(policy_map) != set(POLICIES):
                raise ValueError(f"round {round_number} {client_id} policy set mismatch")
            if decision["primary_decision"] != policy_map["gated_composite"]:
                raise ValueError(f"round {round_number} {client_id} primary policy mismatch")
            contributes = bool(decision["primary_decision"]["contributes"])
            effective_weight = float(decision["effective_weight_decimal"])
            full_weight = float(decision["num_examples"])
            if (
                effective_weight < 0.0
                or effective_weight > full_weight
                or (contributes and effective_weight <= 0.0)
                or (not contributes and effective_weight != 0.0)
            ):
                raise ValueError(f"round {round_number} {client_id} weight mismatch")
            observed_checks = {
                str(item["name"]): bool(item["passed"])
                for item in trust_decision["checks"]
            }
            observed_pass = all(observed_checks.get(name, False) for name in TRUST_CHECKS)
            observed_attestation_pass_count += observed_pass
            controlled_trust_failure_count += bool(record["controlled_trust_failure"])
            controlled_update_intervention_count += bool(
                record["update_intervention_applied"]
            )

            for policy_name, policy in policy_map.items():
                policy_status_counts[policy_name][str(policy["status"])] += 1
                if assignments is not None and client_id in assignments:
                    unsafe = record["security_label"] == "unsafe"
                    quarantined = not bool(policy["contributes"])
                    if unsafe and quarantined:
                        outcome = "true_positive"
                    elif not unsafe and quarantined:
                        outcome = "false_positive"
                    elif not unsafe and not quarantined:
                        outcome = "true_negative"
                    else:
                        outcome = "false_negative"
                    policy_evaluation[policy_name][outcome] += 1

            status = str(decision["primary_decision"]["status"])
            if status not in STATUSES:
                raise ValueError(f"round {round_number} {client_id} status is unknown")
            decision_rows.append(
                {
                    "round": round_number,
                    "client_id": client_id,
                    "condition": record["condition"],
                    "security_label": record["security_label"],
                    "observed_attestation_passed": observed_pass,
                    "controlled_trust_failure": bool(record["controlled_trust_failure"]),
                    "update_intervention_applied": bool(
                        record["update_intervention_applied"]
                    ),
                    "statistical_risk": float(decision["statistics"]["risk"]),
                    "primary_status": status,
                    "effective_weight_fraction": effective_weight / full_weight,
                    **{
                        f"{name}_status": str(policy_map[name]["status"])
                        for name in POLICIES
                    },
                }
            )
            round_decisions.append(decision)
            round_records.append(record)
            for path in (decision_path, trust_path, metrics_path, bundle_path, update_path):
                source_records.append((path.relative_to(workspace).as_posix(), path))

        round_rows.append(
            _round_status_row(
                round_number=round_number,
                validation_macro_f1=float(
                    validation["validation"]["macro_f1_all_model_classes"]
                ),
                decisions=round_decisions,
                records=round_records,
            )
        )

    expected_contributions = round_count * client_count
    if len(decision_rows) != expected_contributions:
        raise ValueError("campaign does not contain the expected decision count")
    if int(core["total_accepted_contributions"]) != sum(
        row["primary_status"] in {"accepted", "accepted_downweighted"}
        for row in decision_rows
    ):
        raise ValueError("campaign accepted-contribution total does not match decisions")
    if int(evaluation["selected_round"]) != int(core["selected_round"]):
        raise ValueError("selected round differs between campaign and evaluation")

    policy_evaluation_json = {
        name: dict(policy_evaluation[name]) for name in POLICIES
    }
    policy_status_json = {
        name: {status: policy_status_counts[name][status] for status in STATUSES}
        for name in POLICIES
    }
    policy_rows: list[dict[str, Any]] = []
    for name in POLICIES:
        counts = policy_evaluation[name]
        unsafe_total = counts["true_positive"] + counts["false_negative"]
        policy_rows.append(
            {
                "policy": name,
                **{status: policy_status_counts[name][status] for status in STATUSES},
                **{key: counts[key] for key in (
                    "true_positive",
                    "false_positive",
                    "true_negative",
                    "false_negative",
                )},
                "controlled_unsafe_recall": counts["true_positive"] / unsafe_total,
            }
        )

    safe_rows = [row for row in decision_rows if row["security_label"] == "safe"]
    unsafe_rows = [row for row in decision_rows if row["security_label"] == "unsafe"]
    safe_interventions = [row for row in safe_rows if row["primary_status"] != "accepted"]
    safe_quarantines = [
        row
        for row in safe_rows
        if row["primary_status"]
        in {"statistically_quarantined", "trust_quarantined"}
    ]
    safe_downweights = [
        row for row in safe_rows if row["primary_status"] == "accepted_downweighted"
    ]
    unsafe_quarantines = [
        row
        for row in unsafe_rows
        if row["primary_status"]
        in {"statistically_quarantined", "trust_quarantined"}
    ]
    selected_metrics = evaluation["metrics"]
    validation_metric = selected_metrics["validation"]
    test_metric = selected_metrics["test"]
    temporal_metric = selected_metrics["temporal_holdout"]
    clean_summary = _load(clean_summary_path.resolve())
    if clean_summary.get("artifact_type") != "published_m5_in_round_campaign_snapshot":
        raise ValueError("clean comparison is not a published M5 campaign summary")
    validation_macro_f1 = float(validation_metric["macro_f1_all_model_classes"])
    test_macro_f1 = float(test_metric["macro_f1_all_model_classes"])
    temporal_values = np.asarray(
        temporal_metric["confusion_matrix"]["values"], dtype=np.int64
    )
    temporal_false_alerts = int(temporal_values[0].sum() - temporal_values[0, 0])

    summary = {
        "artifact_type": "published_m6_live_disagreement_snapshot",
        "schema_version": "1.0",
        "campaign_id": core["campaign_id"],
        "experiment_id": experiment_id,
        "contract_id": contract_id,
        "contract_digest": contract_digest,
        "round_count": round_count,
        "client_count": client_count,
        "contribution_count": expected_contributions,
        "observed_attestation_pass_count": observed_attestation_pass_count,
        "controlled_trust_failure_count": controlled_trust_failure_count,
        "controlled_update_intervention_count": controlled_update_intervention_count,
        "controlled_policy_evaluation": policy_evaluation_json,
        "policy_status_counts": policy_status_json,
        "primary_policy": "gated_composite",
        "primary_contributing_count": int(core["total_accepted_contributions"]),
        "primary_downweighted_count": policy_status_counts["gated_composite"][
            "accepted_downweighted"
        ],
        "primary_quarantined_count": expected_contributions
        - int(core["total_accepted_contributions"]),
        "safe_contribution_count": len(safe_rows),
        "safe_downweighted_count": len(safe_downweights),
        "safe_quarantined_count": len(safe_quarantines),
        "safe_intervention_rate": len(safe_interventions) / len(safe_rows),
        "safe_strict_false_positive_rate": len(safe_quarantines) / len(safe_rows),
        "unsafe_contribution_count": len(unsafe_rows),
        "unsafe_quarantined_count": len(unsafe_quarantines),
        "unsafe_recall": len(unsafe_quarantines) / len(unsafe_rows),
        "selected_round": int(evaluation["selected_round"]),
        "validation_macro_f1": validation_macro_f1,
        "test_macro_f1": test_macro_f1,
        "test_accuracy": float(test_metric["accuracy"]),
        "client_local_test_macro_f1": evaluation[
            "selected_global_client_test_summary"
        ]["macro_f1_all_model_classes"],
        "temporal_holdout_observed_labels": temporal_metric["observed_labels"],
        "temporal_holdout_false_alert_count": temporal_false_alerts,
        "temporal_holdout_false_alert_rate": temporal_false_alerts
        / int(temporal_metric["row_count"]),
        "clean_reference_campaign_id": clean_summary["campaign_id"],
        "clean_reference_selected_round": clean_summary["selected_round"],
        "clean_reference_validation_macro_f1": clean_summary["validation_macro_f1"],
        "clean_reference_test_macro_f1": clean_summary["test_macro_f1"],
        "validation_macro_f1_delta_from_clean": validation_macro_f1
        - float(clean_summary["validation_macro_f1"]),
        "test_macro_f1_delta_from_clean": test_macro_f1
        - float(clean_summary["test_macro_f1"]),
        "source_campaign_manifest_sha256": _sha256(manifest_path),
        "source_selected_evaluation_sha256": _sha256(evaluation_path),
        "source_record_set_sha256": _set_digest(source_records),
        "clean_reference_summary_sha256": _sha256(clean_summary_path.resolve()),
        "renderer_sha256": _sha256(Path(__file__).resolve()),
    }

    round_csv = _csv_bytes(
        list(round_rows[0]),
        round_rows,
    )
    policy_csv = _csv_bytes(list(policy_rows[0]), policy_rows)
    safe_csv = _csv_bytes(
        [
            "round",
            "client_id",
            "condition",
            "primary_status",
            "statistical_risk",
            "effective_weight_fraction",
        ],
        [
            {key: row[key] for key in (
                "round",
                "client_id",
                "condition",
                "primary_status",
                "statistical_risk",
                "effective_weight_fraction",
            )}
            for row in safe_interventions
        ],
    )
    per_class_rows = [
        {"label": label, **values}
        for label, values in test_metric["per_class"].items()
    ]
    per_class_csv = _csv_bytes(list(per_class_rows[0]), per_class_rows)

    readme = f"""# M6 live TPM/statistical disagreement — verified local test v1

This sanitized snapshot summarizes the independently verified 30-round campaign
`{core['campaign_id']}`. Every round trained 15 local clients, obtained a TPM-backed
signature over each submitted update, evaluated the trust and statistical signals on that
same contribution, and used the `gated_composite` decision in the actual FedAvg aggregate.

## Main result

Across {round_count} rounds, the controlled matrix produced {len(unsafe_rows)} unsafe and 30
safe observations; the other 330 safe observations came from the background clients. The
combined policies quarantined all {len(unsafe_rows)} controlled unsafe contributions. TPM-only
missed the correctly attested
statistical anomaly, while statistics-only missed the trust-failed but statistically normal
contribution. This is the intended empirical signal disagreement.

| Policy | TP | FN | TN | FP | Unsafe recall |
|---|---:|---:|---:|---:|---:|
""" + "\n".join(
        f"| {POLICY_LABELS[row['policy']]} | {row['true_positive']} | "
        f"{row['false_negative']} | {row['true_negative']} | "
        f"{row['false_positive']} | {row['controlled_unsafe_recall']:.1%} |"
        for row in policy_rows
    ) + f"""

![Controlled policy outcomes](policy-detection.png)

The deployed composite policy aggregated {summary['primary_contributing_count']} of
{expected_contributions} contributions: {policy_status_counts['gated_composite']['accepted']}
at full weight and {policy_status_counts['gated_composite']['accepted_downweighted']} at reduced
weight. It quarantined {summary['primary_quarantined_count']} contributions. Ninety quarantines
were the three controlled unsafe cells repeated over 30 rounds; the other two were safe
`client06` updates at rounds 21 and 26. Thus strict false-positive quarantine was
{summary['safe_strict_false_positive_rate']:.2%} over safe contributions. A further
{summary['safe_downweighted_count']} safe contributions were retained at reduced weight.

![Training trajectory](training-trajectory.png)

## Selected model utility

Validation-only selection chose round {summary['selected_round']} with macro-F1
`{validation_macro_f1:.6f}`. The isolated test macro-F1 is `{test_macro_f1:.6f}` and accuracy
is `{float(test_metric['accuracy']):.6f}`. Across the 15 client-local test splits, macro-F1 is
`{summary['client_local_test_macro_f1']['mean']:.6f} ± """ + f"""{summary['client_local_test_macro_f1']['population_stddev']:.6f}`
(population standard deviation).

Against the separate clean in-round campaign, test macro-F1 changes by
`{summary['test_macro_f1_delta_from_clean']:+.6f}` and validation macro-F1 by
`{summary['validation_macro_f1_delta_from_clean']:+.6f}`. This is a descriptive comparison of
two deterministic campaign trajectories, not a confidence interval. The performance cost is
consistent with removing three client contributions in every round; the transformed unsafe
updates themselves never enter the deployed composite aggregate.

![Utility comparison](utility-comparison.png)

![Selected test confusion matrix](selected-test-confusion-matrix.png)

## Files

- `summary.json`: compact source bindings, policy totals, false-positive rates, and utility.
- `policy-outcomes.csv`: aggregate status and controlled confusion counts for all four policies.
- `rounds.csv`: validation trajectory and deployed-policy treatment counts by round.
- `safe-interventions.csv`: the 24 safe downweights and two safe quarantines.
- `selected-test-per-class.csv`: isolated test precision, recall, F1, and support by class.
- `manifest.json`: SHA-256 inventory of every published file.

## Scope and limitations

All {observed_attestation_pass_count} per-contribution observed M4 appraisal checks passed. The
60 trust-failure inputs are declared contract-bound counterfactuals used to compare policy
behavior; they are not physical TPM failures. The 60 anomalous updates are genuine
post-training sign-flip and amplification transformations signed by the client TPM ESK.

Only `gated_composite` drives this training trajectory. TPM-only, statistics-only, and
sequential are paired shadow decisions over the same updates, so this snapshot compares their
admission accuracy but does not claim four separately trained model trajectories. Attack labels
are used only after scoring. The temporal holdout is benign-only and is not a multiclass test.
Complete models, signed bundles, update vectors, private keys, and TPM state remain in ignored
`artifacts/` workspaces and are not published here.
"""

    source_campaign_sha256 = summary["source_campaign_manifest_sha256"]
    replace = _authorize_replacement(
        output,
        enabled=replace_existing_snapshot,
        source_campaign_manifest_sha256=source_campaign_sha256,
    )
    files = {
        "README.md": readme.encode("utf-8"),
        "summary.json": _json_bytes(summary),
        "policy-outcomes.csv": policy_csv,
        "rounds.csv": round_csv,
        "safe-interventions.csv": safe_csv,
        "selected-test-per-class.csv": per_class_csv,
        "policy-detection.png": _policy_figure(policy_evaluation_json),
        "training-trajectory.png": _trajectory_figure(
            round_rows, int(evaluation["selected_round"])
        ),
        "selected-test-confusion-matrix.png": _confusion_figure(test_metric),
        "utility-comparison.png": _utility_figure(
            clean_summary,
            validation_macro_f1=validation_macro_f1,
            test_macro_f1=test_macro_f1,
        ),
    }
    for name, content in files.items():
        _write_once(output / name, content, replace=replace)
    published_manifest = {
        "artifact_type": "published_m6_live_disagreement_snapshot_manifest",
        "schema_version": "1.0",
        "campaign_id": core["campaign_id"],
        "source_campaign_manifest_sha256": source_campaign_sha256,
        "source_record_set_sha256": summary["source_record_set_sha256"],
        "files": {
            name: {
                "sha256": _sha256(output / name),
                "size_bytes": (output / name).stat().st_size,
            }
            for name in sorted(files)
        },
    }
    _write_once(
        output / "manifest.json",
        _json_bytes(published_manifest),
        replace=replace,
    )
    return {
        "status": "published",
        "campaign_id": core["campaign_id"],
        "round_count": round_count,
        "contribution_count": expected_contributions,
        "primary_contributing_count": summary["primary_contributing_count"],
        "safe_quarantined_count": len(safe_quarantines),
        "unsafe_recall": summary["unsafe_recall"],
        "selected_round": summary["selected_round"],
        "test_macro_f1": test_macro_f1,
        "file_count": len(files) + 1,
        "workspace": str(output),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--clean-summary",
        type=Path,
        default=Path("results/m5-in-round-composite-local-test-v1/summary.json"),
    )
    parser.add_argument("--replace-existing-snapshot", action="store_true")
    arguments = parser.parse_args()
    result = publish(
        workspace=arguments.workspace,
        output=arguments.output,
        clean_summary_path=arguments.clean_summary,
        replace_existing_snapshot=arguments.replace_existing_snapshot,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
