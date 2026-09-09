#!/usr/bin/env python3
"""Publish a thesis-oriented snapshot of the live M4/M6 TPM failure run."""

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
import matplotlib.pyplot as plt
import numpy as np

from fl_forensics.byzantine import flatten_delta, model_delta
from fl_forensics.federated_model import arrays_from_export

STATUSES = (
    "accepted",
    "accepted_downweighted",
    "statistically_quarantined",
    "trust_quarantined",
)


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
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
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
        != "published_m4_m6_real_attestation_failure_snapshot_manifest"
        or manifest.get("source_campaign_manifest_sha256") != source_campaign_manifest_sha256
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
            raise RuntimeError(f"existing snapshot file changed: {name}")
    return True


def _validate_verifier_receipt(
    receipt: dict[str, Any],
    *,
    client_id: str,
    result_id: str,
    decision_id: str,
) -> None:
    expected = {
        "status": "verified",
        "target_client_id": client_id,
        "post_attestation_result_id": result_id,
        "decision_id": decision_id,
        "authentic_quote_verified": True,
        "failed_measurement_verified": True,
        "fedavg_exclusion_verified": True,
        "error_count": 0,
        "errors": [],
    }
    mismatches = [name for name, value in expected.items() if receipt.get(name) != value]
    if mismatches:
        raise ValueError(
            "independent real-attestation verifier receipt mismatch: " + ", ".join(mismatches)
        )


def _read_campaign(
    workspace: Path,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    manifest = _load(workspace / "campaign-manifest.json")
    evaluation = _load(workspace / "evaluation/selected-checkpoint-evaluation.json")
    if manifest.get("artifact_type") != "secure_multiround_campaign_manifest":
        raise ValueError("unsupported campaign manifest")
    if evaluation.get("artifact_type") != "secure_campaign_selected_checkpoint_evaluation":
        raise ValueError("unsupported selected-checkpoint evaluation")
    core = manifest["core"]
    if evaluation["campaign_id"] != core["campaign_id"]:
        raise ValueError("campaign/evaluation identity mismatch")
    if int(evaluation["selected_round"]) != int(core["selected_round"]):
        raise ValueError("campaign/evaluation selected-round mismatch")

    metrics: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for round_number in range(1, int(core["round_count"]) + 1):
        metric = _load(workspace / "evaluation" / f"round-{round_number:03d}-validation.json")
        if (
            metric.get("artifact_type") != "secure_round_validation_metrics"
            or metric.get("campaign_id") != core["campaign_id"]
            or int(metric.get("round_number", -1)) != round_number
            or metric.get("test_data_observed") is not False
        ):
            raise ValueError(f"round {round_number} validation binding mismatch")
        metrics.append(metric)
        paths = sorted(
            (workspace / "rounds" / f"round-{round_number:03d}" / "in-round-decisions").glob(
                "client*.json"
            )
        )
        if len(paths) != int(core["required_client_count"]):
            raise ValueError(f"round {round_number} decision count mismatch")
        round_nonzero = 0
        for path in paths:
            artifact = _load(path)
            if artifact.get("artifact_type") != "in_round_contribution_decision":
                raise ValueError(f"unsupported contribution decision: {path}")
            decision = artifact["core"]
            slot = (int(decision["round_number"]), str(decision["client_id"]))
            if slot in seen or slot[0] != round_number:
                raise ValueError(f"duplicate or misplaced contribution decision: {path}")
            if decision["campaign_id"] != core["campaign_id"]:
                raise ValueError(f"decision campaign mismatch: {path}")
            if decision["final_status"] not in STATUSES:
                raise ValueError(f"unsupported contribution status: {path}")
            if float(decision["effective_weight_decimal"]) > 0.0:
                round_nonzero += 1
            seen.add(slot)
            decisions.append(decision)
        expected_nonzero = int(core["rounds"][round_number - 1]["accepted_count"])
        if round_nonzero != expected_nonzero:
            raise ValueError(f"round {round_number} non-zero input count mismatch")
    if sum(float(item["effective_weight_decimal"]) > 0 for item in decisions) != int(
        core["total_accepted_contributions"]
    ):
        raise ValueError("campaign total accepted-contribution count mismatch")
    return manifest, evaluation, metrics, decisions


def _decision_set_sha256(workspace: Path) -> str:
    inventory = [
        {
            "path": path.relative_to(workspace).as_posix(),
            "sha256": _sha256(path),
        }
        for path in sorted(workspace.glob("rounds/round-*/in-round-decisions/client*.json"))
    ]
    return hashlib.sha256(_json_bytes(inventory)).hexdigest()


def _model_arrays(path: Path) -> list[np.ndarray]:
    return arrays_from_export(_load(path), np=np)


def _parameter_distance(first: Path, second: Path) -> dict[str, float]:
    difference = flatten_delta(model_delta(_model_arrays(first), _model_arrays(second)))
    return {
        "l2": float(np.linalg.norm(difference)),
        "maximum_absolute": float(np.max(np.abs(difference))),
    }


def _round_counterfactual(
    round_root: Path,
    *,
    target_client_id: str,
) -> dict[str, float | bool]:
    base = _model_arrays(round_root / "public/base-model.json")
    final = _model_arrays(round_root / "checkpoint/global-model.json")
    clients = sorted(path.stem for path in (round_root / "in-round-decisions").glob("*.json"))
    decisions = {
        client: _load(round_root / "in-round-decisions" / f"{client}.json")["core"]
        for client in clients
    }
    matrix = np.stack(
        [
            flatten_delta(
                model_delta(
                    base,
                    _model_arrays(round_root / "submissions" / client / "update.json"),
                )
            )
            for client in clients
        ]
    )
    effective = np.asarray(
        [float(decisions[client]["effective_weight_decimal"]) for client in clients],
        dtype=np.float64,
    )
    nominal = np.asarray(
        [float(decisions[client]["num_examples"]) for client in clients],
        dtype=np.float64,
    )
    if float(effective.sum()) <= 0.0:
        raise ValueError("round effective FedAvg weight is not positive")
    aggregate = np.einsum("i,ij->j", effective, matrix) / effective.sum()
    target_index = clients.index(target_client_id)
    counterfactual = (
        np.einsum("i,ij->j", effective, matrix) + nominal[target_index] * matrix[target_index]
    ) / (effective.sum() + nominal[target_index])
    observed = flatten_delta(model_delta(base, final))
    return {
        "effective_total_weight": float(effective.sum()),
        "target_nominal_weight": float(nominal[target_index]),
        "target_effective_weight": float(effective[target_index]),
        "target_retained_weight_fraction": float(effective[target_index] / nominal[target_index]),
        "target_update_delta_l2": float(np.linalg.norm(matrix[target_index])),
        "full_weight_counterfactual_aggregate_shift_l2": float(
            np.linalg.norm(counterfactual - aggregate)
        ),
        "actual_checkpoint_reconstruction_error_l2": float(np.linalg.norm(observed - aggregate)),
        "target_has_zero_weight": bool(effective[target_index] == 0.0),
    }


def _figure_bytes(figure: plt.Figure) -> bytes:
    output = io.BytesIO()
    figure.savefig(output, format="png", dpi=180, bbox_inches="tight")
    plt.close(figure)
    return output.getvalue()


def _trajectory_figure(
    rows: list[dict[str, Any]], *, selected_round: int, active_round: int
) -> bytes:
    rounds = np.asarray([int(row["round"]) for row in rows])
    validation = np.asarray([float(row["validation_macro_f1"]) for row in rows])
    figure, axes = plt.subplots(2, 1, figsize=(10.6, 7.2), sharex=True)
    axes[0].plot(rounds, validation, color="#1565c0", marker="o", markersize=3)
    selected_index = int(np.where(rounds == selected_round)[0][0])
    axes[0].scatter(
        [selected_round],
        [validation[selected_index]],
        color="#2e7d32",
        zorder=4,
        label=f"selected round {selected_round}",
    )
    axes[0].axvline(
        active_round,
        color="#c62828",
        linestyle="--",
        label=f"real TPM failure round {active_round}",
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
        values = np.asarray([int(row[field]) for row in rows])
        axes[1].bar(rounds, values, bottom=bottoms, label=label, color=color)
        bottoms += values
    axes[1].set_xlabel("Federated round")
    axes[1].set_ylabel("Contributions")
    axes[1].set_yticks(range(0, 16, 3))
    axes[1].grid(axis="y", alpha=0.25)
    axes[1].legend(ncol=2, loc="lower center", bbox_to_anchor=(0.5, -0.38))
    figure.suptitle("M4 trust gate controlling live M6/FedAvg admission")
    figure.tight_layout()
    return _figure_bytes(figure)


def _paired_figure(summary: dict[str, Any]) -> bytes:
    clean = summary["paired_clean_reference"]
    real = summary["contribution_outcomes"]
    labels = ("Full", "Downweighted", "Stat. quarantine", "Trust quarantine")
    clean_values = (
        clean["accepted_count"],
        clean["downweighted_count"],
        clean["statistically_quarantined_count"],
        clean["trust_quarantined_count"],
    )
    real_values = (
        real["accepted_count"],
        real["downweighted_count"],
        real["statistically_quarantined_count"],
        real["trust_quarantined_count"],
    )
    figure, axes = plt.subplots(1, 2, figsize=(12.0, 4.9))
    x = np.arange(len(labels))
    width = 0.34
    clean_bars = axes[0].bar(
        x - width / 2, clean_values, width, label="Clean", color="#78909c"
    )
    real_bars = axes[0].bar(
        x + width / 2,
        real_values,
        width,
        label="Real TPM failure",
        color="#c62828",
    )
    axes[0].set_xticks(x, labels, rotation=25, ha="right")
    axes[0].set_yscale("symlog", linthresh=1.0)
    axes[0].set_ylabel("Contributions across 30 rounds (symlog scale)")
    axes[0].set_title("Admission outcomes — exact counts")
    axes[0].legend()
    axes[0].grid(axis="y", alpha=0.25)
    for bars, values in ((clean_bars, clean_values), (real_bars, real_values)):
        for bar, value in zip(bars, values, strict=True):
            axes[0].text(
                bar.get_x() + bar.get_width() / 2,
                max(float(value), 0.08),
                str(value),
                ha="center",
                va="bottom",
                fontsize=9,
            )

    parameter = summary["paired_parameter_effect"]
    bars = axes[1].bar(
        ("Before failure\n(round 29)", "After failure\n(round 30)"),
        (
            parameter["pre_intervention_checkpoint_l2_difference"],
            parameter["active_round_checkpoint_l2_difference"],
        ),
        color=("#90a4ae", "#c62828"),
    )
    axes[1].set_ylabel("L2 parameter distance from clean reference")
    axes[1].set_title("Paired checkpoint divergence")
    axes[1].grid(axis="y", alpha=0.25)
    for bar in bars:
        value = bar.get_height()
        axes[1].text(
            bar.get_x() + bar.get_width() / 2,
            value,
            f"{value:.6f}",
            ha="center",
            va="bottom",
        )
    figure.tight_layout()
    return _figure_bytes(figure)


def _confusion_figure(evaluation: dict[str, Any]) -> bytes:
    metrics = evaluation["metrics"]
    names = ("validation", "test", "temporal_holdout")
    titles = ("Validation", "Test", "Temporal holdout\n(benign-only)")
    labels = [str(item) for item in metrics["test"]["confusion_matrix"]["labels"]]
    display = [item.replace("_", " ") for item in labels]
    figure, axes = plt.subplots(1, 3, figsize=(18.0, 5.7))
    for axis, name, title in zip(axes, names, titles, strict=True):
        values = np.asarray(metrics[name]["confusion_matrix"]["values"], dtype=float)
        totals = values.sum(axis=1, keepdims=True)
        normalized = np.divide(values, totals, out=np.zeros_like(values), where=totals != 0)
        image = axis.imshow(normalized, cmap="Blues", vmin=0.0, vmax=1.0)
        for row in range(len(labels)):
            for column in range(len(labels)):
                value = normalized[row, column]
                axis.text(
                    column,
                    row,
                    f"{value * 100:.1f}%",
                    ha="center",
                    va="center",
                    fontsize=7,
                    color="white" if value > 0.55 else "black",
                )
        axis.set_xticks(range(len(labels)), display, rotation=40, ha="right")
        axis.set_yticks(range(len(labels)), display)
        axis.set_title(title)
        axis.set_xlabel("Predicted")
        axis.set_ylabel("Actual")
        figure.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    figure.suptitle(f"Selected checkpoint — round {evaluation['selected_round']} — row-normalized")
    figure.tight_layout()
    return _figure_bytes(figure)


def _chain_figure(chain: dict[str, Any]) -> bytes:
    stages = (
        (
            "1. Pre-training",
            f"M4 attestation\n{chain['initial_attestation']['status']}",
            "#2e7d32",
        ),
        (
            "2. Local training",
            "Update and metrics\ncomputed and ESK-signed",
            "#1565c0",
        ),
        (
            "3. Post-training",
            f"PCR {chain['pcr_mutation']['pcr_index']} extended\nauthentic Quote → failed_measurement",
            "#ef6c00",
        ),
        (
            "4. Aggregation",
            "fresh_attestation failed\ntrust quarantine → FedAvg weight 0",
            "#c62828",
        ),
    )
    figure, axis = plt.subplots(figsize=(14.0, 3.5))
    axis.set_xlim(-0.2, 3.2)
    axis.set_ylim(-0.7, 0.7)
    axis.axis("off")
    for index, (title, body, color) in enumerate(stages):
        axis.text(
            index,
            0,
            f"{title}\n\n{body}",
            ha="center",
            va="center",
            fontsize=10,
            bbox={
                "boxstyle": "round,pad=0.6",
                "facecolor": "white",
                "edgecolor": color,
                "linewidth": 2,
            },
        )
        if index < len(stages) - 1:
            axis.annotate(
                "",
                xy=(index + 0.62, 0),
                xytext=(index + 0.38, 0),
                arrowprops={"arrowstyle": "->", "color": "#455a64", "lw": 1.8},
            )
    figure.tight_layout()
    return _figure_bytes(figure)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--trust-workspace", type=Path, required=True)
    parser.add_argument("--clean-workspace", type=Path, required=True)
    parser.add_argument("--clean-results", type=Path, required=True)
    parser.add_argument("--verification-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--attestation-refresh-interval", type=int, required=True)
    parser.add_argument(
        "--replace-existing-snapshot",
        action="store_true",
        help="replace only a complete snapshot bound to the same campaign manifest",
    )
    arguments = parser.parse_args()
    if arguments.attestation_refresh_interval < 1:
        raise ValueError("attestation refresh interval must be positive")

    manifest, evaluation, metrics, decisions = _read_campaign(arguments.workspace)
    core = manifest["core"]
    first_contract = _load(
        arguments.workspace / "rounds/round-001/public/real-attestation-failure-contract.json"
    )
    contract_core = first_contract["core"]
    active_rounds = [int(item) for item in contract_core["active_rounds"]]
    if len(active_rounds) != 1:
        raise ValueError("publication expects exactly one active failure round")
    active_round = active_rounds[0]
    target = str(contract_core["target_client_id"])
    round_root = arguments.workspace / "rounds" / f"round-{active_round:03d}"
    mutation_path = round_root / "real-attestation-evidence/pcr-mutation.json"
    quote_path = round_root / "real-attestation-evidence/quote-evidence.json"
    post_result_path = round_root / "real-attestation-evidence/attestation-result.json"
    mutation = _load(mutation_path)
    quote = _load(quote_path)
    post_result = _load(post_result_path)
    pre_bundle_path = round_root / "submissions" / target / "pre-reattestation-bundle.json"
    post_bundle_path = round_root / "submissions" / target / "bundle.json"
    pre_bundle = _load(pre_bundle_path)
    post_bundle = _load(post_bundle_path)
    trust_decision_path = round_root / "decisions" / f"{target}.json"
    decision_path = round_root / "in-round-decisions" / f"{target}.json"
    trust_decision = _load(trust_decision_path)
    decision_artifact = _load(decision_path)
    decision = decision_artifact["core"]
    checkpoint_path = round_root / "checkpoint/manifest.json"
    checkpoint = _load(checkpoint_path)
    initial_result_id = str(pre_bundle["core"]["attestation_result_id"])
    initial_result_path = arguments.trust_workspace / "results" / f"{initial_result_id}.json"
    initial_result = _load(initial_result_path)

    if first_contract.get("artifact_type") != "m4_m6_real_attestation_failure_contract":
        raise ValueError("unsupported real-attestation contract")
    if active_round > int(core["round_count"]):
        raise ValueError("failure round is outside the campaign")
    if (
        mutation.get("client_id") != target
        or int(mutation.get("pcr_index", -1)) != int(contract_core["pcr_index"])
        or mutation.get("measurement_sha256") != contract_core["measurement_sha256"]
        or mutation.get("after_sha256")
        != quote["core"]["observed_pcr_values"][str(contract_core["pcr_index"])]
    ):
        raise ValueError("PCR mutation and Quote evidence do not bind")
    if (
        initial_result["core"]["client_id"] != target
        or initial_result["core"]["status"] not in contract_core["expected_initial_statuses"]
    ):
        raise ValueError("initial attestation is not an authorized passing result")
    if (
        post_result["core"]["client_id"] != target
        or post_result["core"]["status"] != contract_core["expected_post_status"]
        or post_result["core"]["challenge_id"] != quote["core"]["challenge_id"]
        or post_result["core"]["ak_key_id"] != quote["core"]["ak_key_id"]
    ):
        raise ValueError("post-training appraisal and Quote do not bind")
    invariant_fields = (
        "base_model_sha256",
        "campaign_id",
        "client_id",
        "context_digest",
        "context_id",
        "enrollment_id",
        "metrics_sha256",
        "node_id",
        "num_examples",
        "round_number",
        "snapshot_sha256",
        "tensor_schema_sha256",
        "update_sha256",
    )
    if any(pre_bundle["core"][name] != post_bundle["core"][name] for name in invariant_fields):
        raise ValueError("post-training re-attestation changed the probe update")
    if post_bundle["core"]["attestation_result_id"] != post_result["result_id"]:
        raise ValueError("final bundle does not bind the failed appraisal")
    failed_m5_checks = [str(item["name"]) for item in decision["m5_checks"] if not item["passed"]]
    accepted_clients = {str(item["client_id"]) for item in checkpoint["core"]["accepted_inputs"]}
    if (
        failed_m5_checks != ["fresh_attestation"]
        or trust_decision["core"]["status"] != "quarantined"
        or decision["final_status"] != "trust_quarantined"
        or decision["trust"]["raw_status"] != "failed_measurement"
        or decision["statistics"] is not None
        or decision["primary_decision"] is not None
        or float(decision["effective_weight_decimal"]) != 0.0
        or target in accepted_clients
    ):
        raise ValueError("trust quarantine/FedAvg exclusion chain is inconsistent")
    chronology = (
        pre_bundle["core"]["generated_at"]
        <= mutation["extended_at"]
        <= quote["core"]["generated_at"]
        <= post_result["core"]["evaluated_at"]
        <= post_bundle["core"]["generated_at"]
        <= decision["decided_at"]
    )
    if not chronology:
        raise ValueError("post-training evidence chronology is invalid")

    receipt = _load(arguments.verification_receipt)
    _validate_verifier_receipt(
        receipt,
        client_id=target,
        result_id=str(post_result["result_id"]),
        decision_id=str(decision_artifact["decision_id"]),
    )

    clean_summary = _load(arguments.clean_results / "summary.json")
    clean_manifest_path = arguments.clean_workspace / "campaign-manifest.json"
    clean_evaluation_path = (
        arguments.clean_workspace / "evaluation/selected-checkpoint-evaluation.json"
    )
    if (
        clean_summary.get("artifact_type") != "published_m5_in_round_campaign_snapshot"
        or clean_summary.get("source_campaign_manifest_sha256") != _sha256(clean_manifest_path)
        or clean_summary.get("source_selected_evaluation_sha256") != _sha256(clean_evaluation_path)
    ):
        raise ValueError("clean public result does not bind the supplied clean workspace")
    clean_evaluation = _load(clean_evaluation_path)
    clean_active_metric = _load(
        arguments.clean_workspace / "evaluation" / f"round-{active_round:03d}-validation.json"
    )["validation"]
    real_active_metric = metrics[active_round - 1]["validation"]

    status_counts = Counter(str(item["final_status"]) for item in decisions)
    round_rows: list[dict[str, Any]] = []
    decision_rows: list[dict[str, Any]] = []
    for round_number, metric in enumerate(metrics, start=1):
        current = [item for item in decisions if int(item["round_number"]) == round_number]
        counts = Counter(str(item["final_status"]) for item in current)
        round_rows.append(
            {
                "round": round_number,
                "validation_macro_f1": f"{float(metric['validation']['macro_f1_all_model_classes']):.12f}",
                "validation_loss": f"{float(metric['validation']['loss']):.12f}",
                "accepted": counts["accepted"],
                "accepted_downweighted": counts["accepted_downweighted"],
                "statistically_quarantined": counts["statistically_quarantined"],
                "trust_quarantined": counts["trust_quarantined"],
                "failure_active": round_number == active_round,
                "selected_checkpoint": round_number == int(evaluation["selected_round"]),
            }
        )
    for item in decisions:
        primary = item.get("primary_decision")
        statistics = item.get("statistics")
        decision_rows.append(
            {
                "round": int(item["round_number"]),
                "client_id": str(item["client_id"]),
                "final_status": str(item["final_status"]),
                "trust_admissible": bool(item["trust"]["admissible"]),
                "trust_raw_status": str(item["trust"]["raw_status"]),
                "failed_trust_checks": ";".join(item["trust"]["failed_checks"]),
                "statistical_risk": ""
                if statistics is None
                else f"{float(statistics['risk']):.12f}",
                "composite_score": "" if primary is None else f"{float(primary['score']):.12f}",
                "nominal_weight": str(item["num_examples"]),
                "effective_weight": str(item["effective_weight_decimal"]),
                "bundle_id": str(item["bundle_id"]),
                "update_sha256": str(item["update_sha256"]),
            }
        )

    counterfactual = _round_counterfactual(round_root, target_client_id=target)
    if (
        not counterfactual["target_has_zero_weight"]
        or float(counterfactual["actual_checkpoint_reconstruction_error_l2"]) > 1e-5
    ):
        raise ValueError("FedAvg reconstruction does not confirm the target exclusion")
    pre_round = active_round - 1
    if pre_round < 1:
        real_pre = round_root / "public/base-model.json"
        clean_pre = (
            arguments.clean_workspace
            / "rounds"
            / f"round-{active_round:03d}"
            / "public/base-model.json"
        )
    else:
        real_pre = (
            arguments.workspace
            / "rounds"
            / f"round-{pre_round:03d}"
            / "checkpoint/global-model.json"
        )
        clean_pre = (
            arguments.clean_workspace
            / "rounds"
            / f"round-{pre_round:03d}"
            / "checkpoint/global-model.json"
        )
    real_active_model = round_root / "checkpoint/global-model.json"
    clean_active_model = (
        arguments.clean_workspace
        / "rounds"
        / f"round-{active_round:03d}"
        / "checkpoint/global-model.json"
    )
    pre_distance = _parameter_distance(clean_pre, real_pre)
    active_distance = _parameter_distance(clean_active_model, real_active_model)

    selected = evaluation["metrics"]
    selected_clean = clean_evaluation["metrics"]
    contribution_count = len(decisions)
    summary = {
        "schema_version": "1.0",
        "artifact_type": "published_m4_m6_real_attestation_failure_snapshot",
        "campaign_id": core["campaign_id"],
        "experiment_id": contract_core["experiment_id"],
        "execution_condition": "single-authentic-post-training-pcr-failure",
        "client_count": core["required_client_count"],
        "round_count": core["round_count"],
        "contribution_count": contribution_count,
        "selected_round": evaluation["selected_round"],
        "active_failure_round": active_round,
        "failure_occurs_after_selected_checkpoint": active_round
        > int(evaluation["selected_round"]),
        "attestation_refresh_interval_rounds": arguments.attestation_refresh_interval,
        "contribution_outcomes": {
            "accepted_count": status_counts["accepted"],
            "downweighted_count": status_counts["accepted_downweighted"],
            "statistically_quarantined_count": status_counts["statistically_quarantined"],
            "trust_quarantined_count": status_counts["trust_quarantined"],
            "contributing_count": status_counts["accepted"]
            + status_counts["accepted_downweighted"],
        },
        "selected_checkpoint_performance": {
            "validation_macro_f1": selected["validation"]["macro_f1_all_model_classes"],
            "test_macro_f1": selected["test"]["macro_f1_all_model_classes"],
            "test_accuracy": selected["test"]["accuracy"],
            "client_local_test_macro_f1": evaluation["selected_global_client_test_summary"][
                "macro_f1_all_model_classes"
            ],
            "temporal_holdout_accuracy": selected["temporal_holdout"]["accuracy"],
            "temporal_holdout_observed_labels": selected["temporal_holdout"]["observed_labels"],
        },
        "target_intervention": {
            "client_id": target,
            "node_id": post_result["core"]["node_id"],
            "pcr_bank": mutation["pcr_bank"],
            "pcr_index": mutation["pcr_index"],
            "pcr_before_sha256": mutation["before_sha256"],
            "pcr_after_sha256": mutation["after_sha256"],
            "measurement_sha256": mutation["measurement_sha256"],
            "initial_attestation_result_id": initial_result["result_id"],
            "initial_attestation_status": initial_result["core"]["status"],
            "post_attestation_result_id": post_result["result_id"],
            "post_attestation_status": post_result["core"]["status"],
            "quote_evidence_id": quote["core"]["evidence_id"],
            "failed_m5_checks": failed_m5_checks,
            "final_status": decision["final_status"],
            "statistics_evaluated": decision["statistics"] is not None,
            "update_sha256": post_bundle["core"]["update_sha256"],
            "update_unchanged_after_reattestation": pre_bundle["core"]["update_sha256"]
            == post_bundle["core"]["update_sha256"],
            "metrics_unchanged_after_reattestation": pre_bundle["core"]["metrics_sha256"]
            == post_bundle["core"]["metrics_sha256"],
            "absent_from_checkpoint_accepted_inputs": target not in accepted_clients,
            **counterfactual,
        },
        "paired_clean_reference": {
            "campaign_id": clean_summary["campaign_id"],
            "accepted_count": clean_summary["accepted_count"],
            "downweighted_count": clean_summary["downweighted_count"],
            "statistically_quarantined_count": clean_summary["quarantined_count"],
            "trust_quarantined_count": 0,
            "contributing_count": clean_summary["contributing_count"],
            "selected_round": clean_summary["selected_round"],
            "validation_macro_f1": clean_summary["validation_macro_f1"],
            "test_macro_f1": clean_summary["test_macro_f1"],
            "test_accuracy": clean_summary["test_accuracy"],
        },
        "paired_metric_effect": {
            "selected_validation_macro_f1_delta": selected["validation"][
                "macro_f1_all_model_classes"
            ]
            - selected_clean["validation"]["macro_f1_all_model_classes"],
            "selected_test_macro_f1_delta": selected["test"]["macro_f1_all_model_classes"]
            - selected_clean["test"]["macro_f1_all_model_classes"],
            "active_round_validation_macro_f1_clean": clean_active_metric[
                "macro_f1_all_model_classes"
            ],
            "active_round_validation_macro_f1_real_failure": real_active_metric[
                "macro_f1_all_model_classes"
            ],
            "active_round_validation_macro_f1_delta": real_active_metric[
                "macro_f1_all_model_classes"
            ]
            - clean_active_metric["macro_f1_all_model_classes"],
            "active_round_validation_loss_clean": clean_active_metric["loss"],
            "active_round_validation_loss_real_failure": real_active_metric["loss"],
            "active_round_validation_loss_delta": real_active_metric["loss"]
            - clean_active_metric["loss"],
        },
        "paired_parameter_effect": {
            "pre_intervention_round": pre_round,
            "pre_intervention_checkpoint_l2_difference": pre_distance["l2"],
            "pre_intervention_checkpoint_max_abs_difference": pre_distance["maximum_absolute"],
            "active_round": active_round,
            "active_round_checkpoint_l2_difference": active_distance["l2"],
            "active_round_checkpoint_max_abs_difference": active_distance["maximum_absolute"],
        },
        "independent_verification": {
            "status": receipt["status"],
            "authentic_quote_verified": receipt["authentic_quote_verified"],
            "failed_measurement_verified": receipt["failed_measurement_verified"],
            "fedavg_exclusion_verified": receipt["fedavg_exclusion_verified"],
            "error_count": receipt["error_count"],
        },
        "source_campaign_manifest_sha256": _sha256(arguments.workspace / "campaign-manifest.json"),
        "source_selected_evaluation_sha256": _sha256(
            arguments.workspace / "evaluation/selected-checkpoint-evaluation.json"
        ),
        "source_decision_set_sha256": _decision_set_sha256(arguments.workspace),
        "source_failure_contract_sha256": _sha256(
            round_root / "public/real-attestation-failure-contract.json"
        ),
        "source_pcr_mutation_sha256": _sha256(mutation_path),
        "source_quote_evidence_sha256": _sha256(quote_path),
        "source_post_attestation_result_sha256": _sha256(post_result_path),
        "source_initial_attestation_result_sha256": _sha256(initial_result_path),
        "source_target_decision_sha256": _sha256(decision_path),
        "source_active_checkpoint_sha256": _sha256(checkpoint_path),
        "source_verification_receipt_sha256": _sha256(arguments.verification_receipt),
        "source_clean_campaign_manifest_sha256": _sha256(clean_manifest_path),
        "renderer_sha256": _sha256(Path(__file__)),
    }

    chain = {
        "schema_version": "1.0",
        "artifact_type": "published_real_attestation_decision_chain",
        "campaign_id": core["campaign_id"],
        "round": active_round,
        "target_client_id": target,
        "phase": contract_core["phase"],
        "initial_attestation": {
            "result_id": initial_result["result_id"],
            "status": initial_result["core"]["status"],
            "challenge_id": initial_result["core"]["challenge_id"],
            "evaluated_at": initial_result["core"]["evaluated_at"],
            "baseline_id": initial_result["core"]["baseline_id"],
            "baseline_version": initial_result["core"]["baseline_version"],
        },
        "local_probe": {
            "pre_reattestation_bundle_id": pre_bundle["bundle_id"],
            "generated_at": pre_bundle["core"]["generated_at"],
            "num_examples": pre_bundle["core"]["num_examples"],
            "update_sha256": pre_bundle["core"]["update_sha256"],
            "metrics_sha256": pre_bundle["core"]["metrics_sha256"],
            "test_labels_used_for_admission": False,
        },
        "pcr_mutation": {
            "event_id": mutation["event_id"],
            "extended_at": mutation["extended_at"],
            "pcr_bank": mutation["pcr_bank"],
            "pcr_index": mutation["pcr_index"],
            "before_sha256": mutation["before_sha256"],
            "measurement_sha256": mutation["measurement_sha256"],
            "after_sha256": mutation["after_sha256"],
        },
        "post_training_quote": {
            "evidence_id": quote["core"]["evidence_id"],
            "challenge_id": quote["core"]["challenge_id"],
            "ak_key_id": quote["core"]["ak_key_id"],
            "generated_at": quote["core"]["generated_at"],
            "quote_format": quote["core"]["quote_format"],
            "pcr_selection": quote["core"]["pcr_selection"],
            "observed_pcr_values": quote["core"]["observed_pcr_values"],
            "raw_quote_omitted_from_public_snapshot": True,
        },
        "post_training_appraisal": {
            "result_id": post_result["result_id"],
            "status": post_result["core"]["status"],
            "evaluated_at": post_result["core"]["evaluated_at"],
            "reasons": post_result["core"]["reasons"],
            "verifier_key_id": post_result["signature"]["key_id"],
        },
        "bundle_rebinding": {
            "post_reattestation_bundle_id": post_bundle["bundle_id"],
            "generated_at": post_bundle["core"]["generated_at"],
            "post_attestation_result_id": post_bundle["core"]["attestation_result_id"],
            "update_unchanged": summary["target_intervention"][
                "update_unchanged_after_reattestation"
            ],
            "metrics_unchanged": summary["target_intervention"][
                "metrics_unchanged_after_reattestation"
            ],
            "esk_key_id": post_bundle["signature"]["key_id"],
        },
        "admission": {
            "decision_id": decision_artifact["decision_id"],
            "decided_at": decision["decided_at"],
            "failed_checks": failed_m5_checks,
            "trust_status": decision["trust"]["raw_status"],
            "statistics_evaluated": False,
            "final_status": decision["final_status"],
            "effective_weight_decimal": decision["effective_weight_decimal"],
        },
        "aggregation": {
            "checkpoint_id": checkpoint["checkpoint_id"],
            "accepted_input_count": checkpoint["core"]["accepted_count"],
            "target_absent_from_accepted_inputs": target not in accepted_clients,
            "full_weight_counterfactual_aggregate_shift_l2": counterfactual[
                "full_weight_counterfactual_aggregate_shift_l2"
            ],
        },
    }

    verifier = {
        "schema_version": "1.0",
        "artifact_type": "published_real_attestation_verification_receipt",
        "source_receipt": receipt,
        "publication_consistency_checks": {
            "campaign_identity_matched": True,
            "single_active_failure_round_matched": True,
            "pre_training_attestation_passed": True,
            "pcr_mutation_bound_to_quote": True,
            "post_training_appraisal_failed_measurement": True,
            "probe_update_unchanged": True,
            "only_fresh_attestation_check_failed": True,
            "statistics_skipped_after_trust_failure": True,
            "target_weight_zero": True,
            "target_absent_from_checkpoint_inputs": True,
            "fedavg_checkpoint_recomputed": True,
        },
    }

    explanation = f"""# Forensic explanation of the real TPM admission failure

## Decision

`{target}` was authorized to train in round {active_round} by the passing M4 result
`{initial_result["result_id"]}`. Its local update was computed over
{pre_bundle["core"]["num_examples"]} training examples and signed by its enrolled TPM ESK.

After local training and before aggregation, PCR {mutation["pcr_index"]} in the
`{mutation["pcr_bank"]}` bank changed from `{mutation["before_sha256"]}` to
`{mutation["after_sha256"]}` after extending measurement
`{mutation["measurement_sha256"]}`. A fresh challenge produced Quote
`{quote["core"]["evidence_id"]}`, authentically signed by the enrolled AK. The Quote therefore
proves the observed changed state; it does not prove compliance with the expected baseline.
The M4 verifier returned signed result `{post_result["result_id"]}` with status
`failed_measurement`.

The pre- and post-reattestation bundles retain the same update digest
`{post_bundle["core"]["update_sha256"]}` and metrics digest
`{post_bundle["core"]["metrics_sha256"]}`. This isolates the treatment variable: the model
update did not change; only the fresh trust evidence changed.

Six of seven M5 checks passed. The only failed check was `fresh_attestation`. M6 therefore
made decision `{decision_artifact["decision_id"]}` with status `trust_quarantined`. Statistical
scoring is deliberately absent (`statistics = null`): the fail-closed trust gate runs before
statistical admission. The nominal FedAvg weight was {counterfactual["target_nominal_weight"]:.0f},
the effective weight was zero, and `{target}` is absent from the 14 accepted checkpoint inputs.

## Aggregation effect

Reconstructing weighted FedAvg from the 15 preserved submissions gives checkpoint error
`{counterfactual["actual_checkpoint_reconstruction_error_l2"]:.9g}` L2. Restoring only this
client at full nominal weight while holding all other round inputs fixed would move the
aggregate by `{counterfactual["full_weight_counterfactual_aggregate_shift_l2"]:.9f}` L2.

Compared with the clean paired campaign, the selected round remains 25 and precedes the
failure. Selected validation macro-F1 and isolated test macro-F1 therefore change by
`{summary["paired_metric_effect"]["selected_validation_macro_f1_delta"]:.9f}` and
`{summary["paired_metric_effect"]["selected_test_macro_f1_delta"]:.9f}`. At round 30 the
validation macro-F1 is unchanged, while validation loss changes by
`{summary["paired_metric_effect"]["active_round_validation_loss_delta"]:.9f}`. The checkpoint
parameter distance from the clean reference rises from
`{pre_distance["l2"]:.9f}` before the intervention to `{active_distance["l2"]:.9f}` after it.

## Interpretation boundary

This single-seed, one-client, one-round swtpm experiment proves that an authentic but
non-conforming post-training TPM Quote is detected and excludes the corresponding signed
update from the real FedAvg checkpoint. It does not establish the average utility cost of
earlier or repeated failures, nor does an unchanged class-level F1 prove that exclusions are
always performance-neutral. Those questions require the planned multi-seed and sensitivity
experiments.
"""

    source_campaign_sha256 = summary["source_campaign_manifest_sha256"]
    replace = _authorize_replacement(
        arguments.output,
        enabled=arguments.replace_existing_snapshot,
        source_campaign_manifest_sha256=source_campaign_sha256,
    )
    arguments.output.mkdir(parents=True, exist_ok=True)
    _write_once(arguments.output / "summary.json", _json_bytes(summary), replace=replace)
    _write_once(
        arguments.output / "attestation-decision-chain.json",
        _json_bytes(chain),
        replace=replace,
    )
    _write_once(
        arguments.output / "verification.json",
        _json_bytes(verifier),
        replace=replace,
    )
    _write_once(
        arguments.output / "rounds.csv",
        _csv_bytes(list(round_rows[0]), round_rows),
        replace=replace,
    )
    _write_once(
        arguments.output / "decisions.csv",
        _csv_bytes(list(decision_rows[0]), decision_rows),
        replace=replace,
    )
    _write_once(
        arguments.output / "target-explanation.md",
        explanation.encode("utf-8"),
        replace=replace,
    )
    _write_once(
        arguments.output / "admission-and-validation.png",
        _trajectory_figure(
            round_rows,
            selected_round=int(evaluation["selected_round"]),
            active_round=active_round,
        ),
        replace=replace,
    )
    _write_once(
        arguments.output / "paired-clean-effect.png",
        _paired_figure(summary),
        replace=replace,
    )
    _write_once(
        arguments.output / "attestation-decision-chain.png",
        _chain_figure(chain),
        replace=replace,
    )
    _write_once(
        arguments.output / "selected-confusion-matrices.png",
        _confusion_figure(evaluation),
        replace=replace,
    )

    readme = f"""# Verified real post-training TPM failure

This sanitized thesis snapshot records a 30-round federated campaign in which a real swtpm
PCR change was introduced for `{target}` after local training and before aggregation in round
{active_round}. An independent verifier confirmed the authentic AK Quote, the signed
`failed_measurement` appraisal, and exclusion from weighted FedAvg.

## Main result

- campaign `{core["campaign_id"]}`; 15 clients, 30 rounds, {contribution_count} signed updates;
- `{target}` first passed M4, trained, produced an ESK-signed update, then failed a fresh M4
  appraisal after PCR {mutation["pcr_index"]} changed;
- only `fresh_attestation` failed; artifact, identity, context, ESK, and tensor checks passed;
- final decision: `trust_quarantined`; statistical scoring was not reached; nominal weight
  {counterfactual["target_nominal_weight"]:.0f}, effective FedAvg weight 0;
- 443/450 contributions retained non-zero weight: {status_counts["accepted"]} full,
  {status_counts["accepted_downweighted"]} downweighted, {status_counts["statistically_quarantined"]}
  statistically quarantined, and one trust-quarantined;
- selected checkpoint: round {evaluation["selected_round"]}; validation macro-F1
  `{selected["validation"]["macro_f1_all_model_classes"]:.6f}`, isolated test macro-F1
  `{selected["test"]["macro_f1_all_model_classes"]:.6f}`, test accuracy
  `{selected["test"]["accuracy"]:.6f}`;
- client-local test macro-F1 mean
  `{evaluation["selected_global_client_test_summary"]["macro_f1_all_model_classes"]["mean"]:.6f}`
  (population standard deviation
  `{evaluation["selected_global_client_test_summary"]["macro_f1_all_model_classes"]["population_stddev"]:.6f}`).

## Paired clean comparison

The clean reference retained 444/450 contributions; this run retained 443/450. The exact
difference is the one trust quarantine for `{target}`. Both runs selected round 25, which is
earlier than the active failure in round {active_round}; consequently their selected
validation/test class metrics are identical. This is expected and must not be reported as a
general claim that TPM exclusion has zero utility cost.

Within round {active_round}, the real and clean checkpoints have the same validation macro-F1
`{real_active_metric["macro_f1_all_model_classes"]:.6f}`, but their loss differs by
`{summary["paired_metric_effect"]["active_round_validation_loss_delta"]:.9f}` and their
parameters differ by `{active_distance["l2"]:.9f}` L2. The exact within-round full-weight
counterfactual shift for `{target}` is
`{counterfactual["full_weight_counterfactual_aggregate_shift_l2"]:.9f}` L2.

The benign-only temporal holdout is reported only as an operational false-alert check. Its
six-class macro-F1 is not a multiclass generalization score because five classes have zero
support.

## Files

- `summary.json`: compact thesis metrics, paired effects, limitations, and source hashes;
- `attestation-decision-chain.json`: sanitized machine-readable M4 → M5/M6 → FedAvg lineage;
- `verification.json`: independent verifier receipt plus publication consistency checks;
- `rounds.csv`: validation and all four treatment counts for every round;
- `decisions.csv`: compact record for all 450 contribution decisions;
- `target-explanation.md`: human-readable forensic explanation of the target decision;
- `attestation-decision-chain.png`: visual sequence from pre-training authorization to zero weight;
- `admission-and-validation.png`: validation and contribution treatments across 30 rounds;
- `paired-clean-effect.png`: paired admission counts and checkpoint parameter divergence;
- `selected-confusion-matrices.png`: row-normalized validation, test, and temporal matrices.

## Scope

This experiment validates enforcement and provenance for one authentic non-conforming Quote.
It uses swtpm, one client, one late round, and one seed. Earlier/repeated failures and
population-level utility effects remain subjects for multi-seed and sensitivity analysis.
The effective runtime attestation refresh cadence was every
{arguments.attestation_refresh_interval} rounds.

Source campaign-manifest SHA-256: `{source_campaign_sha256}`. The remaining source digests are
listed in `summary.json`, and every published file is bound by `manifest.json`.
"""
    _write_once(arguments.output / "README.md", readme.encode("utf-8"), replace=replace)

    published = [
        "README.md",
        "admission-and-validation.png",
        "attestation-decision-chain.json",
        "attestation-decision-chain.png",
        "decisions.csv",
        "paired-clean-effect.png",
        "rounds.csv",
        "selected-confusion-matrices.png",
        "summary.json",
        "target-explanation.md",
        "verification.json",
    ]
    result_manifest = {
        "schema_version": "1.0",
        "artifact_type": "published_m4_m6_real_attestation_failure_snapshot_manifest",
        "source_campaign_manifest_sha256": source_campaign_sha256,
        "source_selected_evaluation_sha256": summary["source_selected_evaluation_sha256"],
        "source_verification_receipt_sha256": summary["source_verification_receipt_sha256"],
        "files": {
            name: {
                "sha256": _sha256(arguments.output / name),
                "size_bytes": (arguments.output / name).stat().st_size,
            }
            for name in published
        },
    }
    _write_once(
        arguments.output / "manifest.json",
        _json_bytes(result_manifest),
        replace=replace,
    )
    print(
        json.dumps(
            {
                "status": "published",
                "campaign_id": core["campaign_id"],
                "target_client_id": target,
                "active_failure_round": active_round,
                "contribution_count": contribution_count,
                "contributing_count": summary["contribution_outcomes"]["contributing_count"],
                "trust_quarantined_count": status_counts["trust_quarantined"],
                "selected_round": evaluation["selected_round"],
                "test_macro_f1": selected["test"]["macro_f1_all_model_classes"],
                "file_count": len(published) + 1,
                "workspace": str(arguments.output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
