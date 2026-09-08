#!/usr/bin/env python3
"""Publish a sanitized summary of a verified M5 in-round campaign."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from fl_forensics import contribution_explanation as contribution_explanation_module  # noqa: E402
from fl_forensics.byzantine import flatten_delta, model_delta  # noqa: E402
from fl_forensics.contribution_explanation import tensor_deviation_drivers  # noqa: E402
from fl_forensics.federated_model import arrays_from_export  # noqa: E402


STATUSES = ("accepted", "accepted_downweighted", "statistically_quarantined")
COMPONENTS = (
    "coordinate_median_distance",
    "cosine_to_median",
    "mad_score",
    "relative_norm",
    "validation_impact",
)


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_once(path: Path, content: bytes, *, replace: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content and not replace:
            raise RuntimeError(
                f"refusing to overwrite different published bytes without "
                f"--replace-existing-snapshot: {path}"
            )
        if replace:
            path.write_bytes(content)
        return
    path.write_bytes(content)


def _authorize_replacement(
    output: Path,
    *,
    enabled: bool,
    source_campaign_manifest_sha256: str,
) -> bool:
    if not output.exists():
        return False
    if not enabled:
        return False
    manifest_path = output / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError("existing snapshot has no manifest; replacement is unsafe")
    manifest = _load(manifest_path)
    if (
        manifest.get("artifact_type")
        != "published_m5_in_round_campaign_snapshot_manifest"
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


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _component_map(decision: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = {
        str(item["name"]): item for item in decision["statistics"]["components"]
    }
    if set(components) != set(COMPONENTS):
        raise ValueError("decision does not contain the expected statistical components")
    return components


def _policy_map(decision: dict[str, Any]) -> dict[str, dict[str, Any]]:
    policies = {
        str(item["policy"]): item for item in decision["policy_decisions"]
    }
    expected = {"tpm_only", "statistics_only", "sequential", "gated_composite"}
    if set(policies) != expected:
        raise ValueError("decision does not contain the four admission policies")
    return policies


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(_json_bytes(row) for row in rows)


def _round_update_context(
    workspace: Path,
    decisions: list[dict[str, Any]],
    *,
    top_k: int,
) -> dict[tuple[int, str], dict[str, Any]]:
    """Recompute update-vector and aggregation context for every signed decision."""

    result: dict[tuple[int, str], dict[str, Any]] = {}
    round_numbers = sorted({int(item["round_number"]) for item in decisions})
    for round_number in round_numbers:
        round_root = workspace / "rounds" / f"round-{round_number:03d}"
        base_path = round_root / "public" / "base-model.json"
        base_export = _load(base_path)
        base_sha256 = _sha256(base_path)
        base_arrays = arrays_from_export(base_export, np=np)
        tensor_names = [
            str(item.get("name", "")) for item in base_export.get("parameters", [])
        ]
        if len(tensor_names) != len(base_arrays) or any(not name for name in tensor_names):
            raise ValueError(f"round {round_number} base tensor names do not align")

        round_decisions = sorted(
            (item for item in decisions if int(item["round_number"]) == round_number),
            key=lambda item: str(item["client_id"]),
        )
        client_ids = [str(item["client_id"]) for item in round_decisions]
        deltas: list[list[np.ndarray]] = []
        for item in round_decisions:
            client_id = str(item["client_id"])
            submission = round_root / "submissions" / client_id
            update_path = submission / "update.json"
            bundle = _load(submission / "bundle.json")
            if _sha256(update_path) != str(item["update_sha256"]):
                raise ValueError(f"round {round_number} {client_id} update digest mismatch")
            if bundle["core"]["update_sha256"] != str(item["update_sha256"]):
                raise ValueError(f"round {round_number} {client_id} bundle update mismatch")
            if bundle["core"]["base_model_sha256"] != base_sha256:
                raise ValueError(f"round {round_number} {client_id} base-model mismatch")
            update_arrays = arrays_from_export(_load(update_path), np=np)
            deltas.append(model_delta(base_arrays, update_arrays))

        tensor_drivers = tensor_deviation_drivers(
            deltas,
            client_ids=client_ids,
            tensor_names=tensor_names,
            top_k=top_k,
        )
        matrix = np.stack([flatten_delta(delta) for delta in deltas])
        effective_weights = np.asarray(
            [float(item["effective_weight_decimal"]) for item in round_decisions],
            dtype=np.float64,
        )
        full_weights = np.asarray(
            [float(item["num_examples"]) for item in round_decisions],
            dtype=np.float64,
        )
        if (
            (effective_weights < 0.0).any()
            or (effective_weights > full_weights).any()
            or float(effective_weights.sum()) <= 0.0
        ):
            raise ValueError(f"round {round_number} effective weights are invalid")
        weighted_sum = np.einsum("i,ij->j", effective_weights, matrix)
        total_weight = float(effective_weights.sum())
        aggregate = weighted_sum / total_weight
        aggregate_norm = float(np.linalg.norm(aggregate))
        risk_order = sorted(
            round_decisions,
            key=lambda item: (-float(item["statistics"]["risk"]), item["client_id"]),
        )
        risk_ranks = {
            str(item["client_id"]): rank
            for rank, item in enumerate(risk_order, start=1)
        }

        for index, item in enumerate(round_decisions):
            client_id = str(item["client_id"])
            effective = float(effective_weights[index])
            full = float(full_weights[index])
            delta = matrix[index]
            delta_norm = float(np.linalg.norm(delta))
            without_weight = total_weight - effective
            if effective > 0.0 and without_weight > 0.0:
                aggregate_without = (
                    weighted_sum - effective * delta
                ) / without_weight
                admitted_influence = float(np.linalg.norm(aggregate - aggregate_without))
            else:
                admitted_influence = 0.0
            counterfactual_weight = total_weight - effective + full
            counterfactual_full = (
                weighted_sum - effective * delta + full * delta
            ) / counterfactual_weight
            intervention_effect = float(np.linalg.norm(counterfactual_full - aggregate))
            cosine = 0.0
            if delta_norm > 0.0 and aggregate_norm > 0.0:
                cosine = float(np.dot(delta, aggregate) / (delta_norm * aggregate_norm))
            result[(round_number, client_id)] = {
                "top_tensor_drivers": [
                    driver.model_dump(mode="json")
                    for driver in tensor_drivers[client_id]
                ],
                "risk_rank_in_round": risk_ranks[client_id],
                "peer_count": len(round_decisions),
                "effective_weight_fraction": effective / full,
                "update_l2": delta_norm,
                "cosine_to_effective_aggregate": cosine,
                "admitted_aggregate_influence_l2": admitted_influence,
                "policy_intervention_effect_l2": intervention_effect,
            }
    return result


def _read_sources(workspace: Path) -> tuple[
    dict[str, Any], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]
]:
    manifest_path = workspace / "campaign-manifest.json"
    evaluation_path = workspace / "evaluation" / "selected-checkpoint-evaluation.json"
    manifest = _load(manifest_path)
    evaluation = _load(evaluation_path)
    if manifest.get("artifact_type") != "secure_multiround_campaign_manifest":
        raise ValueError("unsupported campaign manifest")
    if evaluation.get("artifact_type") != "secure_campaign_selected_checkpoint_evaluation":
        raise ValueError("unsupported selected-checkpoint evaluation")
    core = manifest["core"]
    if evaluation["campaign_id"] != core["campaign_id"]:
        raise ValueError("campaign/evaluation identity mismatch")
    if evaluation["selected_round"] != core["selected_round"]:
        raise ValueError("campaign/evaluation selected-round mismatch")

    round_metrics: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    seen_slots: set[tuple[int, str]] = set()
    for round_number in range(1, int(core["round_count"]) + 1):
        metric_path = workspace / "evaluation" / f"round-{round_number:03d}-validation.json"
        metric = _load(metric_path)
        if metric["campaign_id"] != core["campaign_id"]:
            raise ValueError(f"round {round_number} validation campaign mismatch")
        if int(metric["round_number"]) != round_number:
            raise ValueError(f"round {round_number} validation number mismatch")
        round_metrics.append(metric)

        decision_paths = sorted(
            (workspace / "rounds" / f"round-{round_number:03d}" / "in-round-decisions").glob(
                "client*.json"
            )
        )
        if len(decision_paths) != int(core["required_client_count"]):
            raise ValueError(f"round {round_number} decision count mismatch")
        for path in decision_paths:
            artifact = _load(path)
            if artifact.get("artifact_type") != "in_round_contribution_decision":
                raise ValueError(f"unsupported contribution decision: {path}")
            decision = artifact["core"]
            slot = (int(decision["round_number"]), str(decision["client_id"]))
            if slot in seen_slots or slot[0] != round_number:
                raise ValueError(f"duplicate or misplaced contribution decision: {path}")
            if decision["campaign_id"] != core["campaign_id"]:
                raise ValueError(f"contribution decision campaign mismatch: {path}")
            if decision["final_status"] not in STATUSES:
                raise ValueError(f"unsupported contribution status: {path}")
            if decision["primary_decision"]["policy"] != "gated_composite":
                raise ValueError(f"unexpected primary policy: {path}")
            if not all(bool(item["passed"]) for item in decision["m5_checks"]):
                raise ValueError(f"failed M5 check in published reference: {path}")
            _component_map(decision)
            seen_slots.add(slot)
            decisions.append(decision)
    return manifest, evaluation, round_metrics, decisions


def _decision_set_sha256(workspace: Path) -> str:
    paths = sorted(workspace.glob("rounds/round-*/in-round-decisions/client*.json"))
    inventory = [
        {"path": path.relative_to(workspace).as_posix(), "sha256": _sha256(path)}
        for path in paths
    ]
    return hashlib.sha256(_json_bytes(inventory)).hexdigest()


def _format_rate(numerator: int, denominator: int) -> str:
    return f"{100.0 * numerator / denominator:.2f}%"


def _explanation_record(
    decision: dict[str, Any],
    *,
    update_context: dict[str, Any],
    thresholds: dict[str, float],
    prior_status_counts: Counter[str],
) -> dict[str, Any]:
    """Build an exact rule trace plus a deterministic human-readable explanation."""

    status = str(decision["final_status"])
    primary = decision["primary_decision"]
    score = float(primary["score"])
    quarantine_threshold = thresholds["composite_threshold"]
    downweight_threshold = thresholds["composite_downweight_threshold"]
    trust_weight = thresholds["trust_weight"]
    statistical_fraction = 1.0 - trust_weight
    components = sorted(
        decision["statistics"]["components"],
        key=lambda item: (-float(item["weighted_contribution"]), str(item["name"])),
    )
    risk = float(decision["statistics"]["risk"])
    ranked_components = [
        {
            **component,
            "risk_share": (
                float(component["weighted_contribution"]) / risk if risk > 0.0 else 0.0
            ),
        }
        for component in components
    ]
    policies = _policy_map(decision)
    policy_statuses = {
        name: str(item["status"]) for name, item in sorted(policies.items())
    }
    nonzero_reduction = (
        max(0.0, score - quarantine_threshold)
        if status == "statistically_quarantined"
        else 0.0
    )
    full_reduction = max(0.0, score - downweight_threshold)
    validation_component = _component_map(decision)["validation_impact"]
    validation_impact = float(validation_component["raw_value"])

    if status == "accepted":
        action = "accepted at its full example-count weight"
    elif status == "accepted_downweighted":
        action = "accepted at half of its example-count weight"
    else:
        action = "quarantined with zero aggregation weight"
    trust_text = (
        f"All {len(decision['m5_checks'])} M5 checks passed and the fresh M4 "
        "attestation was admissible; no trust failure caused this decision."
    )
    decision_text = (
        f"The contribution was {action}. Its gated-composite score was {score:.6f}; "
        f"the downweight and quarantine thresholds were {downweight_threshold:.6f} "
        f"and {quarantine_threshold:.6f}."
    )
    indicator_text = "; ".join(
        (
            f"{item['name']} raw={float(item['raw_value']):.6f}, "
            f"reference={float(item['reference_median']):.6f}, "
            f"robust-z={float(item['robust_z']):.3f}, "
            f"risk contribution={float(item['weighted_contribution']):.3f}"
        )
        for item in ranked_components[:3]
    )
    tensor_text = "; ".join(
        (
            f"{item['tensor_name']} "
            f"({100.0 * float(item['squared_median_distance_fraction']):.1f}% of "
            "squared update-to-median distance)"
        )
        for item in update_context["top_tensor_drivers"]
    )
    if validation_impact > 0.0:
        validation_text = (
            f"The client model macro-F1 was {validation_impact:.6f} below the incoming "
            "global model on the isolated validation split."
        )
    elif validation_impact < 0.0:
        validation_text = (
            f"The client model macro-F1 was {-validation_impact:.6f} above the incoming "
            "global model on the isolated validation split."
        )
    else:
        validation_text = (
            "The client and incoming global models had equal macro-F1 on the isolated "
            "validation split."
        )
    policy_text = ", ".join(
        f"{name}={policy_statuses[name]}"
        for name in ("tpm_only", "statistics_only", "sequential", "gated_composite")
    )
    counterfactual_text = (
        f"Holding trust, peers, and calibration fixed, a composite "
        f"reduction of {nonzero_reduction:.6f} would restore non-zero weight and a "
        f"reduction of {full_reduction:.6f} would restore full weight. With trust risk "
        f"fixed at zero, these correspond to statistical-risk reductions of "
        f"{nonzero_reduction / statistical_fraction:.6f} and "
        f"{full_reduction / statistical_fraction:.6f}. This is a score-level "
        "counterfactual and does not prescribe one unique indicator or tensor change."
    )
    context_text = (
        f"Its statistical risk ranked {update_context['risk_rank_in_round']} of "
        f"{update_context['peer_count']} in this round (rank 1 is highest). Before this "
        f"round the client had {prior_status_counts['accepted_downweighted']} downweights "
        f"and {prior_status_counts['statistically_quarantined']} quarantines. The actual "
        f"retained-weight fraction was {update_context['effective_weight_fraction']:.2f}."
    )
    aggregate_text = (
        f"Its admitted influence on the effective aggregate was "
        f"{update_context['admitted_aggregate_influence_l2']:.6f} in L2 distance. "
        f"Restoring full weight while holding the round fixed would move the aggregate by "
        f"{update_context['policy_intervention_effect_l2']:.6f}."
    )
    limitation = (
        "This explains the configured admission rule and update geometry. It does not prove "
        "malicious intent; the declared execution condition contains no injected attack."
    )
    return {
        "schema_version": "1.0",
        "round": int(decision["round_number"]),
        "client_id": str(decision["client_id"]),
        "trust_decision_id": str(decision["trust_decision_id"]),
        "bundle_id": str(decision["bundle_id"]),
        "bundle_sha256": str(decision["bundle_sha256"]),
        "update_sha256": str(decision["update_sha256"]),
        "status": status,
        "trust_admissible": bool(decision["trust"]["admissible"]),
        "m5_check_count": len(decision["m5_checks"]),
        "statistical_risk": risk,
        "statistical_quarantine_threshold": thresholds["statistical_threshold"],
        "composite_score": score,
        "composite_downweight_threshold": downweight_threshold,
        "composite_quarantine_threshold": quarantine_threshold,
        "signed_headroom_to_quarantine": quarantine_threshold - score,
        "signed_headroom_to_full_acceptance": downweight_threshold - score,
        "policy_statuses": policy_statuses,
        "ranked_statistical_components": ranked_components,
        "top_tensor_drivers": update_context["top_tensor_drivers"],
        "round_context": {
            "statistical_risk_rank": update_context["risk_rank_in_round"],
            "peer_count": update_context["peer_count"],
            "prior_downweight_count": prior_status_counts[
                "accepted_downweighted"
            ],
            "prior_quarantine_count": prior_status_counts[
                "statistically_quarantined"
            ],
        },
        "aggregation_treatment": {
            "effective_weight_decimal": str(decision["effective_weight_decimal"]),
            "effective_weight_fraction": update_context["effective_weight_fraction"],
            "update_l2": update_context["update_l2"],
            "cosine_to_effective_aggregate": update_context[
                "cosine_to_effective_aggregate"
            ],
            "admitted_aggregate_influence_l2": update_context[
                "admitted_aggregate_influence_l2"
            ],
            "full_weight_counterfactual_aggregate_shift_l2": update_context[
                "policy_intervention_effect_l2"
            ],
        },
        "counterfactual": {
            "composite_reduction_for_nonzero_weight": nonzero_reduction,
            "composite_reduction_for_full_weight": full_reduction,
            "statistical_reduction_for_nonzero_weight": (
                nonzero_reduction / statistical_fraction
            ),
            "statistical_reduction_for_full_weight": (
                full_reduction / statistical_fraction
            ),
            "fixed_context": [
                "trust signal",
                "peer updates",
                "calibration reference",
            ],
        },
        "validation": {
            "base_minus_client_macro_f1": validation_impact,
            "test_data_used": False,
        },
        "narrative": [
            trust_text,
            decision_text,
            f"The leading scalar drivers were: {indicator_text}.",
            validation_text,
            f"Policy comparison: {policy_text}.",
            f"The leading tensor drivers were: {tensor_text}.",
            context_text,
            aggregate_text,
            counterfactual_text,
            limitation,
        ],
    }


def _intervention_markdown(explanations: list[dict[str, Any]]) -> bytes:
    treated = [item for item in explanations if item["status"] != "accepted"]
    quarantined = [
        item for item in treated if item["status"] == "statistically_quarantined"
    ]
    downweighted = [
        item for item in treated if item["status"] == "accepted_downweighted"
    ]
    lines = [
        "# Human-readable in-round contribution explanations",
        "",
        "These deterministic explanations are derived from signed M5 decisions and the",
        "digest-bound update tensors. They use no test rows or attack labels. Each explanation",
        "describes a policy decision, not proof of malicious intent.",
        "",
    ]
    for title, items in (("Quarantined contributions", quarantined), ("Downweighted contributions", downweighted)):
        lines.extend([f"## {title}", ""])
        for item in items:
            lines.append(
                f"### Round {item['round']:02d} · {item['client_id']} · "
                f"{item['status']}"
            )
            lines.append("")
            for paragraph in item["narrative"]:
                lines.extend([str(paragraph), ""])
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def _plot_rounds(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    selected_round: int,
    replace: bool,
) -> None:
    rounds = [int(row["round"]) for row in rows]
    f1 = [float(row["validation_macro_f1"]) for row in rows]
    accepted = np.asarray([int(row["accepted"]) for row in rows])
    downweighted = np.asarray([int(row["downweighted"]) for row in rows])
    quarantined = np.asarray([int(row["quarantined"]) for row in rows])

    figure, axes = plt.subplots(2, 1, figsize=(11, 7.2), sharex=True)
    axes[0].plot(rounds, f1, marker="o", markersize=3.5, color="#184e77")
    axes[0].scatter(
        [selected_round],
        [f1[selected_round - 1]],
        marker="*",
        s=180,
        color="#f4a261",
        edgecolor="black",
        linewidth=0.5,
        zorder=3,
        label=f"selected round {selected_round}",
    )
    axes[0].set_ylabel("Validation macro-F1")
    axes[0].set_ylim(0.0, 1.03)
    axes[0].grid(axis="y", alpha=0.25)
    axes[0].legend(loc="lower right")

    axes[1].bar(rounds, accepted, color="#2a9d8f", label="accepted")
    axes[1].bar(
        rounds,
        downweighted,
        bottom=accepted,
        color="#e9c46a",
        label="downweighted",
    )
    axes[1].bar(
        rounds,
        quarantined,
        bottom=accepted + downweighted,
        color="#e76f51",
        label="quarantined",
    )
    axes[1].set_xlabel("Round")
    axes[1].set_ylabel("Client decisions")
    axes[1].set_xticks(rounds)
    axes[1].set_ylim(0, max(accepted + downweighted + quarantined) + 0.8)
    axes[1].grid(axis="y", alpha=0.2)
    axes[1].legend(loc="lower left", ncol=3)
    figure.suptitle("M5 in-round composite campaign")
    figure.tight_layout()
    output = io.BytesIO()
    figure.savefig(
        output,
        format="png",
        dpi=180,
        metadata={"Software": "fl-forensics"},
    )
    plt.close(figure)
    _write_once(path, output.getvalue(), replace=replace)


def _plot_clients(path: Path, rows: list[dict[str, Any]], *, replace: bool) -> None:
    labels = [str(row["client_id"]) for row in rows]
    accepted = np.asarray([int(row["accepted"]) for row in rows])
    downweighted = np.asarray([int(row["downweighted"]) for row in rows])
    quarantined = np.asarray([int(row["quarantined"]) for row in rows])
    positions = np.arange(len(rows))

    figure, axis = plt.subplots(figsize=(11, 5.6))
    axis.bar(positions, accepted, color="#2a9d8f", label="accepted")
    axis.bar(
        positions,
        downweighted,
        bottom=accepted,
        color="#e9c46a",
        label="downweighted",
    )
    axis.bar(
        positions,
        quarantined,
        bottom=accepted + downweighted,
        color="#e76f51",
        label="quarantined",
    )
    axis.set_xticks(positions, labels, rotation=45, ha="right")
    axis.set_ylabel("Decisions across 30 rounds")
    axis.set_title("Contribution treatment by client")
    axis.set_ylim(0, 31)
    axis.grid(axis="y", alpha=0.2)
    axis.legend(loc="lower center", ncol=3)
    figure.tight_layout()
    output = io.BytesIO()
    figure.savefig(
        output,
        format="png",
        dpi=180,
        metadata={"Software": "fl-forensics"},
    )
    plt.close(figure)
    _write_once(path, output.getvalue(), replace=replace)


def _plot_confusions(
    path: Path,
    evaluation: dict[str, Any],
    *,
    replace: bool,
) -> None:
    splits = ("validation", "test", "temporal_holdout")
    titles = ("Validation", "Test", "Temporal holdout\n(benign-only)")
    figure, axes = plt.subplots(1, 3, figsize=(18, 5.7))
    image = None
    for axis, split, title in zip(axes, splits, titles, strict=True):
        matrix = np.asarray(
            evaluation["metrics"][split]["confusion_matrix"]["values"], dtype=float
        )
        labels = evaluation["metrics"][split]["confusion_matrix"]["labels"]
        support = matrix.sum(axis=1, keepdims=True)
        normalized = np.divide(
            matrix, support, out=np.zeros_like(matrix), where=support != 0
        )
        image = axis.imshow(normalized, vmin=0.0, vmax=1.0, cmap="Blues")
        for row in range(normalized.shape[0]):
            for column in range(normalized.shape[1]):
                value = normalized[row, column]
                axis.text(
                    column,
                    row,
                    f"{100.0 * value:.1f}%",
                    ha="center",
                    va="center",
                    fontsize=7.5,
                    color="white" if value > 0.55 else "black",
                )
        display_labels = [str(label).replace("_", " ") for label in labels]
        axis.set_xticks(range(len(labels)), display_labels, rotation=45, ha="right")
        axis.set_yticks(range(len(labels)), display_labels)
        axis.set_xlabel("Predicted")
        axis.set_ylabel("Actual")
        axis.set_title(title)
    assert image is not None
    color_axis = figure.add_axes([0.945, 0.25, 0.012, 0.52])
    figure.colorbar(image, cax=color_axis, label="Row fraction")
    figure.suptitle(
        f"Selected secure checkpoint — round {evaluation['selected_round']} — row-normalized"
    )
    figure.subplots_adjust(left=0.07, right=0.92, bottom=0.24, top=0.82, wspace=0.42)
    output = io.BytesIO()
    figure.savefig(
        output,
        format="png",
        dpi=180,
        metadata={"Software": "fl-forensics"},
    )
    plt.close(figure)
    _write_once(path, output.getvalue(), replace=replace)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--replace-existing-snapshot",
        action="store_true",
        help="replace only a hash-valid snapshot derived from the same campaign",
    )
    parser.add_argument(
        "--condition",
        choices=("clean-no-injected-attack",),
        required=True,
        help="declared execution condition used only to interpret intervention counts",
    )
    arguments = parser.parse_args()

    manifest, evaluation, round_metrics, decisions = _read_sources(arguments.workspace)
    core = manifest["core"]
    counts = Counter(str(item["final_status"]) for item in decisions)
    total = len(decisions)
    interventions = counts["accepted_downweighted"] + counts["statistically_quarantined"]
    trust_admissible_count = sum(bool(item["trust"]["admissible"]) for item in decisions)
    if trust_admissible_count != total:
        raise ValueError("clean reference contains an inadmissible trust decision")

    primary_thresholds = {float(item["primary_decision"]["threshold"]) for item in decisions}
    if len(primary_thresholds) != 1:
        raise ValueError("primary quarantine threshold changed during campaign")
    quarantine_threshold = primary_thresholds.pop()
    # Contract thresholds are already composite-scale values; keep the source value verbatim.
    contract = _load(
        arguments.workspace
        / "rounds"
        / "round-001"
        / "public"
        / "in-round-admission-contract.json"
    )
    thresholds = {
        name: float(value)
        for name, value in contract["core"]["thresholds"].items()
        if name
        in {
            "statistical_threshold",
            "composite_downweight_threshold",
            "composite_threshold",
            "trust_weight",
        }
    }
    if set(thresholds) != {
        "statistical_threshold",
        "composite_downweight_threshold",
        "composite_threshold",
        "trust_weight",
    }:
        raise ValueError("in-round contract threshold set is incomplete")
    downweight_threshold = thresholds["composite_downweight_threshold"]
    if quarantine_threshold != thresholds["composite_threshold"]:
        raise ValueError("decision and contract quarantine thresholds differ")

    update_context = _round_update_context(
        arguments.workspace,
        decisions,
        top_k=3,
    )
    histories: dict[str, Counter[str]] = defaultdict(Counter)
    explanations: list[dict[str, Any]] = []
    for item in sorted(
        decisions, key=lambda row: (int(row["round_number"]), str(row["client_id"]))
    ):
        client_id = str(item["client_id"])
        slot = (int(item["round_number"]), client_id)
        explanations.append(
            _explanation_record(
                item,
                update_context=update_context[slot],
                thresholds=thresholds,
                prior_status_counts=histories[client_id].copy(),
            )
        )
        histories[client_id][str(item["final_status"])] += 1
    structured_explanations = [
        {key: value for key, value in item.items() if key != "narrative"}
        for item in explanations
    ]
    explanation_by_slot = {
        (int(item["round"]), str(item["client_id"])): item for item in explanations
    }

    decision_rows: list[dict[str, Any]] = []
    for item in sorted(decisions, key=lambda row: (row["round_number"], row["client_id"])):
        component_map = _component_map(item)
        primary = item["primary_decision"]
        explanation = explanation_by_slot[
            (int(item["round_number"]), str(item["client_id"]))
        ]
        aggregation = explanation["aggregation_treatment"]
        row: dict[str, Any] = {
            "round": item["round_number"],
            "client_id": item["client_id"],
            "status": item["final_status"],
            "trust_admissible": str(bool(item["trust"]["admissible"])).lower(),
            "statistical_risk": f"{float(item['statistics']['risk']):.9f}",
            "composite_score": f"{float(primary['score']):.9f}",
            "composite_downweight_threshold": f"{downweight_threshold:.9f}",
            "composite_threshold": f"{float(primary['threshold']):.9f}",
            "signed_headroom_to_quarantine": (
                f"{float(primary['threshold']) - float(primary['score']):.9f}"
            ),
            "signed_headroom_to_full_acceptance": (
                f"{downweight_threshold - float(primary['score']):.9f}"
            ),
            "effective_weight": item["effective_weight_decimal"],
            "effective_weight_fraction": f"{float(aggregation['effective_weight_fraction']):.6f}",
            "risk_rank_in_round": explanation["round_context"][
                "statistical_risk_rank"
            ],
            "dominant_scalar_driver": explanation[
                "ranked_statistical_components"
            ][0]["name"],
            "dominant_tensor_driver": explanation["top_tensor_drivers"][0][
                "tensor_name"
            ],
            "admitted_aggregate_influence_l2": (
                f"{float(aggregation['admitted_aggregate_influence_l2']):.9f}"
            ),
            "full_weight_counterfactual_aggregate_shift_l2": (
                f"{float(aggregation['full_weight_counterfactual_aggregate_shift_l2']):.9f}"
            ),
        }
        for name in COMPONENTS:
            component = component_map[name]
            row[f"{name}_raw"] = f"{float(component['raw_value']):.9f}"
            row[f"{name}_robust_z"] = f"{float(component['robust_z']):.9f}"
            row[f"{name}_risk"] = f"{float(component['component_risk']):.9f}"
        decision_rows.append(row)

    round_rows: list[dict[str, Any]] = []
    for metric in round_metrics:
        round_number = int(metric["round_number"])
        subset = [item for item in decisions if int(item["round_number"]) == round_number]
        statuses = Counter(str(item["final_status"]) for item in subset)
        risks = [float(item["statistics"]["risk"]) for item in subset]
        validation = metric["validation"]
        round_rows.append(
            {
                "round": round_number,
                "validation_macro_f1": f"{float(validation['macro_f1_all_model_classes']):.9f}",
                "validation_accuracy": f"{float(validation['accuracy']):.9f}",
                "accepted": statuses["accepted"],
                "downweighted": statuses["accepted_downweighted"],
                "quarantined": statuses["statistically_quarantined"],
                "contributing": statuses["accepted"] + statuses["accepted_downweighted"],
                "mean_statistical_risk": f"{statistics.fmean(risks):.9f}",
                "maximum_statistical_risk": f"{max(risks):.9f}",
            }
        )

    client_rows: list[dict[str, Any]] = []
    client_test = {
        str(item["client_id"]): float(item["test"]["macro_f1_all_model_classes"])
        for item in evaluation["selected_global_client_test"]
    }
    for client_id in sorted({str(item["client_id"]) for item in decisions}):
        subset = [item for item in decisions if item["client_id"] == client_id]
        statuses = Counter(str(item["final_status"]) for item in subset)
        risks = [float(item["statistics"]["risk"]) for item in subset]
        client_rows.append(
            {
                "client_id": client_id,
                "accepted": statuses["accepted"],
                "downweighted": statuses["accepted_downweighted"],
                "quarantined": statuses["statistically_quarantined"],
                "mean_statistical_risk": f"{statistics.fmean(risks):.9f}",
                "maximum_statistical_risk": f"{max(risks):.9f}",
                "selected_checkpoint_local_test_macro_f1": f"{client_test[client_id]:.9f}",
            }
        )

    saturation = {}
    treated = [item for item in decisions if item["final_status"] != "accepted"]
    for name in COMPONENTS:
        risks = [float(_component_map(item)[name]["component_risk"]) for item in treated]
        saturation[name] = {
            "positive_count": sum(value > 0.0 for value in risks),
            "saturated_count": sum(value >= 1.0 - 1e-12 for value in risks),
            "mean_component_risk": statistics.fmean(risks),
        }

    selected = evaluation["metrics"]
    temporal_matrix = selected["temporal_holdout"]["confusion_matrix"]["values"]
    temporal_total = int(selected["temporal_holdout"]["row_count"])
    temporal_false_alerts = temporal_total - int(temporal_matrix[0][0])
    summary = {
        "schema_version": "1.0",
        "artifact_type": "published_m5_in_round_campaign_snapshot",
        "declared_execution_condition": arguments.condition,
        "campaign_id": core["campaign_id"],
        "round_count": core["round_count"],
        "client_count": core["required_client_count"],
        "contribution_count": total,
        "trust_admissible_count": trust_admissible_count,
        "accepted_count": counts["accepted"],
        "downweighted_count": counts["accepted_downweighted"],
        "quarantined_count": counts["statistically_quarantined"],
        "contributing_count": counts["accepted"] + counts["accepted_downweighted"],
        "clean_intervention_count": interventions,
        "clean_intervention_rate": interventions / total,
        "clean_strict_false_positive_count": counts["statistically_quarantined"],
        "clean_strict_false_positive_rate": counts["statistically_quarantined"] / total,
        "composite_downweight_threshold": downweight_threshold,
        "composite_quarantine_threshold": quarantine_threshold,
        "first_intervention_round": min(
            int(item["round_number"]) for item in treated
        ),
        "selected_round": evaluation["selected_round"],
        "selected_model_sha256": evaluation["selected_model_sha256"],
        "selected_checkpoint_sha256": evaluation["selected_checkpoint_sha256"],
        "validation_macro_f1": selected["validation"]["macro_f1_all_model_classes"],
        "test_macro_f1": selected["test"]["macro_f1_all_model_classes"],
        "test_accuracy": selected["test"]["accuracy"],
        "client_local_test_macro_f1": evaluation[
            "selected_global_client_test_summary"
        ]["macro_f1_all_model_classes"],
        "temporal_holdout_observed_labels": selected["temporal_holdout"][
            "observed_labels"
        ],
        "temporal_holdout_false_alert_count": temporal_false_alerts,
        "temporal_holdout_false_alert_rate": temporal_false_alerts / temporal_total,
        "treated_component_summary": saturation,
        "explanation_count": len(explanations),
        "human_readable_intervention_count": len(
            [item for item in explanations if item["status"] != "accepted"]
        ),
        "top_tensor_driver_count_per_contribution": 3,
        "tensor_explanations_recomputed_from_bound_updates": True,
        "source_campaign_manifest_sha256": _sha256(
            arguments.workspace / "campaign-manifest.json"
        ),
        "source_selected_evaluation_sha256": _sha256(
            arguments.workspace / "evaluation" / "selected-checkpoint-evaluation.json"
        ),
        "source_decision_set_sha256": _decision_set_sha256(arguments.workspace),
        "source_admission_contract_sha256": _sha256(
            arguments.workspace
            / "rounds"
            / "round-001"
            / "public"
            / "in-round-admission-contract.json"
        ),
        "tensor_driver_implementation_sha256": _sha256(
            Path(str(contribution_explanation_module.__file__))
        ),
        "renderer_sha256": _sha256(Path(__file__)),
    }

    replace_existing = _authorize_replacement(
        arguments.output,
        enabled=arguments.replace_existing_snapshot,
        source_campaign_manifest_sha256=summary["source_campaign_manifest_sha256"],
    )
    arguments.output.mkdir(parents=True, exist_ok=True)
    _write_once(
        arguments.output / "summary.json",
        _json_bytes(summary),
        replace=replace_existing,
    )
    _write_once(
        arguments.output / "rounds.csv",
        _csv_bytes(list(round_rows[0]), round_rows),
        replace=replace_existing,
    )
    _write_once(
        arguments.output / "clients.csv",
        _csv_bytes(list(client_rows[0]), client_rows),
        replace=replace_existing,
    )
    _write_once(
        arguments.output / "decisions.csv",
        _csv_bytes(list(decision_rows[0]), decision_rows),
        replace=replace_existing,
    )
    _write_once(
        arguments.output / "explanations.jsonl",
        _jsonl_bytes(structured_explanations),
        replace=replace_existing,
    )
    _write_once(
        arguments.output / "intervention-explanations.md",
        _intervention_markdown(explanations),
        replace=replace_existing,
    )

    round_plot = arguments.output / "admission-and-validation.png"
    client_plot = arguments.output / "client-treatment.png"
    confusion_plot = arguments.output / "selected-confusion-matrices.png"
    _plot_rounds(
        round_plot,
        round_rows,
        selected_round=int(evaluation["selected_round"]),
        replace=replace_existing,
    )
    _plot_clients(client_plot, client_rows, replace=replace_existing)
    _plot_confusions(confusion_plot, evaluation, replace=replace_existing)

    readme = f"""# Verified M5 in-round composite campaign

This sanitized snapshot reports the 30-round clean reference execution in which the
gated TPM/statistical policy controlled the actual weighted FedAvg checkpoint during training.
The source campaign was independently verified before publication. The declared execution
condition is `{arguments.condition}`; no Byzantine update was injected in this run.

## Main results

- campaign `{core['campaign_id']}`; 15 clients, 30 rounds, {total} signed contributions;
- selected checkpoint: round {evaluation['selected_round']};
- validation macro-F1: `{selected['validation']['macro_f1_all_model_classes']:.6f}`;
- isolated test macro-F1: `{selected['test']['macro_f1_all_model_classes']:.6f}`;
- isolated test accuracy: `{selected['test']['accuracy']:.6f}`;
- client-local test macro-F1 mean: `{evaluation['selected_global_client_test_summary']['macro_f1_all_model_classes']['mean']:.6f}`;
- {counts['accepted']} fully accepted, {counts['accepted_downweighted']} downweighted, and
  {counts['statistically_quarantined']} quarantined contributions;
- {counts['accepted'] + counts['accepted_downweighted']}/{total} contributions retained nonzero
  weight (`{_format_rate(counts['accepted'] + counts['accepted_downweighted'], total)}`);
- clean-run intervention rate: `{_format_rate(interventions, total)}`; strict quarantine
  false-positive rate: `{_format_rate(counts['statistically_quarantined'], total)}`.

All {total} contributions passed the M4/M5 trust gate. Therefore the 75 downweights and six
quarantines are statistical interventions over clients declared clean by the experiment. They
begin at round {summary['first_intervention_round']}. This is evidence that the fixed clean
calibration is not invariant to the evolving update geometry; it is not evidence that those
clients were malicious. Five quarantines concern `client06`, and one concerns `client11`.
Cosine-to-median and coordinate-median distance dominate the treated cases.

Every contribution also has an exact decision explanation. It states which trust checks passed,
the score and signed threshold headroom, the leading scalar indicators, the top three named
parameter tensors responsible for update-to-median distance, all four policy outcomes, prior
client interventions, risk rank among the round peers, retained FedAvg weight, and the actual
versus full-weight counterfactual aggregate displacement. The explanation is a deterministic
rule trace; it is not generated prose and does not use the test split.

The benign-only temporal holdout contains {temporal_total} windows and {temporal_false_alerts}
false alerts (`{_format_rate(temporal_false_alerts, temporal_total)}`). Its six-class macro-F1
must not be interpreted as multiclass performance because five classes have zero support.

## Files

- `summary.json`: compact metrics, source hashes, rates, and indicator saturation counts;
- `rounds.csv`: validation performance, risk, and decision counts for every round;
- `clients.csv`: per-client treatment and selected-checkpoint local-test macro-F1;
- `decisions.csv`: 450 compact policy decisions, threshold margins, dominant drivers, and
  aggregate influence values;
- `explanations.jsonl`: complete structured explanations for all 450 contributions;
- `intervention-explanations.md`: human-readable investigations of all 75 downweights and six
  quarantines;
- `admission-and-validation.png`: validation trajectory and treatment counts;
- `client-treatment.png`: accepted/downweighted/quarantined counts by client;
- `selected-confusion-matrices.png`: row-normalized validation, test, and temporal matrices.

## Interpretation boundary

This clean run measures compatibility cost and false interventions. It does not measure attack
detection because no attacker is present. The high selected-checkpoint scores do not by
themselves prove that the admission policy caused an improvement. A causal robustness claim
requires paired clean/attacked policy ablations under the same initialization and data contract.

Source campaign-manifest SHA-256: `{summary['source_campaign_manifest_sha256']}`. Source selected
evaluation SHA-256: `{summary['source_selected_evaluation_sha256']}`. The decision-set digest in
`summary.json` binds the relative path and SHA-256 of all 450 signed decision artifacts.
"""
    _write_once(
        arguments.output / "README.md",
        readme.encode("utf-8"),
        replace=replace_existing,
    )

    published = [
        "README.md",
        "admission-and-validation.png",
        "client-treatment.png",
        "clients.csv",
        "decisions.csv",
        "explanations.jsonl",
        "intervention-explanations.md",
        "rounds.csv",
        "selected-confusion-matrices.png",
        "summary.json",
    ]
    result_manifest = {
        "schema_version": "1.0",
        "artifact_type": "published_m5_in_round_campaign_snapshot_manifest",
        "source_campaign_manifest_sha256": summary["source_campaign_manifest_sha256"],
        "source_selected_evaluation_sha256": summary[
            "source_selected_evaluation_sha256"
        ],
        "source_decision_set_sha256": summary["source_decision_set_sha256"],
        "files": {
            name: {"sha256": _sha256(arguments.output / name)} for name in published
        },
    }
    _write_once(
        arguments.output / "manifest.json",
        _json_bytes(result_manifest),
        replace=replace_existing,
    )
    print(
        json.dumps(
            {
                "status": "published",
                "campaign_id": core["campaign_id"],
                "round_count": core["round_count"],
                "contribution_count": total,
                "downweighted_count": counts["accepted_downweighted"],
                "quarantined_count": counts["statistically_quarantined"],
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
