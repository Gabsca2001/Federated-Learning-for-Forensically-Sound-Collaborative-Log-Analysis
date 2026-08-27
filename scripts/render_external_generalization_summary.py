#!/usr/bin/env python3
"""Publish a compact view of the verified Data22 evaluation and Discovery stress."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

from fl_forensics.canonical import canonical_json_bytes, digest_object, sha256_file
from fl_forensics.discovery_stress import verify_discovery_stress

plt.switch_backend("Agg")


def _load(path: Path, artifact_type: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("artifact_type") != artifact_type:
        raise ValueError(f"unexpected artifact type in {path}")
    return value


def _annotated_matrix(
    axis: Any,
    *,
    values: list[list[int]],
    actual_labels: list[str],
    predicted_labels: list[str],
    title: str,
) -> None:
    normalized = []
    for row in values:
        total = sum(row)
        normalized.append([value / total if total else 0.0 for value in row])
    image = axis.imshow(normalized, cmap="Blues", vmin=0.0, vmax=1.0, aspect="auto")
    axis.set_xticks(range(len(predicted_labels)), predicted_labels, rotation=35, ha="right")
    axis.set_yticks(range(len(actual_labels)), actual_labels)
    axis.set_xlabel("Predicted")
    axis.set_ylabel("Actual")
    axis.set_title(title, pad=12)
    for row_index, row in enumerate(values):
        for column_index, count in enumerate(row):
            fraction = normalized[row_index][column_index]
            color = "white" if fraction > 0.55 else "#222222"
            axis.text(
                column_index,
                row_index,
                f"{count}\n{fraction:.1%}",
                ha="center",
                va="center",
                color=color,
                fontsize=9,
            )
    return image


def _write_confusion_figure(metrics: dict[str, Any], path: Path) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(15.5, 6.3))
    binary = metrics["binary_all_external"]["confusion_matrix"]
    image = _annotated_matrix(
        axes[0],
        values=binary["values"],
        actual_labels=binary["labels"],
        predicted_labels=binary["labels"],
        title="All Data22 windows — binary benign/attack",
    )
    shared = metrics["shared_label_closed_set"]["rectangular_confusion_matrix"]
    _annotated_matrix(
        axes[1],
        values=shared["values"],
        actual_labels=shared["actual_labels"],
        predicted_labels=shared["predicted_model_labels"],
        title="Strict shared truth labels — full model outputs",
    )
    color_axis = figure.add_axes([0.925, 0.25, 0.015, 0.55])
    colorbar = figure.colorbar(image, cax=color_axis)
    colorbar.set_label("Row fraction")
    figure.suptitle(
        "Verified post-selection generalization: Data24 checkpoint on Data22",
        fontsize=15,
    )
    figure.text(
        0.5,
        0.01,
        (
            "Counts and row-normalized percentages. High overall accuracy is dominated by "
            "benign support; attack F1 and per-class recall remain the relevant checks."
        ),
        ha="center",
        fontsize=9,
        color="#444444",
    )
    figure.subplots_adjust(left=0.08, right=0.89, top=0.84, bottom=0.24, wspace=0.32)
    figure.savefig(
        path,
        dpi=180,
        bbox_inches="tight",
        metadata={"Software": "fl-forensics external-generalization renderer"},
    )
    plt.close(figure)


def _trial_state(trial: dict[str, Any]) -> float:
    if trial["all_segments_detected_as_attack"]:
        return 1.0
    if trial["any_segment_detected_as_attack"]:
        return 0.5
    return 0.0


def _write_discovery_figure(stress: dict[str, Any], path: Path) -> None:
    trials = stress["summary"]["trials"]
    bursts = [item["burst_id"] for item in stress["episodes"]]
    offsets = stress["alignment_offsets_seconds"]
    by_key = {(item["burst_id"], item["alignment_offset_seconds"]): item for item in trials}
    values = [[_trial_state(by_key[(burst, offset)]) for offset in offsets] for burst in bursts]
    figure, axis = plt.subplots(figsize=(13.5, 3.8))
    image = axis.imshow(values, cmap="RdYlGn", vmin=0.0, vmax=1.0, aspect="auto")
    axis.set_xticks(range(len(offsets)), [f"{offset}s" for offset in offsets])
    axis.set_yticks(range(len(bursts)), [f"Burst {index}" for index in range(1, len(bursts) + 1)])
    axis.set_xlabel("Window-alignment offset (60-second windows)")
    axis.set_title("Discovery alignment sensitivity — binary attack detection")
    for row_index, burst in enumerate(bursts):
        for column_index, offset in enumerate(offsets):
            trial = by_key[(burst, offset)]
            if trial["all_segments_detected_as_attack"]:
                label = "all"
            elif trial["any_segment_detected_as_attack"]:
                label = "partial"
            else:
                label = "none"
            axis.text(column_index, row_index, label, ha="center", va="center", fontsize=8)
    colorbar = figure.colorbar(image, ax=axis, fraction=0.035, pad=0.025)
    colorbar.set_ticks([0.0, 0.5, 1.0], labels=["none", "partial", "all"])
    figure.text(
        0.5,
        -0.04,
        (
            "The two bursts are the independent units. Offset trials reuse the same events "
            "and are descriptive sensitivity measurements, not additional samples."
        ),
        ha="center",
        fontsize=9,
        color="#444444",
    )
    figure.tight_layout()
    figure.savefig(
        path,
        dpi=180,
        bbox_inches="tight",
        metadata={"Software": "fl-forensics Discovery-stress renderer"},
    )
    plt.close(figure)


def _write_trials_csv(stress: dict[str, Any], path: Path) -> None:
    columns = (
        "burst_id",
        "alignment_offset_seconds",
        "segment_count",
        "any_segment_detected_as_attack",
        "all_segments_detected_as_attack",
        "predicted_model_labels",
        "minimum_maximum_softmax_probability",
    )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for trial in stress["summary"]["trials"]:
            writer.writerow(
                {
                    **trial,
                    "predicted_model_labels": ";".join(trial["predicted_model_labels"]),
                }
            )


def _write_readme(
    *,
    metrics: dict[str, Any],
    stress: dict[str, Any],
    primary_manifest: dict[str, Any],
    stress_manifest: dict[str, Any],
    path: Path,
) -> None:
    binary = metrics["binary_all_external"]
    shared = metrics["shared_label_closed_set"]
    stress_summary = stress["summary"]
    per_burst = stress_summary["per_burst"]
    text = f"""# Verified M5 external generalization on UWF-ZeekData22

This sanitized snapshot reports a post-selection test of the frozen round-{metrics["selected_round"]}
checkpoint from the verified M4/M5 reference campaign. Data22 was not used for training,
validation, checkpoint selection, hyperparameter selection, or threshold selection.

## Main result

The official five-file CSV subset produced {metrics["external_window_count"]:,} 60-second
windows: {metrics["label_space"]["external_label_counts"]["benign"]:,} benign,
{metrics["label_space"]["external_label_counts"]["reconnaissance"]} reconnaissance, and
{metrics["label_space"]["external_label_counts"]["discovery"]} Discovery windows.

| Scope | Result |
|---|---:|
| Binary attack precision | `{binary["attack_precision"]:.4f}` |
| Binary attack recall | `{binary["attack_recall"]:.4f}` |
| Binary attack F1 | `{binary["attack_f1"]:.4f}` |
| Binary balanced accuracy | `{binary["balanced_accuracy"]:.4f}` |
| Benign specificity | `{binary["benign_specificity"]:.4f}` |
| Shared-label macro-F1 | `{shared["macro_f1_shared_labels"]:.4f}` |
| Reconnaissance recall | `{shared["per_class"]["reconnaissance"]["recall"]:.4f}` |
| Rows with any scaled feature beyond ±5 | `{metrics["feature_shift"]["row_any_absolute_z_gt_5_fraction"]:.4f}` |

![External confusion matrices](external-confusion-matrices.png)

Overall accuracy is {binary["accuracy"]:.4f}, but it is dominated by the {binary["confusion_matrix"]["values"][0][0]:,}
correct benign windows. The selected checkpoint recognizes only {binary["confusion_matrix"]["values"][1][1]}
of {sum(binary["confusion_matrix"]["values"][1])} attack windows after benign/attack collapse and
never predicts `reconnaissance`. This is a verified cross-domain generalization failure, not a
pipeline error. The feature-shift result shows that nearly every external row lies far outside
the Data24 training distribution under the frozen train-only scaler.

## Discovery alignment sensitivity

The three primary Discovery windows represent only two independent temporal bursts. A separate
stress test retains the trained 60-second window duration and shifts its alignment through
12 offsets from 0 to 55 seconds. It uses {stress["source_discovery_event_count"]:,} controlled
Discovery events and creates {stress["stress_window_count"]} target-containing windows.

| Discovery scope | Detection result |
|---|---:|
| Burst × alignment trials (correlated) | `{stress_summary["correlated_burst_alignment_trial_count"]}` |
| At least one segment detected as attack | `{stress_summary["any_segment_detection_count"]}/24` (`{stress_summary["any_segment_detection_fraction"]:.4f}`) |
| Every segment detected as attack | `{stress_summary["all_segments_detection_count"]}/24` (`{stress_summary["all_segments_detection_fraction"]:.4f}`) |
| Burst 1: every segment detected | `{per_burst[0]["all_segments_detection_count"]}/12` |
| Burst 2: every segment detected | `{per_burst[1]["all_segments_detection_count"]}/12` |

![Discovery alignment sensitivity](discovery-alignment-sensitivity.png)

Every alignment detects at least one segment from each burst as non-benign. Burst 1 spans a
minute boundary and, for five offsets, is split so that one segment is predicted `benign` and
one `multi_tactic`. Burst 2 remains `multi_tactic` at every offset. Offset zero reproduces the
three primary Discovery predictions byte for byte.

This is not an estimate of Discovery recall over 24 independent observations. Only two bursts
are independent; offsets reuse the same events. Discovery is outside the fixed six-class model
head, so this stress test supports only the binary statement “some part of the burst was flagged
as attack.” It does not demonstrate open-set Discovery classification, calibrated confidence,
or population-level performance.

## Provenance and published files

- external evaluation: `{primary_manifest["evaluation_id"]}`;
- Discovery stress: `{stress_manifest["stress_id"]}`;
- selected model SHA-256: `{metrics["selected_model_sha256"]}`;
- published metrics SHA-256: `{sha256_file(path.parent / "metrics.json")}`;
- the receipt separately binds the complete primary, stress, and external source manifests;
- zero-offset primary reproduction: `{str(stress["zero_offset_reproduces_primary_evaluation"]).lower()}`.

`metrics.json` and `discovery-stress.json` are copied byte-for-byte from verified workspaces.
`discovery-trials.csv` is a compact derived table. The two figures visualize the published
metrics, and `receipt.json` records verification and source hashes. `manifest.json` binds all
published payloads.

Raw Data22 records, per-window predictions, Data24 data, client updates, trust material, and
model checkpoints remain in Git-ignored controlled storage and are deliberately not published.
"""
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--primary-workspace", type=Path, required=True)
    parser.add_argument("--stress-workspace", type=Path, required=True)
    parser.add_argument("--external-workspace", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--campaign-workspace", type=Path, required=True)
    parser.add_argument("--trust-workspace", type=Path, required=True)
    parser.add_argument("--partition-workspace", type=Path, required=True)
    parser.add_argument("--dataset-workspace", type=Path, required=True)
    parser.add_argument("--primary-config", type=Path, required=True)
    parser.add_argument("--stress-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()

    verification = verify_discovery_stress(
        workspace=arguments.stress_workspace,
        primary_workspace=arguments.primary_workspace,
        external_workspace=arguments.external_workspace,
        source_root=arguments.input,
        campaign_workspace=arguments.campaign_workspace,
        trust_workspace=arguments.trust_workspace,
        partition_workspace=arguments.partition_workspace,
        training_dataset_workspace=arguments.dataset_workspace,
        primary_config_path=arguments.primary_config,
        config_path=arguments.stress_config,
    )
    if verification["status"] != "verified":
        raise ValueError(f"Discovery stress is not verified: {verification['errors']}")

    output = arguments.output_dir
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"published output must be new or empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    metrics_path = arguments.primary_workspace / "metrics.json"
    stress_path = arguments.stress_workspace / "stress.json"
    primary_manifest_path = arguments.primary_workspace / "manifest.json"
    stress_manifest_path = arguments.stress_workspace / "manifest.json"
    metrics = _load(metrics_path, "external_generalization_metrics")
    stress = _load(stress_path, "m5_discovery_alignment_stress")
    primary_manifest = json.loads(primary_manifest_path.read_text(encoding="utf-8"))
    stress_manifest = json.loads(stress_manifest_path.read_text(encoding="utf-8"))

    (output / "metrics.json").write_bytes(metrics_path.read_bytes())
    (output / "discovery-stress.json").write_bytes(stress_path.read_bytes())
    _write_trials_csv(stress, output / "discovery-trials.csv")
    _write_confusion_figure(metrics, output / "external-confusion-matrices.png")
    _write_discovery_figure(stress, output / "discovery-alignment-sensitivity.png")
    receipt = {
        "schema_version": "1.0",
        "artifact_type": "m5_external_generalization_published_receipt",
        "evaluation_id": primary_manifest["evaluation_id"],
        "stress_id": stress_manifest["stress_id"],
        "status": "verified",
        "source": {
            "primary_manifest_sha256": sha256_file(primary_manifest_path),
            "stress_manifest_sha256": sha256_file(stress_manifest_path),
            "external_manifest_sha256": sha256_file(arguments.external_workspace / "manifest.json"),
        },
        "verification": verification,
    }
    (output / "receipt.json").write_bytes(canonical_json_bytes(receipt) + b"\n")
    _write_readme(
        metrics=metrics,
        stress=stress,
        primary_manifest=primary_manifest,
        stress_manifest=stress_manifest,
        path=output / "README.md",
    )

    published_names = (
        "README.md",
        "metrics.json",
        "discovery-stress.json",
        "discovery-trials.csv",
        "external-confusion-matrices.png",
        "discovery-alignment-sensitivity.png",
        "receipt.json",
    )
    files = [
        {
            "path": name,
            "size_bytes": (output / name).stat().st_size,
            "sha256": sha256_file(output / name),
        }
        for name in published_names
    ]
    core = {
        "schema_version": "1.0",
        "artifact_type": "m5_external_generalization_published_manifest",
        "evaluation_id": primary_manifest["evaluation_id"],
        "stress_id": stress_manifest["stress_id"],
        "files": files,
    }
    manifest = {
        **core,
        "manifest_id": f"m5-external-published-{digest_object(core)[:24]}",
    }
    (output / "manifest.json").write_bytes(canonical_json_bytes(manifest) + b"\n")
    print(
        json.dumps(
            {
                "status": "published",
                "workspace": str(output),
                "evaluation_id": primary_manifest["evaluation_id"],
                "stress_id": stress_manifest["stress_id"],
                "published_file_count": len(files),
                "manifest_sha256": sha256_file(output / "manifest.json"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
