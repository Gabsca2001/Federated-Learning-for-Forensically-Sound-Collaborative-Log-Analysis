#!/usr/bin/env python3
"""Publish a sanitized summary of an M6-linked M7 investigation chain."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


SNAPSHOT_TYPE = "published_m7_m6_investigation_snapshot_manifest"


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
    output: Path, *, enabled: bool, source_report_manifest_sha256: str
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
        or manifest.get("source_report_manifest_sha256")
        != source_report_manifest_sha256
    ):
        raise RuntimeError("existing snapshot belongs to a different M7 report")
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


def _validate_manifest(
    *, path: Path, artifact_type: str, identifier_field: str
) -> dict[str, Any]:
    manifest = _load(path)
    if manifest.get("artifact_type") != artifact_type:
        raise ValueError(f"unexpected manifest type: {path}")
    core = manifest.get("core")
    if not isinstance(core, dict):
        raise ValueError(f"manifest has no canonical core: {path}")
    serialized = _json_bytes(core)
    accepted_digests = {
        hashlib.sha256(serialized[:-1]).hexdigest(),
        hashlib.sha256(serialized).hexdigest(),
    }
    if manifest.get("canonical_core_sha256") not in accepted_digests:
        raise ValueError(f"manifest canonical core digest mismatch: {path}")
    identifier = manifest.get(identifier_field)
    if not isinstance(identifier, str) or not identifier:
        raise ValueError(f"manifest identifier is missing: {path}")
    return manifest


def _require_digest(path: Path, expected: Any, description: str) -> None:
    if not path.is_file() or _sha256(path) != str(expected):
        raise ValueError(f"{description} digest mismatch")


def _prediction_figure(
    *, labels: list[str], case_rows: list[dict[str, Any]]
) -> bytes:
    matrix = np.zeros((len(labels), len(labels)), dtype=np.int64)
    index = {name: position for position, name in enumerate(labels)}
    for row in case_rows:
        matrix[index[str(row["reference_label"])]][
            index[str(row["predicted_class"])]
        ] += 1
    figure, axis = plt.subplots(figsize=(8.8, 6.8))
    image = axis.imshow(matrix, cmap="Blues", vmin=0)
    maximum = max(int(matrix.max()), 1)
    for actual in range(len(labels)):
        for predicted in range(len(labels)):
            value = int(matrix[actual, predicted])
            axis.text(
                predicted,
                actual,
                str(value),
                ha="center",
                va="center",
                color="white" if value > maximum / 2 else "black",
            )
    display = [item.replace("_", " ") for item in labels]
    axis.set_xticks(range(len(labels)), labels=display, rotation=35, ha="right")
    axis.set_yticks(range(len(labels)), labels=display)
    axis.set_xlabel("Predicted")
    axis.set_ylabel("Evaluation label")
    axis.set_title("Deterministic 16-case selection — not a performance estimate")
    figure.colorbar(image, ax=axis, label="Case count")
    figure.tight_layout()
    return _figure_bytes(figure)


def _feature_figure(feature_rows: list[dict[str, Any]]) -> bytes:
    selected = sorted(
        feature_rows,
        key=lambda row: float(row["mean_absolute_attribution"]),
        reverse=True,
    )[:10]
    selected.reverse()
    figure, axis = plt.subplots(figsize=(9.4, 5.8))
    axis.barh(
        [str(row["feature_name"]).replace("_", " ") for row in selected],
        [float(row["mean_absolute_attribution"]) for row in selected],
        color="#5e35b1",
    )
    axis.set_xlabel("Mean absolute Integrated Gradients attribution")
    axis.set_title("Most influential features across the fixed 16-case bundle")
    axis.grid(axis="x", alpha=0.25)
    figure.tight_layout()
    return _figure_bytes(figure)


def _prototype_figure(case_rows: list[dict[str, Any]]) -> bytes:
    figure, axis = plt.subplots(figsize=(9.2, 5.8))
    matches = [row for row in case_rows if row["prediction_matches_nearest_prototype"]]
    differs = [row for row in case_rows if not row["prediction_matches_nearest_prototype"]]
    for rows, label, color, marker in (
        (matches, "Prediction matches nearest prototype", "#2e7d32", "o"),
        (differs, "Prediction differs from nearest prototype", "#c62828", "X"),
    ):
        if rows:
            axis.scatter(
                [float(row["nearest_prototype_distance"]) for row in rows],
                [float(row["nearest_prototype_margin"]) for row in rows],
                label=label,
                color=color,
                marker=marker,
                s=58,
                alpha=0.85,
            )
    axis.set_xlabel("Distance to nearest training prototype")
    axis.set_ylabel("Nearest-to-second-nearest distance margin")
    axis.set_title("Prototype geometry for the fixed 16-case bundle")
    axis.grid(alpha=0.25)
    axis.legend()
    figure.tight_layout()
    return _figure_bytes(figure)


def _mapping_figure(status_counts: Counter[str]) -> bytes:
    statuses = ("candidate-tactic", "not-applicable", "unresolved-multi-tactic")
    labels = ("Candidate tactic", "Not applicable", "Unresolved")
    values = [status_counts[name] for name in statuses]
    figure, axis = plt.subplots(figsize=(8.0, 4.8))
    bars = axis.bar(labels, values, color=("#1565c0", "#78909c", "#f9a825"))
    axis.set_ylabel("Cases")
    axis.set_ylim(0, max(values, default=0) + 2)
    axis.set_title("MITRE ATT&CK v19.2 mapping outcomes")
    axis.grid(axis="y", alpha=0.25)
    for bar, value in zip(bars, values, strict=True):
        axis.text(
            bar.get_x() + bar.get_width() / 2,
            value + 0.15,
            str(value),
            ha="center",
            va="bottom",
        )
    figure.tight_layout()
    return _figure_bytes(figure)


def _index_unique(
    rows: list[dict[str, Any]], *, key: str, description: str
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        value = str(row.get(key, ""))
        if not value or value in result:
            raise ValueError(f"invalid or duplicate {description}: {value}")
        result[value] = row
    return result


def _source_set_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.parent.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def publish(
    *,
    prediction_workspace: Path,
    explanation_workspace: Path,
    attack_workspace: Path,
    report_workspace: Path,
    output: Path,
    replace_existing_snapshot: bool,
) -> dict[str, Any]:
    prediction_workspace = prediction_workspace.resolve()
    explanation_workspace = explanation_workspace.resolve()
    attack_workspace = attack_workspace.resolve()
    report_workspace = report_workspace.resolve()
    output = output.resolve()

    prediction_manifest_path = prediction_workspace / "manifest.json"
    explanation_manifest_path = explanation_workspace / "manifest.json"
    attack_manifest_path = attack_workspace / "manifest.json"
    report_manifest_path = report_workspace / "manifest.json"
    prediction_manifest = _validate_manifest(
        path=prediction_manifest_path,
        artifact_type="m7_prediction_bundle_manifest",
        identifier_field="bundle_id",
    )
    explanation_manifest = _validate_manifest(
        path=explanation_manifest_path,
        artifact_type="m7_explanation_bundle_manifest",
        identifier_field="explanation_bundle_id",
    )
    attack_manifest = _validate_manifest(
        path=attack_manifest_path,
        artifact_type="m7_attack_mapping_bundle_manifest",
        identifier_field="attack_mapping_bundle_id",
    )
    report_manifest = _validate_manifest(
        path=report_manifest_path,
        artifact_type="m7_investigation_report_bundle_manifest",
        identifier_field="investigation_report_bundle_id",
    )

    prediction_core = prediction_manifest["core"]
    explanation_core = explanation_manifest["core"]
    attack_core = attack_manifest["core"]
    report_core = report_manifest["core"]
    predictions_path = prediction_workspace / "predictions.json"
    lineage_path = prediction_workspace / "lineage.json"
    integrated_gradients_path = explanation_workspace / "integrated-gradients.json"
    prototype_reference_path = explanation_workspace / "prototype-reference.json"
    prototype_distances_path = explanation_workspace / "prototype-distances.json"
    attack_mappings_path = attack_workspace / "attack-mappings.json"
    investigation_report_path = report_workspace / "investigation-report.json"
    report_markdown_path = report_workspace / "report.md"

    digest_checks = (
        (predictions_path, prediction_core["predictions_sha256"], "predictions"),
        (lineage_path, prediction_core["lineage_sha256"], "prediction lineage"),
        (
            integrated_gradients_path,
            explanation_core["integrated_gradients_sha256"],
            "Integrated Gradients",
        ),
        (
            prototype_reference_path,
            explanation_core["prototype_reference_sha256"],
            "prototype reference",
        ),
        (
            prototype_distances_path,
            explanation_core["prototype_distances_sha256"],
            "prototype distances",
        ),
        (attack_mappings_path, attack_core["attack_mappings_sha256"], "ATT&CK mappings"),
        (
            investigation_report_path,
            report_core["investigation_report_sha256"],
            "investigation report",
        ),
        (report_markdown_path, report_core["report_markdown_sha256"], "report Markdown"),
    )
    for path, expected, description in digest_checks:
        _require_digest(path, expected, description)

    prediction_manifest_sha256 = _sha256(prediction_manifest_path)
    explanation_manifest_sha256 = _sha256(explanation_manifest_path)
    attack_manifest_sha256 = _sha256(attack_manifest_path)
    report_manifest_sha256 = _sha256(report_manifest_path)
    prediction_source = prediction_core["sources"]
    explanation_source = explanation_core["source"]
    attack_source = attack_core["source"]
    report_source = report_core["source"]
    for description, core in (
        ("prediction", prediction_core),
        ("explanation", explanation_core),
        ("attack", attack_core),
        ("report", report_core),
    ):
        gate = core.get("reportability_gate", {})
        if (
            gate.get("reportable") is not True
            or int(gate.get("invariant_violation_count", -1)) != 0
        ):
            raise ValueError(f"{description} source is not reportable")
    common = {
        "campaign_id": prediction_source["campaign_id"],
        "round_number": prediction_source["round_number"],
        "global_model_sha256": prediction_source["global_model_sha256"],
        "partition_manifest_sha256": prediction_source["partition_manifest_sha256"],
    }
    for description, source in (
        ("explanation", explanation_source),
        ("attack", attack_source),
        ("report", report_source),
    ):
        if any(source.get(name) != value for name, value in common.items()):
            raise ValueError(f"{description} source differs from the prediction source")
    if (
        explanation_source["prediction_bundle_id"] != prediction_manifest["bundle_id"]
        or explanation_source["prediction_manifest_sha256"]
        != prediction_manifest_sha256
        or attack_source["prediction_bundle_id"] != prediction_manifest["bundle_id"]
        or attack_source["prediction_manifest_sha256"]
        != prediction_manifest_sha256
        or attack_source["explanation_bundle_id"]
        != explanation_manifest["explanation_bundle_id"]
        or attack_source["explanation_manifest_sha256"]
        != explanation_manifest_sha256
        or report_source["prediction_bundle_id"] != prediction_manifest["bundle_id"]
        or report_source["prediction_manifest_sha256"]
        != prediction_manifest_sha256
        or report_source["explanation_bundle_id"]
        != explanation_manifest["explanation_bundle_id"]
        or report_source["explanation_manifest_sha256"]
        != explanation_manifest_sha256
        or report_source["attack_mapping_bundle_id"]
        != attack_manifest["attack_mapping_bundle_id"]
        or report_source["attack_manifest_sha256"] != attack_manifest_sha256
    ):
        raise ValueError("M7 bundle lineage is not transitively bound")

    predictions = _load(predictions_path)
    integrated_gradients = _load(integrated_gradients_path)
    prototype_distances = _load(prototype_distances_path)
    attack_mappings = _load(attack_mappings_path)
    investigation_report = _load(investigation_report_path)
    prediction_rows = list(predictions.get("predictions", []))
    ig_rows = list(integrated_gradients.get("explanations", []))
    prototype_rows = list(prototype_distances.get("explanations", []))
    mapping_rows = list(attack_mappings.get("mappings", []))
    report_cases = list(investigation_report.get("cases", []))
    count = int(prediction_core["prediction_count"])
    if predictions.get("reference_labels_used_for_inference") is not False:
        raise ValueError("prediction source used reference labels for inference")
    if integrated_gradients.get("causal_claim") is not False:
        raise ValueError("Integrated Gradients source asserts causality")
    if prototype_distances.get("row_embeddings_preserved") is not False:
        raise ValueError("prototype source preserved row embeddings")
    if attack_mappings.get("technique_claims_enabled") is not False:
        raise ValueError("ATT&CK source enabled unsupported technique claims")
    if count <= 0 or any(
        len(rows) != count
        for rows in (prediction_rows, ig_rows, prototype_rows, mapping_rows, report_cases)
    ):
        raise ValueError("M7 bundle counts are incomplete or inconsistent")

    predictions_by_id = _index_unique(
        prediction_rows, key="prediction_id", description="prediction id"
    )
    ig_by_id = _index_unique(ig_rows, key="prediction_id", description="IG prediction id")
    prototype_by_id = _index_unique(
        prototype_rows, key="prediction_id", description="prototype prediction id"
    )
    mapping_by_id = _index_unique(
        mapping_rows, key="prediction_id", description="mapping prediction id"
    )
    cases_by_id: dict[str, dict[str, Any]] = {}
    for case in report_cases:
        prediction_id = str(case.get("identity", {}).get("prediction_id", ""))
        if not prediction_id or prediction_id in cases_by_id:
            raise ValueError(f"invalid or duplicate report prediction id: {prediction_id}")
        cases_by_id[prediction_id] = case
    expected_ids = set(predictions_by_id)
    if any(set(index) != expected_ids for index in (ig_by_id, prototype_by_id, mapping_by_id, cases_by_id)):
        raise ValueError("M7 case identities differ across bundles")

    case_rows: list[dict[str, Any]] = []
    prototype_public_rows: list[dict[str, Any]] = []
    mapping_public_rows: list[dict[str, Any]] = []
    all_feature_values: dict[str, list[dict[str, Any]]] = {}
    for number, prediction_id in enumerate(
        [str(row["prediction_id"]) for row in prediction_rows], start=1
    ):
        prediction = predictions_by_id[prediction_id]
        ig = ig_by_id[prediction_id]
        prototype = prototype_by_id[prediction_id]
        mapping = mapping_by_id[prediction_id]
        case = cases_by_id[prediction_id]
        window_id = str(prediction["window_id"])
        if any(
            str(item.get("window_id")) != window_id
            for item in (ig, prototype, mapping)
        ) or str(case["identity"]["window_id"]) != window_id:
            raise ValueError(f"M7 case window binding mismatch: {prediction_id}")
        feature_values = list(ig.get("feature_attributions", []))
        if len(feature_values) != int(explanation_core["feature_count"]):
            raise ValueError(f"incomplete attribution vector: {prediction_id}")
        for feature in feature_values:
            all_feature_values.setdefault(str(feature["feature_name"]), []).append(feature)
        top_feature = min(feature_values, key=lambda item: int(item["absolute_rank"]))
        tactic_candidates = list(mapping.get("tactic_candidates", []))
        tactics = "|".join(
            f"{item['tactic_id']}:{item['tactic_name']}" for item in tactic_candidates
        )
        reference_label = str(prediction["reference_label"])
        predicted_class = str(prediction["predicted_class"])
        public_case = {
            "case_number": number,
            "case_id": str(case["case_id"]),
            "prediction_id": prediction_id,
            "window_id": window_id,
            "reference_label": reference_label,
            "reference_label_role": "evaluation-only-not-used-for-selection-or-inference",
            "predicted_class": predicted_class,
            "prediction_correct": reference_label == predicted_class,
            "confidence": float(prediction["confidence"]),
            "probability_margin": float(prediction["probability_margin"]),
            "ig_steps": int(ig["steps"]),
            "ig_absolute_completeness_error": float(ig["absolute_completeness_error"]),
            "top_absolute_feature": str(top_feature["feature_name"]),
            "top_absolute_attribution": float(top_feature["attribution"]),
            "top_feature_direction": str(top_feature["direction_for_target_logit"]),
            "nearest_prototype_class": str(prototype["nearest_prototype_class"]),
            "prediction_matches_nearest_prototype": bool(
                prototype["prediction_matches_nearest_prototype"]
            ),
            "nearest_prototype_distance": float(
                prototype["nearest_prototype_distance"]
            ),
            "nearest_prototype_margin": float(prototype["nearest_prototype_margin"]),
            "mapping_status": str(mapping["mapping_status"]),
            "tactic_candidates": tactics,
            "source_event_count": int(case["primary_evidence"]["source_event_count"]),
        }
        case_rows.append(public_case)
        prototype_public_rows.append(
            {
                "case_number": number,
                "prediction_id": prediction_id,
                "predicted_class": predicted_class,
                "nearest_prototype_class": str(prototype["nearest_prototype_class"]),
                "second_nearest_prototype_class": str(
                    prototype["second_nearest_prototype_class"]
                ),
                "prediction_matches_nearest_prototype": bool(
                    prototype["prediction_matches_nearest_prototype"]
                ),
                "nearest_prototype_distance": float(
                    prototype["nearest_prototype_distance"]
                ),
                "second_nearest_prototype_distance": float(
                    prototype["second_nearest_prototype_distance"]
                ),
                "nearest_prototype_margin": float(
                    prototype["nearest_prototype_margin"]
                ),
                "predicted_class_prototype_distance": float(
                    prototype["predicted_class_prototype_distance"]
                ),
                "predicted_class_prototype_rank": int(
                    prototype["predicted_class_prototype_rank"]
                ),
            }
        )
        mapping_public_rows.append(
            {
                "case_number": number,
                "prediction_id": prediction_id,
                "predicted_class": predicted_class,
                "mapping_status": str(mapping["mapping_status"]),
                "rule_id": str(mapping["rule_id"]),
                "tactic_candidates": tactics,
                "technique_candidates_enabled": False,
                "decision_basis": str(mapping["decision_basis"]),
            }
        )

    feature_rows: list[dict[str, Any]] = []
    for feature_name in sorted(all_feature_values):
        values = all_feature_values[feature_name]
        signed = [float(item["attribution"]) for item in values]
        absolute = [abs(value) for value in signed]
        feature_rows.append(
            {
                "feature_name": feature_name,
                "case_count": len(values),
                "mean_signed_attribution": statistics.fmean(signed),
                "mean_absolute_attribution": statistics.fmean(absolute),
                "median_absolute_attribution": statistics.median(absolute),
                "top_rank_count": sum(int(item["absolute_rank"]) == 1 for item in values),
                "supports_target_count": sum(
                    item["direction_for_target_logit"] == "supports-target"
                    for item in values
                ),
                "opposes_target_count": sum(
                    item["direction_for_target_logit"] == "opposes-target"
                    for item in values
                ),
            }
        )
    if len(feature_rows) != int(explanation_core["feature_count"]):
        raise ValueError("public feature summary is incomplete")

    labels = [str(item) for item in predictions["class_names"]]
    missing_reference_classes = sorted(
        set(labels) - set(str(item["reference_label"]) for item in prediction_rows)
    )
    correct_count = sum(bool(row["prediction_correct"]) for row in case_rows)
    prototype_match_count = sum(
        bool(row["prediction_matches_nearest_prototype"]) for row in case_rows
    )
    mapping_status_counts = Counter(str(row["mapping_status"]) for row in case_rows)
    reference_counts = Counter(str(row["reference_label"]) for row in case_rows)
    predicted_counts = Counter(str(row["predicted_class"]) for row in case_rows)
    top_features = sorted(
        feature_rows,
        key=lambda row: float(row["mean_absolute_attribution"]),
        reverse=True,
    )[:5]
    selection = prediction_core["selection"]
    summary = {
        "schema_version": "1.0",
        "artifact_type": "published_m7_m6_investigation_summary",
        "status": "verified-source-sanitized-summary",
        "campaign_id": common["campaign_id"],
        "round_number": common["round_number"],
        "global_model_sha256": common["global_model_sha256"],
        "prediction_bundle_id": prediction_manifest["bundle_id"],
        "explanation_bundle_id": explanation_manifest["explanation_bundle_id"],
        "attack_mapping_bundle_id": attack_manifest["attack_mapping_bundle_id"],
        "investigation_report_bundle_id": report_manifest[
            "investigation_report_bundle_id"
        ],
        "source_manifest_sha256": {
            "prediction": prediction_manifest_sha256,
            "explanation": explanation_manifest_sha256,
            "attack": attack_manifest_sha256,
            "report": report_manifest_sha256,
        },
        "source_checkpoint": {
            "checkpoint_id": prediction_source["checkpoint_id"],
            "checkpoint_manifest_sha256": prediction_source[
                "checkpoint_manifest_sha256"
            ],
            "round_context_sha256": prediction_source["round_context_sha256"],
        },
        "selection": {
            "split": selection["split"],
            "method": selection["method"],
            "provenance": selection["selection_provenance"],
            "case_count": count,
        },
        "descriptive_evaluation": {
            "correct_count": correct_count,
            "incorrect_count": count - correct_count,
            "accuracy": correct_count / count,
            "reference_class_counts": dict(sorted(reference_counts.items())),
            "predicted_class_counts": dict(sorted(predicted_counts.items())),
            "missing_reference_classes": missing_reference_classes,
            "performance_estimate": False,
        },
        "explanation": {
            "feature_count": int(explanation_core["feature_count"]),
            "class_count": int(explanation_core["class_count"]),
            "maximum_absolute_completeness_error": int(
                explanation_core["maximum_absolute_completeness_error_scaled_1e12"]
            )
            / 1_000_000_000_000,
            "prototype_match_count": prototype_match_count,
            "prototype_match_fraction": prototype_match_count / count,
            "top_features_by_mean_absolute_attribution": [
                {
                    "feature_name": str(row["feature_name"]),
                    "mean_absolute_attribution": float(
                        row["mean_absolute_attribution"]
                    ),
                }
                for row in top_features
            ],
        },
        "attack_mapping": {
            "framework": attack_core["framework"],
            "version": attack_core["attack_version"],
            "candidate_tactic_count": mapping_status_counts["candidate-tactic"],
            "not_applicable_count": mapping_status_counts["not-applicable"],
            "unresolved_count": mapping_status_counts["unresolved-multi-tactic"],
            "technique_claims_enabled": False,
        },
        "lineage": {
            "source_event_count": int(report_core["source_event_count"]),
            "source_record_count": int(report_core["source_record_count"]),
            "complete": True,
        },
        "interpretation_boundaries": [
            "the fixed 16-case selection is not a population performance estimate",
            "reference labels are evaluation-only and were not used for selection or inference",
            "Integrated Gradients describes model sensitivity, not causal evidence",
            "prototype distances describe embedding geometry, not malicious intent",
            "ATT&CK mappings are predicted-class hypotheses and contain no technique claims",
            "raw lineage records, source paths, model parameters, and embeddings are not published",
        ],
    }

    case_fields = list(case_rows[0])
    feature_fields = list(feature_rows[0])
    prototype_fields = list(prototype_public_rows[0])
    mapping_fields = list(mapping_public_rows[0])
    top_feature_text = ", ".join(
        f"`{row['feature_name']}` ({float(row['mean_absolute_attribution']):.4f})"
        for row in top_features
    )
    readme = f"""# Verified M7 investigation of the M6 disagreement checkpoint

This sanitized snapshot reports the deterministic 16-case M7 investigation bound to
M6 campaign `{common['campaign_id']}`, selected round `{common['round_number']}`, and global
model `{common['global_model_sha256']}`. The complete source bundles remain under `artifacts/`
and are intended for M8 preservation; this directory publishes only bounded derived fields.

## Verified chain

- prediction bundle: `{prediction_manifest['bundle_id']}`;
- explanation bundle: `{explanation_manifest['explanation_bundle_id']}`;
- ATT&CK mapping bundle: `{attack_manifest['attack_mapping_bundle_id']}`;
- investigation report: `{report_manifest['investigation_report_bundle_id']}`;
- complete primary-evidence lineage: `{int(report_core['source_event_count'])}` normalized events
  and `{int(report_core['source_record_count'])}` controlled-ingestion source records;
- source manifest and artifact digests are recorded in `summary.json` and `manifest.json`.

The prediction bundle selected the first `{count}` test window identifiers in lexicographic
order. Selection used no label, prediction, confidence, or metric. The bundle produced
`{correct_count}/{count}` correct evaluation outcomes (`{correct_count / count:.1%}`), but this
small fixed case set is an investigative demonstration and **not** a model-performance estimate.
Population-level test performance remains the isolated M6 evaluation.

## Explanation result

Integrated Gradients explained all `{count}` cases across
`{int(explanation_core['feature_count'])}` features. Maximum absolute completeness error was
`{int(explanation_core['maximum_absolute_completeness_error_scaled_1e12']) / 1_000_000_000_000:.9f}`,
below the configured `0.001` threshold. The five largest features by mean absolute attribution
were {top_feature_text}.

The predicted class matched the nearest training-only prototype in
`{prototype_match_count}/{count}` cases (`{prototype_match_count / count:.1%}`). Distances and
margins are model-geometry measurements; no row embeddings or global prototype vectors are
published here.

## ATT&CK result

MITRE ATT&CK Enterprise v{attack_core['attack_version']} produced
`{mapping_status_counts['candidate-tactic']}` candidate-tactic cases,
`{mapping_status_counts['not-applicable']}` benign/not-applicable cases, and
`{mapping_status_counts['unresolved-multi-tactic']}` deliberately unresolved multi-tactic cases.
The rule uses only the predicted class. Reference labels, Integrated Gradients, prototype
distances, and dataset ATT&CK annotations are excluded from rule selection. Technique-level
claims remain disabled.

## Files

- `summary.json`: compact source bindings, counts, descriptive measurements, and boundaries;
- `cases.csv`: one sanitized row per fixed case, including evaluation-only label and model/XAI
  summaries;
- `feature-attributions.csv`: aggregate attribution statistics for all 25 features;
- `prototype-summary.csv`: per-case nearest-prototype geometry without embeddings;
- `attack-mappings.csv`: per-case tactic status and rule, without source-record detail;
- `prediction-outcomes.png`: count matrix for the fixed selection, explicitly not a performance
  estimate;
- `feature-attributions.png`: ten largest mean absolute IG attributions;
- `prototype-distances.png`: nearest distance and separation margin;
- `attack-mapping-outcomes.png`: candidate, not-applicable, and unresolved counts;
- `manifest.json`: SHA-256 inventory of every published file and source-manifest bindings.

## Interpretation and disclosure boundary

Integrated Gradients and prototype geometry explain model behaviour; they do not establish
causality or malicious intent. ATT&CK entries are investigative hypotheses, not primary evidence.
`cases.csv` includes reference labels only for post-selection evaluation and labels that role
explicitly. This snapshot excludes source paths and row numbers, raw Zeek data, complete lineage
records, scaled input vectors, logits and probability vectors, model parameters, prototype
vectors, row embeddings, client updates, and private trust material.
""".encode("utf-8")

    files: dict[str, bytes] = {
        "README.md": readme,
        "summary.json": _json_bytes(summary),
        "cases.csv": _csv_bytes(case_fields, case_rows),
        "feature-attributions.csv": _csv_bytes(feature_fields, feature_rows),
        "prototype-summary.csv": _csv_bytes(prototype_fields, prototype_public_rows),
        "attack-mappings.csv": _csv_bytes(mapping_fields, mapping_public_rows),
        "prediction-outcomes.png": _prediction_figure(
            labels=labels, case_rows=case_rows
        ),
        "feature-attributions.png": _feature_figure(feature_rows),
        "prototype-distances.png": _prototype_figure(case_rows),
        "attack-mapping-outcomes.png": _mapping_figure(mapping_status_counts),
    }
    replace = _authorize_replacement(
        output,
        enabled=replace_existing_snapshot,
        source_report_manifest_sha256=report_manifest_sha256,
    )
    for name, content in files.items():
        _write_once(output / name, content, replace=replace)

    source_manifest_paths = [
        prediction_manifest_path,
        explanation_manifest_path,
        attack_manifest_path,
        report_manifest_path,
    ]
    manifest = {
        "schema_version": "1.0",
        "artifact_type": SNAPSHOT_TYPE,
        "source_report_manifest_sha256": report_manifest_sha256,
        "source_manifest_set_sha256": _source_set_digest(source_manifest_paths),
        "source_manifests": {
            "prediction": prediction_manifest_sha256,
            "explanation": explanation_manifest_sha256,
            "attack": attack_manifest_sha256,
            "report": report_manifest_sha256,
        },
        "source_bundle_ids": {
            "prediction": prediction_manifest["bundle_id"],
            "explanation": explanation_manifest["explanation_bundle_id"],
            "attack": attack_manifest["attack_mapping_bundle_id"],
            "report": report_manifest["investigation_report_bundle_id"],
        },
        "files": {
            name: {"sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)}
            for name, content in sorted(files.items())
        },
        "privacy_boundary": (
            "sanitized derived summary; no raw lineage, source paths, feature rows, "
            "embeddings, model parameters, client updates, or private trust material"
        ),
    }
    manifest_bytes = _json_bytes(manifest)
    _write_once(output / "manifest.json", manifest_bytes, replace=replace)
    return {
        "status": "published",
        "campaign_id": common["campaign_id"],
        "round_number": common["round_number"],
        "case_count": count,
        "correct_case_count": correct_count,
        "prototype_match_count": prototype_match_count,
        "candidate_tactic_count": mapping_status_counts["candidate-tactic"],
        "unresolved_count": mapping_status_counts["unresolved-multi-tactic"],
        "source_event_count": int(report_core["source_event_count"]),
        "source_record_count": int(report_core["source_record_count"]),
        "file_count": len(files) + 1,
        "workspace": str(output),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prediction-workspace", type=Path, required=True)
    parser.add_argument("--explanation-workspace", type=Path, required=True)
    parser.add_argument("--attack-workspace", type=Path, required=True)
    parser.add_argument("--report-workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replace-existing-snapshot", action="store_true")
    arguments = parser.parse_args()
    result = publish(
        prediction_workspace=arguments.prediction_workspace,
        explanation_workspace=arguments.explanation_workspace,
        attack_workspace=arguments.attack_workspace,
        report_workspace=arguments.report_workspace,
        output=arguments.output,
        replace_existing_snapshot=arguments.replace_existing_snapshot,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
