"""Alignment-sensitivity stress test for the external Data22 Discovery bursts."""

from __future__ import annotations

import csv
import json
import math
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file
from .config import load_yaml
from .external_generalization import (
    EXPECTED_COLUMNS,
    LABEL_COLUMN,
    ExternalGeneralizationError,
    _dependencies,
    _event,
    _external_label,
    _identity,
    _load_json,
    _predict,
    _validated_evaluation_inputs,
    _verified_sources,
    verify_external_generalization,
)
from .preprocessing import build_window_row, derived_json_bytes
from .storage import write_once


class DiscoveryStressError(ValueError):
    """Raised when the Discovery sensitivity contract cannot be reconstructed."""


def _utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def _episodes(
    target_events: list[tuple[str, float]], *, gap_seconds: float
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if not target_events:
        raise DiscoveryStressError("the controlled source contains no Discovery events")
    ordered = sorted(target_events, key=lambda item: (item[1], item[0]))
    groups: list[list[tuple[str, float]]] = [[]]
    previous: float | None = None
    for identity, timestamp in ordered:
        if previous is not None and timestamp - previous > gap_seconds:
            groups.append([])
        groups[-1].append((identity, timestamp))
        previous = timestamp

    episodes: list[dict[str, Any]] = []
    identity_to_episode: dict[str, str] = {}
    for index, group in enumerate(groups, start=1):
        identities = sorted(identity for identity, _ in group)
        timestamps = [timestamp for _, timestamp in group]
        episode_id = (
            f"discovery-burst-{index:02d}-{sha256_bytes(canonical_json_bytes(identities))[:16]}"
        )
        for identity in identities:
            identity_to_episode[identity] = episode_id
        episodes.append(
            {
                "burst_id": episode_id,
                "source_event_count": len(identities),
                "source_identity_set_sha256": sha256_bytes(canonical_json_bytes(identities)),
                "start_epoch": min(timestamps),
                "end_epoch": max(timestamps),
                "start_utc": _utc(min(timestamps)),
                "end_utc": _utc(max(timestamps)),
                "duration_seconds": max(timestamps) - min(timestamps),
            }
        )
    return episodes, identity_to_episode


def _external_audit_discovery_files(*, external_workspace: Path, target_label: str) -> list[str]:
    audit = _load_json(external_workspace / "audit.json")
    paths = [
        str(record["relative_path"])
        for record in audit.get("source_files", [])
        if int(record.get("raw_label_counts", {}).get(target_label, 0)) > 0
    ]
    if not paths:
        raise DiscoveryStressError(f"external audit contains no {target_label} source file")
    return sorted(paths)


def _target_events(
    *,
    source_root: Path,
    source_paths: list[str],
    target_label: str,
    benign_labels: set[str],
) -> list[tuple[str, float]]:
    events: dict[str, float] = {}
    for relative in source_paths:
        path = source_root / relative
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != EXPECTED_COLUMNS:
                raise DiscoveryStressError(f"unexpected Data22 schema in {relative}")
            for row in reader:
                if _external_label(row[LABEL_COLUMN], benign_labels) != target_label:
                    continue
                timestamp = float(row["ts"])
                if not math.isfinite(timestamp) or timestamp < 0:
                    raise DiscoveryStressError(f"invalid target timestamp in {relative}")
                events[_identity(row)] = timestamp
    return sorted(events.items(), key=lambda item: (item[1], item[0]))


def _context_events(
    *,
    source_root: Path,
    sources: list[dict[str, Any]],
    benign_labels: set[str],
    minimum_epoch: float,
    maximum_epoch: float,
) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for source in sources:
        relative = str(source["relative_path"])
        path = source_root / relative
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != EXPECTED_COLUMNS:
                raise DiscoveryStressError(f"unexpected Data22 schema in {relative}")
            for row in reader:
                timestamp = float(row["ts"])
                if timestamp < minimum_epoch or timestamp >= maximum_epoch:
                    continue
                identity = _identity(row)
                label = _external_label(row[LABEL_COLUMN], benign_labels)
                record = records.setdefault(
                    identity,
                    {"row": row, "labels": set(), "occurrence_count": 0},
                )
                record["labels"].add(label)
                record["occurrence_count"] += 1
    events = [
        _event(
            identity=identity,
            row=record["row"],
            labels=sorted(record["labels"]),
            occurrence_count=int(record["occurrence_count"]),
        )
        for identity, record in sorted(records.items())
    ]
    events.sort(
        key=lambda item: (
            item["capture_id"],
            item["timestamp"],
            item["uid"],
            item["source_identity_sha256"],
        )
    )
    return events


def _aligned_target_windows(
    *,
    events: list[dict[str, Any]],
    identity_to_episode: dict[str, str],
    offsets: list[int],
    window_seconds: int,
) -> list[dict[str, Any]]:
    windows: list[dict[str, Any]] = []
    for offset in offsets:
        grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            start = (
                math.floor((float(event["timestamp"]) - offset) / window_seconds) * window_seconds
                + offset
            )
            grouped[(str(event["capture_id"]), int(start))].append(event)
        for (capture_id, start), items in sorted(grouped.items()):
            target_ids = sorted(
                str(item["source_identity_sha256"])
                for item in items
                if str(item["source_identity_sha256"]) in identity_to_episode
            )
            if not target_ids:
                continue
            row, _ = build_window_row(
                events=items,
                capture_id=capture_id,
                bucket=start // window_seconds,
                window_seconds=window_seconds,
                client_id="external-data22",
                benign_labels={"benign"},
                mixed_attack_label="multi_tactic",
                split_seed=0,
                split_percentages={"train": 0, "validation": 0, "test": 100},
            )
            if offset == 0:
                window_id = (
                    "external-window-data22-"
                    f"{sha256_bytes(f'{capture_id}:{start // window_seconds}'.encode())[:24]}"
                )
            else:
                window_id = (
                    "discovery-stress-window-"
                    f"{sha256_bytes(f'{offset}:{capture_id}:{start}'.encode())[:24]}"
                )
            source_ids = sorted(str(item["source_identity_sha256"]) for item in items)
            row.update(
                {
                    "window_id": window_id,
                    "window_start_epoch": start,
                    "window_end_epoch": start + window_seconds,
                    "alignment_offset_seconds": offset,
                    "target_burst_ids": sorted(
                        {identity_to_episode[identity] for identity in target_ids}
                    ),
                    "target_discovery_event_count": len(target_ids),
                    "source_event_count": len(source_ids),
                    "source_identity_set_sha256": sha256_bytes(canonical_json_bytes(source_ids)),
                }
            )
            row.pop("source_event_ids", None)
            row["split"] = "discovery_stress"
            windows.append(row)
    windows.sort(
        key=lambda item: (
            int(item["alignment_offset_seconds"]),
            int(item["window_start_epoch"]),
            str(item["window_id"]),
        )
    )
    return windows


def _stress_summary(
    *,
    episodes: list[dict[str, Any]],
    offsets: list[int],
    records: list[dict[str, Any]],
    benign_label: str,
) -> dict[str, Any]:
    trials: list[dict[str, Any]] = []
    for episode in episodes:
        burst_id = str(episode["burst_id"])
        for offset in offsets:
            segments = [
                record
                for record in records
                if int(record["alignment_offset_seconds"]) == offset
                and burst_id in record["target_burst_ids"]
            ]
            if not segments:
                raise DiscoveryStressError(
                    f"missing aligned Discovery segment: {burst_id}/offset-{offset}"
                )
            detected = [record["predicted_model_label"] != benign_label for record in segments]
            trials.append(
                {
                    "burst_id": burst_id,
                    "alignment_offset_seconds": offset,
                    "segment_count": len(segments),
                    "any_segment_detected_as_attack": any(detected),
                    "all_segments_detected_as_attack": all(detected),
                    "predicted_model_labels": [
                        record["predicted_model_label"] for record in segments
                    ],
                    "minimum_maximum_softmax_probability": min(
                        float(record["maximum_softmax_probability"]) for record in segments
                    ),
                }
            )
    per_burst = []
    for episode in episodes:
        burst_id = str(episode["burst_id"])
        selected = [trial for trial in trials if trial["burst_id"] == burst_id]
        per_burst.append(
            {
                **episode,
                "alignment_count": len(selected),
                "any_segment_detection_count": sum(
                    bool(item["any_segment_detected_as_attack"]) for item in selected
                ),
                "all_segments_detection_count": sum(
                    bool(item["all_segments_detected_as_attack"]) for item in selected
                ),
                "any_segment_detection_fraction": sum(
                    bool(item["any_segment_detected_as_attack"]) for item in selected
                )
                / len(selected),
                "all_segments_detection_fraction": sum(
                    bool(item["all_segments_detected_as_attack"]) for item in selected
                )
                / len(selected),
            }
        )
    any_count = sum(bool(item["any_segment_detected_as_attack"]) for item in trials)
    all_count = sum(bool(item["all_segments_detected_as_attack"]) for item in trials)
    return {
        "independent_burst_count": len(episodes),
        "alignment_count": len(offsets),
        "correlated_burst_alignment_trial_count": len(trials),
        "any_segment_detection_count": any_count,
        "any_segment_detection_fraction": any_count / len(trials),
        "all_segments_detection_count": all_count,
        "all_segments_detection_fraction": all_count / len(trials),
        "per_burst": per_burst,
        "trials": trials,
        "independence_warning": (
            "Only temporal bursts are independent units. Offset trials reuse the same events "
            "and are descriptive sensitivity measurements, not additional samples."
        ),
    }


def _primary_discovery_predictions(primary_workspace: Path) -> list[dict[str, Any]]:
    records = [
        json.loads(line)
        for line in (primary_workspace / "predictions.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]
    return sorted(
        [item for item in records if item["actual_external_label"] == "discovery"],
        key=lambda item: item["window_id"],
    )


def _stress_artifacts(
    *,
    primary_workspace: Path,
    external_workspace: Path,
    source_root: Path,
    campaign_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    training_dataset_workspace: Path,
    primary_config_path: Path,
    config_path: Path,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    primary_status = verify_external_generalization(
        workspace=primary_workspace,
        external_workspace=external_workspace,
        source_root=source_root,
        campaign_workspace=campaign_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        training_dataset_workspace=training_dataset_workspace,
        config_path=primary_config_path,
    )
    if primary_status["status"] != "verified":
        raise DiscoveryStressError(
            f"primary external evaluation does not verify: {primary_status['errors']}"
        )
    validated = _validated_evaluation_inputs(
        external_workspace=external_workspace,
        campaign_workspace=campaign_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        training_dataset_workspace=training_dataset_workspace,
    )
    stress_config, stress_config_sha256 = load_yaml(config_path)
    primary_config, primary_config_sha256 = load_yaml(primary_config_path)
    settings = dict(stress_config.get("discovery_stress", {}))
    target_label = str(settings.get("target_label", "discovery"))
    window_seconds = int(settings.get("window_seconds", 60))
    offsets = [int(item) for item in settings.get("alignment_offsets_seconds", [])]
    gap_seconds = float(settings.get("episode_gap_seconds", 60))
    batch_size = int(settings.get("batch_size", 1024))
    if window_seconds != 60:
        raise DiscoveryStressError("stress window length must remain the trained 60 seconds")
    if not offsets or offsets != sorted(set(offsets)):
        raise DiscoveryStressError("alignment offsets must be non-empty, unique, and sorted")
    if offsets[0] < 0 or offsets[-1] >= window_seconds:
        raise DiscoveryStressError("alignment offsets must fall inside one 60-second window")
    if 0 not in offsets:
        raise DiscoveryStressError("alignment offsets must include the primary zero offset")
    if gap_seconds <= 0 or batch_size <= 0:
        raise DiscoveryStressError("episode gap and batch size must be positive")
    benign_labels = {
        str(item).strip().lower()
        for item in primary_config.get("external_dataset", {}).get("benign_labels", ["none"])
    }
    benign_label = str(primary_config.get("evaluation", {}).get("benign_label", "benign"))

    _source_manifest, sources = _verified_sources(source_root)
    discovery_files = _external_audit_discovery_files(
        external_workspace=external_workspace, target_label=target_label
    )
    targets = _target_events(
        source_root=source_root,
        source_paths=discovery_files,
        target_label=target_label,
        benign_labels=benign_labels,
    )
    episodes, identity_to_episode = _episodes(targets, gap_seconds=gap_seconds)
    minimum_epoch = min(timestamp for _, timestamp in targets) - window_seconds
    maximum_epoch = max(timestamp for _, timestamp in targets) + window_seconds
    events = _context_events(
        source_root=source_root,
        sources=sources,
        benign_labels=benign_labels,
        minimum_epoch=minimum_epoch,
        maximum_epoch=maximum_epoch,
    )
    windows = _aligned_target_windows(
        events=events,
        identity_to_episode=identity_to_episode,
        offsets=offsets,
        window_seconds=window_seconds,
    )

    np, torch = _dependencies()
    raw = np.asarray([row["features"] for row in windows], dtype=np.float64)
    means = np.asarray(validated["scaler"]["mean"], dtype=np.float64)
    scales = np.asarray(validated["scaler"]["scale"], dtype=np.float64)
    scaled = (raw - means) / scales
    if not np.isfinite(scaled).all():
        raise DiscoveryStressError("Discovery stress scaling produced non-finite values")
    prediction_ids, confidence = _predict(
        model_export=validated["model"],
        features=scaled,
        batch_size=batch_size,
        np=np,
        torch=torch,
    )
    class_names = validated["class_names"]
    prediction_records = [
        {
            "window_id": row["window_id"],
            "alignment_offset_seconds": row["alignment_offset_seconds"],
            "window_start_epoch": row["window_start_epoch"],
            "window_end_epoch": row["window_end_epoch"],
            "target_burst_ids": row["target_burst_ids"],
            "target_discovery_event_count": row["target_discovery_event_count"],
            "source_event_count": row["source_event_count"],
            "source_identity_set_sha256": row["source_identity_set_sha256"],
            "actual_external_label": row["label"],
            "predicted_model_label": class_names[prediction_id],
            "predicted_binary_label": (
                "benign" if class_names[prediction_id] == benign_label else "attack"
            ),
            "maximum_softmax_probability": round(probability, 12),
        }
        for row, prediction_id, probability in zip(windows, prediction_ids, confidence, strict=True)
    ]
    zero_offset = sorted(
        [record for record in prediction_records if record["alignment_offset_seconds"] == 0],
        key=lambda item: item["window_id"],
    )
    primary_discovery = _primary_discovery_predictions(primary_workspace)
    zero_projection = [
        {
            "window_id": item["window_id"],
            "predicted_model_label": item["predicted_model_label"],
            "predicted_binary_label": item["predicted_binary_label"],
            "maximum_softmax_probability": item["maximum_softmax_probability"],
        }
        for item in zero_offset
    ]
    primary_projection = [
        {
            "window_id": item["window_id"],
            "predicted_model_label": item["predicted_model_label"],
            "predicted_binary_label": item["predicted_binary_label"],
            "maximum_softmax_probability": item["maximum_softmax_probability"],
        }
        for item in primary_discovery
    ]
    if zero_projection != primary_projection:
        raise DiscoveryStressError(
            "zero-offset Discovery predictions do not reproduce the primary evaluation"
        )

    summary = _stress_summary(
        episodes=episodes,
        offsets=offsets,
        records=prediction_records,
        benign_label=benign_label,
    )
    stress = {
        "schema_version": "1.0",
        "artifact_type": "m5_discovery_alignment_stress",
        "target_label": target_label,
        "window_seconds": window_seconds,
        "alignment_offsets_seconds": offsets,
        "episode_gap_seconds": gap_seconds,
        "source_discovery_event_count": len(targets),
        "context_event_count": len(events),
        "stress_window_count": len(prediction_records),
        "source_files_with_discovery": discovery_files,
        "episodes": episodes,
        "summary": summary,
        "zero_offset_reproduces_primary_evaluation": True,
        "prediction_distribution": dict(
            sorted(Counter(item["predicted_model_label"] for item in prediction_records).items())
        ),
        "interpretation_constraints": [
            "The two temporal bursts, not the offset trials, are the independent units.",
            "Offsets retain the trained 60-second duration but reuse correlated source events.",
            "Discovery is outside the fixed model label space and is evaluated as binary attack detection only.",
            "Maximum softmax probability is descriptive and is not calibrated under domain shift.",
            "The stress test cannot establish population-level Discovery recall or confidence intervals.",
        ],
    }
    stress_bytes = derived_json_bytes(stress)
    predictions_bytes = b"".join(derived_json_bytes(item) for item in prediction_records)
    core = {
        "primary_evaluation_manifest_sha256": sha256_file(primary_workspace / "manifest.json"),
        "external_manifest_sha256": sha256_file(external_workspace / "manifest.json"),
        "campaign_manifest_sha256": sha256_file(campaign_workspace / "campaign-manifest.json"),
        "selected_round": validated["selected_round"],
        "selected_model_sha256": sha256_file(validated["model_path"]),
        "training_scaler_sha256": sha256_file(training_dataset_workspace / "scaler.json"),
        "primary_configuration_sha256": primary_config_sha256,
        "stress_configuration_sha256": stress_config_sha256,
        "stress_sha256": sha256_bytes(stress_bytes),
        "predictions_sha256": sha256_bytes(predictions_bytes),
    }
    stress_id = f"m5-discovery-stress-{sha256_bytes(canonical_json_bytes(core))[:24]}"
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "m5_discovery_stress_manifest",
        "stress_id": stress_id,
        "code_version": __version__,
        "implementation_files": {
            "discovery_stress.py": sha256_file(Path(__file__)),
            "external_generalization.py": sha256_file(
                Path(__file__).with_name("external_generalization.py")
            ),
            "preprocessing.py": sha256_file(Path(__file__).with_name("preprocessing.py")),
            "federated_model.py": sha256_file(Path(__file__).with_name("federated_model.py")),
        },
        "core": core,
        "artifacts": {
            "stress.json": sha256_bytes(stress_bytes),
            "predictions.jsonl": sha256_bytes(predictions_bytes),
        },
        "primary_evaluation_immutable": True,
    }
    artifacts = {
        "stress.json": stress_bytes,
        "predictions.jsonl": predictions_bytes,
        "manifest.json": derived_json_bytes(manifest),
    }
    return artifacts, stress


def create_discovery_stress(
    *,
    primary_workspace: Path,
    external_workspace: Path,
    source_root: Path,
    campaign_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    training_dataset_workspace: Path,
    primary_config_path: Path,
    config_path: Path,
    output: Path,
) -> dict[str, Any]:
    artifacts, stress = _stress_artifacts(
        primary_workspace=primary_workspace,
        external_workspace=external_workspace,
        source_root=source_root,
        campaign_workspace=campaign_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        training_dataset_workspace=training_dataset_workspace,
        primary_config_path=primary_config_path,
        config_path=config_path,
    )
    for name, value in artifacts.items():
        write_once(output / name, value)
    manifest = json.loads(artifacts["manifest.json"])
    summary = stress["summary"]
    return {
        "status": "discovery_stress_completed",
        "workspace": str(output),
        "stress_id": manifest["stress_id"],
        "source_discovery_event_count": stress["source_discovery_event_count"],
        "independent_burst_count": summary["independent_burst_count"],
        "alignment_count": summary["alignment_count"],
        "stress_window_count": stress["stress_window_count"],
        "any_segment_detection_fraction": summary["any_segment_detection_fraction"],
        "all_segments_detection_fraction": summary["all_segments_detection_fraction"],
        "zero_offset_reproduces_primary_evaluation": stress[
            "zero_offset_reproduces_primary_evaluation"
        ],
        "manifest_sha256": sha256_bytes(artifacts["manifest.json"]),
    }


def verify_discovery_stress(
    *,
    workspace: Path,
    primary_workspace: Path,
    external_workspace: Path,
    source_root: Path,
    campaign_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    training_dataset_workspace: Path,
    primary_config_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    stress_id: str | None = None
    source_recomputed = False
    predictions_recomputed = False
    summary_recomputed = False
    implementation_binding = False
    try:
        expected, stress = _stress_artifacts(
            primary_workspace=primary_workspace,
            external_workspace=external_workspace,
            source_root=source_root,
            campaign_workspace=campaign_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            training_dataset_workspace=training_dataset_workspace,
            primary_config_path=primary_config_path,
            config_path=config_path,
        )
        for name, value in expected.items():
            path = workspace / name
            if not path.is_file() or path.read_bytes() != value:
                errors.append(f"recomputed Discovery stress artifact mismatch: {name}")
        manifest = json.loads(expected["manifest.json"])
        stress_id = manifest["stress_id"]
        source_recomputed = True
        predictions_recomputed = (workspace / "predictions.jsonl").is_file() and (
            workspace / "predictions.jsonl"
        ).read_bytes() == expected["predictions.jsonl"]
        summary_recomputed = (workspace / "stress.json").is_file() and (
            workspace / "stress.json"
        ).read_bytes() == expected["stress.json"]
        implementation_binding = manifest["implementation_files"] == {
            "discovery_stress.py": sha256_file(Path(__file__)),
            "external_generalization.py": sha256_file(
                Path(__file__).with_name("external_generalization.py")
            ),
            "preprocessing.py": sha256_file(Path(__file__).with_name("preprocessing.py")),
            "federated_model.py": sha256_file(Path(__file__).with_name("federated_model.py")),
        }
        if stress["summary"]["independent_burst_count"] < 1:
            errors.append("Discovery stress contains no independent burst")
    except (ExternalGeneralizationError, FileNotFoundError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "stress_id": stress_id,
        "primary_evaluation_reverified": not errors,
        "source_recomputed": source_recomputed,
        "predictions_recomputed": predictions_recomputed,
        "summary_recomputed": summary_recomputed,
        "implementation_binding_verified": implementation_binding,
        "error_count": len(errors),
        "errors": errors,
    }
