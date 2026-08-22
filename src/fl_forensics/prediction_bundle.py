"""M7 prediction bundles with fail-closed lineage to controlled Zeek records."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from . import __version__
from .byzantine_experiment import _verify_partition_snapshot_files
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file
from .config import load_yaml
from .federated_model import arrays_from_export, build_model, load_ndarrays
from .federated_partitioning import verify_partitions
from .investigation_models import (
    PredictionBundleCore,
    PredictionBundleManifest,
    PredictionReportabilityGate,
    PredictionSelection,
    PredictionSourceReferences,
)
from .preprocessing import derived_json_bytes
from .secure_round import verify_secure_round
from .storage import load_json, write_once


class PredictionBundleError(RuntimeError):
    """Raised when inference or its evidentiary lineage cannot be completed."""


def _ml_dependencies() -> tuple[Any, Any]:
    try:
        import numpy as np
        import torch
    except ImportError as exc:
        raise PredictionBundleError(
            'M7 prediction bundles require: python -m pip install -e ".[federated]"'
        ) from exc
    return np, torch


def _hex_digest(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _validate_config(config: dict[str, Any]) -> dict[str, Any]:
    investigation = config.get("investigation", {})
    if investigation.get("schema_version") != "1.0":
        raise PredictionBundleError("unexpected M7 investigation schema")
    allowed_splits = [str(item) for item in investigation.get("allowed_splits", [])]
    if allowed_splits != ["validation", "test", "temporal_holdout"]:
        raise PredictionBundleError("M7 allowed splits differ from the frozen contract")
    maximum = int(investigation.get("maximum_windows_per_bundle", 0))
    if maximum <= 0:
        raise PredictionBundleError("maximum prediction bundle size must be positive")
    inference = investigation.get("inference", {})
    if inference.get("method") != "classification-head-softmax-argmax":
        raise PredictionBundleError("unexpected M7 inference method")
    if inference.get("device") != "cpu":
        raise PredictionBundleError("M7 deterministic prediction inference requires CPU")
    if int(inference.get("round_digits", -1)) != 12:
        raise PredictionBundleError("M7 prediction rounding must remain 12 digits")
    reportability = investigation.get("reportability", {})
    required_flags = (
        "require_verified_checkpoint",
        "require_verified_partition",
        "require_verified_m2_snapshot",
        "require_complete_event_lineage",
        "require_source_record_digests",
    )
    if any(reportability.get(name) is not True for name in required_flags):
        raise PredictionBundleError("all M7 reportability gates must be enabled")
    return investigation


def _source_file_index(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in manifest.get("source_files", []):
        relative_path = str(record.get("relative_path", ""))
        if (
            not relative_path
            or relative_path in result
            or not _hex_digest(record.get("sha256"))
            or int(record.get("size_bytes", -1)) <= 0
        ):
            raise PredictionBundleError("invalid or duplicate M2 source-file reference")
        result[relative_path] = {
            "relative_path": relative_path,
            "sha256": str(record["sha256"]),
            "size_bytes": int(record["size_bytes"]),
            "source_url": str(record.get("source_url", "")),
        }
    if not result:
        raise PredictionBundleError("M2 manifest does not reference source files")
    return result


def _selected_rows(
    *,
    server: dict[str, Any],
    split: str,
    window_ids: list[str] | None,
    first: int | None,
    maximum: int,
) -> tuple[list[dict[str, Any]], PredictionSelection]:
    if split not in {"validation", "test", "temporal_holdout"}:
        raise PredictionBundleError("prediction split is not allowed")
    if (window_ids is None) == (first is None):
        raise PredictionBundleError("choose either explicit window ids or --first")
    rows = list(server.get("rows", {}).get(split, []))
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        window_id = str(row.get("window_id", ""))
        if not window_id or window_id in by_id:
            raise PredictionBundleError(f"invalid or duplicate M3 window id: {window_id}")
        by_id[window_id] = row
    if first is not None:
        if first <= 0 or first > maximum:
            raise PredictionBundleError("--first exceeds the configured bundle size")
        selected_ids = sorted(by_id)[:first]
        if len(selected_ids) != first:
            raise PredictionBundleError("evaluation split has fewer rows than requested")
        method = "lexicographic-first-window-ids"
        selection_provenance = "window-id-only-no-label-prediction-or-metric"
    else:
        assert window_ids is not None
        if (
            not window_ids
            or len(window_ids) > maximum
            or len(window_ids) != len(set(window_ids))
        ):
            raise PredictionBundleError("explicit window selection is empty, duplicate, or too large")
        selected_ids = sorted(str(item) for item in window_ids)
        missing = sorted(set(selected_ids) - set(by_id))
        if missing:
            raise PredictionBundleError(
                f"requested windows are absent from {split}: {', '.join(missing)}"
            )
        method = "explicit-window-ids"
        selection_provenance = "investigator-supplied-basis-not-assessed"
    selection = PredictionSelection(
        split=split,
        method=method,
        selection_provenance=selection_provenance,
        window_ids=selected_ids,
        row_count=len(selected_ids),
    )
    return [by_id[window_id] for window_id in selected_ids], selection


def _reconstructed_rows(
    *,
    selected_m3_rows: list[dict[str, Any]],
    m2_dataset: dict[str, Any],
    scaler: dict[str, Any],
    split: str,
    np: Any,
) -> list[dict[str, Any]]:
    selected_ids = {str(row["window_id"]) for row in selected_m3_rows}
    m2_by_id: dict[str, dict[str, Any]] = {}
    for row in m2_dataset.get("rows", []):
        window_id = str(row.get("window_id", ""))
        if window_id in selected_ids:
            if window_id in m2_by_id:
                raise PredictionBundleError(f"duplicate selected M2 window: {window_id}")
            m2_by_id[window_id] = row
    if set(m2_by_id) != selected_ids:
        missing = sorted(selected_ids - set(m2_by_id))
        raise PredictionBundleError(f"selected windows lack M2 rows: {', '.join(missing)}")

    means = np.asarray(scaler["mean"], dtype=np.float64)
    scales = np.asarray(scaler["scale"], dtype=np.float64)
    if (
        means.ndim != 1
        or scales.shape != means.shape
        or bool((scales <= 0).any())
    ):
        raise PredictionBundleError("invalid M2 scaler")
    result: list[dict[str, Any]] = []
    for m3_row in selected_m3_rows:
        window_id = str(m3_row["window_id"])
        m2_row = m2_by_id[window_id]
        if str(m2_row.get("split")) != split:
            raise PredictionBundleError(f"M2 split mismatch: {window_id}")
        raw_features = np.asarray(m2_row.get("features", []), dtype=np.float64)
        if raw_features.shape != means.shape:
            raise PredictionBundleError(f"M2 feature width mismatch: {window_id}")
        expected_m3_row = {
            "window_id": window_id,
            "capture_id": str(m2_row["capture_id"]),
            "label": str(m2_row["label"]),
            "features": ((raw_features - means) / scales).tolist(),
        }
        if derived_json_bytes(expected_m3_row) != derived_json_bytes(m3_row):
            raise PredictionBundleError(
                f"M3 feature row differs from M2/scaler reconstruction: {window_id}"
            )
        source_event_ids = [str(item) for item in m2_row.get("source_event_ids", [])]
        if not source_event_ids or len(source_event_ids) != len(set(source_event_ids)):
            raise PredictionBundleError(f"invalid M2 source-event list: {window_id}")
        result.append(
            {
                "m3_row": m3_row,
                "m2_row": m2_row,
                "m3_evaluation_row_sha256": sha256_bytes(
                    derived_json_bytes(m3_row)
                ),
                "inference_input_sha256": sha256_bytes(
                    derived_json_bytes(
                        {
                            "window_id": window_id,
                            "features": m3_row["features"],
                        }
                    )
                ),
                "m2_window_row_sha256": sha256_bytes(derived_json_bytes(m2_row)),
                "source_event_ids": source_event_ids,
            }
        )
    return result


def _validated_inputs(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    config_path: Path,
    split: str,
    window_ids: list[str] | None,
    first: int | None,
) -> dict[str, Any]:
    config, config_digest = load_yaml(config_path)
    investigation = _validate_config(config)
    if split not in investigation["allowed_splits"]:
        raise PredictionBundleError("selected split is disabled by configuration")

    round_verification = verify_secure_round(
        workspace=round_workspace,
        trust_workspace=trust_workspace,
        submissions_root=round_workspace / "submissions",
    )
    if round_verification.get("status") != "verified":
        raise PredictionBundleError(
            f"M5 checkpoint verification failed: {round_verification.get('errors', [])}"
        )
    partition_verification = verify_partitions(
        workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
    )
    if partition_verification.get("status") != "verified":
        raise PredictionBundleError(
            f"M3/M2 verification failed: {partition_verification.get('errors', [])}"
        )

    context_path = round_workspace / "public" / "round-context.json"
    public_partition_path = round_workspace / "public" / "partition-manifest.json"
    checkpoint_path = round_workspace / "checkpoint" / "manifest.json"
    model_path = round_workspace / "checkpoint" / "global-model.json"
    partition_path = partition_workspace / "manifest.json"
    m2_manifest_path = dataset_workspace / "manifest.json"
    m2_dataset_path = dataset_workspace / "dataset.json"
    m2_scaler_path = dataset_workspace / "scaler.json"
    m2_lineage_path = dataset_workspace / "lineage.jsonl"

    context = load_json(context_path)
    checkpoint = load_json(checkpoint_path)
    model_export = load_json(model_path)
    resolver_partition_manifest = load_json(partition_path)
    public_partition = load_json(public_partition_path)
    m2_manifest = load_json(m2_manifest_path)
    m2_dataset = load_json(m2_dataset_path)
    scaler = load_json(m2_scaler_path)

    context_core = context["core"]
    checkpoint_core = checkpoint["core"]
    if sha256_file(public_partition_path) != context_core["partition_manifest_sha256"]:
        raise PredictionBundleError("M5 public partition differs from signed context")
    try:
        evaluation_path = _verify_partition_snapshot_files(
            partition_workspace=partition_workspace,
            partition_manifest=public_partition,
        )
    except RuntimeError as exc:
        raise PredictionBundleError(str(exc)) from exc
    server = load_json(evaluation_path)
    resolver_data_keys = (
        "dataset",
        "source_m2_manifest_sha256",
        "source_m2_dataset_sha256",
        "source_m2_scaler_sha256",
        "feature_names",
        "class_names",
        "clients",
        "server_evaluation_path",
        "server_evaluation_sha256",
    )
    if any(
        resolver_partition_manifest.get(key) != public_partition.get(key)
        for key in resolver_data_keys
    ):
        raise PredictionBundleError(
            "M3 resolver workspace differs from the signed M5 data snapshot"
        )
    if sha256_file(model_path) != checkpoint_core["global_model_sha256"]:
        raise PredictionBundleError("checkpoint model digest mismatch")
    if checkpoint_core["context_digest"] != context["core_digest"]:
        raise PredictionBundleError("checkpoint/context digest mismatch")
    if public_partition.get("server_evaluation_sha256") != sha256_file(
        evaluation_path
    ):
        raise PredictionBundleError("M3 evaluation snapshot digest mismatch")
    expected_m2_refs = {
        "source_m2_manifest_sha256": sha256_file(m2_manifest_path),
        "source_m2_dataset_sha256": sha256_file(m2_dataset_path),
        "source_m2_scaler_sha256": sha256_file(m2_scaler_path),
    }
    for name, actual in expected_m2_refs.items():
        if public_partition.get(name) != actual:
            raise PredictionBundleError(f"M3-to-M2 digest mismatch: {name}")
    if m2_manifest.get("artifacts", {}).get("lineage.jsonl") != sha256_file(
        m2_lineage_path
    ):
        raise PredictionBundleError("M2 lineage digest mismatch")
    if server.get("feature_names") != m2_dataset.get("feature_names"):
        raise PredictionBundleError("M2/M3 feature schema mismatch")
    if model_export.get("class_names") != server.get("class_names"):
        raise PredictionBundleError("checkpoint/M3 class order mismatch")
    architecture = model_export.get("architecture", {})
    if int(architecture.get("input_features", -1)) != len(server["feature_names"]):
        raise PredictionBundleError("checkpoint feature width mismatch")

    np, torch = _ml_dependencies()
    selected_m3_rows, selection = _selected_rows(
        server=server,
        split=split,
        window_ids=window_ids,
        first=first,
        maximum=int(investigation["maximum_windows_per_bundle"]),
    )
    selected = _reconstructed_rows(
        selected_m3_rows=selected_m3_rows,
        m2_dataset=m2_dataset,
        scaler=scaler,
        split=split,
        np=np,
    )
    sources = PredictionSourceReferences(
        campaign_id=str(checkpoint_core["campaign_id"]),
        round_number=int(checkpoint_core["round_number"]),
        context_id=str(checkpoint_core["context_id"]),
        checkpoint_id=str(checkpoint["checkpoint_id"]),
        round_context_sha256=sha256_file(context_path),
        checkpoint_manifest_sha256=sha256_file(checkpoint_path),
        global_model_sha256=sha256_file(model_path),
        partition_manifest_sha256=sha256_file(public_partition_path),
        server_evaluation_sha256=sha256_file(evaluation_path),
        m2_manifest_sha256=sha256_file(m2_manifest_path),
        m2_dataset_sha256=sha256_file(m2_dataset_path),
        m2_scaler_sha256=sha256_file(m2_scaler_path),
        m2_lineage_sha256=sha256_file(m2_lineage_path),
    )
    return {
        "config_digest": config_digest,
        "investigation": investigation,
        "selection": selection,
        "selected": selected,
        "sources": sources,
        "source_file_index": _source_file_index(m2_manifest),
        "lineage_path": m2_lineage_path,
        "model_export": model_export,
        "np": np,
        "torch": torch,
    }


def _prediction_id(
    *,
    window_id: str,
    inference_input_sha256: str,
    sources: PredictionSourceReferences,
) -> str:
    core = {
        "inference_method": "classification-head-softmax-argmax",
        "checkpoint_model_sha256": sources.global_model_sha256,
        "server_evaluation_sha256": sources.server_evaluation_sha256,
        "window_id": window_id,
        "inference_input_sha256": inference_input_sha256,
    }
    return f"m7-prediction-{sha256_bytes(canonical_json_bytes(core))[:24]}"


def _model_from_export(value: dict[str, Any], *, np: Any, torch: Any) -> Any:
    architecture = value["architecture"]
    model = build_model(
        input_features=int(architecture["input_features"]),
        class_count=int(architecture["classification_head_outputs"]),
        hidden_layers=[int(item) for item in architecture["encoder_hidden_layers"]],
        embedding_size=int(architecture["embedding_size"]),
        dropout=float(architecture["dropout"]),
        torch=torch,
    )
    load_ndarrays(
        model,
        arrays_from_export(value, np=np),
        torch=torch,
        np=np,
    )
    return model


def _inference_rows(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    np = inputs["np"]
    torch = inputs["torch"]
    model_export = inputs["model_export"]
    class_names = [str(item) for item in model_export["class_names"]]
    model = _model_from_export(model_export, np=np, torch=torch)
    model.to("cpu")
    model.eval()
    features = np.asarray(
        [item["m3_row"]["features"] for item in inputs["selected"]],
        dtype=np.float32,
    )
    with torch.no_grad():
        logits_tensor = model(torch.from_numpy(features))
        probabilities_tensor = torch.softmax(logits_tensor, dim=1)
    logits = logits_tensor.cpu().numpy()
    probabilities = probabilities_tensor.cpu().numpy()
    rows: list[dict[str, Any]] = []
    sources: PredictionSourceReferences = inputs["sources"]
    for index, item in enumerate(inputs["selected"]):
        values = probabilities[index]
        predicted_index = int(values.argmax())
        ordered = np.sort(values)
        confidence = float(values[predicted_index])
        margin = float(ordered[-1] - ordered[-2]) if len(ordered) > 1 else confidence
        if not math.isfinite(confidence) or not math.isfinite(margin):
            raise PredictionBundleError("model inference produced non-finite probabilities")
        window_id = str(item["m3_row"]["window_id"])
        rows.append(
            {
                "prediction_id": _prediction_id(
                    window_id=window_id,
                    inference_input_sha256=item["inference_input_sha256"],
                    sources=sources,
                ),
                "window_id": window_id,
                "split": inputs["selection"].split,
                "capture_id": str(item["m3_row"]["capture_id"]),
                "predicted_class": class_names[predicted_index],
                "predicted_class_index": predicted_index,
                "confidence": round(confidence, 12),
                "probability_margin": round(margin, 12),
                "class_probabilities": [round(float(value), 12) for value in values],
                "logits": [round(float(value), 12) for value in logits[index]],
                "reference_label": str(item["m3_row"]["label"]),
                "reference_label_role": "evaluation-only-not-an-inference-input",
                "inference_input_sha256": item["inference_input_sha256"],
                "evaluation_row_sha256": item["m3_evaluation_row_sha256"],
            }
        )
    return rows


def _event_evidence(
    *,
    record: dict[str, Any],
    raw_line: bytes,
    source_files: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    event_id = str(record.get("event_id", ""))
    identity = str(record.get("source_identity_sha256", ""))
    if (
        record.get("record_type") != "event"
        or not event_id
        or not _hex_digest(identity)
        or not event_id.endswith(identity[:20])
    ):
        raise PredictionBundleError(f"invalid source-event lineage record: {event_id}")
    source_records: list[dict[str, Any]] = []
    for source in record.get("source_records", []):
        relative_path = str(source.get("relative_path", ""))
        row_number = source.get("row_number")
        source_digest = source.get("source_record_sha256")
        if (
            relative_path not in source_files
            or isinstance(row_number, bool)
            or not isinstance(row_number, int)
            or row_number < 0
            or not _hex_digest(source_digest)
        ):
            raise PredictionBundleError(f"invalid source-record reference: {event_id}")
        source_records.append(
            {
                **source,
                "source_file_sha256": source_files[relative_path]["sha256"],
                "source_file_size_bytes": source_files[relative_path]["size_bytes"],
            }
        )
    if not source_records:
        raise PredictionBundleError(f"source event has no raw-record references: {event_id}")
    return {
        "event_id": event_id,
        "source_identity_sha256": identity,
        "lineage_record_sha256": sha256_bytes(raw_line),
        "source_records": source_records,
    }


def _resolve_lineage(
    *,
    selected: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
    lineage_path: Path,
    source_files: dict[str, dict[str, Any]],
    sources: PredictionSourceReferences,
) -> dict[str, Any]:
    prediction_by_window = {
        str(item["window_id"]): str(item["prediction_id"])
        for item in prediction_rows
    }
    required_event_ids = {
        event_id for item in selected for event_id in item["source_event_ids"]
    }
    required_windows = {
        str(item["m3_row"]["window_id"]): item["source_event_ids"]
        for item in selected
    }
    found: dict[str, dict[str, Any]] = {}
    found_windows: dict[str, str] = {}
    with lineage_path.open("rb") as handle:
        for raw_line in handle:
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise PredictionBundleError("invalid JSON in M2 lineage.jsonl") from exc
            event_id = str(record.get("event_id", ""))
            if event_id in required_event_ids:
                if event_id in found:
                    raise PredictionBundleError(f"duplicate M2 event lineage: {event_id}")
                found[event_id] = _event_evidence(
                    record=record,
                    raw_line=raw_line,
                    source_files=source_files,
                )
            window_id = str(record.get("window_id", ""))
            if window_id in required_windows:
                if window_id in found_windows:
                    raise PredictionBundleError(
                        f"duplicate M2 window lineage: {window_id}"
                    )
                observed_events = [
                    str(item) for item in record.get("source_event_ids", [])
                ]
                if (
                    record.get("record_type") != "window"
                    or not record.get("feature_schema")
                    or observed_events != required_windows[window_id]
                ):
                    raise PredictionBundleError(
                        f"M2 window/event lineage mismatch: {window_id}"
                    )
                found_windows[window_id] = sha256_bytes(raw_line)
    missing = sorted(required_event_ids - set(found))
    if missing:
        raise PredictionBundleError(
            f"prediction lineage is incomplete; missing events: {', '.join(missing[:8])}"
        )
    missing_windows = sorted(set(required_windows) - set(found_windows))
    if missing_windows:
        raise PredictionBundleError(
            "prediction lineage is incomplete; missing windows: "
            f"{', '.join(missing_windows)}"
        )

    referenced_source_paths = {
        str(record["relative_path"])
        for event in found.values()
        for record in event["source_records"]
    }
    windows = []
    for item in selected:
        window_id = str(item["m3_row"]["window_id"])
        windows.append(
            {
                "prediction_id": prediction_by_window[window_id],
                "window_id": window_id,
                "split": str(item["m2_row"]["split"]),
                "capture_id": str(item["m2_row"]["capture_id"]),
                "m3_evaluation_row_sha256": item["m3_evaluation_row_sha256"],
                "inference_input_sha256": item["inference_input_sha256"],
                "m2_window_row_sha256": item["m2_window_row_sha256"],
                "m2_window_lineage_record_sha256": found_windows[window_id],
                "source_event_count": len(item["source_event_ids"]),
                "source_event_ids": item["source_event_ids"],
                "lineage_complete": True,
            }
        )
    events = [found[event_id] for event_id in sorted(found)]
    return {
        "schema_version": "1.0",
        "artifact_type": "m7_prediction_lineage",
        "resolution_path": [
            "prediction",
            "signed_m5_checkpoint",
            "m3_scaled_feature_window",
            "m2_window",
            "normalized_zeek_event",
            "controlled_ingestion_source_record",
        ],
        "source_snapshot_digests": {
            "partition_manifest_sha256": sources.partition_manifest_sha256,
            "server_evaluation_sha256": sources.server_evaluation_sha256,
            "m2_manifest_sha256": sources.m2_manifest_sha256,
            "m2_dataset_sha256": sources.m2_dataset_sha256,
            "m2_lineage_sha256": sources.m2_lineage_sha256,
        },
        "source_files": [source_files[path] for path in sorted(referenced_source_paths)],
        "windows": windows,
        "events": events,
        "resolution_boundary": (
            "source-record digests and source-file digests from verified controlled "
            "ingestion; raw Parquet row bytes are not copied into this bundle"
        ),
        "complete_window_count": len(windows),
        "incomplete_window_count": 0,
        "invariant_violation_count": 0,
    }


def _build_artifacts(inputs: dict[str, Any]) -> dict[str, bytes]:
    prediction_rows = _inference_rows(inputs)
    predictions = {
        "schema_version": "1.0",
        "artifact_type": "m7_prediction_results",
        "inference_method": "classification-head-softmax-argmax",
        "inference_device": "cpu",
        "class_names": [str(item) for item in inputs["model_export"]["class_names"]],
        "prediction_count": len(prediction_rows),
        "reference_labels_used_for_inference": False,
        "numerical_environment": {
            "numpy_version": str(inputs["np"].__version__),
            "torch_version": str(inputs["torch"].__version__),
            "round_digits": 12,
        },
        "predictions": prediction_rows,
    }
    prediction_bytes = derived_json_bytes(predictions)
    lineage = _resolve_lineage(
        selected=inputs["selected"],
        prediction_rows=prediction_rows,
        lineage_path=inputs["lineage_path"],
        source_files=inputs["source_file_index"],
        sources=inputs["sources"],
    )
    lineage_bytes = derived_json_bytes(lineage)
    source_record_count = sum(
        len(event["source_records"]) for event in lineage["events"]
    )
    core = PredictionBundleCore(
        code_version=__version__,
        implementation_sha256=sha256_file(Path(__file__)),
        investigation_config_sha256=inputs["config_digest"],
        prediction_count=len(prediction_rows),
        source_event_count=len(lineage["events"]),
        source_record_count=source_record_count,
        sources=inputs["sources"],
        selection=inputs["selection"],
        predictions_sha256=sha256_bytes(prediction_bytes),
        lineage_sha256=sha256_bytes(lineage_bytes),
        reportability_gate=PredictionReportabilityGate(
            complete_window_count=len(prediction_rows)
        ),
    )
    core_value = core.model_dump(mode="json")
    core_digest = sha256_bytes(canonical_json_bytes(core_value))
    manifest = PredictionBundleManifest(
        bundle_id=f"m7-prediction-bundle-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
    )
    return {
        "predictions.json": prediction_bytes,
        "lineage.json": lineage_bytes,
        "manifest.json": derived_json_bytes(manifest.model_dump(mode="json")),
    }


def create_prediction_bundle(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    output: Path,
    config_path: Path,
    split: str,
    window_ids: list[str] | None = None,
    first: int | None = None,
) -> dict[str, Any]:
    """Run inference and publish only predictions with complete source lineage."""

    inputs = _validated_inputs(
        round_workspace=round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
        config_path=config_path,
        split=split,
        window_ids=window_ids,
        first=first,
    )
    artifacts = _build_artifacts(inputs)
    for name in ("predictions.json", "lineage.json", "manifest.json"):
        write_once(output / name, artifacts[name])
    manifest = PredictionBundleManifest.model_validate_json(artifacts["manifest.json"])
    return {
        "status": "reportable",
        "bundle_id": manifest.bundle_id,
        "campaign_id": manifest.core.sources.campaign_id,
        "round_number": manifest.core.sources.round_number,
        "split": manifest.core.selection.split,
        "selection_method": manifest.core.selection.method,
        "prediction_count": manifest.core.prediction_count,
        "source_event_count": manifest.core.source_event_count,
        "source_record_count": manifest.core.source_record_count,
        "lineage_complete": True,
        "invariant_violation_count": 0,
        "manifest_sha256": sha256_bytes(artifacts["manifest.json"]),
        "workspace": str(output),
    }


def verify_prediction_bundle(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Recompute checkpoint inference and the complete prediction lineage."""

    errors: list[str] = []
    manifest: PredictionBundleManifest | None = None
    source_recomputed = False
    try:
        manifest_path = workspace / "manifest.json"
        manifest = PredictionBundleManifest.model_validate(load_json(manifest_path))
        expected_core_digest = sha256_bytes(
            canonical_json_bytes(manifest.core.model_dump(mode="json"))
        )
        if manifest.canonical_core_sha256 != expected_core_digest:
            raise PredictionBundleError("prediction manifest core digest mismatch")
        selection = manifest.core.selection
        inputs = _validated_inputs(
            round_workspace=round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            dataset_workspace=dataset_workspace,
            config_path=config_path,
            split=selection.split,
            window_ids=(
                selection.window_ids
                if selection.method == "explicit-window-ids"
                else None
            ),
            first=(
                selection.row_count
                if selection.method == "lexicographic-first-window-ids"
                else None
            ),
        )
        source_recomputed = True
        expected = _build_artifacts(inputs)
        for name in ("predictions.json", "lineage.json", "manifest.json"):
            path = workspace / name
            if not path.is_file():
                errors.append(f"missing prediction artifact: {name}")
            elif path.read_bytes() != expected[name]:
                errors.append(f"prediction artifact differs from recomputation: {name}")
        expected_names = {"predictions.json", "lineage.json", "manifest.json"}
        actual_names = {
            path.relative_to(workspace).as_posix()
            for path in workspace.rglob("*")
            if path.is_file()
        }
        unexpected = sorted(actual_names - expected_names)
        if unexpected:
            errors.append(f"unexpected prediction artifacts: {', '.join(unexpected)}")
    except (KeyError, OSError, PredictionBundleError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "bundle_id": manifest.bundle_id if manifest is not None else None,
        "campaign_id": (
            manifest.core.sources.campaign_id if manifest is not None else None
        ),
        "round_number": (
            manifest.core.sources.round_number if manifest is not None else None
        ),
        "split": manifest.core.selection.split if manifest is not None else None,
        "prediction_count": (
            manifest.core.prediction_count if manifest is not None else 0
        ),
        "source_event_count": (
            manifest.core.source_event_count if manifest is not None else 0
        ),
        "source_record_count": (
            manifest.core.source_record_count if manifest is not None else 0
        ),
        "reportable": not errors,
        "source_recomputed": source_recomputed,
        "verification_recomputed_model_inference": source_recomputed,
        "verification_recomputed_lineage": source_recomputed,
        "error_count": len(errors),
        "errors": errors,
        "manifest_sha256": (
            sha256_file(workspace / "manifest.json")
            if (workspace / "manifest.json").is_file()
            else None
        ),
        "workspace": str(workspace),
    }
