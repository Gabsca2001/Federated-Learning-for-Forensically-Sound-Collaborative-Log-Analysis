"""Deterministic investigation reporting for Milestone 7."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .attack_mapping import (
    AttackMappingError,
    verify_attack_mapping_bundle,
)
from .investigation_models import (
    AttackMappingBundleManifest,
    ExplanationBundleManifest,
    InvestigationReportabilityGate,
    InvestigationReportBundleCore,
    InvestigationReportBundleManifest,
    InvestigationReportSourceReferences,
    PredictionBundleManifest,
)

EXPECTED_OUTPUT_FILES = {
    "investigation-report.json",
    "manifest.json",
    "report.md",
}

SOURCE_RECORD_FIELDS = (
    "relative_path",
    "row_number",
    "source_record_sha256",
    "source_file_sha256",
    "source_file_size_bytes",
)

FORBIDDEN_DATASET_LABEL_FIELDS = {
    "label_binary",
    "label_tactic",
    "label_technique",
}


class InvestigationReportError(RuntimeError):
    """Raised when a deterministic investigation report is unsafe."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _read_json(path: Path, description: str) -> Any:
    if not path.is_file():
        raise InvestigationReportError(
            f"missing {description}: {path}"
        )

    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise InvestigationReportError(
            f"invalid {description}: {path}"
        ) from exc


def _load_report_config(
    config_path: Path,
) -> tuple[dict[str, Any], str]:
    if not config_path.is_file():
        raise InvestigationReportError(
            f"missing investigation report config: {config_path}"
        )

    raw = config_path.read_bytes()

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise InvestigationReportError(
            "invalid investigation report YAML"
        ) from exc

    if not isinstance(document, dict):
        raise InvestigationReportError(
            "investigation report config root must be an object"
        )

    if set(document) != {
        "schema_version",
        "investigation_report",
    }:
        raise InvestigationReportError(
            "unexpected investigation report config contract"
        )

    if document["schema_version"] != "1.0":
        raise InvestigationReportError(
            "unexpected investigation report schema version"
        )

    config = document["investigation_report"]

    if not isinstance(config, dict):
        raise InvestigationReportError(
            "missing investigation_report configuration"
        )

    expected_keys = {
        "case_order",
        "integrated_gradients_top_features",
        "primary_evidence",
        "label_policy",
        "interpretation",
    }

    if set(config) != expected_keys:
        raise InvestigationReportError(
            "unexpected investigation report configuration"
        )

    if config["case_order"] != "prediction-id-lexicographic":
        raise InvestigationReportError(
            "M7 report case order must be prediction-id-lexicographic"
        )

    top_features = config["integrated_gradients_top_features"]

    if (
        not isinstance(top_features, int)
        or isinstance(top_features, bool)
        or top_features <= 0
    ):
        raise InvestigationReportError(
            "integrated_gradients_top_features must be positive"
        )

    primary = config["primary_evidence"]

    if primary != {
        "include_source_file_url": False,
        "source_record_fields": list(SOURCE_RECORD_FIELDS),
    }:
        raise InvestigationReportError(
            "primary-evidence report contract is not frozen"
        )

    labels = config["label_policy"]

    if labels != {
        "include_reference_labels": False,
        "include_dataset_attack_labels": False,
        "use_dataset_labels_for_reporting": False,
    }:
        raise InvestigationReportError(
            "dataset-label independence contract is not frozen"
        )

    interpretation = config["interpretation"]

    if interpretation != {
        "primary_evidence_role": (
            "source-record-digest-reference"
        ),
        "model_measurement_role": (
            "model-derived-measurement"
        ),
        "derived_interpretation_role": (
            "model-derived-interpretation"
        ),
        "allow_report_to_resolve_multi_tactic": False,
    }:
        raise InvestigationReportError(
            "investigation interpretation boundary is not frozen"
        )

    return config, _sha256_bytes(raw)


def _index_records(
    records: Any,
    *,
    key: str,
    artifact: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        raise InvestigationReportError(
            f"{artifact} records are not a list"
        )

    indexed: dict[str, dict[str, Any]] = {}

    for record in records:
        if not isinstance(record, dict):
            raise InvestigationReportError(
                f"{artifact} contains a non-object record"
            )

        value = record.get(key)

        if not isinstance(value, str) or not value:
            raise InvestigationReportError(
                f"{artifact} record has no {key}"
            )

        if value in indexed:
            raise InvestigationReportError(
                f"{artifact} contains duplicate {key}: {value}"
            )

        indexed[value] = record

    return indexed


def _verified_attack_source(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    explanation_workspace: Path,
    attack_workspace: Path,
    prediction_config_path: Path,
    explanation_config_path: Path,
    attack_config_path: Path,
) -> dict[str, Any]:
    try:
        verification = verify_attack_mapping_bundle(
            round_workspace=round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            dataset_workspace=dataset_workspace,
            prediction_workspace=prediction_workspace,
            explanation_workspace=explanation_workspace,
            workspace=attack_workspace,
            prediction_config_path=prediction_config_path,
            explanation_config_path=explanation_config_path,
            config_path=attack_config_path,
        )
    except (AttackMappingError, OSError, ValueError) as exc:
        raise InvestigationReportError(
            "ATT&CK Mapping Bundle verification raised an error"
        ) from exc

    if verification.get("status") != "verified":
        raise InvestigationReportError(
            "ATT&CK Mapping Bundle did not pass verification"
        )

    if verification.get("reportable") is not True:
        raise InvestigationReportError(
            "ATT&CK Mapping Bundle is not reportable"
        )

    if verification.get("source_explanation_verified") is not True:
        raise InvestigationReportError(
            "Explanation Bundle was not transitively verified"
        )

    if (
        verification.get(
            "verification_recomputed_attack_mapping"
        )
        is not True
    ):
        raise InvestigationReportError(
            "ATT&CK verifier did not recompute mapping"
        )

    return verification


def _source_record_reference(
    record: dict[str, Any],
    *,
    source_files_by_path: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    missing = [
        field
        for field in SOURCE_RECORD_FIELDS
        if field not in record
    ]

    if missing:
        raise InvestigationReportError(
            f"source record is missing required fields: {missing}"
        )

    relative_path = record["relative_path"]
    row_number = record["row_number"]
    source_record_sha256 = record["source_record_sha256"]
    source_file_sha256 = record["source_file_sha256"]
    source_file_size_bytes = record[
        "source_file_size_bytes"
    ]

    if not isinstance(relative_path, str) or not relative_path:
        raise InvestigationReportError(
            "invalid source-record relative path"
        )

    if (
        not isinstance(row_number, int)
        or isinstance(row_number, bool)
        or row_number < 0
    ):
        raise InvestigationReportError(
            "invalid source-record row number"
        )

    for description, value in (
        ("source-record digest", source_record_sha256),
        ("source-file digest", source_file_sha256),
    ):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(
                char not in "0123456789abcdef"
                for char in value
            )
        ):
            raise InvestigationReportError(
                f"invalid {description}"
            )

    if (
        not isinstance(source_file_size_bytes, int)
        or isinstance(source_file_size_bytes, bool)
        or source_file_size_bytes <= 0
    ):
        raise InvestigationReportError(
            "invalid source-file size"
        )

    registered_file = source_files_by_path.get(
        relative_path
    )

    if registered_file is None:
        raise InvestigationReportError(
            f"source file is absent from lineage registry: "
            f"{relative_path}"
        )

    if registered_file.get("sha256") != source_file_sha256:
        raise InvestigationReportError(
            "source-record file digest differs from "
            "lineage source-file registry"
        )

    if (
        registered_file.get("size_bytes")
        != source_file_size_bytes
    ):
        raise InvestigationReportError(
            "source-record file size differs from "
            "lineage source-file registry"
        )

    # Deliberate allowlist:
    # label_binary, label_tactic and label_technique are not copied.
    return {
        "relative_path": relative_path,
        "row_number": row_number,
        "source_file_sha256": source_file_sha256,
        "source_file_size_bytes": source_file_size_bytes,
        "source_record_sha256": source_record_sha256,
    }


def _validated_report_inputs(
    *,
    prediction_workspace: Path,
    explanation_workspace: Path,
    attack_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    config, config_sha256 = _load_report_config(
        config_path
    )

    prediction_manifest_path = (
        prediction_workspace / "manifest.json"
    )
    predictions_path = (
        prediction_workspace / "predictions.json"
    )
    lineage_path = prediction_workspace / "lineage.json"

    explanation_manifest_path = (
        explanation_workspace / "manifest.json"
    )
    integrated_gradients_path = (
        explanation_workspace / "integrated-gradients.json"
    )
    prototype_reference_path = (
        explanation_workspace / "prototype-reference.json"
    )
    prototype_distances_path = (
        explanation_workspace / "prototype-distances.json"
    )

    attack_manifest_path = attack_workspace / "manifest.json"
    attack_mappings_path = (
        attack_workspace / "attack-mappings.json"
    )

    try:
        prediction_manifest = (
            PredictionBundleManifest.model_validate(
                _read_json(
                    prediction_manifest_path,
                    "Prediction Bundle manifest",
                )
            )
        )
        explanation_manifest = (
            ExplanationBundleManifest.model_validate(
                _read_json(
                    explanation_manifest_path,
                    "Explanation Bundle manifest",
                )
            )
        )
        attack_manifest = (
            AttackMappingBundleManifest.model_validate(
                _read_json(
                    attack_manifest_path,
                    "ATT&CK Mapping Bundle manifest",
                )
            )
        )
    except ValidationError as exc:
        raise InvestigationReportError(
            "invalid upstream M7 manifest"
        ) from exc

    predictions = _read_json(
        predictions_path,
        "Prediction Bundle predictions",
    )
    lineage = _read_json(
        lineage_path,
        "Prediction Bundle lineage",
    )
    integrated_gradients = _read_json(
        integrated_gradients_path,
        "Integrated Gradients artifact",
    )
    prototype_distances = _read_json(
        prototype_distances_path,
        "prototype distances artifact",
    )
    attack_mappings = _read_json(
        attack_mappings_path,
        "ATT&CK mapping artifact",
    )

    for description, payload in (
        ("predictions", predictions),
        ("lineage", lineage),
        ("Integrated Gradients", integrated_gradients),
        ("prototype distances", prototype_distances),
        ("ATT&CK mappings", attack_mappings),
    ):
        if not isinstance(payload, dict):
            raise InvestigationReportError(
                f"{description} artifact must be an object"
            )

    prediction_manifest_sha256 = _sha256_file(
        prediction_manifest_path
    )
    predictions_sha256 = _sha256_file(predictions_path)
    lineage_sha256 = _sha256_file(lineage_path)

    explanation_manifest_sha256 = _sha256_file(
        explanation_manifest_path
    )
    integrated_gradients_sha256 = _sha256_file(
        integrated_gradients_path
    )
    prototype_reference_sha256 = _sha256_file(
        prototype_reference_path
    )
    prototype_distances_sha256 = _sha256_file(
        prototype_distances_path
    )

    attack_mappings_sha256 = _sha256_file(
        attack_mappings_path
    )

    if (
        prediction_manifest.core.predictions_sha256
        != predictions_sha256
    ):
        raise InvestigationReportError(
            "Prediction Bundle predictions digest mismatch"
        )

    if (
        prediction_manifest.core.lineage_sha256
        != lineage_sha256
    ):
        raise InvestigationReportError(
            "Prediction Bundle lineage digest mismatch"
        )

    if (
        explanation_manifest.core.source.
        prediction_manifest_sha256
        != prediction_manifest_sha256
    ):
        raise InvestigationReportError(
            "Explanation Bundle prediction manifest "
            "binding mismatch"
        )

    if (
        explanation_manifest.core.integrated_gradients_sha256
        != integrated_gradients_sha256
    ):
        raise InvestigationReportError(
            "Integrated Gradients digest mismatch"
        )

    if (
        explanation_manifest.core.prototype_reference_sha256
        != prototype_reference_sha256
    ):
        raise InvestigationReportError(
            "prototype reference digest mismatch"
        )

    if (
        explanation_manifest.core.prototype_distances_sha256
        != prototype_distances_sha256
    ):
        raise InvestigationReportError(
            "prototype distances digest mismatch"
        )

    attack_source = attack_manifest.core.source

    if (
        attack_source.explanation_manifest_sha256
        != explanation_manifest_sha256
    ):
        raise InvestigationReportError(
            "ATT&CK explanation manifest binding mismatch"
        )

    if (
        attack_source.prediction_manifest_sha256
        != prediction_manifest_sha256
    ):
        raise InvestigationReportError(
            "ATT&CK prediction manifest binding mismatch"
        )

    if (
        attack_source.predictions_sha256
        != predictions_sha256
    ):
        raise InvestigationReportError(
            "ATT&CK predictions binding mismatch"
        )

    if attack_source.lineage_sha256 != lineage_sha256:
        raise InvestigationReportError(
            "ATT&CK lineage binding mismatch"
        )

    if (
        attack_source.integrated_gradients_sha256
        != integrated_gradients_sha256
    ):
        raise InvestigationReportError(
            "ATT&CK Integrated Gradients binding mismatch"
        )

    if (
        attack_source.prototype_reference_sha256
        != prototype_reference_sha256
    ):
        raise InvestigationReportError(
            "ATT&CK prototype-reference binding mismatch"
        )

    if (
        attack_source.prototype_distances_sha256
        != prototype_distances_sha256
    ):
        raise InvestigationReportError(
            "ATT&CK prototype-distances binding mismatch"
        )

    if (
        attack_manifest.core.attack_mappings_sha256
        != attack_mappings_sha256
    ):
        raise InvestigationReportError(
            "ATT&CK mapping digest mismatch"
        )

    if (
        predictions.get(
            "reference_labels_used_for_inference"
        )
        is not False
    ):
        raise InvestigationReportError(
            "Prediction Bundle does not preserve "
            "reference-label independence"
        )

    if lineage.get("complete_window_count") != (
        prediction_manifest.core.prediction_count
    ):
        raise InvestigationReportError(
            "lineage complete-window count mismatch"
        )

    if lineage.get("incomplete_window_count") != 0:
        raise InvestigationReportError(
            "lineage contains incomplete windows"
        )

    if lineage.get("invariant_violation_count") != 0:
        raise InvestigationReportError(
            "lineage contains invariant violations"
        )

    predictions_by_id = _index_records(
        predictions.get("predictions"),
        key="prediction_id",
        artifact="predictions.json",
    )

    windows_by_prediction = _index_records(
        lineage.get("windows"),
        key="prediction_id",
        artifact="lineage windows",
    )

    events_by_id = _index_records(
        lineage.get("events"),
        key="event_id",
        artifact="lineage events",
    )

    ig_by_prediction = _index_records(
        integrated_gradients.get("explanations"),
        key="prediction_id",
        artifact="Integrated Gradients",
    )

    distances_by_prediction = _index_records(
        prototype_distances.get("explanations"),
        key="prediction_id",
        artifact="prototype distances",
    )

    mappings_by_prediction = _index_records(
        attack_mappings.get("mappings"),
        key="prediction_id",
        artifact="ATT&CK mappings",
    )

    prediction_ids = set(predictions_by_id)

    for description, indexed in (
        ("lineage windows", windows_by_prediction),
        ("Integrated Gradients", ig_by_prediction),
        ("prototype distances", distances_by_prediction),
        ("ATT&CK mappings", mappings_by_prediction),
    ):
        if set(indexed) != prediction_ids:
            raise InvestigationReportError(
                f"{description} coverage differs from predictions"
            )

    expected_count = prediction_manifest.core.prediction_count

    if len(predictions_by_id) != expected_count:
        raise InvestigationReportError(
            "Prediction Bundle count mismatch"
        )

    if attack_manifest.core.mapping_count != expected_count:
        raise InvestigationReportError(
            "ATT&CK mapping count differs from predictions"
        )

    source_files = lineage.get("source_files")

    if not isinstance(source_files, list):
        raise InvestigationReportError(
            "lineage source_files must be a list"
        )

    source_files_by_path: dict[str, dict[str, Any]] = {}

    for source_file in source_files:
        if not isinstance(source_file, dict):
            raise InvestigationReportError(
                "lineage contains invalid source-file record"
            )

        relative_path = source_file.get("relative_path")

        if (
            not isinstance(relative_path, str)
            or not relative_path
        ):
            raise InvestigationReportError(
                "lineage source file has invalid path"
            )

        if relative_path in source_files_by_path:
            raise InvestigationReportError(
                f"duplicate lineage source file: {relative_path}"
            )

        source_files_by_path[relative_path] = source_file

    referenced_event_ids: set[str] = set()
    referenced_source_record_digests: set[str] = set()

    for prediction_id in sorted(prediction_ids):
        prediction = predictions_by_id[prediction_id]
        window = windows_by_prediction[prediction_id]
        ig = ig_by_prediction[prediction_id]
        distance = distances_by_prediction[prediction_id]
        mapping = mappings_by_prediction[prediction_id]

        window_id = prediction.get("window_id")
        predicted_class = prediction.get("predicted_class")
        input_sha256 = prediction.get(
            "inference_input_sha256"
        )

        if window.get("window_id") != window_id:
            raise InvestigationReportError(
                f"lineage window mismatch for {prediction_id}"
            )

        if window.get("lineage_complete") is not True:
            raise InvestigationReportError(
                f"incomplete lineage for {prediction_id}"
            )

        if (
            window.get("inference_input_sha256")
            != input_sha256
        ):
            raise InvestigationReportError(
                f"lineage input digest mismatch for {prediction_id}"
            )

        if ig.get("window_id") != window_id:
            raise InvestigationReportError(
                f"IG window mismatch for {prediction_id}"
            )

        if ig.get("target_class") != predicted_class:
            raise InvestigationReportError(
                f"IG target mismatch for {prediction_id}"
            )

        if (
            ig.get("inference_input_sha256")
            != input_sha256
        ):
            raise InvestigationReportError(
                f"IG input digest mismatch for {prediction_id}"
            )

        if distance.get("window_id") != window_id:
            raise InvestigationReportError(
                f"prototype window mismatch for {prediction_id}"
            )

        if (
            distance.get("predicted_class")
            != predicted_class
        ):
            raise InvestigationReportError(
                f"prototype class mismatch for {prediction_id}"
            )

        if (
            distance.get("inference_input_sha256")
            != input_sha256
        ):
            raise InvestigationReportError(
                f"prototype input mismatch for {prediction_id}"
            )

        explanation_id = ig.get("explanation_id")

        if (
            distance.get("explanation_id")
            != explanation_id
        ):
            raise InvestigationReportError(
                f"explanation identity mismatch for {prediction_id}"
            )

        if mapping.get("window_id") != window_id:
            raise InvestigationReportError(
                f"ATT&CK window mismatch for {prediction_id}"
            )

        if mapping.get("explanation_id") != explanation_id:
            raise InvestigationReportError(
                f"ATT&CK explanation mismatch for {prediction_id}"
            )

        if mapping.get("predicted_class") != predicted_class:
            raise InvestigationReportError(
                f"ATT&CK class mismatch for {prediction_id}"
            )

        if mapping.get("primary_evidence") is not False:
            raise InvestigationReportError(
                "ATT&CK mapping was incorrectly promoted "
                "to primary evidence"
            )

        explanation_context = mapping.get(
            "explanation_context"
        )

        if not isinstance(explanation_context, dict):
            raise InvestigationReportError(
                f"missing ATT&CK explanation context "
                f"for {prediction_id}"
            )

        if (
            explanation_context.get(
                "used_for_rule_selection"
            )
            is not False
        ):
            raise InvestigationReportError(
                "ATT&CK rule selection depends on explanation"
            )

        event_ids = window.get("source_event_ids")

        if not isinstance(event_ids, list) or not event_ids:
            raise InvestigationReportError(
                f"missing source events for {prediction_id}"
            )

        if len(set(event_ids)) != len(event_ids):
            raise InvestigationReportError(
                f"duplicate source event for {prediction_id}"
            )

        if window.get("source_event_count") != len(
            event_ids
        ):
            raise InvestigationReportError(
                f"source-event count mismatch for {prediction_id}"
            )

        for event_id in event_ids:
            if event_id not in events_by_id:
                raise InvestigationReportError(
                    f"unresolved event {event_id}"
                )

            referenced_event_ids.add(event_id)

            event = events_by_id[event_id]
            source_records = event.get("source_records")

            if (
                not isinstance(source_records, list)
                or not source_records
            ):
                raise InvestigationReportError(
                    f"event {event_id} has no source records"
                )

            for source_record in source_records:
                if not isinstance(source_record, dict):
                    raise InvestigationReportError(
                        f"event {event_id} has invalid "
                        "source-record reference"
                    )

                safe_reference = _source_record_reference(
                    source_record,
                    source_files_by_path=source_files_by_path,
                )

                referenced_source_record_digests.add(
                    safe_reference[
                        "source_record_sha256"
                    ]
                )

    if referenced_event_ids != set(events_by_id):
        raise InvestigationReportError(
            "lineage contains events outside selected predictions"
        )

    if len(referenced_event_ids) != (
        prediction_manifest.core.source_event_count
    ):
        raise InvestigationReportError(
            "source-event count differs from Prediction Bundle"
        )

    if len(referenced_source_record_digests) != (
        prediction_manifest.core.source_record_count
    ):
        raise InvestigationReportError(
            "source-record count differs from Prediction Bundle"
        )

    return {
        "config": config,
        "config_sha256": config_sha256,
        "prediction_manifest": prediction_manifest,
        "prediction_manifest_path": prediction_manifest_path,
        "predictions_by_id": predictions_by_id,
        "predictions_path": predictions_path,
        "lineage": lineage,
        "lineage_path": lineage_path,
        "windows_by_prediction": windows_by_prediction,
        "events_by_id": events_by_id,
        "source_files_by_path": source_files_by_path,
        "explanation_manifest": explanation_manifest,
        "explanation_manifest_path": explanation_manifest_path,
        "integrated_gradients_path": integrated_gradients_path,
        "prototype_reference_path": prototype_reference_path,
        "prototype_distances_path": prototype_distances_path,
        "ig_by_prediction": ig_by_prediction,
        "distances_by_prediction": distances_by_prediction,
        "attack_manifest": attack_manifest,
        "attack_manifest_path": attack_manifest_path,
        "attack_mappings_path": attack_mappings_path,
        "mappings_by_prediction": mappings_by_prediction,
        "source_event_count": len(referenced_event_ids),
        "source_record_count": len(
            referenced_source_record_digests
        ),
    }


def _build_primary_evidence(
    *,
    window: dict[str, Any],
    events_by_id: dict[str, dict[str, Any]],
    source_files_by_path: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []

    for event_id in window["source_event_ids"]:
        event = events_by_id[event_id]

        source_records = [
            _source_record_reference(
                record,
                source_files_by_path=source_files_by_path,
            )
            for record in event["source_records"]
        ]

        source_records.sort(
            key=lambda record: (
                record["relative_path"],
                record["row_number"],
                record["source_record_sha256"],
            )
        )

        events.append(
            {
                "event_id": event["event_id"],
                "lineage_record_sha256": event[
                    "lineage_record_sha256"
                ],
                "source_identity_sha256": event[
                    "source_identity_sha256"
                ],
                "source_records": source_records,
            }
        )

    return {
        "lineage_complete": True,
        "m2_window_lineage_record_sha256": window[
            "m2_window_lineage_record_sha256"
        ],
        "m2_window_row_sha256": window[
            "m2_window_row_sha256"
        ],
        "m3_evaluation_row_sha256": window[
            "m3_evaluation_row_sha256"
        ],
        "source_event_count": len(events),
        "events": events,
    }


def _build_case(
    *,
    prediction: dict[str, Any],
    window: dict[str, Any],
    integrated_gradients: dict[str, Any],
    prototype_distance: dict[str, Any],
    attack_mapping: dict[str, Any],
    events_by_id: dict[str, dict[str, Any]],
    source_files_by_path: dict[str, dict[str, Any]],
    top_feature_count: int,
) -> dict[str, Any]:
    feature_attributions = integrated_gradients.get(
        "feature_attributions"
    )

    if not isinstance(feature_attributions, list):
        raise InvestigationReportError(
            "Integrated Gradients feature attributions "
            "are missing"
        )

    ordered_features = sorted(
        feature_attributions,
        key=lambda record: record["absolute_rank"],
    )

    top_features = []

    for feature in ordered_features[:top_feature_count]:
        top_features.append(
            {
                "absolute_rank": feature["absolute_rank"],
                "attribution": feature["attribution"],
                "direction": feature[
                    "direction_for_target_logit"
                ],
                "feature_name": feature["feature_name"],
            }
        )

    primary_evidence = _build_primary_evidence(
        window=window,
        events_by_id=events_by_id,
        source_files_by_path=source_files_by_path,
    )

    case_core = {
        "identity": {
            "attack_mapping_id": attack_mapping[
                "mapping_id"
            ],
            "capture_id": prediction["capture_id"],
            "explanation_id": integrated_gradients[
                "explanation_id"
            ],
            "prediction_id": prediction["prediction_id"],
            "split": prediction["split"],
            "window_id": prediction["window_id"],
        },
        "model_measurement": {
            "confidence": prediction["confidence"],
            "inference_input_sha256": prediction[
                "inference_input_sha256"
            ],
            "predicted_class": prediction[
                "predicted_class"
            ],
            "probability_margin": prediction[
                "probability_margin"
            ],
            "role": "model-derived-measurement",
        },
        "explanation": {
            "integrated_gradients": {
                "absolute_completeness_error": (
                    integrated_gradients[
                        "absolute_completeness_error"
                    ]
                ),
                "interpretation": (
                    "model-sensitivity-not-causal-evidence"
                ),
                "top_features": top_features,
            },
            "prototype_geometry": {
                "interpretation": (
                    "embedding-similarity-not-primary-evidence"
                ),
                "nearest_prototype_class": (
                    prototype_distance[
                        "nearest_prototype_class"
                    ]
                ),
                "nearest_prototype_distance": (
                    prototype_distance[
                        "nearest_prototype_distance"
                    ]
                ),
                "nearest_prototype_margin": (
                    prototype_distance[
                        "nearest_prototype_margin"
                    ]
                ),
                "predicted_class_prototype_distance": (
                    prototype_distance[
                        "predicted_class_prototype_distance"
                    ]
                ),
                "predicted_class_prototype_rank": (
                    prototype_distance[
                        "predicted_class_prototype_rank"
                    ]
                ),
                "prediction_matches_nearest_prototype": (
                    prototype_distance[
                        "prediction_matches_nearest_prototype"
                    ]
                ),
                "second_nearest_prototype_class": (
                    prototype_distance[
                        "second_nearest_prototype_class"
                    ]
                ),
                "second_nearest_prototype_distance": (
                    prototype_distance[
                        "second_nearest_prototype_distance"
                    ]
                ),
            },
            "role": "model-derived-interpretation",
        },
        "attack_interpretation": {
            "attack_domain": attack_mapping[
                "attack_domain"
            ],
            "attack_framework": attack_mapping[
                "attack_framework"
            ],
            "attack_version": attack_mapping[
                "attack_version"
            ],
            "mapping_status": attack_mapping[
                "mapping_status"
            ],
            "role": "model-derived-interpretation",
            "rule_id": attack_mapping["rule_id"],
            "tactic_candidates": attack_mapping[
                "tactic_candidates"
            ],
            "technique_candidates": attack_mapping[
                "technique_candidates"
            ],
        },
        "primary_evidence": primary_evidence,
        "evidence_roles": {
            "derived_interpretation": (
                "IG-prototype-and-ATT&CK-not-primary-evidence"
            ),
            "model_measurement": (
                "prediction-and-confidence-model-derived"
            ),
            "primary_evidence": (
                "verified-controlled-ingestion-source-record-digests"
            ),
        },
    }

    case_sha256 = _sha256_bytes(
        _canonical_json_bytes(case_core)
    )

    return {
        "case_id": f"m7-investigation-case-{case_sha256[:24]}",
        **case_core,
    }


def _markdown_number(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
    )


def _render_markdown(
    report: dict[str, Any],
) -> bytes:
    lines = [
        "# M7 Investigation Report",
        "",
        (
            "This report is a deterministic investigative view of "
            "verified M7 artifacts."
        ),
        "",
        (
            "**Evidence boundary:** primary evidence is represented "
            "by verified controlled-ingestion source-record and "
            "source-file digest references. Model predictions, "
            "explanations and ATT&CK mappings are derived outputs."
        ),
        "",
        f"- Cases: {report['case_count']}",
        f"- Source events: {report['source_event_count']}",
        f"- Source records: {report['source_record_count']}",
        "- Reference labels included: false",
        "- Dataset ATT&CK labels included: false",
        "- Dataset labels used for reporting: false",
        "",
    ]

    for case in report["cases"]:
        identity = case["identity"]
        measurement = case["model_measurement"]
        explanation = case["explanation"]
        attack = case["attack_interpretation"]
        evidence = case["primary_evidence"]

        lines.extend(
            [
                f"## Case {case['case_id']}",
                "",
                "### Identity",
                "",
                f"- Prediction: `{identity['prediction_id']}`",
                f"- Explanation: `{identity['explanation_id']}`",
                f"- ATT&CK mapping: `{identity['attack_mapping_id']}`",
                f"- Window: `{identity['window_id']}`",
                f"- Capture: `{identity['capture_id']}`",
                f"- Split: `{identity['split']}`",
                "",
                "### Model measurement",
                "",
                (
                    f"- Predicted class: "
                    f"`{measurement['predicted_class']}`"
                ),
                (
                    f"- Confidence: "
                    f"{_markdown_number(measurement['confidence'])}"
                ),
                (
                    f"- Probability margin: "
                    f"{_markdown_number(measurement['probability_margin'])}"
                ),
                (
                    f"- Inference input SHA-256: "
                    f"`{measurement['inference_input_sha256']}`"
                ),
                "",
                "### Integrated Gradients",
                "",
                (
                    f"- Absolute completeness error: "
                    f"{_markdown_number(explanation['integrated_gradients']['absolute_completeness_error'])}"
                ),
                "- Top absolute attributions:",
            ]
        )

        for feature in explanation[
            "integrated_gradients"
        ]["top_features"]:
            lines.append(
                
                    f"  {feature['absolute_rank']}. "
                    f"`{feature['feature_name']}` — "
                    f"{_markdown_number(feature['attribution'])} "
                    f"({feature['direction']})"
                
            )

        prototype = explanation["prototype_geometry"]

        lines.extend(
            [
                "",
                "### Prototype geometry",
                "",
                (
                    f"- Nearest prototype: "
                    f"`{prototype['nearest_prototype_class']}` "
                    f"({_markdown_number(prototype['nearest_prototype_distance'])})"
                ),
                (
                    f"- Second nearest prototype: "
                    f"`{prototype['second_nearest_prototype_class']}` "
                    f"({_markdown_number(prototype['second_nearest_prototype_distance'])})"
                ),
                (
                    f"- Predicted-class prototype rank: "
                    f"{prototype['predicted_class_prototype_rank']}"
                ),
                (
                    f"- Prediction matches nearest prototype: "
                    f"{str(prototype['prediction_matches_nearest_prototype']).lower()}"
                ),
                "",
                "### ATT&CK interpretation",
                "",
                f"- Status: `{attack['mapping_status']}`",
                f"- Rule: `{attack['rule_id']}`",
                f"- ATT&CK version: `{attack['attack_version']}`",
            ]
        )

        tactics = attack["tactic_candidates"]

        if tactics:
            lines.append("- Candidate tactics:")

            for tactic in tactics:
                lines.append(
                    f"  - `{tactic['tactic_id']}` "
                    f"{tactic['tactic_name']}"
                )
        else:
            lines.append("- Candidate tactics: none")

        techniques = attack["technique_candidates"]

        if techniques:
            lines.append("- Candidate techniques:")

            for technique in techniques:
                lines.append(
                    f"  - `{technique}`"
                )
        else:
            lines.append("- Candidate techniques: none")

        lines.extend(
            [
                "",
                "### Primary evidence references",
                "",
                (
                    f"- M2 window lineage SHA-256: "
                    f"`{evidence['m2_window_lineage_record_sha256']}`"
                ),
                (
                    f"- M2 window row SHA-256: "
                    f"`{evidence['m2_window_row_sha256']}`"
                ),
                (
                    f"- M3 evaluation row SHA-256: "
                    f"`{evidence['m3_evaluation_row_sha256']}`"
                ),
                (
                    f"- Source events: "
                    f"{evidence['source_event_count']}"
                ),
            ]
        )

        for event in evidence["events"]:
            lines.extend(
                [
                    "",
                    f"#### Event `{event['event_id']}`",
                    "",
                    (
                        f"- Lineage record SHA-256: "
                        f"`{event['lineage_record_sha256']}`"
                    ),
                    (
                        f"- Source identity SHA-256: "
                        f"`{event['source_identity_sha256']}`"
                    ),
                    "- Source records:",
                ]
            )

            for source_record in event[
                "source_records"
            ]:
                lines.extend(
                    [
                        (
                            f"  - `{source_record['relative_path']}` "
                            f"row {source_record['row_number']}"
                        ),
                        (
                            f"    - Record SHA-256: "
                            f"`{source_record['source_record_sha256']}`"
                        ),
                        (
                            f"    - File SHA-256: "
                            f"`{source_record['source_file_sha256']}`"
                        ),
                    ]
                )

        lines.extend(
            [
                "",
                (
                    "> Prediction confidence, Integrated Gradients, "
                    "prototype geometry and ATT&CK mappings are "
                    "derived model outputs and are not primary "
                    "Zeek evidence."
                ),
                "",
            ]
        )

    return ("\n".join(lines).rstrip() + "\n").encode()


def _build_report_artifacts(
    inputs: dict[str, Any],
) -> dict[str, bytes]:
    config = inputs["config"]

    cases = []

    for prediction_id in sorted(
        inputs["predictions_by_id"]
    ):
        cases.append(
            _build_case(
                prediction=inputs[
                    "predictions_by_id"
                ][prediction_id],
                window=inputs[
                    "windows_by_prediction"
                ][prediction_id],
                integrated_gradients=inputs[
                    "ig_by_prediction"
                ][prediction_id],
                prototype_distance=inputs[
                    "distances_by_prediction"
                ][prediction_id],
                attack_mapping=inputs[
                    "mappings_by_prediction"
                ][prediction_id],
                events_by_id=inputs["events_by_id"],
                source_files_by_path=inputs[
                    "source_files_by_path"
                ],
                top_feature_count=config[
                    "integrated_gradients_top_features"
                ],
            )
        )

    candidate_count = sum(
        case["attack_interpretation"]["mapping_status"]
        == "candidate-tactic"
        for case in cases
    )
    not_applicable_count = sum(
        case["attack_interpretation"]["mapping_status"]
        == "not-applicable"
        for case in cases
    )
    unresolved_count = sum(
        case["attack_interpretation"]["mapping_status"]
        == "unresolved-multi-tactic"
        for case in cases
    )

    if (
        candidate_count
        + not_applicable_count
        + unresolved_count
        != len(cases)
    ):
        raise InvestigationReportError(
            "unexpected ATT&CK mapping status in report"
        )

    report = {
        "schema_version": "1.0",
        "artifact_type": "m7_investigation_report",
        "case_order": "prediction-id-lexicographic",
        "case_count": len(cases),
        "source_event_count": inputs[
            "source_event_count"
        ],
        "source_record_count": inputs[
            "source_record_count"
        ],
        "reference_labels_included": False,
        "dataset_attack_labels_included": False,
        "dataset_labels_used_for_reporting": False,
        "evidence_boundary": (
            "source-record-and-source-file-digest-references-"
            "are-primary-evidence-boundary"
        ),
        "cases": cases,
    }

    report_bytes = _canonical_json_bytes(report)
    markdown_bytes = _render_markdown(report)

    attack_manifest = inputs["attack_manifest"]
    attack_source = attack_manifest.core.source

    source = InvestigationReportSourceReferences(
        attack_mapping_bundle_id=(
            attack_manifest.attack_mapping_bundle_id
        ),
        attack_manifest_sha256=_sha256_file(
            inputs["attack_manifest_path"]
        ),
        attack_mappings_sha256=(
            attack_manifest.core.attack_mappings_sha256
        ),
        explanation_bundle_id=(
            attack_source.explanation_bundle_id
        ),
        explanation_manifest_sha256=(
            attack_source.explanation_manifest_sha256
        ),
        integrated_gradients_sha256=(
            attack_source.integrated_gradients_sha256
        ),
        prototype_reference_sha256=(
            attack_source.prototype_reference_sha256
        ),
        prototype_distances_sha256=(
            attack_source.prototype_distances_sha256
        ),
        prediction_bundle_id=(
            attack_source.prediction_bundle_id
        ),
        prediction_manifest_sha256=(
            attack_source.prediction_manifest_sha256
        ),
        predictions_sha256=(
            attack_source.predictions_sha256
        ),
        lineage_sha256=attack_source.lineage_sha256,
        campaign_id=attack_source.campaign_id,
        round_number=attack_source.round_number,
        global_model_sha256=(
            attack_source.global_model_sha256
        ),
        partition_manifest_sha256=(
            attack_source.partition_manifest_sha256
        ),
    )

    core = InvestigationReportBundleCore(
        code_version=attack_manifest.core.code_version,
        implementation_sha256=_sha256_file(
            Path(__file__)
        ),
        report_config_sha256=inputs[
            "config_sha256"
        ],
        source=source,
        case_count=len(cases),
        source_event_count=inputs[
            "source_event_count"
        ],
        source_record_count=inputs[
            "source_record_count"
        ],
        candidate_tactic_case_count=candidate_count,
        not_applicable_attack_case_count=(
            not_applicable_count
        ),
        unresolved_attack_case_count=unresolved_count,
        investigation_report_sha256=_sha256_bytes(
            report_bytes
        ),
        report_markdown_sha256=_sha256_bytes(
            markdown_bytes
        ),
        reportability_gate=(
            InvestigationReportabilityGate(
                attack_mapping_bundle_verified=True,
                explanation_bundle_transitively_verified=True,
                prediction_bundle_transitively_verified=True,
                complete_case_coverage=True,
                complete_primary_evidence_lineage=True,
                reference_labels_included=False,
                dataset_attack_labels_included=False,
                dataset_labels_used_for_reporting=False,
                model_measurements_separated=True,
                derived_interpretations_separated=True,
                complete_case_count=len(cases),
                incomplete_case_count=0,
                invariant_violation_count=0,
                reportable=True,
            )
        ),
    )

    core_document = core.model_dump(mode="json")

    canonical_core_sha256 = _sha256_bytes(
        _canonical_json_bytes(core_document)
    )

    manifest = InvestigationReportBundleManifest(
        investigation_report_bundle_id=(
            "m7-investigation-report-bundle-"
            f"{canonical_core_sha256[:24]}"
        ),
        core=core,
        canonical_core_sha256=canonical_core_sha256,
    )

    return {
        "investigation-report.json": report_bytes,
        "manifest.json": _canonical_json_bytes(
            manifest.model_dump(mode="json")
        ),
        "report.md": markdown_bytes,
    }


def _prepare_report_inputs(
    *,
    prediction_workspace: Path,
    explanation_workspace: Path,
    attack_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    return _validated_report_inputs(
        prediction_workspace=prediction_workspace,
        explanation_workspace=explanation_workspace,
        attack_workspace=attack_workspace,
        config_path=config_path,
    )


def create_investigation_report_bundle(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    explanation_workspace: Path,
    attack_workspace: Path,
    output: Path,
    prediction_config_path: Path,
    explanation_config_path: Path,
    attack_config_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Create the deterministic final M7 investigation report."""

    if output.exists():
        raise InvestigationReportError(
            f"investigation report output already exists: {output}"
        )

    _verified_attack_source(
        round_workspace=round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
        prediction_workspace=prediction_workspace,
        explanation_workspace=explanation_workspace,
        attack_workspace=attack_workspace,
        prediction_config_path=prediction_config_path,
        explanation_config_path=explanation_config_path,
        attack_config_path=attack_config_path,
    )

    inputs = _prepare_report_inputs(
        prediction_workspace=prediction_workspace,
        explanation_workspace=explanation_workspace,
        attack_workspace=attack_workspace,
        config_path=config_path,
    )

    artifacts = _build_report_artifacts(inputs)

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        dir=output.parent,
        prefix=".m7-report-",
    ) as temporary:
        staging = Path(temporary) / "bundle"
        staging.mkdir()

        for name in sorted(artifacts):
            (staging / name).write_bytes(
                artifacts[name]
            )

        os.replace(staging, output)

    manifest = (
        InvestigationReportBundleManifest.model_validate(
            json.loads(artifacts["manifest.json"])
        )
    )

    return {
        "status": "reported_verified_source",
        "investigation_report_bundle_id": (
            manifest.investigation_report_bundle_id
        ),
        "attack_mapping_bundle_id": (
            manifest.core.source.attack_mapping_bundle_id
        ),
        "explanation_bundle_id": (
            manifest.core.source.explanation_bundle_id
        ),
        "prediction_bundle_id": (
            manifest.core.source.prediction_bundle_id
        ),
        "case_count": manifest.core.case_count,
        "source_event_count": (
            manifest.core.source_event_count
        ),
        "source_record_count": (
            manifest.core.source_record_count
        ),
        "candidate_tactic_case_count": (
            manifest.core.candidate_tactic_case_count
        ),
        "unresolved_attack_case_count": (
            manifest.core.unresolved_attack_case_count
        ),
        "manifest_sha256": _sha256_bytes(
            artifacts["manifest.json"]
        ),
        "reportable": True,
        "source_attack_verified": True,
        "workspace": str(output),
    }


def verify_investigation_report_bundle(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    explanation_workspace: Path,
    attack_workspace: Path,
    workspace: Path,
    prediction_config_path: Path,
    explanation_config_path: Path,
    attack_config_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Recompute M7 report artifacts and compare them byte-for-byte."""

    errors: list[str] = []
    source_attack_verified = False
    verification_recomputed_report = False

    expected: dict[str, bytes] | None = None
    manifest: InvestigationReportBundleManifest | None = None

    try:
        _verified_attack_source(
            round_workspace=round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            dataset_workspace=dataset_workspace,
            prediction_workspace=prediction_workspace,
            explanation_workspace=explanation_workspace,
            attack_workspace=attack_workspace,
            prediction_config_path=prediction_config_path,
            explanation_config_path=explanation_config_path,
            attack_config_path=attack_config_path,
        )
        source_attack_verified = True
    except (InvestigationReportError, OSError, ValueError) as exc:
        errors.append(str(exc))

    if not errors:
        try:
            inputs = _prepare_report_inputs(
                prediction_workspace=prediction_workspace,
                explanation_workspace=explanation_workspace,
                attack_workspace=attack_workspace,
                config_path=config_path,
            )

            expected = _build_report_artifacts(
                inputs
            )
            verification_recomputed_report = True

        except (
            InvestigationReportError,
            OSError,
            ValueError,
            ValidationError,
        ) as exc:
            errors.append(str(exc))

    if not workspace.is_dir():
        errors.append(
            f"investigation report workspace does not exist: "
            f"{workspace}"
        )
    else:
        actual_entries = {
            path.name
            for path in workspace.iterdir()
        }

        missing = sorted(
            EXPECTED_OUTPUT_FILES - actual_entries
        )
        unexpected = sorted(
            actual_entries - EXPECTED_OUTPUT_FILES
        )

        if missing:
            errors.append(
                f"missing investigation report files: {missing}"
            )

        if unexpected:
            errors.append(
                f"unexpected investigation report files: "
                f"{unexpected}"
            )

    if expected is not None and workspace.is_dir():
        for name in sorted(EXPECTED_OUTPUT_FILES):
            path = workspace / name

            if not path.is_file():
                continue

            if path.read_bytes() != expected[name]:
                errors.append(
                    "investigation report artifact differs "
                    f"from recomputation: {name}"
                )

    manifest_path = workspace / "manifest.json"

    if manifest_path.is_file():
        try:
            manifest = (
                InvestigationReportBundleManifest.model_validate(
                    _read_json(
                        manifest_path,
                        "investigation report manifest",
                    )
                )
            )
        except (
            InvestigationReportError,
            ValidationError,
        ) as exc:
            errors.append(str(exc))

    status = "verified" if not errors else "failed"

    return {
        "status": status,
        "investigation_report_bundle_id": (
            manifest.investigation_report_bundle_id
            if manifest is not None
            else None
        ),
        "attack_mapping_bundle_id": (
            manifest.core.source.attack_mapping_bundle_id
            if manifest is not None
            else None
        ),
        "case_count": (
            manifest.core.case_count
            if manifest is not None
            else 0
        ),
        "source_event_count": (
            manifest.core.source_event_count
            if manifest is not None
            else 0
        ),
        "source_record_count": (
            manifest.core.source_record_count
            if manifest is not None
            else 0
        ),
        "candidate_tactic_case_count": (
            manifest.core.candidate_tactic_case_count
            if manifest is not None
            else 0
        ),
        "unresolved_attack_case_count": (
            manifest.core.unresolved_attack_case_count
            if manifest is not None
            else 0
        ),
        "manifest_sha256": (
            _sha256_file(manifest_path)
            if manifest_path.is_file()
            else None
        ),
        "reportable": (
            status == "verified"
            and manifest is not None
            and manifest.core.reportability_gate.reportable
        ),
        "source_attack_verified": (
            source_attack_verified
        ),
        "verification_recomputed_report": (
            verification_recomputed_report
        ),
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }