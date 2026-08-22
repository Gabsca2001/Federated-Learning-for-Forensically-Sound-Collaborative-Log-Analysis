"""Versioned MITRE ATT&CK hypothesis mapping for Milestone 7."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .explanation_bundle import (
    ExplanationBundleError,
    verify_explanation_bundle,
)
from .investigation_models import (
    AttackMappingBundleCore,
    AttackMappingBundleManifest,
    AttackMappingReportabilityGate,
    AttackMappingSourceReferences,
    ExplanationBundleManifest,
    PredictionBundleManifest,
)

EXPECTED_OUTPUT_FILES = {
    "attack-mappings.json",
    "manifest.json",
}

EXPECTED_MODEL_CLASSES = [
    "benign",
    "credential_access",
    "exfiltration",
    "initial_access",
    "multi_tactic",
    "reconnaissance",
]

EXPECTED_RULE_CONTRACT = {
    "benign": {
        "mapping_status": "not-applicable",
        "tactic_candidates": [],
    },
    "credential_access": {
        "mapping_status": "candidate-tactic",
        "tactic_candidates": [
            {
                "tactic_id": "TA0006",
                "tactic_name": "Credential Access",
            }
        ],
    },
    "exfiltration": {
        "mapping_status": "candidate-tactic",
        "tactic_candidates": [
            {
                "tactic_id": "TA0010",
                "tactic_name": "Exfiltration",
            }
        ],
    },
    "initial_access": {
        "mapping_status": "candidate-tactic",
        "tactic_candidates": [
            {
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
            }
        ],
    },
    "multi_tactic": {
        "mapping_status": "unresolved-multi-tactic",
        "tactic_candidates": [],
    },
    "reconnaissance": {
        "mapping_status": "candidate-tactic",
        "tactic_candidates": [
            {
                "tactic_id": "TA0043",
                "tactic_name": "Reconnaissance",
            }
        ],
    },
}


class AttackMappingError(RuntimeError):
    """Raised when an ATT&CK hypothesis cannot be safely published."""


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
    ).encode("utf-8")


def _read_json(path: Path, label: str) -> Any:
    if not path.is_file():
        raise AttackMappingError(f"missing {label}: {path}")

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttackMappingError(f"invalid {label}: {path}") from exc


def _load_attack_config(
    config_path: Path,
) -> tuple[dict[str, Any], str]:
    if not config_path.is_file():
        raise AttackMappingError(
            f"missing ATT&CK configuration: {config_path}"
        )

    raw = config_path.read_bytes()

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise AttackMappingError(
            "invalid ATT&CK configuration YAML"
        ) from exc

    if not isinstance(document, dict):
        raise AttackMappingError(
            "ATT&CK configuration root must be an object"
        )

    if set(document) != {
        "schema_version",
        "investigation_attack",
    }:
        raise AttackMappingError(
            "unexpected ATT&CK configuration top-level contract"
        )

    if document.get("schema_version") != "1.0":
        raise AttackMappingError(
            "unexpected ATT&CK configuration schema"
        )

    config = document.get("investigation_attack")

    if not isinstance(config, dict):
        raise AttackMappingError(
            "missing investigation_attack configuration"
        )

    expected_keys = {
        "framework",
        "domain",
        "version",
        "mapping_policy",
        "interpretation",
        "model_taxonomy",
        "rules",
    }

    if set(config) != expected_keys:
        raise AttackMappingError(
            "unexpected investigation_attack configuration contract"
        )

    if config.get("framework") != "MITRE ATT&CK":
        raise AttackMappingError(
            "M7 ATT&CK framework must be MITRE ATT&CK"
        )

    if config.get("domain") != "enterprise":
        raise AttackMappingError(
            "M7 ATT&CK domain must be enterprise"
        )

    if config.get("version") != "19.2":
        raise AttackMappingError(
            "M7 ATT&CK mapping is frozen to version 19.2"
        )

    if (
        config.get("mapping_policy")
        != "predicted-class-only-versioned-tactic-hypothesis"
    ):
        raise AttackMappingError(
            "unexpected ATT&CK mapping policy"
        )

    interpretation = config.get("interpretation")

    required_interpretation = {
        "assertion_type": "investigative-hypothesis",
        "primary_evidence": False,
        "allow_technique_claims": False,
        "require_verified_explanation_bundle": True,
        "use_reference_labels": False,
        "use_dataset_attack_labels": False,
        "use_integrated_gradients_for_rule_selection": False,
        "use_prototype_distances_for_rule_selection": False,
    }

    if interpretation != required_interpretation:
        raise AttackMappingError(
            "ATT&CK interpretation contract is not frozen as required"
        )

    model_taxonomy = config.get("model_taxonomy")

    if not isinstance(model_taxonomy, dict):
        raise AttackMappingError(
            "missing ATT&CK model taxonomy contract"
        )

    if set(model_taxonomy) != {"source", "class_names"}:
        raise AttackMappingError(
            "unexpected model taxonomy contract"
        )

    if (
        model_taxonomy.get("source")
        != "frozen-m5-classification-contract"
    ):
        raise AttackMappingError(
            "unexpected model taxonomy source"
        )

    if model_taxonomy.get("class_names") != EXPECTED_MODEL_CLASSES:
        raise AttackMappingError(
            "ATT&CK configuration does not match the frozen M5 classes"
        )

    rules = config.get("rules")

    if not isinstance(rules, dict):
        raise AttackMappingError(
            "ATT&CK mapping rules must be an object"
        )

    if set(rules) != set(EXPECTED_MODEL_CLASSES):
        raise AttackMappingError(
            "ATT&CK mapping rule coverage is incomplete"
        )

    seen_rule_ids: set[str] = set()

    for class_name in EXPECTED_MODEL_CLASSES:
        rule = rules[class_name]

        if not isinstance(rule, dict):
            raise AttackMappingError(
                f"invalid ATT&CK rule for {class_name}"
            )

        if set(rule) != {
            "rule_id",
            "mapping_status",
            "tactic_candidates",
            "rationale",
        }:
            raise AttackMappingError(
                f"unexpected ATT&CK rule contract for {class_name}"
            )

        rule_id = rule.get("rule_id")

        if not isinstance(rule_id, str) or not rule_id:
            raise AttackMappingError(
                f"invalid ATT&CK rule id for {class_name}"
            )

        if rule_id in seen_rule_ids:
            raise AttackMappingError(
                f"duplicate ATT&CK rule id: {rule_id}"
            )

        seen_rule_ids.add(rule_id)

        expected = EXPECTED_RULE_CONTRACT[class_name]

        if rule.get("mapping_status") != expected["mapping_status"]:
            raise AttackMappingError(
                f"unexpected mapping status for {class_name}"
            )

        if (
            rule.get("tactic_candidates")
            != expected["tactic_candidates"]
        ):
            raise AttackMappingError(
                f"unexpected tactic mapping for {class_name}"
            )

        rationale = rule.get("rationale")

        if not isinstance(rationale, str) or not rationale.strip():
            raise AttackMappingError(
                f"missing ATT&CK rationale for {class_name}"
            )

    return config, _sha256_bytes(raw)


def _index_records(
    records: Any,
    *,
    artifact: str,
) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        raise AttackMappingError(
            f"{artifact} record collection is not a list"
        )

    indexed: dict[str, dict[str, Any]] = {}

    for record in records:
        if not isinstance(record, dict):
            raise AttackMappingError(
                f"{artifact} contains a non-object record"
            )

        prediction_id = record.get("prediction_id")

        if not isinstance(prediction_id, str) or not prediction_id:
            raise AttackMappingError(
                f"{artifact} record has no prediction_id"
            )

        if prediction_id in indexed:
            raise AttackMappingError(
                f"{artifact} contains duplicate prediction_id "
                f"{prediction_id}"
            )

        indexed[prediction_id] = record

    return indexed


def _record_sha256(record: dict[str, Any]) -> str:
    return _sha256_bytes(_canonical_json_bytes(record))


def _verified_explanation_source(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    explanation_workspace: Path,
    prediction_config_path: Path,
    explanation_config_path: Path,
) -> dict[str, Any]:
    try:
        verification = verify_explanation_bundle(
            round_workspace=round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            dataset_workspace=dataset_workspace,
            prediction_workspace=prediction_workspace,
            workspace=explanation_workspace,
            prediction_config_path=prediction_config_path,
            config_path=explanation_config_path,
        )
    except (ExplanationBundleError, OSError, ValueError) as exc:
        raise AttackMappingError(
            "Explanation Bundle verification raised an error"
        ) from exc

    if verification.get("status") != "verified":
        raise AttackMappingError(
            "Explanation Bundle did not pass independent verification"
        )

    if verification.get("reportable") is not True:
        raise AttackMappingError(
            "Explanation Bundle is not reportable"
        )

    if verification.get("source_prediction_verified") is not True:
        raise AttackMappingError(
            "Prediction Bundle was not transitively verified"
        )

    required_recomputations = (
        "verification_recomputed_integrated_gradients",
        "verification_recomputed_prototype_distances",
        "verification_recomputed_training_prototypes",
    )

    for key in required_recomputations:
        if verification.get(key) is not True:
            raise AttackMappingError(
                f"Explanation Bundle verifier did not confirm {key}"
            )

    return verification


def _validated_attack_inputs(
    *,
    prediction_workspace: Path,
    explanation_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    config, config_sha256 = _load_attack_config(config_path)

    prediction_manifest_path = prediction_workspace / "manifest.json"
    predictions_path = prediction_workspace / "predictions.json"
    lineage_path = prediction_workspace / "lineage.json"

    explanation_manifest_path = explanation_workspace / "manifest.json"
    integrated_gradients_path = (
        explanation_workspace / "integrated-gradients.json"
    )
    prototype_reference_path = (
        explanation_workspace / "prototype-reference.json"
    )
    prototype_distances_path = (
        explanation_workspace / "prototype-distances.json"
    )

    try:
        prediction_manifest = PredictionBundleManifest.model_validate(
            _read_json(
                prediction_manifest_path,
                "Prediction Bundle manifest",
            )
        )
        explanation_manifest = ExplanationBundleManifest.model_validate(
            _read_json(
                explanation_manifest_path,
                "Explanation Bundle manifest",
            )
        )
    except ValidationError as exc:
        raise AttackMappingError(
            "invalid upstream M7 manifest"
        ) from exc

    predictions_payload = _read_json(
        predictions_path,
        "Prediction Bundle predictions",
    )
    integrated_payload = _read_json(
        integrated_gradients_path,
        "Integrated Gradients artifact",
    )
    prototype_reference_payload = _read_json(
        prototype_reference_path,
        "prototype reference artifact",
    )
    prototype_distances_payload = _read_json(
        prototype_distances_path,
        "prototype distances artifact",
    )

    if not isinstance(predictions_payload, dict):
        raise AttackMappingError(
            "predictions.json must contain an object"
        )

    if not isinstance(integrated_payload, dict):
        raise AttackMappingError(
            "integrated-gradients.json must contain an object"
        )

    if not isinstance(prototype_reference_payload, dict):
        raise AttackMappingError(
            "prototype-reference.json must contain an object"
        )

    if not isinstance(prototype_distances_payload, dict):
        raise AttackMappingError(
            "prototype-distances.json must contain an object"
        )

    actual_predictions_sha256 = _sha256_file(predictions_path)
    actual_lineage_sha256 = _sha256_file(lineage_path)

    if (
        prediction_manifest.core.predictions_sha256
        != actual_predictions_sha256
    ):
        raise AttackMappingError(
            "Prediction Bundle predictions digest mismatch"
        )

    if prediction_manifest.core.lineage_sha256 != actual_lineage_sha256:
        raise AttackMappingError(
            "Prediction Bundle lineage digest mismatch"
        )

    if (
        explanation_manifest.core.source.prediction_manifest_sha256
        != _sha256_file(prediction_manifest_path)
    ):
        raise AttackMappingError(
            "Explanation Bundle prediction manifest binding mismatch"
        )

    if (
        explanation_manifest.core.source.predictions_sha256
        != actual_predictions_sha256
    ):
        raise AttackMappingError(
            "Explanation Bundle predictions binding mismatch"
        )

    if (
        explanation_manifest.core.source.lineage_sha256
        != actual_lineage_sha256
    ):
        raise AttackMappingError(
            "Explanation Bundle lineage binding mismatch"
        )

    if (
        explanation_manifest.core.integrated_gradients_sha256
        != _sha256_file(integrated_gradients_path)
    ):
        raise AttackMappingError(
            "Integrated Gradients digest mismatch"
        )

    if (
        explanation_manifest.core.prototype_reference_sha256
        != _sha256_file(prototype_reference_path)
    ):
        raise AttackMappingError(
            "prototype reference digest mismatch"
        )

    if (
        explanation_manifest.core.prototype_distances_sha256
        != _sha256_file(prototype_distances_path)
    ):
        raise AttackMappingError(
            "prototype distances digest mismatch"
        )

    class_names = predictions_payload.get("class_names")

    if class_names != EXPECTED_MODEL_CLASSES:
        raise AttackMappingError(
            "Prediction Bundle class contract differs from frozen M5 "
            "taxonomy"
        )

    if (
        class_names
        != config["model_taxonomy"]["class_names"]
    ):
        raise AttackMappingError(
            "Prediction Bundle classes differ from ATT&CK configuration"
        )

    if (
        prototype_distances_payload.get("class_names")
        != class_names
    ):
        raise AttackMappingError(
            "prototype-distance class contract differs from predictions"
        )

    if (
        predictions_payload.get(
            "reference_labels_used_for_inference"
        )
        is not False
    ):
        raise AttackMappingError(
            "Prediction Bundle does not preserve label independence"
        )

    prediction_rows = predictions_payload.get("predictions")

    predictions_by_id = _index_records(
        prediction_rows,
        artifact="predictions.json",
    )

    ig_by_id = _index_records(
        integrated_payload.get("explanations"),
        artifact="integrated-gradients.json",
    )

    distances_by_id = _index_records(
        prototype_distances_payload.get("explanations"),
        artifact="prototype-distances.json",
    )

    prediction_ids = set(predictions_by_id)

    if set(ig_by_id) != prediction_ids:
        raise AttackMappingError(
            "Integrated Gradients coverage differs from predictions"
        )

    if set(distances_by_id) != prediction_ids:
        raise AttackMappingError(
            "prototype-distance coverage differs from predictions"
        )

    expected_count = prediction_manifest.core.prediction_count

    if len(predictions_by_id) != expected_count:
        raise AttackMappingError(
            "prediction count differs from Prediction Bundle manifest"
        )

    if (
        explanation_manifest.core.prediction_count
        != expected_count
    ):
        raise AttackMappingError(
            "Explanation Bundle prediction count mismatch"
        )

    for prediction_id in sorted(prediction_ids):
        prediction = predictions_by_id[prediction_id]
        ig = ig_by_id[prediction_id]
        distance = distances_by_id[prediction_id]

        predicted_class = prediction.get("predicted_class")
        window_id = prediction.get("window_id")
        inference_input_sha256 = prediction.get(
            "inference_input_sha256"
        )

        if predicted_class not in EXPECTED_MODEL_CLASSES:
            raise AttackMappingError(
                f"unknown frozen model class: {predicted_class}"
            )

        if (
            prediction.get("reference_label_role")
            != "evaluation-only-not-an-inference-input"
        ):
            raise AttackMappingError(
                f"invalid reference-label role for {prediction_id}"
            )

        if ig.get("target_class") != predicted_class:
            raise AttackMappingError(
                f"IG target differs from prediction for {prediction_id}"
            )

        if distance.get("predicted_class") != predicted_class:
            raise AttackMappingError(
                "prototype-distance class differs from prediction for "
                f"{prediction_id}"
            )

        if ig.get("window_id") != window_id:
            raise AttackMappingError(
                f"IG window differs from prediction for {prediction_id}"
            )

        if distance.get("window_id") != window_id:
            raise AttackMappingError(
                "prototype-distance window differs from prediction for "
                f"{prediction_id}"
            )

        if (
            ig.get("inference_input_sha256")
            != inference_input_sha256
        ):
            raise AttackMappingError(
                "IG input digest differs from prediction for "
                f"{prediction_id}"
            )

        if (
            distance.get("inference_input_sha256")
            != inference_input_sha256
        ):
            raise AttackMappingError(
                "prototype-distance input digest differs from prediction "
                f"for {prediction_id}"
            )

        if ig.get("explanation_id") != distance.get(
            "explanation_id"
        ):
            raise AttackMappingError(
                "IG and prototype distance explanation ids differ for "
                f"{prediction_id}"
            )

        if distance.get("row_embedding_preserved") is not False:
            raise AttackMappingError(
                "row embeddings must not be preserved"
            )

    return {
        "config": config,
        "config_sha256": config_sha256,
        "prediction_manifest": prediction_manifest,
        "explanation_manifest": explanation_manifest,
        "predictions_by_id": predictions_by_id,
        "ig_by_id": ig_by_id,
        "distances_by_id": distances_by_id,
        "class_names": class_names,
    }


def _mapping_record(
    *,
    prediction: dict[str, Any],
    integrated_gradients: dict[str, Any],
    prototype_distance: dict[str, Any],
    rule: dict[str, Any],
    attack_version: str,
) -> dict[str, Any]:
    mapping_core = {
        "schema_version": "1.0",
        "prediction_id": prediction["prediction_id"],
        "explanation_id": integrated_gradients["explanation_id"],
        "window_id": prediction["window_id"],
        "inference_input_sha256": prediction[
            "inference_input_sha256"
        ],
        "predicted_class": prediction["predicted_class"],
        "rule_id": rule["rule_id"],
        "mapping_status": rule["mapping_status"],
        "decision_basis": (
            "predicted-class-only-versioned-rule"
        ),
        "attack_framework": "MITRE ATT&CK",
        "attack_domain": "enterprise",
        "attack_version": attack_version,
        "tactic_candidates": rule["tactic_candidates"],
        "technique_candidates": [],
        "explanation_context": {
            "integrated_gradients_record_sha256": (
                _record_sha256(integrated_gradients)
            ),
            "prototype_distance_record_sha256": (
                _record_sha256(prototype_distance)
            ),
            "used_for_rule_selection": False,
        },
        "excluded_decision_inputs": [
            "reference_label",
            "dataset_label_tactic",
            "dataset_label_technique",
            "integrated_gradients",
            "prototype_distances",
        ],
        "evidentiary_role": "derived-investigative-hypothesis",
        "primary_evidence": False,
        "rationale": rule["rationale"],
    }

    mapping_sha256 = _sha256_bytes(
        _canonical_json_bytes(mapping_core)
    )

    return {
        "mapping_id": (
            f"m7-attack-mapping-{mapping_sha256[:24]}"
        ),
        **mapping_core,
    }


def _build_attack_artifacts(
    inputs: dict[str, Any],
) -> dict[str, bytes]:
    config = inputs["config"]
    predictions_by_id = inputs["predictions_by_id"]
    ig_by_id = inputs["ig_by_id"]
    distances_by_id = inputs["distances_by_id"]
    explanation_manifest = inputs["explanation_manifest"]
    prediction_manifest = inputs["prediction_manifest"]

    rules = config["rules"]
    attack_version = config["version"]

    mappings = []

    for prediction_id in sorted(predictions_by_id):
        prediction = predictions_by_id[prediction_id]
        predicted_class = prediction["predicted_class"]

        mappings.append(
            _mapping_record(
                prediction=prediction,
                integrated_gradients=ig_by_id[prediction_id],
                prototype_distance=distances_by_id[
                    prediction_id
                ],
                rule=rules[predicted_class],
                attack_version=attack_version,
            )
        )

    candidate_count = sum(
        row["mapping_status"] == "candidate-tactic"
        for row in mappings
    )
    not_applicable_count = sum(
        row["mapping_status"] == "not-applicable"
        for row in mappings
    )
    unresolved_count = sum(
        row["mapping_status"] == "unresolved-multi-tactic"
        for row in mappings
    )

    mappings_document = {
        "schema_version": "1.0",
        "artifact_type": "m7_attack_mappings",
        "framework": "MITRE ATT&CK",
        "domain": "enterprise",
        "attack_version": attack_version,
        "mapping_policy": config["mapping_policy"],
        "assertion_type": "investigative-hypothesis",
        "primary_evidence": False,
        "technique_claims_enabled": False,
        "model_class_names": inputs["class_names"],
        "mapping_count": len(mappings),
        "mappings": mappings,
    }

    mappings_bytes = _canonical_json_bytes(mappings_document)
    mappings_sha256 = _sha256_bytes(mappings_bytes)

    source = AttackMappingSourceReferences(
        explanation_bundle_id=(
            explanation_manifest.explanation_bundle_id
        ),
        explanation_manifest_sha256=_sha256_file(
            inputs["explanation_manifest_path"]
        ),
        integrated_gradients_sha256=(
            explanation_manifest.core.integrated_gradients_sha256
        ),
        prototype_reference_sha256=(
            explanation_manifest.core.prototype_reference_sha256
        ),
        prototype_distances_sha256=(
            explanation_manifest.core.prototype_distances_sha256
        ),
        prediction_bundle_id=prediction_manifest.bundle_id,
        prediction_manifest_sha256=(
            explanation_manifest.core.source.prediction_manifest_sha256
        ),
        predictions_sha256=(
            explanation_manifest.core.source.predictions_sha256
        ),
        lineage_sha256=(
            explanation_manifest.core.source.lineage_sha256
        ),
        campaign_id=(
            explanation_manifest.core.source.campaign_id
        ),
        round_number=(
            explanation_manifest.core.source.round_number
        ),
        global_model_sha256=(
            explanation_manifest.core.source.global_model_sha256
        ),
        partition_manifest_sha256=(
            explanation_manifest.core.source.partition_manifest_sha256
        ),
    )

    core = AttackMappingBundleCore(
        code_version=explanation_manifest.core.code_version,
        implementation_sha256=_sha256_file(Path(__file__)),
        attack_config_sha256=inputs["config_sha256"],
        framework="MITRE ATT&CK",
        domain="enterprise",
        attack_version="19.2",
        mapping_policy=config["mapping_policy"],
        model_class_names=inputs["class_names"],
        source=source,
        mapping_count=len(mappings),
        candidate_tactic_mapping_count=candidate_count,
        not_applicable_mapping_count=not_applicable_count,
        unresolved_mapping_count=unresolved_count,
        attack_mappings_sha256=mappings_sha256,
        reportability_gate=AttackMappingReportabilityGate(
            explanation_bundle_verified=True,
            prediction_bundle_transitively_verified=True,
            model_taxonomy_verified=True,
            complete_mapping_coverage=True,
            reference_labels_used_for_mapping=False,
            dataset_attack_labels_used_for_mapping=False,
            integrated_gradients_used_for_rule_selection=False,
            prototype_distances_used_for_rule_selection=False,
            technique_claims_enabled=False,
            complete_prediction_count=len(mappings),
            unmapped_prediction_count=0,
            unresolved_prediction_count=unresolved_count,
            invariant_violation_count=0,
            reportable=True,
        ),
    )

    core_document = core.model_dump(mode="json")
    canonical_core_sha256 = _sha256_bytes(
        _canonical_json_bytes(core_document)
    )

    manifest = AttackMappingBundleManifest(
        attack_mapping_bundle_id=(
            "m7-attack-mapping-bundle-"
            f"{canonical_core_sha256[:24]}"
        ),
        core=core,
        canonical_core_sha256=canonical_core_sha256,
    )

    manifest_bytes = _canonical_json_bytes(
        manifest.model_dump(mode="json")
    )

    return {
        "attack-mappings.json": mappings_bytes,
        "manifest.json": manifest_bytes,
    }


def _prepare_attack_inputs(
    *,
    prediction_workspace: Path,
    explanation_workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    inputs = _validated_attack_inputs(
        prediction_workspace=prediction_workspace,
        explanation_workspace=explanation_workspace,
        config_path=config_path,
    )
    inputs["explanation_manifest_path"] = (
        explanation_workspace / "manifest.json"
    )
    return inputs


def create_attack_mapping_bundle(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    explanation_workspace: Path,
    output: Path,
    prediction_config_path: Path,
    explanation_config_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Map verified M7 predictions to versioned ATT&CK hypotheses."""

    if output.exists():
        raise AttackMappingError(
            f"ATT&CK output already exists: {output}"
        )

    _verified_explanation_source(
        round_workspace=round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
        prediction_workspace=prediction_workspace,
        explanation_workspace=explanation_workspace,
        prediction_config_path=prediction_config_path,
        explanation_config_path=explanation_config_path,
    )

    inputs = _prepare_attack_inputs(
        prediction_workspace=prediction_workspace,
        explanation_workspace=explanation_workspace,
        config_path=config_path,
    )

    artifacts = _build_attack_artifacts(inputs)

    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        dir=output.parent,
        prefix=".m7-attack-",
    ) as temporary:
        staging = Path(temporary) / "bundle"
        staging.mkdir()

        for name in sorted(artifacts):
            (staging / name).write_bytes(artifacts[name])

        os.replace(staging, output)

    manifest = AttackMappingBundleManifest.model_validate(
        json.loads(artifacts["manifest.json"])
    )

    return {
        "status": "mapped_verified_source",
        "attack_mapping_bundle_id": (
            manifest.attack_mapping_bundle_id
        ),
        "explanation_bundle_id": (
            manifest.core.source.explanation_bundle_id
        ),
        "prediction_bundle_id": (
            manifest.core.source.prediction_bundle_id
        ),
        "attack_version": manifest.core.attack_version,
        "mapping_count": manifest.core.mapping_count,
        "candidate_tactic_mapping_count": (
            manifest.core.candidate_tactic_mapping_count
        ),
        "not_applicable_mapping_count": (
            manifest.core.not_applicable_mapping_count
        ),
        "unresolved_mapping_count": (
            manifest.core.unresolved_mapping_count
        ),
        "manifest_sha256": _sha256_bytes(
            artifacts["manifest.json"]
        ),
        "reportable": True,
        "source_explanation_verified": True,
        "workspace": str(output),
    }


def verify_attack_mapping_bundle(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    explanation_workspace: Path,
    workspace: Path,
    prediction_config_path: Path,
    explanation_config_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Recompute and byte-verify a versioned M7 ATT&CK bundle."""

    errors: list[str] = []
    source_explanation_verified = False
    recomputed_attack_mapping = False
    expected: dict[str, bytes] | None = None
    manifest: AttackMappingBundleManifest | None = None

    try:
        _verified_explanation_source(
            round_workspace=round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            dataset_workspace=dataset_workspace,
            prediction_workspace=prediction_workspace,
            explanation_workspace=explanation_workspace,
            prediction_config_path=prediction_config_path,
            explanation_config_path=explanation_config_path,
        )
        source_explanation_verified = True
    except (AttackMappingError, OSError, ValueError) as exc:
        errors.append(str(exc))

    if not errors:
        try:
            inputs = _prepare_attack_inputs(
                prediction_workspace=prediction_workspace,
                explanation_workspace=explanation_workspace,
                config_path=config_path,
            )
            expected = _build_attack_artifacts(inputs)
            recomputed_attack_mapping = True
        except (
            AttackMappingError,
            OSError,
            ValueError,
            ValidationError,
        ) as exc:
            errors.append(str(exc))

    if not workspace.is_dir():
        errors.append(
            f"ATT&CK mapping workspace does not exist: {workspace}"
        )
    else:
        actual_entries = {
            path.name
            for path in workspace.iterdir()
        }

        missing = sorted(EXPECTED_OUTPUT_FILES - actual_entries)
        unexpected = sorted(actual_entries - EXPECTED_OUTPUT_FILES)

        if missing:
            errors.append(
                f"missing ATT&CK bundle files: {missing}"
            )

        if unexpected:
            errors.append(
                f"unexpected ATT&CK bundle files: {unexpected}"
            )

    if expected is not None and workspace.is_dir():
        for name in sorted(EXPECTED_OUTPUT_FILES):
            path = workspace / name

            if not path.is_file():
                continue

            if path.read_bytes() != expected[name]:
                errors.append(
                    f"ATT&CK artifact differs from recomputation: {name}"
                )

    manifest_path = workspace / "manifest.json"

    if manifest_path.is_file():
        try:
            manifest = AttackMappingBundleManifest.model_validate(
                _read_json(
                    manifest_path,
                    "ATT&CK mapping manifest",
                )
            )
        except (
            AttackMappingError,
            ValidationError,
        ) as exc:
            errors.append(str(exc))

    status = "verified" if not errors else "failed"

    return {
        "status": status,
        "attack_mapping_bundle_id": (
            manifest.attack_mapping_bundle_id
            if manifest is not None
            else None
        ),
        "explanation_bundle_id": (
            manifest.core.source.explanation_bundle_id
            if manifest is not None
            else None
        ),
        "prediction_bundle_id": (
            manifest.core.source.prediction_bundle_id
            if manifest is not None
            else None
        ),
        "attack_version": (
            manifest.core.attack_version
            if manifest is not None
            else None
        ),
        "mapping_count": (
            manifest.core.mapping_count
            if manifest is not None
            else 0
        ),
        "candidate_tactic_mapping_count": (
            manifest.core.candidate_tactic_mapping_count
            if manifest is not None
            else 0
        ),
        "not_applicable_mapping_count": (
            manifest.core.not_applicable_mapping_count
            if manifest is not None
            else 0
        ),
        "unresolved_mapping_count": (
            manifest.core.unresolved_mapping_count
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
        "source_explanation_verified": (
            source_explanation_verified
        ),
        "verification_recomputed_attack_mapping": (
            recomputed_attack_mapping
        ),
        "error_count": len(errors),
        "errors": errors,
        "workspace": str(workspace),
    }