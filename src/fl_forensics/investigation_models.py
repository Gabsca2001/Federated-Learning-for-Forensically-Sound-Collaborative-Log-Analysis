"""Strict schemas for the M7 investigative prediction evidence path."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .models import HEX_256_PATTERN, StrictModel


class PredictionSourceReferences(StrictModel):
    campaign_id: str
    round_number: int = Field(gt=0)
    context_id: str
    checkpoint_id: str
    round_context_sha256: str = Field(pattern=HEX_256_PATTERN)
    checkpoint_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    global_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    partition_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    server_evaluation_sha256: str = Field(pattern=HEX_256_PATTERN)
    m2_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    m2_dataset_sha256: str = Field(pattern=HEX_256_PATTERN)
    m2_scaler_sha256: str = Field(pattern=HEX_256_PATTERN)
    m2_lineage_sha256: str = Field(pattern=HEX_256_PATTERN)


class PredictionSelection(StrictModel):
    split: Literal["validation", "test", "temporal_holdout"]
    method: Literal["explicit-window-ids", "lexicographic-first-window-ids"]
    selection_provenance: Literal[
        "investigator-supplied-basis-not-assessed",
        "window-id-only-no-label-prediction-or-metric",
    ]
    window_ids: list[str]
    row_count: int = Field(gt=0)

    @field_validator("window_ids")
    @classmethod
    def _ordered_unique_windows(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("window ids must be unique and lexicographically ordered")
        return value

    @model_validator(mode="after")
    def _count_matches(self) -> PredictionSelection:
        if self.row_count != len(self.window_ids):
            raise ValueError("prediction row count does not match window ids")
        expected = (
            "investigator-supplied-basis-not-assessed"
            if self.method == "explicit-window-ids"
            else "window-id-only-no-label-prediction-or-metric"
        )
        if self.selection_provenance != expected:
            raise ValueError("selection provenance does not match its method")
        return self


class PredictionReportabilityGate(StrictModel):
    policy: Literal["complete-digest-valid-lineage-required"] = (
        "complete-digest-valid-lineage-required"
    )
    checkpoint_verified: Literal[True] = True
    partition_verified: Literal[True] = True
    m2_snapshot_verified: Literal[True] = True
    model_inference_completed: Literal[True] = True
    complete_window_count: int = Field(gt=0)
    incomplete_window_count: Literal[0] = 0
    invariant_violation_count: Literal[0] = 0
    reportable: Literal[True] = True


class PredictionBundleCore(StrictModel):
    code_version: str
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    investigation_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    inference_method: Literal["classification-head-softmax-argmax"] = (
        "classification-head-softmax-argmax"
    )
    inference_device: Literal["cpu"] = "cpu"
    prediction_count: int = Field(gt=0)
    source_event_count: int = Field(gt=0)
    source_record_count: int = Field(gt=0)
    sources: PredictionSourceReferences
    selection: PredictionSelection
    predictions_sha256: str = Field(pattern=HEX_256_PATTERN)
    lineage_sha256: str = Field(pattern=HEX_256_PATTERN)
    reportability_gate: PredictionReportabilityGate

    @model_validator(mode="after")
    def _prediction_count_matches(self) -> PredictionBundleCore:
        if self.prediction_count != self.selection.row_count:
            raise ValueError("prediction count does not match the selection")
        return self


class PredictionBundleManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m7_prediction_bundle_manifest"] = (
        "m7_prediction_bundle_manifest"
    )
    bundle_id: str
    core: PredictionBundleCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    integrity_assurance: Literal["content-addressed-unanchored"] = (
        "content-addressed-unanchored"
    )


class ExplanationSourceReferences(StrictModel):
    prediction_bundle_id: str
    prediction_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    predictions_sha256: str = Field(pattern=HEX_256_PATTERN)
    lineage_sha256: str = Field(pattern=HEX_256_PATTERN)
    campaign_id: str
    round_number: int = Field(gt=0)
    global_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    partition_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)


class ExplanationReportabilityGate(StrictModel):
    policy: Literal["verified-prediction-and-complete-explanation-required"] = (
        "verified-prediction-and-complete-explanation-required"
    )
    prediction_bundle_verified: Literal[True] = True
    training_only_baseline: Literal[True] = True
    training_only_prototypes: Literal[True] = True
    integrated_gradients_complete: Literal[True] = True
    prototype_distances_complete: Literal[True] = True
    row_embeddings_preserved: Literal[False] = False
    complete_prediction_count: int = Field(gt=0)
    incomplete_prediction_count: Literal[0] = 0
    invariant_violation_count: Literal[0] = 0
    reportable: Literal[True] = True


class ExplanationBundleCore(StrictModel):
    code_version: str
    implementation_sha256: dict[str, str]
    explanation_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    source: ExplanationSourceReferences
    prediction_count: int = Field(gt=0)
    feature_count: int = Field(gt=0)
    class_count: int = Field(gt=1)
    integrated_gradients_sha256: str = Field(pattern=HEX_256_PATTERN)
    prototype_reference_sha256: str = Field(pattern=HEX_256_PATTERN)
    prototype_distances_sha256: str = Field(pattern=HEX_256_PATTERN)
    maximum_absolute_completeness_error_scaled_1e12: int = Field(ge=0)
    reportability_gate: ExplanationReportabilityGate

    @field_validator("implementation_sha256")
    @classmethod
    def _implementation_digests(cls, value: dict[str, str]) -> dict[str, str]:
        required = {"explanation_bundle", "prediction_bundle", "prototype_core"}
        if set(value) != required:
            raise ValueError("explanation implementation digest set is incomplete")
        if any(
            re.fullmatch(HEX_256_PATTERN, digest) is None
            for digest in value.values()
        ):
            raise ValueError("invalid explanation implementation digest")
        return value


class ExplanationBundleManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m7_explanation_bundle_manifest"] = (
        "m7_explanation_bundle_manifest"
    )
    explanation_bundle_id: str
    core: ExplanationBundleCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    interpretation_boundary: Literal[
        "model-derived-interpretation-not-primary-zeek-evidence"
    ] = "model-derived-interpretation-not-primary-zeek-evidence"
    integrity_assurance: Literal["content-addressed-unanchored"] = (
        "content-addressed-unanchored"
    )

class AttackTacticCandidate(StrictModel):
    tactic_id: str = Field(pattern=r"^TA\d{4}$")
    tactic_name: str


class AttackMappingSourceReferences(StrictModel):
    explanation_bundle_id: str
    explanation_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    integrated_gradients_sha256: str = Field(pattern=HEX_256_PATTERN)
    prototype_reference_sha256: str = Field(pattern=HEX_256_PATTERN)
    prototype_distances_sha256: str = Field(pattern=HEX_256_PATTERN)
    prediction_bundle_id: str
    prediction_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)
    predictions_sha256: str = Field(pattern=HEX_256_PATTERN)
    lineage_sha256: str = Field(pattern=HEX_256_PATTERN)
    campaign_id: str
    round_number: int = Field(gt=0)
    global_model_sha256: str = Field(pattern=HEX_256_PATTERN)
    partition_manifest_sha256: str = Field(pattern=HEX_256_PATTERN)


class AttackMappingReportabilityGate(StrictModel):
    policy: Literal[
        "verified-explanation-and-complete-versioned-mapping-required"
    ] = "verified-explanation-and-complete-versioned-mapping-required"
    explanation_bundle_verified: Literal[True] = True
    prediction_bundle_transitively_verified: Literal[True] = True
    model_taxonomy_verified: Literal[True] = True
    complete_mapping_coverage: Literal[True] = True
    reference_labels_used_for_mapping: Literal[False] = False
    dataset_attack_labels_used_for_mapping: Literal[False] = False
    integrated_gradients_used_for_rule_selection: Literal[False] = False
    prototype_distances_used_for_rule_selection: Literal[False] = False
    technique_claims_enabled: Literal[False] = False
    complete_prediction_count: int = Field(gt=0)
    unmapped_prediction_count: Literal[0] = 0
    unresolved_prediction_count: int = Field(ge=0)
    invariant_violation_count: Literal[0] = 0
    reportable: Literal[True] = True


class AttackMappingBundleCore(StrictModel):
    code_version: str
    implementation_sha256: str = Field(pattern=HEX_256_PATTERN)
    attack_config_sha256: str = Field(pattern=HEX_256_PATTERN)
    framework: Literal["MITRE ATT&CK"] = "MITRE ATT&CK"
    domain: Literal["enterprise"] = "enterprise"
    attack_version: Literal["19.2"] = "19.2"
    mapping_policy: Literal[
        "predicted-class-only-versioned-tactic-hypothesis"
    ] = "predicted-class-only-versioned-tactic-hypothesis"
    model_class_names: list[str]
    source: AttackMappingSourceReferences
    mapping_count: int = Field(gt=0)
    candidate_tactic_mapping_count: int = Field(ge=0)
    not_applicable_mapping_count: int = Field(ge=0)
    unresolved_mapping_count: int = Field(ge=0)
    attack_mappings_sha256: str = Field(pattern=HEX_256_PATTERN)
    reportability_gate: AttackMappingReportabilityGate

    @field_validator("model_class_names")
    @classmethod
    def _model_classes_are_ordered_unique(
        cls,
        value: list[str],
    ) -> list[str]:
        if not value:
            raise ValueError("ATT&CK mapping requires model classes")
        if value != sorted(set(value)):
            raise ValueError(
                "ATT&CK model classes must be unique and ordered"
            )
        return value

    @model_validator(mode="after")
    def _mapping_counts_match(self) -> AttackMappingBundleCore:
        mapped = (
            self.candidate_tactic_mapping_count
            + self.not_applicable_mapping_count
            + self.unresolved_mapping_count
        )
        if mapped != self.mapping_count:
            raise ValueError("ATT&CK mapping counts do not sum correctly")
        if (
            self.reportability_gate.complete_prediction_count
            != self.mapping_count
        ):
            raise ValueError(
                "ATT&CK mapping count does not match reportability gate"
            )
        if (
            self.reportability_gate.unresolved_prediction_count
            != self.unresolved_mapping_count
        ):
            raise ValueError(
                "ATT&CK unresolved count does not match reportability gate"
            )
        return self


class AttackMappingBundleManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["m7_attack_mapping_bundle_manifest"] = (
        "m7_attack_mapping_bundle_manifest"
    )
    attack_mapping_bundle_id: str
    core: AttackMappingBundleCore
    canonical_core_sha256: str = Field(pattern=HEX_256_PATTERN)
    interpretation_boundary: Literal[
        "attack-hypothesis-derived-from-model-not-primary-zeek-evidence"
    ] = "attack-hypothesis-derived-from-model-not-primary-zeek-evidence"
    integrity_assurance: Literal["content-addressed-unanchored"] = (
        "content-addressed-unanchored"
    )