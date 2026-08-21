"""Pre-test selection lock for paper-faithful and hybrid PROTEAN endpoints."""

from __future__ import annotations

import math
import tempfile
from pathlib import Path
from typing import Any

from . import __version__, protean_reporting
from .canonical import sha256_file
from .dataset24 import DATASET_NAME
from .federated_training import SELECTION_METRIC
from .preprocessing import derived_json_bytes
from .protean_reporting import (
    _load_json,
    _validate_sweep,
    _validated_candidate,
    _validated_fedavg,
    verify_protean_validation_report,
)
from .storage import write_once

PRIMARY_ENDPOINT_ID = "paper_faithful_nearest_prototype"
SECONDARY_ENDPOINT_ID = "hybrid_operational_classification_head"
SECONDARY_SELECTION_POLICY = {
    "split": "validation",
    "classifier": "classification_head",
    "metric": SELECTION_METRIC,
    "mode": "maximize",
    "scope": "all_registered_lambda_candidates_and_rounds",
    "round_tie_breaker": "earliest_round",
    "candidate_tie_breaker": "smallest_prototype_alignment_weight",
    "registration_status": "selected_after_primary_validation_report_before_test",
}


def _same_float(left: Any, right: Any) -> bool:
    return math.isclose(
        float(left), float(right), rel_tol=0.0, abs_tol=1e-12
    )


def _candidate_by_manifest(
    candidates: list[dict[str, Any]], digest: str
) -> dict[str, Any]:
    matches = [
        candidate
        for candidate in candidates
        if candidate["source_digests"]["manifest_sha256"] == digest
    ]
    if len(matches) != 1:
        raise ValueError("selection does not identify exactly one candidate manifest")
    return matches[0]


def _round_metric(candidate: dict[str, Any], round_number: int) -> dict[str, Any]:
    matches = [
        item
        for item in candidate["metrics"]["rounds"]
        if int(item["round"]) == round_number
    ]
    if len(matches) != 1:
        raise ValueError(f"candidate contains no unique round {round_number}")
    return matches[0]


def _primary_endpoint(
    *, selection: dict[str, Any], candidates: list[dict[str, Any]]
) -> dict[str, Any]:
    selected = selection["selected"]
    candidate = _candidate_by_manifest(
        candidates, str(selected["candidate_manifest_sha256"])
    )
    candidate_selected = candidate["metrics"]["selected"]
    if not _same_float(selected["prototype_alignment_weight"], candidate["weight"]):
        raise ValueError("primary lambda does not match its candidate manifest")
    if int(selected["round"]) != int(candidate_selected["round"]):
        raise ValueError("primary round does not match candidate selection")
    if not _same_float(
        selected["validation_macro_f1"], candidate["selected_prototype_f1"]
    ):
        raise ValueError("primary validation metric does not match candidate selection")
    if selected["model_sha256"] != candidate_selected["model_sha256"]:
        raise ValueError("primary model digest does not match candidate selection")
    if selected["global_prototypes_sha256"] != candidate_selected[
        "global_prototypes_sha256"
    ]:
        raise ValueError("primary prototype digest does not match candidate selection")
    metric = _round_metric(candidate, int(selected["round"]))
    if metric["global_model_sha256"] != selected["model_sha256"]:
        raise ValueError("primary model digest does not match round metrics")
    if metric["global_prototypes_sha256"] != selected["global_prototypes_sha256"]:
        raise ValueError("primary prototype digest does not match round metrics")
    return {
        "endpoint_id": PRIMARY_ENDPOINT_ID,
        "role": "confirmatory_primary",
        "paper_faithful_inference": True,
        "classifier": "nearest_global_prototype",
        "prototype_alignment_weight": candidate["weight"],
        "round": int(metric["round"]),
        "validation_metric": {
            "name": SELECTION_METRIC,
            "value": float(selected["validation_macro_f1"]),
        },
        "candidate_manifest_sha256": candidate["source_digests"][
            "manifest_sha256"
        ],
        "candidate_metrics_sha256": candidate["source_digests"]["metrics_sha256"],
        "model_sha256": str(metric["global_model_sha256"]),
        "global_prototypes_sha256": str(metric["global_prototypes_sha256"]),
        "selection_policy": selection["policy"],
        "interpretation": (
            "This endpoint preserves the predeclared nearest-global-prototype selector "
            "and is the only endpoint used for paper-faithful PROTEAN claims."
        ),
    }


def _secondary_endpoint(
    *, selection: dict[str, Any], candidates: list[dict[str, Any]]
) -> dict[str, Any]:
    ranked = [
        (candidate, metric)
        for candidate in candidates
        for metric in candidate["metrics"]["rounds"]
    ]
    candidate, metric = max(
        ranked,
        key=lambda pair: (
            float(pair[1]["validation"]["classification_head"][SELECTION_METRIC]),
            -float(pair[0]["weight"]),
            -int(pair[1]["round"]),
        ),
    )
    diagnostic = selection["head_diagnostic"]
    value = float(metric["validation"]["classification_head"][SELECTION_METRIC])
    if not _same_float(diagnostic["prototype_alignment_weight"], candidate["weight"]):
        raise ValueError("head diagnostic lambda does not match the validation maximum")
    if int(diagnostic["round"]) != int(metric["round"]):
        raise ValueError("head diagnostic round does not match the validation maximum")
    if not _same_float(diagnostic["validation_macro_f1"], value):
        raise ValueError("head diagnostic metric does not match the validation maximum")
    return {
        "endpoint_id": SECONDARY_ENDPOINT_ID,
        "role": "secondary_operational_adaptation",
        "paper_faithful_inference": False,
        "classifier": "classification_head",
        "prototype_role": "explainability_and_agreement_evidence_only",
        "prototype_alignment_weight": candidate["weight"],
        "round": int(metric["round"]),
        "validation_metric": {"name": SELECTION_METRIC, "value": value},
        "candidate_manifest_sha256": candidate["source_digests"][
            "manifest_sha256"
        ],
        "candidate_metrics_sha256": candidate["source_digests"]["metrics_sha256"],
        "model_sha256": str(metric["global_model_sha256"]),
        "global_prototypes_sha256": str(metric["global_prototypes_sha256"]),
        "selection_policy": SECONDARY_SELECTION_POLICY,
        "interpretation": (
            "This endpoint was selected transparently on validation after the primary "
            "report and before any PROTEAN test access. It is not evidence that the "
            "paper-faithful nearest-prototype rule outperforms FedAvg."
        ),
    }


def _lock_payload(
    *,
    selection: dict[str, Any],
    summary: dict[str, Any],
    candidates: list[dict[str, Any]],
    baseline: dict[str, Any],
    config_digest: str,
    report_workspace: Path,
) -> dict[str, Any]:
    if selection.get("test_data_accessed") is not False:
        raise ValueError("selection crossed the PROTEAN test-data barrier")
    if summary.get("test_data_accessed") is not False:
        raise ValueError("report crossed the PROTEAN test-data barrier")
    if summary.get("selection_sha256") != sha256_file(
        report_workspace / "selection.json"
    ):
        raise ValueError("selection digest does not match report summary")
    if summary.get("protean_config_sha256") != config_digest:
        raise ValueError("report does not bind the supplied PROTEAN config")

    primary = _primary_endpoint(selection=selection, candidates=candidates)
    secondary = _secondary_endpoint(selection=selection, candidates=candidates)
    return {
        "schema_version": "1.0",
        "artifact_type": "protean_pretest_selection_lock",
        "dataset": DATASET_NAME,
        "partition_mode": "non-iid",
        "primary_endpoint": primary,
        "secondary_endpoint": secondary,
        "fedavg_validation_reference": {
            "metric": SELECTION_METRIC,
            "value": baseline["validation_f1"],
            "manifest_sha256": baseline["source_digests"]["manifest_sha256"],
            "comparison_sha256": baseline["source_digests"]["comparison_sha256"],
        },
        "validation_report": {
            "summary_sha256": sha256_file(report_workspace / "summary.json"),
            "selection_sha256": sha256_file(report_workspace / "selection.json"),
        },
        "test_gate": {
            "state": "locked",
            "allowed_only_after": "selection_lock_verification",
            "evaluation_count": "one_per_frozen_endpoint",
            "forbidden_after_unlock": [
                "hyperparameter_changes",
                "checkpoint_reselection",
                "threshold_tuning",
                "class_remapping",
            ],
            "primary_claim_source": PRIMARY_ENDPOINT_ID,
            "secondary_claim_boundary": (
                "operational adaptation selected on validation before test"
            ),
        },
        "explainability_contract": {
            "primary": [
                "nearest_prototype_label",
                "nearest_prototype_distance",
                "prototype_distance_margin",
            ],
            "secondary": [
                "head_prototype_label_agreement",
                "prototype_distance_margin",
                "class_aggregated_gradient_x_input",
            ],
            "feature_attribution_baseline": "zero_in_training_standardized_space",
            "privacy_boundary": "no_row_embeddings_or_row_attributions_persisted",
        },
        "test_data_accessed": False,
        "interpretation_constraints": [
            "The primary endpoint remains the predeclared paper-faithful selector.",
            "The secondary endpoint is a transparent operational adaptation.",
            "Both endpoints were frozen before any PROTEAN test or holdout access.",
            "Validation performance is not reported as final generalization evidence.",
        ],
    }


def create_protean_selection_lock(
    *,
    candidate_workspaces: list[Path],
    fedavg_workspace: Path,
    report_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Freeze both endpoints while preserving the PROTEAN test barrier."""

    report_verification = verify_protean_validation_report(
        candidate_workspaces=candidate_workspaces,
        fedavg_workspace=fedavg_workspace,
        workspace=report_workspace,
        config_path=config_path,
    )
    if report_verification["status"] != "verified":
        raise ValueError(
            f"PROTEAN report verification failed: {report_verification['errors']}"
        )
    candidates = sorted(
        [_validated_candidate(path) for path in candidate_workspaces],
        key=lambda item: item["weight"],
    )
    if not candidates:
        raise ValueError("selection lock requires registered PROTEAN candidates")
    _config, config_digest = _validate_sweep(candidates, config_path)
    baseline = _validated_fedavg(fedavg_workspace)
    if baseline["manifest"].get("partition_manifest_sha256") != candidates[0][
        "manifest"
    ].get("partition_manifest_sha256"):
        raise ValueError("FedAvg and PROTEAN partition snapshots do not match")
    selection = _load_json(
        report_workspace / "selection.json", "PROTEAN validation selection"
    )
    summary = _load_json(report_workspace / "summary.json", "PROTEAN report summary")
    lock = _lock_payload(
        selection=selection,
        summary=summary,
        candidates=candidates,
        baseline=baseline,
        config_digest=config_digest,
        report_workspace=report_workspace,
    )
    lock_bytes = derived_json_bytes(lock)
    write_once(output / "selection_lock.json", lock_bytes)
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "protean_selection_lock_manifest",
        "dataset": DATASET_NAME,
        "code_version": __version__,
        "selection_lock_sha256": sha256_file(output / "selection_lock.json"),
        "protean_config_sha256": config_digest,
        "partition_manifest_sha256": candidates[0]["manifest"][
            "partition_manifest_sha256"
        ],
        "dataset_manifest_sha256": candidates[0]["manifest"][
            "dataset_manifest_sha256"
        ],
        "validation_report_summary_sha256": sha256_file(
            report_workspace / "summary.json"
        ),
        "validation_report_selection_sha256": sha256_file(
            report_workspace / "selection.json"
        ),
        "candidate_sources": [item["source_digests"] for item in candidates],
        "fedavg_source": baseline["source_digests"],
        "implementation_files": {
            "protean_selection_lock.py": sha256_file(Path(__file__)),
            "protean_reporting.py": sha256_file(Path(protean_reporting.__file__)),
        },
        "test_data_accessed": False,
    }
    manifest_bytes = derived_json_bytes(manifest)
    write_once(output / "manifest.json", manifest_bytes)
    return {
        "status": "locked_pretest",
        "workspace": str(output),
        "primary_endpoint": PRIMARY_ENDPOINT_ID,
        "primary_validation_macro_f1": lock["primary_endpoint"][
            "validation_metric"
        ]["value"],
        "secondary_endpoint": SECONDARY_ENDPOINT_ID,
        "secondary_validation_macro_f1": lock["secondary_endpoint"][
            "validation_metric"
        ]["value"],
        "selection_lock_sha256": sha256_file(output / "selection_lock.json"),
        "manifest_sha256": sha256_file(output / "manifest.json"),
        "test_data_accessed": False,
    }


def _workspace_digests(workspace: Path) -> dict[str, str]:
    return {
        path.relative_to(workspace).as_posix(): sha256_file(path)
        for path in sorted(workspace.rglob("*"))
        if path.is_file()
    }


def verify_protean_selection_lock(
    *,
    candidate_workspaces: list[Path],
    fedavg_workspace: Path,
    report_workspace: Path,
    workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Recreate and compare the complete pre-test selection lock."""

    errors: list[str] = []
    lock: dict[str, Any] = {}
    try:
        if not workspace.is_dir():
            raise ValueError(f"missing PROTEAN selection-lock workspace: {workspace}")
        actual = _workspace_digests(workspace)
        with tempfile.TemporaryDirectory(prefix="fl-forensics-protean-lock-") as temp:
            expected_workspace = Path(temp) / "lock"
            create_protean_selection_lock(
                candidate_workspaces=candidate_workspaces,
                fedavg_workspace=fedavg_workspace,
                report_workspace=report_workspace,
                output=expected_workspace,
                config_path=config_path,
            )
            expected = _workspace_digests(expected_workspace)
        if actual.keys() != expected.keys():
            missing = sorted(expected.keys() - actual.keys())
            unexpected = sorted(actual.keys() - expected.keys())
            if missing:
                errors.append(f"missing selection-lock files: {missing}")
            if unexpected:
                errors.append(f"unexpected selection-lock files: {unexpected}")
        for relative in sorted(actual.keys() & expected.keys()):
            if actual[relative] != expected[relative]:
                errors.append(f"selection-lock digest mismatch: {relative}")
        lock = _load_json(
            workspace / "selection_lock.json", "PROTEAN selection lock"
        )
        manifest = _load_json(
            workspace / "manifest.json", "PROTEAN selection-lock manifest"
        )
        if manifest.get("selection_lock_sha256") != sha256_file(
            workspace / "selection_lock.json"
        ):
            errors.append("selection-lock manifest digest mismatch")
        if lock.get("test_data_accessed") is not False:
            errors.append("selection lock crossed the PROTEAN test-data barrier")
        if manifest.get("test_data_accessed") is not False:
            errors.append("selection-lock manifest crossed the test-data barrier")
    except (KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))

    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "error_count": len(errors),
        "errors": errors,
        "primary_endpoint": lock.get("primary_endpoint", {}).get("endpoint_id"),
        "secondary_endpoint": lock.get("secondary_endpoint", {}).get("endpoint_id"),
        "test_gate": lock.get("test_gate", {}).get("state"),
        "test_data_accessed": False,
        "selection_lock_sha256": (
            sha256_file(workspace / "selection_lock.json")
            if (workspace / "selection_lock.json").is_file()
            else None
        ),
    }
