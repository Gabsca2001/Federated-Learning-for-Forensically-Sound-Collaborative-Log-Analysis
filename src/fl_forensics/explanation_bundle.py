"""M7 Integrated Gradients and prototype-distance explanation bundles."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file
from .config import load_yaml
from .investigation_models import (
    ExplanationBundleCore,
    ExplanationBundleManifest,
    ExplanationReportabilityGate,
    ExplanationSourceReferences,
    PredictionBundleManifest,
)
from .prediction_bundle import (
    PredictionBundleError,
    _inference_rows,
    _model_from_export,
    _validated_inputs,
    verify_prediction_bundle,
)
from .preprocessing import derived_json_bytes
from .prototypes import (
    PrototypeConfigurationError,
    aggregate_class_prototypes,
    extract_class_prototypes,
)
from .storage import load_json, write_once


class ExplanationBundleError(RuntimeError):
    """Raised when an explanation cannot be bound to verified source evidence."""


def _validate_explanation_config(config: dict[str, Any]) -> dict[str, Any]:
    if config.get("schema_version") != "1.0":
        raise ExplanationBundleError("unexpected M7 explanation schema")
    explanations = config.get("investigation_explanations", {})
    integrated = explanations.get("integrated_gradients", {})
    if integrated.get("target") != "predicted-class-logit":
        raise ExplanationBundleError("Integrated Gradients must explain the predicted logit")
    if integrated.get("baseline") != "training-feature-coordinate-median":
        raise ExplanationBundleError("unexpected Integrated Gradients baseline")
    if integrated.get("integration_rule") != "trapezoidal":
        raise ExplanationBundleError("unexpected Integrated Gradients integration rule")
    initial_steps = int(integrated.get("initial_steps", 0))
    maximum_steps = int(integrated.get("maximum_steps", 0))
    tolerance = float(integrated.get("absolute_completeness_tolerance", -1.0))
    step_ratio = maximum_steps // initial_steps if initial_steps > 0 else 0
    if (
        initial_steps <= 0
        or maximum_steps < initial_steps
        or maximum_steps % initial_steps != 0
        or step_ratio & (step_ratio - 1)
    ):
        raise ExplanationBundleError("Integrated Gradients step schedule is invalid")
    if not math.isfinite(tolerance) or tolerance <= 0:
        raise ExplanationBundleError("Integrated Gradients tolerance must be positive")

    prototypes = explanations.get("prototypes", {})
    expected = {
        "source_split": "train",
        "embedding": "verified-m5-global-encoder",
        "aggregation": "coordinate_median",
        "distance": "euclidean",
        "preserve_row_embeddings": False,
    }
    if any(prototypes.get(key) != value for key, value in expected.items()):
        raise ExplanationBundleError("prototype explanation contract differs from configuration")
    if (
        int(prototypes.get("minimum_local_support", 0)) <= 0
        or int(prototypes.get("class_quorum", 0)) <= 0
        or int(prototypes.get("batch_size", 0)) <= 0
    ):
        raise ExplanationBundleError("prototype support, quorum, and batch size must be positive")
    interpretation = explanations.get("interpretation", {})
    if (
        interpretation.get("require_verified_prediction_bundle") is not True
        or interpretation.get("primary_evidence") is not False
    ):
        raise ExplanationBundleError("M7 explanations must remain verified interpretations")
    return explanations


def _safe_file(root: Path, relative_path: Any, expected_sha256: Any, label: str) -> Path:
    root_resolved = root.resolve()
    candidate = (root / str(relative_path)).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ExplanationBundleError(f"{label} escapes the partition workspace") from exc
    if not candidate.is_file():
        raise ExplanationBundleError(f"missing {label}")
    if sha256_file(candidate) != str(expected_sha256):
        raise ExplanationBundleError(f"{label} digest mismatch")
    return candidate


def _selection_arguments(
    manifest: PredictionBundleManifest,
) -> tuple[list[str] | None, int | None]:
    selection = manifest.core.selection
    if selection.method == "explicit-window-ids":
        return selection.window_ids, None
    return None, selection.row_count


def _validated_explanation_inputs(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    prediction_config_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    verification = verify_prediction_bundle(
        round_workspace=round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
        workspace=prediction_workspace,
        config_path=prediction_config_path,
    )
    if verification.get("status") != "verified":
        raise ExplanationBundleError(
            f"source Prediction Bundle verification failed: {verification.get('errors', [])}"
        )
    prediction_manifest_path = prediction_workspace / "manifest.json"
    prediction_manifest = PredictionBundleManifest.model_validate(
        load_json(prediction_manifest_path)
    )
    window_ids, first = _selection_arguments(prediction_manifest)
    try:
        inputs = _validated_inputs(
            round_workspace=round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            dataset_workspace=dataset_workspace,
            config_path=prediction_config_path,
            split=prediction_manifest.core.selection.split,
            window_ids=window_ids,
            first=first,
        )
    except PredictionBundleError as exc:
        raise ExplanationBundleError(str(exc)) from exc
    explanation_config_value, explanation_config_digest = load_yaml(config_path)
    explanation_config = _validate_explanation_config(explanation_config_value)
    public_partition_path = round_workspace / "public" / "partition-manifest.json"
    if sha256_file(public_partition_path) != inputs["sources"].partition_manifest_sha256:
        raise ExplanationBundleError("signed partition manifest digest changed")
    partition_manifest = load_json(public_partition_path)
    predictions_path = prediction_workspace / "predictions.json"
    lineage_path = prediction_workspace / "lineage.json"
    if sha256_file(predictions_path) != prediction_manifest.core.predictions_sha256:
        raise ExplanationBundleError("source prediction digest differs from its manifest")
    if sha256_file(lineage_path) != prediction_manifest.core.lineage_sha256:
        raise ExplanationBundleError("source lineage digest differs from its manifest")
    predictions = load_json(predictions_path)
    recomputed_rows = _inference_rows(inputs)
    if predictions.get("predictions") != recomputed_rows:
        raise ExplanationBundleError("source predictions differ from recomputed inference")
    if int(predictions.get("prediction_count", -1)) != len(recomputed_rows):
        raise ExplanationBundleError("source prediction count is inconsistent")
    return {
        **inputs,
        "explanation_config": explanation_config,
        "explanation_config_digest": explanation_config_digest,
        "partition_workspace": partition_workspace,
        "partition_manifest": partition_manifest,
        "prediction_manifest": prediction_manifest,
        "prediction_manifest_sha256": sha256_file(prediction_manifest_path),
        "prediction_rows": recomputed_rows,
    }


def _training_prototype_reference(
    inputs: dict[str, Any], *, model: Any
) -> tuple[dict[str, Any], Any]:
    np = inputs["np"]
    torch = inputs["torch"]
    partition_workspace: Path = inputs["partition_workspace"]
    partition_manifest = inputs["partition_manifest"]
    model_export = inputs["model_export"]
    class_names = [str(item) for item in model_export["class_names"]]
    feature_names = [str(item) for item in partition_manifest["feature_names"]]
    settings = inputs["explanation_config"]["prototypes"]
    submissions: list[dict[str, Any]] = []
    commitments: list[dict[str, Any]] = []
    training_features: list[list[float]] = []
    client_ids: list[str] = []
    for client in partition_manifest.get("clients", []):
        client_id = str(client.get("client_id", ""))
        if not client_id or client_id in client_ids:
            raise ExplanationBundleError("partition clients are empty or duplicate")
        client_ids.append(client_id)
        dataset_path = _safe_file(
            partition_workspace,
            client.get("dataset_path"),
            client.get("dataset_sha256"),
            f"{client_id} training snapshot",
        )
        dataset = load_json(dataset_path)
        if [str(item) for item in dataset.get("feature_names", [])] != feature_names:
            raise ExplanationBundleError(f"{client_id} feature schema mismatch")
        if [str(item) for item in dataset.get("class_names", [])] != class_names:
            raise ExplanationBundleError(f"{client_id} class schema mismatch")
        rows = list(dataset.get("rows", {}).get("train", []))
        if not rows or len(rows) != int(client.get("train_row_count", -1)):
            raise ExplanationBundleError(f"{client_id} training row count mismatch")
        training_features.extend(row["features"] for row in rows)
        extraction = extract_class_prototypes(
            model=model,
            rows=rows,
            class_names=class_names,
            minimum_support=int(settings["minimum_local_support"]),
            batch_size=int(settings["batch_size"]),
            torch=torch,
        )
        submission = {"client_id": client_id, **extraction}
        submissions.append(submission)
        commitments.append(
            {
                "client_id": client_id,
                "training_snapshot_sha256": str(client["dataset_sha256"]),
                "training_row_count": len(rows),
                "class_supports": extraction["class_supports"],
                "eligible_class_count": extraction["eligible_class_count"],
                "local_prototypes_sha256": sha256_bytes(
                    derived_json_bytes(submission)
                ),
            }
        )
    if not client_ids:
        raise ExplanationBundleError("partition contains no training clients")
    matrix = np.asarray(training_features, dtype=np.float64)
    if (
        matrix.ndim != 2
        or matrix.shape[1] != len(feature_names)
        or not bool(np.isfinite(matrix).all())
    ):
        raise ExplanationBundleError("training baseline matrix is invalid")
    baseline = np.median(matrix, axis=0)
    aggregate = aggregate_class_prototypes(
        submissions,
        class_names=class_names,
        minimum_local_support=int(settings["minimum_local_support"]),
        class_quorum=int(settings["class_quorum"]),
        strategy="coordinate_median",
    )
    for class_name in class_names:
        record = aggregate["classes"].get(class_name, {})
        if record.get("status") != "aggregated" or "values" not in record:
            raise ExplanationBundleError(
                f"prototype quorum is incomplete for class: {class_name}"
            )
    baseline_record = {
        "method": "training-feature-coordinate-median",
        "source_split": "train",
        "row_count": int(matrix.shape[0]),
        "feature_names": feature_names,
        "values": [round(float(value), 12) for value in baseline],
    }
    baseline_record["baseline_sha256"] = sha256_bytes(
        derived_json_bytes(baseline_record)
    )
    reference = {
        "schema_version": "1.0",
        "artifact_type": "m7_training_prototype_reference",
        "embedding": "verified-m5-global-encoder",
        "source_split": "train",
        "aggregation": "coordinate_median",
        "distance": "euclidean",
        "minimum_local_support": int(settings["minimum_local_support"]),
        "class_quorum": int(settings["class_quorum"]),
        "training_client_count": len(client_ids),
        "training_row_count": int(matrix.shape[0]),
        "row_embeddings_preserved": False,
        "baseline": baseline_record,
        "local_prototype_commitments": commitments,
        "global_prototypes": aggregate,
    }
    return reference, baseline.astype(np.float32, copy=False)


def _integrated_gradients(
    *,
    model: Any,
    features: Any,
    baseline: Any,
    target_index: int,
    settings: dict[str, Any],
    np: Any,
    torch: Any,
) -> dict[str, Any]:
    feature_array = np.asarray(features, dtype=np.float32)
    baseline_array = np.asarray(baseline, dtype=np.float32)
    if (
        feature_array.ndim != 1
        or baseline_array.shape != feature_array.shape
        or not bool(np.isfinite(feature_array).all())
        or not bool(np.isfinite(baseline_array).all())
    ):
        raise ExplanationBundleError("Integrated Gradients input or baseline is invalid")
    initial_steps = int(settings["initial_steps"])
    maximum_steps = int(settings["maximum_steps"])
    tolerance = float(settings["absolute_completeness_tolerance"])
    model.to("cpu")
    model.eval()
    step_count = initial_steps
    while True:
        alpha = torch.linspace(0.0, 1.0, step_count + 1, dtype=torch.float32)
        start = torch.from_numpy(baseline_array)
        delta = torch.from_numpy(feature_array - baseline_array)
        path = start.unsqueeze(0) + alpha.unsqueeze(1) * delta.unsqueeze(0)
        path.requires_grad_(True)
        scores = model(path)[:, target_index]
        gradients = torch.autograd.grad(scores.sum(), path)[0]
        integrated_gradient = (
            gradients[0]
            + gradients[-1]
            + 2.0 * gradients[1:-1].sum(dim=0)
        ) / (2.0 * step_count)
        attributions = delta * integrated_gradient
        target_baseline = float(scores[0].detach().cpu().item())
        target_input = float(scores[-1].detach().cpu().item())
        score_delta = target_input - target_baseline
        attribution_sum = float(attributions.detach().cpu().sum().item())
        completeness_delta = score_delta - attribution_sum
        absolute_error = abs(completeness_delta)
        if not all(
            math.isfinite(value)
            for value in (
                target_baseline,
                target_input,
                score_delta,
                attribution_sum,
                completeness_delta,
                absolute_error,
            )
        ):
            raise ExplanationBundleError("Integrated Gradients produced non-finite values")
        if absolute_error <= tolerance:
            return {
                "attributions": attributions.detach().cpu().numpy().astype(np.float64),
                "steps": step_count,
                "target_baseline_logit": target_baseline,
                "target_input_logit": target_input,
                "target_logit_delta": score_delta,
                "attribution_sum": attribution_sum,
                "completeness_delta": completeness_delta,
                "absolute_completeness_error": absolute_error,
            }
        if step_count >= maximum_steps:
            raise ExplanationBundleError(
                "Integrated Gradients completeness tolerance was not reached"
            )
        step_count = min(step_count * 2, maximum_steps)


def _feature_attributions(
    *, feature_names: list[str], features: Any, baseline: Any, attributions: Any
) -> list[dict[str, Any]]:
    values = [float(item) for item in attributions]
    order = sorted(range(len(values)), key=lambda index: (-abs(values[index]), index))
    ranks = {feature_index: rank + 1 for rank, feature_index in enumerate(order)}
    rows: list[dict[str, Any]] = []
    for index, name in enumerate(feature_names):
        attribution = values[index]
        direction = (
            "supports-target"
            if attribution > 0
            else "opposes-target"
            if attribution < 0
            else "neutral"
        )
        rows.append(
            {
                "feature_index": index,
                "feature_name": name,
                "input_value_scaled": round(float(features[index]), 12),
                "baseline_value_scaled": round(float(baseline[index]), 12),
                "attribution": round(attribution, 12),
                "absolute_rank": ranks[index],
                "direction_for_target_logit": direction,
            }
        )
    return rows


def _build_explanation_artifacts(inputs: dict[str, Any]) -> dict[str, bytes]:
    np = inputs["np"]
    torch = inputs["torch"]
    model = _model_from_export(inputs["model_export"], np=np, torch=torch)
    prototype_reference, baseline = _training_prototype_reference(inputs, model=model)
    prototype_reference_bytes = derived_json_bytes(prototype_reference)
    prototype_reference_sha256 = sha256_bytes(prototype_reference_bytes)
    class_names = [str(item) for item in inputs["model_export"]["class_names"]]
    feature_names = [str(item) for item in inputs["partition_manifest"]["feature_names"]]
    integrated_settings = inputs["explanation_config"]["integrated_gradients"]
    prediction_rows = inputs["prediction_rows"]
    if len(prediction_rows) != len(inputs["selected"]):
        raise ExplanationBundleError("prediction and selected-row counts differ")

    model.to("cpu")
    model.eval()
    feature_matrix = np.asarray(
        [item["m3_row"]["features"] for item in inputs["selected"]],
        dtype=np.float32,
    )
    with torch.no_grad():
        embeddings = model.encoder(torch.from_numpy(feature_matrix)).cpu().numpy()
    global_classes = prototype_reference["global_prototypes"]["classes"]
    prototype_matrix = np.asarray(
        [global_classes[name]["values"] for name in class_names], dtype=np.float64
    )

    integrated_rows: list[dict[str, Any]] = []
    distance_rows: list[dict[str, Any]] = []
    maximum_error = 0.0
    for item, prediction, embedding in zip(
        inputs["selected"], prediction_rows, embeddings, strict=True
    ):
        if prediction["inference_input_sha256"] != item["inference_input_sha256"]:
            raise ExplanationBundleError("prediction/input digest binding mismatch")
        target_index = int(prediction["predicted_class_index"])
        if class_names[target_index] != prediction["predicted_class"]:
            raise ExplanationBundleError("prediction class index/name mismatch")
        integrated = _integrated_gradients(
            model=model,
            features=item["m3_row"]["features"],
            baseline=baseline,
            target_index=target_index,
            settings=integrated_settings,
            np=np,
            torch=torch,
        )
        maximum_error = max(
            maximum_error, float(integrated["absolute_completeness_error"])
        )
        explanation_core = {
            "prediction_id": prediction["prediction_id"],
            "prediction_bundle_id": inputs["prediction_manifest"].bundle_id,
            "inference_input_sha256": prediction["inference_input_sha256"],
            "global_model_sha256": inputs["sources"].global_model_sha256,
            "target": "predicted-class-logit",
            "target_class": prediction["predicted_class"],
            "baseline_sha256": prototype_reference["baseline"]["baseline_sha256"],
            "prototype_reference_sha256": prototype_reference_sha256,
        }
        explanation_id = (
            f"m7-explanation-{sha256_bytes(canonical_json_bytes(explanation_core))[:24]}"
        )
        integrated_rows.append(
            {
                "explanation_id": explanation_id,
                "prediction_id": prediction["prediction_id"],
                "window_id": prediction["window_id"],
                "target_class": prediction["predicted_class"],
                "target_class_index": target_index,
                "inference_input_sha256": prediction["inference_input_sha256"],
                "baseline_sha256": prototype_reference["baseline"]["baseline_sha256"],
                "integration_rule": "trapezoidal",
                "steps": int(integrated["steps"]),
                "target_baseline_logit": round(
                    float(integrated["target_baseline_logit"]), 12
                ),
                "target_input_logit": round(float(integrated["target_input_logit"]), 12),
                "target_logit_delta": round(float(integrated["target_logit_delta"]), 12),
                "attribution_sum": round(float(integrated["attribution_sum"]), 12),
                "completeness_delta": round(
                    float(integrated["completeness_delta"]), 12
                ),
                "absolute_completeness_error": round(
                    float(integrated["absolute_completeness_error"]), 12
                ),
                "completeness_tolerance": float(
                    integrated_settings["absolute_completeness_tolerance"]
                ),
                "feature_attributions": _feature_attributions(
                    feature_names=feature_names,
                    features=item["m3_row"]["features"],
                    baseline=baseline,
                    attributions=integrated["attributions"],
                ),
                "interpretation": "model-behaviour-attribution-not-causal-evidence",
            }
        )

        vector = np.asarray(embedding, dtype=np.float64)
        distances = np.linalg.norm(prototype_matrix - vector, axis=1)
        if not bool(np.isfinite(distances).all()):
            raise ExplanationBundleError("prototype distance computation is non-finite")
        order = sorted(range(len(class_names)), key=lambda index: (distances[index], index))
        nearest = order[0]
        second = order[1]
        ranks = {class_index: rank + 1 for rank, class_index in enumerate(order)}
        distance_rows.append(
            {
                "explanation_id": explanation_id,
                "prediction_id": prediction["prediction_id"],
                "window_id": prediction["window_id"],
                "inference_input_sha256": prediction["inference_input_sha256"],
                "predicted_class": prediction["predicted_class"],
                "nearest_prototype_class": class_names[nearest],
                "nearest_prototype_distance": round(float(distances[nearest]), 12),
                "second_nearest_prototype_class": class_names[second],
                "second_nearest_prototype_distance": round(
                    float(distances[second]), 12
                ),
                "nearest_prototype_margin": round(
                    float(distances[second] - distances[nearest]), 12
                ),
                "predicted_class_prototype_distance": round(
                    float(distances[target_index]), 12
                ),
                "predicted_class_prototype_rank": ranks[target_index],
                "prediction_matches_nearest_prototype": target_index == nearest,
                "class_distances": [
                    {
                        "class_index": index,
                        "class_name": class_name,
                        "distance": round(float(distances[index]), 12),
                        "distance_rank": ranks[index],
                    }
                    for index, class_name in enumerate(class_names)
                ],
                "row_embedding_preserved": False,
                "interpretation": "embedding-similarity-not-primary-evidence",
            }
        )

    integrated_artifact = {
        "schema_version": "1.0",
        "artifact_type": "m7_integrated_gradients_explanations",
        "prediction_bundle_id": inputs["prediction_manifest"].bundle_id,
        "target": "predicted-class-logit",
        "baseline": "training-feature-coordinate-median",
        "integration_rule": "trapezoidal",
        "feature_space": "m3-training-scaled-input-features",
        "feature_names": feature_names,
        "explanation_count": len(integrated_rows),
        "causal_claim": False,
        "explanations": integrated_rows,
    }
    distance_artifact = {
        "schema_version": "1.0",
        "artifact_type": "m7_prototype_distance_explanations",
        "prediction_bundle_id": inputs["prediction_manifest"].bundle_id,
        "prototype_reference_sha256": prototype_reference_sha256,
        "embedding": "verified-m5-global-encoder",
        "distance": "euclidean",
        "class_names": class_names,
        "explanation_count": len(distance_rows),
        "row_embeddings_preserved": False,
        "causal_claim": False,
        "explanations": distance_rows,
    }
    integrated_bytes = derived_json_bytes(integrated_artifact)
    distance_bytes = derived_json_bytes(distance_artifact)
    prediction_manifest: PredictionBundleManifest = inputs["prediction_manifest"]
    source = ExplanationSourceReferences(
        prediction_bundle_id=prediction_manifest.bundle_id,
        prediction_manifest_sha256=inputs["prediction_manifest_sha256"],
        predictions_sha256=prediction_manifest.core.predictions_sha256,
        lineage_sha256=prediction_manifest.core.lineage_sha256,
        campaign_id=prediction_manifest.core.sources.campaign_id,
        round_number=prediction_manifest.core.sources.round_number,
        global_model_sha256=prediction_manifest.core.sources.global_model_sha256,
        partition_manifest_sha256=(
            prediction_manifest.core.sources.partition_manifest_sha256
        ),
    )
    core = ExplanationBundleCore(
        code_version=__version__,
        implementation_sha256={
            "explanation_bundle": sha256_file(Path(__file__)),
            "prediction_bundle": sha256_file(Path(__file__).with_name("prediction_bundle.py")),
            "prototype_core": sha256_file(Path(__file__).with_name("prototypes.py")),
        },
        explanation_config_sha256=inputs["explanation_config_digest"],
        source=source,
        prediction_count=len(prediction_rows),
        feature_count=len(feature_names),
        class_count=len(class_names),
        integrated_gradients_sha256=sha256_bytes(integrated_bytes),
        prototype_reference_sha256=prototype_reference_sha256,
        prototype_distances_sha256=sha256_bytes(distance_bytes),
        maximum_absolute_completeness_error_scaled_1e12=round(
            maximum_error * 1_000_000_000_000
        ),
        reportability_gate=ExplanationReportabilityGate(
            complete_prediction_count=len(prediction_rows)
        ),
    )
    core_value = core.model_dump(mode="json")
    core_digest = sha256_bytes(canonical_json_bytes(core_value))
    manifest = ExplanationBundleManifest(
        explanation_bundle_id=f"m7-explanation-bundle-{core_digest[:24]}",
        core=core,
        canonical_core_sha256=core_digest,
    )
    return {
        "integrated-gradients.json": integrated_bytes,
        "prototype-reference.json": prototype_reference_bytes,
        "prototype-distances.json": distance_bytes,
        "manifest.json": derived_json_bytes(manifest.model_dump(mode="json")),
    }


def create_explanation_bundle(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    output: Path,
    prediction_config_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Explain every prediction only after its complete source bundle verifies."""

    inputs = _validated_explanation_inputs(
        round_workspace=round_workspace,
        trust_workspace=trust_workspace,
        partition_workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
        prediction_workspace=prediction_workspace,
        prediction_config_path=prediction_config_path,
        config_path=config_path,
    )
    artifacts = _build_explanation_artifacts(inputs)
    names = (
        "integrated-gradients.json",
        "prototype-reference.json",
        "prototype-distances.json",
        "manifest.json",
    )
    for name in names:
        write_once(output / name, artifacts[name])
    manifest = ExplanationBundleManifest.model_validate_json(artifacts["manifest.json"])
    return {
        "status": "explained_verified_source",
        "explanation_bundle_id": manifest.explanation_bundle_id,
        "prediction_bundle_id": manifest.core.source.prediction_bundle_id,
        "prediction_count": manifest.core.prediction_count,
        "feature_count": manifest.core.feature_count,
        "class_count": manifest.core.class_count,
        "maximum_absolute_completeness_error": (
            manifest.core.maximum_absolute_completeness_error_scaled_1e12
            / 1_000_000_000_000
        ),
        "source_prediction_verified": True,
        "reportable": True,
        "manifest_sha256": sha256_bytes(artifacts["manifest.json"]),
        "workspace": str(output),
    }


def verify_explanation_bundle(
    *,
    round_workspace: Path,
    trust_workspace: Path,
    partition_workspace: Path,
    dataset_workspace: Path,
    prediction_workspace: Path,
    workspace: Path,
    prediction_config_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    """Recompute IG, training prototypes, and all prototype distances."""

    errors: list[str] = []
    manifest: ExplanationBundleManifest | None = None
    source_recomputed = False
    try:
        manifest_path = workspace / "manifest.json"
        manifest = ExplanationBundleManifest.model_validate(load_json(manifest_path))
        expected_core_digest = sha256_bytes(
            canonical_json_bytes(manifest.core.model_dump(mode="json"))
        )
        if manifest.canonical_core_sha256 != expected_core_digest:
            raise ExplanationBundleError("explanation manifest core digest mismatch")
        inputs = _validated_explanation_inputs(
            round_workspace=round_workspace,
            trust_workspace=trust_workspace,
            partition_workspace=partition_workspace,
            dataset_workspace=dataset_workspace,
            prediction_workspace=prediction_workspace,
            prediction_config_path=prediction_config_path,
            config_path=config_path,
        )
        source_recomputed = True
        expected = _build_explanation_artifacts(inputs)
        expected_names = set(expected)
        for name in sorted(expected_names):
            path = workspace / name
            if not path.is_file():
                errors.append(f"missing explanation artifact: {name}")
            elif path.read_bytes() != expected[name]:
                errors.append(f"explanation artifact differs from recomputation: {name}")
        actual_names = {
            path.relative_to(workspace).as_posix()
            for path in workspace.rglob("*")
            if path.is_file()
        }
        unexpected = sorted(actual_names - expected_names)
        if unexpected:
            errors.append(f"unexpected explanation artifacts: {', '.join(unexpected)}")
    except (
        KeyError,
        OSError,
        PredictionBundleError,
        PrototypeConfigurationError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(str(exc))
    return {
        "status": "verified" if not errors else "failed",
        "explanation_bundle_id": (
            manifest.explanation_bundle_id if manifest is not None else None
        ),
        "prediction_bundle_id": (
            manifest.core.source.prediction_bundle_id if manifest is not None else None
        ),
        "prediction_count": manifest.core.prediction_count if manifest is not None else 0,
        "source_prediction_verified": source_recomputed,
        "verification_recomputed_integrated_gradients": source_recomputed,
        "verification_recomputed_training_prototypes": source_recomputed,
        "verification_recomputed_prototype_distances": source_recomputed,
        "reportable": not errors,
        "error_count": len(errors),
        "errors": errors,
        "manifest_sha256": (
            sha256_file(workspace / "manifest.json")
            if (workspace / "manifest.json").is_file()
            else None
        ),
        "workspace": str(workspace),
    }
