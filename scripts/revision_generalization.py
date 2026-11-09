"""Train-only preprocessing screening and explicitly exploratory Data22 diagnosis.

Select the variant on Data24 validation before opening external feature rows.
Preserve numeric model states rather than executable pickle objects.
"""

from __future__ import annotations

import argparse
import json
import platform
from collections import Counter
from pathlib import Path
from statistics import mean, stdev
from typing import Any

import m2_preprocessing_experiment as screening
import numpy as np
from threadpoolctl import threadpool_limits

from fl_forensics.canonical import digest_object, sha256_file
from fl_forensics.config import load_yaml
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.external_generalization import _binary_metrics, _predict
from fl_forensics.federated_model import dependencies
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.robust_preprocessing import apply_feature_transform, fit_feature_transform
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.secure_round import _coordinator_public_key, _verify_signed
from fl_forensics.secure_round_models import SecureCampaignManifest
from fl_forensics.storage import write_once

VARIANTS = (
    "standard",
    "log1p",
    "log1p-winsor",
    "proportions-only",
    "counts-only",
    "standard-group-balanced",
    "log1p-winsor-group-balanced",
)
SEEDS = (341593, 342593, 343593)


def save(path: Path, value: Any) -> None:
    write_once(path, derived_json_bytes(value))


def fit_variant(
    raw: np.ndarray, names: list[str], variant: str, baseline_scaler: dict[str, Any]
) -> dict[str, Any]:
    if variant not in VARIANTS:
        raise ValueError("unknown preprocessing variant")
    indices = (
        list(range(10, 25))
        if variant == "proportions-only"
        else list(range(10))
        if variant == "counts-only"
        else list(range(25))
    )
    selected_names = [names[index] for index in indices]
    mode = "log1p" if variant == "counts-only" else variant.removesuffix("-group-balanced")
    if mode == "proportions-only":
        mode = "standard"
    specification = fit_feature_transform(
        train_features=raw[:, indices],
        feature_names=selected_names,
        mode=mode,
        lower_quantile=0.001,
        upper_quantile=0.999,
    )
    if mode == "standard":
        specification["mean_after_transform"] = [
            baseline_scaler["mean"][index] for index in indices
        ]
        specification["scale_after_transform"] = [
            baseline_scaler["scale"][index] for index in indices
        ]
    factors = [1.0] * len(indices)
    if variant.endswith("-group-balanced"):
        factors = [np.sqrt(25.0 / (2.0 * (10 if index < 10 else 15))) for index in indices]
    return {
        "variant": variant,
        "source_feature_names": names,
        "indices": indices,
        "transform": specification,
        "post_standardization_block_factors": factors,
        "fit_scope": "Data24 train only; no validation/test/external fitting",
    }


def transform(raw: np.ndarray, specification: dict[str, Any]) -> np.ndarray:
    indices = specification["indices"]
    names = [specification["source_feature_names"][index] for index in indices]
    result = apply_feature_transform(
        features=raw[:, indices], feature_names=names, specification=specification["transform"]
    )
    return result * np.asarray(specification["post_standardization_block_factors"])


def inference_state(model: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "artifact_type": "sklearn_mlp_numeric_inference_state",
        "classes": model.classes_.tolist(),
        "hidden_activation": "relu",
        "output_activation": "softmax",
        "coefficients": [value.tolist() for value in model.coefs_],
        "intercepts": [value.tolist() for value in model.intercepts_],
    }


def predict_state(state: dict[str, Any], features: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    value = features
    for index, (weights, bias) in enumerate(
        zip(state["coefficients"], state["intercepts"], strict=True)
    ):
        value = value @ np.asarray(weights, dtype=np.float64) + np.asarray(bias, dtype=np.float64)
        if index < len(state["coefficients"]) - 1:
            value = np.maximum(value, 0)
    exponent = np.exp(value - value.max(axis=1, keepdims=True))
    probability = exponent / exponent.sum(axis=1, keepdims=True)
    return np.asarray(state["classes"])[probability.argmax(axis=1)], probability


def describe_shift(
    raw_train: np.ndarray, raw_external: np.ndarray, names: list[str], scaler: dict[str, Any]
) -> dict[str, Any]:
    from scipy.stats import ks_2samp

    scale = np.asarray(scaler["scale"], dtype=np.float64)
    z = (raw_external - np.asarray(scaler["mean"], dtype=np.float64)) / scale
    features = []
    for index, name in enumerate(names):
        features.append(
            {
                "feature": name,
                "train_quantiles_0_50_95_99_100": np.quantile(
                    raw_train[:, index], [0, 0.5, 0.95, 0.99, 1]
                ).tolist(),
                "external_quantiles_0_50_95_99_100": np.quantile(
                    raw_external[:, index], [0, 0.5, 0.95, 0.99, 1]
                ).tolist(),
                "external_fraction_absolute_training_z_above5": float(
                    (np.abs(z[:, index]) > 5).mean()
                ),
                "ks_statistic_descriptive_no_multiple_test_claim": float(
                    ks_2samp(raw_train[:, index], raw_external[:, index]).statistic
                ),
            }
        )
    return {
        "features": features,
        "any_absolute_training_z_above5_fraction": float((np.abs(z) > 5).any(axis=1).mean()),
        "interpretation": "Descriptive shift; neither a unique causal diagnosis nor evidence that counts alone explain transfer failure.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-workspace", type=Path, required=True)
    parser.add_argument("--partition-workspace", type=Path, required=True)
    parser.add_argument("--external-workspace", type=Path, required=True)
    parser.add_argument("--reference-campaign", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/base.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    output = arguments.output
    output.mkdir(parents=True, exist_ok=False)
    config, config_hash = load_yaml(arguments.config)
    dataset_manifest = json.loads((arguments.dataset_workspace / "manifest.json").read_bytes())
    for name in ("dataset.json", "scaler.json"):
        if sha256_file(arguments.dataset_workspace / name) != dataset_manifest["artifacts"][name]:
            raise ValueError(f"changed Data24 {name}")
    dataset = json.loads((arguments.dataset_workspace / "dataset.json").read_bytes())
    names = dataset["feature_names"]
    if len(names) != 25:
        raise ValueError("this declared ablation protocol requires the original 25-feature schema")
    baseline_scaler = json.loads((arguments.dataset_workspace / "scaler.json").read_bytes())
    partition = json.loads((arguments.partition_workspace / "manifest.json").read_bytes())
    raw = {
        split: np.asarray(
            [row["features"] for row in dataset["rows"] if row["split"] == split], dtype=np.float64
        )
        for split in ("train", "validation")
    }
    labels = {
        split: np.asarray([row["label"] for row in dataset["rows"] if row["split"] == split])
        for split in ("train", "validation")
    }
    ids = {
        split: {row["window_id"] for row in dataset["rows"] if row["split"] == split}
        for split in ("train", "validation", "test")
    }
    assert not (
        ids["train"] & ids["validation"]
        or ids["train"] & ids["test"]
        or ids["validation"] & ids["test"]
    )
    classes = sorted(set(labels["train"]))
    assert classes == partition["class_names"]
    class_weights = partition["global_class_weights"]
    protocol = {
        "seeds": list(SEEDS),
        "variants_in_tie_break_order": list(VARIANTS),
        "epochs": int(config["model"]["max_iterations"]),
        "checkpoint_selection": "minimum Data24 validation weighted log-loss, earliest epoch on ties",
        "variant_selection": "maximum mean Data24 validation macro-F1 over the declared seeds; declared variant order breaks exact ties",
        "external_metrics_used_for_selection": False,
        "external_domain_previously_observed": True,
        "external_interpretation": "exploratory diagnosis of already observed Data22 domain",
        "test_access": "only the variant frozen after validation; once per seed",
        "implementation_sha256": implementation_sha256(),
        "script_sha256": sha256_file(Path(__file__)),
        "config_sha256": config_hash,
        "dataset_sha256": sha256_file(arguments.dataset_workspace / "dataset.json"),
        "scaler_sha256": sha256_file(arguments.dataset_workspace / "scaler.json"),
        "partition_manifest_sha256": sha256_file(arguments.partition_workspace / "manifest.json"),
        "python": platform.python_version(),
    }
    save(output / "protocol-before-training.json", protocol)
    write_once(output / "producer-script.py", Path(__file__).read_bytes())
    dependencies_screen = screening._dependencies()
    trained, results, specs = {}, {}, {}
    with threadpool_limits(limits=1):
        for variant in VARIANTS:
            specification = fit_variant(raw["train"], names, variant, baseline_scaler)
            specs[variant] = specification
            save(output / variant / "feature-transform.json", specification)
            x_train, x_validation = (
                transform(raw["train"], specification),
                transform(raw["validation"], specification),
            )
            results[variant], trained[variant] = [], []
            for seed in SEEDS:
                run, model = screening._train_run(
                    np=np,
                    train_features=x_train,
                    train_labels=labels["train"],
                    validation_features=x_validation,
                    validation_labels=labels["validation"],
                    test_features=None,
                    test_labels=None,
                    class_names=classes,
                    class_weights=class_weights,
                    model_config=config["model"],
                    federation_config=config["federation"],
                    seed=seed,
                    epochs=protocol["epochs"],
                    dependencies=dependencies_screen,
                )
                state = inference_state(model)
                portable, probability = predict_state(state, x_validation)
                assert np.array_equal(portable, model.predict(x_validation))
                assert np.allclose(
                    probability, model.predict_proba(x_validation), rtol=1e-12, atol=1e-13
                )
                save(output / variant / f"model-s{seed}.json", state)
                save(output / variant / f"validation-s{seed}.json", run)
                results[variant].append(run)
                trained[variant].append(model)
                print(
                    f"{variant} s{seed}: selected epoch {run['selected_epoch']}; validation macro-F1 {run['metrics']['validation']['macro_f1_all_model_classes']:.6f}",
                    flush=True,
                )
        means = {
            variant: mean(
                run["metrics"]["validation"]["macro_f1_all_model_classes"] for run in runs
            )
            for variant, runs in results.items()
        }
        selected = max(VARIANTS, key=lambda variant: (means[variant], -VARIANTS.index(variant)))
        selection = {
            "selected_variant": selected,
            "mean_validation_macro_f1": means,
            "external_metrics_used_for_selection": False,
            "test_metrics_used_for_selection": False,
            "protocol_sha256": sha256_file(output / "protocol-before-training.json"),
        }
        save(output / "selection-before-external-and-test.json", selection)
        # External rows and their labels are opened only after this selection is durable.
        external_manifest = json.loads(
            (arguments.external_workspace / "manifest.json").read_bytes()
        )
        if (
            sha256_file(arguments.external_workspace / "dataset.json")
            != external_manifest["artifacts"]["dataset.json"]
        ):
            raise ValueError("changed Data22 feature snapshot")
        external = json.loads((arguments.external_workspace / "dataset.json").read_bytes())
        assert external["feature_names"] == names
        x_external_raw = np.asarray([row["features"] for row in external["rows"]], dtype=np.float64)
        y_external = [row["label"] for row in external["rows"]]
        external_results = {}
        for variant in VARIANTS:
            x_external = transform(x_external_raw, specs[variant])
            external_results[variant] = [
                _binary_metrics(y_external, model.predict(x_external).tolist(), benign="benign")
                for model in trained[variant]
            ]
        test_rows = [row for row in dataset["rows"] if row["split"] == "test"]
        x_test = transform(
            np.asarray([row["features"] for row in test_rows], dtype=np.float64), specs[selected]
        )
        y_test = np.asarray([row["label"] for row in test_rows])
        (
            _,
            _,
            accuracy_score,
            log_loss,
            precision_recall_fscore_support,
            _MLP,
            compute_sample_weight,
        ) = dependencies_screen
        test_metrics = [
            screening._evaluate(
                model=model,
                features=x_test,
                labels=y_test,
                class_names=classes,
                class_weights=class_weights,
                accuracy_score=accuracy_score,
                log_loss=log_loss,
                precision_recall_fscore_support=precision_recall_fscore_support,
                compute_sample_weight=compute_sample_weight,
            )
            for model in trained[selected]
        ]
    # A current signed reference is identified separately from the older publication.
    reference = SecureCampaignManifest.model_validate_json(
        (arguments.reference_campaign / "campaign-manifest.json").read_bytes()
    )
    if not _verify_signed(reference, _coordinator_public_key(arguments.reference_campaign)):
        raise ValueError("invalid current reference campaign signature")
    model_path = (
        arguments.reference_campaign
        / "rounds"
        / f"round-{reference.core.selected_round:03d}"
        / "checkpoint/global-model.json"
    )
    if sha256_file(model_path) != reference.core.selected_model_sha256:
        raise ValueError("current reference model differs from signed selection")
    np_dep, torch, *_ = dependencies()
    old_threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        scaled_external = (x_external_raw - np.asarray(baseline_scaler["mean"])) / np.asarray(
            baseline_scaler["scale"]
        )
        model_export = json.loads(model_path.read_bytes())
        predicted_ids, _confidence = _predict(
            model_export=model_export,
            features=scaled_external,
            batch_size=1024,
            np=np_dep,
            torch=torch,
        )
    finally:
        torch.set_num_threads(old_threads)
    frozen_metrics = _binary_metrics(
        y_external, [model_export["class_names"][index] for index in predicted_ids], benign="benign"
    )
    frozen = {
        "selected_model_sha256": reference.core.selected_model_sha256,
        "selected_round": reference.core.selected_round,
        "signed_campaign_manifest_sha256": sha256_file(
            arguments.reference_campaign / "campaign-manifest.json"
        ),
        "metrics": frozen_metrics,
        "published_historical_model_sha256": "007e3fafd35f292eb72cc4c42c1f05b51210f90637af7da9b345d1e45a123e6e",
        "same_bytes_as_published_historical_model": reference.core.selected_model_sha256
        == "007e3fafd35f292eb72cc4c42c1f05b51210f90637af7da9b345d1e45a123e6e",
        "historical_campaign_training_recomputed": False,
    }
    summary = {
        "protocol": protocol,
        "selection": selection,
        "validation": {
            variant: {
                "mean_macro_f1": means[variant],
                "sample_std_macro_f1": stdev(
                    run["metrics"]["validation"]["macro_f1_all_model_classes"]
                    for run in results[variant]
                ),
            }
            for variant in VARIANTS
        },
        "external_data22": external_results,
        "external_label_counts": dict(Counter(y_external)),
        "selected_variant_test": test_metrics,
        "current_frozen_signed_reference": frozen,
        "feature_shift": describe_shift(raw["train"], x_external_raw, names, baseline_scaler),
        "external_snapshot_manifest_sha256": sha256_file(
            arguments.external_workspace / "manifest.json"
        ),
        "model_export_predictions_match_sklearn_on_all_validation_rows": True,
        "interpretation": "Exploratory representation comparison after historical transfer failure; variant and checkpoints selected using Data24 validation only. Central screening differs from federated training and needs a paired federated confirmation.",
    }
    save(output / "summary.json", summary)
    plt = dependencies_screen[0]
    positions = np.arange(len(VARIANTS))
    figure, axes = plt.subplots(1, 2, figsize=(13, 5))
    axes[0].bar(
        positions,
        [means[name] for name in VARIANTS],
        yerr=[summary["validation"][name]["sample_std_macro_f1"] for name in VARIANTS],
        capsize=3,
    )
    axes[0].set_title("Data24 validation — 3 seeds")
    axes[0].set_ylabel("Macro F1 (six model classes)")
    axes[1].bar(
        positions,
        [mean(item["attack_f1"] for item in external_results[name]) for name in VARIANTS],
        yerr=[stdev(item["attack_f1"] for item in external_results[name]) for name in VARIANTS],
        capsize=3,
    )
    axes[1].set_title("Data22 — exploratory binary transfer")
    axes[1].set_ylabel("Attack F1")
    for axis in axes:
        axis.set_xticks(positions, VARIANTS, rotation=50, ha="right")
        axis.set_ylim(0, 1)
    figure.tight_layout()
    figure.savefig(output / "preprocessing-comparison.png", dpi=180)
    plt.close(figure)
    artifacts = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    authority = SoftwareECDSASigner.generate()
    write_once(output / "experiment-authority.public.pem", authority.public_pem())
    core = {
        "domain": "fl-preprocessing-screening-v1",
        "artifacts": artifacts,
        "selected_variant": selected,
        "producer_script_sha256": protocol["script_sha256"],
        "private_key_exported": False,
    }
    digest = digest_object(core)
    save(
        output / "manifest.json",
        {
            "core": core,
            "core_digest": digest,
            "signature": {
                "key_id": authority.key_id,
                "value_b64": authority.sign_digest(digest),
                "trust_level": "software-development",
            },
        },
    )
    print(
        json.dumps(
            {
                "selected_variant": selected,
                "data24_validation_mean_macro_f1": means,
                "current_frozen_reference": frozen,
            },
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
