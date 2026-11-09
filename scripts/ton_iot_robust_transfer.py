"""Data24-selected preprocessing variants for frozen transfer to ToN-IoT windows.

Twin of ``revision_generalization.py`` / ``revision_federated_generalization.py``
(neither is modified). It reuses ``revision_generalization.fit_variant`` and
``transform`` for the declared VARIANTS, adds feature-group ablations, and trains
each variant with the controlled FedAvg replay. Two separate phases:

* ``train``: Data24 only. Fits transforms on Data24 train, trains every variant
  and seed, selects rounds and the variant on Data24 validation, and writes
  ``selection-before-ton-iot.json`` plus its SHA-256. ToN-IoT is never opened.
* ``evaluate``: requires the frozen protocol and selection digests, then opens
  the ToN-IoT windows and scores every variant and seed.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path
from statistics import mean, stdev
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import revision_generalization as screening

from fl_forensics.canonical import sha256_bytes, sha256_file
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.external_generalization import _model_from_export
from fl_forensics.federated_model import (
    architecture_record,
    build_model,
    dependencies,
    export_state,
    seed_everything,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.retraining_replay import (
    RetrainingPlan,
    create_retraining_replay,
    verify_retraining_replay,
)
from fl_forensics.robust_preprocessing import fit_feature_transform
from fl_forensics.storage import write_once

PREPROCESSING_VARIANTS = tuple(screening.VARIANTS)
ABLATION_GROUPS = {
    "ablate-ports-destinations": ("unique_destination_count", "unique_destination_port_count"),
    "ablate-connection-states": (
        "state_sf_fraction",
        "state_s0_fraction",
        "state_rej_fraction",
        "state_rsto_fraction",
        "state_rstr_fraction",
        "state_other_fraction",
    ),
    "ablate-byte-packet-volumes": (
        "originator_bytes_sum",
        "responder_bytes_sum",
        "originator_packets_sum",
        "responder_packets_sum",
    ),
    "ablate-durations": ("duration_mean", "duration_std", "duration_max"),
}
ALL_VARIANTS = PREPROCESSING_VARIANTS + tuple(ABLATION_GROUPS)
SEEDS = tuple(screening.SEEDS)
FROZEN_BASELINE = {
    "balanced_accuracy": 0.5013,
    "false_positive_rate": 0.9972,
    "auroc": 0.8935,
    "confusion_matrix": [[8, 2880], [1, 5045]],
}
TON_IOT_WINDOWS = {
    "occurrence": ("occurrence-windows.json", "57ebec4e6fc6d087b5da527421ce32b08382e9666993b8fa7a9556b9592e3c2c"),
    "exact-projection": (
        "exact-projection-windows.json",
        "97b4da805134fb24dbeb3dabaab477d5d2164548cb448e4b34d1c41c9741605c",
    ),
}


def save(path: Path, value: Any) -> None:
    write_once(path, derived_json_bytes(value))


def check_protocol(output: Path) -> str:
    recorded = (output / "protocol.sha256").read_text().split()[0]
    actual = sha256_file(output / "protocol.md")
    if actual != recorded:
        raise ValueError("protocol.md differs from protocol.sha256")
    return actual


def fit_ablation(names: list[str], variant: str, raw_train: np.ndarray, baseline: dict[str, Any]) -> dict[str, Any]:
    """Standard z-score with the frozen training scaler restricted to the kept columns."""
    removed = set(ABLATION_GROUPS[variant])
    missing = removed - set(names)
    if missing:
        raise ValueError(f"unknown ablation features: {sorted(missing)}")
    indices = [i for i, name in enumerate(names) if name not in removed]
    selected = [names[i] for i in indices]
    spec = fit_feature_transform(train_features=raw_train[:, indices], feature_names=selected, mode="standard")
    spec["mean_after_transform"] = [baseline["mean"][i] for i in indices]
    spec["scale_after_transform"] = [baseline["scale"][i] for i in indices]
    return {
        "variant": variant,
        "source_feature_names": names,
        "indices": indices,
        "removed_features": sorted(removed, key=names.index),
        "transform": spec,
        "post_standardization_block_factors": [1.0] * len(indices),
        "fit_scope": "Data24 train only (frozen M2 training scaler restricted to kept columns)",
    }


def fit_any(names: list[str], variant: str, raw_train: np.ndarray, baseline: dict[str, Any]) -> dict[str, Any]:
    if variant in PREPROCESSING_VARIANTS:
        return screening.fit_variant(raw_train, names, variant, baseline)
    if variant in ABLATION_GROUPS:
        return fit_ablation(names, variant, raw_train, baseline)
    raise ValueError(f"unknown variant {variant}")


def apply(raw: np.ndarray, spec: dict[str, Any]) -> np.ndarray:
    return np.round(screening.transform(np.asarray(raw, dtype=np.float64), spec), 12)


def select_variant(validation_means: dict[str, float]) -> str:
    eligible = [v for v in PREPROCESSING_VARIANTS if v in validation_means]
    if not eligible:
        raise ValueError("no eligible preprocessing variant")
    return max(eligible, key=lambda v: (validation_means[v], -PREPROCESSING_VARIANTS.index(v)))


def select_round(evaluations: list[tuple[int, dict[str, Any]]]) -> tuple[int, dict[str, Any]]:
    return max(evaluations, key=lambda item: (item[1]["macro_f1_all_model_classes"], -item[0]))


def binary_metrics(actual: Any, predicted: Any, scores: Any) -> dict[str, Any]:
    from sklearn.metrics import average_precision_score, roc_auc_score

    actual = np.asarray(actual, dtype=bool)
    predicted = np.asarray(predicted, dtype=bool)
    tn = int((~actual & ~predicted).sum())
    fp = int((~actual & predicted).sum())
    fn = int((actual & ~predicted).sum())
    tp = int((actual & predicted).sum())
    recall = tp / (tp + fn) if tp + fn else None
    specificity = tn / (tn + fp) if tn + fp else None
    attack_f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0
    benign_f1 = 2 * tn / (2 * tn + fn + fp) if 2 * tn + fn + fp else 0.0
    both = bool(tp + fn and tn + fp)
    return {
        "rows": len(actual),
        "confusion_matrix": {"labels": ["benign", "attack"], "values": [[tn, fp], [fn, tp]]},
        "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None,
        "false_positive_rate": fp / (tn + fp) if tn + fp else None,
        "attack_recall": recall,
        "attack_precision": tp / (tp + fp) if tp + fp else None,
        "attack_f1": attack_f1,
        "benign_f1": benign_f1,
        "binary_macro_f1": (attack_f1 + benign_f1) / 2,
        "auroc": float(roc_auc_score(actual, scores)) if both else None,
        "average_precision": float(average_precision_score(actual, scores)) if both else None,
    }


def softmax_predict(model_export: dict[str, Any], features: np.ndarray, torch: Any) -> np.ndarray:
    model = _model_from_export(model_export, np=np, torch=torch)
    model.eval()
    out = []
    with torch.no_grad():
        for offset in range(0, len(features), 1024):
            batch = torch.from_numpy(np.asarray(features[offset : offset + 1024], dtype=np.float32))
            out.append(torch.softmax(model(batch), dim=1).numpy())
    probability = np.concatenate(out)
    if not np.isfinite(probability).all():
        raise ValueError("non-finite probabilities")
    return probability


# --------------------------------------------------------------------------- train


def train_phase(args: argparse.Namespace) -> None:
    out = args.output
    protocol_sha = check_protocol(out)
    if (out / "selection-before-ton-iot.json").exists():
        raise SystemExit("selection already frozen; refusing to retrain")
    import yaml

    config = yaml.safe_load(args.config.read_bytes())
    dataset_manifest = json.loads((args.dataset_workspace / "manifest.json").read_bytes())
    for name in ("dataset.json", "scaler.json"):
        if sha256_file(args.dataset_workspace / name) != dataset_manifest["artifacts"][name]:
            raise ValueError(f"changed Data24 {name}")
    dataset = json.loads((args.dataset_workspace / "dataset.json").read_bytes())
    names = list(dataset["feature_names"])
    baseline = json.loads((args.dataset_workspace / "scaler.json").read_bytes())
    partition_bytes = (args.partition_workspace / "manifest.json").read_bytes()
    partition = json.loads(partition_bytes)
    if partition["source_m2_scaler_sha256"] != sha256_file(args.dataset_workspace / "scaler.json"):
        raise ValueError("partition/scaler mismatch")
    raw_train = np.asarray([r["features"] for r in dataset["rows"] if r["split"] == "train"], dtype=np.float64)
    by_id = {r["window_id"]: r for r in dataset["rows"]}
    validation_raw = [r for r in dataset["rows"] if r["split"] == "validation"]
    variants = list(args.variants or ALL_VARIANTS)
    seeds = [int(s) for s in (args.seeds or SEEDS)]
    rounds = int(args.rounds or config["training"]["rounds"])
    run_record = {
        "protocol_sha256": protocol_sha,
        "variants": variants,
        "seeds": seeds,
        "rounds": rounds,
        "model": config["model"],
        "training": config["training"],
        "dataset_sha256": sha256_file(args.dataset_workspace / "dataset.json"),
        "scaler_sha256": sha256_file(args.dataset_workspace / "scaler.json"),
        "partition_manifest_sha256": sha256_bytes(partition_bytes),
        "script_sha256": sha256_file(Path(__file__)),
        "revision_generalization_sha256": sha256_file(Path(screening.__file__)),
        "python": platform.python_version(),
        "ton_iot_opened": False,
    }
    save(out / "train-run-record.json", run_record)
    np_dep, torch, *_ = dependencies()
    signer = SoftwareECDSASigner.generate()
    write_once(out / "experiment-authority.public.pem", signer.public_pem())
    reports: dict[str, dict[str, Any]] = {}
    for variant in variants:
        spec = fit_any(names, variant, raw_train, baseline)
        save(out / "transforms" / f"{variant}.json", spec)
        prepared = out / "inputs" / variant
        refs = []
        for record in partition["clients"]:
            original = (args.partition_workspace / record["dataset_path"]).read_bytes()
            if sha256_bytes(original) != record["dataset_sha256"]:
                raise ValueError("changed client snapshot")
            snapshot = json.loads(original)
            rows = {}
            for split in ("train", "validation"):
                old = snapshot["rows"][split]
                raw_rows = [by_id[r["window_id"]] for r in old]
                if not all(o["label"] == r["label"] and r["split"] == split for o, r in zip(old, raw_rows, strict=True)):
                    raise ValueError("client rows disagree with Data24 dataset")
                values = apply(np.asarray([r["features"] for r in raw_rows]), spec)
                if variant == "standard" and not np.array_equal(
                    values.astype(np.float32), np.asarray([r["features"] for r in old], dtype=np.float32)
                ):
                    raise ValueError("standard transform does not reproduce the reference partition features")
                rows[split] = [{**r, "features": v.tolist()} for r, v in zip(old, values, strict=True)]
            data = derived_json_bytes({**snapshot, "feature_names": spec["transform"]["feature_names"], "rows": rows})
            write_once(prepared / record["dataset_path"], data)
            refs.append({**record, "dataset_sha256": sha256_bytes(data)})
        save(
            prepared / "manifest.json",
            {
                **partition,
                "artifact_type": "controlled_replay_transformed_partition_set",
                "feature_names": spec["transform"]["feature_names"],
                "clients": refs,
                "source_partition_manifest_sha256": sha256_bytes(partition_bytes),
                "transform_sha256": sha256_file(out / "transforms" / f"{variant}.json"),
            },
        )
        val_values = apply(np.asarray([r["features"] for r in validation_raw]), spec)
        validation_path = prepared / "validation.json"
        save(
            validation_path,
            {
                "split": "validation",
                "class_names": partition["class_names"],
                "rows": {"validation": [{**r, "features": v.tolist()} for r, v in zip(validation_raw, val_values, strict=True)]},
            },
        )
        for seed in seeds:
            name = f"{variant}-s{seed}"
            started = time.monotonic()
            seed_everything(seed, torch=torch, np=np_dep)
            dims = {
                "input_features": len(spec["indices"]),
                "class_count": len(partition["class_names"]),
                "hidden_layers": config["model"]["hidden_layers"],
                "embedding_size": config["model"]["embedding_size"],
                "dropout": float(config["model"]["dropout"]),
            }
            base_path = prepared / f"base-s{seed}.json"
            save(base_path, export_state(build_model(**dims, torch=torch), architecture=architecture_record(**dims), class_names=partition["class_names"]))
            plan = RetrainingPlan(
                rounds=rounds,
                seed=seed,
                local_epochs=int(config["training"]["local_epochs"]),
                batch_size=int(config["training"]["batch_size"]),
                learning_rate_decimal=str(config["training"]["learning_rate"]),
                minimum_contributors=len(partition["clients"]),
                clients=sorted(r["client_id"] for r in partition["clients"]),
            )
            created = create_retraining_replay(
                output=out / "runs" / name,
                plan=plan,
                base_model_path=base_path,
                expected_base_sha256=sha256_file(base_path),
                partition_workspace=prepared,
                expected_partition_sha256=sha256_file(prepared / "manifest.json"),
                validation_split_path=validation_path,
                expected_validation_sha256=sha256_file(validation_path),
                signer=signer,
                authority_public_key=signer.private_key.public_key(),
            )
            verification = verify_retraining_replay(
                workspace=out / "runs" / name,
                expected_sha256=created["manifest_sha256"],
                base_model_path=base_path,
                partition_workspace=prepared,
                validation_split_path=validation_path,
                authority_public_key=signer.private_key.public_key(),
            )
            if verification["status"] != "verified":
                raise ValueError(f"replay verification failed: {verification}")
            evaluations = [
                (n, json.loads((out / "runs" / name / "rounds" / f"round-{n:03d}" / "evaluation.json").read_bytes()))
                for n in range(1, rounds + 1)
            ]
            number, metric = select_round(evaluations)
            model_path = out / "runs" / name / "rounds" / f"round-{number:03d}" / "model.json"
            reports[name] = {
                "variant": variant,
                "seed": seed,
                "eligible_for_selection": variant in PREPROCESSING_VARIANTS,
                "selected_round": number,
                "validation_macro_f1": metric["macro_f1_all_model_classes"],
                "selected_model_sha256": sha256_file(model_path),
                "replay_manifest_sha256": created["manifest_sha256"],
                "seconds": round(time.monotonic() - started, 1),
            }
            print(f"{name}: round {number} val macro-F1 {metric['macro_f1_all_model_classes']:.6f} ({reports[name]['seconds']} s)", flush=True)
    means = {v: mean(r["validation_macro_f1"] for r in reports.values() if r["variant"] == v) for v in variants}
    selected = select_variant(means)
    selection = {
        "selected_variant": selected,
        "metric": "mean over seeds of Data24 validation macro_f1_all_model_classes at the selected round",
        "tie_break": "declared PREPROCESSING_VARIANTS order",
        "validation_mean_macro_f1": means,
        "runs": reports,
        "protocol_sha256": protocol_sha,
        "train_run_record_sha256": sha256_file(out / "train-run-record.json"),
        "ton_iot_opened": False,
        "data24_test_used": False,
        "standard_s341593_reproduces_frozen_model": reports.get("standard-s341593", {}).get("selected_model_sha256")
        == "39075d9cbf7c45248c475ae3ddfb66f0e032d55cc210eba2a9e97c19e3d594e5",
    }
    save(out / "selection-before-ton-iot.json", selection)
    digest = sha256_file(out / "selection-before-ton-iot.json")
    write_once(out / "selection-before-ton-iot.sha256", f"{digest}  selection-before-ton-iot.json\n".encode())
    print(json.dumps({"selected_variant": selected, "selection_sha256": digest, "validation_mean_macro_f1": means}, indent=2))


# ------------------------------------------------------------------------ evaluate


def evaluate_phase(args: argparse.Namespace) -> None:
    out = args.output
    protocol_sha = check_protocol(out)
    selection_path = out / "selection-before-ton-iot.json"
    recorded = (out / "selection-before-ton-iot.sha256").read_text().split()[0]
    if sha256_file(selection_path) != recorded:
        raise ValueError("selection file differs from its recorded digest")
    selection = json.loads(selection_path.read_bytes())
    if selection["protocol_sha256"] != protocol_sha:
        raise ValueError("selection was made under a different protocol")
    _np, torch, *_ = dependencies()
    torch.set_num_threads(1)
    windows = {}
    for view, (filename, expected) in TON_IOT_WINDOWS.items():
        path = args.ton_iot_windows / filename
        if sha256_file(path) != expected:
            raise ValueError(f"ToN-IoT {view} windows digest mismatch")
        data = json.loads(path.read_bytes())
        windows[view] = data
    names = windows["occurrence"]["feature_names"]
    results: dict[str, Any] = {}
    # Pipeline control: the frozen checkpoint with the original (unrounded) scaling.
    control = None
    if args.frozen_model and args.frozen_scaler:
        frozen = json.loads(args.frozen_model.read_bytes())
        scaler = json.loads(args.frozen_scaler.read_bytes())
        rows = windows["occurrence"]["rows"]
        raw = np.asarray([r["features"] for r in rows], dtype=np.float64)
        p = softmax_predict(frozen, (raw - np.asarray(scaler["mean"])) / np.asarray(scaler["scale"]), torch)
        b = frozen["class_names"].index("benign")
        control = binary_metrics([r["label"] != "benign" for r in rows], p.argmax(1) != b, 1 - p[:, b])
        control["frozen_model_sha256"] = sha256_file(args.frozen_model)
    for name, run in selection["runs"].items():
        spec = json.loads((out / "transforms" / f"{run['variant']}.json").read_bytes())
        if spec["source_feature_names"] != names:
            raise ValueError("feature order mismatch")
        model_path = out / "runs" / name / "rounds" / f"round-{run['selected_round']:03d}" / "model.json"
        if sha256_file(model_path) != run["selected_model_sha256"]:
            raise ValueError("selected model changed after selection")
        model_export = json.loads(model_path.read_bytes())
        benign = model_export["class_names"].index("benign")
        per_view = {}
        for view, data in windows.items():
            rows = data["rows"]
            features = apply(np.asarray([r["features"] for r in rows]), spec)
            probability = softmax_predict(model_export, features, torch)
            per_view[view] = binary_metrics(
                [r["label"] != "benign" for r in rows], probability.argmax(1) != benign, 1 - probability[:, benign]
            )
        results[name] = {**run, "ton_iot": per_view}
    keys = ("balanced_accuracy", "false_positive_rate", "attack_recall", "binary_macro_f1", "auroc", "average_precision")
    aggregate: dict[str, Any] = {}
    for variant in dict.fromkeys(r["variant"] for r in results.values()):
        runs = [r for r in results.values() if r["variant"] == variant]
        aggregate[variant] = {
            "validation_macro_f1_mean": mean(r["validation_macro_f1"] for r in runs),
            **{
                view: {
                    k: {
                        "mean": mean(r["ton_iot"][view][k] for r in runs),
                        "sd": stdev(r["ton_iot"][view][k] for r in runs) if len(runs) > 1 else None,
                    }
                    for k in keys
                }
                for view in windows
            },
        }
    assessment = assess(selection["selected_variant"], results)
    ablation = ablation_effects(results)
    summary = {
        "protocol_sha256": protocol_sha,
        "selection_sha256": recorded,
        "selected_variant": selection["selected_variant"],
        "frozen_baseline_reported": FROZEN_BASELINE,
        "pipeline_control_frozen_checkpoint_occurrence": control,
        "per_run": results,
        "per_variant": aggregate,
        "assessment": assessment,
        "ablation_effects_vs_standard": ablation,
        "evaluate_script_sha256": sha256_file(Path(__file__)),
    }
    save(out / "ton-iot-results.json", summary)
    print(json.dumps({"selected": selection["selected_variant"], "assessment": assessment, "ablation": ablation}, indent=2))


def assess(selected: str, results: dict[str, Any], view: str = "occurrence") -> dict[str, Any]:
    runs = sorted((r for r in results.values() if r["variant"] == selected), key=lambda r: r["seed"])
    std = {r["seed"]: r for r in results.values() if r["variant"] == "standard"}
    m = [r["ton_iot"][view] for r in runs]
    ba = mean(x["balanced_accuracy"] for x in m)
    fpr = mean(x["false_positive_rate"] for x in m)
    rec = mean(x["attack_recall"] for x in m)
    i1 = ba >= 0.60
    i2 = all(x["balanced_accuracy"] > FROZEN_BASELINE["balanced_accuracy"] and x["false_positive_rate"] < FROZEN_BASELINE["false_positive_rate"] for x in m)
    i3 = rec >= 0.50
    i4 = selected == "standard" or all(
        r["ton_iot"][view]["balanced_accuracy"] > std[r["seed"]]["ton_iot"][view]["balanced_accuracy"] for r in runs
    )
    n1, n2, n3 = ba <= 0.55, fpr >= 0.95, selected == "standard"
    if n1 or n2 or n3:
        verdict = "negative"
    elif i1 and i2 and i3 and i4:
        verdict = "improvement"
    elif i1 and i2 and i3:
        verdict = "inconclusive (improvement over frozen checkpoint, not attributable to preprocessing)"
    else:
        verdict = "inconclusive"
    return {
        "view": view,
        "selected_variant": selected,
        "mean_balanced_accuracy": ba,
        "mean_false_positive_rate": fpr,
        "mean_attack_recall": rec,
        "criteria": {"I1": i1, "I2": i2, "I3": i3, "I4": i4, "N1": n1, "N2": n2, "N3": n3},
        "verdict": verdict,
    }


def ablation_effects(results: dict[str, Any], view: str = "occurrence") -> dict[str, Any]:
    std = {r["seed"]: r["ton_iot"][view] for r in results.values() if r["variant"] == "standard"}
    effects = {}
    for group in ABLATION_GROUPS:
        runs = [r for r in results.values() if r["variant"] == group and r["seed"] in std]
        if not runs:
            continue
        effects[group] = {
            k: mean(r["ton_iot"][view][k] - std[r["seed"]][k] for r in runs)
            for k in ("false_positive_rate", "auroc", "balanced_accuracy")
        }
    if not effects:
        return {}
    return {
        "mean_paired_change": effects,
        "largest_abs_fpr_change": max(effects, key=lambda g: abs(effects[g]["false_positive_rate"])),
        "largest_abs_auroc_change": max(effects, key=lambda g: abs(effects[g]["auroc"])),
    }


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    out_default = root / "artifacts/ton-iot-robust-transfer-v1"
    transfer = Path(
        "/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/ton-iot-transfer-20261109"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("train", "evaluate"))
    parser.add_argument("--output", type=Path, default=out_default)
    parser.add_argument("--dataset-workspace", type=Path, default=root / "artifacts/m2-data24-parquet")
    parser.add_argument("--partition-workspace", type=Path, default=root / "artifacts/m3-data24-parquet-iid-local-test-v1")
    parser.add_argument("--config", type=Path, default=root / "configs/federation.yaml")
    parser.add_argument("--ton-iot-windows", type=Path, default=transfer / "windows")
    parser.add_argument("--frozen-model", type=Path, default=transfer / "frozen-model.json")
    parser.add_argument("--frozen-scaler", type=Path, default=transfer / "frozen-scaler.json")
    parser.add_argument("--variants", nargs="*", help="subset (pilot/timing only)")
    parser.add_argument("--seeds", nargs="*", help="subset (pilot/timing only)")
    parser.add_argument("--rounds", type=int, help="override (pilot/timing only)")
    args = parser.parse_args(argv)
    (train_phase if args.phase == "train" else evaluate_phase)(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
