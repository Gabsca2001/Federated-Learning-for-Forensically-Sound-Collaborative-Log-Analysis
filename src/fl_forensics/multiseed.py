"""Verified aggregation of repeated M3 FedAvg experiments."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import statistics
from pathlib import Path
from typing import Any

from .canonical import canonical_json_bytes, sha256_file
from .config import load_yaml
from .federated_partitioning import verify_partitions
from .federated_training import verify_federated_baseline
from .preprocessing import derived_json_bytes
from .storage import write_once


class MultiSeedError(ValueError):
    """Raised when repeated runs do not satisfy the frozen comparison contract."""


_T_CRITICAL_95 = {
    1: 12.706204736,
    2: 4.30265273,
    3: 3.182446305,
    4: 2.776445105,
    5: 2.570581836,
    6: 2.446911851,
    7: 2.364624252,
    8: 2.306004135,
    9: 2.262157163,
    10: 2.228138852,
    11: 2.20098516,
    12: 2.17881283,
    13: 2.160368656,
    14: 2.144786688,
    15: 2.131449546,
    16: 2.119905299,
    17: 2.109815578,
    18: 2.10092204,
    19: 2.093024054,
    20: 2.085963447,
    21: 2.079613845,
    22: 2.073873068,
    23: 2.06865761,
    24: 2.063898562,
    25: 2.059538553,
    26: 2.055529439,
    27: 2.051830516,
    28: 2.048407142,
    29: 2.045229642,
    30: 2.042272456,
}


def load_multiseed_contract(config_path: Path) -> tuple[dict[str, Any], str]:
    config, digest = load_yaml(config_path)
    if config.get("schema_version") != "1.0":
        raise MultiSeedError("unsupported M3 multi-seed schema_version")
    if not str(config.get("experiment_id", "")).strip():
        raise MultiSeedError("experiment_id is required")
    seeds = config.get("seeds")
    if not isinstance(seeds, list) or len(seeds) < 2:
        raise MultiSeedError("at least two seeds are required")
    if any(isinstance(seed, bool) or not isinstance(seed, int) for seed in seeds):
        raise MultiSeedError("seeds must be integers")
    if seeds != sorted(set(seeds)):
        raise MultiSeedError("seeds must be unique and sorted")
    modes = config.get("modes")
    if modes != ["iid", "non-iid"]:
        raise MultiSeedError("modes must be exactly [iid, non-iid]")
    if not str(config.get("base_federation_config", "")).strip():
        raise MultiSeedError("base_federation_config is required")
    execution = config.get("execution")
    if not isinstance(execution, dict) or execution.get("device") not in {"cpu", "cuda"}:
        raise MultiSeedError("execution.device must be cpu or cuda")
    expected_statistics = {
        "primary_metric": "macro_f1_all_model_classes",
        "primary_split": "test",
        "standard_deviation": "sample",
        "confidence_interval": "student-t-95-percent",
        "pairing": "by-seed",
    }
    if config.get("statistics") != expected_statistics:
        raise MultiSeedError("multi-seed statistics policy mismatch")
    return config, digest


def describe(values: list[float]) -> dict[str, float | int]:
    if len(values) < 2:
        raise MultiSeedError("at least two finite measurements are required")
    finite = [float(value) for value in values]
    if not all(math.isfinite(value) for value in finite):
        raise MultiSeedError("multi-seed measurements must be finite")
    count = len(finite)
    mean = statistics.fmean(finite)
    sample_std = statistics.stdev(finite)
    standard_error = sample_std / math.sqrt(count)
    degrees_of_freedom = count - 1
    t_critical = _T_CRITICAL_95.get(degrees_of_freedom, 1.959963985)
    half_width = t_critical * standard_error
    return {
        "count": count,
        "mean": mean,
        "sample_standard_deviation": sample_std,
        "standard_error": standard_error,
        "confidence_interval_95_lower": mean - half_width,
        "confidence_interval_95_upper": mean + half_width,
        "minimum": min(finite),
        "median": statistics.median(finite),
        "maximum": max(finite),
    }


def _run_paths(runs_workspace: Path, seed: int, mode: str) -> tuple[Path, Path, Path]:
    base = runs_workspace / f"seed-{seed}" / mode
    return (
        runs_workspace / "configs" / f"federation-seed-{seed}.yaml",
        base / "partition",
        base / "run",
    )


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise MultiSeedError(f"required multi-seed artifact is missing: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise MultiSeedError(f"JSON artifact must contain an object: {path}")
    return value


def _collect_run(
    *,
    runs_workspace: Path,
    dataset_workspace: Path,
    seed: int,
    mode: str,
) -> dict[str, Any]:
    config_path, partition_workspace, run_workspace = _run_paths(
        runs_workspace, seed, mode
    )
    partition_status = verify_partitions(
        workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
    )
    if partition_status.get("status") != "verified":
        raise MultiSeedError(
            f"partition verification failed for seed={seed}, mode={mode}: "
            f"{partition_status.get('errors', [])}"
        )
    run_status = verify_federated_baseline(
        workspace=run_workspace,
        partition_workspace=partition_workspace,
        dataset_workspace=dataset_workspace,
    )
    if run_status.get("status") != "verified":
        raise MultiSeedError(
            f"run verification failed for seed={seed}, mode={mode}: "
            f"{run_status.get('errors', [])}"
        )

    generated_config, _config_source_digest = load_yaml(config_path)
    partition_manifest = _load_json(partition_workspace / "manifest.json")
    run_manifest = _load_json(run_workspace / "manifest.json")
    metrics = _load_json(run_workspace / "metrics.json")

    if int(generated_config.get("partitioning", {}).get("seed", -1)) != seed:
        raise MultiSeedError(f"partition seed mismatch: seed={seed}, mode={mode}")
    if int(generated_config.get("training", {}).get("seed", -1)) != seed:
        raise MultiSeedError(f"training seed mismatch: seed={seed}, mode={mode}")
    if run_manifest.get("partition_mode") != mode or metrics.get("partition_mode") != mode:
        raise MultiSeedError(f"partition mode mismatch: seed={seed}, mode={mode}")
    if int(run_manifest.get("training", {}).get("seed", -1)) != seed:
        raise MultiSeedError(f"run manifest seed mismatch: seed={seed}, mode={mode}")
    if run_manifest.get("federation_config_sha256") != sha256_file(config_path):
        raise MultiSeedError(f"federation config digest mismatch: seed={seed}, mode={mode}")
    if run_manifest.get("partition_manifest_sha256") != sha256_file(
        partition_workspace / "manifest.json"
    ):
        raise MultiSeedError(f"partition binding mismatch: seed={seed}, mode={mode}")
    if run_manifest.get("metrics_sha256") != sha256_file(run_workspace / "metrics.json"):
        raise MultiSeedError(f"metrics digest mismatch: seed={seed}, mode={mode}")

    selected = metrics.get("selected")
    if not isinstance(selected, dict):
        raise MultiSeedError(f"selected checkpoint metrics are missing: seed={seed}, mode={mode}")
    expected_selection = {
        "metric": "macro_f1_all_model_classes",
        "mode": "maximize",
        "split": "validation",
        "test_policy": "selected-checkpoint-only",
        "tie_breaker": "earliest_round",
    }
    if run_manifest.get("selection_policy") != expected_selection:
        raise MultiSeedError(f"selection policy mismatch: seed={seed}, mode={mode}")
    if int(run_manifest.get("selected_round", -1)) != int(selected.get("round", -2)):
        raise MultiSeedError(f"selected round mismatch: seed={seed}, mode={mode}")

    validation = selected.get("validation", {})
    test = selected.get("test", {})
    temporal = selected.get("temporal_holdout", {})
    operational = selected.get("operational_metrics", {})
    temporal_false_alarms = operational.get(
        "temporal_holdout_benign_false_alarms", {}
    )
    class_names = list(partition_manifest.get("class_names", []))
    if not class_names:
        raise MultiSeedError(f"class names are missing: seed={seed}, mode={mode}")
    per_class = test.get("per_class", {})
    if set(per_class) != set(class_names):
        raise MultiSeedError(f"test per-class metrics are incomplete: seed={seed}, mode={mode}")

    return {
        "seed": seed,
        "mode": mode,
        "selected_round": int(selected["round"]),
        "validation_macro_f1": float(validation["macro_f1_all_model_classes"]),
        "test_macro_f1": float(test["macro_f1_all_model_classes"]),
        "test_accuracy": float(test["accuracy"]),
        "test_balanced_accuracy": float(test["balanced_accuracy_observed_classes"]),
        "temporal_holdout_accuracy": float(temporal["accuracy"]),
        "temporal_holdout_false_alarm_rate": float(
            temporal_false_alarms["false_alarm_rate"]
        ),
        "test_per_class_f1": {
            label: float(per_class[label]["f1"]) for label in class_names
        },
        "source": {
            "config_path": config_path.relative_to(runs_workspace).as_posix(),
            "config_sha256": sha256_file(config_path),
            "partition_workspace": partition_workspace.relative_to(
                runs_workspace
            ).as_posix(),
            "partition_manifest_sha256": sha256_file(
                partition_workspace / "manifest.json"
            ),
            "run_workspace": run_workspace.relative_to(runs_workspace).as_posix(),
            "run_manifest_sha256": sha256_file(run_workspace / "manifest.json"),
            "metrics_sha256": sha256_file(run_workspace / "metrics.json"),
        },
    }


def _mode_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    class_names = list(runs[0]["test_per_class_f1"])
    return {
        "run_count": len(runs),
        "selected_round": describe([float(run["selected_round"]) for run in runs]),
        "validation_macro_f1": describe(
            [run["validation_macro_f1"] for run in runs]
        ),
        "test_macro_f1": describe([run["test_macro_f1"] for run in runs]),
        "test_accuracy": describe([run["test_accuracy"] for run in runs]),
        "test_balanced_accuracy": describe(
            [run["test_balanced_accuracy"] for run in runs]
        ),
        "temporal_holdout_accuracy": describe(
            [run["temporal_holdout_accuracy"] for run in runs]
        ),
        "temporal_holdout_false_alarm_rate": describe(
            [run["temporal_holdout_false_alarm_rate"] for run in runs]
        ),
        "test_per_class_f1": {
            label: describe([run["test_per_class_f1"][label] for run in runs])
            for label in class_names
        },
    }


def _runs_csv(runs: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    fieldnames = [
        "seed",
        "mode",
        "selected_round",
        "validation_macro_f1",
        "test_macro_f1",
        "test_accuracy",
        "test_balanced_accuracy",
        "temporal_holdout_accuracy",
        "temporal_holdout_false_alarm_rate",
    ]
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for run in runs:
        writer.writerow({key: run[key] for key in fieldnames})
    return stream.getvalue().encode("utf-8")


def _build_outputs(
    *,
    runs_workspace: Path,
    dataset_workspace: Path,
    config_path: Path,
) -> tuple[bytes, bytes, bytes, dict[str, Any]]:
    config, config_sha256 = load_multiseed_contract(config_path)
    runs = [
        _collect_run(
            runs_workspace=runs_workspace,
            dataset_workspace=dataset_workspace,
            seed=int(seed),
            mode=str(mode),
        )
        for seed in config["seeds"]
        for mode in config["modes"]
    ]
    grouped = {
        mode: [run for run in runs if run["mode"] == mode]
        for mode in config["modes"]
    }
    paired_deltas = []
    for seed in config["seeds"]:
        by_mode = {
            run["mode"]: run
            for run in runs
            if int(run["seed"]) == int(seed)
        }
        paired_deltas.append(
            {
                "seed": int(seed),
                "test_macro_f1_non_iid_minus_iid": (
                    by_mode["non-iid"]["test_macro_f1"]
                    - by_mode["iid"]["test_macro_f1"]
                ),
            }
        )
    summary = {
        "schema_version": "1.0",
        "artifact_type": "m3_multiseed_summary",
        "experiment_id": config["experiment_id"],
        "seed_count": len(config["seeds"]),
        "run_count": len(runs),
        "seeds": config["seeds"],
        "modes": config["modes"],
        "statistics_policy": config["statistics"],
        "mode_summaries": {
            mode: _mode_summary(grouped[mode]) for mode in config["modes"]
        },
        "paired_comparison": {
            "runs": paired_deltas,
            "test_macro_f1_non_iid_minus_iid": describe(
                [item["test_macro_f1_non_iid_minus_iid"] for item in paired_deltas]
            ),
        },
        "runs": runs,
        "interpretation_constraints": [
            "The M2 dataset split is fixed across all runs.",
            "Each seed controls M3 partition allocation and training stochasticity.",
            "IID and non-IID outcomes are paired by seed.",
            "Checkpoint selection uses validation macro-F1 only.",
            "Test and benign-only temporal holdout are opened only after selection.",
            "The temporal holdout is not a multiclass attack-detection test.",
        ],
    }
    summary_bytes = derived_json_bytes(summary)
    csv_bytes = _runs_csv(runs)
    dataset_manifest = dataset_workspace / "manifest.json"
    if not dataset_manifest.is_file():
        raise MultiSeedError("M2 dataset manifest is missing")
    manifest = {
        "schema_version": "1.0",
        "artifact_type": "m3_multiseed_summary_manifest",
        "experiment_id": config["experiment_id"],
        "config_sha256": config_sha256,
        "dataset_manifest_sha256": sha256_file(dataset_manifest),
        "seed_count": len(config["seeds"]),
        "run_count": len(runs),
        "modes": config["modes"],
        "statistics_policy": {
            "confidence_interval": "student-t-95-percent",
            "pairing": "by-seed",
            "standard_deviation": "sample",
        },
        "summary_sha256": hashlib.sha256(summary_bytes).hexdigest(),
        "runs_csv_sha256": hashlib.sha256(csv_bytes).hexdigest(),
        "sources": [
            {
                "seed": run["seed"],
                "mode": run["mode"],
                **run["source"],
            }
            for run in runs
        ],
    }
    manifest_bytes = canonical_json_bytes(manifest) + b"\n"
    return summary_bytes, csv_bytes, manifest_bytes, summary


def create_multiseed_summary(
    *,
    runs_workspace: Path,
    dataset_workspace: Path,
    output: Path,
    config_path: Path,
) -> dict[str, Any]:
    summary_bytes, csv_bytes, manifest_bytes, summary = _build_outputs(
        runs_workspace=runs_workspace,
        dataset_workspace=dataset_workspace,
        config_path=config_path,
    )
    write_once(output / "summary.json", summary_bytes)
    write_once(output / "runs.csv", csv_bytes)
    write_once(output / "manifest.json", manifest_bytes)
    return {
        "status": "summarized",
        "workspace": str(output),
        "experiment_id": summary["experiment_id"],
        "seed_count": summary["seed_count"],
        "run_count": summary["run_count"],
        "iid_test_macro_f1_mean": summary["mode_summaries"]["iid"][
            "test_macro_f1"
        ]["mean"],
        "non_iid_test_macro_f1_mean": summary["mode_summaries"]["non-iid"][
            "test_macro_f1"
        ]["mean"],
        "manifest_sha256": sha256_file(output / "manifest.json"),
    }


def verify_multiseed_summary(
    *,
    runs_workspace: Path,
    dataset_workspace: Path,
    workspace: Path,
    config_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        summary_bytes, csv_bytes, manifest_bytes, summary = _build_outputs(
            runs_workspace=runs_workspace,
            dataset_workspace=dataset_workspace,
            config_path=config_path,
        )
    except (MultiSeedError, FileNotFoundError, KeyError, TypeError, ValueError) as exc:
        return {
            "status": "failed",
            "workspace": str(workspace),
            "error_count": 1,
            "errors": [str(exc)],
            "verification_recomputed_sources": False,
        }
    expected = {
        "summary.json": summary_bytes,
        "runs.csv": csv_bytes,
        "manifest.json": manifest_bytes,
    }
    for name, content in expected.items():
        path = workspace / name
        if not path.is_file():
            errors.append(f"missing multi-seed summary artifact: {name}")
        elif path.read_bytes() != content:
            errors.append(f"multi-seed summary artifact mismatch: {name}")
    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "experiment_id": summary["experiment_id"],
        "seed_count": summary["seed_count"],
        "run_count": summary["run_count"],
        "error_count": len(errors),
        "errors": errors,
        "verification_recomputed_sources": not errors,
        "verification_recomputed_statistics": not errors,
    }
