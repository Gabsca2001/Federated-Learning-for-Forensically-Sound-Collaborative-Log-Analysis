"""Prespecified, low-storage target-domain FedAvg diagnosis; no live admission."""

import argparse
import datetime as dt
import hashlib
import json
import math
import shutil
import time
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from flwr.server.strategy.aggregate import aggregate

from fl_forensics.class_weighting import compute_class_weights
from fl_forensics.federated_model import (
    build_model,
    load_ndarrays,
    model_to_ndarrays,
    seed_everything,
    train_local,
)
from fl_forensics.preprocessing import FEATURE_NAMES
from fl_forensics.ton_iot_retraining import (
    MODES,
    SEEDS,
    binary_metrics,
    fit_transform,
    iid_partitions,
    select_round,
    split_rows,
    tensor_digest,
    transform,
    verify_checkpoint,
)

R = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def load(path):
    return json.loads(path.read_text())


def new_model(seed):
    seed_everything(seed, torch=torch, np=np)
    return build_model(
        input_features=25,
        class_count=2,
        hidden_layers=[128, 64],
        embedding_size=32,
        dropout=0.0,
        torch=torch,
    )


def predict(model, features):
    model.eval()
    pieces = []
    with torch.no_grad():
        for offset in range(0, len(features), 1024):
            pieces.append(
                torch.softmax(
                    model(
                        torch.from_numpy(
                            np.asarray(features[offset : offset + 1024], dtype=np.float32)
                        )
                    ),
                    dim=1,
                ).numpy()
            )
    result = np.concatenate(pieces)
    if not np.isfinite(result).all():
        raise ValueError("Nonfinite prediction")
    return result


def save_arrays(path, arrays):
    np.savez_compressed(path, **{f"p{index:02d}": array for index, array in enumerate(arrays)})


def check_protocol(workspace):
    protocol = load(workspace / "protocol-before-training.json")
    module = Path(__import__("fl_forensics.ton_iot_retraining", fromlist=["x"]).__file__)
    assert sha(Path(__file__)) == protocol["runner_sha256"]
    assert sha(module) == protocol["module_sha256"]
    for name, expected in protocol["implementation_sha256"].items():
        assert sha(R / "src/fl_forensics" / name) == expected
    assert sha(workspace / "split-and-partition.json") == protocol["split_partition_sha256"]
    return protocol


def prepare(workspace, transfer):
    if workspace.exists():
        raise ValueError("Refuse to reuse study directory")
    if shutil.disk_usage(workspace.parent).free < 6 * 1024**3:
        raise ValueError("Preserve six GiB free")
    prior = load(transfer / "transfer-results.json")
    verified = load(transfer / "verification.json")
    assert verified["status"] == "verified"
    assert sha(transfer / "transfer-results.json") == verified["transfer_results_sha256"]
    for view in ("occurrence", "exact-projection"):
        assert (
            sha(transfer / "windows" / (view + "-windows.json"))
            == prior["results"][view]["window_dataset_sha256"]
        )
    assert sha(transfer / "frozen-scaler.json") == prior["scaler_sha256"]
    workspace.mkdir()
    source_scaler = load(transfer / "frozen-scaler.json")
    views = {
        view: load(transfer / "windows" / (view + "-windows.json"))
        for view in ("occurrence", "exact-projection")
    }
    assert all(value["feature_names"] == FEATURE_NAMES for value in views.values())
    groups = {view: split_rows(value["rows"]) for view, value in views.items()}
    base = groups["occurrence"]
    for split in base:
        assert [(r["window_start_epoch"], r["label"]) for r in base[split]] == [
            (r["window_start_epoch"], r["label"]) for r in groups["exact-projection"][split]
        ]
    labels = np.asarray([int(r["label"] == "attack") for r in base["train"]])
    partitions = iid_partitions(labels)
    class_weights = compute_class_weights(
        [r["label"] for r in base["train"]], strategy="global-sqrt-balanced-training-only"
    )
    split_summary = {
        split: {
            "rows": len(rows),
            "label_counts": dict(Counter(r["label"] for r in rows)),
            "buckets": [r["window_start_epoch"] // 60 for r in rows],
            "dates": sorted({r["capture_id"] for r in rows}),
        }
        for split, rows in base.items()
    }
    assert (
        split_summary["validation"]["label_counts"]["benign"] >= 20
        and split_summary["test"]["label_counts"]["benign"] >= 20
    )
    save(
        workspace / "split-and-partition.json",
        {
            "splits": split_summary,
            "train_indices_by_client": partitions,
            "class_weights": class_weights,
        },
    )
    inputs = {}
    for view, split in groups.items():
        raw = {
            name: np.asarray([r["features"] for r in split[name]], dtype=np.float64)
            for name in ("train", "validation", "test")
        }
        y = {
            name: np.asarray([int(r["label"] == "attack") for r in split[name]], dtype=np.int64)
            for name in raw
        }
        for mode in MODES:
            key = view + "-" + mode
            spec = fit_transform(raw["train"], mode, source_scaler)
            directory = workspace / "prepared" / key
            directory.mkdir(parents=True)
            save(directory / "transform.json", spec)
            scaled = {name: transform(value, spec) for name, value in raw.items()}
            np.savez_compressed(
                directory / "train-validation.npz",
                x_train=scaled["train"],
                y_train=y["train"],
                x_validation=scaled["validation"],
                y_validation=y["validation"],
            )
            np.savez_compressed(directory / "test.npz", x=scaled["test"], y=y["test"])
            inputs[key] = {
                name: sha(directory / name)
                for name in ("transform.json", "train-validation.npz", "test.npz")
            }
    module = Path(__import__("fl_forensics.ton_iot_retraining", fromlist=["x"]).__file__)
    protocol = {
        "name": "ToN-IoT-target-domain-FedAvg-diagnostic-v1",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "primary_view": "occurrence",
        "primary_preprocessing": "target-standard",
        "views": list(views),
        "modes": list(MODES),
        "seeds": list(SEEDS),
        "input_dataset_sha256": {
            view: sha(transfer / "windows" / (view + "-windows.json")) for view in views
        },
        "prior_transfer_results_sha256": sha(transfer / "transfer-results.json"),
        "source_scaler_sha256": sha(transfer / "frozen-scaler.json"),
        "split": "Train through 27 April 2019, validation on 28 April and test on 29 April UTC; remove the hour preceding each next split boundary.",
        "train_rows": split_summary["train"]["rows"],
        "validation_rows": split_summary["validation"]["rows"],
        "test_rows": split_summary["test"]["rows"],
        "preprocessing_fit": "Only target training inputs; source-standard reuses the original Data24 training-only scaler.",
        "architecture": {
            "input_features": 25,
            "hidden_layers": [128, 64],
            "embedding_size": 32,
            "outputs": 2,
            "dropout": 0.0,
        },
        "training": {
            "rounds": 30,
            "local_epochs": 2,
            "batch_size": 128,
            "learning_rate": 0.001,
            "optimizer": "Adam reset each client/round",
            "aggregation": "Existing Flower FedAvg aggregate; sample-count weights",
            "clients": 15,
            "client_partition": "Fixed seed-341593 stratified IID round-robin",
            "class_weighting": "global-sqrt-balanced-training-only",
            "device": "CPU",
        },
        "selection": "Maximum binary validation macro-F1 over 30 rounds, earliest round on ties; each seed retained; target-standard remains primary.",
        "evaluation": "Close all checkpoint selections before target test evaluation; report all 18 runs and all failures. No test-driven regime or seed selection.",
        "binary_prediction": "Argmax of the new two-output head; no tuned threshold.",
        "previously_observed_test": "The date was part of the earlier frozen-model transfer. This is an exploratory follow-up with target-fitting/selection isolation, not a new blind external test.",
        "isolation_limits": "Day/time disjoint with a one-hour boundary purge; hosts and attack infrastructure may recur. Only 30 benign test windows; repeated seeds are not new test populations.",
        "profile": "Numerical clean-client IID FedAvg diagnostic; attack-labelled traffic is supervised task data, not Byzantine update poisoning. No TPM admission or DBA replay.",
        "storage": "Compressed global checkpoints only; local tensor digests and seeds retained for reproduction. No raw-data copies or local tensor archive.",
        "source_model_difference": "New models train from scratch with the same encoder architecture and a two-class head; this is not fine-tuning the six-class source classifier.",
        "prepared_inputs": inputs,
        "runner_sha256": sha(Path(__file__)),
        "module_sha256": sha(module),
        "implementation_sha256": {
            name: sha(R / "src/fl_forensics" / name)
            for name in ("federated_model.py", "class_weighting.py", "robust_preprocessing.py")
        },
        "split_partition_sha256": sha(workspace / "split-and-partition.json"),
        "manuscript_changed": False,
    }
    save(workspace / "protocol-before-training.json", protocol)
    print(
        json.dumps(
            {
                k: protocol[k]
                for k in (
                    "name",
                    "train_rows",
                    "validation_rows",
                    "test_rows",
                    "modes",
                    "seeds",
                    "profile",
                )
            },
            indent=2,
        ),
        flush=True,
    )


def train(workspace):
    protocol = check_protocol(workspace)
    split = load(workspace / "split-and-partition.json")
    partitions = split["train_indices_by_client"]
    weights = split["class_weights"]
    selections = []
    for view in protocol["views"]:
        for mode in MODES:
            key = view + "-" + mode
            data_dir = workspace / "prepared" / key
            assert (
                sha(data_dir / "train-validation.npz")
                == protocol["prepared_inputs"][key]["train-validation.npz"]
            )
            with np.load(data_dir / "train-validation.npz", allow_pickle=False) as data:
                x_train, y_train = data["x_train"], data["y_train"]
                x_val, y_val = data["x_validation"], data["y_validation"]
            rows = [
                {"features": features.tolist(), "label": "attack" if label else "benign"}
                for features, label in zip(x_train, y_train, strict=True)
            ]
            for seed in SEEDS:
                run_id = key + "-s" + str(seed)
                directory = workspace / "runs" / run_id
                directory.mkdir(parents=True, exist_ok=False)
                (directory / "checkpoints").mkdir()
                model = new_model(seed)
                history = []
                previous = "0" * 64
                started = time.monotonic()
                try:
                    for round_number in range(1, 31):
                        base = model_to_ndarrays(model, np=np)
                        updates = []
                        client_refs = []
                        for client, indices in enumerate(partitions):
                            local = new_model(seed)
                            load_ndarrays(local, base, torch=torch, np=np)
                            client_seed = seed + round_number * 10000 + client
                            trained = train_local(
                                model=local,
                                rows=[rows[index] for index in indices],
                                class_names=["benign", "attack"],
                                class_weights=weights,
                                epochs=2,
                                batch_size=128,
                                learning_rate=0.001,
                                seed=client_seed,
                                device_name="cpu",
                                torch=torch,
                                np=np,
                            )
                            if not math.isfinite(trained["train_loss"]):
                                raise ValueError("Nonfinite local loss")
                            arrays = model_to_ndarrays(local, np=np)
                            digest = tensor_digest(arrays)
                            updates.append((arrays, len(indices)))
                            client_refs.append(
                                {
                                    "client": client,
                                    "examples": len(indices),
                                    "seed": client_seed,
                                    "tensor_sha256": digest,
                                }
                            )
                        averaged = aggregate(updates)
                        tensor = tensor_digest(averaged)
                        load_ndarrays(model, averaged, torch=torch, np=np)
                        probability = predict(model, x_val)
                        metrics = binary_metrics(y_val, probability.argmax(axis=1))
                        checkpoint = directory / "checkpoints" / f"round-{round_number:03d}.npz"
                        save_arrays(checkpoint, averaged)
                        record = {
                            "round": round_number,
                            "validation_macro_f1": metrics["macro_f1"],
                            "validation": metrics,
                            "tensor_sha256": tensor,
                            "checkpoint_sha256": sha(checkpoint),
                            "previous_round_sha256": previous,
                            "client_updates": client_refs,
                        }
                        previous = hashlib.sha256(
                            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                        ).hexdigest()
                        record["round_sha256"] = previous
                        history.append(record)
                    best = select_round(history)
                    entry = {
                        "status": "trained",
                        "run_id": run_id,
                        "view": view,
                        "mode": mode,
                        "seed": seed,
                        "selected_round": best["round"],
                        "selected_validation_macro_f1": best["validation_macro_f1"],
                        "tensor_sha256": best["tensor_sha256"],
                        "checkpoint_sha256": best["checkpoint_sha256"],
                        "completed_rounds": 30,
                        "training_seconds": time.monotonic() - started,
                    }
                except (ValueError, FloatingPointError) as error:
                    entry = {
                        "status": "numerical_failure",
                        "run_id": run_id,
                        "view": view,
                        "mode": mode,
                        "seed": seed,
                        "completed_rounds": len(history),
                        "reason": str(error),
                        "test_evaluated": False,
                    }
                save(directory / "history.json", history)
                save(directory / "selection.json", entry)
                entry["history_sha256"] = sha(directory / "history.json")
                entry["selection_sha256"] = sha(directory / "selection.json")
                selections.append(entry)
                print(
                    json.dumps(
                        {
                            "status": entry["status"],
                            "run_id": run_id,
                            "selected_round": entry.get("selected_round"),
                            "validation_macro_f1": entry.get("selected_validation_macro_f1"),
                        }
                    ),
                    flush=True,
                )
    save(
        workspace / "training-closure-before-test.json",
        {
            "protocol_sha256": sha(workspace / "protocol-before-training.json"),
            "closed_utc": dt.datetime.now(dt.UTC).isoformat(),
            "run_count": len(selections),
            "selections": selections,
            "test_results_used": False,
        },
    )


def evaluate(workspace, transfer):
    closure = load(workspace / "training-closure-before-test.json")
    protocol = check_protocol(workspace)
    assert (
        closure["protocol_sha256"] == sha(workspace / "protocol-before-training.json")
        and closure["run_count"] == 18
    )
    results = []
    labels_reference = None
    for entry in closure["selections"]:
        if entry["status"] != "trained":
            results.append(entry)
            continue
        directory = workspace / "runs" / entry["run_id"]
        assert sha(directory / "selection.json") == entry["selection_sha256"]
        history = load(directory / "history.json")
        assert sha(directory / "history.json") == entry["history_sha256"]
        best = select_round(history)
        assert best["round"] == entry["selected_round"]
        checkpoint = directory / "checkpoints" / f"round-{entry['selected_round']:03d}.npz"
        assert sha(checkpoint) == entry["checkpoint_sha256"]
        arrays = verify_checkpoint(checkpoint, entry["tensor_sha256"])
        model = new_model(entry["seed"])
        load_ndarrays(model, arrays, torch=torch, np=np)
        key = entry["view"] + "-" + entry["mode"]
        test_path = workspace / "prepared" / key / "test.npz"
        assert sha(test_path) == protocol["prepared_inputs"][key]["test.npz"]
        with np.load(test_path, allow_pickle=False) as data:
            x, y = data["x"], data["y"]
        if labels_reference is None:
            labels_reference = y.copy()
        else:
            assert np.array_equal(y, labels_reference)
        probability = predict(model, x)
        predicted = probability.argmax(axis=1)
        metrics = binary_metrics(y, predicted, probability[:, 1])
        np.savez_compressed(
            directory / "test-predictions.npz",
            actual=y,
            predicted=predicted,
            attack_score=probability[:, 1],
        )
        result = dict(
            **entry, test=metrics, prediction_file_sha256=sha(directory / "test-predictions.npz")
        )
        results.append(result)
        print(
            json.dumps(
                {
                    "status": "test_evaluated",
                    "run_id": entry["run_id"],
                    "balanced_accuracy": metrics["balanced_accuracy"],
                    "fpr": metrics["false_positive_rate"],
                }
            ),
            flush=True,
        )
    baseline = []
    for view in protocol["views"]:
        previous = load(transfer / (view + "-predictions.json"))
        test = [r for r in previous if r["capture_id"] == "2019-04-29"]
        baseline.append(
            {
                "view": view,
                "scope": "Frozen six-class source model restricted to the same target test date",
                "test": binary_metrics(
                    [r["actual_binary_label"] for r in test],
                    [r["predicted_binary_label"] for r in test],
                    [r["attack_score"] for r in test],
                ),
            }
        )
    save(
        workspace / "target-test-results.json",
        {
            "status": "target_retraining_evaluated",
            "protocol_sha256": sha(workspace / "protocol-before-training.json"),
            "training_closure_sha256": sha(workspace / "training-closure-before-test.json"),
            "results": results,
            "frozen_source_baselines": baseline,
            "target_test_used_for_fitting_or_selection": False,
            "blind_external_test_claimed": False,
            "new_TPM_or_DBA_campaign": False,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["prepare", "train", "evaluate"])
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--transfer", type=Path, required=True)
    args = parser.parse_args()
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    {
        "prepare": lambda: prepare(args.workspace, args.transfer),
        "train": lambda: train(args.workspace),
        "evaluate": lambda: evaluate(args.workspace, args.transfer),
    }[args.phase]()
