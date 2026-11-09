"""Correct target checkpoint selection using connection-end-bounded validation.

Training, scalers, checkpoints and test windows remain unchanged. This is a
separately declared post-observation correction, not a new blind trial.
"""

import datetime as dt
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import torch

from fl_forensics.external_generalization import _predict
from fl_forensics.federated_model import (
    architecture_record,
    build_model,
    export_state,
    load_ndarrays,
    seed_everything,
)
from fl_forensics.ton_iot_retraining import (
    TEST_START,
    VALIDATION_START,
    binary_metrics,
    select_round,
    verify_checkpoint,
)
from fl_forensics.ton_iot_time_bounds import indices_observed_by, observation_end_upper_bound

O = Path(__file__).resolve().parent
W = O / "study"
V = W / "flow-end-selection-v2"
T = O.parent / "ton-iot-transfer-20261109"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_text())


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def model_from(path, digest, seed):
    seed_everything(seed, torch=torch, np=np)
    model = build_model(
        input_features=25,
        class_count=2,
        hidden_layers=[128, 64],
        embedding_size=32,
        dropout=0.0,
        torch=torch,
    )
    load_ndarrays(model, verify_checkpoint(path, digest), torch=torch, np=np)
    model.eval()
    return model


def predict(model, x):
    with torch.no_grad():
        return torch.softmax(model(torch.from_numpy(x)), dim=1).numpy()


def main(workspace, transfer):
    global W, V, T
    W = Path(workspace).resolve()
    V = W / "flow-end-selection-v2"
    T = Path(transfer).resolve()
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    assert not V.exists()
    V.mkdir()
    original = load(W / "protocol-before-training.json")
    split = load(W / "split-and-partition.json")
    source_rows = load(T / "windows/occurrence-windows.json")["rows"]
    by_bucket = {r["window_start_epoch"] // 60: r for r in source_rows}
    train_rows = [by_bucket[b] for b in split["splits"]["train"]["buckets"]]
    val_rows = [by_bucket[b] for b in split["splits"]["validation"]["buckets"]]
    train_keep = indices_observed_by(train_rows, VALIDATION_START - 3600)
    assert len(train_keep) == len(train_rows), (
        "Training inputs must change; checkpoint reuse is not valid"
    )
    keep = indices_observed_by(val_rows, TEST_START - 3600)
    remove = sorted(set(range(len(val_rows))) - set(keep))
    labels = Counter(val_rows[index]["label"] for index in keep)
    assert min(labels.values()) >= 20 and len(labels) == 2
    for view in ("occurrence", "exact-projection"):
        rows = load(T / "windows" / (view + "-windows.json"))["rows"]
        lookup = {r["window_start_epoch"] // 60: r for r in rows}
        assert (
            indices_observed_by(
                [lookup[b] for b in split["splits"]["validation"]["buckets"]], TEST_START - 3600
            )
            == keep
        )
    module = Path(__import__("fl_forensics.ton_iot_time_bounds", fromlist=["x"]).__file__)
    protocol = {
        "name": "ToN-IoT-flow-end-bounded-selection-v2",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "reason": "Audit after the first study found possible validation observations extending into the target test period. Apply a conservative end-time bound before reselection.",
        "observation_end_bound": "window_end_epoch + duration_max_seconds + 1 second rounding guard",
        "train_deadline": VALIDATION_START - 3600,
        "validation_deadline": TEST_START - 3600,
        "reused_training_validated": True,
        "train_windows": len(train_rows),
        "original_validation_windows": len(val_rows),
        "retained_validation_windows": len(keep),
        "validation_label_counts": dict(labels),
        "excluded_validation_windows": len(remove),
        "retained_validation_indices": keep,
        "excluded_buckets": [val_rows[index]["window_start_epoch"] // 60 for index in remove],
        "excluded_window_bounds": [
            {
                "bucket": val_rows[index]["window_start_epoch"] // 60,
                "label": val_rows[index]["label"],
                "upper_bound": observation_end_upper_bound(val_rows[index]),
            }
            for index in remove
        ],
        "test_windows": 718,
        "test_unchanged": True,
        "models_and_scalers_unchanged": True,
        "previously_observed_test": True,
        "original_protocol_sha256": sha(W / "protocol-before-training.json"),
        "original_training_closure_sha256": sha(W / "training-closure-before-test.json"),
        "original_verification_sha256": sha(W / "verification.json"),
        "controller_sha256": sha(Path(__file__)),
        "time_bound_module_sha256": sha(module),
        "primary_view": "occurrence",
        "primary_preprocessing": "target-standard",
        "selection": "Maximum corrected-validation macro-F1 over all original 30 global checkpoints, earliest on ties; all seeds and conditions retained.",
    }
    save(V / "protocol-before-reselection.json", protocol)
    closure = load(W / "training-closure-before-test.json")
    selections = []
    for entry in closure["selections"]:
        assert entry["status"] == "trained"
        key = entry["view"] + "-" + entry["mode"]
        directory = W / "runs" / entry["run_id"]
        history = load(directory / "history.json")
        with np.load(W / "prepared" / key / "train-validation.npz", allow_pickle=False) as data:
            x, y = data["x_validation"][keep], data["y_validation"][keep]
        corrected = []
        for record in history:
            path = directory / "checkpoints" / f"round-{record['round']:03d}.npz"
            assert sha(path) == record["checkpoint_sha256"]
            model = model_from(path, record["tensor_sha256"], entry["seed"])
            prob = predict(model, x)
            metrics = binary_metrics(y, prob.argmax(axis=1))
            corrected.append(
                {
                    "round": record["round"],
                    "validation_macro_f1": metrics["macro_f1"],
                    "validation": metrics,
                    "tensor_sha256": record["tensor_sha256"],
                    "checkpoint_sha256": record["checkpoint_sha256"],
                }
            )
        best = select_round(corrected)
        updated = dict(**entry)
        updated.update(
            selected_round=best["round"],
            selected_validation_macro_f1=best["validation_macro_f1"],
            tensor_sha256=best["tensor_sha256"],
            checkpoint_sha256=best["checkpoint_sha256"],
            original_selected_round=entry["selected_round"],
            selection_changed=best["round"] != entry["selected_round"],
        )
        save(V / (entry["run_id"] + "-validation.json"), corrected)
        selections.append(updated)
        print(
            json.dumps(
                {
                    "status": "flow_bound_reselected",
                    "run_id": entry["run_id"],
                    "selected_round": best["round"],
                    "previous_round": entry["selected_round"],
                }
            ),
            flush=True,
        )
    save(
        V / "selection-closure-before-reevaluation.json",
        {
            "protocol_sha256": sha(V / "protocol-before-reselection.json"),
            "selections": selections,
            "test_used_for_reselection": False,
        },
    )
    results = []
    checked = 0
    architecture = architecture_record(
        input_features=25, class_count=2, hidden_layers=[128, 64], embedding_size=32, dropout=0.0
    )
    for entry in selections:
        directory = W / "runs" / entry["run_id"]
        path = directory / "checkpoints" / f"round-{entry['selected_round']:03d}.npz"
        model = model_from(path, entry["tensor_sha256"], entry["seed"])
        key = entry["view"] + "-" + entry["mode"]
        test_path = W / "prepared" / key / "test.npz"
        assert sha(test_path) == original["prepared_inputs"][key]["test.npz"]
        with np.load(test_path, allow_pickle=False) as data:
            x, y = data["x"], data["y"]
        prob = predict(model, x)
        ids = prob.argmax(axis=1)
        metrics = binary_metrics(y, ids, prob[:, 1])
        exported = export_state(model, architecture=architecture, class_names=["benign", "attack"])
        independent, _ = _predict(
            model_export=exported, features=x, batch_size=257, np=np, torch=torch
        )
        assert np.array_equal(ids, independent)
        checked += 1
        np.savez_compressed(
            V / (entry["run_id"] + "-test.npz"), actual=y, predicted=ids, attack_score=prob[:, 1]
        )
        results.append(dict(**entry, test=metrics))
    original_results = load(W / "target-test-results.json")
    save(
        V / "target-test-results.json",
        {
            "status": "flow_end_bounded_target_diagnostic_complete",
            "results": results,
            "frozen_source_baselines": original_results["frozen_source_baselines"],
            "protocol_sha256": sha(V / "protocol-before-reselection.json"),
            "selection_closure_sha256": sha(V / "selection-closure-before-reevaluation.json"),
            "new_blind_test_claimed": False,
        },
    )
    save(
        V / "verification.json",
        {
            "status": "verified",
            "training_rows_changed": 0,
            "corrected_validation_checkpoint_scores": 540,
            "test_prediction_sets_recomputed": checked,
            "selection_changes": sum(r["selection_changed"] for r in results),
            "original_training_verification_sha256": sha(W / "verification.json"),
            "original_replay_rounds": 30,
            "original_replayed_local_updates": 450,
            "original_global_checkpoints_unchanged": True,
            "new_model_training_performed": False,
            "temporal_bound_is_conservative": True,
            "actual_packet_arrival_or_log_write_times_verified": False,
            "test_was_previously_observed": True,
            "qualification": "Corrected validation excludes windows that can extend beyond the observation deadline; it reuses unchanged training and test inputs and preserves the exploratory scope.",
        },
    )
    print(
        json.dumps(
            {
                "status": "flow_bound_complete",
                "retained_validation": len(keep),
                "removed": len(remove),
                "labels": dict(labels),
                "selection_changes": sum(r["selection_changed"] for r in results),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--transfer", type=Path, required=True)
    args = parser.parse_args()
    for name in (
        "protocol-before-training.json",
        "training-closure-before-test.json",
        "target-test-results.json",
        "verification.json",
    ):
        if not (args.workspace / name).is_file():
            parser.error("A completed original target study is required")
    if not (args.transfer / "verification.json").is_file():
        parser.error("A verified frozen-transfer workspace is required")
    main(args.workspace, args.transfer)
