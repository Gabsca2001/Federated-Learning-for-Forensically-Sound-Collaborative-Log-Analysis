"""A fixed validation-selected F1 study; all candidates and failures retained."""

import argparse
import datetime as dt
import hashlib
import json
import platform
import time
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np
import sklearn
import torch
from flwr.server.strategy.aggregate import aggregate
from scipy.special import expit
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from threadpoolctl import threadpool_limits

from fl_forensics.external_generalization import _model_from_export
from fl_forensics.federated_model import (
    build_model,
    load_ndarrays,
    model_to_ndarrays,
    seed_everything,
)
from fl_forensics.ton_iot_calibration import fit_macro_threshold, metrics
from fl_forensics.ton_iot_retraining import SEEDS, tensor_digest, verify_checkpoint

R = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads(path.read_text())


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def network(kind, seed):
    seed_everything(seed, torch=torch, np=np)
    if kind == "linear":
        return torch.nn.Linear(25, 2)
    return build_model(
        input_features=25,
        class_count=2,
        hidden_layers=[64, 32] if kind == "small" else [128, 64],
        embedding_size=16 if kind == "small" else 32,
        dropout=0.1 if kind == "small" else 0.0,
        torch=torch,
    )


def score(model, x):
    model.eval()
    with torch.no_grad():
        result = torch.softmax(
            model(torch.from_numpy(np.asarray(x, dtype=np.float32))), dim=1
        ).numpy()[:, 1]
    if not np.isfinite(result).all():
        raise ValueError("Nonfinite score")
    return result


def fit_local(model, x, y, weights, seed, kind):
    seed_everything(seed, torch=torch, np=np)
    model.train()
    generator = torch.Generator().manual_seed(seed)
    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(torch.from_numpy(x), torch.from_numpy(y)),
        batch_size=128,
        shuffle=True,
        generator=generator,
        num_workers=0,
    )
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=0.001, weight_decay=0.01 if kind == "linear" else 0.001
    )
    criterion = torch.nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32))
    for _ in range(2):
        for batch, labels in loader:
            optimizer.zero_grad()
            loss = criterion(model(batch), labels)
            if not torch.isfinite(loss):
                raise ValueError("Nonfinite local loss")
            loss.backward()
            optimizer.step()


def main(workspace, parent, transfer):
    if workspace.exists():
        raise ValueError("Fresh study workspace required")
    import shutil

    if shutil.disk_usage(workspace.parent).free < 6 * 1024**3:
        raise ValueError("Preserve six GiB free")
    workspace.mkdir()
    correction = parent / "flow-end-selection-v2"
    corrected = load(correction / "target-test-results.json")
    assert (
        sha(correction / "selection-closure-before-reevaluation.json")
        == corrected["selection_closure_sha256"]
    )
    keep = load(correction / "protocol-before-reselection.json")["retained_validation_indices"]
    parent_protocol = load(parent / "protocol-before-training.json")
    split = load(parent / "split-and-partition.json")
    assert load(correction / "verification.json")["status"] == "verified"
    modes = ["target-standard", "target-log1p"]
    protocol = {
        "name": "ToN-IoT-validation-selected-F1-diagnostic-v1",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "primary_objective": "Validation macro-F1 with benign and attack F1 both reported; test never used for choosing candidates, thresholds or seed.",
        "f1_goal": "macro-F1 >= .85 and both class F1 >= .80",
        "low_alert_goal": "FPR <= .10 and attack recall >= .90, reported separately.",
        "candidates": "18 parent federated checkpoints, 12 new regularized federated runs, 16 centralized references and 2 frozen-source score controls; 48 total.",
        "threshold_rule": "Strict score > threshold; maximize corrected validation macro-F1, ties fewer false positives then higher threshold.",
        "federated_selection": "Choose family by mean calibrated validation macro-F1 across three seeds in the occurrence view; report all seeds and both views.",
        "central_selection": "Choose reference family by calibrated validation macro-F1 in the occurrence view, separately from federated candidates.",
        "new_federated": {
            "profiles": [
                "small encoder [64,32]/embedding16/dropout .1/AdamW decay .001",
                "linear 25-to-2/AdamW decay .01",
            ],
            "mode": "target-log1p",
            "seeds": list(SEEDS),
            "rounds": 30,
            "clients": 15,
            "local_epochs": 2,
            "batch_size": 128,
            "learning_rate": 0.001,
            "checkpoint": "Maximum uncalibrated validation macro-F1, earliest tie; threshold fit after checkpoint selection.",
        },
        "centralized": {
            "modes": modes,
            "seed": 341593,
            "models": {
                "logistic": "C=1, lbfgs, max_iter=3000",
                "svm": "RBF C=10, gamma=scale, expit(margin) ranking score",
                "histogram": "150 rounds, learning_rate=.05, 15 leaves, l2=1, early_stopping=False",
                "extra_trees": "256 trees, min leaf=2, max_features=1.0, one CPU thread",
            },
        },
        "train_weights": "Parent training-only global sqrt-balanced weights; same training and corrected-validation rows.",
        "existing_test_scope": "The same 718-window date has been observed before. Exploratory follow-up, not a new blind test. All choices close before this study evaluates it.",
        "scope": "Honest-client numerical IID federated training and separate centralized references. No TPM or Byzantine campaign.",
        "parent_protocol_sha256": sha(parent / "protocol-before-training.json"),
        "corrected_selection_sha256": sha(
            correction / "selection-closure-before-reevaluation.json"
        ),
        "source_scaler_sha256": sha(transfer / "frozen-scaler.json"),
        "source_model_sha256": sha(transfer / "frozen-model.json"),
        "runner_sha256": sha(Path(__file__)),
        "calibration_module_sha256": sha(
            Path(__import__("fl_forensics.ton_iot_calibration", fromlist=["x"]).__file__)
        ),
        "python": platform.python_version(),
        "torch": torch.__version__,
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "manuscript_changed": False,
    }
    save(workspace / "protocol-before-fitting.json", protocol)
    partitions = split["train_indices_by_client"]
    weights = [split["class_weights"]["benign"], split["class_weights"]["attack"]]
    prepared = {}
    candidates = []
    objects = {}
    failures = []
    for view in ("occurrence", "exact-projection"):
        for mode in ["source-standard", *modes]:
            key = view + "-" + mode
            path = parent / "prepared" / key / "train-validation.npz"
            assert sha(path) == parent_protocol["prepared_inputs"][key]["train-validation.npz"]
            with np.load(path, allow_pickle=False) as data:
                prepared[key] = (
                    data["x_train"],
                    data["y_train"],
                    data["x_validation"][keep],
                    data["y_validation"][keep],
                )

    def close_candidate(
        identifier, family, scope, view, mode, seed, val_scores, default=0.5, extra=None
    ):
        _, _, _, y = prepared[view + "-" + mode]
        fitted = fit_macro_threshold(y, val_scores)
        entry = {
            "id": identifier,
            "family": family,
            "scope": scope,
            "view": view,
            "mode": mode,
            "seed": seed,
            "threshold": fitted["threshold"],
            "validation": fitted["validation"],
            "validation_default": metrics(y, val_scores, default),
            "metadata": extra or {},
        }
        candidates.append(entry)
        np.savez_compressed(
            workspace / (identifier + "-validation.npz"), actual=y, score=val_scores
        )
        print(
            json.dumps(
                {
                    "status": "candidate_closed",
                    "id": identifier,
                    "validation_macro_f1": entry["validation"]["macro_f1"],
                    "threshold": entry["threshold"],
                }
            ),
            flush=True,
        )

    # Reuse the end-time-corrected selected parent checkpoints without refitting them.
    for entry in corrected["results"]:
        key = entry["view"] + "-" + entry["mode"]
        x, y, xv, yv = prepared[key]
        model = network("legacy", entry["seed"])
        path = (
            parent
            / "runs"
            / entry["run_id"]
            / "checkpoints"
            / f"round-{entry['selected_round']:03d}.npz"
        )
        assert sha(path) == entry["checkpoint_sha256"]
        load_ndarrays(model, verify_checkpoint(path, entry["tensor_sha256"]), torch=torch, np=np)
        identifier = "legacy-" + entry["run_id"]
        family = "fedavg-legacy-" + entry["mode"]
        objects[identifier] = ("torch", model)
        close_candidate(
            identifier,
            family,
            "federated",
            entry["view"],
            entry["mode"],
            entry["seed"],
            score(model, xv),
            extra={
                "parent_run": entry["run_id"],
                "round": entry["selected_round"],
                "tensor_sha256": entry["tensor_sha256"],
            },
        )
    # New numerical federated profiles use the same training rows and 30-round budget.
    for view in ("occurrence", "exact-projection"):
        key = view + "-target-log1p"
        x, y, xv, yv = prepared[key]
        for kind in ("small", "linear"):
            for seed in SEEDS:
                identifier = f"fedavg-{kind}-{view}-s{seed}"
                directory = workspace / identifier
                directory.mkdir()
                model = network(kind, seed)
                history = []
                started = time.monotonic()
                try:
                    for round_number in range(1, 31):
                        base = model_to_ndarrays(model, np=np)
                        updates = []
                        for client, indices in enumerate(partitions):
                            local = network(kind, seed)
                            load_ndarrays(local, base, torch=torch, np=np)
                            fit_local(
                                local,
                                x[indices],
                                y[indices],
                                weights,
                                seed + round_number * 10000 + client,
                                kind,
                            )
                            arrays = model_to_ndarrays(local, np=np)
                            tensor_digest(arrays)
                            updates.append((arrays, len(indices)))
                        arrays = aggregate(updates)
                        digest = tensor_digest(arrays)
                        load_ndarrays(model, arrays, torch=torch, np=np)
                        values = score(model, xv)
                        quality = metrics(yv, values)
                        path = directory / f"round-{round_number:03d}.npz"
                        np.savez_compressed(path, **{f"p{i:02d}": a for i, a in enumerate(arrays)})
                        history.append(
                            {
                                "round": round_number,
                                "macro_f1": quality["macro_f1"],
                                "tensor_sha256": digest,
                                "checkpoint_sha256": sha(path),
                            }
                        )
                    selected = max(history, key=lambda r: (r["macro_f1"], -r["round"]))
                    path = directory / f"round-{selected['round']:03d}.npz"
                    load_ndarrays(
                        model,
                        verify_checkpoint(path, selected["tensor_sha256"]),
                        torch=torch,
                        np=np,
                    )
                    save(directory / "history.json", history)
                    objects[identifier] = ("torch", model)
                    close_candidate(
                        identifier,
                        "fedavg-" + kind + "-log1p",
                        "federated",
                        view,
                        "target-log1p",
                        seed,
                        score(model, xv),
                        extra={
                            "round": selected["round"],
                            "tensor_sha256": selected["tensor_sha256"],
                            "training_seconds": time.monotonic() - started,
                        },
                    )
                except (ValueError, FloatingPointError) as error:
                    failures.append(
                        {"id": identifier, "reason": str(error), "completed_rounds": len(history)}
                    )
                    save(directory / "failure.json", failures[-1])
    # Centralized references diagnose model capacity; they are never represented as federated defenses.
    for view in ("occurrence", "exact-projection"):
        for mode in modes:
            x, y, xv, yv = prepared[view + "-" + mode]
            sample_weights = np.asarray(weights)[y]
            models = {
                "logistic": LogisticRegression(C=1, max_iter=3000, solver="lbfgs"),
                "svm": SVC(C=10, kernel="rbf", gamma="scale", probability=False, cache_size=128),
                "histogram": HistGradientBoostingClassifier(
                    max_iter=150,
                    learning_rate=0.05,
                    max_leaf_nodes=15,
                    l2_regularization=1.0,
                    early_stopping=False,
                    random_state=341593,
                ),
                "extra_trees": ExtraTreesClassifier(
                    n_estimators=256,
                    min_samples_leaf=2,
                    max_features=1.0,
                    n_jobs=1,
                    random_state=341593,
                ),
            }
            for kind, model in models.items():
                identifier = f"central-{kind}-{mode}-{view}"
                started = time.monotonic()
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    model.fit(x, y, sample_weight=sample_weights)
                values = (
                    expit(model.decision_function(xv))
                    if kind == "svm"
                    else model.predict_proba(xv)[:, 1]
                )
                objects[identifier] = ("svm" if kind == "svm" else "sklearn", model)
                close_candidate(
                    identifier,
                    "central-" + kind + "-" + mode,
                    "centralized-reference",
                    view,
                    mode,
                    341593,
                    values,
                    extra={
                        "parameters": model.get_params(deep=False),
                        "training_seconds": time.monotonic() - started,
                        "warnings": [str(w.message) for w in caught],
                        "score_semantics": "expit of SVM margin, not a calibrated probability"
                        if kind == "svm"
                        else "classifier probability score",
                    },
                )
    # Frozen six-class source-score calibration is a separate diagnostic from argmax collapse.
    source_model = _model_from_export(load(transfer / "frozen-model.json"), np=np, torch=torch)
    source_model.eval()
    benign_index = load(transfer / "frozen-model.json")["class_names"].index("benign")
    for view in ("occurrence", "exact-projection"):
        xv = prepared[view + "-source-standard"][2]
        with torch.no_grad():
            values = (
                1.0
                - torch.softmax(source_model(torch.from_numpy(xv)), dim=1).numpy()[:, benign_index]
            )
        identifier = "frozen-score-" + view
        objects[identifier] = ("source", source_model)
        close_candidate(
            identifier,
            "frozen-score",
            "source-score-control",
            view,
            "source-standard",
            341593,
            values,
            extra={
                "score": "1 - six-class benign softmax; original argmax decisions are not overwritten"
            },
        )
    families = defaultdict(list)
    for entry in candidates:
        if entry["view"] == "occurrence":
            families[(entry["scope"], entry["family"])].append(entry["validation"]["macro_f1"])
    selected = {}
    for scope in ("federated", "centralized-reference", "source-score-control"):
        available = [
            (statistics_mean(values), family)
            for (role, family), values in families.items()
            if role == scope
        ]
        selected[scope] = max(available, key=lambda v: (v[0], v[1]))[1]
    save(
        workspace / "selection-and-calibration-closure-before-test.json",
        {
            "protocol_sha256": sha(workspace / "protocol-before-fitting.json"),
            "candidates": candidates,
            "failures": failures,
            "selected_families": selected,
            "test_results_used_for_choices": False,
        },
    )
    results = []
    # Test arrays are opened for scoring only after all candidates and choices have closed.
    for entry in candidates:
        path = parent / "prepared" / (entry["view"] + "-" + entry["mode"]) / "test.npz"
        assert (
            sha(path)
            == parent_protocol["prepared_inputs"][entry["view"] + "-" + entry["mode"]]["test.npz"]
        )
        with np.load(path, allow_pickle=False) as data:
            x, y = data["x"], data["y"]
        kind, model = objects[entry["id"]]
        if kind == "torch":
            values = score(model, x)
        elif kind == "source":
            with torch.no_grad():
                values = (
                    1.0 - torch.softmax(model(torch.from_numpy(x)), dim=1).numpy()[:, benign_index]
                )
        elif kind == "svm":
            values = expit(model.decision_function(x))
        else:
            values = model.predict_proba(x)[:, 1]
        np.savez_compressed(workspace / (entry["id"] + "-test.npz"), actual=y, score=values)
        results.append(
            dict(
                **entry,
                test=metrics(y, values, entry["threshold"]),
                test_default=metrics(y, values),
                selected_family=entry["family"] == selected[entry["scope"]],
            )
        )
    save(
        workspace / "test-results.json",
        {
            "status": "fixed_f1_study_complete",
            "protocol_sha256": sha(workspace / "protocol-before-fitting.json"),
            "closure_sha256": sha(workspace / "selection-and-calibration-closure-before-test.json"),
            "results": results,
            "failures": failures,
            "selected_families": selected,
            "new_blind_test_claimed": False,
            "operational_readiness_claimed": False,
        },
    )
    print(
        json.dumps(
            {
                "status": "study_complete",
                "candidates": len(candidates),
                "failures": len(failures),
                "selected_families": selected,
            },
            indent=2,
        ),
        flush=True,
    )


def statistics_mean(values):
    return float(sum(values) / len(values))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", type=Path, required=True)
    p.add_argument("--parent", type=Path, required=True)
    p.add_argument("--transfer", type=Path, required=True)
    args = p.parse_args()
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):
        main(args.workspace, args.parent, args.transfer)
