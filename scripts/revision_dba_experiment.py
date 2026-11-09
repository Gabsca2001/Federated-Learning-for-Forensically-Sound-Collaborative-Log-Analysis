"""Reproducible software-only DBA campaigns and common-input defense comparison.

Pilot/configuration selection uses validation only. Every common-input adapter
consumes the same stored local models. Live-gradient interpretations are separate
protocols and never use final Adam updates as if they were gradients.
"""

from __future__ import annotations

import argparse
import copy
import importlib.metadata
import json
import tempfile
from pathlib import Path

import numpy as np
import yaml

from fl_forensics.byzantine import aggregate_deltas, apply_delta, model_delta, update_indicators
from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.composite_admission import (
    build_indicator_references,
    calibrate_policy_thresholds,
    decide_admission_policies,
    score_statistical_indicators,
)
from fl_forensics.composite_admission_models import TrustSignal
from fl_forensics.crypto import (
    SoftwareECDSASigner,
    load_public_key,
    public_key_id,
    verify_digest_signature,
)
from fl_forensics.distributed_backdoor import (
    DistributedBackdoorPlan,
    apply_evaluation_trigger,
    poison_local_rows,
)
from fl_forensics.external_generalization import _predict
from fl_forensics.federated_model import (
    arrays_from_export,
    dependencies,
    evaluate_rows,
    export_state,
    train_local,
)
from fl_forensics.literature_baselines import (
    fedgradtrace_global_gradient,
    flame_aggregate,
    weidetect_aggregate,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.secure_round import _model_from_export
from fl_forensics.storage import write_once


def save(path, value):
    write_once(path, derived_json_bytes(value))


def signature(signer, digest):
    return {
        "key_id": signer.key_id,
        "value_b64": signer.sign_digest(digest),
        "trust_level": "software-development",
    }


def environment():
    return {
        name: importlib.metadata.version(name)
        for name in ("numpy", "torch", "flwr", "scikit-learn", "scipy")
    }


def read_pinned(path, expected):
    data = Path(path).read_bytes()
    if sha256_bytes(data) != expected:
        raise ValueError(f"changed pinned input: {path}")
    return json.loads(data)


def authenticate(workspace, expected):
    manifest = read_pinned(workspace / "manifest.json", expected)
    key = load_public_key((workspace / "experiment-authority.public.pem").read_bytes())
    assert manifest["core_digest"] == digest_object(manifest["core"])
    assert manifest["signature"]["key_id"] == public_key_id(key)
    assert verify_digest_signature(key, manifest["core_digest"], manifest["signature"]["value_b64"])
    actual = {p.relative_to(workspace).as_posix() for p in workspace.rglob("*") if p.is_file()}
    assert actual == {"manifest.json", *manifest["core"]["artifacts"]}
    for name, digest in manifest["core"]["artifacts"].items():
        target = workspace / name
        assert target.resolve().is_relative_to(workspace.resolve())
        assert sha256_file(target) == digest, name
    # Signatures authenticate experimental software identities, never TPM Quotes.
    for path in workspace.glob("rounds/*/signatures/*.json"):
        statement = json.loads(path.read_bytes())
        client = statement["core"]["client_id"]
        client_key = load_public_key(
            (workspace / "software-identities" / f"{client}.public.pem").read_bytes()
        )
        assert digest_object(statement["core"]) == statement["core_digest"]
        assert statement["signature"]["key_id"] == public_key_id(client_key)
        assert verify_digest_signature(
            client_key, statement["core_digest"], statement["signature"]["value_b64"]
        )
        update_path = (
            workspace / path.parent.parent.relative_to(workspace) / "updates" / f"{client}.json"
        )
        assert sha256_file(update_path) == statement["core"]["local_model_sha256"]
        round_record = json.loads((path.parent.parent / "round.json").read_bytes())
        assert statement["core"]["base_model_sha256"] == round_record["base_model_sha256"]
    return manifest


def model_with_arrays(template, arrays):
    result = copy.deepcopy(template)
    for parameter, array in zip(result["parameters"], arrays, strict=True):
        parameter["values"] = np.asarray(array, dtype=np.dtype(parameter["dtype"])).tolist()
    return result


def evaluate(model_export, rows, deps):
    np_dep, torch, _flwr, _sklearn, _aggregate, accuracy, confusion, precision_recall = deps
    return evaluate_rows(
        model=_model_from_export(model_export, torch=torch, np=np_dep),
        rows=rows,
        class_names=model_export["class_names"],
        batch_size=1024,
        torch=torch,
        np=np_dep,
        accuracy_score=accuracy,
        confusion_matrix=confusion,
        precision_recall_fscore_support=precision_recall,
    )


def predict(model_export, rows, deps):
    np_dep, torch, *_ = deps
    ids, confidence = _predict(
        model_export=model_export,
        features=np.asarray([row["features"] for row in rows], dtype=np.float32),
        batch_size=1024,
        np=np_dep,
        torch=torch,
    )
    return [model_export["class_names"][int(index)] for index in ids], confidence


def outcomes(model_export, rows, plan, reference_correct, deps):
    original, _ = predict(model_export, rows, deps)
    eligible = [i for i, row in enumerate(rows) if row["label"] != plan.target_label]
    conditional = [i for i in eligible if reference_correct[i]]

    def success(triggered):
        predicted, _ = predict(model_export, triggered, deps)
        return {
            "target_predictions": sum(predicted[i] == plan.target_label for i in eligible),
            "non_target_denominator": len(eligible),
            "asr": sum(predicted[i] == plan.target_label for i in eligible) / len(eligible)
            if eligible
            else None,
            "reference_correct_target_predictions": sum(
                predicted[i] == plan.target_label for i in conditional
            ),
            "reference_correct_denominator": len(conditional),
            "reference_correct_asr": sum(predicted[i] == plan.target_label for i in conditional)
            / len(conditional)
            if conditional
            else None,
        }

    return {
        "clean": evaluate(model_export, rows, deps),
        "untriggered_non_target_to_target_rate": sum(
            original[i] == plan.target_label for i in eligible
        )
        / len(eligible)
        if eligible
        else None,
        "complete_trigger": success(apply_evaluation_trigger(rows=rows, plan=plan)),
        "component_triggers": {
            client: success(
                apply_evaluation_trigger(rows=rows, plan=plan, component_client_id=client)
            )
            for client in sorted(plan.client_components)
        },
    }


def full_gradient(model_export, rows, class_weights, deps):
    """Actual gradient of the full weighted local CE at the current global model."""
    np_dep, torch, *_ = deps
    model = _model_from_export(model_export, torch=torch, np=np_dep)
    model.train()
    classes = model_export["class_names"]
    features = torch.tensor([row["features"] for row in rows], dtype=torch.float32)
    labels = torch.tensor([classes.index(row["label"]) for row in rows], dtype=torch.long)
    criterion = torch.nn.CrossEntropyLoss(
        weight=torch.tensor([class_weights[name] for name in classes], dtype=torch.float32)
    )
    model.zero_grad()
    loss = criterion(model(features), labels)
    if not torch.isfinite(loss):
        raise ValueError("nonfinite live gradient loss")
    loss.backward()
    named = list(model.named_parameters())
    assert [name for name, _ in named] == [p["name"] for p in model_export["parameters"]]
    gradients = [parameter.grad.detach().cpu().numpy().copy() for _, parameter in named]
    if not all(np_dep.isfinite(value).all() for value in gradients):
        raise ValueError("nonfinite live gradient")
    return gradients, {
        "weighted_full_snapshot_loss": float(loss.item()),
        "actual_gradient_evaluations": 1,
        "optimizer_steps": 0,
    }


def execute(config, output):
    output.mkdir(parents=True, exist_ok=False)
    save(output / "protocol-before-training.json", config)
    partition_root = Path(config["partition_workspace"])
    partition = read_pinned(partition_root / "manifest.json", config["partition_manifest_sha256"])
    base = read_pinned(config["base_model_path"], config["base_model_sha256"])
    evaluation = read_pinned(config["validation_path"], config["validation_sha256"])
    assert (
        evaluation["split"] == "validation"
        and evaluation["class_names"] == base["class_names"] == partition["class_names"]
    )
    rows = evaluation["rows"]["validation"]
    clients = sorted(record["client_id"] for record in partition["clients"])
    assert len(clients) == len(set(clients)) == 15
    records = {record["client_id"]: record for record in partition["clients"]}
    snapshots = {}
    all_ids = set()
    validation_ids = {row["window_id"] for row in rows}
    for client in clients:
        path = partition_root / records[client]["dataset_path"]
        assert path.resolve().is_relative_to(partition_root.resolve())
        snapshot = read_pinned(path, records[client]["dataset_sha256"])
        assert snapshot["client_id"] == client and snapshot["class_names"] == base["class_names"]
        training = snapshot["rows"]["train"]
        ids = {row["window_id"] for row in training}
        assert len(ids) == len(training) == records[client]["train_row_count"] and not (
            ids & all_ids or ids & validation_ids
        )
        all_ids.update(ids)
        snapshots[client] = training
    plan = DistributedBackdoorPlan.model_validate(config["attack_plan"])
    assert set(plan.client_components) <= set(clients) and plan.target_label in base["class_names"]
    assert plan.attack_rounds[-1] <= config["rounds"]
    assert 0 < config["accepted_downweight_factor"] < 1
    assert config["attack_mode"] in ("clean", "distributed", "complete-trigger")
    assert config["recurrence"] in (
        "fedavg",
        "gated_composite",
        "flame",
        "weidetect",
        "gradient_fedavg",
        "literal_eq2",
        "literal_eq3",
    )
    deps = dependencies()
    torch = deps[1]
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    assert base["architecture"]["dropout"] == 0
    reference_predictions, confidence = predict(base, rows, deps)
    reference_correct = [
        predicted == row["label"]
        for row, predicted in zip(rows, reference_predictions, strict=True)
    ]
    auxiliary = [
        row
        for row, correct, conf in zip(rows, reference_correct, confidence, strict=True)
        if correct and conf > 0.9
    ]
    assert auxiliary and {row["label"] for row in auxiliary} == set(base["class_names"])
    save(
        output / "fixed-auxiliary-validation-set.json",
        {
            "window_ids": [row["window_id"] for row in auxiliary],
            "selection": "correct under initial reference and max softmax > 0.9; fixed for all rounds",
            "macro_f1_adaptation": "six-class macro-F1; unavailable classes are not silently dropped",
        },
    )
    save(output / "initial-evaluation.json", outcomes(base, rows, plan, reference_correct, deps))
    composite = (
        read_pinned(config["composite_config_path"], config["composite_config_sha256"])
        if str(config["composite_config_path"]).endswith(".json")
        else yaml.safe_load(Path(config["composite_config_path"]).read_bytes())
    )
    assert sha256_file(Path(config["composite_config_path"])) == config["composite_config_sha256"]
    clean_root = (
        Path(config["clean_reference_workspace"])
        if config.get("clean_reference_workspace")
        else None
    )
    if clean_root is not None:
        authenticate(clean_root, config["clean_reference_manifest_sha256"])
        clean_protocol = json.loads((clean_root / "protocol-before-training.json").read_bytes())
        for key in (
            "partition_manifest_sha256",
            "base_model_sha256",
            "validation_sha256",
            "seed",
            "rounds",
            "local_epochs",
            "batch_size",
            "learning_rate",
            "composite_config_sha256",
        ):
            assert config[key] == clean_protocol[key], key
        assert clean_protocol["attack_mode"] == "clean"
    elif config["attack_mode"] != "clean":
        raise ValueError(
            "attack campaign requires an authenticated clean-only calibration campaign"
        )
    class_weights = {
        name: float(partition["global_class_weights"][name]) for name in base["class_names"]
    }
    summary = []
    histories = {client: [] for client in clients}
    gradient_mode = config["recurrence"] in ("gradient_fedavg", "literal_eq2", "literal_eq3")
    for number in range(1, config["rounds"] + 1):
        prefix = output / "rounds" / f"round-{number:03d}"
        base_arrays = arrays_from_export(base, np=np)
        base_hash = sha256_bytes(derived_json_bytes(base))
        save(prefix / "base-model.json", base)
        models, counts, training_records, poison_records, gradients = [], [], [], [], []
        for client in clients:
            local_rows, poisoning = poison_local_rows(
                rows=snapshots[client],
                plan=plan,
                client_id=client,
                round_number=number,
                distributed=config["attack_mode"] != "complete-trigger",
            )
            if config["attack_mode"] == "clean":
                local_rows = snapshots[client]
                poisoning = {
                    "client_id": client,
                    "round_number": number,
                    "poisoned_window_ids": [],
                    "feature_indices": [],
                    "label_flip_count": 0,
                    "modified_feature_values": 0,
                    "source_row_count": len(local_rows),
                }
            seed = config["seed"] + number * 10000 + int(records[client]["partition_id"])
            if gradient_mode:
                gradient, metrics = full_gradient(base, local_rows, class_weights, deps)
                gradients.append(gradient)
                flat = np.concatenate([value.astype(np.float64).reshape(-1) for value in gradient])
                histories[client].append(flat)
                histories[client] = histories[client][-config["gradient_history_length"] :]
                save(
                    prefix / "gradients" / f"{client}.json",
                    {
                        "parameter_names": [p["name"] for p in base["parameters"]],
                        "values": [value.tolist() for value in gradient],
                        "loss_definition": "full-snapshot class-weighted cross-entropy mean at current global model",
                    },
                )
                local = model_with_arrays(
                    base,
                    [
                        value - config["learning_rate"] * change
                        for value, change in zip(base_arrays, gradient, strict=True)
                    ],
                )
            else:
                local_model = _model_from_export(base, torch=torch, np=np)
                metrics = train_local(
                    model=local_model,
                    rows=local_rows,
                    class_names=base["class_names"],
                    class_weights=class_weights,
                    epochs=config["local_epochs"],
                    batch_size=config["batch_size"],
                    learning_rate=config["learning_rate"],
                    seed=seed,
                    device_name="cpu",
                    torch=torch,
                    np=np,
                )
                local = export_state(
                    local_model, architecture=base["architecture"], class_names=base["class_names"]
                )
            save(prefix / "updates" / f"{client}.json", local)
            models.append(arrays_from_export(local, np=np))
            counts.append(len(local_rows))
            training_records.append(
                {
                    "client_id": client,
                    "seed": seed,
                    "source_snapshot_sha256": records[client]["dataset_sha256"],
                    "poisoned_snapshot_sha256": sha256_bytes(derived_json_bytes(local_rows)),
                    "local_model_sha256": sha256_file(prefix / "updates" / f"{client}.json"),
                    "metrics": metrics,
                }
            )
            poison_records.append(poisoning)
        save(prefix / "poisoning-evaluation-only.json", poison_records)
        comparisons = {}
        if gradient_mode:
            alternatives = {}
            alternatives["gradient_fedavg"] = (
                model_with_arrays(
                    base,
                    [
                        old
                        - config["learning_rate"]
                        * np.average(
                            np.stack([gradient[index] for gradient in gradients]),
                            axis=0,
                            weights=counts,
                        )
                        for index, old in enumerate(base_arrays)
                    ],
                ),
                {
                    "method": "sample-weighted full-gradient SGD control",
                    "local_Adam_steps_performed": 0,
                },
            )
            for formula in ("literal_eq2", "literal_eq3"):
                arrays, report = fedgradtrace_global_gradient(
                    base=base_arrays,
                    gradients=gradients,
                    gradient_histories=[np.stack(histories[client]) for client in clients],
                    client_ids=clients,
                    sample_counts=counts,
                    learning_rate=config["learning_rate"],
                    formula=formula,
                )
                alternatives[formula] = (model_with_arrays(base, arrays), report)
        else:
            deltas = [model_delta(base_arrays, model) for model in models]
            indicators = update_indicators(deltas, client_ids=clients)
            base_f1 = evaluate(base, rows, deps)["macro_f1_all_model_classes"]
            auxiliary_scores = []
            for index, client in enumerate(clients):
                local = json.loads((prefix / "updates" / f"{client}.json").read_bytes())
                indicators[index]["validation_impact"] = (
                    base_f1 - evaluate(local, rows, deps)["macro_f1_all_model_classes"]
                )
                auxiliary_scores.append(
                    evaluate(local, auxiliary, deps)["macro_f1_all_model_classes"]
                )
            specs = composite["statistics"]["indicators"]
            directions = {name: spec["direction"] for name, spec in specs.items()}
            weights = {name: spec["weight"] for name, spec in specs.items()}
            if clean_root is None:
                clean_indicators = indicators
            else:
                clean_indicators = json.loads(
                    (clean_root / "rounds" / f"round-{number:03d}" / "indicators.json").read_bytes()
                )
            references = build_indicator_references(clean_indicators, directions=directions)
            clean_scores = score_statistical_indicators(
                clean_indicators,
                references=references,
                weights=weights,
                z_cap=composite["statistics"]["robust_z_cap"],
            )
            candidate_scores = score_statistical_indicators(
                indicators,
                references=references,
                weights=weights,
                z_cap=composite["statistics"]["robust_z_cap"],
            )
            settings = composite["policies"]
            calibration = settings["calibration"]
            thresholds = calibrate_policy_thresholds(
                list(clean_scores.values()),
                trust_weight=settings["composite_trust_weight"],
                statistical_margin=calibration["statistical_max_margin"],
                composite_margin=calibration["composite_max_margin"],
                downweight_quantile=calibration["composite_downweight_quantile"],
            )
            trust = TrustSignal(
                raw_status="software-experiment-admissibility-assumption",
                admissible=True,
                risk=0,
                evaluated_checks=[],
                failed_checks=[],
                reasons=[
                    "All software experiment identities are assumed admissible. No fresh TPM attestation is claimed."
                ],
            )
            decisions, masses = [], []
            for index, client in enumerate(clients):
                decision = next(
                    item
                    for item in decide_admission_policies(
                        trust=trust,
                        statistics=candidate_scores[client],
                        statistical_threshold=thresholds.statistical_threshold,
                        composite_threshold=thresholds.composite_threshold,
                        composite_downweight_threshold=thresholds.composite_downweight_threshold,
                        trust_weight=thresholds.trust_weight,
                    )
                    if item.policy == "gated_composite"
                )
                # Original runtime uses the contract's fixed downweight factor.
                mass = (
                    counts[index] * config["accepted_downweight_factor"]
                    if decision.status == "accepted_downweighted"
                    else float(counts[index])
                    if decision.contributes
                    else 0.0
                )
                masses.append(mass)
                decisions.append(
                    {
                        "client_id": client,
                        "statistics": candidate_scores[client].model_dump(mode="json"),
                        "decision": decision.model_dump(mode="json"),
                        "mass": mass,
                    }
                )
            save(prefix / "indicators.json", indicators)
            save(
                prefix / "calibration-and-decisions.json",
                {
                    "references": {
                        name: ref.model_dump(mode="json") for name, ref in references.items()
                    },
                    "thresholds": thresholds.model_dump(mode="json"),
                    "decisions": decisions,
                    "attacker_identities_used": False,
                },
            )
            alternatives = {}
            for method in ("fedavg", "coordinate_median", "trimmed_mean", "multikrum", "bulyan"):
                arrays = apply_delta(
                    base_arrays,
                    aggregate_deltas(
                        deltas,
                        strategy=method,
                        f=0 if method == "fedavg" else config["declared_max_faulty_clients"],
                        weights=counts if method == "fedavg" else None,
                    ),
                )
                alternatives[method] = (
                    model_with_arrays(base, arrays),
                    {
                        "method": method,
                        "declared_fault_bound": config["declared_max_faulty_clients"],
                        "weights": "sample-count" if method == "fedavg" else "strategy-specific",
                    },
                )
            flame, report = flame_aggregate(
                base=base_arrays,
                models=models,
                client_ids=clients,
                noise_factor=0.01,
                seed=config["seed"] + number,
            )
            alternatives["flame"] = (
                model_with_arrays(base, flame) if flame is not None else None,
                report,
            )
            wei, report = weidetect_aggregate(
                models=models,
                client_ids=clients,
                validation_f1=auxiliary_scores,
                keep_count=config["weidetect_keep_count"],
                seed=config["seed"] + number,
            )
            alternatives["weidetect"] = (model_with_arrays(base, wei), report)
            surviving = [index for index, mass in enumerate(masses) if mass > 0]
            if len(surviving) < config["minimum_contributors"]:
                alternatives["gated_composite"] = (
                    None,
                    {"status": "insufficient_contributors", "masses": masses},
                )
            else:
                arrays = deps[4]([(models[index], masses[index]) for index in surviving])
                alternatives["gated_composite"] = (
                    model_with_arrays(base, arrays),
                    {
                        "status": "aggregated",
                        "masses": masses,
                        "normalized_weights": [mass / sum(masses) for mass in masses],
                        "trust_signal": trust.model_dump(mode="json"),
                    },
                )
        for method, (state, report) in alternatives.items():
            if state is not None:
                save(prefix / "aggregates" / f"{method}.json", state)
                comparisons[method] = {
                    "status": "aggregated",
                    "model_sha256": sha256_file(prefix / "aggregates" / f"{method}.json"),
                    "aggregation": report,
                    "validation": outcomes(state, rows, plan, reference_correct, deps),
                }
            else:
                comparisons[method] = {"status": "failed_without_model", "aggregation": report}
        save(
            prefix / "comparison.json",
            {
                "same_frozen_client_order": clients,
                "base_model_sha256": base_hash,
                "update_sha256": [item["local_model_sha256"] for item in training_records],
                "comparisons": comparisons,
                "recurrence": config["recurrence"],
                "closed_loop_claim": "Only the declared recurrence drives subsequent local training; other outputs are conditional same-input comparisons.",
            },
        )
        state = alternatives[config["recurrence"]][0]
        save(
            prefix / "round.json",
            {
                "round_number": number,
                "client_ids": clients,
                "base_model_sha256": base_hash,
                "local_training_records": training_records,
                "recurrence": config["recurrence"],
                "global_model_sha256": sha256_bytes(derived_json_bytes(state))
                if state is not None
                else None,
            },
        )
        summary.append(
            {
                "round": number,
                "recurrence": config["recurrence"],
                "status": comparisons[config["recurrence"]]["status"],
                "validation": comparisons[config["recurrence"]].get("validation"),
            }
        )
        print(
            f"round {number}/{config['rounds']} {config['attack_mode']} {config['recurrence']}: {json.dumps(summary[-1].get('validation', {}).get('complete_trigger', {}))}",
            flush=True,
        )
        if state is None:
            break
        base = state
    save(
        output / "summary.json",
        {
            "rounds": summary,
            "test_set_opened": False,
            "fresh_TPM_attestation_performed": False,
            "private_client_keys_exported": False,
            "source_training_rows_unchanged": True,
            "gradient_protocol": gradient_mode,
            "final_checkpoint_rule": "last successfully completed predeclared round; no validation-ASR checkpoint maximization",
        },
    )


def close_experiment(config, output):
    authority = SoftwareECDSASigner.generate()
    write_once(output / "experiment-authority.public.pem", authority.public_pem())
    client_signers = {}
    protocol_hash = sha256_file(output / "protocol-before-training.json")
    for path in sorted(output.glob("rounds/*/round.json")):
        record = json.loads(path.read_bytes())
        for local in record["local_training_records"]:
            client = local["client_id"]
            if client not in client_signers:
                client_signers[client] = SoftwareECDSASigner.generate()
                write_once(
                    output / "software-identities" / f"{client}.public.pem",
                    client_signers[client].public_pem(),
                )
            core = {
                "domain": "software-experiment-model-submission-v1",
                "client_id": client,
                "protocol_sha256": protocol_hash,
                "round_number": record["round_number"],
                "base_model_sha256": record["base_model_sha256"],
                "local_model_sha256": local["local_model_sha256"],
                "source_snapshot_sha256": local["source_snapshot_sha256"],
                "training_snapshot_sha256": local["poisoned_snapshot_sha256"],
                "attestation_level": "software-only-no-TPM-Quote",
            }
            digest = digest_object(core)
            save(
                path.parent / "signatures" / f"{client}.json",
                {
                    "core": core,
                    "core_digest": digest,
                    "signature": signature(client_signers[client], digest),
                },
            )
    write_once(output / "producer-script.py", Path(__file__).read_bytes())
    files = {
        p.relative_to(output).as_posix(): sha256_file(p)
        for p in sorted(output.rglob("*"))
        if p.is_file()
    }
    core = {
        "domain": "software-DBA-common-input-experiment-v1",
        "config_sha256": protocol_hash,
        "implementation_sha256": implementation_sha256(),
        "script_sha256": sha256_file(Path(__file__)),
        "environment": environment(),
        "artifacts": files,
        "fresh_TPM_attestation_performed": False,
    }
    digest = digest_object(core)
    save(
        output / "manifest.json",
        {"core": core, "core_digest": digest, "signature": signature(authority, digest)},
    )
    return {
        "manifest_sha256": sha256_file(output / "manifest.json"),
        "artifact_count": len(files),
        "status": "created",
        "public_key_sha256": sha256_file(output / "experiment-authority.public.pem"),
    }


def verify(workspace, expected):
    manifest = authenticate(workspace, expected)
    assert manifest["core"]["implementation_sha256"] == implementation_sha256(), (
        "use preserved source release"
    )
    assert manifest["core"]["script_sha256"] == sha256_file(Path(__file__))
    assert manifest["core"]["environment"] == environment()
    config = json.loads((workspace / "protocol-before-training.json").read_bytes())
    with tempfile.TemporaryDirectory(prefix="revision-dba-replay-") as temporary:
        replay = Path(temporary) / "replay"
        execute(config, replay)
        numeric = {
            p.relative_to(replay).as_posix(): sha256_file(p)
            for p in replay.rglob("*")
            if p.is_file()
        }
        expected_numeric = {
            name: digest
            for name, digest in manifest["core"]["artifacts"].items()
            if name not in ("experiment-authority.public.pem", "producer-script.py")
            and not name.startswith("software-identities/")
            and "/signatures/" not in name
        }
        assert numeric == expected_numeric, {
            "different": [name for name in numeric if numeric[name] != expected_numeric.get(name)],
            "missing": list(set(expected_numeric) - set(numeric)),
        }
    return {
        "status": "verified",
        "training_or_live_gradients_reexecuted": True,
        "same_numeric_artifacts": len(numeric),
        "software_client_signatures_verified": True,
        "fresh_TPM_attestation_performed": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256")
    args = parser.parse_args()
    if args.mode == "create":
        config = json.loads(args.config.read_bytes())
        execute(config, args.workspace)
        result = close_experiment(config, args.workspace)
    else:
        if not args.expected_manifest_sha256:
            parser.error("verification requires an externally pinned manifest digest")
        result = verify(args.workspace, args.expected_manifest_sha256)
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
