"""Analyze the declared attacked campaign; keep reachability and effects separate."""

from __future__ import annotations

from pathlib import Path

import numpy as np
from revision_attested_dba import BRANCHES, CLIENTS, ROUNDS, omitted, save
from revision_dba_experiment import outcomes, predict

from fl_forensics.campaign_derivation import structural_blast_radius_set
from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.counterfactual_round import (
    create_counterfactual_round,
    verify_counterfactual_round,
)
from fl_forensics.crypto import load_public_key
from fl_forensics.dba_training import prepare_dba_training_rows
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan, apply_evaluation_trigger
from fl_forensics.federated_model import arrays_from_export, dependencies, export_state, train_local
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _coordinator_signer, _model_from_export
from fl_forensics.storage import load_json


def distance(first, second):
    a = arrays_from_export(first, np=np)
    b = arrays_from_export(second, np=np)
    flat = np.concatenate(
        [(x.astype(np.float64) - y.astype(np.float64)).ravel() for x, y in zip(a, b, strict=True)]
    )
    return float(np.linalg.norm(flat))


def analyze(root: Path):
    deps = dependencies()
    torch = deps[1]
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    signer = _coordinator_signer(root / "coordinator", create=False)
    key = load_public_key(signer.public_pem())
    protocol = load_json(root / "protocol.json")
    plan = DistributedBackdoorPlan.model_validate(protocol["attack_plan"]["plan"])
    evaluation = root / "partition/server/splits/validation.json"
    rows = load_json(evaluation)["rows"]["validation"]
    initial = load_json(root / "branches/baseline/rounds/round-001/public/base-model.json")
    initial_predictions, _ = predict(initial, rows, deps)
    reference_correct = [
        p == row["label"] for p, row in zip(initial_predictions, rows, strict=True)
    ]
    variants = {"clean": rows, "complete_trigger": apply_evaluation_trigger(rows=rows, plan=plan)}
    variants.update(
        {
            f"component_{c}": apply_evaluation_trigger(rows=rows, plan=plan, component_client_id=c)
            for c in sorted(plan.client_components)
        }
    )
    rounds, products = {}, {}
    selections = {BRANCHES[1]: [], BRANCHES[2]: []}
    treatments, retraining, comparison, evaluations = [], [], [], []
    for branch in BRANCHES:
        for n in range(1, ROUNDS + 1):
            workspace = root / "branches" / branch / "rounds" / f"round-{n:03d}"
            rounds[sha256_file(workspace / "derivation/manifest.json")] = workspace
            context = load_json(workspace / "public/round-context.json")["core"]
            training = load_json(workspace / "public/training-contract.json")
            base = load_json(workspace / "public/base-model.json")
            model = load_json(workspace / "checkpoint/global-model.json")
            baseline_workspace = root / "branches/baseline/rounds" / f"round-{n:03d}"
            baseline_model = load_json(baseline_workspace / "checkpoint/global-model.json")
            if branch == "control":
                assert sha256_file(workspace / "checkpoint/global-model.json") == sha256_file(
                    baseline_workspace / "checkpoint/global-model.json"
                )
            source = load_json(workspace / "derivation/manifest.json")
            if branch == "baseline":
                for disposition in source["core"]["dispositions"]:
                    if disposition["client_id"] == "client01" and n <= 3:
                        selections[BRANCHES[2]].append(disposition["submission_id"])
                        if n == 1:
                            selections[BRANCHES[1]].append(disposition["submission_id"])
            matching, different = [], []
            for client in CLIENTS:
                submission = workspace / "submissions" / client
                if omitted(branch, n, client):
                    assert not (submission / "bundle.json").exists()
                    continue
                snapshot = load_json(root / "partition/clients" / client / "dataset.json")
                snapshot_manifest = load_json(root / "partition/clients" / client / "manifest.json")
                source_rows = snapshot["rows"]["train"]
                trained_rows, treatment = prepare_dba_training_rows(
                    training=training, rows=source_rows, client_id=client, round_number=n
                )
                metrics = load_json(submission / "metrics.json")
                assert metrics["dba_training_experiment"] == treatment
                treatments.append({"branch": branch, **treatment})
                # Independent numerical replay, from the branch's pinned base.
                local = _model_from_export(base, torch=torch, np=np)
                train_local(
                    model=local,
                    rows=trained_rows,
                    class_names=base["class_names"],
                    class_weights={
                        k: float(v) for k, v in training["global_class_weights"].items()
                    },
                    epochs=context["local_epochs"],
                    batch_size=context["batch_size"],
                    learning_rate=float(context["learning_rate_decimal"]),
                    seed=context["seed"] + n * 10000 + int(snapshot_manifest["partition_id"]),
                    device_name="cpu",
                    torch=torch,
                    np=np,
                )
                replay = export_state(
                    local, architecture=base["architecture"], class_names=base["class_names"]
                )
                actual = sha256_file(submission / "update.json")
                assert sha256_bytes(derived_json_bytes(replay)) == actual, (
                    branch,
                    n,
                    client,
                    "local replay",
                )
                retraining.append(
                    {
                        "branch": branch,
                        "round": n,
                        "client_id": client,
                        "base_model_sha256": context["base_model_sha256"],
                        "replayed_update_sha256": actual,
                        "matched": True,
                    }
                )
                reference = baseline_workspace / "submissions" / client / "update.json"
                (matching if sha256_file(reference) == actual else different).append(client)
            baseline_labels = {
                name: predict(baseline_model, data, deps)[0] for name, data in variants.items()
            }
            predictions = {name: predict(model, data, deps)[0] for name, data in variants.items()}
            changed = {
                name: sum(a != b for a, b in zip(baseline_labels[name], labels, strict=True))
                for name, labels in predictions.items()
            }
            record = outcomes(model, rows, plan, reference_correct, deps)
            evaluations.append(
                {
                    "branch": branch,
                    "round": n,
                    "model_sha256": sha256_file(workspace / "checkpoint/global-model.json"),
                    "outcomes": record,
                }
            )
            save(
                root / "analysis/predictions" / f"{branch}-{n:03d}.json",
                {
                    "window_ids": [r["window_id"] for r in rows],
                    "reference_labels": [r["label"] for r in rows],
                    "predictions": predictions,
                },
            )
            comparison.append(
                {
                    "branch": branch,
                    "round": n,
                    "parameter_l2_vs_baseline": distance(baseline_model, model),
                    "class_changes_vs_baseline": changed,
                    "common_local_models_matching_baseline": matching,
                    "common_local_models_different_from_baseline": different,
                }
            )
            print(f"analysis replay and evaluation {branch} {n}", flush=True)
    for path in (root / "products").glob("*/*/manifest.json"):
        products[sha256_file(path)] = path.parent
    common = {
        "workspace": root / "graph",
        "expected_sha256": sha256_file(root / "graph/manifest.json"),
        "round_workspaces": rounds,
        "product_workspaces": products,
        "coordinator_public_key": key,
        "authority_public_key": key,
    }
    for branch, ids in selections.items():
        radius = structural_blast_radius_set(submission_ids=ids, **common)
        assert radius["status"] == "verified", radius
        save(root / "analysis" / f"{branch}-radius.json", radius)
    first = root / "branches/baseline/rounds/round-001"
    cf_reports = []
    for mode in ("frozen_decisions", "rescore_round"):
        destination = root / "counterfactuals" / mode
        kwargs = {
            "round_workspace": first,
            "submissions_root": first / "submissions",
            "validation_split_path": evaluation,
            "coordinator_public_key": key,
            "authority_public_key": key,
        }
        result = create_counterfactual_round(
            output=destination,
            expected_source_manifest_sha256=sha256_file(first / "derivation/manifest.json"),
            removed_submission_ids=selections[BRANCHES[1]],
            mode=mode,
            signer=signer,
            **kwargs,
        )
        verified = verify_counterfactual_round(
            workspace=destination, expected_sha256=result["manifest_sha256"], **kwargs
        )
        assert verified["status"] == "verified", verified
        intervention = (
            root / "branches" / BRANCHES[1] / "rounds/round-001/checkpoint/global-model.json"
        )
        cf_model = destination / "counterfactual-model.json"
        # The exact analyst output path is taken from the generated core below.
        if not cf_model.exists():
            models = [p for p in destination.glob("*.json") if load_json(p).get("parameters")]
            assert len(models) == 1, [str(p) for p in destination.iterdir()]
            cf_model = models[0]
        cf_reports.append(
            {
                "mode": mode,
                "creation": result,
                "verification": verified,
                "matches_live_intervention": sha256_file(cf_model) == sha256_file(intervention),
                "parameter_l2_vs_live_intervention": distance(
                    load_json(cf_model), load_json(intervention)
                ),
            }
        )
    save(root / "analysis/treatment-checks.json", treatments)
    save(root / "analysis/local-numerical-replay.json", retraining)
    save(root / "analysis/trajectory-comparison.json", comparison)
    save(root / "analysis/attack-evaluation.json", evaluations)
    save(root / "analysis/direct-counterfactuals.json", cf_reports)
    summary = {
        "profile": "attested-dba-retrospective-case-v1",
        "status": "verified",
        "local_models_independently_retrained": len(retraining),
        "poisoning_records_verified": len(treatments),
        "selected_submission_ids": selections,
        "graph_manifest_sha256": sha256_file(root / "graph/manifest.json"),
        "structural_reachability_is_measured_effect": False,
        "malicious_identity": "declared experiment ground truth, not automatically detected",
        "selection_scope": "one submission versus three explicitly selected submissions of client01; client returns after round3",
        "evaluation_scope": "all validation rows at five fixed endpoints; no test evaluation",
        "actual_trigger_realizability": "feature space only",
        "private_data_integrity": "pinned clean partition plus explicit deterministic training transformation",
        "global_product_completeness": False,
        "independent_deadline_verified": False,
        "thesis_edited": False,
    }
    save(root / "analysis/summary.json", summary)
    core = {
        "protocol_sha256": sha256_file(root / "protocol.json"),
        "graph_manifest_sha256": sha256_file(root / "graph/manifest.json"),
        "source_round_manifests": sorted(rounds),
        "source_product_manifests": sorted(products),
        "artifacts": {
            str(p.relative_to(root)): sha256_file(p)
            for folder in ("analysis", "counterfactuals")
            for p in sorted((root / folder).rglob("*"))
            if p.is_file()
        },
    }
    digest = digest_object(core)
    save(
        root / "intervention-manifest.json",
        {
            "core": core,
            "core_digest": digest,
            "signature": {
                "key_id": signer.key_id,
                "value_b64": signer.sign_digest(digest),
                "trust_level": "software-development",
            },
        },
    )
    return summary
