"""Paired federated confirmation and explicitly external-guided ablation.

Standard remains the validation-selected primary representation. Counts-only is
an exploratory follow-up after observing its Data22 result, not a new blind test.
"""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path

import numpy as np
import revision_generalization as screening
import yaml

from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.crypto import (
    SoftwareECDSASigner,
    load_public_key,
    public_key_id,
    verify_digest_signature,
)
from fl_forensics.external_generalization import _binary_metrics, _predict
from fl_forensics.federated_model import (
    architecture_record,
    build_model,
    dependencies,
    evaluate_rows,
    export_state,
    seed_everything,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.retraining_replay import (
    RetrainingPlan,
    create_retraining_replay,
    verify_retraining_replay,
)
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.secure_round import _model_from_export
from fl_forensics.storage import write_once

VARIANTS = ("standard", "counts-only")
SEEDS = (341593, 342593, 343593)


def save(path, value):
    write_once(path, derived_json_bytes(value))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-workspace", type=Path, required=True)
    parser.add_argument("--partition-workspace", type=Path, required=True)
    parser.add_argument("--external-workspace", type=Path, required=True)
    parser.add_argument("--screening-workspace", type=Path, required=True)
    parser.add_argument("--expected-screening-manifest-sha256", required=True)
    parser.add_argument("--config", type=Path, default=Path("configs/federation.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = args.screening_workspace / "manifest.json"
    assert sha256_file(manifest_path) == args.expected_screening_manifest_sha256
    manifest = json.loads(manifest_path.read_bytes())
    key = load_public_key(
        (args.screening_workspace / "experiment-authority.public.pem").read_bytes()
    )
    assert manifest["core_digest"] == digest_object(manifest["core"])
    assert manifest["signature"]["key_id"] == public_key_id(key)
    assert verify_digest_signature(key, manifest["core_digest"], manifest["signature"]["value_b64"])
    assert manifest["core"]["selected_variant"] == "standard"
    dataset = json.loads((args.dataset_workspace / "dataset.json").read_bytes())
    partition_data = (args.partition_workspace / "manifest.json").read_bytes()
    partition = json.loads(partition_data)
    screen_protocol = json.loads(
        (args.screening_workspace / "protocol-before-training.json").read_bytes()
    )
    assert sha256_bytes(partition_data) == screen_protocol["partition_manifest_sha256"]
    assert sha256_file(args.dataset_workspace / "dataset.json") == screen_protocol["dataset_sha256"]
    config = yaml.safe_load(args.config.read_bytes())
    by_id = {row["window_id"]: row for row in dataset["rows"]}
    assert len(by_id) == len(dataset["rows"])
    validation_raw = [row for row in dataset["rows"] if row["split"] == "validation"]
    test_raw = [row for row in dataset["rows"] if row["split"] == "test"]
    protocol = {
        "variants": list(VARIANTS),
        "seeds": list(SEEDS),
        "rounds": int(config["training"]["rounds"]),
        "primary_validation_selected_variant": "standard",
        "counts_only_followup": "external-guided exploratory diagnostic chosen after the Data22 screening result; not an independent confirmatory external test",
        "architecture_hyperparameters": config["model"],
        "training_hyperparameters": config["training"],
        "feature_serialization": "12 decimal places before float32 training, matching the existing scaler serialization",
        "selection": "maximum Data24 validation macro-F1 across rounds, earliest round on ties",
        "dataset_sha256": sha256_file(args.dataset_workspace / "dataset.json"),
        "source_partition_manifest_sha256": sha256_bytes(partition_data),
        "screening_manifest_sha256": args.expected_screening_manifest_sha256,
        "script_sha256": sha256_file(Path(__file__)),
        "library_package_sha256": implementation_sha256(),
        "library_source_path": str(Path(__import__("fl_forensics").__file__).resolve()),
        "python": platform.python_version(),
        "full_attested_system_replayed": False,
    }
    save(output / "protocol-before-training.json", protocol)
    write_once(output / "producer-script.py", Path(__file__).read_bytes())
    (
        np_dep,
        torch,
        _flwr,
        _sklearn,
        _aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependencies()
    signer = SoftwareECDSASigner.generate()
    write_once(output / "experiment-authority.public.pem", signer.public_pem())
    reports = {}
    original_hashes = {"manifest.json": sha256_bytes(partition_data)}
    for variant in VARIANTS:
        transform_path = args.screening_workspace / variant / "feature-transform.json"
        assert (
            sha256_file(transform_path)
            == manifest["core"]["artifacts"][f"{variant}/feature-transform.json"]
        )
        specification = json.loads(transform_path.read_bytes())
        prepared = output / "inputs" / variant
        client_refs = []
        for record in partition["clients"]:
            relative = Path(record["dataset_path"])
            assert not relative.is_absolute() and ".." not in relative.parts
            original_bytes = (args.partition_workspace / record["dataset_path"]).read_bytes()
            assert sha256_bytes(original_bytes) == record["dataset_sha256"]
            original_hashes[record["dataset_path"]] = record["dataset_sha256"]
            snapshot = json.loads(original_bytes)
            rows = {}
            for split in ("train", "validation"):
                old_rows = snapshot["rows"][split]
                raw_rows = [by_id[row["window_id"]] for row in old_rows]
                assert all(
                    old["label"] == raw["label"] and raw["split"] == split
                    for old, raw in zip(old_rows, raw_rows, strict=True)
                )
                values = np.round(
                    screening.transform(
                        np.asarray([row["features"] for row in raw_rows]), specification
                    ),
                    12,
                )
                if variant == "standard":
                    assert np.array_equal(
                        values.astype(np.float32),
                        np.asarray([row["features"] for row in old_rows], dtype=np.float32),
                    )
                rows[split] = [
                    {**row, "features": vector.tolist()}
                    for row, vector in zip(old_rows, values, strict=True)
                ]
            data = derived_json_bytes(
                {
                    **snapshot,
                    "feature_names": specification["transform"]["feature_names"],
                    "rows": rows,
                }
            )
            write_once(prepared / record["dataset_path"], data)
            client_refs.append({**record, "dataset_sha256": sha256_bytes(data)})
        derived_partition = {
            **partition,
            "artifact_type": "controlled_replay_transformed_partition_set",
            "feature_names": specification["transform"]["feature_names"],
            "clients": client_refs,
            "source_partition_manifest_sha256": sha256_bytes(partition_data),
            "transform_sha256": sha256_file(transform_path),
        }
        save(prepared / "manifest.json", derived_partition)
        val_vectors = np.round(
            screening.transform(
                np.asarray([row["features"] for row in validation_raw]), specification
            ),
            12,
        )
        validation_path = prepared / "validation.json"
        save(
            validation_path,
            {
                "split": "validation",
                "class_names": partition["class_names"],
                "rows": {
                    "validation": [
                        {**row, "features": vector.tolist()}
                        for row, vector in zip(validation_raw, val_vectors, strict=True)
                    ]
                },
            },
        )
        for seed in SEEDS:
            name = f"{variant}-s{seed}"
            seed_everything(seed, torch=torch, np=np_dep)
            dimensions = {
                "input_features": len(specification["indices"]),
                "class_count": len(partition["class_names"]),
                "hidden_layers": config["model"]["hidden_layers"],
                "embedding_size": config["model"]["embedding_size"],
                "dropout": float(config["model"]["dropout"]),
            }
            base_path = prepared / f"base-s{seed}.json"
            save(
                base_path,
                export_state(
                    build_model(**dimensions, torch=torch),
                    architecture=architecture_record(**dimensions),
                    class_names=partition["class_names"],
                ),
            )
            plan = RetrainingPlan(
                rounds=protocol["rounds"],
                seed=seed,
                local_epochs=int(config["training"]["local_epochs"]),
                batch_size=int(config["training"]["batch_size"]),
                learning_rate_decimal=str(config["training"]["learning_rate"]),
                minimum_contributors=len(partition["clients"]),
                clients=sorted(record["client_id"] for record in partition["clients"]),
            )
            result = create_retraining_replay(
                output=output / name,
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
            print(name + ": training completed " + json.dumps(result), flush=True)
            verification = verify_retraining_replay(
                workspace=output / name,
                expected_sha256=result["manifest_sha256"],
                base_model_path=base_path,
                partition_workspace=prepared,
                validation_split_path=validation_path,
                authority_public_key=signer.private_key.public_key(),
            )
            assert verification["status"] == "verified", verification
            rounds = [
                (
                    number,
                    json.loads(
                        (
                            output / name / "rounds" / f"round-{number:03d}" / "evaluation.json"
                        ).read_bytes()
                    ),
                )
                for number in range(1, plan.rounds + 1)
            ]
            number, metric = max(
                rounds, key=lambda item: (item[1]["macro_f1_all_model_classes"], -item[0])
            )
            selected_model = output / name / "rounds" / f"round-{number:03d}" / "model.json"
            report = {
                "variant": variant,
                "seed": seed,
                "creation": result,
                "verification": verification,
                "selected_round": number,
                "selected_validation": metric,
                "selected_model_sha256": sha256_file(selected_model),
            }
            save(output / f"{name}-selection-before-external-and-test.json", report)
            reports[name] = report
    # Freeze all round selections before evaluating test/external for this follow-up.
    external = json.loads((args.external_workspace / "dataset.json").read_bytes())
    assert external["feature_names"] == dataset["feature_names"]
    external_truth = [row["label"] for row in external["rows"]]
    old_threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        for name, report in reports.items():
            specification = json.loads(
                (
                    args.screening_workspace / report["variant"] / "feature-transform.json"
                ).read_bytes()
            )
            model_path = (
                output / name / "rounds" / f"round-{report['selected_round']:03d}" / "model.json"
            )
            model_export = json.loads(model_path.read_bytes())
            ext_features = np.round(
                screening.transform(
                    np.asarray([row["features"] for row in external["rows"]]), specification
                ),
                12,
            )
            labels, _confidence = _predict(
                model_export=model_export,
                features=ext_features,
                batch_size=1024,
                np=np_dep,
                torch=torch,
            )
            report["external_binary"] = _binary_metrics(
                external_truth,
                [partition["class_names"][index] for index in labels],
                benign="benign",
            )
            test_vectors = np.round(
                screening.transform(
                    np.asarray([row["features"] for row in test_raw]), specification
                ),
                12,
            )
            test_rows = [
                {**row, "features": vector.tolist()}
                for row, vector in zip(test_raw, test_vectors, strict=True)
            ]
            report["data24_test"] = evaluate_rows(
                model=_model_from_export(model_export, np=np_dep, torch=torch),
                rows=test_rows,
                class_names=partition["class_names"],
                batch_size=1024,
                np=np_dep,
                torch=torch,
                accuracy_score=accuracy_score,
                confusion_matrix=confusion_matrix,
                precision_recall_fscore_support=precision_recall_fscore_support,
            )
    finally:
        torch.set_num_threads(old_threads)
    assert original_hashes == {
        relative: sha256_file(args.partition_workspace / relative) for relative in original_hashes
    }
    summary = {
        "protocol": protocol,
        "runs": reports,
        "source_files_unchanged": True,
        "external_metrics_used_for_round_selection": False,
        "counts_only_followup_is_exploratory_after_external_screening": True,
        "private_authority_key_exported": False,
    }
    save(output / "summary.json", summary)
    print(
        json.dumps(
            {
                name: {
                    "selected_round": report["selected_round"],
                    "data24_test_macro_f1": report["data24_test"]["macro_f1_all_model_classes"],
                    "data22_attack_f1": report["external_binary"]["attack_f1"],
                }
                for name, report in reports.items()
            },
            indent=2,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
