from __future__ import annotations

import csv
import json
from pathlib import Path

import yaml

from fl_forensics.canonical import sha256_file
from fl_forensics.external_generalization import (
    EXPECTED_COLUMNS,
    _binary_metrics,
    _shared_label_metrics,
    evaluate_external_generalization,
    prepare_external_dataset,
    verify_external_dataset,
    verify_external_generalization,
)
from fl_forensics.federated_model import build_model, export_state


def _record(*, uid: str, timestamp: float, label: str) -> dict[str, str]:
    values = {column: "0" for column in EXPECTED_COLUMNS}
    values.update(
        {
            "resp_pkts": "2",
            "service": "dns",
            "orig_ip_bytes": "186",
            "local_resp": "false",
            "missed_bytes": "0",
            "protocol": "udp",
            "duration": "0.002",
            "conn_state": "SF",
            "dest_ip": "143.88.5.1",
            "orig_pkts": "2",
            "community_id": f"community-{uid}",
            "resp_ip_bytes": "186",
            "dest_port": "53",
            "orig_bytes": "130",
            "local_orig": "false",
            "datetime": "2022-02-10T03:00:00.000Z",
            "history": "Dd",
            "resp_bytes": "130",
            "uid": uid,
            "src_port": "36073",
            "ts": str(timestamp),
            "src_ip": "143.88.5.12",
            "mitre_attack_tactics": label,
        }
    )
    return values


def _source(root: Path) -> None:
    root.mkdir(parents=True)
    records = {
        "hour-a.csv": [
            _record(uid="benign", timestamp=60.0, label="none"),
            _record(uid="recon", timestamp=120.0, label="Reconnaissance"),
            _record(uid="recon", timestamp=120.0, label="Reconnaissance"),
        ],
        "hour-b.csv": [_record(uid="discovery", timestamp=180.0, label="Discovery")],
    }
    manifest_records = []
    for name, rows in records.items():
        path = root / name
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=EXPECTED_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        manifest_records.append(
            {
                "relative_path": name,
                "source_url": f"https://datasets.uwf.edu/test/{name}",
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    (root / "download_manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "dataset": "UWF-ZeekData22",
                "source_format": "csv",
                "files": manifest_records,
            }
        ),
        encoding="utf-8",
    )


def _config(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "external_dataset": {
                    "dataset": "UWF-ZeekData22",
                    "training_dataset": "UWF-ZeekData24",
                    "window_seconds": 60,
                    "benign_labels": ["none", "benign", "normal", "-"],
                },
                "evaluation": {
                    "batch_size": 16,
                    "benign_label": "benign",
                    "shared_labels": ["benign", "reconnaissance"],
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_external_snapshot_is_deterministic_and_source_recomputed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    config = tmp_path / "external.yaml"
    workspace = tmp_path / "external"
    _source(source)
    _config(config)

    result = prepare_external_dataset(
        source_root=source, output=workspace, config_path=config
    )
    assert result["status"] == "prepared"
    assert result["raw_record_count"] == 4
    assert result["unique_event_count"] == 3
    assert result["window_count"] == 3
    assert result["class_counts"] == {
        "benign": 1,
        "discovery": 1,
        "reconnaissance": 1,
    }

    verified = verify_external_dataset(
        workspace=workspace, source_root=source, config_path=config
    )
    assert verified["status"] == "verified"
    assert verified["source_recomputed"] is True


def test_external_metrics_keep_binary_and_shared_label_scopes_separate() -> None:
    actual = ["benign", "reconnaissance", "discovery", "discovery"]
    predicted = ["benign", "reconnaissance", "multi_tactic", "benign"]
    binary = _binary_metrics(actual, predicted, benign="benign")
    assert binary["confusion_matrix"]["values"] == [[1, 0], [1, 2]]
    assert binary["attack_recall"] == 2 / 3

    shared = _shared_label_metrics(
        actual,
        predicted,
        shared_labels=["benign", "reconnaissance"],
        model_labels=["benign", "multi_tactic", "reconnaissance"],
    )
    assert shared["row_count"] == 2
    assert shared["accuracy"] == 1.0
    assert shared["macro_f1_shared_labels"] == 1.0


def test_external_checkpoint_evaluation_and_independent_verification(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    config = tmp_path / "external.yaml"
    external_workspace = tmp_path / "external"
    _source(source)
    _config(config)
    prepare_external_dataset(
        source_root=source, output=external_workspace, config_path=config
    )

    training = tmp_path / "training"
    training.mkdir()
    scaler = {
        "schema_version": "1.0",
        "method": "standard_score_population_variance",
        "fitted_on_split": "train",
        "feature_names": json.loads(
            (external_workspace / "dataset.json").read_text(encoding="utf-8")
        )["feature_names"],
        "mean": [0.0] * 25,
        "scale": [1.0] * 25,
    }
    (training / "scaler.json").write_text(json.dumps(scaler), encoding="utf-8")
    (training / "manifest.json").write_text(
        json.dumps({"dataset": "UWF-ZeekData24"}), encoding="utf-8"
    )

    class_names = [
        "benign",
        "credential_access",
        "exfiltration",
        "initial_access",
        "multi_tactic",
        "reconnaissance",
    ]
    import numpy as np
    import torch

    model = build_model(
        input_features=25,
        class_count=len(class_names),
        hidden_layers=[128, 64],
        embedding_size=32,
        dropout=0.0,
        torch=torch,
    )
    for parameter in model.parameters():
        parameter.data.zero_()
    model_export = export_state(
        model,
        architecture={
            "input_features": 25,
            "classification_head_outputs": len(class_names),
            "encoder_hidden_layers": [128, 64],
            "embedding_size": 32,
            "dropout": 0.0,
        },
        class_names=class_names,
    )
    assert np.isfinite(model_export["parameters"][0]["values"]).all()

    partition = tmp_path / "partition"
    (partition / "server").mkdir(parents=True)
    (partition / "server" / "evaluation.json").write_text("{}", encoding="utf-8")
    (partition / "manifest.json").write_text(
        json.dumps(
            {
                "server_evaluation_path": "server/evaluation.json",
                "source_m2_scaler_sha256": sha256_file(training / "scaler.json"),
                "class_names": class_names,
            }
        ),
        encoding="utf-8",
    )

    campaign = tmp_path / "campaign"
    model_path = campaign / "rounds" / "round-001" / "checkpoint" / "global-model.json"
    model_path.parent.mkdir(parents=True)
    model_path.write_text(json.dumps(model_export), encoding="utf-8")
    (campaign / "campaign-manifest.json").write_text(
        json.dumps(
            {
                "core": {
                    "selected_round": 1,
                    "selected_model_sha256": sha256_file(model_path),
                }
            }
        ),
        encoding="utf-8",
    )
    trust = tmp_path / "trust"
    trust.mkdir()
    output = tmp_path / "evaluation"

    monkeypatch.setattr(
        "fl_forensics.external_generalization.verify_m2_workspace",
        lambda _workspace: {"status": "verified", "errors": []},
    )
    monkeypatch.setattr(
        "fl_forensics.external_generalization.verify_secure_campaign",
        lambda **_kwargs: {"status": "verified", "errors": []},
    )

    result = evaluate_external_generalization(
        external_workspace=external_workspace,
        campaign_workspace=campaign,
        trust_workspace=trust,
        partition_workspace=partition,
        training_dataset_workspace=training,
        output=output,
        config_path=config,
    )
    assert result["status"] == "evaluated_external_post_selection"
    assert result["external_window_count"] == 3

    verified = verify_external_generalization(
        workspace=output,
        external_workspace=external_workspace,
        source_root=source,
        campaign_workspace=campaign,
        trust_workspace=trust,
        partition_workspace=partition,
        training_dataset_workspace=training,
        config_path=config,
    )
    assert verified["status"] == "verified"
    assert verified["metrics_recomputed"] is True
    assert verified["predictions_recomputed"] is True
