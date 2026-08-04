"""Flower Message API ClientApp backed by frozen M3 client snapshots."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flwr.app import ArrayRecord, Context, Message, MetricRecord, RecordDict
from flwr.clientapp import ClientApp

from .config import load_yaml
from .federated_model import (
    build_model,
    dependencies,
    evaluate_rows,
    model_to_ndarrays,
    train_local,
)

app = ClientApp()


def _client_contract(context: Context) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    workspace = Path(str(context.run_config["partition-workspace"]))
    manifest = json.loads((workspace / "manifest.json").read_text(encoding="utf-8"))
    partition_id = int(context.node_config["partition-id"])
    if partition_id < 0 or partition_id >= int(manifest["client_count"]):
        raise ValueError(f"Flower partition-id outside M3 contract: {partition_id}")
    record = manifest["clients"][partition_id]
    snapshot = json.loads((workspace / record["dataset_path"]).read_text(encoding="utf-8"))
    config, _digest = load_yaml(Path("configs/federation.yaml"))
    return manifest, snapshot, config


def _model(manifest: dict[str, Any], config: dict[str, Any], torch: Any) -> Any:
    model_config = config["model"]
    return build_model(
        input_features=len(manifest["feature_names"]),
        class_count=len(manifest["class_names"]),
        hidden_layers=[int(value) for value in model_config["hidden_layers"]],
        embedding_size=int(model_config["embedding_size"]),
        dropout=float(model_config["dropout"]),
        torch=torch,
    )


@app.train()
def train(msg: Message, context: Context) -> Message:
    dependency_values = dependencies()
    np, torch, *_rest = dependency_values
    manifest, snapshot, config = _client_contract(context)
    model = _model(manifest, config, torch)
    model.load_state_dict(msg.content["arrays"].to_torch_state_dict(), strict=True)
    partition_id = int(context.node_config["partition-id"])
    server_round = int(msg.content["config"]["server-round"])
    base_arrays = model_to_ndarrays(model, np=np)
    training = config["training"]
    result = train_local(
        model=model,
        rows=snapshot["rows"]["train"],
        class_names=manifest["class_names"],
        class_weights={
            key: float(value)
            for key, value in manifest["global_class_weights"].items()
        },
        epochs=int(context.run_config["local-epochs"]),
        batch_size=int(context.run_config["batch-size"]),
        learning_rate=float(msg.content["config"]["learning-rate"]),
        seed=int(context.run_config["seed"]) + server_round * 10_000 + partition_id,
        device_name=str(training["device"]),
        torch=torch,
        np=np,
    )
    updated_arrays = model_to_ndarrays(model, np=np)
    squared = sum(
        float(np.square(new.astype(np.float64) - old.astype(np.float64)).sum())
        for old, new in zip(base_arrays, updated_arrays, strict=True)
    )
    metrics = MetricRecord(
        {
            "train_loss": float(result["train_loss"]),
            "num-examples": int(result["num_examples"]),
            "update_delta_l2": float(np.sqrt(squared)),
        }
    )
    return Message(
        content=RecordDict(
            {"arrays": ArrayRecord(model.state_dict()), "metrics": metrics}
        ),
        reply_to=msg,
    )


@app.evaluate()
def evaluate(msg: Message, context: Context) -> Message:
    dependency_values = dependencies()
    (
        np,
        torch,
        _flwr,
        _sklearn,
        _aggregate,
        accuracy_score,
        confusion_matrix,
        precision_recall_fscore_support,
    ) = dependency_values
    manifest, snapshot, config = _client_contract(context)
    model = _model(manifest, config, torch)
    model.load_state_dict(msg.content["arrays"].to_torch_state_dict(), strict=True)
    result = evaluate_rows(
        model=model,
        rows=snapshot["rows"]["validation"],
        class_names=manifest["class_names"],
        batch_size=int(context.run_config["batch-size"]),
        torch=torch,
        np=np,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )
    metrics = MetricRecord(
        {
            "eval_loss": float(result["loss"]),
            "eval_accuracy": float(result["accuracy"]),
            "eval_macro_f1": float(result["macro_f1_all_model_classes"]),
            "num-examples": int(result["row_count"]),
        }
    )
    return Message(content=RecordDict({"metrics": metrics}), reply_to=msg)
