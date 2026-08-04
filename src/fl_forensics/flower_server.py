"""Flower Message API ServerApp for the clean 15-client FedAvg baseline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flwr.app import ArrayRecord, ConfigRecord, Context, MetricRecord
from flwr.serverapp import Grid, ServerApp
from flwr.serverapp.strategy import FedAvg

from .config import load_yaml
from .federated_model import build_model, dependencies, evaluate_rows, seed_everything

app = ServerApp()


@app.main()
def main(grid: Grid, context: Context) -> None:
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
    workspace = Path(str(context.run_config["partition-workspace"]))
    manifest = json.loads((workspace / "manifest.json").read_text(encoding="utf-8"))
    server_evaluation = json.loads(
        (workspace / manifest["server_evaluation_path"]).read_text(encoding="utf-8")
    )
    config, _digest = load_yaml(Path("configs/federation.yaml"))
    model_config = config["model"]
    seed_everything(int(context.run_config["seed"]), torch=torch, np=np)

    def new_model() -> Any:
        return build_model(
            input_features=len(manifest["feature_names"]),
            class_count=len(manifest["class_names"]),
            hidden_layers=[int(value) for value in model_config["hidden_layers"]],
            embedding_size=int(model_config["embedding_size"]),
            dropout=float(model_config["dropout"]),
            torch=torch,
        )

    initial_model = new_model()

    def global_evaluate(server_round: int, arrays: ArrayRecord) -> MetricRecord:
        evaluation_model = new_model()
        evaluation_model.load_state_dict(arrays.to_torch_state_dict(), strict=True)
        result = evaluate_rows(
            model=evaluation_model,
            rows=server_evaluation["rows"]["validation"],
            class_names=manifest["class_names"],
            batch_size=int(context.run_config["batch-size"]),
            torch=torch,
            np=np,
            accuracy_score=accuracy_score,
            confusion_matrix=confusion_matrix,
            precision_recall_fscore_support=precision_recall_fscore_support,
        )
        return MetricRecord(
            {
                "server_round": server_round,
                "validation_loss": float(result["loss"]),
                "validation_accuracy": float(result["accuracy"]),
                "validation_macro_f1": float(result["macro_f1_all_model_classes"]),
            }
        )

    client_count = int(manifest["client_count"])
    strategy = FedAvg(
        fraction_train=1.0,
        fraction_evaluate=1.0,
        min_train_nodes=client_count,
        min_evaluate_nodes=client_count,
        min_available_nodes=client_count,
        weighted_by_key="num-examples",
    )
    strategy.start(
        grid=grid,
        initial_arrays=ArrayRecord(initial_model.state_dict()),
        train_config=ConfigRecord(
            {"learning-rate": float(context.run_config["learning-rate"])}
        ),
        num_rounds=int(context.run_config["num-server-rounds"]),
        evaluate_fn=global_evaluate,
    )
