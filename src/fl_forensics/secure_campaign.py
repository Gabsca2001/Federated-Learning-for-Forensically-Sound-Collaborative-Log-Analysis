"""Verification, validation-only selection, and final evaluation for secure M5 campaigns."""

from __future__ import annotations

import statistics
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from .canonical import digest_object, sha256_bytes, sha256_file
from .federated_model import (
    arrays_from_export,
    build_model,
    dependencies,
    evaluate_rows,
    load_ndarrays,
)
from .preprocessing import derived_json_bytes
from .secure_round import (
    EXPECTED_CLIENTS,
    GENESIS_DIGEST,
    SecureRoundError,
    _coordinator_public_key,
    _coordinator_signer,
    _signature,
    _verify_signed,
    verify_secure_round,
)
from .secure_round_models import (
    SecureCampaignManifest,
    SecureCampaignManifestCore,
    SecureCampaignRoundReference,
    SecureCheckpoint,
    SecureRoundContext,
)
from .storage import load_json, write_json_once, write_once

SELECTION_METRIC = "macro_f1_all_model_classes"


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _round_workspace(campaign_workspace: Path, round_number: int) -> Path:
    return campaign_workspace / "rounds" / f"round-{round_number:03d}"


def _model_from_export(value: dict[str, Any], *, torch: Any, np: Any) -> Any:
    architecture = value["architecture"]
    model = build_model(
        input_features=int(architecture["input_features"]),
        class_count=int(architecture["classification_head_outputs"]),
        hidden_layers=[int(item) for item in architecture["encoder_hidden_layers"]],
        embedding_size=int(architecture["embedding_size"]),
        dropout=float(architecture["dropout"]),
        torch=torch,
    )
    load_ndarrays(
        model,
        arrays_from_export(value, np=np),
        torch=torch,
        np=np,
    )
    return model


def _evaluate_export(
    *,
    model_export: dict[str, Any],
    rows: list[dict[str, Any]],
    class_names: list[str],
    batch_size: int,
    dependency_values: tuple[Any, ...],
) -> dict[str, Any]:
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
    model = _model_from_export(model_export, torch=torch, np=np)
    return evaluate_rows(
        model=model,
        rows=rows,
        class_names=class_names,
        batch_size=batch_size,
        torch=torch,
        np=np,
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
    )


def _load_client_local_tests(
    *, partition_manifest_path: Path, partition: dict[str, Any]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Load digest-bound local tests only when the partition supports them."""

    if not partition.get("local_test_strategy"):
        return []
    snapshots = []
    partition_workspace = partition_manifest_path.parent
    for record in partition.get("clients", []):
        relative = str(record.get("local_test_path", ""))
        relative_path = Path(relative)
        expected_prefix = f"evaluation/clients/{record['client_id']}/"
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or not relative_path.as_posix().startswith(expected_prefix)
        ):
            raise SecureRoundError(
                f"local test is outside evaluation boundary: {record['client_id']}"
            )
        path = partition_workspace / relative_path
        if not path.is_file() or sha256_file(path) != record.get("local_test_sha256"):
            raise SecureRoundError(f"local test digest mismatch: {record['client_id']}")
        snapshot = load_json(path)
        if snapshot.get("client_id") != record["client_id"] or set(snapshot.get("rows", {})) != {
            "test"
        }:
            raise SecureRoundError(f"local test identity or split mismatch: {record['client_id']}")
        if snapshot.get("class_names") != partition.get("class_names"):
            raise SecureRoundError(f"local test class order mismatch: {record['client_id']}")
        if len(snapshot["rows"]["test"]) != int(record.get("local_test_row_count", -1)):
            raise SecureRoundError(f"local test row count mismatch: {record['client_id']}")
        snapshots.append((record, snapshot))
    return snapshots


def _load_isolated_server_split(
    *, partition_manifest_path: Path, partition: dict[str, Any], split: str
) -> list[dict[str, Any]]:
    records = partition.get("server_evaluation_splits")
    if not isinstance(records, dict) or split not in records:
        raise SecureRoundError(f"missing isolated server split: {split}")
    record = records[split]
    relative = Path(str(record.get("path", "")))
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not relative.as_posix().startswith("server/splits/")
    ):
        raise SecureRoundError(f"server {split} path escapes split boundary")
    path = partition_manifest_path.parent / relative
    if not path.is_file() or sha256_file(path) != record.get("sha256"):
        raise SecureRoundError(f"server {split} isolated digest mismatch")
    snapshot = load_json(path)
    if (
        snapshot.get("split") != split
        or set(snapshot.get("rows", {})) != {split}
        or snapshot.get("class_names") != partition.get("class_names")
    ):
        raise SecureRoundError(f"server {split} isolated identity mismatch")
    rows = list(snapshot["rows"][split])
    if not rows or len(rows) != int(record.get("row_count", -1)):
        raise SecureRoundError(f"server {split} isolated row count mismatch")
    return rows


def _metric_summary(items: list[dict[str, Any]], key: str) -> dict[str, Any]:
    values = [float(item[key]) for item in items if item.get(key) is not None]
    return {
        "client_count": len(values),
        "mean": statistics.fmean(values) if values else None,
        "population_stddev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "minimum": min(values) if values else None,
        "maximum": max(values) if values else None,
    }


def _inspect_campaign(
    *,
    workspace: Path,
    trust_workspace: Path,
    partition_manifest_path: Path,
    server_evaluation_path: Path,
    expected_rounds: int,
) -> dict[str, Any]:
    if expected_rounds < 1:
        raise SecureRoundError("a secure campaign must contain at least one round")
    partition = load_json(partition_manifest_path)
    if (
        int(partition.get("client_count", 0)) != len(EXPECTED_CLIENTS)
        or [item.get("client_id") for item in partition.get("clients", [])] != EXPECTED_CLIENTS
    ):
        raise SecureRoundError("campaign partition does not contain the ordered 15 clients")
    if sha256_file(server_evaluation_path) != partition.get("server_evaluation_sha256"):
        raise SecureRoundError("server evaluation digest does not match partition manifest")
    class_names = [str(item) for item in partition["class_names"]]
    isolated_server_splits = bool(partition.get("server_evaluation_splits"))
    server_evaluation = None
    if isolated_server_splits:
        validation_rows = _load_isolated_server_split(
            partition_manifest_path=partition_manifest_path,
            partition=partition,
            split="validation",
        )
    else:
        server_evaluation = load_json(server_evaluation_path)
        if server_evaluation.get("class_names") != class_names:
            raise SecureRoundError("server evaluation class order differs from partition")
        for split in ("validation", "test", "temporal_holdout"):
            if not server_evaluation.get("rows", {}).get(split):
                raise SecureRoundError(f"server evaluation split is empty: {split}")
        validation_rows = server_evaluation["rows"]["validation"]

    coordinator_key = _coordinator_public_key(workspace)
    dependency_values = dependencies()
    partition_sha256 = sha256_file(partition_manifest_path)
    previous_checkpoint_sha256 = GENESIS_DIGEST
    previous_model_sha256: str | None = None
    campaign_id: str | None = None
    federation_config_sha256: str | None = None
    references: list[SecureCampaignRoundReference] = []
    validation_artifacts: list[dict[str, Any]] = []

    for round_number in range(1, expected_rounds + 1):
        round_workspace = _round_workspace(workspace, round_number)
        verification = verify_secure_round(
            workspace=round_workspace,
            trust_workspace=trust_workspace,
            submissions_root=round_workspace / "submissions",
        )
        if verification["status"] != "verified":
            raise SecureRoundError(
                f"secure round {round_number} failed independent verification: "
                f"{verification['errors']}"
            )
        context_path = round_workspace / "public" / "round-context.json"
        checkpoint_path = round_workspace / "checkpoint" / "manifest.json"
        model_path = round_workspace / "checkpoint" / "global-model.json"
        context = SecureRoundContext.model_validate(load_json(context_path))
        checkpoint = SecureCheckpoint.model_validate(load_json(checkpoint_path))
        if not _verify_signed(context, coordinator_key):
            raise SecureRoundError(f"round {round_number} context uses another coordinator")
        if not _verify_signed(checkpoint, coordinator_key):
            raise SecureRoundError(f"round {round_number} checkpoint uses another coordinator")
        if campaign_id is None:
            campaign_id = context.core.campaign_id
            federation_config_sha256 = context.core.federation_config_sha256
        binding_valid = (
            context.core.campaign_id == campaign_id
            and checkpoint.core.campaign_id == campaign_id
            and context.core.round_number == round_number
            and checkpoint.core.round_number == round_number
            and checkpoint.core.context_digest == context.core_digest
            and context.core.previous_checkpoint_sha256 == previous_checkpoint_sha256
            and checkpoint.core.previous_checkpoint_sha256 == previous_checkpoint_sha256
            and context.core.partition_manifest_sha256 == partition_sha256
            and context.core.federation_config_sha256 == federation_config_sha256
            and checkpoint.core.base_model_sha256 == context.core.base_model_sha256
            and (
                previous_model_sha256 is None
                or context.core.base_model_sha256 == previous_model_sha256
            )
            and checkpoint.core.accepted_count == len(EXPECTED_CLIENTS)
            and checkpoint.core.quarantined_count == 0
            and sha256_file(model_path) == checkpoint.core.global_model_sha256
        )
        if not binding_valid:
            raise SecureRoundError(f"round {round_number} breaks the campaign chain")

        model_export = load_json(model_path)
        if model_export.get("class_names") != class_names:
            raise SecureRoundError(f"round {round_number} changed model class order")
        validation = _evaluate_export(
            model_export=model_export,
            rows=validation_rows,
            class_names=class_names,
            batch_size=context.core.batch_size,
            dependency_values=dependency_values,
        )
        validation_artifact = {
            "schema_version": "1.0",
            "artifact_type": "secure_round_validation_metrics",
            "campaign_id": campaign_id,
            "round_number": round_number,
            "checkpoint_sha256": sha256_file(checkpoint_path),
            "global_model_sha256": checkpoint.core.global_model_sha256,
            "selection_eligible": True,
            "test_data_observed": False,
            "validation": validation,
        }
        validation_bytes = derived_json_bytes(validation_artifact)
        references.append(
            SecureCampaignRoundReference(
                round_number=round_number,
                context_id=context.context_id,
                context_sha256=sha256_file(context_path),
                checkpoint_id=checkpoint.checkpoint_id,
                checkpoint_sha256=sha256_file(checkpoint_path),
                base_model_sha256=context.core.base_model_sha256,
                global_model_sha256=checkpoint.core.global_model_sha256,
                validation_metrics_sha256=sha256_bytes(validation_bytes),
                accepted_count=checkpoint.core.accepted_count,
            )
        )
        validation_artifacts.append(validation_artifact)
        previous_checkpoint_sha256 = sha256_file(checkpoint_path)
        previous_model_sha256 = checkpoint.core.global_model_sha256

    selected_validation = max(
        validation_artifacts,
        key=lambda item: (
            float(item["validation"][SELECTION_METRIC]),
            -int(item["round_number"]),
        ),
    )
    selected_round = int(selected_validation["round_number"])
    selected_reference = references[selected_round - 1]
    selected_context = SecureRoundContext.model_validate(
        load_json(_round_workspace(workspace, selected_round) / "public" / "round-context.json")
    )
    selected_model = load_json(
        _round_workspace(workspace, selected_round) / "checkpoint" / "global-model.json"
    )
    if isolated_server_splits:
        test_rows = _load_isolated_server_split(
            partition_manifest_path=partition_manifest_path,
            partition=partition,
            split="test",
        )
        temporal_holdout_rows = _load_isolated_server_split(
            partition_manifest_path=partition_manifest_path,
            partition=partition,
            split="temporal_holdout",
        )
    else:
        assert server_evaluation is not None
        test_rows = server_evaluation["rows"]["test"]
        temporal_holdout_rows = server_evaluation["rows"]["temporal_holdout"]
    client_local_tests = _load_client_local_tests(
        partition_manifest_path=partition_manifest_path, partition=partition
    )
    if client_local_tests:
        observed_local_test_ids = [
            str(row.get("window_id"))
            for _record, snapshot in client_local_tests
            for row in snapshot["rows"]["test"]
        ]
        expected_test_ids = [str(row.get("window_id")) for row in test_rows]
        if len(observed_local_test_ids) != len(set(observed_local_test_ids)) or set(
            observed_local_test_ids
        ) != set(expected_test_ids):
            raise SecureRoundError(
                "client-local tests do not exactly reconstruct the server test split"
            )
    selected_client_test = [
        {
            "client_id": record["client_id"],
            "local_test_snapshot_sha256": record["local_test_sha256"],
            "test": _evaluate_export(
                model_export=selected_model,
                rows=snapshot["rows"]["test"],
                class_names=class_names,
                batch_size=selected_context.core.batch_size,
                dependency_values=dependency_values,
            ),
        }
        for record, snapshot in client_local_tests
    ]
    final_evaluation = {
        "schema_version": "1.0",
        "artifact_type": "secure_campaign_selected_checkpoint_evaluation",
        "campaign_id": campaign_id,
        "selected_round": selected_round,
        "selected_checkpoint_sha256": selected_reference.checkpoint_sha256,
        "selected_model_sha256": selected_reference.global_model_sha256,
        "selection": {
            "split": "validation",
            "metric": SELECTION_METRIC,
            "mode": "maximize",
            "tie_breaker": "earliest_round",
            "value": selected_validation["validation"][SELECTION_METRIC],
        },
        "evaluation_order": [
            "select checkpoint from stored per-round validation metrics",
            "evaluate selected checkpoint on validation, test, and temporal_holdout",
        ],
        "metrics": {
            split: _evaluate_export(
                model_export=selected_model,
                rows={
                    "validation": validation_rows,
                    "test": test_rows,
                    "temporal_holdout": temporal_holdout_rows,
                }[split],
                class_names=class_names,
                batch_size=selected_context.core.batch_size,
                dependency_values=dependency_values,
            )
            for split in ("validation", "test", "temporal_holdout")
        },
    }
    if selected_client_test:
        final_evaluation["evaluation_order"].append(
            "evaluate the already-selected checkpoint on separate client-local test snapshots"
        )
        final_evaluation["client_local_test_strategy"] = partition["local_test_strategy"]
        final_evaluation["selected_global_client_test"] = selected_client_test
        final_evaluation["selected_global_client_test_summary"] = {
            SELECTION_METRIC: _metric_summary(
                [item["test"] for item in selected_client_test], SELECTION_METRIC
            )
        }
    if isolated_server_splits:
        final_evaluation["test_access_mode"] = "isolated-split-artifacts-after-selection"
    assert campaign_id is not None
    assert federation_config_sha256 is not None
    return {
        "campaign_id": campaign_id,
        "partition_manifest_sha256": partition_sha256,
        "server_evaluation_sha256": sha256_file(server_evaluation_path),
        "federation_config_sha256": federation_config_sha256,
        "references": references,
        "validation_artifacts": validation_artifacts,
        "selected_validation": selected_validation,
        "selected_reference": selected_reference,
        "final_evaluation": final_evaluation,
    }


def finalize_secure_campaign(
    *,
    workspace: Path,
    trust_workspace: Path,
    partition_manifest_path: Path,
    server_evaluation_path: Path,
    expected_rounds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify all rounds, select on validation, then evaluate test exactly once."""

    manifest_path = workspace / "campaign-manifest.json"
    if manifest_path.exists():
        raise FileExistsError(f"secure campaign is already finalized: {manifest_path}")
    inspected = _inspect_campaign(
        workspace=workspace,
        trust_workspace=trust_workspace,
        partition_manifest_path=partition_manifest_path,
        server_evaluation_path=server_evaluation_path,
        expected_rounds=expected_rounds,
    )
    evaluation_root = workspace / "evaluation"
    for artifact in inspected["validation_artifacts"]:
        round_number = int(artifact["round_number"])
        write_once(
            evaluation_root / f"round-{round_number:03d}-validation.json",
            derived_json_bytes(artifact),
        )
    final_bytes = derived_json_bytes(inspected["final_evaluation"])
    final_path = evaluation_root / "selected-checkpoint-evaluation.json"
    write_once(final_path, final_bytes)

    selected_validation = inspected["selected_validation"]
    selected_reference = inspected["selected_reference"]
    core = SecureCampaignManifestCore(
        campaign_id=inspected["campaign_id"],
        round_count=expected_rounds,
        required_client_count=len(EXPECTED_CLIENTS),
        total_accepted_contributions=expected_rounds * len(EXPECTED_CLIENTS),
        partition_manifest_sha256=inspected["partition_manifest_sha256"],
        server_evaluation_sha256=inspected["server_evaluation_sha256"],
        federation_config_sha256=inspected["federation_config_sha256"],
        selected_round=int(selected_validation["round_number"]),
        selected_checkpoint_sha256=selected_reference.checkpoint_sha256,
        selected_model_sha256=selected_reference.global_model_sha256,
        selected_validation_macro_f1_decimal=str(
            Decimal(str(selected_validation["validation"][SELECTION_METRIC]))
        ),
        final_evaluation_sha256=sha256_file(final_path),
        rounds=inspected["references"],
        created_at=_utc(now or datetime.now(UTC)),
    )
    digest = digest_object(core.model_dump(mode="json"))
    signer = _coordinator_signer(workspace, create=False, coordinator_workspace=workspace)
    manifest = SecureCampaignManifest(
        manifest_id=f"secure-campaign-{digest[:24]}",
        core=core,
        core_digest=digest,
        signature=_signature(signer, digest, "software-development"),
    )
    write_json_once(manifest_path, manifest.model_dump(mode="json"))
    return {
        "status": "finalized",
        "campaign_id": core.campaign_id,
        "round_count": core.round_count,
        "accepted_contribution_count": core.total_accepted_contributions,
        "selected_round": core.selected_round,
        "selected_validation_macro_f1": float(core.selected_validation_macro_f1_decimal),
        "selected_test_macro_f1": inspected["final_evaluation"]["metrics"]["test"][
            SELECTION_METRIC
        ],
        "confusion_matrices": {
            split: inspected["final_evaluation"]["metrics"][split]["confusion_matrix"]
            for split in ("validation", "test", "temporal_holdout")
        },
        "client_confusion_matrix_count": len(
            inspected["final_evaluation"].get("selected_global_client_test", [])
        ),
        "manifest_sha256": sha256_file(manifest_path),
        "workspace": str(workspace),
    }


def verify_secure_campaign(
    *,
    workspace: Path,
    trust_workspace: Path,
    partition_manifest_path: Path,
    server_evaluation_path: Path,
) -> dict[str, Any]:
    """Independently verify the round chain, selection, and final evaluation."""

    errors: list[str] = []
    inspected: dict[str, Any] | None = None
    try:
        manifest_path = workspace / "campaign-manifest.json"
        manifest = SecureCampaignManifest.model_validate(load_json(manifest_path))
        if not _verify_signed(manifest, _coordinator_public_key(workspace)):
            errors.append("invalid coordinator signature on campaign manifest")
        inspected = _inspect_campaign(
            workspace=workspace,
            trust_workspace=trust_workspace,
            partition_manifest_path=partition_manifest_path,
            server_evaluation_path=server_evaluation_path,
            expected_rounds=manifest.core.round_count,
        )
        expected_references = [item.model_dump(mode="json") for item in inspected["references"]]
        if [item.model_dump(mode="json") for item in manifest.core.rounds] != (expected_references):
            errors.append("campaign round references differ from verified round artifacts")
        selected_reference = inspected["selected_reference"]
        expected_core_values = {
            "campaign id": (manifest.core.campaign_id, inspected["campaign_id"]),
            "partition digest": (
                manifest.core.partition_manifest_sha256,
                inspected["partition_manifest_sha256"],
            ),
            "server evaluation digest": (
                manifest.core.server_evaluation_sha256,
                inspected["server_evaluation_sha256"],
            ),
            "federation config digest": (
                manifest.core.federation_config_sha256,
                inspected["federation_config_sha256"],
            ),
            "selected round": (
                manifest.core.selected_round,
                int(inspected["selected_validation"]["round_number"]),
            ),
            "selected checkpoint": (
                manifest.core.selected_checkpoint_sha256,
                selected_reference.checkpoint_sha256,
            ),
            "selected model": (
                manifest.core.selected_model_sha256,
                selected_reference.global_model_sha256,
            ),
        }
        for name, (observed, expected) in expected_core_values.items():
            if observed != expected:
                errors.append(f"campaign {name} mismatch")
        expected_f1 = str(
            Decimal(str(inspected["selected_validation"]["validation"][SELECTION_METRIC]))
        )
        if manifest.core.selected_validation_macro_f1_decimal != expected_f1:
            errors.append("selected validation metric mismatch")
        for artifact in inspected["validation_artifacts"]:
            round_number = int(artifact["round_number"])
            path = workspace / "evaluation" / f"round-{round_number:03d}-validation.json"
            expected_bytes = derived_json_bytes(artifact)
            if not path.is_file() or path.read_bytes() != expected_bytes:
                errors.append(f"round {round_number} validation artifact mismatch")
        final_path = workspace / "evaluation" / "selected-checkpoint-evaluation.json"
        expected_final = derived_json_bytes(inspected["final_evaluation"])
        if not final_path.is_file() or final_path.read_bytes() != expected_final:
            errors.append("selected checkpoint evaluation mismatch")
        elif sha256_file(final_path) != manifest.core.final_evaluation_sha256:
            errors.append("selected checkpoint evaluation digest mismatch")
        expected_total = manifest.core.round_count * len(EXPECTED_CLIENTS)
        if (
            manifest.core.required_client_count != len(EXPECTED_CLIENTS)
            or manifest.core.total_accepted_contributions != expected_total
        ):
            errors.append("campaign accepted-contribution count mismatch")
    except (FileNotFoundError, KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(str(exc))
        manifest = None
    return {
        "status": "verified" if not errors else "failed",
        "workspace": str(workspace),
        "campaign_id": manifest.core.campaign_id if manifest is not None else None,
        "round_count": manifest.core.round_count if manifest is not None else 0,
        "selected_round": manifest.core.selected_round if manifest is not None else None,
        "accepted_contribution_count": (
            manifest.core.total_accepted_contributions if manifest is not None else 0
        ),
        "confusion_matrices": (
            {
                split: inspected["final_evaluation"]["metrics"][split]["confusion_matrix"]
                for split in ("validation", "test", "temporal_holdout")
            }
            if inspected is not None and not errors
            else {}
        ),
        "client_confusion_matrix_count": (
            len(inspected["final_evaluation"].get("selected_global_client_test", []))
            if inspected is not None and not errors
            else 0
        ),
        "error_count": len(errors),
        "errors": errors,
    }
