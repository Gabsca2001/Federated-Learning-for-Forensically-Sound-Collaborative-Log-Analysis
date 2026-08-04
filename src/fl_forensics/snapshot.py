"""Construction of immutable local dataset snapshots from admitted batches."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .canonical import digest_object, sha256_bytes
from .lineage import LineageStore
from .models import AdmissionDecision, BatchManifest, DigestRef, SnapshotManifest
from .preprocessing import FEATURE_NAMES, derived_json_bytes, normalize_and_window
from .storage import utc_now, write_once, write_json_once


def build_snapshot(
    *,
    raw: bytes,
    manifest: BatchManifest,
    decision: AdmissionDecision,
    output_root: Path,
    lineage_store: LineageStore,
    preprocessing_config: dict[str, Any],
    source_dataset: str,
    source_dataset_version: str,
    code_version: str = "0.1.0",
) -> tuple[SnapshotManifest, Path]:
    if decision.status != "accepted":
        raise PermissionError("Snapshot Builder accepts only positively admitted batches")

    decision_digest = digest_object(decision.model_dump(mode="json"))
    result = normalize_and_window(
        raw=raw,
        batch_id=manifest.core.batch_id,
        batch_digest=manifest.chain_hash,
        client_id=manifest.core.client_id,
        config=preprocessing_config,
    )
    dataset = {
        "schema_version": str(preprocessing_config["schema_version"]),
        "feature_names": FEATURE_NAMES,
        "rows": result.rows,
    }
    dataset_bytes = derived_json_bytes(dataset)
    lineage_bytes = derived_json_bytes(result.lineage)
    dataset_digest = sha256_bytes(dataset_bytes)
    lineage_digest = sha256_bytes(lineage_bytes)
    snapshot_id = f"snapshot-{manifest.core.client_id}-{dataset_digest[:24]}"
    snapshot_directory = output_root / snapshot_id

    class_counts = Counter(row["label"] for row in result.rows)
    split_counts = Counter(row["split"] for row in result.rows)
    preprocessing_digest = digest_object(preprocessing_config)
    snapshot_manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        client_id=manifest.core.client_id,
        input_batches=[
            DigestRef(artifact_id=manifest.core.batch_id, digest=manifest.chain_hash)
        ],
        input_decisions=[
            DigestRef(artifact_id=decision.decision_id, digest=decision_digest)
        ],
        source_dataset=source_dataset,
        source_dataset_version=source_dataset_version,
        preprocessing_schema=str(preprocessing_config["schema_version"]),
        preprocessing_config_digest=preprocessing_digest,
        code_version=code_version,
        seed=int(preprocessing_config["split_seed"]),
        feature_names=FEATURE_NAMES,
        class_counts=dict(sorted(class_counts.items())),
        split_counts=dict(sorted(split_counts.items())),
        discarded_records=result.discarded_records,
        dataset_digest=dataset_digest,
        lineage_digest=lineage_digest,
        built_at=utc_now(),
    )

    write_once(snapshot_directory / "dataset.json", dataset_bytes)
    write_once(snapshot_directory / "window_lineage.json", lineage_bytes)
    normalized_bytes = b"".join(
        derived_json_bytes(event) for event in result.normalized_events
    )
    write_once(snapshot_directory / "normalized_events.jsonl", normalized_bytes)
    write_json_once(snapshot_directory / "manifest.json", snapshot_manifest.model_dump(mode="json"))

    lineage_store.record_snapshot_path(
        batch_id=manifest.core.batch_id,
        batch_digest=manifest.chain_hash,
        decision_id=decision.decision_id,
        decision_digest=decision_digest,
        snapshot_id=snapshot_id,
        snapshot_digest=dataset_digest,
        window_ids=[row["window_id"] for row in result.rows],
    )
    return snapshot_manifest, snapshot_directory

