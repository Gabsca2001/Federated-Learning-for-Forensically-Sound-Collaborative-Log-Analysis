"""Small queryable lineage index backed by immutable graph fragments."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import digest_object
from .storage import write_json_once


class LineageStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.fragments = root / "fragments"

    def preserve_fragment(self, fragment: dict[str, Any]) -> tuple[str, Path]:
        digest = digest_object(fragment)
        path = self.fragments / digest[:2] / f"{digest}.json"
        write_json_once(path, fragment)
        return digest, path

    def record_snapshot_path(
        self,
        *,
        batch_id: str,
        batch_digest: str,
        decision_id: str,
        decision_digest: str,
        snapshot_id: str,
        snapshot_digest: str,
        window_ids: list[str],
    ) -> tuple[str, Path]:
        fragment = {
            "schema_version": "1.0",
            "entities": [
                {"id": batch_id, "type": "batch_bundle", "digest": batch_digest},
                {"id": decision_id, "type": "admission_decision", "digest": decision_digest},
                {"id": snapshot_id, "type": "dataset_snapshot", "digest": snapshot_digest},
                *[{"id": item, "type": "feature_window"} for item in sorted(window_ids)],
            ],
            "activities": [
                {"id": f"activity-build-{snapshot_id}", "type": "snapshot_construction"}
            ],
            "relations": [
                {"type": "wasAdmittedBy", "entity": batch_id, "decision": decision_id},
                {
                    "type": "used",
                    "activity": f"activity-build-{snapshot_id}",
                    "entity": batch_id,
                },
                {
                    "type": "wasGeneratedBy",
                    "entity": snapshot_id,
                    "activity": f"activity-build-{snapshot_id}",
                },
                *[
                    {"type": "wasDerivedFrom", "entity": item, "source": snapshot_id}
                    for item in sorted(window_ids)
                ],
            ],
        }
        return self.preserve_fragment(fragment)

