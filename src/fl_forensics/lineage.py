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

    def record_review_path(
        self,
        *,
        manifest_sha256: str,
        context_digest: str,
        submission_id: str,
        disposition_sha256: str,
        review_id: str,
        review_record_sha256: str,
        previous_review_record_sha256: str | None = None,
    ) -> tuple[str, Path]:
        """Index an already verified review without changing its historical target.

        This fragment is a rebuildable index, not proof of a ledger signature,
        reviewer authorization, or an externally anchored history. The previous
        review, when provided, is the previous review of this subject.
        """
        commitments = [manifest_sha256, context_digest, disposition_sha256, review_record_sha256]
        if previous_review_record_sha256 is not None:
            commitments.append(previous_review_record_sha256)
        if any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in commitments
        ):
            raise ValueError("review lineage requires full lowercase SHA-256 commitments")
        if not submission_id.strip() or not review_id.strip():
            raise ValueError("review lineage requires submission and review identifiers")
        if previous_review_record_sha256 == review_record_sha256:
            raise ValueError("a review cannot be its own predecessor")
        manifest_node = f"manifest:{manifest_sha256}"
        disposition_node = f"disposition:{disposition_sha256}"
        review_node = f"review-record:{review_record_sha256}"
        entities = [
            {
                "id": manifest_node,
                "type": "round_derivation_manifest",
                "digest": manifest_sha256,
            },
            {"id": submission_id, "type": "submission"},
            {
                "id": disposition_node,
                "type": "submission_final_disposition",
                "digest": disposition_sha256,
            },
            {
                "id": review_node,
                "type": "semantic_review_record",
                "digest": review_record_sha256,
                "review_id": review_id,
            },
        ]
        relations = [
            {"type": "review", "source": disposition_node, "target": review_node},
            {"type": "audit", "source": manifest_node, "target": review_node},
            {"type": "audit", "source": submission_id, "target": review_node},
        ]
        if previous_review_record_sha256 is not None:
            previous_node = f"review-record:{previous_review_record_sha256}"
            entities.append(
                {
                    "id": previous_node,
                    "type": "semantic_review_record",
                    "digest": previous_review_record_sha256,
                }
            )
            relations.append({"type": "review", "source": previous_node, "target": review_node})
        return self.preserve_fragment(
            {
                "schema_version": "1.0",
                "fragment_type": "semantic_review",
                "scope": {"context_digest": context_digest, "submission_id": submission_id},
                "entities": entities,
                "activities": [],
                "relations": relations,
            }
        )
