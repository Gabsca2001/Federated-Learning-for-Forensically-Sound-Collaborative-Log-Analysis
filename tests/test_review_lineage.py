from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fl_forensics.canonical import digest_object
from fl_forensics.lineage import LineageStore


class ReviewLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = LineageStore(self.root / "lineage")
        self.options = {
            "manifest_sha256": "1" * 64,
            "context_digest": "2" * 64,
            "submission_id": "submission-existing-immutable-subject",
            "disposition_sha256": "3" * 64,
            "review_id": "review-human-label",
            "review_record_sha256": "4" * 64,
        }

    def _record(self, **changes):
        digest, path = self.store.record_review_path(**{**self.options, **changes})
        return digest, path, json.loads(path.read_text(encoding="utf-8"))

    def test_initial_review_uses_serialized_record_commitment_and_context_scope(self) -> None:
        digest, path, fragment = self._record()
        self.assertEqual(digest_object(fragment), digest)
        self.assertEqual(path.name, f"{digest}.json")
        self.assertEqual(fragment["fragment_type"], "semantic_review")
        self.assertEqual(
            fragment["scope"],
            {
                "context_digest": self.options["context_digest"],
                "submission_id": self.options["submission_id"],
            },
        )
        reviews = [
            item for item in fragment["entities"] if item["type"] == "semantic_review_record"
        ]
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["id"], "review-record:" + self.options["review_record_sha256"])
        self.assertEqual(reviews[0]["digest"], self.options["review_record_sha256"])
        self.assertEqual(reviews[0]["review_id"], self.options["review_id"])

    def test_review_relations_do_not_assert_numeric_or_policy_changes(self) -> None:
        _, _, fragment = self._record()
        target = "review-record:" + self.options["review_record_sha256"]
        relations = {
            (item["type"], item["source"], item["target"]) for item in fragment["relations"]
        }
        self.assertEqual(
            relations,
            {
                ("review", "disposition:" + self.options["disposition_sha256"], target),
                ("audit", "manifest:" + self.options["manifest_sha256"], target),
                ("audit", self.options["submission_id"], target),
            },
        )
        self.assertTrue(all(item["type"] in {"review", "audit"} for item in fragment["relations"]))
        self.assertNotIn("checkpoint", {item["type"] for item in fragment["entities"]})

    def test_subject_predecessor_is_linked_without_rewriting_previous_fragment(self) -> None:
        _, first_path, _ = self._record()
        original = first_path.read_bytes()
        _, second_path, second = self._record(
            review_id="review-followup",
            review_record_sha256="5" * 64,
            previous_review_record_sha256=self.options["review_record_sha256"],
        )
        self.assertNotEqual(second_path, first_path)
        self.assertEqual(first_path.read_bytes(), original)
        self.assertIn(
            {
                "type": "review",
                "source": "review-record:" + self.options["review_record_sha256"],
                "target": "review-record:" + "5" * 64,
            },
            second["relations"],
        )
        identifiers = {item["id"] for item in second["entities"]}
        self.assertTrue(
            all(
                item["source"] in identifiers and item["target"] in identifiers
                for item in second["relations"]
            )
        )

    def test_retry_reuses_same_fragment_bytes_and_path(self) -> None:
        first_digest, first_path, _ = self._record()
        original = first_path.read_bytes()
        second_digest, second_path, _ = self._record()
        self.assertEqual((second_digest, second_path), (first_digest, first_path))
        self.assertEqual(second_path.read_bytes(), original)
        self.assertEqual(len(list(self.store.fragments.rglob("*.json"))), 1)

    def test_context_is_part_of_the_fragment_commitment(self) -> None:
        first_digest, first_path, _ = self._record()
        second_digest, second_path, second = self._record(context_digest="6" * 64)
        self.assertNotEqual(first_digest, second_digest)
        self.assertNotEqual(first_path, second_path)
        self.assertEqual(second["scope"]["context_digest"], "6" * 64)

    def test_invalid_commitments_and_self_predecessor_are_rejected(self) -> None:
        for field in (
            "manifest_sha256",
            "context_digest",
            "disposition_sha256",
            "review_record_sha256",
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self._record(**{field: "truncated"})
        with self.assertRaises(ValueError):
            self._record(previous_review_record_sha256=self.options["review_record_sha256"])
        self.assertEqual(len(list(self.store.fragments.rglob("*.json"))), 0)


if __name__ == "__main__":
    unittest.main()
