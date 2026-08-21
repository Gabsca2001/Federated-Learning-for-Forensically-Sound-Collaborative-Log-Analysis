from __future__ import annotations

import copy
import math
import unittest

from fl_forensics.federated_model import FederatedDependencyError, dependencies
from fl_forensics.prototypes import (
    PrototypeConfigurationError,
    aggregate_class_prototypes,
    extract_class_prototypes,
    poison_prototype_records,
    prototype_distance_indicators,
)


def _submission(
    client_id: str,
    *,
    reconnaissance: list[float],
    rare: list[float] | None = None,
) -> dict[str, object]:
    prototypes: dict[str, object] = {
        "reconnaissance": {"support": 10, "values": reconnaissance}
    }
    if rare is not None:
        prototypes["rare"] = {"support": 5, "values": rare}
    return {
        "client_id": client_id,
        "embedding_size": 2,
        "prototypes": prototypes,
    }


class PrototypeTests(unittest.TestCase):
    def test_extracts_encoder_centroids_and_preserves_support_gate(self) -> None:
        try:
            _np, torch, *_rest = dependencies()
        except FederatedDependencyError as exc:
            self.skipTest(str(exc))

        class IdentityEncoder(torch.nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.encoder = torch.nn.Identity()

        rows = [
            {"features": [1.0, 2.0], "label": "reconnaissance"},
            {"features": [3.0, 4.0], "label": "reconnaissance"},
            {"features": [5.0, 6.0], "label": "reconnaissance"},
            {"features": [10.0, 10.0], "label": "rare"},
            {"features": [12.0, 12.0], "label": "rare"},
        ]
        result = extract_class_prototypes(
            model=IdentityEncoder(),
            rows=rows,
            class_names=["reconnaissance", "rare"],
            minimum_support=3,
            batch_size=2,
            torch=torch,
        )
        self.assertEqual(result["embedding_size"], 2)
        self.assertEqual(result["row_count"], 5)
        self.assertEqual(
            result["class_supports"], {"reconnaissance": 3, "rare": 2}
        )
        self.assertEqual(result["eligible_class_count"], 1)
        self.assertEqual(
            result["prototypes"]["reconnaissance"],
            {"support": 3, "values": [3.0, 4.0]},
        )
        self.assertNotIn("rare", result["prototypes"])

    def test_poisoning_changes_only_source_vector_and_preserves_support(self) -> None:
        clean = {
            "embedding_size": 2,
            "prototypes": {
                "reconnaissance": {"support": 8, "values": [0.0, 0.0]},
                "benign": {"support": 20, "values": [2.0, 2.0]},
            },
        }
        original = copy.deepcopy(clean)
        poisoned = poison_prototype_records(
            clean,
            source_class="reconnaissance",
            target_class="benign",
            scale=1.5,
        )
        self.assertEqual(clean, original)
        self.assertEqual(
            poisoned["prototypes"]["reconnaissance"],
            {"support": 8, "values": [3.0, 3.0]},
        )
        self.assertEqual(
            poisoned["prototypes"]["benign"],
            original["prototypes"]["benign"],
        )
        self.assertEqual(poisoned["poisoning"]["support_preserved"], 8)
        self.assertAlmostEqual(
            poisoned["poisoning"]["source_shift_l2"], math.sqrt(18.0)
        )

    def test_quorum_and_robust_aggregation_are_explicit(self) -> None:
        submissions = [
            _submission("client01", reconnaissance=[0.0, 0.0], rare=[1.0, 1.0]),
            _submission("client02", reconnaissance=[0.0, 0.0], rare=[1.0, 1.0]),
            _submission("client03", reconnaissance=[0.0, 0.0]),
            _submission("client04", reconnaissance=[9.0, 9.0]),
            _submission("client05", reconnaissance=[9.0, 9.0]),
        ]
        original = copy.deepcopy(submissions)
        baseline = aggregate_class_prototypes(
            submissions,
            class_names=["reconnaissance", "rare"],
            minimum_local_support=5,
            class_quorum=3,
            strategy="support_weighted_mean",
        )
        robust = aggregate_class_prototypes(
            submissions,
            class_names=["reconnaissance", "rare"],
            minimum_local_support=5,
            class_quorum=3,
            strategy="coordinate_median",
        )
        self.assertEqual(submissions, original)
        self.assertEqual(
            baseline["classes"]["reconnaissance"]["values"], [3.6, 3.6]
        )
        self.assertEqual(
            robust["classes"]["reconnaissance"]["values"], [0.0, 0.0]
        )
        for result in (baseline, robust):
            rare = result["classes"]["rare"]
            self.assertEqual(rare["status"], "insufficient_quorum")
            self.assertEqual(rare["supporting_client_count"], 2)
            self.assertNotIn("values", rare)

    def test_distance_indicators_and_invalid_shapes_are_explicit(self) -> None:
        submissions = [
            _submission("client01", reconnaissance=[0.0, 0.0]),
            _submission("client02", reconnaissance=[0.0, 0.0]),
            _submission("client03", reconnaissance=[9.0, 9.0]),
        ]
        indicators = prototype_distance_indicators(
            submissions, class_names=["reconnaissance"]
        )
        by_client = {item["client_id"]: item for item in indicators}
        self.assertEqual(
            by_client["client01"]["distance_to_coordinate_median"], 0.0
        )
        self.assertEqual(
            by_client["client02"]["distance_to_coordinate_median"], 0.0
        )
        self.assertAlmostEqual(
            by_client["client03"]["distance_to_coordinate_median"],
            math.sqrt(162.0),
        )
        self.assertGreater(
            by_client["client03"]["relative_distance"], 1.0
        )
        malformed = copy.deepcopy(submissions)
        malformed[0]["prototypes"]["reconnaissance"]["values"] = [0.0]
        with self.assertRaisesRegex(
            PrototypeConfigurationError, "match the embedding size"
        ):
            prototype_distance_indicators(
                malformed, class_names=["reconnaissance"]
            )
