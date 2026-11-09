from __future__ import annotations

import copy
import unittest

from fl_forensics.distributed_backdoor import (
    DistributedBackdoorPlan,
    apply_evaluation_trigger,
    poison_local_rows,
)


class DistributedBackdoorTests(unittest.TestCase):
    def setUp(self):
        self.plan = DistributedBackdoorPlan(
            target_label="benign",
            client_components={"client01": [0], "client02": [1], "client03": [2]},
            trigger_values_decimal={"0": "12", "1": "12", "2": "12"},
            poisoned_fraction_decimal="0.10",
            attack_rounds=[1, 2],
            seed=341593,
        )
        self.rows = [
            {
                "window_id": f"row-{index:03d}",
                "features": [float(index), float(index + 1), float(index + 2), 0.5],
                "label": "reconnaissance",
            }
            for index in range(23)
        ]

    def test_each_client_only_receives_its_assigned_subtrigger(self):
        before = copy.deepcopy(self.rows)
        for client, indices in self.plan.client_components.items():
            poisoned, record = poison_local_rows(
                rows=self.rows, plan=self.plan, client_id=client, round_number=1
            )
            self.assertEqual(len(record["poisoned_window_ids"]), 3)
            chosen = set(record["poisoned_window_ids"])
            for old, new in zip(self.rows, poisoned, strict=True):
                if old["window_id"] in chosen:
                    self.assertEqual(new["label"], "benign")
                    for index in range(4):
                        self.assertEqual(
                            new["features"][index],
                            12.0 if index in indices else old["features"][index],
                        )
                else:
                    self.assertEqual(new, old)
        self.assertEqual(self.rows, before)

    def test_complete_and_distributed_triggers_have_identical_poisoned_row_budget(self):
        local, local_record = poison_local_rows(
            rows=self.rows, plan=self.plan, client_id="client01", round_number=1
        )
        full, full_record = poison_local_rows(
            rows=self.rows, plan=self.plan, client_id="client01", round_number=1, distributed=False
        )
        self.assertEqual(local_record["poisoned_window_ids"], full_record["poisoned_window_ids"])
        self.assertEqual(local_record["label_flip_count"], full_record["label_flip_count"])
        self.assertEqual(
            local_record["modified_feature_values"] * 3, full_record["modified_feature_values"]
        )
        self.assertNotEqual(local, full)

    def test_benign_clients_and_post_attack_rounds_remain_unmodified(self):
        for client, number in (("client04", 1), ("client01", 3)):
            result, record = poison_local_rows(
                rows=self.rows, plan=self.plan, client_id=client, round_number=number
            )
            self.assertEqual(result, self.rows)
            self.assertFalse(record["poisoned_window_ids"])

    def test_evaluation_trigger_keeps_labels_and_original_test_rows(self):
        before = copy.deepcopy(self.rows)
        full = apply_evaluation_trigger(rows=self.rows, plan=self.plan)
        part = apply_evaluation_trigger(
            rows=self.rows, plan=self.plan, component_client_id="client02"
        )
        for old, all_values, component in zip(self.rows, full, part, strict=True):
            self.assertEqual(all_values["label"], old["label"])
            self.assertEqual(component["label"], old["label"])
            self.assertEqual(all_values["features"][:3], [12.0] * 3)
            self.assertEqual(
                component["features"],
                [old["features"][0], 12.0, old["features"][2], old["features"][3]],
            )
        self.assertEqual(self.rows, before)

    def test_duplicate_overlap_bad_value_and_bad_budget_fail_validation(self):
        for changes in (
            {"client_components": {"a": [0], "b": [0]}},
            {"poisoned_fraction_decimal": "0"},
            {"trigger_values_decimal": {"0": "NaN", "1": "12", "2": "12"}},
            {"attack_rounds": [2, 1]},
            {"client_components": {"only-one": [0]}},
        ):
            with self.assertRaises(ValueError):
                DistributedBackdoorPlan.model_validate(
                    {**self.plan.model_dump(mode="json"), **changes}
                )

    def test_schema_mismatch_and_duplicate_row_identity_are_rejected(self):
        wrong = copy.deepcopy(self.rows)
        wrong[0]["features"] = [0.0]
        with self.assertRaisesRegex(ValueError, "schema"):
            poison_local_rows(rows=wrong, plan=self.plan, client_id="client01", round_number=1)
        wrong = copy.deepcopy(self.rows)
        wrong[0]["window_id"] = wrong[1]["window_id"]
        with self.assertRaisesRegex(ValueError, "identities"):
            poison_local_rows(rows=wrong, plan=self.plan, client_id="client01", round_number=1)

    def test_repeated_calls_reuse_the_same_selection_and_do_not_mutate_source(self):
        first = poison_local_rows(
            rows=self.rows, plan=self.plan, client_id="client03", round_number=2
        )
        second = poison_local_rows(
            rows=self.rows, plan=self.plan, client_id="client03", round_number=2
        )
        self.assertEqual(first, second)
