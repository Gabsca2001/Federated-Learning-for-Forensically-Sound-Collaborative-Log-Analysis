from __future__ import annotations

import unittest
from pathlib import Path

from fl_forensics.config import load_yaml

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    def test_m2_is_bound_to_uwf_zeekdata24(self) -> None:
        config, _ = load_yaml(ROOT / "configs" / "base.yaml")
        mapping, _ = load_yaml(ROOT / "configs" / "attack_mapping.yaml")
        self.assertEqual(config["experiment"]["dataset"], "UWF-ZeekData24")
        self.assertEqual(mapping["source_dataset"], "UWF-ZeekData24")

    def test_finalized_topology_contains_fifteen_unique_pairs(self) -> None:
        config, _ = load_yaml(ROOT / "configs" / "clients.yaml")
        clients = config["clients"]
        self.assertEqual(len(clients), 15)
        self.assertEqual(len({item["client_id"] for item in clients}), 15)
        self.assertEqual(len({item["node_id"] for item in clients}), 15)
        self.assertEqual(len({item["tpm"] for item in clients}), 15)

    def test_m3_clean_baseline_requires_full_fifteen_client_fedavg(self) -> None:
        config, _ = load_yaml(ROOT / "configs" / "federation.yaml")
        self.assertEqual(config["dataset"], "UWF-ZeekData24")
        self.assertEqual(config["partitioning"]["client_count"], 15)
        self.assertEqual(config["training"]["aggregator"], "fedavg")
        self.assertEqual(
            config["training"]["class_weighting"],
            "global-sqrt-balanced-training-only",
        )
        self.assertEqual(config["training"]["participation_fraction"], 1.0)
        self.assertEqual(config["training"]["minimum_fit_clients"], 15)
        self.assertEqual(
            config["training"]["checkpoint_selection"],
            {
                "split": "validation",
                "metric": "macro_f1_all_model_classes",
                "mode": "maximize",
                "tie_breaker": "earliest_round",
                "test_policy": "selected-checkpoint-only",
            },
        )

    def test_m4_uses_sha256_quote_policy_and_separate_measurement_roles(self) -> None:
        config, _ = load_yaml(ROOT / "configs" / "trust.yaml")
        self.assertEqual(config["attestation"]["pcr_bank"], "sha256")
        self.assertEqual(config["attestation"]["pcr_selection"], [0, 2, 4, 7, 10])
        self.assertEqual(config["mtls"]["minimum_version"], "TLSv1.3")
        measured_components = {item["component_id"] for item in config["measurements"]}
        self.assertIn("acquisition-agent", measured_components)
        self.assertIn("admission-policy", measured_components)
        self.assertIn("trust-policy", measured_components)
        self.assertIn("secure-campaign-coordinator", measured_components)
        self.assertIn("command-interface", measured_components)
        self.assertIn("secure-multiround-orchestrator", measured_components)

    def test_m5_policy_gates_all_fifteen_signed_updates(self) -> None:
        config, _ = load_yaml(ROOT / "configs" / "secure-round.yaml")
        policy = config["secure_round"]
        self.assertEqual(policy["required_clients"], 15)
        self.assertEqual(policy["aggregation"], "FedAvg")
        self.assertEqual(policy["campaign_rounds"], 30)
        self.assertEqual(policy["attestation_refresh_interval_rounds"], 5)
        self.assertEqual(
            policy["checkpoint_selection"],
            {
                "split": "validation",
                "metric": "macro_f1_all_model_classes",
                "mode": "maximize",
                "tie_breaker": "earliest_round",
                "test_policy": "selected-checkpoint-only",
            },
        )
        self.assertTrue(policy["require_fresh_attestation"])
        self.assertTrue(policy["require_tpm_esk_signature"])
        self.assertTrue(policy["require_exact_tensor_schema"])

    def test_m6_compares_all_defenses_on_the_same_frozen_updates(self) -> None:
        config, _ = load_yaml(ROOT / "configs" / "byzantine.yaml")
        self.assertEqual(config["experiment"]["client_count"], 15)
        self.assertEqual(config["experiment"]["byzantine_counts"], [1, 2, 3])
        self.assertEqual(
            config["defenses"]["aggregators"],
            [
                "fedavg",
                "coordinate_median",
                "trimmed_mean",
                "multikrum",
                "bulyan",
            ],
        )
        self.assertEqual(len(config["attacks"]["enabled"]), 7)
        self.assertTrue(
            config["acceptance"]["same_frozen_updates_for_every_aggregator"]
        )
        self.assertTrue(config["acceptance"]["invalid_byzantine_bounds_halt"])

    def test_m6_malicious_model_replacement_has_an_explicit_objective(self) -> None:
        config, _ = load_yaml(
            ROOT / "configs" / "byzantine-malicious-model-replacement.yaml"
        )
        self.assertIn("update_amplification", config["attacks"]["enabled"])
        self.assertEqual(
            config["attacks"]["model_replacement"]["objective"],
            {
                "type": "targeted_label_flip",
                "source": "reconnaissance",
                "target": "benign",
            },
        )


if __name__ == "__main__":
    unittest.main()
