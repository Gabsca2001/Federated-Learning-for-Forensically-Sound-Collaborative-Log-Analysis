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
        self.assertEqual(config["training"]["participation_fraction"], 1.0)
        self.assertEqual(config["training"]["minimum_fit_clients"], 15)


if __name__ == "__main__":
    unittest.main()
