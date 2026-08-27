from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from fl_forensics.canonical import sha256_bytes
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.runtime_overhead import (
    RUNTIME_STAGE_IDS,
    SPAN_STAGE_IDS,
    RuntimeOverheadError,
    benchmark_tpm_esk_sign,
    create_runtime_overhead_receipt,
    load_runtime_overhead_contract,
    verify_runtime_overhead_receipt,
)


class RuntimeOverheadTests(unittest.TestCase):
    def _fixture(self, root: Path, *, repetitions: int = 2) -> tuple[Path, list[dict]]:
        source = root / "source.txt"
        source.write_text("bound source\n", encoding="utf-8")
        expected = {stage_id: {"status": "ok"} for stage_id in RUNTIME_STAGE_IDS}
        config = root / "configs" / "runtime.yaml"
        config.parent.mkdir(parents=True)
        config.write_text(
            yaml.safe_dump(
                {
                    "schema_version": "1.0",
                    "benchmark_id": "test-runtime-overhead",
                    "profile": "containerized-secure-round-runtime-v1",
                    "project_root": "..",
                    "project_namespace": "test_runtime",
                    "repetitions": repetitions,
                    "workers": 2,
                    "compose_m4": "compose.m4.yaml",
                    "compose_m5": "compose.m5.yaml",
                    "partition_workspace": "partition",
                    "work_root": "work",
                    "trust_config": "trust.yaml",
                    "clients_config": "clients.yaml",
                    "federation_config": "federation.yaml",
                    "secure_round_config": "secure-round.yaml",
                    "tpm_sign_probe": {"warmup_runs": 1, "repetitions": 2},
                    "source_markers": ["source.txt"],
                    "expected": expected,
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        trials = []
        for trial_index in range(1, repetitions + 1):
            trial_root = root / "work" / f"trial-{trial_index:03d}"
            trust = trial_root / "m4-trust"
            nodes = trial_root / "m4-nodes"
            round_workspace = trial_root / "m5-secure-round"
            markers = (
                trust / "manifest.json",
                trust / "baseline" / "baseline.json",
                trust / "registry" / "index.json",
                trust / "challenges" / "challenge.json",
                trust / "results" / "attestation.json",
                round_workspace / "public" / "round-context.json",
                round_workspace / "submissions" / "client01" / "bundle.json",
                round_workspace / "checkpoint" / "manifest.json",
                round_workspace / "checkpoint" / "global-model.json",
            )
            for marker in markers:
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text(f"{trial_index}:{marker.name}\n", encoding="utf-8")
            for client_index in range(1, 16):
                node = nodes / f"client{client_index:02d}"
                for relative in (
                    "provisioning_summary.json",
                    "enrollment_record.json",
                    "quote_evidence.json",
                    "tpm-objects/esk.public.pem",
                ):
                    marker = node / relative
                    marker.parent.mkdir(parents=True, exist_ok=True)
                    marker.write_text(
                        f"{trial_index}:{client_index}:{marker.name}\n",
                        encoding="utf-8",
                    )
            stages = [
                {
                    "stage_id": stage_id,
                    "wall_time_ns": trial_index * 1_000 + index,
                    "cpu_time_ns": trial_index * 100 + index,
                    "outcome": (
                        {
                            "status": "ok",
                            "median_sign_wall_time_ms": 1.25,
                            "measured_sample_count": 2,
                        }
                        if stage_id == "m4-swtpm-esk-sign-probe"
                        else {"status": "ok"}
                    ),
                }
                for index, stage_id in enumerate(RUNTIME_STAGE_IDS)
            ]
            spans = {
                name: sum(
                    stage["wall_time_ns"]
                    for stage in stages
                    if stage["stage_id"] in stage_ids
                )
                for name, stage_ids in SPAN_STAGE_IDS.items()
            }
            spans["measured-total"] = sum(stage["wall_time_ns"] for stage in stages)
            trials.append(
                {
                    "trial_index": trial_index,
                    "compose_project": f"test_runtime_{trial_index:03d}",
                    "workspaces": {
                        "trust_workspace": trust.relative_to(root).as_posix(),
                        "node_root": nodes.relative_to(root).as_posix(),
                        "round_workspace": round_workspace.relative_to(root).as_posix(),
                        "coordinator_workspace": (
                            trial_root / "m5-coordinator"
                        ).relative_to(root).as_posix(),
                    },
                    "stage_order_sha256": sha256_bytes(
                        "\n".join(RUNTIME_STAGE_IDS).encode()
                    ),
                    "stages": stages,
                    "spans": spans,
                }
            )
        return config, trials

    def test_receipt_and_runtime_evidence_are_recomputed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, trials = self._fixture(root)
            output = root / "receipt"
            created = create_runtime_overhead_receipt(
                output=output,
                config_path=config,
                trials=trials,
                environment={"test": True},
                started_at="2026-08-26T00:00:00Z",
                completed_at="2026-08-26T00:01:00Z",
            )
            self.assertEqual(created["status"], "benchmarked")
            self.assertEqual(created["trial_count"], 2)
            verified = verify_runtime_overhead_receipt(
                workspace=output,
                config_path=config,
            )
            self.assertEqual(verified["status"], "verified")
            self.assertTrue(verified["runtime_evidence_recomputed"])
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["trial_count"], 2)
            self.assertFalse(summary["methodology"]["network_update_api_present"])

    def test_runtime_evidence_tampering_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, trials = self._fixture(root, repetitions=1)
            output = root / "receipt"
            create_runtime_overhead_receipt(
                output=output,
                config_path=config,
                trials=trials,
                environment={},
                started_at="start",
                completed_at="end",
            )
            marker = root / "work/trial-001/m5-secure-round/checkpoint/manifest.json"
            marker.write_text("tampered\n", encoding="utf-8")
            result = verify_runtime_overhead_receipt(
                workspace=output,
                config_path=config,
            )
            self.assertEqual(result["status"], "failed")
            self.assertIn("binding", " ".join(result["errors"]))

    def test_contract_requires_all_runtime_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _trials = self._fixture(root)
            value = yaml.safe_load(config.read_text())
            value["expected"].pop(RUNTIME_STAGE_IDS[-1])
            config.write_text(yaml.safe_dump(value), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeOverheadError, "exact"):
                load_runtime_overhead_contract(config)

    def test_trial_namespace_must_match_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, trials = self._fixture(root, repetitions=1)
            trials[0]["compose_project"] = "unexpected_project"
            with self.assertRaisesRegex(RuntimeOverheadError, "Compose"):
                create_runtime_overhead_receipt(
                    output=root / "receipt",
                    config_path=config,
                    trials=trials,
                    environment={},
                    started_at="start",
                    completed_at="end",
                )

    def test_tpm_probe_verifies_every_signature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            node = Path(temporary)
            signer = SoftwareECDSASigner.generate()
            public_path = node / "tpm-objects" / "esk.public.pem"
            public_path.parent.mkdir(parents=True)
            public_path.write_bytes(signer.public_pem())
            with patch(
                "fl_forensics.runtime_overhead.TPM2ToolsSigner",
                return_value=signer,
            ):
                result = benchmark_tpm_esk_sign(
                    node_workspace=node,
                    tcti="mock",
                    warmup_runs=1,
                    repetitions=3,
                )
            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["measured_sample_count"], 3)
            self.assertEqual(len(result["samples"]), 4)
            self.assertTrue(all(item["verified"] for item in result["samples"]))


if __name__ == "__main__":
    unittest.main()
