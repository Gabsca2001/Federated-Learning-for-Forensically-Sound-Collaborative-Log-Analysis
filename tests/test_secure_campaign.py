from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.models import SignatureBlock
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_campaign import (
    _load_client_local_tests,
    finalize_secure_campaign,
    verify_secure_campaign,
)
from fl_forensics.secure_round import SecureRoundError, initialize_secure_round
from fl_forensics.secure_round_models import (
    CheckpointInput,
    RoundClientContract,
    SecureCheckpoint,
    SecureCheckpointCore,
    SecureRoundContext,
    SecureRoundContextCore,
)
from fl_forensics.storage import write_json_once, write_once

CLIENTS = ["client01", "client02"]


class SecureCampaignTests(unittest.TestCase):
    def _signed_context(
        self,
        *,
        signer: SoftwareECDSASigner,
        campaign_id: str,
        round_number: int,
        previous_checkpoint_sha256: str,
        base_model_sha256: str,
        partition_sha256: str,
    ) -> SecureRoundContext:
        now = datetime.now(UTC)
        contracts = [
            RoundClientContract(
                client_id=client_id,
                node_id=f"node{index:02d}",
                enrollment_id=f"enrollment-{index}",
                attestation_result_id=f"attestation-{index}",
                attestation_result_sha256=f"{index:064x}",
                snapshot_sha256=f"{index + 10:064x}",
                snapshot_manifest_sha256=f"{index + 20:064x}",
                train_row_count=3,
            )
            for index, client_id in enumerate(CLIENTS, start=1)
        ]
        core = SecureRoundContextCore(
            campaign_id=campaign_id,
            round_number=round_number,
            previous_checkpoint_sha256=previous_checkpoint_sha256,
            base_model_sha256=base_model_sha256,
            training_contract_sha256="1" * 64,
            partition_manifest_sha256=partition_sha256,
            federation_config_sha256="2" * 64,
            seed=341593,
            local_epochs=2,
            batch_size=4,
            learning_rate_decimal="0.001",
            required_client_count=len(CLIENTS),
            clients=contracts,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=10)).isoformat(),
        )
        digest = digest_object(core.model_dump(mode="json"))
        return SecureRoundContext(
            context_id=f"round-context-{digest[:24]}",
            core=core,
            core_digest=digest,
            signature={
                "key_id": signer.key_id,
                "value_b64": signer.sign_digest(digest),
                "trust_level": "software-development",
            },
        )

    def _signed_checkpoint(
        self,
        *,
        signer: SoftwareECDSASigner,
        context: SecureRoundContext,
        global_model_sha256: str,
        clients: list[str] | None = None,
    ) -> SecureCheckpoint:
        clients = clients or CLIENTS
        inputs = [
            CheckpointInput(
                client_id=client_id,
                decision_id=f"decision-{index}",
                decision_sha256=f"{index + 30:064x}",
                bundle_id=f"bundle-{index}",
                bundle_sha256=f"{index + 40:064x}",
                update_sha256=f"{index + 50:064x}",
                num_examples=3,
            )
            for index, client_id in enumerate(clients, start=1)
        ]
        core = SecureCheckpointCore(
            campaign_id=context.core.campaign_id,
            context_id=context.context_id,
            context_digest=context.core_digest,
            round_number=context.core.round_number,
            previous_checkpoint_sha256=context.core.previous_checkpoint_sha256,
            base_model_sha256=context.core.base_model_sha256,
            required_client_count=len(clients),
            accepted_count=len(clients),
            quarantined_count=0,
            total_examples=3 * len(clients),
            accepted_inputs=inputs,
            quarantined_decision_sha256=[],
            global_model_sha256=global_model_sha256,
            created_at=datetime.now(UTC).isoformat(),
        )
        digest = digest_object(core.model_dump(mode="json"))
        return SecureCheckpoint(
            checkpoint_id=f"secure-checkpoint-{digest[:24]}",
            core=core,
            core_digest=digest,
            signature={
                "key_id": signer.key_id,
                "value_b64": signer.sign_digest(digest),
                "trust_level": "software-development",
            },
        )

    def _workspace(self, root: Path, *, isolated_splits: bool = True) -> tuple[Path, Path, Path]:
        campaign = root / "campaign"
        partition_path = root / "partition" / "manifest.json"
        evaluation_path = root / "partition" / "server" / "evaluation.json"
        signer = SoftwareECDSASigner.generate()
        write_once(
            campaign / "authority" / "round-coordinator.private.pem",
            signer.private_pem(),
        )
        write_once(
            campaign / "authority" / "round-coordinator.public.pem",
            signer.public_pem(),
        )
        server = {
            "class_names": ["benign", "attack"],
            "rows": {
                "validation": [{"label": "validation", "window_id": "validation-1"}],
                "test": [
                    {"label": "test", "window_id": f"test-{client_id}"} for client_id in CLIENTS
                ],
                "temporal_holdout": [{"label": "temporal_holdout", "window_id": "holdout-1"}],
            },
        }
        write_once(evaluation_path, derived_json_bytes(server))
        clients = []
        for index, client_id in enumerate(CLIENTS, start=1):
            relative = Path("evaluation") / "clients" / client_id / "test.json"
            local_test = {
                "client_id": client_id,
                "class_names": server["class_names"],
                "rows": {
                    "test": [
                        {
                            "label": f"test-{client_id}",
                            "window_id": f"test-{client_id}",
                        }
                    ]
                },
            }
            local_bytes = derived_json_bytes(local_test)
            write_once(partition_path.parent / relative, local_bytes)
            clients.append(
                {
                    "client_id": client_id,
                    "partition_id": index - 1,
                    "local_test_path": relative.as_posix(),
                    "local_test_sha256": sha256_bytes(local_bytes),
                    "local_test_row_count": 1,
                }
            )
        server_splits = {}
        if isolated_splits:
            for split in ("validation", "test", "temporal_holdout"):
                relative = Path("server") / "splits" / f"{split}.json"
                snapshot = {
                    "class_names": server["class_names"],
                    "split": split,
                    "rows": {split: server["rows"][split]},
                }
                split_bytes = derived_json_bytes(snapshot)
                write_once(partition_path.parent / relative, split_bytes)
                server_splits[split] = {
                    "path": relative.as_posix(),
                    "sha256": sha256_bytes(split_bytes),
                    "row_count": len(server["rows"][split]),
                }
        partition = {
            "client_count": len(CLIENTS),
            "clients": clients,
            "class_names": server["class_names"],
            "local_test_strategy": "train-profile-proportional",
            "server_evaluation_sha256": sha256_file(evaluation_path),
        }
        if isolated_splits:
            partition["server_evaluation_splits"] = server_splits
        write_once(partition_path, derived_json_bytes(partition))
        partition_sha256 = sha256_file(partition_path)
        previous_checkpoint_sha256 = "0" * 64
        previous_model_sha256 = "a" * 64
        for round_number, score in ((1, 0.9), (2, 0.8)):
            round_workspace = campaign / "rounds" / f"round-{round_number:03d}"
            model = {
                "architecture": {
                    "input_features": 1,
                    "encoder_hidden_layers": [2],
                    "embedding_size": 1,
                    "classification_head_outputs": 2,
                    "dropout": 0.0,
                },
                "class_names": server["class_names"],
                "parameters": [],
                "score": score,
            }
            model_bytes = derived_json_bytes(model)
            model_sha256 = sha256_bytes(model_bytes)
            context = self._signed_context(
                signer=signer,
                campaign_id="campaign-test",
                round_number=round_number,
                previous_checkpoint_sha256=previous_checkpoint_sha256,
                base_model_sha256=previous_model_sha256,
                partition_sha256=partition_sha256,
            )
            checkpoint = self._signed_checkpoint(
                signer=signer,
                context=context,
                global_model_sha256=model_sha256,
            )
            write_once(
                round_workspace / "public" / "round-coordinator.public.pem",
                signer.public_pem(),
            )
            write_json_once(
                round_workspace / "public" / "round-context.json",
                context.model_dump(mode="json"),
            )
            write_json_once(
                round_workspace / "checkpoint" / "manifest.json",
                checkpoint.model_dump(mode="json"),
            )
            write_once(round_workspace / "checkpoint" / "global-model.json", model_bytes)
            previous_checkpoint_sha256 = sha256_file(
                round_workspace / "checkpoint" / "manifest.json"
            )
            previous_model_sha256 = model_sha256
        return campaign, partition_path, evaluation_path

    @staticmethod
    def _evaluation(*, model_export, rows, **_kwargs):
        score = float(model_export["score"])
        return {
            "row_count": len(rows),
            "macro_f1_all_model_classes": score,
        }

    def test_campaign_selects_validation_before_test_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign, partition, evaluation = self._workspace(root)
            verified_round = {
                "status": "verified",
                "accepted_count": len(CLIENTS),
                "matches_reference_checkpoint": True,
                "errors": [],
            }
            with (
                patch("fl_forensics.secure_campaign.EXPECTED_CLIENTS", CLIENTS),
                patch(
                    "fl_forensics.secure_campaign.verify_secure_round",
                    return_value=verified_round,
                ),
                patch("fl_forensics.secure_campaign.dependencies", return_value=()),
                patch(
                    "fl_forensics.secure_campaign._evaluate_export",
                    side_effect=self._evaluation,
                ),
            ):
                result = finalize_secure_campaign(
                    workspace=campaign,
                    trust_workspace=root / "trust",
                    partition_manifest_path=partition,
                    server_evaluation_path=evaluation,
                    expected_rounds=2,
                )
                verification = verify_secure_campaign(
                    workspace=campaign,
                    trust_workspace=root / "trust",
                    partition_manifest_path=partition,
                    server_evaluation_path=evaluation,
                )
            self.assertEqual(result["selected_round"], 1)
            self.assertEqual(result["accepted_contribution_count"], 4)
            self.assertEqual(verification["status"], "verified")
            final = (campaign / "evaluation" / "selected-checkpoint-evaluation.json").read_text(
                encoding="utf-8"
            )
            self.assertIn('"selected_round":1', final)
            self.assertIn('"selected_global_client_test"', final)
            self.assertIn('"client_count":2', final)
            self.assertIn('"test_access_mode"', final)

    def test_legacy_combined_server_evaluation_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign, partition, evaluation = self._workspace(root, isolated_splits=False)
            with (
                patch("fl_forensics.secure_campaign.EXPECTED_CLIENTS", CLIENTS),
                patch(
                    "fl_forensics.secure_campaign.verify_secure_round",
                    return_value={"status": "verified", "errors": []},
                ),
                patch("fl_forensics.secure_campaign.dependencies", return_value=()),
                patch(
                    "fl_forensics.secure_campaign._evaluate_export",
                    side_effect=self._evaluation,
                ),
            ):
                result = finalize_secure_campaign(
                    workspace=campaign,
                    trust_workspace=root / "trust",
                    partition_manifest_path=partition,
                    server_evaluation_path=evaluation,
                    expected_rounds=2,
                )

            self.assertEqual(result["selected_round"], 1)
            final = (campaign / "evaluation" / "selected-checkpoint-evaluation.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn('"test_access_mode"', final)

    def test_local_test_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            partition_path = root / "manifest.json"
            partition = {
                "local_test_strategy": "train-profile-proportional",
                "class_names": ["benign", "attack"],
                "clients": [
                    {
                        "client_id": "client01",
                        "local_test_path": ("evaluation/clients/client01/../client02/test.json"),
                        "local_test_sha256": "0" * 64,
                        "local_test_row_count": 1,
                    }
                ],
            }

            with self.assertRaisesRegex(SecureRoundError, "outside evaluation boundary"):
                _load_client_local_tests(
                    partition_manifest_path=partition_path,
                    partition=partition,
                )

    def test_broken_checkpoint_chain_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign, partition, evaluation = self._workspace(root)
            context_path = campaign / "rounds" / "round-002" / "public" / "round-context.json"
            context = SecureRoundContext.model_validate_json(context_path.read_text())
            signer = SoftwareECDSASigner.load(
                campaign / "authority" / "round-coordinator.private.pem"
            )
            changed_core = context.core.model_copy(update={"previous_checkpoint_sha256": "f" * 64})
            digest = digest_object(changed_core.model_dump(mode="json"))
            changed = context.model_copy(
                update={
                    "context_id": f"round-context-{digest[:24]}",
                    "core": changed_core,
                    "core_digest": digest,
                    "signature": SignatureBlock(
                        key_id=signer.key_id,
                        value_b64=signer.sign_digest(digest),
                        trust_level="software-development",
                    ),
                }
            )
            context_path.chmod(0o600)
            context_path.write_bytes(derived_json_bytes(changed.model_dump(mode="json")))
            with (
                patch("fl_forensics.secure_campaign.EXPECTED_CLIENTS", CLIENTS),
                patch(
                    "fl_forensics.secure_campaign.verify_secure_round",
                    return_value={"status": "verified", "errors": []},
                ),
                patch("fl_forensics.secure_campaign.dependencies", return_value=()),
                patch(
                    "fl_forensics.secure_campaign._evaluate_export",
                    side_effect=self._evaluation,
                ),
                self.assertRaisesRegex(ValueError, "breaks the campaign chain"),
            ):
                finalize_secure_campaign(
                    workspace=campaign,
                    trust_workspace=root / "trust",
                    partition_manifest_path=partition,
                    server_evaluation_path=evaluation,
                    expected_rounds=2,
                )

    def test_later_round_uses_the_signed_previous_global_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign = root / "campaign"
            trust = root / "trust"
            partition_path = root / "partition.json"
            config_path = root / "federation.yaml"
            secure_config_path = root / "secure-round.yaml"
            authority = SoftwareECDSASigner.generate()
            write_once(
                trust / "authority" / "enrollment-authority.public.pem",
                authority.public_pem(),
            )
            config = {
                "model": {
                    "hidden_layers": [2],
                    "embedding_size": 1,
                    "dropout": 0.0,
                    "activation": "relu",
                },
                "training": {
                    "aggregator": "fedavg",
                    "optimizer": "adam",
                    "class_weighting": "test-weighting",
                    "minimum_fit_clients": 1,
                    "participation_fraction": 1.0,
                    "seed": 7,
                    "local_epochs": 2,
                    "batch_size": 4,
                    "learning_rate": 0.001,
                },
            }
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
            secure_config_path.write_text(
                yaml.safe_dump(
                    {
                        "secure_round": {
                            "required_clients": 1,
                            "aggregation": "FedAvg",
                            "context_lifetime_seconds": 600,
                            "minimum_attestation_remaining_seconds": 120,
                        }
                    }
                ),
                encoding="utf-8",
            )
            architecture = {
                "input_features": 1,
                "encoder_hidden_layers": [2],
                "embedding_size": 1,
                "classification_head_outputs": 2,
                "dropout": 0.0,
            }
            initial_model = {
                "architecture": architecture,
                "class_names": ["benign", "attack"],
                "parameters": [
                    {
                        "name": "weight",
                        "shape": [1],
                        "dtype": "float32",
                        "values": [0.0],
                    }
                ],
            }
            partition = {
                "client_count": 1,
                "feature_names": ["feature"],
                "class_names": ["benign", "attack"],
                "class_weighting": "test-weighting",
                "global_class_weights": {"benign": 1.0, "attack": 1.0},
                "clients": [
                    {
                        "client_id": "client01",
                        "dataset_sha256": "3" * 64,
                        "manifest_sha256": "4" * 64,
                        "train_row_count": 3,
                    }
                ],
                "partition_config_sha256": sha256_file(config_path),
            }
            write_once(partition_path, derived_json_bytes(partition))
            now = datetime.now(UTC)
            enrollment = SimpleNamespace(
                core=SimpleNamespace(
                    enrollment_id="enrollment-1",
                    node_id="node01",
                    status="active",
                    valid_from=(now - timedelta(minutes=1)).isoformat(),
                    valid_until=(now + timedelta(days=1)).isoformat(),
                )
            )
            result = SimpleNamespace(
                result_id="attestation-1",
                core=SimpleNamespace(expires_at=(now + timedelta(minutes=15)).isoformat()),
            )
            result_path = trust / "results" / "attestation-1.json"
            write_once(result_path, b"{}")
            patches = (
                patch("fl_forensics.secure_round.EXPECTED_CLIENTS", ["client01"]),
                patch("fl_forensics.secure_round._enrollment", return_value=enrollment),
                patch("fl_forensics.secure_round._revoked", return_value=False),
                patch(
                    "fl_forensics.secure_round._current_attestation",
                    return_value=(result, result_path),
                ),
                patch(
                    "fl_forensics.secure_round._new_model",
                    return_value=(object(), architecture),
                ),
                patch(
                    "fl_forensics.secure_round.export_state",
                    return_value=initial_model,
                ),
            )
            for active_patch in patches:
                active_patch.start()
                self.addCleanup(active_patch.stop)
            round1 = campaign / "rounds" / "round-001"
            first = initialize_secure_round(
                workspace=round1,
                coordinator_workspace=campaign,
                trust_workspace=trust,
                partition_manifest_path=partition_path,
                config_path=config_path,
                secure_config_path=secure_config_path,
                now=now,
            )
            context1 = SecureRoundContext.model_validate_json(
                (round1 / "public" / "round-context.json").read_text()
            )
            learned_model = {
                **initial_model,
                "parameters": [
                    {
                        "name": "weight",
                        "shape": [1],
                        "dtype": "float32",
                        "values": [0.75],
                    }
                ],
            }
            learned_bytes = derived_json_bytes(learned_model)
            learned_sha256 = sha256_bytes(learned_bytes)
            signer = SoftwareECDSASigner.load(
                campaign / "authority" / "round-coordinator.private.pem"
            )
            checkpoint1 = self._signed_checkpoint(
                signer=signer,
                context=context1,
                global_model_sha256=learned_sha256,
                clients=["client01"],
            )
            write_once(round1 / "checkpoint" / "global-model.json", learned_bytes)
            write_json_once(
                round1 / "checkpoint" / "manifest.json",
                checkpoint1.model_dump(mode="json"),
            )
            round2 = campaign / "rounds" / "round-002"
            second = initialize_secure_round(
                workspace=round2,
                coordinator_workspace=campaign,
                campaign_id=first["campaign_id"],
                round_number=2,
                previous_round_workspace=round1,
                trust_workspace=trust,
                partition_manifest_path=partition_path,
                config_path=config_path,
                secure_config_path=secure_config_path,
                now=now,
            )
            self.assertEqual((round2 / "public" / "base-model.json").read_bytes(), learned_bytes)
            self.assertEqual(second["base_model_sha256"], learned_sha256)
            self.assertEqual(
                second["previous_checkpoint_sha256"],
                sha256_file(round1 / "checkpoint" / "manifest.json"),
            )


if __name__ == "__main__":
    unittest.main()
