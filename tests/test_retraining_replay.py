from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fl_forensics.canonical import sha256_bytes, sha256_file
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.federated_model import (
    architecture_record,
    build_model,
    dependencies,
    export_state,
    seed_everything,
)
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.retraining_replay import (
    RetrainingPlan,
    RetrainingReplayError,
    create_retraining_replay,
    verify_retraining_replay,
)
from fl_forensics.storage import write_once


class RetrainingReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        np, torch, *_ = dependencies()
        seed_everything(123, torch=torch, np=np)
        architecture = architecture_record(
            input_features=2, class_count=2, hidden_layers=[4, 3], embedding_size=2, dropout=0.0
        )
        model = build_model(
            input_features=2,
            class_count=2,
            hidden_layers=[4, 3],
            embedding_size=2,
            dropout=0.0,
            torch=torch,
        )
        self.classes = ["benign", "attack"]
        self.base = self.root / "inputs/base.json"
        write_once(
            self.base,
            derived_json_bytes(
                export_state(model, architecture=architecture, class_names=self.classes)
            ),
        )
        self.partition = self.root / "partitions"
        clients = []
        for index in range(3):
            client = f"client{index + 1:02d}"
            rows = [
                {
                    "window_id": f"{client}-{row}",
                    "features": [float(row + index), float(index - row)],
                    "label": self.classes[(row + index) % 2],
                }
                for row in range(4)
            ]
            data = derived_json_bytes(
                {"client_id": client, "class_names": self.classes, "rows": {"train": rows}}
            )
            relative = f"clients/{client}/dataset.json"
            write_once(self.partition / relative, data)
            clients.append(
                {
                    "client_id": client,
                    "dataset_path": relative,
                    "dataset_sha256": sha256_bytes(data),
                    "partition_id": index,
                    "train_row_count": len(rows),
                }
            )
        write_once(
            self.partition / "manifest.json",
            derived_json_bytes(
                {
                    "class_names": self.classes,
                    "global_class_weights": dict.fromkeys(self.classes, 1.0),
                    "clients": clients,
                }
            ),
        )
        self.validation = self.root / "inputs/validation.json"
        write_once(
            self.validation,
            derived_json_bytes(
                {
                    "split": "validation",
                    "class_names": self.classes,
                    "rows": {
                        "validation": [
                            {"window_id": "val-0", "features": [0.0, 1.0], "label": "benign"},
                            {"window_id": "val-1", "features": [1.0, 0.0], "label": "attack"},
                        ]
                    },
                }
            ),
        )
        self.signer = SoftwareECDSASigner.generate()
        self.plan = RetrainingPlan(
            rounds=3,
            seed=7,
            local_epochs=1,
            batch_size=2,
            learning_rate_decimal="0.01",
            minimum_contributors=2,
            clients=[item["client_id"] for item in clients],
        )

    def _create(self, name="baseline", plan=None):
        result = create_retraining_replay(
            output=self.root / name,
            plan=plan or self.plan,
            base_model_path=self.base,
            expected_base_sha256=sha256_file(self.base),
            partition_workspace=self.partition,
            expected_partition_sha256=sha256_file(self.partition / "manifest.json"),
            validation_split_path=self.validation,
            expected_validation_sha256=sha256_file(self.validation),
            signer=self.signer,
            authority_public_key=self.signer.private_key.public_key(),
        )
        return result

    def _verify(self, name, pin):
        return verify_retraining_replay(
            workspace=self.root / name,
            expected_sha256=pin,
            base_model_path=self.base,
            partition_workspace=self.partition,
            validation_split_path=self.validation,
            authority_public_key=self.signer.private_key.public_key(),
        )

    def test_actual_three_round_training_reproduces_all_trajectory_bytes(self):
        result = self._create()
        self.assertEqual(result["actual_local_training_runs"], 9)
        report = self._verify("baseline", result["manifest_sha256"])
        self.assertEqual(report["status"], "verified", report)
        self.assertTrue(report["training_reexecuted"])
        self.assertFalse(report["future_historical_updates_reused"])

    def test_removal_retrains_future_rounds_from_corrected_model(self):
        baseline = self._create()
        plan = self.plan.model_copy(update={"remove_at_round": {"1": ["client03"]}})
        branch = self._create("branch", plan)
        self.assertEqual(baseline["actual_local_training_runs"], 9)
        self.assertEqual(branch["actual_local_training_runs"], 8)
        previous = self.root / "branch/rounds/round-001/model.json"
        self.assertNotEqual(
            previous.read_bytes(), (self.root / "baseline/rounds/round-001/model.json").read_bytes()
        )
        details = json.loads((self.root / "branch/rounds/round-002/round.json").read_bytes())
        self.assertEqual(details["base_model_sha256"], sha256_file(previous))
        self.assertEqual(details["selected_clients"], self.plan.clients)
        for record in details["local_training_runs"]:
            self.assertEqual(record["base_model_sha256"], sha256_file(previous))
            self.assertGreater(record["metrics"]["optimizer_steps"], 0)
        self.assertNotEqual(
            (self.root / "baseline/rounds/round-002/updates/client01.json").read_bytes(),
            (self.root / "branch/rounds/round-002/updates/client01.json").read_bytes(),
        )
        self.assertEqual(self._verify("branch", branch["manifest_sha256"])["status"], "verified")

    def test_no_intervention_control_has_identical_artifact_hashes(self):
        self._create()
        control = self._create("control")
        first = json.loads((self.root / "baseline/manifest.json").read_bytes())["core"]["artifacts"]
        second = json.loads((self.root / "control/manifest.json").read_bytes())["core"]["artifacts"]
        self.assertEqual(first, second)
        self.assertEqual(self._verify("control", control["manifest_sha256"])["status"], "verified")

    def test_quorum_failure_produces_no_fictitious_model_or_future_training(self):
        plan = self.plan.model_copy(update={"remove_at_round": {"2": ["client01", "client02"]}})
        result = self._create(plan=plan)
        self.assertEqual(result["actual_local_training_runs"], 3)
        self.assertFalse((self.root / "baseline/rounds/round-002/model.json").exists())
        self.assertFalse((self.root / "baseline/rounds/round-003").exists())
        self.assertEqual(self._verify("baseline", result["manifest_sha256"])["status"], "verified")

    def test_changed_training_snapshot_is_detected(self):
        result = self._create()
        path = self.partition / "clients/client01/dataset.json"
        path.chmod(0o600)
        path.write_bytes(b"changed")
        self.assertEqual(self._verify("baseline", result["manifest_sha256"])["status"], "failed")

    def test_invalid_removal_schedule_is_rejected(self):
        for schedule in ({"4": ["client01"]}, {"1": ["unknown"]}, {"1": ["client01", "client01"]}):
            with self.assertRaisesRegex(RetrainingReplayError, "schedule"):
                self._create(plan=self.plan.model_copy(update={"remove_at_round": schedule}))

    def test_tampered_model_and_unexpected_artifact_are_rejected(self):
        result = self._create()
        path = self.root / "baseline/rounds/round-003/model.json"
        path.chmod(0o600)
        path.write_bytes(b"changed")
        self.assertEqual(self._verify("baseline", result["manifest_sha256"])["status"], "failed")

    def test_source_inputs_and_prior_output_are_not_rewritten(self):
        sources = [
            self.base,
            self.validation,
            *[p for p in self.partition.rglob("*") if p.is_file()],
        ]
        before = {str(path): path.read_bytes() for path in sources}
        self._create()
        manifest = (self.root / "baseline/manifest.json").read_bytes()
        self._create()
        self.assertEqual((self.root / "baseline/manifest.json").read_bytes(), manifest)
        self.assertEqual(before, {str(path): path.read_bytes() for path in sources})

    def test_cli_exposes_actual_training_and_public_recomputation(self):
        import io
        from contextlib import redirect_stdout

        from fl_forensics.cli import main

        public, private = self.root / "replay.public.pem", self.root / "replay.private.pem"
        write_once(public, self.signer.public_pem())
        write_once(private, self.signer.private_pem())
        plan = self.root / "plan.json"
        write_once(
            plan,
            derived_json_bytes(self.plan.model_copy(update={"rounds": 1}).model_dump(mode="json")),
        )
        common = [
            "--workspace",
            str(self.root / "cli-replay"),
            "--base-model",
            str(self.base),
            "--partition-workspace",
            str(self.partition),
            "--validation-split",
            str(self.validation),
            "--authority-public-key",
            str(public),
        ]
        with redirect_stdout(io.StringIO()) as stdout:
            code = main(
                [
                    "retraining-create",
                    *common,
                    "--plan",
                    str(plan),
                    "--expected-base-sha256",
                    sha256_file(self.base),
                    "--expected-partition-sha256",
                    sha256_file(self.partition / "manifest.json"),
                    "--expected-validation-sha256",
                    sha256_file(self.validation),
                    "--authority-private-key",
                    str(private),
                ]
            )
        self.assertEqual(code, 0, stdout.getvalue())
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["actual_local_training_runs"], 3)
        with redirect_stdout(io.StringIO()) as stdout:
            code = main(
                ["retraining-verify", *common, "--expected-sha256", result["manifest_sha256"]]
            )
        self.assertEqual(code, 0, stdout.getvalue())
        self.assertTrue(json.loads(stdout.getvalue())["training_reexecuted"])
