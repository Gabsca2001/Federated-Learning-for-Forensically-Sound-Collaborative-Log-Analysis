"""Meaningful checks of live gradients and experimental evidence authentication."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import (
    architecture_record,
    build_model,
    dependencies,
    export_state,
    seed_everything,
)
from fl_forensics.secure_round import _model_from_export

spec = importlib.util.spec_from_file_location(
    "revision_dba_runner_under_test",
    Path(__file__).parents[1] / "scripts/revision_dba_experiment.py",
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class DBARunnerTests(unittest.TestCase):
    def test_gradient_is_at_global_model_and_matches_weighted_loss(self):
        deps = dependencies()
        torch = deps[1]
        seed_everything(83, torch=torch, np=np)
        model = build_model(
            input_features=2,
            class_count=2,
            hidden_layers=[4, 3],
            embedding_size=2,
            dropout=0,
            torch=torch,
        )
        architecture = architecture_record(
            input_features=2, class_count=2, hidden_layers=[4, 3], embedding_size=2, dropout=0
        )
        state = export_state(model, architecture=architecture, class_names=["benign", "attack"])
        original = json.dumps(state, sort_keys=True)
        rows = [
            {"features": [1.0, 2.0], "label": "benign"},
            {"features": [-2.0, 3.0], "label": "attack"},
            {"features": [2.0, 1.0], "label": "attack"},
        ]
        gradients, metrics = runner.full_gradient(state, rows, {"benign": 2.0, "attack": 5.0}, deps)
        reference = _model_from_export(state, torch=torch, np=np)
        loss = torch.nn.CrossEntropyLoss(weight=torch.tensor([2.0, 5.0]))(
            reference(torch.tensor([[1.0, 2.0], [-2.0, 3.0], [2.0, 1.0]])), torch.tensor([0, 1, 1])
        )
        loss.backward()
        for actual, expected in zip(gradients, reference.parameters(), strict=True):
            np.testing.assert_array_equal(actual, expected.grad.numpy())
        self.assertEqual(metrics["optimizer_steps"], 0)
        self.assertEqual(original, json.dumps(state, sort_keys=True))

    def _evidence(self, root):
        runner.save(root / "protocol-before-training.json", {"test_only": True})
        update = root / "rounds/round-001/updates/client01.json"
        runner.save(update, {"a": [1, 2]})
        runner.save(
            root / "rounds/round-001/round.json",
            {
                "round_number": 1,
                "base_model_sha256": "1" * 64,
                "local_training_records": [
                    {
                        "client_id": "client01",
                        "local_model_sha256": sha256_file(update),
                        "source_snapshot_sha256": "2" * 64,
                        "poisoned_snapshot_sha256": "3" * 64,
                    }
                ],
            },
        )
        return runner.close_experiment({}, root)

    def test_public_software_signatures_verify_without_private_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self._evidence(root)
            runner.authenticate(root, report["manifest_sha256"])
            self.assertFalse(any("private" in path.name for path in root.rglob("*")))

    def test_changed_signed_local_model_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self._evidence(root)
            altered = root / "rounds/round-001/updates/client01.json"
            altered.chmod(0o640)  # simulate a writer who can bypass the local mode bit
            altered.write_text('{"a": [4]}')
            with self.assertRaises(AssertionError):
                runner.authenticate(root, report["manifest_sha256"])

    def test_empty_or_unexpected_evidence_does_not_authenticate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self._evidence(root)
            (root / "unexpected.json").write_text("{}")
            with self.assertRaises(AssertionError):
                runner.authenticate(root, report["manifest_sha256"])
            with self.assertRaises(ValueError):
                runner.authenticate(root, "0" * 64)
