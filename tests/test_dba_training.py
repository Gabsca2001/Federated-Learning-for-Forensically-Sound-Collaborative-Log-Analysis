import json
from copy import deepcopy

import pytest

from fl_forensics.canonical import sha256_bytes
from fl_forensics.dba_training import build_dba_training_binding, prepare_dba_training_rows
from fl_forensics.preprocessing import derived_json_bytes


@pytest.fixture
def bound(tmp_path):
    config = {
        "profile": "bound-dba-training-v1",
        "plan": {
            "target_label": "benign",
            "client_components": {"a": [0], "b": [1]},
            "trigger_values_decimal": {"0": "12", "1": "12"},
            "poisoned_fraction_decimal": "0.50",
            "attack_rounds": [1],
            "seed": 12,
        },
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(config))
    training = {
        "clients": [{"client_id": c} for c in ("a", "b", "c")],
        "class_names": ["benign", "attack"],
        "feature_names": ["x", "y"],
    }
    training["dba_training_experiment"] = build_dba_training_binding(path, training)
    rows = [
        {"window_id": str(i), "features": [float(i), float(i + 1)], "label": "attack"}
        for i in range(8)
    ]
    return training, rows, path


def test_training_transform_does_not_mutate_pinned_input_and_preserves_row_budget(bound):
    training, rows, _ = bound
    original = deepcopy(rows)
    changed, record = prepare_dba_training_rows(
        training=training, rows=rows, client_id="a", round_number=1
    )
    assert rows == original and changed != original
    assert len(record["poisoned_window_ids"]) == 4
    assert record["feature_indices"] == [0]
    assert record["source_rows_sha256"] == sha256_bytes(derived_json_bytes(original))
    assert record["training_rows_sha256"] == sha256_bytes(derived_json_bytes(changed))
    assert [r["features"][1] for r in changed] == [r["features"][1] for r in rows]


@pytest.mark.parametrize("client,number", [("c", 1), ("a", 2)])
def test_benign_and_post_attack_training_are_unchanged(bound, client, number):
    training, rows, _ = bound
    changed, record = prepare_dba_training_rows(
        training=training, rows=rows, client_id=client, round_number=number
    )
    assert changed == rows and record["poisoned_window_ids"] == []
    assert record["source_rows_sha256"] == record["training_rows_sha256"]


def test_changed_plan_without_updated_binding_is_rejected(bound):
    training, rows, _ = bound
    training["dba_training_experiment"]["plan"]["target_label"] = "attack"
    with pytest.raises(ValueError, match="digest"):
        prepare_dba_training_rows(training=training, rows=rows, client_id="a", round_number=1)


def test_unbound_nominal_path_remains_unchanged(bound):
    _, rows, _ = bound
    changed, record = prepare_dba_training_rows(
        training={}, rows=rows, client_id="a", round_number=1
    )
    assert changed is rows and record is None


@pytest.mark.parametrize("change", ["client", "target", "width", "profile"])
def test_invalid_experiment_rejected_before_training(bound, change):
    training, _, path = bound
    data = json.loads(path.read_text())
    if change == "client":
        training["clients"] = [{"client_id": "a"}]
    if change == "target":
        training["class_names"] = ["attack"]
    if change == "width":
        training["feature_names"] = ["x"]
    if change == "profile":
        data["profile"] = "unknown"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        build_dba_training_binding(path, training)
