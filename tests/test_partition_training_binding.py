import copy

import pytest
import yaml

from fl_forensics.canonical import sha256_file
from fl_forensics.partition_training_binding import partition_training_binding


def source(tmp_path):
    config = {
        "partitioning": {"seed": 7},
        "model": {"size": 4},
        "training": {"seed": 7, "local_epochs": 2, "rounds": 30, "optimizer": "adam"},
    }
    path = tmp_path / "original.yaml"
    path.write_text(yaml.safe_dump(config))
    return config, path, {"partition_config_sha256": sha256_file(path)}


def test_only_declared_training_fields_can_change(tmp_path):
    original, path, manifest = source(tmp_path)
    config = copy.deepcopy(original)
    config["training"].update(seed=123, local_epochs=10, rounds=5)
    result = partition_training_binding(config, "a" * 64, manifest, path)
    assert set(result["changed_training_fields"]) == {"seed", "local_epochs", "rounds"}


@pytest.mark.parametrize("field", ["partitioning", "model", "optimizer"])
def test_protected_changes_are_rejected(tmp_path, field):
    config, path, manifest = source(tmp_path)
    if field == "optimizer":
        config["training"][field] = "sgd"
    else:
        config[field] = {"changed": True}
    with pytest.raises(ValueError, match="protected setting"):
        partition_training_binding(config, "a" * 64, manifest, path)


def test_different_config_requires_the_exact_original(tmp_path):
    config, path, manifest = source(tmp_path)
    with pytest.raises(ValueError, match="explicit partition"):
        partition_training_binding(config, "a" * 64, manifest)
    path.write_text("changed: true\n")
    with pytest.raises(ValueError, match="digest mismatch"):
        partition_training_binding(config, "a" * 64, manifest, path)
