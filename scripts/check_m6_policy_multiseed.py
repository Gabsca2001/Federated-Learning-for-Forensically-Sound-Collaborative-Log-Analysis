"""Read-only preflight for the fixed M6 paired experiment."""
from pathlib import Path
import hashlib
import json
import yaml


def check(root: Path) -> None:
    lock = json.loads((root / "configs/m6-policy-multiseed-v1.lock.json").read_text())
    for group in ("files", "pilot_manifests"):
        for name, expected in lock[group].items():
            actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
            if actual != expected:
                raise ValueError(f"Frozen experiment input changed: {name}")
    base = yaml.safe_load((root / "configs/federation.yaml").read_text())
    for seed in lock["new_seeds"]:
        config = yaml.safe_load((root / f"configs/federation-m6-policy-seed-{seed}.yaml").read_text())
        if config["training"]["seed"] != seed or config["partitioning"]["seed"] != seed:
            raise ValueError(f"Seed mismatch: {seed}")
        config["training"]["seed"] = base["training"]["seed"]
        config["partitioning"]["seed"] = base["partitioning"]["seed"]
        if config != base or config["training"]["device"] != "cpu":
            raise ValueError("Only the paired seed may differ from the pilot")
    implementation = None
    partition_digest = None
    for policy in lock["policies"]:
        config_name = "in-round-admission.yaml" if policy == "gated_composite" else "in-round-admission-sequential.yaml"
        policy_digest = hashlib.sha256((root / "configs" / config_name).read_bytes()).hexdigest()
        for condition in lock["conditions"]:
            workspace = root / f"artifacts/m6-policy-pilot-{policy}-{condition}-s341593-v1"
            manifest = json.loads((workspace / "campaign-manifest.json").read_text())["core"]
            if manifest["round_count"] != 30:
                raise ValueError("Pilot must contain 30 rounds")
            partition_digest = partition_digest or manifest["partition_manifest_sha256"]
            if manifest["partition_manifest_sha256"] != partition_digest:
                raise ValueError("Pilot partitions differ")
            evaluation = workspace / "evaluation/selected-checkpoint-evaluation.json"
            if hashlib.sha256(evaluation.read_bytes()).hexdigest() != manifest["final_evaluation_sha256"]:
                raise ValueError("Pilot final evaluation changed")
            for number in range(1, 31):
                public = workspace / f"rounds/round-{number:03d}/public"
                contract = json.loads((public / "in-round-admission-contract.json").read_text())["core"]
                if contract["primary_policy"] != policy or contract["policy_config_sha256"] != policy_digest:
                    raise ValueError("Pilot policy differs from planned policy")
                implementation = implementation or contract["implementation_sha256"]
                if contract["implementation_sha256"] != implementation:
                    raise ValueError("Pilot implementation changed across campaigns")
    from fl_forensics.in_round_admission import _implementation_sha256
    if implementation != _implementation_sha256():
        raise ValueError("Admission implementation differs from pilot")
    print("Preflight passed: four preserved pilot campaigns; four new paired CPU seeds; fixed code and calibration.")


if __name__ == "__main__":
    check(Path(__file__).resolve().parents[1])
