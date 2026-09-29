"""Read-only fixed-protocol preflight for exploratory live sensitivity."""
from pathlib import Path
import copy
import hashlib
import json
import yaml
from check_m6_policy_multiseed import check

ROOT = Path(__file__).resolve().parents[1]

def main():
    check(ROOT)
    lock = json.loads((ROOT / "configs/m6-downplus10-v1.lock.json").read_text())
    for name, expected in lock["files"].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Frozen input changed: {name}")
    base = yaml.safe_load((ROOT/"configs/in-round-admission.yaml").read_text())
    variant = yaml.safe_load((ROOT/"configs/in-round-admission-downplus10-v1.yaml").read_text())
    expected = copy.deepcopy(base)
    expected["runtime_admission"]["policy_id"] = "m6-gated-downplus10-v1"
    expected["runtime_admission"]["calibration"]["thresholds"]["composite_downweight_threshold"] *= 1.1
    if variant != expected:
        raise ValueError("Variant must change only the downweight threshold by +10% and policy id")
    for seed in (341593,342593,343593,344593,345593):
        phase = "pilot" if seed == 341593 else "multiseed"
        partition = "m3-data24-parquet-iid-local-test-v1" if seed == 341593 else f"m6-policy-partition-s{seed}-v1"
        for condition in ("clean", "disagreement"):
            w = ROOT/"artifacts"/f"m6-policy-{phase}-gated_composite-{condition}-s{seed}-v1"
            m = json.loads((w/"campaign-manifest.json").read_text())["core"]
            if m["round_count"] != 30 or m["partition_manifest_sha256"] != hashlib.sha256((ROOT/"artifacts"/partition/"manifest.json").read_bytes()).hexdigest():
                raise ValueError("Baseline/partition pairing mismatch")
    print("Live sensitivity preflight passed: fixed +10% downweight threshold, ten preserved paired baselines.")

if __name__ == "__main__":
    main()
