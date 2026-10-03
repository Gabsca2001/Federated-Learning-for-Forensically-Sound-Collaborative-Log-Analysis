import copy, hashlib, json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEEDS = (343593, 344593, 345593)
BASE_PLAN = ROOT / "configs/m6-adaptive-untargeted-paired-s342593-v1.json"
BASE_LOCK = ROOT / "configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json"
DOC = ROOT / "docs/M6_ADAPTIVE_UNTARGETED_REPLICATION_V1.md"
GENERATOR = ROOT / "scripts/prepare_m6_adaptive_untargeted_replicas_v1.py"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def file_digest(path):
    return digest(path.read_bytes())

def create_once(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)

def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

def main():
    base_plan = json.loads(BASE_PLAN.read_text(encoding="utf-8"))
    base_lock = json.loads(BASE_LOCK.read_text(encoding="utf-8"))
    if digest(BASE_PLAN.read_bytes()) != base_lock["plan_sha256"]:
        raise ValueError("Seed-342593 base plan differs from its frozen lock")
    for name, expected in base_lock["files"].items():
        if file_digest(ROOT / name) != expected:
            raise ValueError("Seed-342593 frozen input changed: " + name)
    if not DOC.is_file():
        raise FileNotFoundError(DOC)
    if not GENERATOR.is_file():
        raise FileNotFoundError(GENERATOR)

    base_runner = (ROOT / "scripts/run_m6_adaptive_untargeted_paired_v1.py").read_text(encoding="utf-8")
    base_verifier = (ROOT / "scripts/verify_m6_adaptive_untargeted_paired_v1.py").read_text(encoding="utf-8")
    outputs = []
    for seed in SEEDS:
        tag = f"m6-adaptive-untargeted-paired-s{seed}-v1"
        plan_rel = f"configs/{tag}.json"
        lock_rel = f"configs/{tag}.lock.json"
        run_rel = f"scripts/run_m6_adaptive_untargeted_paired_s{seed}_v1.py"
        verify_rel = f"scripts/verify_m6_adaptive_untargeted_paired_s{seed}_v1.py"
        partition = f"artifacts/m6-policy-partition-s{seed}-v1"
        federation = f"configs/federation-m6-policy-seed-{seed}.yaml"

        plan = copy.deepcopy(base_plan)
        plan.update({
            "experiment_id": tag,
            "seed": seed,
            "trust_tag": tag,
            "partition": partition,
            "federation_config": federation,
            "interpretation_scope": "Outcome-aware exploratory seed replication after seed 342593; same dataset, not confirmatory."
        })
        plan_data = json_bytes(plan)
        runner = base_runner.replace(
            "configs/m6-adaptive-untargeted-paired-s342593-v1.json", plan_rel
        ).replace(
            "configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json", lock_rel
        ).replace(
            "scripts/verify_m6_adaptive_untargeted_paired_v1.py", verify_rel
        )
        verifier = base_verifier.replace(
            "configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json", lock_rel
        )
        if "342593" in runner or "342593" in verifier:
            raise ValueError(f"Seed-specific source still contains old seed: {seed}")

        replacements = {
            "scripts/run_m6_adaptive_untargeted_paired_v1.py": run_rel,
            "scripts/verify_m6_adaptive_untargeted_paired_v1.py": verify_rel,
        }
        files = {}
        for old_name in base_lock["files"]:
            new_name = old_name.replace("342593", str(seed))
            new_name = replacements.get(old_name, new_name)
            files[new_name] = None
        for path in (ROOT / partition / "manifest.json",
                     ROOT / partition / "server/evaluation.json",
                     ROOT / partition / "server/splits/validation.json",
                     ROOT / federation):
            if not path.is_file():
                raise FileNotFoundError(path)
        runner_data = runner.encode("utf-8")
        verifier_data = verifier.encode("utf-8")
        generated_data = {
            plan_rel: plan_data,
            run_rel: runner_data,
            verify_rel: verifier_data,
        }
        files[DOC.relative_to(ROOT).as_posix()] = file_digest(DOC)
        files[GENERATOR.relative_to(ROOT).as_posix()] = file_digest(GENERATOR)
        for name in list(files):
            if name in generated_data:
                files[name] = digest(generated_data[name])
            else:
                files[name] = file_digest(ROOT / name)
        lock = {
            "schema_version": base_lock["schema_version"],
            "artifact_type": "m6_adaptive_untargeted_prespecification_lock",
            "created_at": datetime.now(UTC).isoformat(),
            "plan_sha256": digest(plan_data),
            "protocol_sha256": file_digest(DOC),
            "files": dict(sorted(files.items())),
        }
        lock_data = json_bytes(lock)
        outputs.extend([
            (ROOT / plan_rel, plan_data),
            (ROOT / run_rel, runner_data),
            (ROOT / verify_rel, verifier_data),
            (ROOT / lock_rel, lock_data),
        ])

    collisions = [str(path) for path, _ in outputs if path.exists()]
    if collisions:
        raise FileExistsError("Fresh-only preparation destinations exist: " + ", ".join(collisions))
    for path, data in outputs:
        create_once(path, data)
    print(json.dumps({
        "status": "prepared",
        "seeds": list(SEEDS),
        "files": [str(path.relative_to(ROOT)) for path, _ in outputs],
    }, indent=2))

if __name__ == "__main__":
    main()
