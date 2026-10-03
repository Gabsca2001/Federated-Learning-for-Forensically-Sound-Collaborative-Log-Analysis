"""Continue the frozen seed-342593 M6 campaign on an explicit evidence branch."""
import fcntl
import hashlib
import json
import os
import shutil
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_m6_adaptive_untargeted_paired_v1 as frozen
import resume_m6_adaptive_untargeted_paired_s342593_v1 as support
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _coordinator_signer, _load_context
from run_m5_secure_multiround import refresh_attestations
from run_m6_adaptive_paired_seed import IDS, signed, training_command

PLAN_FILE = ROOT / "configs/m6-adaptive-untargeted-continuation-s342593-v2.json"
LOCK_FILE = ROOT / "configs/m6-adaptive-untargeted-continuation-s342593-v2.lock.json"
SOURCE = ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1"
BRANCH = ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1-continuation-v2"
STAGING = ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1-continuation-v2.staging"
TRUST = ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1-trust"
NODES = ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1-nodes"
ARTIFACTS = ROOT / "artifacts"
LOG = ROOT / "m6-adaptive-untargeted-paired-v1-continuation-v2.log"
PROCESS = ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-continuation-v2-process.json"
ROUND24_RECEIPT = ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-continuation-v2-round24.json"
COMPLETE = ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-continuation-v2-completion.json"
ARMS = ("gated_clean", "gated_adaptive", "tpm_clean", "tpm_adaptive")
ATTACKERS = ("client02", "client05", "client14")
POLICY = "configs/in-round-admission.yaml"
SECURE = "configs/secure-round.yaml"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def once(path, value):
    path = Path(path)
    data = derived_json_bytes(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def check_continuation_lock():
    plan = read(PLAN_FILE)
    lock = read(LOCK_FILE)
    require(lock["plan_sha256"] == sha(PLAN_FILE), "Continuation plan hash mismatch")
    for name, digest in lock["files"].items():
        require(sha(ROOT / name) == digest, "Continuation lock changed: " + name)
    require(plan["continuation_id"] == "m6-adaptive-untargeted-continuation-s342593-v2",
            "Unexpected continuation identity")
    return plan, lock


def source_inventory(execution, plan):
    markers = []
    import re
    marker_re = re.compile(r"^VERIFIED (gated_clean|gated_adaptive|tpm_clean|tpm_adaptive) round (\d+)/30")
    source_log = support.RECOVERY_LOG
    require(source_log.is_file(), "Original recovery log missing")
    for line in source_log.read_text(errors="replace").splitlines():
        match = marker_re.match(line)
        if match:
            markers.append((match.group(1), int(match.group(2))))
    expected_markers = {(arm, n) for arm in ARMS for n in range(1, 24)}
    expected_markers.add(("gated_clean", 24))
    require(len(markers) == 93 and set(markers) == expected_markers,
            "Original recovery log does not prove the expected 93 verified rounds")

    expected_counts = {"gated_clean": 24, "gated_adaptive": 24,
                       "tpm_clean": 23, "tpm_adaptive": 23}
    for arm, count in expected_counts.items():
        rounds = sorted((SOURCE / arm / "rounds").glob("round-*"))
        numbers = {int(item.name.removeprefix("round-")) for item in rounds}
        require(numbers == set(range(1, count + 1)),
                "Unexpected source round inventory for " + arm)

    partial = SOURCE / "gated_adaptive/rounds/round-024"
    require(partial.is_dir(), "Expected partial round 24 is missing")
    require(not any((partial / name).exists()
                    for name in ("checkpoint", "decisions", "in-round-decisions")),
            "Partial source round contains aggregation outputs; stop for review")
    context = _load_context(partial / "public")
    expires = datetime.fromisoformat(context.core.expires_at.replace("Z", "+00:00"))
    require(expires <= datetime.now(UTC), "Source partial context is not expired yet")

    require(execution["files"] == frozen.static_lock()["files"],
            "Source execution lock input hashes differ from the frozen lock")
    return {
        "verified_markers": 93,
        "partial_context_digest": context.core_digest,
        "partial_context_sha256": sha(partial / "public/round-context.json"),
        "partial_context_expires_at": context.core.expires_at,
        "partial_selection_sha256": sha(partial / "adaptive-selection.json"),
        "partial_search_summary_sha256": sha(partial / "adaptive-search/summary.json"),
    }


def included_paths(root):
    paths = [root / "execution-lock.json"]
    for arm in ARMS:
        campaign = root / arm
        paths.extend([campaign / "experiment-precommit.json"])
        paths.extend(sorted((campaign / "authority").rglob("*")))
        counts = 24 if arm == "gated_clean" else 23
        for number in range(1, counts + 1):
            paths.extend(sorted((campaign / "rounds" / f"round-{number:03d}").rglob("*")))
    return [path for path in paths if path.is_file()]


def copy_verified_branch(plan, partial):
    require(not BRANCH.exists(), "Continuation branch already exists; preserve and inspect it")
    require(not STAGING.exists(), "Continuation staging path already exists; preserve and inspect it")
    require(not PROCESS.exists() and not COMPLETE.exists() and not ROUND24_RECEIPT.exists(),
            "Continuation receipt already exists; do not duplicate the run")
    STAGING.mkdir()
    shutil.copy2(SOURCE / "execution-lock.json", STAGING / "execution-lock.json")
    for arm in ARMS:
        source_campaign = SOURCE / arm
        target_campaign = STAGING / arm
        target_campaign.mkdir()
        shutil.copy2(source_campaign / "experiment-precommit.json",
                     target_campaign / "experiment-precommit.json")
        shutil.copytree(source_campaign / "authority", target_campaign / "authority")
        target_rounds = target_campaign / "rounds"
        target_rounds.mkdir()
        count = 24 if arm == "gated_clean" else 23
        for number in range(1, count + 1):
            shutil.copytree(source_campaign / "rounds" / f"round-{number:03d}",
                            target_rounds / f"round-{number:03d}")

    source_files = included_paths(SOURCE)
    target_files = included_paths(STAGING)
    source_map = {str(path.relative_to(SOURCE)): path for path in source_files}
    target_map = {str(path.relative_to(STAGING)): path for path in target_files}
    require(set(source_map) == set(target_map), "Copied file inventory differs from source")
    manifest = {}
    total_bytes = 0
    for relative, source in source_map.items():
        target = target_map[relative]
        source_digest = sha(source)
        require(sha(target) == source_digest, "Copied file hash mismatch: " + relative)
        total_bytes += source.stat().st_size
        manifest[relative] = source_digest

    partial_round = SOURCE / "gated_adaptive/rounds/round-024"
    record = {
        "schema_version": "1.0",
        "artifact_type": "m6_adaptive_untargeted_continuation_branch",
        "continuation_id": plan["continuation_id"],
        "source_experiment_id": plan["source_experiment_id"],
        "source_workspace": str(SOURCE),
        "branch_workspace": str(BRANCH),
        "source_execution_lock_sha256": sha(SOURCE / "execution-lock.json"),
        "source_static_lock_sha256": sha(LOCK_FILE.parent / "m6-adaptive-untargeted-paired-s342593-v1.lock.json"),
        "continuation_lock_sha256": sha(LOCK_FILE),
        "copied_verified_round_count": 93,
        "copied_file_count": len(manifest),
        "copied_bytes": total_bytes,
        "copied_file_manifest_sha256": hashlib.sha256(
            derived_json_bytes(manifest)
        ).hexdigest(),
        "excluded_partial_round": "gated_adaptive/rounds/round-024",
        "excluded_partial_context_sha256": partial["partial_context_sha256"],
        "excluded_partial_context_digest": partial["partial_context_digest"],
        "exclusion_reason": "The M5 signed context expired before all client submissions and aggregation completed.",
        "newly_created_rounds": plan["recreated_rounds"],
        "test_data_accessed": False,
        "created_at": datetime.now(UTC).isoformat(),
    }
    once(STAGING / "continuation-branch.json", record)
    os.rename(STAGING, BRANCH)
    return record


def audit_source_runtime(plan, execution, env, namespace):
    support.audit_runtime(plan, env, namespace, execution)
    observed = frozen.tpm_boots(env)
    require(observed == execution["tpm_start_times"],
            "TPM identity/start times differ from the source execution lock")


def create_gated_adaptive_round24(plan, execution, env):
    federation = ROOT / plan["source_plan"]
    plan_source = read(federation)
    federation = ROOT / plan_source["federation_config"]
    validation = ROOT / plan_source["partition"] / "server/splits/validation.json"
    compose = ["docker", "compose", "-f", str(ROOT / "compose.m5.yaml")]
    arm = "gated_adaptive"
    policy = "gated_composite"
    campaign = BRANCH / arm
    source = campaign / "rounds/round-024"
    require(not source.exists(), "Branch round 24 already exists; stop and inspect")
    env["M5_COORDINATOR_WORKSPACE"] = str(campaign)
    env["M5_WORKSPACE"] = str(source)
    signer = _coordinator_signer(campaign, create=False)

    refresh_attestations(root=ROOT, environment=env, trust_workspace=TRUST,
                         node_root=NODES, compose_m4=ROOT / "compose.m4.yaml")
    args = [
        "fl-forensics", "m5-init", "--workspace", source,
        "--coordinator-workspace", campaign, "--trust-workspace", TRUST,
        "--partition-manifest", ROOT / plan_source["partition"] / "manifest.json",
        "--config", federation, "--secure-config", ROOT / SECURE,
        "--round-number", "24", "--in-round-admission-config", ROOT / POLICY,
    ]
    first = _load_context(campaign / "rounds/round-001/public")
    args += ["--campaign-id", first.core.campaign_id,
             "--previous-round-workspace", campaign / "rounds/round-023"]
    frozen.run(args, env)
    context = _load_context(source / "public")
    cfg = frozen.configs(plan_source)["gated_composite"]
    pre = source / "adaptive-precommit.json"
    code = {name: sha(ROOT / name) for name in (
        "scripts/m6_adaptive_untargeted_live_search.py",
        "scripts/m6_adaptive_live_signing.py",
        "scripts/verify_m6_adaptive_untargeted_paired_v1.py",
    )}
    signed(pre, {
        "artifact_type": "adaptive_live_precommit",
        "created_at": datetime.now(UTC).isoformat(),
        "context_digest": context.core_digest,
        "config_json": derived_json_bytes(cfg).decode(),
        "execution_lock_sha256": sha(BRANCH / "execution-lock.json"),
        "arm": arm, "policy": policy, "attack_active": True,
        "numerical_runtime": plan_source["numerical_runtime"], "code": code,
        "validation_sha256": sha(validation),
        "attestation_scope": "M4 baseline unchanged; adaptive search, signer and policy bound by signed coordinator precommit",
    }, signer)

    def train(client_id):
        proposal = source / "proposals" / client_id
        proposal.mkdir(parents=True)
        frozen.run(training_command(compose, proposal, client_id), env)

    with ThreadPoolExecutor(max_workers=plan_source["workers"]) as pool:
        list(pool.map(train, IDS))
    frozen.search_and_sign(source, cfg, signer, pre, TRUST,
                           ROOT / plan_source["partition"], compose, env)

    aggregate = [
        "fl-forensics", "m5-admit-composite-aggregate", "--workspace", source,
        "--coordinator-workspace", campaign, "--trust-workspace", TRUST,
        "--submissions", source / "submissions", "--validation-split", validation,
    ]
    frozen.run(aggregate, env)
    frozen.run([
        sys.executable, "scripts/verify_m6_adaptive_untargeted_paired_v1.py",
        "--pair", BRANCH, "--arm", arm, "--round", "24",
    ], env)
    once(ROUND24_RECEIPT, {
        "schema_version": "1.0",
        "artifact_type": "m6_adaptive_untargeted_branch_round",
        "status": "verified",
        "arm": arm,
        "round": 24,
        "context_id": context.context_id,
        "context_digest": context.core_digest,
        "execution_lock_sha256": sha(BRANCH / "execution-lock.json"),
        "branch_record_sha256": sha(BRANCH / "continuation-branch.json"),
        "test_data_accessed": False,
        "verified_at": datetime.now(UTC).isoformat(),
    })
    print("VERIFIED gated_adaptive round 24/30 attack_active=True (new branch context)",
          flush=True)


def run_campaign():
    plan, continuation_lock = check_continuation_lock()
    plan_source = read(ROOT / plan["source_plan"])
    source_execution = read(SOURCE / "execution-lock.json")
    require(source_execution["static_lock_sha256"] == sha(ROOT / plan["source_lock"]),
            "Source execution lock has a different static-lock digest")
    require(source_execution["plan"] == plan_source,
            "Source execution lock plan differs from the frozen plan")
    partial = source_inventory(source_execution, plan)
    env, namespace = support.environment(plan_source)
    audit_source_runtime(plan_source, source_execution, env, namespace)

    guard_path = ARTIFACTS / (plan["continuation_id"] + ".process-lock")
    with guard_path.open("a") as guard:
        fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not BRANCH.exists() and not STAGING.exists(),
                "Branch or staging already exists; preserve and inspect")
        once(PROCESS, {
            "schema_version": "1.0",
            "artifact_type": "m6_adaptive_untargeted_continuation_process",
            "continuation_id": plan["continuation_id"],
            "pid": os.getpid(),
            "status": "started",
            "started_at": datetime.now(UTC).isoformat(),
            "plan_sha256": sha(PLAN_FILE),
            "continuation_lock_sha256": sha(LOCK_FILE),
            "source_execution_lock_sha256": sha(SOURCE / "execution-lock.json"),
            "log": str(LOG),
            "tpm_start_times": source_execution["tpm_start_times"],
        })
        branch_record = copy_verified_branch(plan, partial)
        print(json.dumps({
            "status": "branch_copy_verified",
            "branch_workspace": str(BRANCH),
            "verified_rounds_copied": 93,
            "copied_gib": round(branch_record["copied_bytes"] / (1024 ** 3), 3),
            "excluded_round": "gated_adaptive/round-024",
            "test_data_accessed": False,
        }, indent=2), flush=True)

        support.PAIR = BRANCH
        support.PROCESS = PROCESS
        support.COMPLETE = COMPLETE
        support.ROUND24_RECEIPT = ROUND24_RECEIPT
        support.LOG = LOG
        audit_source_runtime(plan_source, source_execution, env, namespace)
        create_gated_adaptive_round24(plan, source_execution, env)
        support.run_remaining(plan_source, source_execution, env)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "run"))
    args = parser.parse_args()
    plan, _ = check_continuation_lock()
    if args.action == "preflight":
        source_plan = read(ROOT / plan["source_plan"])
        static = frozen.static_lock()
        execution = read(SOURCE / "execution-lock.json")
        partial = source_inventory(execution, plan)
        env, namespace = support.environment(source_plan)
        audit_source_runtime(source_plan, execution, env, namespace)
        require(not BRANCH.exists() and not STAGING.exists(),
                "Branch or staging already exists; preserve and inspect")
        print(json.dumps({
            "status": "continuation_preflight_verified",
            "source_verified_rounds": partial["verified_markers"],
            "rounds_to_create": plan["recreated_round_count"],
            "source_lock_files": len(static["files"]),
            "namespace": namespace,
            "test_data_accessed": False,
        }, indent=2))
        return
    if LOG.exists():
        raise RuntimeError("Continuation log already exists; refusing overwrite")
    with LOG.open("x", encoding="utf-8") as stream:
        stream.flush()
        os.dup2(stream.fileno(), 1)
        os.dup2(stream.fileno(), 2)
        try:
            run_campaign()
        except BaseException:
            traceback.print_exc()
            raise


if __name__ == "__main__":
    if os.environ.get("M6_NUMERIC_RUNTIME") != "single-thread-compatible-v1":
        os.execv(sys.executable, [sys.executable, str(ROOT / "scripts/m6_numeric_runtime.py"),
                                  "script", str(Path(__file__)), *sys.argv[1:]])
    import torch
    if torch.get_num_threads() != 1 or torch.get_num_interop_threads() != 1:
        raise RuntimeError("Numerical runtime not configured")
    main()
