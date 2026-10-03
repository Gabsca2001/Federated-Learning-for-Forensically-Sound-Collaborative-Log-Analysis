"""Strict continuation for the frozen M6 untargeted seed-342593 campaign."""
import contextlib, fcntl, hashlib, json, os, re, shutil, subprocess, sys, traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_m6_adaptive_untargeted_paired_v1 as frozen
from fl_forensics.crypto import load_public_key
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _coordinator_signer, _load_context, _verify_signed
from m6_adaptive_live_signing import verified_authorization
from run_m5_secure_multiround import refresh_attestations
from run_m6_adaptive_paired_seed import IDS, signed, training_command

PLAN = ROOT / "configs/m6-adaptive-untargeted-paired-s342593-v1.json"
LOCK = ROOT / "configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json"
RECOVERY = ROOT / "configs/m6-adaptive-untargeted-paired-s342593-v1-recovery-v1.json"
PAIR = ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1"
TRUST = ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1-trust"
NODES = ROOT / "artifacts/m6-adaptive-untargeted-paired-s342593-v1-nodes"
ARTIFACTS = ROOT / "artifacts"
LOG = ROOT / "m6-adaptive-untargeted-paired-v1-resume3.log"
PROCESS = ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-resume-process-v2.json"
ROUND24_RECEIPT = ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-round24-resume-receipt.json"
COMPLETE = ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-resume-completion.json"
ATTACKERS = ("client02", "client05", "client14")
ARMS = ("gated_clean", "gated_adaptive", "tpm_clean", "tpm_adaptive")
RECOVERY_LOG = ROOT / "m6-adaptive-untargeted-paired-v1-recovery.log"

def read(path):
    return json.loads(Path(path).read_text())

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def once(path, value):
    path = Path(path)
    data = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def environment(plan):
    env = os.environ.copy()
    env["PATH"] = str(ROOT / ".venv/bin") + os.pathsep + env.get("PATH", "")
    ns = "flforensics_" + plan["trust_tag"].replace("-", "_")
    env.update(
        COMPOSE_PROJECT_NAME=ns,
        M4_TRUST_WORKSPACE=str(TRUST),
        M4_NODE_ROOT=str(NODES),
        M5_PARTITION_WORKSPACE=str(ROOT / plan["partition"]),
        M5_RUNTIME_IMAGE=plan["runtime_image"],
        M4_UID=str(os.getuid()),
        M4_GID=str(os.getgid()),
        M5_UID=str(os.getuid()),
        M5_GID=str(os.getgid()),
    )
    return env, ns

def audit_runtime(plan, env, ns, execution):
    ids = subprocess.check_output(
        ["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + ns],
        text=True, env=env,
    ).split()
    require(len(ids) == 15, "Expected exactly the 15 persistent TPM containers")
    observed = {}
    for cid in ids:
        item = json.loads(subprocess.check_output(["docker", "inspect", cid], text=True, env=env))[0]
        state = item["State"]
        name = item["Name"].lstrip("/")
        require(state["Running"] and state.get("Health", {}).get("Status") == "healthy",
                "TPM not running and healthy: " + name)
        require(item["Image"] == plan["m4_runtime_image_id"], "TPM image mismatch: " + name)
        observed[name] = state["StartedAt"]
    require(observed == execution["tpm_start_times"], "TPM identity/start times changed")
    recovery = read(RECOVERY)
    setup = read(ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-recovery-receipt.json")
    net = json.loads(subprocess.check_output(
        ["docker", "network", "inspect", recovery["network_name"]], text=True, env=env
    ))[0]
    require(net["Internal"] is True, "Recovery network is no longer internal")
    require(net["Id"] == setup["network"]["id"], "Recovery network identity changed")
    require(setup["m4_enrollment"]["status"] == "enrolled" and
            setup["m4_enrollment"]["error_count"] == 0 and
            setup["m4_mtls"]["status"] == "verified" and
            setup["m4_mtls"]["error_count"] == 0, "M4 recovery receipt is not verified")

def compare_dirs(left, right):
    a = {p.name for p in left.iterdir() if p.is_file()}
    b = {p.name for p in right.iterdir() if p.is_file()}
    require(a == b, "Directory file set differs: " + str(left))
    for name in a:
        require((left / name).read_bytes() == (right / name).read_bytes(),
                "Protected proposal differs: " + str(left / name))

def validate_round24(plan, execution, env):
    source = PAIR / "gated_adaptive/rounds/round-024"
    expected_top = {
        "adaptive-search", "proposals", "public", "signing-staging", "submissions",
        "adaptive-precommit.json", "adaptive-search-time.json",
        "adaptive-selection.json", "state.json",
    }
    require({p.name for p in source.iterdir()} == expected_top,
            "Round 24 partial workspace has unexpected or completed outputs")
    require(not (source / "checkpoint").exists() and not (source / "decisions").exists()
            and not (source / "in-round-decisions").exists(),
            "Round 24 already contains aggregation outputs; investigate before continuing")
    context = _load_context(source / "public")
    public_key = load_public_key((source / "public/round-coordinator.public.pem").read_bytes())
    require(_verify_signed(context, public_key), "Round 24 M5 context signature invalid")
    campaign_auth = verified_authorization(PAIR / "gated_adaptive/experiment-precommit.json", public_key)
    require(campaign_auth["arm"] == "gated_adaptive" and
            campaign_auth["policy"] == "gated_composite" and
            campaign_auth["execution_lock_sha256"] == sha(PAIR / "execution-lock.json"),
            "Campaign precommit does not match the execution lock")
    pre_path = source / "adaptive-precommit.json"
    pre = verified_authorization(pre_path, public_key)
    cfg = json.loads(pre["config_json"])
    require(pre["arm"] == "gated_adaptive" and pre["policy"] == "gated_composite"
            and pre["attack_active"] is True
            and pre["context_digest"] == context.core_digest
            and pre["execution_lock_sha256"] == sha(PAIR / "execution-lock.json")
            and pre["numerical_runtime"] == plan["numerical_runtime"]
            and cfg == execution["attack_configs"]["gated_composite"],
            "Round 24 signed precommit differs from the frozen plan")
    for name, digest in pre["code"].items():
        require(sha(ROOT / name) == digest, "Round 24 code binding changed: " + name)
    validation = ROOT / plan["partition"] / "server/splits/validation.json"
    require(pre["validation_sha256"] == sha(validation), "Validation split binding changed")

    search = source / "adaptive-search"
    summary = read(search / "summary.json")
    require(summary["source_verified"] is True and summary["test_data_accessed"] is False
            and summary["selected_query"] == 32
            and summary["objective"] == "untargeted_all_class_validation_macro_f1_degradation",
            "Adaptive search receipt is not the expected validation-only result")
    auth = verified_authorization(source / "adaptive-selection.json", public_key)
    require(auth["artifact_type"] == "adaptive_live_selection"
            and auth["context_digest"] == context.core_digest
            and auth["precommit_sha256"] == sha(pre_path)
            and auth["search_receipt_sha256"] == sha(search / "summary.json")
            and auth["selected_query"] == 32
            and set(auth["clients"]) == set(ATTACKERS),
            "Signed query-32 selection does not bind the frozen attackers")
    for cid in ATTACKERS:
        candidate = search / "queries/032" / f"{cid}.json"
        proposal = source / "proposals" / cid
        require(auth["clients"][cid]["candidate_sha256"] == sha(candidate)
                and auth["clients"][cid]["proposal_bundle_sha256"] == sha(proposal / "bundle.json"),
                "Selection candidate binding changed for " + cid)

    evaluated_at = datetime.fromisoformat(read(source / "adaptive-search-time.json")["evaluated_at"])
    selected_at = datetime.fromisoformat(auth["selected_at"])
    created_at = datetime.fromisoformat(pre["created_at"])
    require(created_at <= evaluated_at <= selected_at, "Adaptive selection chronology invalid")
    frozen.execute_live(
        search, True, source=source, trust=TRUST, validation=validation,
        cfg=cfg, evaluation_time=evaluated_at,
    )

    proposals = source / "proposals"
    require({p.name for p in proposals.iterdir() if p.is_dir()} == set(IDS),
            "Round 24 proposal set incomplete")
    submissions = source / "submissions"
    require({p.name for p in submissions.iterdir() if p.is_dir()}
            == {"client01", "client02", "client03", "client04"},
            "Round 24 existing submissions differ from the known partial state")
    for cid in ("client01", "client03", "client04"):
        compare_dirs(proposals / cid, submissions / cid)
    signed02 = submissions / "client02"
    require({p.name for p in signed02.iterdir() if p.is_file()}
            == {"bundle.json", "metrics.json", "update.json"},
            "Existing client02 signed submission is incomplete")
    require((signed02 / "update.json").read_bytes()
            == (search / "queries/032/client02.json").read_bytes(),
            "Existing client02 update differs from signed selected candidate")
    provenance = read(signed02 / "metrics.json")["m6_adaptive_live"]
    for field, expected in (
        ("authorization_sha256", sha(source / "adaptive-selection.json")),
        ("precommit_sha256", sha(pre_path)),
        ("search_receipt_sha256", sha(search / "summary.json")),
        ("original_bundle_sha256", sha(proposals / "client02/bundle.json")),
    ):
        require(provenance[field] == expected, "Existing client02 provenance mismatch: " + field)
    staging = source / "signing-staging"
    require({p.name for p in staging.iterdir() if p.is_dir()} == {"client02", "client05"},
            "Unexpected failed-attempt staging directories")
    require(all(not any(p.iterdir()) for p in staging.iterdir() if p.is_dir()),
            "Failed-attempt staging contains data; preserve and investigate")

def preflight(plan, env, ns):
    static = frozen.static_lock()
    require(PAIR.is_dir(), "Campaign workspace is missing")
    require(not PROCESS.exists() and not COMPLETE.exists() and
            not ROUND24_RECEIPT.exists(), "A resume receipt already exists; do not duplicate")
    require(not (PAIR / "complete.json").exists(), "Campaign is already finalized")
    require(not (ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-resume-staging-v2").exists(),
            "Resume staging already exists; preserve and investigate")
    execution = read(PAIR / "execution-lock.json")
    require(execution["static_lock_sha256"] == sha(LOCK)
            and execution["files"] == static["files"]
            and execution["plan"] == plan,
            "Campaign execution lock differs from frozen plan")
    require(execution["runtime_image_id"] == plan["runtime_image_id"]
            and execution["m4_runtime_image_id"] == plan["m4_runtime_image_id"],
            "Locked runtime images differ")
    require(RECOVERY_LOG.is_file(), "Original recovery log missing")
    markers = []
    pattern = re.compile(r"^VERIFIED (gated_clean|gated_adaptive|tpm_clean|tpm_adaptive) round (\d+)/30")
    for line in RECOVERY_LOG.read_text(errors="replace").splitlines():
        match = pattern.match(line)
        if match:
            markers.append((match.group(1), int(match.group(2))))
    expected = {(arm, n) for arm in ARMS for n in range(1, 24)}
    expected.add(("gated_clean", 24))
    require(len(markers) == 93 and set(markers) == expected,
            "Prior verified-round log does not match the expected 93 rounds")
    expected_counts = {"gated_clean": 24, "gated_adaptive": 24,
                       "tpm_clean": 23, "tpm_adaptive": 23}
    for arm, count in expected_counts.items():
        dirs = sorted((PAIR / arm / "rounds").glob("round-*"))
        numbers = {int(p.name.removeprefix("round-")) for p in dirs}
        require(numbers == set(range(1, count + 1)), "Unexpected round set for " + arm)
    for arm in ARMS:
        require(not (PAIR / arm / "trajectory-complete.json").exists(),
                "Trajectory was already finalized: " + arm)

    audit_runtime(plan, env, ns, execution)
    validate_round24(plan, execution, env)
    return execution

def sign_missing_attacker(source, cid, selected, auth, compose, env):
    staging_root = ARTIFACTS / "m6-adaptive-untargeted-paired-s342593-v1-resume-staging-v2"
    staging = staging_root / "gated_adaptive/rounds/round-024" / cid
    require(not staging.exists(), "Recovery staging path already exists: " + str(staging))
    staging.mkdir(parents=True)
    final = source / "submissions" / cid
    require(not final.exists(), "Refusing to overwrite signed submission: " + cid)
    command = [
        *compose, "--profile", "secure-round", "run", "--rm", "--entrypoint", "python",
        "--volume", str(ROOT / "scripts/m6_numeric_runtime.py") + ":/numeric.py:ro",
        "--volume", str(staging) + ":/submission",
        "--volume", str(source / "proposals" / cid) + ":/proposal:ro",
        "--volume", str(source / "adaptive-search/queries" / f"{selected:03d}" / f"{cid}.json") + ":/candidate.json:ro",
        "--volume", str(auth) + ":/selection.json:ro", cid, "/numeric.py", "script",
        "/app/scripts/m6_adaptive_live_signing.py", "--public", "/campaign/public",
        "--proposal", "/proposal", "--candidate", "/candidate.json",
        "--authorization", "/selection.json", "--node", "/runtime",
        "--output", "/submission/final", "--client-id", cid,
        "--tcti", "swtpm:path=/run/swtpm/swtpm.sock",
    ]
    frozen.run(command, env)
    require((staging / "final").is_dir(), "TPM signer did not produce final submission: " + cid)
    (staging / "final").rename(final)

def finish_round24(plan, execution, env):
    source = PAIR / "gated_adaptive/rounds/round-024"
    env["M5_COORDINATOR_WORKSPACE"] = str(PAIR / "gated_adaptive")
    env["M5_WORKSPACE"] = str(source)
    search = source / "adaptive-search"
    selected = 32
    auth = source / "adaptive-selection.json"
    compose = ["docker", "compose", "-f", str(ROOT / "compose.m5.yaml")]
    existing = {p.name for p in (source / "submissions").iterdir() if p.is_dir()}
    for cid in IDS:
        dst = source / "submissions" / cid
        if cid in ATTACKERS:
            if cid in existing:
                require(cid == "client02", "Unexpected prior attacker submission: " + cid)
            else:
                sign_missing_attacker(source, cid, selected, auth, compose, env)
        elif not dst.exists():
            shutil.copytree(source / "proposals" / cid, dst)
        else:
            compare_dirs(source / "proposals" / cid, dst)
    require({p.name for p in (source / "submissions").iterdir() if p.is_dir()} == set(IDS),
            "Round 24 submission set incomplete after recovery")
    frozen.run([
        "fl-forensics", "m5-admit-composite-aggregate", "--workspace", source,
        "--coordinator-workspace", PAIR / "gated_adaptive", "--trust-workspace", TRUST,
        "--submissions", source / "submissions", "--validation-split",
        ROOT / plan["partition"] / "server/splits/validation.json",
    ], env)
    frozen.run([
        sys.executable, "scripts/verify_m6_adaptive_untargeted_paired_v1.py",
        "--pair", PAIR, "--arm", "gated_adaptive", "--round", "24",
    ], env)
    once(ROUND24_RECEIPT, {
        "artifact_type": "m6_adaptive_untargeted_round_resume",
        "status": "verified",
        "round": 24,
        "arm": "gated_adaptive",
        "selected_query": selected,
        "completed_missing_signatures": ["client05", "client14"],
        "preserved_existing_signature": "client02",
        "verified_at": datetime.now(UTC).isoformat(),
        "execution_lock_sha256": sha(PAIR / "execution-lock.json"),
        "adaptive_selection_sha256": sha(auth),
        "test_data_accessed": False,
    })
    print("VERIFIED gated_adaptive round 24/30 attack_active=True (resumed)", flush=True)

def run_remaining(plan, execution, env):
    federation = ROOT / plan["federation_config"]
    validation = ROOT / plan["partition"] / "server/splits/validation.json"
    compose = ["docker", "compose", "-f", str(ROOT / "compose.m5.yaml")]
    compose_m4 = ["docker", "compose", "-f", str(ROOT / "compose.m4.yaml")]
    attack = frozen.configs(plan)
    boots = execution["tpm_start_times"]

    def check():
        frozen.static_lock()
        require(frozen.tpm_boots(env) == boots, "TPM identity/restart changed; stop and preserve")

    schedule = [(24, ("tpm_clean", "tpm_adaptive"))]
    schedule.extend((number, ARMS) for number in range(25, plan["rounds"] + 1))
    for number, scheduled_arms in schedule:
        for arm in scheduled_arms:
            check()
            policy = plan["policy_by_arm"][arm]
            campaign = PAIR / arm
            env["M5_COORDINATOR_WORKSPACE"] = str(campaign)
            signer = _coordinator_signer(campaign, create=False)
            source = campaign / "rounds" / f"round-{number:03d}"
            require(not source.exists(), "Future round workspace already exists: " + str(source))
            env["M5_WORKSPACE"] = str(source)
            refresh_attestations(root=ROOT, environment=env, trust_workspace=TRUST,
                                 node_root=NODES, compose_m4=ROOT / "compose.m4.yaml")
            args = [
                "fl-forensics", "m5-init", "--workspace", source,
                "--coordinator-workspace", campaign, "--trust-workspace", TRUST,
                "--partition-manifest", ROOT / plan["partition"] / "manifest.json",
                "--config", federation, "--secure-config", ROOT / frozen.SECURE,
                "--round-number", str(number),
            ]
            if policy == "gated_composite":
                args += ["--in-round-admission-config", ROOT / frozen.POLICY]
            if number > 1:
                first = _load_context(campaign / "rounds/round-001/public")
                args += ["--campaign-id", first.core.campaign_id,
                         "--previous-round-workspace", campaign / "rounds" / f"round-{number-1:03d}"]
            frozen.run(args, env)
            context = _load_context(source / "public")
            active = arm.endswith("_adaptive") and number in plan["attack_rounds"]
            pre = source / "adaptive-precommit.json"
            cfg = attack[policy]
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
                "execution_lock_sha256": sha(PAIR / "execution-lock.json"),
                "arm": arm, "policy": policy, "attack_active": active,
                "numerical_runtime": plan["numerical_runtime"], "code": code,
                "validation_sha256": sha(validation),
                "attestation_scope": "M4 baseline unchanged; adaptive search, signer and policy bound by signed coordinator precommit",
            }, signer)

            def train(cid):
                proposal = source / "proposals" / cid
                proposal.mkdir(parents=True)
                frozen.run(training_command(compose, proposal, cid), env)

            with ThreadPoolExecutor(max_workers=plan["workers"]) as pool:
                list(pool.map(train, IDS))
            if active:
                frozen.search_and_sign(source, cfg, signer, pre, TRUST,
                                       ROOT / plan["partition"], compose, env)
            else:
                (source / "submissions").mkdir()
                for cid in IDS:
                    shutil.copytree(source / "proposals" / cid, source / "submissions" / cid)
            command = "m5-admit-composite-aggregate" if policy == "gated_composite" else "m5-admit-aggregate"
            aggregate = [
                "fl-forensics", command, "--workspace", source,
                "--coordinator-workspace", campaign, "--trust-workspace", TRUST,
                "--submissions", source / "submissions",
            ]
            if policy == "gated_composite":
                aggregate += ["--validation-split", validation]
            frozen.run(aggregate, env)
            frozen.run([
                sys.executable, "scripts/verify_m6_adaptive_untargeted_paired_v1.py",
                "--pair", PAIR, "--arm", arm, "--round", str(number),
            ], env)
            if arm.endswith("_adaptive") and number < min(plan["attack_rounds"]):
                clean = "gated_clean" if policy == "gated_composite" else "tpm_clean"
                reference = PAIR / clean / "rounds" / f"round-{number:03d}/checkpoint/global-model.json"
                require(reference.read_bytes() == (source / "checkpoint/global-model.json").read_bytes(),
                        f"Pre-attack pairing mismatch: {policy} round {number}")
            print(f"VERIFIED {arm} round {number:02d}/{plan['rounds']} attack_active={active}", flush=True)

    for arm in ARMS:
        frozen.write_json_once(PAIR / arm / "trajectory-complete.json",
                               {"rounds": plan["rounds"], "test_data_accessed": False})
    for arm in ARMS:
        check()
        campaign = PAIR / arm
        frozen.run([
            "fl-forensics", "m5-finalize-campaign", "--workspace", campaign,
            "--trust-workspace", TRUST, "--partition-manifest",
            ROOT / plan["partition"] / "manifest.json", "--server-evaluation",
            ROOT / plan["partition"] / "server/evaluation.json",
            "--rounds", str(plan["rounds"]),
        ], env)
        frozen.run([
            "fl-forensics", "m5-verify-campaign", "--workspace", campaign,
            "--trust-workspace", TRUST, "--partition-manifest",
            ROOT / plan["partition"] / "manifest.json", "--server-evaluation",
            ROOT / plan["partition"] / "server/evaluation.json",
        ], env)
    frozen.write_once(PAIR / "complete.json", derived_json_bytes({
        "status": "verified", "arms": list(ARMS), "rounds_per_arm": plan["rounds"],
        "execution_lock_sha256": sha(PAIR / "execution-lock.json"),
        "static_lock_sha256": sha(LOCK), "test_data_accessed": True,
    }))
    frozen.run([*compose_m4, "stop", *[f"tpm{i:02d}" for i in range(1, 16)]], env)
    once(COMPLETE, {
        "artifact_type": "m6_adaptive_untargeted_resume_completion",
        "status": "verified", "arms": list(ARMS), "rounds_per_arm": plan["rounds"],
        "execution_lock_sha256": sha(PAIR / "execution-lock.json"),
        "round24_receipt_sha256": sha(ROUND24_RECEIPT),
        "test_data_accessed": True, "completed_at": datetime.now(UTC).isoformat(),
    })
    print("ADAPTIVE UNTARGETED FOUR-ARM CAMPAIGN VERIFIED", flush=True)

def run_campaign():
    plan = read(PLAN)
    env, ns = environment(plan)
    guard_path = ARTIFACTS / (plan["experiment_id"] + ".process-lock")
    with guard_path.open("a") as guard:
        fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        execution = preflight(plan, env, ns)
        once(PROCESS, {
            "artifact_type": "m6_adaptive_untargeted_resume_process",
            "pid": os.getpid(), "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
            "script_sha256": sha(__file__), "plan_sha256": sha(PLAN),
            "static_lock_sha256": sha(LOCK),
            "execution_lock_sha256": sha(PAIR / "execution-lock.json"),
            "tpm_start_times": execution["tpm_start_times"], "log": str(LOG),
        })
        print("RESUME PREFLIGHT VERIFIED: preserving all completed rounds and TPM identities", flush=True)
        audit_runtime(plan, env, ns, execution)
        finish_round24(plan, execution, env)
        run_remaining(plan, execution, env)

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "run"))
    args = parser.parse_args()
    plan = read(PLAN)
    env, ns = environment(plan)
    if args.action == "preflight":
        result = preflight(plan, env, ns)
        print(json.dumps({
            "status": "resume_preflight_verified",
            "completed_rounds": 93,
            "partial_round": "gated_adaptive/24",
            "selected_query": 32,
            "next_round": 25,
            "tpm_count": len(result["tpm_start_times"]),
            "test_data_accessed": False,
        }, indent=2))
        return
    if LOG.exists():
        raise RuntimeError("Resume log exists; refusing overwrite")
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
    main()





