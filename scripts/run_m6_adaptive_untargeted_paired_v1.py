"""Fresh-only runner for the M6 untargeted adaptive four-arm campaign."""
import fcntl, json, os, platform, shutil, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _coordinator_signer, _load_context
from fl_forensics.storage import write_json_once, write_once
from m6_adaptive_untargeted_live_search import execute_live
from run_m5_secure_multiround import refresh_attestations
from run_m6_adaptive_paired_seed import IDS, signed, training_command

ROOT=Path(__file__).resolve().parents[1]
PLAN=ROOT/"configs/m6-adaptive-untargeted-paired-s342593-v1.json"
LOCK=ROOT/"configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json"
REF=ROOT/"configs/m6-adaptive-frozen-pilot-v1.json"
POLICY="configs/in-round-admission.yaml"
SECURE="configs/secure-round.yaml"

def read(p): return json.loads(p.read_text())
def sha(p): return sha256_file(p)

def configs(plan):
    base=read(REF)
    for key in ("bindings","source_workspace","trust_workspace","validation_split",
                "source_class","target_class","minimum_asr_gain"):
        base.pop(key,None)
    common={"experiment_id":plan["experiment_id"],
        "objective":"untargeted_all_class_validation_macro_f1_degradation",
        "artifact_semantics":"live signed adaptive search, validation-only oracle",
        "knowledge":"white-box per-round oracle over every update and exact validation; gate known; not a guaranteed upper bound",
        "selection":plan["selection"],"test_access":False,"attackers":plan["attackers"],
        "max_queries":plan["queries_per_attack_round"],"radii":plan["attack_radii"],
        "steps_per_radius":plan["steps_per_radius"],"initial_step":plan["initial_step"],
        "step_growth":plan["step_growth"],"step_shrink":plan["step_shrink"],
        "minimum_step":plan["minimum_step"],
        "minimum_validation_macro_f1_drop":plan["minimum_validation_macro_f1_drop"]}
    return {p:{**base,**common,"admission_policy":p}
            for p in ("gated_composite","tpm_only")}

def static_lock():
    lock=read(LOCK)
    if lock["plan_sha256"]!=sha(PLAN): raise ValueError("Frozen plan changed")
    for name,digest in lock["files"].items():
        if sha(ROOT/name)!=digest: raise ValueError("Frozen input changed: "+name)
    return lock

def preflight(plan,env):
    if plan["arms"]!=["gated_clean","gated_adaptive","tpm_clean","tpm_adaptive"]:
        raise ValueError("Arm order differs")
    pair=ROOT/"artifacts"/plan["experiment_id"]
    trust=ROOT/"artifacts"/(plan["trust_tag"]+"-trust")
    nodes=ROOT/"artifacts"/(plan["trust_tag"]+"-nodes")
    for p in (pair,trust,nodes):
        if p.exists(): raise FileExistsError("Fresh-only destination exists: "+str(p))
    ns=env["COMPOSE_PROJECT_NAME"]
    for kind,args in (("container",["-a"]),("volume",[]),("network",[])):
        out=subprocess.check_output(["docker",kind,"ls",*args,"-q","--filter",
            "label=com.docker.compose.project="+ns],text=True,env=env)
        if out.strip(): raise FileExistsError("Existing Docker namespace: "+ns)
    for image in (plan["runtime_image_id"],plan["m4_runtime_image_id"]):
        actual=subprocess.check_output(["docker","image","inspect",image,"--format","{{.Id}}"],text=True,env=env).strip()
        if actual!=image: raise ValueError("Locked image unavailable: "+image)
    partition=ROOT/plan["partition"]
    import yaml
    fc=yaml.safe_load((ROOT/plan["federation_config"]).read_text())
    if fc["training"]["seed"]!=plan["seed"] or fc["partitioning"]["seed"]!=plan["seed"]:
        raise ValueError("Federation seed mismatch")
    if read(partition/"manifest.json")["seed"]!=plan["seed"]:
        raise ValueError("Partition seed mismatch")
    subprocess.run([str(ROOT/".venv/bin/fl-forensics"),"m3-verify-partitions",
        "--workspace",str(partition),"--dataset-workspace",str(ROOT/plan["dataset_workspace"])],
        cwd=ROOT,env=env,check=True)
    pre=read(ROOT/plan["numerical_preflight"])
    if pre["status"]!="verified" or pre["independent_containers"]!=36 or pre["runtime_image_id"]!=plan["runtime_image_id"]:
        raise ValueError("Numerical preflight absent or incompatible")
    return pair,trust,nodes,partition

def tpm_boots(env):
    result={}
    for i in range(1,16):
        name=env["COMPOSE_PROJECT_NAME"]+f"-tpm{i:02d}-1"
        state=json.loads(subprocess.check_output(["docker","inspect",name],text=True,env=env))[0]["State"]
        if not state["Running"]: raise ValueError("TPM stopped: "+name)
        result[name]=state["StartedAt"]
    return result

def run(args,env):
    args=list(map(str,args))
    if args[0]=="fl-forensics" and args[1].startswith("m5-"):
        args=[sys.executable,str(ROOT/"scripts/m6_numeric_runtime.py"),"module","fl_forensics.cli",*args[1:]]
    elif args[0]==sys.executable and args[1].endswith("verify_m6_adaptive_untargeted_paired_v1.py"):
        args=[sys.executable,str(ROOT/"scripts/m6_numeric_runtime.py"),"script",*args[1:]]
    print(" ".join(args),flush=True)
    subprocess.run(args,cwd=ROOT,env=env,check=True)

def search_and_sign(source,cfg,signer,pre,trust,partition,compose,env):
    context=_load_context(source/"public")
    evaluated=datetime.now(UTC)
    search=source/"adaptive-search";search.mkdir()
    write_json_once(source/"adaptive-search-time.json",{"evaluated_at":evaluated.isoformat()})
    result=execute_live(search,False,source=source,trust=trust,
        validation=partition/"server/splits/validation.json",cfg=cfg,evaluation_time=evaluated)
    chosen=result["selected_query"]
    attacked=cfg["attackers"] if chosen is not None else []
    auth=source/"adaptive-selection.json"
    signed(auth,{"artifact_type":"adaptive_live_selection","context_digest":context.core_digest,
        "selected_at":datetime.now(UTC).isoformat(),"precommit_sha256":sha(pre),
        "search_receipt_sha256":sha(search/"summary.json"),"selected_query":chosen,
        "clients":{cid:{"proposal_bundle_sha256":sha(source/"proposals"/cid/"bundle.json"),
            "candidate_sha256":sha(search/"queries"/f"{chosen:03d}"/f"{cid}.json")}
            for cid in attacked}},signer)
    (source/"submissions").mkdir(exist_ok=True)
    for cid in IDS:
        if cid not in attacked:
            shutil.copytree(source/"proposals"/cid,source/"submissions"/cid);continue
        staging=source/"signing-staging"/cid;staging.mkdir(parents=True)
        run([*compose,"--profile","secure-round","run","--rm","--entrypoint","python",
            "--volume",str(ROOT/"scripts/m6_numeric_runtime.py")+":/numeric.py:ro",
            "--volume",str(staging)+":/submission",
            "--volume",str(source/"proposals"/cid)+":/proposal:ro",
            "--volume",str(search/"queries"/f"{chosen:03d}"/f"{cid}.json")+":/candidate.json:ro",
            "--volume",str(auth)+":/selection.json:ro",cid,"/numeric.py","script",
            "/app/scripts/m6_adaptive_live_signing.py","--public","/campaign/public",
            "--proposal","/proposal","--candidate","/candidate.json","--authorization","/selection.json",
            "--node","/runtime","--output","/submission/final","--client-id",cid,
            "--tcti","swtpm:path=/run/swtpm/swtpm.sock"],env)
        (staging/"final").rename(source/"submissions"/cid)
    return chosen

def execute(plan,pair,trust,nodes,partition,env):
    federation=ROOT/plan["federation_config"]
    validation=partition/"server/splits/validation.json"
    compose=["docker","compose","-f",str(ROOT/"compose.m5.yaml")]
    compose_m4=["docker","compose","-f",str(ROOT/"compose.m4.yaml")]
    lock=static_lock(); attack=configs(plan); boots=tpm_boots(env)
    pair.mkdir()
    write_once(pair/"execution-lock.json",derived_json_bytes({
        "schema_version":"1.0","artifact_type":"m6_adaptive_untargeted_execution_lock",
        "static_lock_sha256":sha(LOCK),"files":lock["files"],
        "runtime_image_id":plan["runtime_image_id"],"m4_runtime_image_id":plan["m4_runtime_image_id"],
        "python":platform.python_version(),"packages":{n:version(n) for n in ("numpy","torch","flwr","scikit-learn")},
        "plan":plan,"attack_configs":attack,"tpm_start_times":boots,
        "created_at":datetime.now(UTC).isoformat()}))
    def check():
        static_lock()
        if tpm_boots(env)!=boots: raise ValueError("TPM identity/restart changed; stop and preserve")
    for arm in plan["arms"]:
        env["M5_COORDINATOR_WORKSPACE"]=str(pair/arm)
        c=pair/arm;c.mkdir()
        signer=_coordinator_signer(c,create=True)
        signed(c/"experiment-precommit.json",{"artifact_type":"adaptive_paired_campaign_precommit",
            "arm":arm,"policy":plan["policy_by_arm"][arm],
            "execution_lock_sha256":sha(pair/"execution-lock.json"),
            "created_at":datetime.now(UTC).isoformat()},signer)
    attack=configs(plan)
    for number in range(1,plan["rounds"]+1):
        for arm in plan["arms"]:
            check()
            policy=plan["policy_by_arm"][arm];campaign=pair/arm
            env["M5_COORDINATOR_WORKSPACE"]=str(campaign)
            signer=_coordinator_signer(campaign,create=False)
            source=campaign/"rounds"/f"round-{number:03d}";env["M5_WORKSPACE"]=str(source)
            refresh_attestations(root=ROOT,environment=env,trust_workspace=trust,
                node_root=nodes,compose_m4=ROOT/"compose.m4.yaml")
            args=["fl-forensics","m5-init","--workspace",source,"--coordinator-workspace",campaign,
                "--trust-workspace",trust,"--partition-manifest",partition/"manifest.json",
                "--config",federation,"--secure-config",SECURE,"--round-number",str(number)]
            if policy=="gated_composite":args += ["--in-round-admission-config",POLICY]
            if number>1:
                first=_load_context(campaign/"rounds/round-001/public")
                args += ["--campaign-id",first.core.campaign_id,"--previous-round-workspace",
                    campaign/"rounds"/f"round-{number-1:03d}"]
            run(args,env);context=_load_context(source/"public")
            active=arm.endswith("_adaptive") and number in plan["attack_rounds"]
            pre=source/"adaptive-precommit.json";cfg=attack[policy]
            code={name:sha(ROOT/name) for name in (
                "scripts/m6_adaptive_untargeted_live_search.py",
                "scripts/m6_adaptive_live_signing.py",
                "scripts/verify_m6_adaptive_untargeted_paired_v1.py")}
            signed(pre,{"artifact_type":"adaptive_live_precommit","created_at":datetime.now(UTC).isoformat(),
                "context_digest":context.core_digest,"config_json":derived_json_bytes(cfg).decode(),
                "execution_lock_sha256":sha(pair/"execution-lock.json"),
                "arm":arm,"policy":policy,"attack_active":active,
                "numerical_runtime":plan["numerical_runtime"],"code":code,
                "validation_sha256":sha(validation),
                "attestation_scope":"M4 baseline unchanged; adaptive search, signer and policy bound by signed coordinator precommit"},signer)
            def train(cid):
                p=source/"proposals"/cid;p.mkdir(parents=True)
                run(training_command(compose,p,cid),env)
            with ThreadPoolExecutor(max_workers=plan["workers"]) as pool:list(pool.map(train,IDS))
            if active:search_and_sign(source,cfg,signer,pre,trust,partition,compose,env)
            else:
                (source/"submissions").mkdir(exist_ok=True)
                for cid in IDS:shutil.copytree(source/"proposals"/cid,source/"submissions"/cid)
            command="m5-admit-composite-aggregate" if policy=="gated_composite" else "m5-admit-aggregate"
            agg=["fl-forensics",command,"--workspace",source,"--coordinator-workspace",campaign,
                "--trust-workspace",trust,"--submissions",source/"submissions"]
            if policy=="gated_composite":agg += ["--validation-split",validation]
            run(agg,env)
            run([sys.executable,"scripts/verify_m6_adaptive_untargeted_paired_v1.py",
                "--pair",pair,"--arm",arm,"--round",str(number)],env)
            if arm.endswith("_adaptive") and number<min(plan["attack_rounds"]):
                clean="gated_clean" if policy=="gated_composite" else "tpm_clean"
                ref=pair/clean/"rounds"/f"round-{number:03d}/checkpoint/global-model.json"
                if ref.read_bytes()!=(source/"checkpoint/global-model.json").read_bytes():
                    raise ValueError(f"Pre-attack pairing mismatch: {policy} round {number}")
            print(f"VERIFIED {arm} round {number:02d}/{plan['rounds']} attack_active={active}",flush=True)
    for arm in plan["arms"]:
        write_json_once(pair/arm/"trajectory-complete.json",{"rounds":plan["rounds"],"test_data_accessed":False})
    for arm in plan["arms"]:
        check();campaign=pair/arm
        run(["fl-forensics","m5-finalize-campaign","--workspace",campaign,"--trust-workspace",trust,
            "--partition-manifest",partition/"manifest.json","--server-evaluation",partition/"server/evaluation.json",
            "--rounds",str(plan["rounds"])],env)
        run(["fl-forensics","m5-verify-campaign","--workspace",campaign,"--trust-workspace",trust,
            "--partition-manifest",partition/"manifest.json","--server-evaluation",partition/"server/evaluation.json"],env)
    write_json_once(pair/"complete.json",{"status":"verified","arms":plan["arms"],
        "rounds_per_arm":plan["rounds"],"execution_lock_sha256":sha(pair/"execution-lock.json"),
        "static_lock_sha256":sha(LOCK),"test_data_accessed":True})
    run([*compose_m4,"stop",*[f"tpm{i:02d}" for i in range(1,16)]],env)
    print("ADAPTIVE UNTARGETED FOUR-ARM CAMPAIGN VERIFIED",flush=True)

def main():
    import argparse
    p=argparse.ArgumentParser();p.add_argument("action",choices=("preflight","run"))
    a=p.parse_args();plan=read(PLAN);lock=static_lock()
    env=os.environ.copy();env["PATH"]=str(ROOT/".venv/bin")+os.pathsep+env["PATH"]
    ns="flforensics_"+plan["trust_tag"].replace("-","_")
    env.update(COMPOSE_PROJECT_NAME=ns,M4_TRUST_WORKSPACE=str(ROOT/"artifacts"/(plan["trust_tag"]+"-trust")),
        M4_NODE_ROOT=str(ROOT/"artifacts"/(plan["trust_tag"]+"-nodes")),
        M5_PARTITION_WORKSPACE=str(ROOT/plan["partition"]),M5_RUNTIME_IMAGE=plan["runtime_image"],
        M4_UID=str(os.getuid()),M4_GID=str(os.getgid()),M5_UID=str(os.getuid()),M5_GID=str(os.getgid()))
    pair,trust,nodes,partition=preflight(plan,env)
    print(json.dumps({"status":"preflight_verified" if a.action=="preflight" else "launching",
        "arms":plan["arms"],"rounds_per_arm":30,"total_rounds":120,
        "adaptive_queries_max":2640,"output":str(pair),"namespace":ns},indent=2),flush=True)
    if a.action=="preflight":return
    guard=ROOT/"artifacts"/(plan["experiment_id"]+".process-lock")
    with guard.open("a") as handle:
        fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        preflight(plan,env)
        image=plan["m4_runtime_image_id"]
        for service in ([f"client{i:02d}" for i in range(1,16)]
                        +[f"tpm{i:02d}" for i in range(1,16)]+["verifier"]):
            run(["docker","tag",image,ns+"-"+service+":latest"],env)
        run(["fl-forensics","m4-init","--workspace",trust,"--project-root",ROOT],env)
        run([sys.executable,"scripts/run_m4_swtpm.py","provision","--skip-build",
            "--trust-workspace",trust,"--node-root",nodes],env)
        run(["fl-forensics","m4-enroll","--workspace",trust,"--node-root",nodes],env)
        run(["fl-forensics","m4-mtls-test","--workspace",trust,"--node-root",nodes],env)
        if len(tpm_boots(env))!=15:raise ValueError("Expected 15 fresh TPMs")
        execute(plan,pair,trust,nodes,partition,env)

if __name__=="__main__":
    if os.environ.get("M6_NUMERIC_RUNTIME")!="single-thread-compatible-v1":
        os.execv(sys.executable,[sys.executable,str(ROOT/"scripts/m6_numeric_runtime.py"),
            "script",str(Path(__file__)),*sys.argv[1:]])
    import torch
    if torch.get_num_threads()!=1 or torch.get_num_interop_threads()!=1:
        raise ValueError("Numerical runtime not configured")
    main()
