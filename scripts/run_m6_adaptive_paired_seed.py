"""Paired 30-round exploratory adaptive experiment; immutable evidence and fixed plan."""
import json
import os
import shutil
import subprocess
import sys
import platform
from importlib.metadata import version
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from fl_forensics.canonical import digest_object, sha256_file
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _coordinator_signer, _signature, _load_context
from fl_forensics.storage import write_json_once, write_once
from m6_adaptive_live_search import execute_live
from run_m5_secure_multiround import refresh_attestations
ROOT=Path(__file__).resolve().parents[1]
PLAN=ROOT/"configs/m6-adaptive-paired-s341593-v4.json"
IDS=[f"client{i:02d}" for i in range(1,16)]
def read(p):return json.loads(p.read_text())
def signed(path,core,signer):
    digest=digest_object(core)
    write_json_once(path,{"core":core,"core_digest":digest,"signature":_signature(signer,digest,"software-development").model_dump(mode="json")})
def attacked_round(*,source,cfg,signer,precommit,trust,partition,compose,run):
    context=_load_context(source/"public")
    evaluation_time=datetime.now(UTC)
    search=source/"adaptive-search";search.mkdir()
    write_json_once(source/"adaptive-search-time.json",{"evaluated_at":evaluation_time.isoformat()})
    summary=execute_live(search,False,source=source,trust=trust,validation=partition/"server/splits/validation.json",cfg=cfg,evaluation_time=evaluation_time)
    index=summary["selected_query"]
    attackers=cfg["attackers"] if index is not None else []
    auth=source/"adaptive-selection.json"
    signed(auth,{"artifact_type":"adaptive_live_selection","context_digest":context.core_digest,
        "selected_at":datetime.now(UTC).isoformat(),"precommit_sha256":sha256_file(precommit),
        "search_receipt_sha256":sha256_file(search/"summary.json"),"selected_query":index,
        "clients":{cid:{"proposal_bundle_sha256":sha256_file(source/"proposals"/cid/"bundle.json"),
            "candidate_sha256":sha256_file(search/f"queries/{index:03d}/{cid}.json")} for cid in attackers}},signer)
    (source/"submissions").mkdir(exist_ok=True)
    for cid in IDS:
        if cid not in attackers:
            shutil.copytree(source/"proposals"/cid,source/"submissions"/cid)
            continue
        staging=source/"signing-staging"/cid;staging.mkdir(parents=True)
        run([*compose,"--profile","secure-round","run","--rm","--entrypoint","python",
            "--volume",str(ROOT/"scripts/m6_numeric_runtime.py")+":/numeric.py:ro",
            "--volume",str(staging)+":/submission",
            "--volume",str(source/"proposals"/cid)+":/proposal:ro",
            "--volume",str(search/f"queries/{index:03d}/{cid}.json")+":/candidate.json:ro",
            "--volume",str(auth)+":/selection.json:ro",cid,
            "/numeric.py","script","/app/scripts/m6_adaptive_live_signing.py","--public","/campaign/public",
            "--proposal","/proposal","--candidate","/candidate.json","--authorization","/selection.json",
            "--node","/runtime","--output","/submission/final","--client-id",cid,
            "--tcti","swtpm:path=/run/swtpm/swtpm.sock"])
        (staging/"final").rename(source/"submissions"/cid)
    return index

def training_command(compose,proposal,cid):
    if cid not in IDS:raise ValueError("Unknown client")
    return [*compose,"--profile","secure-round","run","--rm","--entrypoint","python",
        "--volume",str(ROOT/"scripts/m6_numeric_runtime.py")+":/numeric.py:ro",
        "--volume",str(proposal)+":/submission",cid,"/numeric.py","module","fl_forensics.cli","m5-client-update",
        "--public-workspace","/campaign/public","--client-dataset","/client/dataset.json",
        "--client-manifest","/client/manifest.json","--node-workspace","/runtime",
        "--submission-workspace","/submission","--client-id",cid,"--tcti","swtpm:path=/run/swtpm/swtpm.sock"]

def main():
    global PLAN
    PLAN=ROOT/sys.argv[1]
    plan=read(PLAN)
    federation=ROOT/plan["federation_config"]
    import yaml
    fc=yaml.safe_load(federation.read_text())
    if fc["training"]["seed"]!=plan["seed"] or fc["partitioning"]["seed"]!=plan["seed"]:raise ValueError("Seed mismatch")
    if read(ROOT/plan["partition"]/"manifest.json")["seed"]!=plan["seed"]:raise ValueError("Partition seed mismatch")
    pair=ROOT/"artifacts"/plan["experiment_id"]
    if pair.exists():raise FileExistsError(f"Preserve existing experiment: {pair}")
    trust=ROOT/"artifacts"/(plan["trust_tag"]+"-trust")
    nodes=ROOT/"artifacts"/(plan["trust_tag"]+"-nodes")
    partition=ROOT/plan["partition"];validation=partition/"server/splits/validation.json"
    env=os.environ.copy();env.update(COMPOSE_PROJECT_NAME="flforensics_"+plan["trust_tag"].replace("-","_"),
        M4_TRUST_WORKSPACE=str(trust),M4_NODE_ROOT=str(nodes),M5_PARTITION_WORKSPACE=str(partition),
        M5_RUNTIME_IMAGE=plan["runtime_image"],M4_UID=str(os.getuid()),M4_GID=str(os.getgid()),
        M5_UID=str(os.getuid()),M5_GID=str(os.getgid()))
    env["PATH"]=str(ROOT/".venv/bin")+os.pathsep+env["PATH"]
    compose=["docker","compose","-f",str(ROOT/"compose.m5.yaml")]
    def run(args):
        args=list(map(str,args))
        if args[0]=="fl-forensics" and args[1].startswith("m5-"):
            args=[sys.executable,str(ROOT/"scripts/m6_numeric_runtime.py"),"module","fl_forensics.cli",*args[1:]]
        elif args[0]==sys.executable and args[1].endswith("verify_m6_adaptive_paired_v4.py"):
            args=[sys.executable,str(ROOT/"scripts/m6_numeric_runtime.py"),"script",*args[1:]]
        print(" ".join(map(str,args)),flush=True)
        subprocess.run(list(map(str,args)),cwd=ROOT,env=env,check=True)
    def image_check():
        actual=subprocess.check_output(["docker","image","inspect",plan["runtime_image"],"--format","{{.Id}}"],env=env,text=True).strip()
        if actual!=plan["runtime_image_id"]:raise ValueError("Runtime image changed")
    image_check()
    run(["fl-forensics","m3-verify-partitions","--workspace",partition,"--dataset-workspace",ROOT/"artifacts/m2-data24-parquet"])
    cfg=read(ROOT/"configs/m6-adaptive-frozen-pilot-v1.json")
    for field in ["bindings","source_workspace","trust_workspace","validation_split"]:cfg.pop(field)
    cfg.update(experiment_id=plan["experiment_id"],artifact_semantics="live signed adaptive round, privileged validation, paired exploratory campaign")
    if cfg["attackers"]!=plan["attackers"] or cfg["max_queries"]!=plan["queries_per_attack_round"]:raise ValueError("Attack settings differ")
    preflight=read(ROOT/plan["numerical_preflight"])
    if preflight["status"]!="verified" or preflight["independent_containers"]!=36 or preflight["runtime_image_id"]!=plan["runtime_image_id"]:
        raise ValueError("Numerical preflight incomplete or incompatible")
    for path,digest in preflight["code"].items():
        if sha256_file(ROOT/path)!=digest:raise ValueError("Numerical preflight code changed")
    def tpm_boots():
        values={}
        for i in range(1,16):
            name=env["COMPOSE_PROJECT_NAME"]+f"-tpm{i:02d}-1"
            state=json.loads(subprocess.check_output(["docker","inspect",name],text=True,env=env))[0]["State"]
            if not state["Running"]:raise ValueError("TPM is stopped; fresh provisioning required: "+name)
            values[name]=state["StartedAt"]
        return values
    initial_boots=tpm_boots()
    pair.mkdir()
    files=[PLAN,Path(__file__),ROOT/"scripts/m6_adaptive_live_search.py",ROOT/"scripts/m6_adaptive_live_signing.py",ROOT/"scripts/verify_m6_adaptive_paired_v4.py",
        federation,ROOT/"configs/m6-adaptive-multiseed-v1.lock.json",ROOT/"scripts/run_m6_adaptive_multiseed_v1.py",ROOT/"configs/in-round-admission.yaml",ROOT/"configs/secure-round.yaml",partition/"manifest.json",validation]
    files.extend([ROOT/"scripts/m6_numeric_runtime.py",ROOT/plan["numerical_preflight"]])
    files.extend(sorted((ROOT/"src/fl_forensics").glob("*.py")))
    lock={"files":{str(p.relative_to(ROOT)):sha256_file(p) for p in files},"runtime_image_id":plan["runtime_image_id"],
        "python":platform.python_version(),"packages":{n:version(n) for n in ["numpy","torch","flwr","scikit-learn"]},"plan":plan,"attack_config":cfg,"tpm_start_times":initial_boots}
    write_once(pair/"execution-lock.json",derived_json_bytes(lock))
    def lock_check():
        image_check()
        if tpm_boots()!=initial_boots:raise ValueError("A TPM restarted during the experiment")
        for name,digest in lock["files"].items():
            if sha256_file(ROOT/name)!=digest:raise ValueError("Locked input changed: "+name)
    # Existing nodes stay running; their boot identities are locked above.
    for arm in plan["arms"]:
        campaign=pair/arm;campaign.mkdir()
        env["M5_COORDINATOR_WORKSPACE"]=str(campaign)
        signer=_coordinator_signer(campaign,create=True)
        signed(campaign/"experiment-precommit.json",{"artifact_type":"adaptive_paired_campaign_precommit",
            "arm":arm,"execution_lock_sha256":sha256_file(pair/"execution-lock.json"),"created_at":datetime.now(UTC).isoformat()},signer)
    for number in range(1,plan["rounds"]+1):
        for arm in plan["arms"]:
            campaign=pair/arm
            env["M5_COORDINATOR_WORKSPACE"]=str(campaign)
            signer=_coordinator_signer(campaign,create=False)
            lock_check()
            source=campaign/"rounds"/f"round-{number:03d}"
            env["M5_WORKSPACE"]=str(source)
            refresh_attestations(root=ROOT,environment=env,trust_workspace=trust,node_root=nodes,compose_m4=ROOT/"compose.m4.yaml")
            args=["fl-forensics","m5-init","--workspace",source,"--coordinator-workspace",campaign,
                "--trust-workspace",trust,"--partition-manifest",partition/"manifest.json","--config",federation,
                "--secure-config","configs/secure-round.yaml","--round-number",str(number),
                "--in-round-admission-config","configs/in-round-admission.yaml"]
            if number>1:args += ["--campaign-id",_load_context(campaign/"rounds/round-001/public").core.campaign_id,
                "--previous-round-workspace",campaign/"rounds"/f"round-{number-1:03d}"]
            run(args)
            context=_load_context(source/"public")
            active=arm=="adaptive" and number in plan["attack_rounds"]
            precommit=source/"adaptive-precommit.json"
            signed(precommit,{"artifact_type":"adaptive_live_precommit","created_at":datetime.now(UTC).isoformat(),
                "context_digest":context.core_digest,"config_json":derived_json_bytes(cfg).decode(),
                "execution_lock_sha256":sha256_file(pair/"execution-lock.json"),"arm":arm,"attack_active":active,
                "numerical_runtime":plan["numerical_runtime"],
                "code":{str(p.relative_to(ROOT)):sha256_file(p) for p in files if p.suffix==".py"},
                "validation_sha256":sha256_file(validation),
                "attestation_scope":"existing M4 baseline; additional adaptive code bound by coordinator precommit"},signer)
            def train(cid):
                proposal=source/"proposals"/cid;proposal.mkdir(parents=True)
                run(training_command(compose,proposal,cid))
            with ThreadPoolExecutor(max_workers=plan["workers"]) as pool:list(pool.map(train,IDS))
            if active:
                index=attacked_round(source=source,cfg=cfg,signer=signer,precommit=precommit,trust=trust,partition=partition,compose=compose,run=run)
            else:
                (source/"submissions").mkdir(exist_ok=True)
                for cid in IDS:shutil.copytree(source/"proposals"/cid,source/"submissions"/cid)
            run(["fl-forensics","m5-admit-composite-aggregate","--workspace",source,"--coordinator-workspace",campaign,
                "--trust-workspace",trust,"--submissions",source/"submissions","--validation-split",validation])
            run([sys.executable,"scripts/verify_m6_adaptive_paired_v4.py","--pair",pair,"--arm",arm,"--round",str(number)])
            if arm=="adaptive" and number<min(plan["attack_rounds"]):
                reference=pair/"clean/rounds"/f"round-{number:03d}/checkpoint/global-model.json"
                if reference.read_bytes()!=(source/"checkpoint/global-model.json").read_bytes():raise ValueError("Pre-attack paired trajectories differ")
            print(f"VERIFIED {arm} round {number:02d}/{plan['rounds']} attack_active={active}",flush=True)
    for arm in plan["arms"]:
        write_json_once(pair/arm/"trajectory-complete.json",{"rounds":plan["rounds"],"test_data_accessed":False})
    # No test access until both locked trajectories have completed.
    for arm in plan["arms"]:
        lock_check();campaign=pair/arm
        run(["fl-forensics","m5-finalize-campaign","--workspace",campaign,"--trust-workspace",trust,
            "--partition-manifest",partition/"manifest.json","--server-evaluation",partition/"server/evaluation.json","--rounds",str(plan["rounds"])])
        run(["fl-forensics","m5-verify-campaign","--workspace",campaign,"--trust-workspace",trust,
            "--partition-manifest",partition/"manifest.json","--server-evaluation",partition/"server/evaluation.json"])
    write_json_once(pair/"complete.json",{"status":"verified","rounds_per_arm":plan["rounds"],"arms":plan["arms"],"execution_lock_sha256":sha256_file(pair/"execution-lock.json")})
    run(["docker","compose","-f","compose.m4.yaml","stop",*[f"tpm{i:02d}" for i in range(1,16)]])
    print("ADAPTIVE PAIRED CAMPAIGN VERIFIED",flush=True)
if __name__=="__main__":
    if os.environ.get("M6_NUMERIC_RUNTIME")!="single-thread-compatible-v1":
        os.execv(sys.executable,[sys.executable,str(ROOT/"scripts/m6_numeric_runtime.py"),"script",str(Path(__file__))])
    import torch
    if torch.get_num_threads()!=1 or torch.get_num_interop_threads()!=1:raise ValueError("Numerical runtime not configured")
    main()
