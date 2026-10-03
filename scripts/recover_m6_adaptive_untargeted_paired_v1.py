"""Infrastructure-only recovery launcher; leaves the frozen M6 protocol intact."""
import fcntl, hashlib, ipaddress, json, os, subprocess, sys
from datetime import UTC, datetime
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import run_m6_adaptive_untargeted_paired_v1 as frozen
P=ROOT/"configs/m6-adaptive-untargeted-paired-s342593-v1.json"
L=ROOT/"configs/m6-adaptive-untargeted-paired-s342593-v1.lock.json"
R=ROOT/"configs/m6-adaptive-untargeted-paired-s342593-v1-recovery-v1.json"
PAIR=ROOT/"artifacts/m6-adaptive-untargeted-paired-s342593-v1"
TRUST=ROOT/"artifacts/m6-adaptive-untargeted-paired-s342593-v1-trust"
NODES=ROOT/"artifacts/m6-adaptive-untargeted-paired-s342593-v1-nodes"
LOG=ROOT/"m6-adaptive-untargeted-paired-v1.log"
PROC=ROOT/"artifacts/m6-adaptive-untargeted-paired-s342593-v1-recovery-process.json"
SETUP=ROOT/"artifacts/m6-adaptive-untargeted-paired-s342593-v1-recovery-receipt.json"
M4="sha256:36cbed2fcb4b2f6ce60e1eed2929037296939ec20be37f2383724ffe79450eb2"
M5="sha256:c5fdc9897569c01651e5af83be32f10bd63ff53d8a3288fe2391544a7cc9e1f0"

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p): return json.loads(Path(p).read_text())
def once(p,obj):
    data=json.dumps(obj,sort_keys=True,indent=2).encode()+b"\n"
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o440)
    with os.fdopen(fd,"wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
def run(args,env,capture=False):
    args=list(map(str,args)); print("+"," ".join(args),flush=True)
    r=subprocess.run(args,cwd=ROOT,env=env,text=True,capture_output=capture,check=True)
    if capture:
        print(r.stdout,end="",flush=True)
        if r.stderr: print(r.stderr,file=sys.stderr,end="",flush=True)
    return r
def boots(env,ns):
    ids=subprocess.check_output(["docker","ps","-aq","--filter","label=com.docker.compose.project="+ns],text=True,env=env).split()
    expected={f"/{ns}-tpm{i:02d}-1" for i in range(1,16)}; got=set(); times={}
    for cid in ids:
        d=json.loads(subprocess.check_output(["docker","inspect",cid],text=True,env=env))[0]
        s=d["State"]; got.add(d["Name"])
        if not s["Running"] or s.get("Health",{}).get("Status")!="healthy" or d["Image"]!=M4:
            raise RuntimeError("TPM stopped, unhealthy, or image mismatch: "+d["Name"])
        times[d["Name"]]=s["StartedAt"]
    if got!=expected: raise RuntimeError("Unexpected namespace containers: "+repr(sorted(got)))
    return times
def preflight(plan,rec,env,ns):
    frozen.static_lock()
    if sha(P)!=rec["plan_sha256"] or sha(L)!=rec["static_lock_sha256"]:
        raise RuntimeError("Recovery parameters no longer match the frozen inputs")
    if PAIR.exists() or PROC.exists() or SETUP.exists(): raise FileExistsError("Recovery/campaign artifact exists")
    if not LOG.is_file(): raise FileNotFoundError("Original failed log missing")
    if read(TRUST/"registry/index.json").get("enrollments")!={}: raise RuntimeError("Enrollments already exist")
    if any(x.is_file() for x in NODES.rglob("*")): raise RuntimeError("Node artifacts exist; preserve and investigate")
    bt=boots(env,ns)
    net=rec["network_name"]
    if subprocess.run(["docker","network","inspect",net],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
        raise FileExistsError("Recovery network already exists")
    subnet=ipaddress.ip_network(rec["network_subnet"])
    ids=subprocess.check_output(["docker","network","ls","-q"],text=True,env=env).split()
    for nid in ids:
        d=json.loads(subprocess.check_output(["docker","network","inspect",nid],text=True,env=env))[0]
        for c in d.get("IPAM",{}).get("Config") or []:
            if subnet.overlaps(ipaddress.ip_network(c["Subnet"],strict=False)): raise RuntimeError("Docker subnet overlap")
    for rt in json.loads(subprocess.check_output(["ip","-j","route"],text=True,env=env)):
        dst=rt.get("dst")
        if dst and dst!="default" and subnet.overlaps(ipaddress.ip_network(dst,strict=False)): raise RuntimeError("WSL route overlap")
    import yaml
    partition=ROOT/plan["partition"]
    fc=yaml.safe_load((ROOT/plan["federation_config"]).read_text())
    if fc["training"]["seed"]!=plan["seed"] or fc["partitioning"]["seed"]!=plan["seed"] or read(partition/"manifest.json")["seed"]!=plan["seed"]:
        raise RuntimeError("Seed mismatch")
    nf=read(ROOT/plan["numerical_preflight"])
    if nf["status"]!="verified" or nf["independent_containers"]!=36 or nf["runtime_image_id"]!=plan["runtime_image_id"]:
        raise RuntimeError("Numerical preflight incompatible")
    for image in (M4,M5):
        if subprocess.check_output(["docker","image","inspect",image,"--format","{{.Id}}"],text=True,env=env).strip()!=image:
            raise RuntimeError("Locked image missing: "+image)
    run([ROOT/".venv/bin/fl-forensics","m3-verify-partitions","--workspace",partition,
         "--dataset-workspace",ROOT/plan["dataset_workspace"]],env,True)
    return partition,bt
def main():
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument("action",choices=["preflight","run"]); a=ap.parse_args()
    os.chdir(ROOT); plan=read(P); rec=read(R); env=os.environ.copy()
    env["PATH"]=str(ROOT/".venv/bin")+os.pathsep+env["PATH"]
    ns="flforensics_"+plan["trust_tag"].replace("-","_")
    env.update(COMPOSE_PROJECT_NAME=ns,M4_TRUST_WORKSPACE=str(TRUST),M4_NODE_ROOT=str(NODES),
       M5_PARTITION_WORKSPACE=str(ROOT/plan["partition"]),M5_RUNTIME_IMAGE=plan["runtime_image"],
       M4_UID=str(os.getuid()),M4_GID=str(os.getgid()),M5_UID=str(os.getuid()),M5_GID=str(os.getgid()))
    if rec["experiment_id"]!=plan["experiment_id"] or rec["network_internal"] is not True: raise RuntimeError("Recovery spec mismatch")
    part,bt=preflight(plan,rec,env,ns)
    if a.action=="preflight":
        print(json.dumps({"status":"recovery_preflight_verified","tpm_count":len(bt),"network":rec["network_name"],"subnet":rec["network_subnet"],"training_started":False},indent=2)); return
    with (ROOT/"artifacts"/(plan["experiment_id"]+".process-lock")).open("a") as guard:
        fcntl.flock(guard.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        part,bt=preflight(plan,rec,env,ns)
        once(PROC,{"artifact_type":"m6_adaptive_untargeted_recovery_process","pid":os.getpid(),"started_at":datetime.now(UTC).isoformat(),"status":"running","recovery_script_sha256":sha(__file__),"recovery_spec_sha256":sha(R),"static_lock_sha256":sha(L),"original_failure_log_sha256":sha(LOG),"tpm_start_times":bt})
        labels=["--label","com.docker.compose.project="+ns,"--label","com.docker.compose.network=trust","--label","com.docker.compose.version=5.5.1","--label","m6.recovery.static-lock-sha256="+sha(L)]
        run(["docker","network","create","--driver","bridge","--internal","--subnet",rec["network_subnet"],*labels,rec["network_name"]],env,True)
        comp=["docker","compose","-f",ROOT/"compose.m4.yaml"]
        for i in range(1,16):
            run([*comp,"--profile","provision","run","--no-deps","--rm",f"client{i:02d}"],env)
            if boots(env,ns)!=bt: raise RuntimeError("TPM restarted during provisioning")
        if len(list(NODES.glob("client*/enrollment_request.json")))!=15: raise RuntimeError("15 enrollment requests not created")
        er=run(["fl-forensics","m4-enroll","--workspace",TRUST,"--node-root",NODES],env,True)
        enrollment=json.loads(er.stdout)
        if enrollment.get("status")!="enrolled" or enrollment.get("error_count",0): raise RuntimeError("Enrollment check failed")
        mr=run(["fl-forensics","m4-mtls-test","--workspace",TRUST,"--node-root",NODES],env,True)
        mtls=json.loads(mr.stdout)
        if mtls.get("status")!="verified" or mtls.get("error_count",0): raise RuntimeError("mTLS check failed")
        if boots(env,ns)!=bt: raise RuntimeError("TPM restarted during M4 checks")
        network=json.loads(subprocess.check_output(["docker","network","inspect",rec["network_name"]],text=True,env=env))[0]
        once(SETUP,{"artifact_type":"m6_adaptive_untargeted_recovery_setup","created_at":datetime.now(UTC).isoformat(),
          "original_failure_log_sha256":sha(LOG),"recovery_spec_sha256":sha(R),"recovery_script_sha256":sha(__file__),
          "static_lock_sha256":sha(L),"plan_sha256":sha(P),"network":{"name":network["Name"],"id":network["Id"],"subnet":rec["network_subnet"],"internal":network["Internal"]},
          "m4_enrollment":{"status":enrollment["status"],"error_count":enrollment.get("error_count",0)},
          "m4_mtls":{"status":mtls["status"],"error_count":mtls.get("error_count",0)},"tpm_start_times":bt})
        print("M4_RECOVERY_SETUP_VERIFIED",flush=True)
        frozen.execute(plan,PAIR,TRUST,NODES,part,env)
if __name__=="__main__":
    if os.environ.get("M6_NUMERIC_RUNTIME")!="single-thread-compatible-v1":
        os.execv(sys.executable,[sys.executable,str(ROOT/"scripts/m6_numeric_runtime.py"),"script",str(Path(__file__)),*sys.argv[1:]])
    main()
