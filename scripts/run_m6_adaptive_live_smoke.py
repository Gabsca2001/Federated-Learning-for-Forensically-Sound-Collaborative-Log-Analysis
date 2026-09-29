"""Fresh one-round end-to-end adaptive smoke; never reuse completed evidence."""
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from fl_forensics.canonical import digest_object, sha256_file
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _coordinator_signer, _signature, _load_context
from fl_forensics.storage import write_json_once
from m6_adaptive_live_search import execute_live
from run_m5_secure_multiround import refresh_attestations
ROOT=Path(__file__).resolve().parents[1]
TAG="m6-adaptive-live-smoke-v1"
IDS=[f"client{i:02d}" for i in range(1,16)]

def main():
    campaign=ROOT/"artifacts"/TAG
    trust=ROOT/"artifacts"/(TAG+"-trust");nodes=ROOT/"artifacts"/(TAG+"-nodes")
    source=campaign/"rounds/round-001"
    partition=ROOT/"artifacts/m3-data24-parquet-iid-local-test-v1"
    for p in [campaign,trust,nodes]:
        if p.exists():raise FileExistsError(f"Preserve existing evidence: {p}")
    env=os.environ.copy();env.update(COMPOSE_PROJECT_NAME="flforensics_"+TAG.replace("-","_"),
        M4_TRUST_WORKSPACE=str(trust),M4_NODE_ROOT=str(nodes),M5_WORKSPACE=str(source),
        M5_COORDINATOR_WORKSPACE=str(campaign),M5_PARTITION_WORKSPACE=str(partition),
        M5_RUNTIME_IMAGE="flforensics-m6-adaptive-live-v1:latest",
        M4_UID=str(os.getuid()),M4_GID=str(os.getgid()),M5_UID=str(os.getuid()),M5_GID=str(os.getgid()))
    env["PATH"]=str(ROOT/".venv/bin")+os.pathsep+env["PATH"]
    compose=["docker","compose","-f",str(ROOT/"compose.m5.yaml")]
    def run(args):
        print(" ".join(map(str,args)),flush=True)
        subprocess.run(list(map(str,args)),cwd=ROOT,env=env,check=True)
    def signed(path,core,signer):
        digest=digest_object(core)
        write_json_once(path,{"core":core,"core_digest":digest,"signature":_signature(signer,digest,"software-development").model_dump(mode="json")})
    for kind in ["container","volume"]:
        existing=subprocess.check_output(["docker",kind,"ls",*(["-a"] if kind=="container" else []),"-q","--filter","label=com.docker.compose.project="+env["COMPOSE_PROJECT_NAME"]],env=env,text=True)
        if existing.strip():raise ValueError("Docker experiment namespace already exists")
    # Resolve/build before starting clocks or creating signed experiment evidence.
    run([*compose,"--profile","coordinator","build","coordinator"])
    run(["fl-forensics","m4-init","--workspace",trust,"--project-root",ROOT])
    run([sys.executable,"scripts/run_m4_swtpm.py","provision","--trust-workspace",trust,"--node-root",nodes])
    run(["fl-forensics","m4-enroll","--workspace",trust,"--node-root",nodes])
    run(["fl-forensics","m4-mtls-test","--workspace",trust,"--node-root",nodes])
    run(["docker","compose","-f","compose.m4.yaml","--profile","verify","build","verifier"])
    refresh_attestations(root=ROOT,environment=env,trust_workspace=trust,node_root=nodes,compose_m4=ROOT/"compose.m4.yaml")
    run(["fl-forensics","m5-init","--workspace",source,"--coordinator-workspace",campaign,
         "--trust-workspace",trust,"--partition-manifest",partition/"manifest.json",
         "--config","configs/federation.yaml","--secure-config","configs/secure-round.yaml",
         "--round-number","1","--in-round-admission-config","configs/in-round-admission.yaml"])
    context=_load_context(source/"public")
    cfg=json.loads((ROOT/"configs/m6-adaptive-frozen-pilot-v1.json").read_text())
    for field in ["bindings","source_workspace","trust_workspace","validation_split"]:cfg.pop(field)
    cfg.update(experiment_id=TAG,artifact_semantics="one-round live smoke; separately signed adaptive submissions; validation only")
    signer=_coordinator_signer(source,create=False,coordinator_workspace=campaign)
    precommit=source/"adaptive-precommit.json"
    codepaths=[Path(__file__),ROOT/"scripts/m6_adaptive_live_search.py",ROOT/"scripts/m6_adaptive_live_signing.py"]
    signed(precommit,{"artifact_type":"adaptive_live_precommit","created_at":datetime.now(UTC).isoformat(),
        "context_digest":context.core_digest,"config_json":derived_json_bytes(cfg).decode("utf-8"),"code":{str(p.relative_to(ROOT)):sha256_file(p) for p in codepaths},
        "validation_sha256":sha256_file(partition/"server/splits/validation.json"),
        "attestation_scope":"existing M4 core baseline; additional adaptive scripts bound by coordinator precommit, not added to PCR baseline"},signer)
    def train(cid):
        proposal=source/"proposals"/cid;proposal.mkdir(parents=True)
        run([*compose,"--profile","secure-round","run","--rm","--volume",str(proposal)+":/submission",cid])
    with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(train,IDS))
    evaluation_time=datetime.now(UTC)
    search=source/"adaptive-search";search.mkdir()
    write_json_once(source/"adaptive-search-time.json",{"evaluated_at":evaluation_time.isoformat()})
    summary=execute_live(search,False,source=source,trust=trust,validation=partition/"server/splits/validation.json",cfg=cfg,evaluation_time=evaluation_time)
    index=summary["selected_query"]
    if index is None:raise ValueError("No feasible adaptive candidate; preserve search and stop")
    auth=source/"adaptive-selection.json"
    signed(auth,{"artifact_type":"adaptive_live_selection","context_digest":context.core_digest,
        "selected_at":datetime.now(UTC).isoformat(),"precommit_sha256":sha256_file(precommit),
        "search_receipt_sha256":sha256_file(search/"summary.json"),"selected_query":index,
        "clients":{cid:{"proposal_bundle_sha256":sha256_file(source/"proposals"/cid/"bundle.json"),
            "candidate_sha256":sha256_file(search/f"queries/{index:03d}/{cid}.json")} for cid in cfg["attackers"]}},signer)
    (source/"submissions").mkdir(exist_ok=True)
    for cid in IDS:
        if cid not in cfg["attackers"]:
            shutil.copytree(source/"proposals"/cid,source/"submissions"/cid)
            continue
        staging=source/"signing-staging"/cid;staging.mkdir(parents=True)
        run([*compose,"--profile","secure-round","run","--rm","--entrypoint","python",
            "--volume",str(staging)+":/submission",
            "--volume",str(source/"proposals"/cid)+":/proposal:ro",
            "--volume",str(search/f"queries/{index:03d}/{cid}.json")+":/candidate.json:ro",
            "--volume",str(auth)+":/selection.json:ro",cid,
            "/app/scripts/m6_adaptive_live_signing.py","--public","/campaign/public",
            "--proposal","/proposal","--candidate","/candidate.json","--authorization","/selection.json",
            "--node","/runtime","--output","/submission/final","--client-id",cid,
            "--tcti","swtpm:path=/run/swtpm/swtpm.sock"])
        (staging/"final").rename(source/"submissions"/cid)
    run(["fl-forensics","m5-admit-composite-aggregate","--workspace",source,"--coordinator-workspace",campaign,
        "--trust-workspace",trust,"--submissions",source/"submissions","--validation-split",partition/"server/splits/validation.json"])
    run(["fl-forensics","m5-verify-composite-round","--workspace",source,"--trust-workspace",trust,
        "--submissions",source/"submissions","--validation-split",partition/"server/splits/validation.json"])
    execute_live(search,True,source=source,trust=trust,validation=partition/"server/splits/validation.json",cfg=cfg,evaluation_time=evaluation_time)
    if (source/"checkpoint/global-model.json").read_bytes()!=(search/f"queries/{index:03d}/aggregate.json").read_bytes():
        raise ValueError("Actual signed aggregate differs from optimizer prediction")
    write_json_once(campaign/"adaptive-smoke-complete.json",{"status":"verified","round_count":1,
        "selection_sha256":sha256_file(auth),"checkpoint_sha256":sha256_file(source/"checkpoint/manifest.json"),
        "test_data_accessed":False,"scope":"one-round integration smoke; not a 30-round research result"})
    run(["docker","compose","-f","compose.m4.yaml","stop",*[f"tpm{i:02d}" for i in range(1,16)]])
    print("ADAPTIVE LIVE SMOKE VERIFIED",flush=True)
if __name__=="__main__":main()
