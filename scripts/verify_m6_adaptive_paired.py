"""Independent read-only verification of each paired adaptive round."""
import argparse
import json
from datetime import datetime
from pathlib import Path
from fl_forensics.canonical import sha256_file
from fl_forensics.crypto import load_public_key
from fl_forensics.secure_round import _load_context, _verify_signed
from fl_forensics.in_round_admission import verify_in_round_secure_round
from m6_adaptive_live_signing import verified_authorization
from m6_adaptive_live_search import execute_live
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads(p.read_text())
def check_equal(actual,expected,message):
    if actual!=expected:raise ValueError(message)
def verify(pair,arm,number):
    lock=read(pair/"execution-lock.json");plan=lock["plan"]
    if arm not in plan["arms"] or not 1<=number<=plan["rounds"]:raise ValueError("Round outside protocol")
    for path,digest in lock["files"].items():check_equal(sha256_file(ROOT/path),digest,"Locked input changed: "+path)
    campaign=pair/arm;source=campaign/"rounds"/f"round-{number:03d}"
    trust=ROOT/"artifacts"/(plan["trust_tag"]+"-trust");validation=ROOT/plan["partition"]/"server/splits/validation.json"
    context=_load_context(source/"public")
    key=load_public_key((source/"public/round-coordinator.public.pem").read_bytes())
    if not _verify_signed(context,key):raise ValueError("Invalid context")
    campaign_pre=verified_authorization(campaign/"experiment-precommit.json",key)
    check_equal(campaign_pre["arm"],arm,"Campaign arm mismatch")
    check_equal(campaign_pre["execution_lock_sha256"],sha256_file(pair/"execution-lock.json"),"Campaign lock changed")
    pre=verified_authorization(source/"adaptive-precommit.json",key)
    active=arm=="adaptive" and number in plan["attack_rounds"]
    check_equal(pre["artifact_type"],"adaptive_live_precommit","Wrong precommit type")
    check_equal(pre["context_digest"],context.core_digest,"Wrong context")
    check_equal(pre["execution_lock_sha256"],sha256_file(pair/"execution-lock.json"),"Round lock changed")
    check_equal(pre["arm"],arm,"Round arm changed");check_equal(pre["attack_active"],active,"Treatment changed")
    cfg=json.loads(pre["config_json"]);check_equal(cfg,lock["attack_config"],"Attack configuration changed")
    check_equal(pre["validation_sha256"],sha256_file(validation),"Validation changed")
    for path,digest in pre["code"].items():check_equal(sha256_file(ROOT/path),digest,"Round implementation changed")
    selected=None;attackers=[]
    if active:
        sel=verified_authorization(source/"adaptive-selection.json",key)
        check_equal(sel["artifact_type"],"adaptive_live_selection","Wrong selection type")
        check_equal(sel["context_digest"],context.core_digest,"Selection context changed")
        check_equal(sel["precommit_sha256"],sha256_file(source/"adaptive-precommit.json"),"Precommit changed")
        search=source/"adaptive-search";summary=read(search/"summary.json")
        check_equal(sel["search_receipt_sha256"],sha256_file(search/"summary.json"),"Search receipt changed")
        selected=summary["selected_query"];check_equal(sel["selected_query"],selected,"Selection changed")
        attackers=cfg["attackers"] if selected is not None else []
        check_equal(set(sel["clients"]),set(attackers),"Selected client set changed")
    elif (source/"adaptive-selection.json").exists() or (source/"adaptive-search").exists():raise ValueError("Unexpected adaptive treatment")
    for i in range(1,16):
        cid=f"client{i:02d}";proposal=source/"proposals"/cid;submission=source/"submissions"/cid
        generated=datetime.fromisoformat(read(proposal/"bundle.json")["core"]["generated_at"].replace("Z","+00:00"))
        if generated<datetime.fromisoformat(pre["created_at"]):raise ValueError("Proposal predates precommit")
        if cid in attackers:
            binding=sel["clients"][cid]
            check_equal(binding["proposal_bundle_sha256"],sha256_file(proposal/"bundle.json"),"Proposal changed")
            check_equal(binding["candidate_sha256"],sha256_file(search/f"queries/{selected:03d}/{cid}.json"),"Candidate changed")
            check_equal(binding["candidate_sha256"],sha256_file(submission/"update.json"),"Signed candidate differs")
            provenance=read(submission/"metrics.json")["m6_adaptive_live"]
            check_equal(provenance["authorization_sha256"],sha256_file(source/"adaptive-selection.json"),"Authorization changed")
            for name in ["precommit_sha256","search_receipt_sha256"]:check_equal(provenance[name],sel[name],"Signed provenance changed")
            check_equal(provenance["original_bundle_sha256"],sha256_file(proposal/"bundle.json"),"Signed source changed")
        else:
            for filename in ["bundle.json","update.json","metrics.json"]:check_equal((proposal/filename).read_bytes(),(submission/filename).read_bytes(),"Untreated proposal changed")
    result=verify_in_round_secure_round(workspace=source,trust_workspace=trust,submissions_root=source/"submissions",validation_split_path=validation)
    check_equal(result["status"],"verified","Round verification failed")
    if active:
        timestamp=datetime.fromisoformat(read(source/"adaptive-search-time.json")["evaluated_at"])
        if not datetime.fromisoformat(pre["created_at"])<=timestamp<=datetime.fromisoformat(sel["selected_at"]):raise ValueError("Search chronology changed")
        execute_live(search,True,source=source,trust=trust,validation=validation,cfg=cfg,evaluation_time=timestamp)
        query=selected if selected is not None else 0
        check_equal((source/"checkpoint/global-model.json").read_bytes(),(search/f"queries/{query:03d}/aggregate.json").read_bytes(),"Actual aggregate differs from prediction")
    if arm=="adaptive" and number<min(plan["attack_rounds"]):
        check_equal((source/"checkpoint/global-model.json").read_bytes(),(pair/"clean/rounds"/f"round-{number:03d}/checkpoint/global-model.json").read_bytes(),"Pre-attack paired trajectories differ")
    print(json.dumps({"status":"verified","arm":arm,"round":number,"attack_active":active,"signed_adaptive_clients":len(attackers),"test_data_accessed":False}),flush=True)
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--pair",type=Path,required=True);parser.add_argument("--arm",required=True);parser.add_argument("--round",type=int,required=True)
    args=parser.parse_args();verify(args.pair.resolve(),args.arm,args.round)
if __name__=="__main__":main()
