"""Read-only audit of the live smoke's signed experimental provenance."""
import json
from pathlib import Path
from datetime import datetime
from fl_forensics.canonical import sha256_file
from fl_forensics.crypto import load_public_key
from fl_forensics.secure_round import _load_context, _verify_signed
from fl_forensics.in_round_admission import verify_in_round_secure_round
from m6_adaptive_live_signing import verified_authorization
from m6_adaptive_live_search import execute_live
ROOT=Path(__file__).resolve().parents[1]
TAG="m6-adaptive-live-smoke-v2"
TRUST_TAG="m6-adaptive-live-smoke-v1"
def read(p):return json.loads(p.read_text())
def main():
    campaign=ROOT/"artifacts"/TAG;source=campaign/"rounds/round-001"
    trust=ROOT/"artifacts"/(TRUST_TAG+"-trust")
    validation=ROOT/"artifacts/m3-data24-parquet-iid-local-test-v1/server/splits/validation.json"
    context=_load_context(source/"public")
    key=load_public_key((source/"public/round-coordinator.public.pem").read_bytes())
    if not _verify_signed(context,key):raise ValueError("Invalid context")
    pre=verified_authorization(source/"adaptive-precommit.json",key)
    sel=verified_authorization(source/"adaptive-selection.json",key)
    if pre["artifact_type"]!="adaptive_live_precommit" or sel["artifact_type"]!="adaptive_live_selection":raise ValueError("Unexpected protocol")
    if pre["context_digest"]!=context.core_digest or sel["context_digest"]!=context.core_digest:raise ValueError("Context mismatch")
    if sel["precommit_sha256"]!=sha256_file(source/"adaptive-precommit.json"):raise ValueError("Precommit changed")
    if pre["validation_sha256"]!=sha256_file(validation):raise ValueError("Validation changed")
    for path,digest in pre["code"].items():
        if sha256_file(ROOT/path)!=digest:raise ValueError("Implementation changed: "+path)
    search=source/"adaptive-search";summary=read(search/"summary.json")
    if sel["search_receipt_sha256"]!=sha256_file(search/"summary.json") or sel["selected_query"]!=summary["selected_query"]:raise ValueError("Selection changed")
    selected=sel["selected_query"]
    for i in range(1,16):
        cid=f"client{i:02d}";proposal=source/"proposals"/cid;submission=source/"submissions"/cid
        if cid in json.loads(pre["config_json"])["attackers"]:
            binding=sel["clients"][cid]
            if binding["proposal_bundle_sha256"]!=sha256_file(proposal/"bundle.json"):raise ValueError("Proposal changed")
            if binding["candidate_sha256"]!=sha256_file(search/f"queries/{selected:03d}/{cid}.json"):raise ValueError("Candidate changed")
            if binding["candidate_sha256"]!=sha256_file(submission/"update.json"):raise ValueError("Signed tensor mismatch")
            provenance=read(submission/"metrics.json")["m6_adaptive_live"]
            if provenance["authorization_sha256"]!=sha256_file(source/"adaptive-selection.json"):raise ValueError("Signed authorization mismatch")
            for name in ["precommit_sha256","search_receipt_sha256"]:
                if provenance[name]!=sel[name]:raise ValueError("Signed provenance mismatch")
            if provenance["original_bundle_sha256"]!=sha256_file(proposal/"bundle.json"):raise ValueError("Signed proposal mismatch")
        else:
            for filename in ["bundle.json","update.json","metrics.json"]:
                if (proposal/filename).read_bytes()!=(submission/filename).read_bytes():raise ValueError("Honest proposal modified")
    result=verify_in_round_secure_round(workspace=source,trust_workspace=trust,submissions_root=source/"submissions",validation_split_path=validation)
    if result["status"]!="verified":raise ValueError(result)
    timestamp=datetime.fromisoformat(read(source/"adaptive-search-time.json")["evaluated_at"])
    if not datetime.fromisoformat(pre["created_at"])<=timestamp<=datetime.fromisoformat(sel["selected_at"]):raise ValueError("Search chronology mismatch")
    execute_live(search,True,source=source,trust=trust,validation=validation,cfg=json.loads(pre["config_json"]),evaluation_time=timestamp)
    if (source/"checkpoint/global-model.json").read_bytes()!=(search/f"queries/{selected:03d}/aggregate.json").read_bytes():raise ValueError("Aggregate differs")
    print(json.dumps({"status":"verified","signed_adaptive_clients":len(json.loads(pre["config_json"])["attackers"]),"rounds":1,"targeted_asr":summary["selected_targeted_asr"],"asr_gain":summary["selected_asr_gain"],"test_data_accessed":False}))
if __name__=="__main__":main()
