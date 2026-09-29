"""Separate final signing stage for controlled adaptive live experiments.

Original proposals are immutable and never used as final adaptive signatures.
The coordinator signs an explicit selection authorization; the client signs new
update and metrics digests with its own ESK. This helper alone is not a campaign.
"""
import argparse
import copy
import json
from datetime import UTC, datetime
from pathlib import Path
import numpy as np
from fl_forensics.canonical import digest_object, sha256_bytes, sha256_file
from fl_forensics.crypto import load_public_key, public_key_id, verify_digest_signature
from fl_forensics.federated_model import arrays_from_export, delta_l2
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import (_load_context, _parse_time, _verify_signed,
    _tensor_validation, _signature, _utc)
from fl_forensics.secure_round_models import UpdateBundle, tensor_schema
from fl_forensics.storage import load_json, write_once, write_json_once
from fl_forensics.tpm_adapter import ESK_HANDLE, TPM2ToolsSigner

def verified_authorization(path, public_key):
    value=load_json(path)
    digest=digest_object(value["core"])
    if (value.get("core_digest")!=digest or
        value["signature"]["key_id"]!=public_key_id(public_key) or
        not verify_digest_signature(public_key,digest,value["signature"]["value_b64"])):
        raise ValueError("Invalid coordinator authorization signature")
    return value["core"]

def prepare(*, public, proposal, candidate, authorization, node, client_id, now):
    context=_load_context(public)
    coordinator_key=load_public_key((public/"round-coordinator.public.pem").read_bytes())
    if not _verify_signed(context,coordinator_key):
        raise ValueError("Invalid round context signature")
    if not _parse_time(context.core.issued_at)<=now<_parse_time(context.core.expires_at):
        raise ValueError("Round context expired or not yet valid")
    selection=verified_authorization(authorization,coordinator_key)
    if selection.get("artifact_type")!="adaptive_live_selection" or selection.get("context_digest")!=context.core_digest:
        raise ValueError("Selection belongs to another protocol or round")
    if not _parse_time(context.core.issued_at)<=_parse_time(selection["selected_at"])<=now:
        raise ValueError("Invalid selection time")
    bundle=UpdateBundle.model_validate(load_json(proposal/"bundle.json"))
    key=load_public_key((node/"tpm-objects/esk.public.pem").read_bytes())
    if not _verify_signed(bundle,key) or bundle.core.client_id!=client_id or bundle.core.context_digest!=context.core_digest:
        raise ValueError("Invalid original proposal signature or identity")
    if (sha256_file(proposal/"update.json")!=bundle.core.update_sha256 or
        sha256_file(proposal/"metrics.json")!=bundle.core.metrics_sha256):
        raise ValueError("Original proposal bytes changed")
    binding=selection["clients"].get(client_id)
    if binding is None or binding["proposal_bundle_sha256"]!=sha256_file(proposal/"bundle.json") or binding["candidate_sha256"]!=sha256_file(candidate):
        raise ValueError("Candidate or proposal not authorized for this client")
    if not selection.get("precommit_sha256") or not selection.get("search_receipt_sha256"):
        raise ValueError("Missing experiment provenance")
    base=load_json(public/"base-model.json")
    if sha256_file(public/"base-model.json")!=context.core.base_model_sha256:
        raise ValueError("Base model changed")
    update=load_json(candidate)
    valid,detail=_tensor_validation(update,base)
    if not valid:raise ValueError(detail)
    metrics=copy.deepcopy(load_json(proposal/"metrics.json"))
    metrics["update_delta_l2"]=delta_l2(arrays_from_export(base,np=np),arrays_from_export(update,np=np),np=np)
    metrics["m6_adaptive_live"]={"authorization_sha256":sha256_file(authorization),
        "precommit_sha256":selection["precommit_sha256"],
        "search_receipt_sha256":selection["search_receipt_sha256"],
        "original_bundle_sha256":sha256_file(proposal/"bundle.json"),
        "original_update_sha256":bundle.core.update_sha256,
        "training_metrics_semantics":"original local training; tensors subsequently modified by declared adaptive treatment"}
    # Preserve authorized candidate bytes exactly, rather than reserializing them.
    update_bytes=candidate.read_bytes();metrics_bytes=derived_json_bytes(metrics)
    core=bundle.core.model_copy(update={"update_sha256":sha256_bytes(update_bytes),
        "metrics_sha256":sha256_bytes(metrics_bytes),"tensor_schema_sha256":digest_object(tensor_schema(update)),
        "generated_at":_utc(now)})
    return core,update_bytes,metrics_bytes

def sign_submission(*,public,proposal,candidate,authorization,node,output,client_id,tcti):
    now=datetime.now(UTC)
    core,update_bytes,metrics_bytes=prepare(public=public,proposal=proposal,candidate=candidate,
        authorization=authorization,node=node,client_id=client_id,now=now)
    if output.exists():raise FileExistsError("Final submission must be a new directory")
    signer=TPM2ToolsSigner(key_context=ESK_HANDLE,public_key_pem=(node/"tpm-objects/esk.public.pem").read_bytes(),tcti=tcti)
    digest=digest_object(core.model_dump(mode="json"))
    bundle=UpdateBundle(bundle_id=f"update-bundle-{digest[:24]}",core=core,core_digest=digest,
        signature=_signature(signer,digest,str(load_json(node/"provisioning_summary.json")["trust_level"])))
    output.mkdir(parents=True,exist_ok=False)
    write_once(output/"update.json",update_bytes);write_once(output/"metrics.json",metrics_bytes)
    write_json_once(output/"bundle.json",bundle.model_dump(mode="json"))
    return {"status":"signed_adaptive_submission","client_id":client_id,"bundle_id":bundle.bundle_id}

def main():
    parser=argparse.ArgumentParser()
    for name in ["public","proposal","candidate","authorization","node","output"]:parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--client-id",required=True);parser.add_argument("--tcti",required=True)
    print(json.dumps(sign_submission(**vars(parser.parse_args())),indent=2))
if __name__=="__main__":main()
