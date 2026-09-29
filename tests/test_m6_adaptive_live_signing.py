import importlib.util
import json
from pathlib import Path
import pytest
from fl_forensics.canonical import digest_object
from fl_forensics.crypto import SoftwareECDSASigner, load_public_key
from fl_forensics.secure_round import _signature

spec=importlib.util.spec_from_file_location("live_signing",Path(__file__).resolve().parents[1]/"scripts/m6_adaptive_live_signing.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def authorization(tmp_path):
    signer=SoftwareECDSASigner.generate()
    core={"artifact_type":"adaptive_live_selection","context_digest":"a"*64,
          "clients":{"client02":{"candidate_sha256":"b"*64}}}
    digest=digest_object(core)
    value={"core":core,"core_digest":digest,"signature":_signature(signer,digest,"software-development").model_dump(mode="json")}
    path=tmp_path/"selection.json";path.write_text(json.dumps(value))
    return path,value,load_public_key(signer.public_pem())

def test_accepts_coordinator_signature(tmp_path):
    path,value,key=authorization(tmp_path)
    assert module.verified_authorization(path,key)==value["core"]

@pytest.mark.parametrize("mutation",["candidate","context","digest","key"])
def test_rejects_changed_authorization(tmp_path,mutation):
    path,value,key=authorization(tmp_path)
    if mutation=="candidate":value["core"]["clients"]["client02"]["candidate_sha256"]="c"*64
    elif mutation=="context":value["core"]["context_digest"]="d"*64
    elif mutation=="digest":value["core_digest"]="e"*64
    else:key=load_public_key(SoftwareECDSASigner.generate().public_pem())
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError,match="authorization signature"):
        module.verified_authorization(path,key)


def test_signed_precommit_encodes_float_configuration_as_exact_json_string(tmp_path):
    from fl_forensics.preprocessing import derived_json_bytes
    cfg={"radii":[0.25,0.5,1.0,2.0],"initial_step":0.25}
    core={"artifact_type":"adaptive_live_precommit","config_json":derived_json_bytes(cfg).decode("utf-8")}
    signer=SoftwareECDSASigner.generate();digest=digest_object(core)
    value={"core":core,"core_digest":digest,"signature":_signature(signer,digest,"software-development").model_dump(mode="json")}
    path=tmp_path/"precommit.json";path.write_text(json.dumps(value))
    verified=module.verified_authorization(path,load_public_key(signer.public_pem()))
    assert json.loads(verified["config_json"])==cfg
