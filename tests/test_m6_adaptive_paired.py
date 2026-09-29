import importlib.util
import json
import sys
import pytest
from pathlib import Path
from types import SimpleNamespace
from fl_forensics.crypto import SoftwareECDSASigner
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import run_m6_adaptive_paired as paired

@pytest.mark.parametrize("module_name",["run_m6_adaptive_paired","run_m6_adaptive_paired_v4","run_m6_adaptive_paired_seed"])
def test_no_feasible_attack_preserves_every_original_proposal(tmp_path,monkeypatch,module_name):
    paired=importlib.import_module(module_name)
    source=tmp_path/"round";source.mkdir()
    pre=source/"precommit.json";pre.write_text("{}")
    for cid in paired.IDS:
        proposal=source/"proposals"/cid;proposal.mkdir(parents=True)
        for name in ["bundle.json","update.json","metrics.json"]:(proposal/name).write_text(json.dumps({"client":cid,"file":name}))
    def search(output,*args,**kwargs):
        (output/"summary.json").write_text('{"selected_query":null}')
        return {"selected_query":None}
    monkeypatch.setattr(paired,"execute_live",search)
    monkeypatch.setattr(paired,"_load_context",lambda _:SimpleNamespace(core_digest="a"*64))
    def no_signing(args):raise AssertionError("A failed search must not sign altered tensors")
    selected=paired.attacked_round(source=source,cfg={"attackers":["client02","client05","client14"]},
        signer=SoftwareECDSASigner.generate(),precommit=pre,trust=tmp_path,partition=tmp_path,compose=[],run=no_signing)
    assert selected is None
    for cid in paired.IDS:
        for name in ["bundle.json","update.json","metrics.json"]:
            assert (source/"submissions"/cid/name).read_bytes()==(source/"proposals"/cid/name).read_bytes()
    selection=json.loads((source/"adaptive-selection.json").read_text())
    assert selection["core"]["clients"]=={}
    assert selection["core"]["selected_query"] is None
