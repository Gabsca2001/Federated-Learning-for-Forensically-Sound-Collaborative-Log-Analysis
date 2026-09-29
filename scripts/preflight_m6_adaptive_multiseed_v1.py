"""Check local M4 image and release only four detached historical bridge networks."""
from pathlib import Path
import json,subprocess,hashlib
import yaml
ROOT=Path(__file__).resolve().parents[1]
out=ROOT/'results/m6-adaptive-multiseed-preflight-v1';out.mkdir(exist_ok=True)
plan=json.loads((ROOT/'configs/m6-adaptive-paired-s342593-v1.json').read_text())
paths=[m['path'] for m in yaml.safe_load((ROOT/'configs/trust.yaml').read_text())['measurements']]
probe='import json,hashlib;from pathlib import Path;paths='+repr(paths)+';print(json.dumps({p:hashlib.sha256((Path("/app")/p).read_bytes()).hexdigest() for p in paths}))'
actual=json.loads(subprocess.check_output(['docker','run','--rm','--network','none','--entrypoint','python3',plan['m4_runtime_image_id'],'-c',probe],text=True))
for p,digest in actual.items():
    assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==digest,p
(out/'image-measurements.json').write_text(json.dumps(actual,indent=2))
for seed in [342593,343593,344593,345593]:
    tag=f'm6_policy_multiseed_gated_composite_clean_s{seed}_v1'
    namespace='flforensics_'+tag;name=namespace+'_trust'
    manifest=ROOT/f'artifacts/m6-policy-multiseed-gated_composite-clean-s{seed}-v1/campaign-manifest.json'
    assert json.loads(manifest.read_text())['core']['round_count']==30
    state=json.loads(subprocess.check_output(['docker','network','inspect',name],text=True))
    (out/(name+'.json')).write_text(json.dumps(state,indent=2))
    assert not state[0]['Containers'],'Network still in use'
    active=subprocess.check_output(['docker','ps','-q','--filter','label=com.docker.compose.project='+namespace],text=True)
    assert not active.strip(),'Historical project still active'
    subprocess.run(['docker','network','rm',name],check=True)
print('M4 measured files match; four empty historical networks released; all volumes and artifacts preserved.')