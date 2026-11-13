"""Repeat the full shared-input analysis and compare every numerical artifact."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

out=Path(__file__).parent;root=Path.cwd()/'artifacts/revision-research-closure-v1'
source=root/'shared-gradient-baselines-v2';target=root/'shared-gradient-replay'
assert not target.exists()
text=(out/'shared_gradient_baselines.py').read_text()
text=text.replace("DEST=ROOT/'shared-gradient-baselines-v2'", "DEST=ROOT/'shared-gradient-replay'")
text=text.replace("OUT/'shared-gradient-results.json'", "OUT/'shared-gradient-replayed-results.json'")
controller=out/'shared_gradient_replay_controller.py'
assert not controller.exists();controller.write_text(text)
env={**os.environ,'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1'}
subprocess.run([sys.executable,'-u',str(controller)],env=env,check=True)
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest()
exclude={'manifest.json','experiment-authority.public.pem','controller.py','protocol-before-comparison.json'}
first={p.relative_to(source).as_posix():h(p) for p in source.rglob('*') if p.is_file() and p.relative_to(source).as_posix() not in exclude}
second={p.relative_to(target).as_posix():h(p) for p in target.rglob('*') if p.is_file() and p.relative_to(target).as_posix() not in exclude}
assert first==second,[(n,v,second.get(n)) for n,v in first.items() if second.get(n)!=v][:5]
data=json.loads((source/'results.json').read_bytes())
record={'status':'verified','counts':data['counts'],'numerical_files_exactly_equal':len(first),
        'original_manifest_sha256':h(source/'manifest.json'),'replay_manifest_sha256':h(target/'manifest.json'),
        'scope':'A separate complete execution from the same frozen source inputs using the same numerical implementation. Every model, result, calibration/decision and derived-input record compared byte-for-byte; independent software keys and controller metadata excluded. No new training or TPM Quotes.'}
(root/'shared-gradient-replay.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'shared-gradient-replay.json').write_bytes((root/'shared-gradient-replay.json').read_bytes())
print('FULL SHARED GRADIENT REPLAY VERIFIED',json.dumps(record),flush=True)
