"""Run fixed-endpoint checks after the owned integration controller completes."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import time

repo=Path.cwd();out=Path(__file__).parent;root=repo/'artifacts/revision-research-closure-v1/live-robust-tpm-v1'
for _ in range(90):
    log=(root.parent/'live-runtime.log').read_text()
    if 'Traceback (most recent call last)' in log:raise RuntimeError('Integration controller failed; preserve partial evidence.')
    if (root/'runtime-image.json').exists() and 'LIVE ENVELOPE TPM CASE COMPLETED' in log:break
    time.sleep(10)
else:raise TimeoutError('Integration not complete; no completion claim emitted.')
env={**os.environ,'DOCKER_HOST':'unix:///run/revision-dba-engine.sock','DOCKER_CONFIG':'/tmp/revision-dba-docker-config'}
image='revision-live-robust:20261104-v1'
actual=subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],env=env,text=True).strip()
assert actual==json.loads((root/'reserved-image-before-training.json').read_bytes())['Id']
helpers=root/'verification-tools';helpers.mkdir(exist_ok=False)
shutil.copy2(out.parent/'bounded-influence-20261104/evaluate_live.py',helpers/'evaluate_endpoints.py')
shutil.copy2(out/'verify_live_robust.py',helpers/'verify_live_robust.py')
for name in ('evaluate_endpoints.py','verify_live_robust.py'):
    command=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
      '--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
      '--tmpfs','/tmp:rw,size=512m','-v',f'{root}:/evidence','-v',f'{helpers}:/verification-tools:ro',
      image,f'/verification-tools/{name}']
    with (root/'logs'/f'final-{name}.log').open('wb') as log:
        subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
quotes=[json.loads(p.read_bytes()) for p in (root/'logs').glob('*-client*-quote.txt')]
assert len(quotes)==225 and len({q['evidence_id'] for q in quotes})==225 and all(q['status']=='quoted' for q in quotes)
trains=[json.loads(p.read_bytes()) for p in (root/'logs').glob('*-client*-train.txt')]
assert len(trains)==225 and all(t['status']=='submitted' for t in trains)
profile=json.loads((root/'reports/robust-profile-verification.json').read_bytes())
endpoints=json.loads((root/'reports/fixed-endpoint-evaluation.json').read_bytes())
assert profile['status']=='verified' and len(endpoints['rounds'])==15
record={k:v for k,v in profile.items() if k!='rounds'}
record.update({'image_id':actual,'fresh_quote_executions':len(quotes),'distinct_quote_evidence_ids':len({q['evidence_id'] for q in quotes}),
 'fresh_local_training_submissions':len(trains),'endpoint_totals':endpoints['totals'],
 'claimed_scope':'Three five-round software-TPM mechanism histories. No general mitigation conclusion from an ineffective short attacked control.'})
for p in (root.parent/'live-runtime-verification.json',out/'live-runtime-verification.json'):
    p.write_text(json.dumps(record,indent=2)+'\n')
print('ROBUST LIVE FOLLOW-UP VERIFIED',json.dumps(record),flush=True)
