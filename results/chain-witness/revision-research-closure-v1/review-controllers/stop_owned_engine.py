"""Stop only the verified idle research-owned Docker daemon; preserve all evidence."""
from pathlib import Path
import json
import os
import signal
import subprocess
import time

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-research-closure-v1'
assert json.loads((lab/'live-runtime-verification.json').read_bytes())['status']=='verified'
pid=415825;proc=Path('/proc')/str(pid)
cmd=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode()
expected_data=repo/'artifacts/revision-dba-isolated-runtime-v1/data'
assert '/usr/bin/dockerd ' in cmd and '--host unix:///run/revision-dba-engine.sock ' in cmd
assert '--data-root '+str(expected_data)+' ' in cmd and '--containerd-namespace revision-dba-v1 ' in cmd
env={**os.environ,'DOCKER_HOST':'unix:///run/revision-dba-engine.sock','DOCKER_CONFIG':'/tmp/revision-dba-docker-config'}
running=subprocess.check_output(['docker','ps','-q'],env=env,text=True).strip()
assert not running,'Never stop a non-idle daemon.'
os.kill(pid,signal.SIGTERM)
for _ in range(30):
    if not proc.exists():break
    time.sleep(1)
assert not proc.exists(),'Daemon stop has not completed.'
record={'status':'stopped-owned-idle-engine','pid':pid,'verified_cmdline':cmd,
        'evidence_data_retained':str(expected_data),'other_engines_modified':False,
        'scope':'Only this task-owned isolated daemon was terminated after all owned training and verification containers had exited. Images, stopped emulators, TPM states, keys and evidence remain local.'}
for p in (lab/'owned-engine-stop.json',out/'owned-engine-stop.json'):p.write_text(json.dumps(record,indent=2)+'\n')
print('Owned idle engine stopped; all evidence retained.',flush=True)
