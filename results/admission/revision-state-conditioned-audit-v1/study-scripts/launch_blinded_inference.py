"""Task-owned isolated runtime: mount observations, code and models, never rows."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from fl_forensics.canonical import sha256_file

parser=argparse.ArgumentParser();parser.add_argument('phase',choices=['fit','infer']);args=parser.parse_args()
repo=Path.cwd();lab=repo/'artifacts/revision-state-conditioned-heldout-v1'
env={**os.environ,'DOCKER_HOST':'unix:///run/revision-dba-engine.sock','DOCKER_CONFIG':'/tmp/revision-dba-docker-config'}
image='sha256:c763483709fabee912591d8b2cd95f06733f381602723244f281bdcb76d0d575'
assert json.loads(subprocess.check_output(['docker','image','inspect',image],env=env))[0]['Id']==image
binding=json.loads((lab/'fit-input-closure.json').read_bytes())
for name,digest in binding['code'].items():assert sha256_file(lab/name)==digest
models=lab/'models';results=lab/'selections'
if args.phase=='fit':models.mkdir(exist_ok=False)
else:
    assert (models/'model-closure.json').exists();results.mkdir(exist_ok=False)
name=f'revision-state-audit-{args.phase}-20261103'
command=['docker','create','--name',name,'--network','none','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
    '--tmpfs','/tmp:rw,size=1g','--tmpfs','/observations:rw,size=16m',
    '-e','PYTHONPATH=/code','-e','PYTHONDONTWRITEBYTECODE=1','-e','OPENBLAS_NUM_THREADS=1','-e','OMP_NUM_THREADS=1',
    '-v',f'{lab/"detector-code"}:/code:ro','-v',f'{lab/"observable-inference"}:/observations/observable-inference:ro',
    '-v',f'{models}:/models'+('' if args.phase=='fit' else ':ro')]
if args.phase=='fit':
    command += ['-v',f'{lab/"fit-input-index.json"}:/observations/fit-input-index.json:ro',
                '-v',f'{lab/"fit-input-closure.json"}:/observations/fit-input-closure.json:ro']
else:
    command += ['-v',f'{lab/"blinded-evaluation-input-index.json"}:/observations/evaluation-input-index.json:ro',
                '-v',f'{results}:/results']
command += [image,'/code/run_isolated_detector.py','--phase',args.phase]
container=subprocess.check_output(command,env=env,text=True).strip()
inspection=json.loads(subprocess.check_output(['docker','inspect',container],env=env))[0]
assert inspection['HostConfig']['NetworkMode']=='none' and inspection['HostConfig']['ReadonlyRootfs']
assert all('/private-generation' not in mount.get('Source','') for mount in inspection['Mounts'])
(lab/f'{args.phase}-runtime-inspection.json').write_text(json.dumps(inspection,indent=2,sort_keys=True)+'\n')
run=subprocess.run(['docker','start','-a',container],env=env)
exit_code=int(subprocess.check_output(['docker','inspect','--format','{{.State.ExitCode}}',container],env=env,text=True))
subprocess.run(['docker','rm',container],env=env,check=True,capture_output=True)
assert run.returncode==0 and exit_code==0,(run.returncode,exit_code)
print('ISOLATED DETECTOR COMPLETED',args.phase,flush=True)
