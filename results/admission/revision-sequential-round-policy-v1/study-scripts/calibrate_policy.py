"""Collect observable risks and fit cutoffs before reserved online episodes."""
from pathlib import Path
import json
import shutil
import subprocess
import os
from worker_link import WorkerLink
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-sequential-round-policy-v1'
old=repo/'artifacts/revision-state-conditioned-heldout-v1'
protocol=json.loads((lab/'protocol-before-new-training.json').read_bytes())
assert sha256_file(repo/'src/fl_forensics/sequential_decision.py')==protocol['source_policy_sha256']
assert sha256_file(lab/'worker-code/policy_worker.py')==protocol['worker_sha256']
index_new=json.loads((lab/'new-clean-calibration-index.json').read_bytes())
old_index=json.loads((old/'fit-input-index.json').read_bytes())
old_rows=json.loads((old/'post-selection-evaluation.json').read_bytes())['rows']
inputs=lab/'risk-calibration-inputs';inputs.mkdir(exist_ok=False)
index={'model_closure_sha256':protocol['model_closure_sha256'],'cohorts':{}}
worker=WorkerLink(repo,lab,'calibration')
try:
    assert worker.ready['model_closure_sha256']==protocol['model_closure_sha256']
    for cohort,spec in index_new['cohorts'].items():
        normalizer=[];threshold=[]
        paths=[('normalizer',old/path) for path in old_index['cohorts'][cohort]['calibration']]
        paths += [('threshold',old/'observable-inference'/r['alias']) for r in old_rows
            if r['cohort']==cohort and r['method']=='fusion' and r['mode'] in ('clean','matched-state-clean')]
        paths += [('threshold',lab/path) for path in spec['new_clean_threshold_inputs']]
        for number,(role,path) in enumerate(paths):
            request,response=worker.request(path,cohort=cohort)
            scored=response['scored']
            record={'sequence_id':f'{cohort}-{role}-{number:03d}',**scored,
                'source_commitment':response['source_observation_sha256']}
            record.pop('base_support_limits')
            (normalizer if role=='normalizer' else threshold).append(record)
        save(inputs/f'{cohort}.json',{'normalizer':normalizer,'threshold':threshold,
            'role':'Clean-only normalization and sequential null cutoffs; previous evaluation clean/null cases are now development calibration data.'})
        index['cohorts'][cohort]={'path':f'{cohort}.json','sha256':sha256_file(inputs/f'{cohort}.json')}
finally:worker.stop()
save(inputs/'index.json',index)
shutil.copy(out/'fit_policy_isolated.py',lab/'worker-code/fit_policy_isolated.py')
env={**os.environ,'DOCKER_HOST':'unix:///run/revision-dba-engine.sock','DOCKER_CONFIG':'/tmp/revision-dba-docker-config'}
image='sha256:c763483709fabee912591d8b2cd95f06733f381602723244f281bdcb76d0d575'
command=['docker','create','--name','revision-sequential-cutoffs-20261103','--network','none','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
    '--tmpfs','/tmp:rw,size=1g','-e','PYTHONPATH=/code','-e','PYTHONDONTWRITEBYTECODE=1','-e','OPENBLAS_NUM_THREADS=1',
    '-v',f'{lab/"worker-code"}:/code:ro','-v',f'{inputs}:/risk-inputs:ro','-v',f'{lab/"policy-calibration"}:/policy-out',
    image,'/code/fit_policy_isolated.py']
container=subprocess.check_output(command,env=env,text=True).strip()
inspection=json.loads(subprocess.check_output(['docker','inspect',container],env=env))[0]
save(lab/'cutoff-runtime-inspection.json',inspection)
run=subprocess.run(['docker','start','-a',container],env=env)
exitcode=int(subprocess.check_output(['docker','inspect','--format','{{.State.ExitCode}}',container],env=env,text=True))
subprocess.run(['docker','rm',container],env=env,check=True,capture_output=True)
assert run.returncode==exitcode==0
save(lab/'calibration-frozen-before-evaluation.json',{'policy_closure_sha256':sha256_file(lab/'policy-calibration/closure.json'),
    'protocol_sha256':sha256_file(lab/'protocol-before-new-training.json'),'raw_client_data_used_by_worker':False})
print('SEQUENTIAL CALIBRATION FROZEN',flush=True)
