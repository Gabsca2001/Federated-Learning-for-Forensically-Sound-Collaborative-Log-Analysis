"""Reserve a fresh software-TPM integration case for the optional robust profile."""
from pathlib import Path
import json
import os
import shutil
import subprocess

import yaml

from fl_forensics.canonical import sha256_file
from fl_forensics.round_derivation import implementation_sha256

repo=Path.cwd();out=Path(__file__).parent
lab=repo/'artifacts/revision-research-closure-v1/live-robust-tpm-v1'
old=repo/'artifacts/revision-live-bounded-tpm-v2'
assert not lab.exists();lab.mkdir()
for name in ('partition','config'):shutil.copytree(old/name,lab/name)
shutil.copy2(old/'initial-model.json',lab/'initial-model.json')
cfg=yaml.safe_load((lab/'config/federation.yaml').read_text())
cfg['training']['seed']=2026110461
(lab/'config/federation.yaml').write_text(yaml.safe_dump(cfg,sort_keys=False))
plan=json.loads((lab/'config/dba-plan.json').read_bytes())
plan['plan']['seed']=2026110461
plan['plan']['client_components']={'client02':[13],'client07':[17],'client13':[24]}
(lab/'config/dba-plan.json').write_text(json.dumps(plan,sort_keys=True,indent=2)+'\n')
original=yaml.safe_load((old/'config/active.yaml').read_text())
for branch in ('clean','control','active'):
    value=json.loads(json.dumps(original))
    value['runtime_admission']['policy_id']='live-robust-bounded-'+branch+'-v1'
    if branch!='control':
        value['runtime_admission']['observable_policy']['profile']='live-client-envelope-robust-bounded-v1'
    (lab/'config'/f'{branch}.yaml').write_text(yaml.safe_dump(value,sort_keys=False))
trust=yaml.safe_load((repo/'configs/revision-bounded-live-trust.yaml').read_text())
trust['attestation']['baseline_id']='robust-bounded-live-tpm-20261104-v1'
trust['measurements'].append({'component_id':'robust-bounded-aggregation','component_version':'1.0.0',
                             'pcr_index':7,'path':'src/fl_forensics/robust_bounded_aggregation.py'})
trust_path=repo/'configs/revision-robust-live-trust.yaml'
assert not trust_path.exists();trust_path.write_text(yaml.safe_dump(trust,sort_keys=False))
text=(repo/'scripts/revision_live_bounded_v2.py').read_text()
for before,after in [('revision_live_bounded_v2.py','revision_live_robust_bounded.py'),
                     ('revision-bounded-live-trust.yaml','revision-robust-live-trust.yaml'),
                     ('revision-live-bounded:20261104-v2','revision-live-robust:20261104-v1'),
                     ('revision-bounded-tpm-20261104-v2-','revision-robust-tpm-20261104-v1-'),
                     ('live-bounded-','live-robust-bounded-'),
                     ('artifacts/revision-live-bounded-tpm-v2','artifacts/revision-research-closure-v1/live-robust-tpm-v1')]:
    text=text.replace(before,after)
text=text.replace('artifacts/revision-live-robust-bounded-tpm-v2','artifacts/revision-research-closure-v1/live-robust-tpm-v1')
runner=repo/'scripts/revision_live_robust_bounded.py'
assert not runner.exists();runner.write_text(text)
dockerfile=repo/'Dockerfile.revision-live-robust'
assert not dockerfile.exists()
dockerfile.write_text((repo/'Dockerfile.revision-live-bounded').read_text())
protocol={'profile':'live-robust-bounded-integration-v1','branches':['clean','control','active'],'rounds':5,
    'implementation_sha256':implementation_sha256(),'source_implementation_sha256':implementation_sha256(),
    'runner_sha256':sha256_file(runner),'training_seed':2026110461,'attack_plan':plan,
    'base_model_sha256':sha256_file(lab/'initial-model.json'),
    'branches_semantics':{'clean':'Unmodified training with robust bounded aggregation',
                         'control':'Three DBA rounds under the existing bounded envelope, then two continuations',
                         'active':'Same DBA schedule under the optional robust bounded profile'},
    'case_role':'New-seed runtime mechanism case. No general efficacy claim if the attacked control is ineffective. Fifteen logical software-TPM clients on one host; no physical-TPM protection.',
    'config_files':{p.relative_to(lab).as_posix():sha256_file(p) for p in (lab/'config').rglob('*') if p.is_file()},
    'verification':'Fresh Quotes, signed originals, client receipts, full admission and numerical reconstruction, final robust coefficients and graph transformation binding. No raw client signature is transferred to a derived object.'}
(lab/'reserved-protocol-before-training.json').write_text(json.dumps(protocol,indent=2,sort_keys=True)+'\n')
env={**os.environ,'DOCKER_HOST':'unix:///run/revision-dba-engine.sock','DOCKER_CONFIG':'/tmp/revision-dba-docker-config'}
base_id=subprocess.check_output(['docker','image','inspect','revision-attested-chain:20261102-v4','--format','{{.Id}}'],env=env,text=True).strip()
assert base_id=='sha256:ea5b05c218bf9840c660aa61c21ecb792c5ead1efecf7e36d8fed8fb6724effa'
with (lab/'image-build.log').open('wb') as log:
    subprocess.run(['docker','build','--network=none','--pull=false','-f',str(dockerfile),
                    '-t','revision-live-robust:20261104-v1','.'],env=env,check=True,stdout=log,stderr=subprocess.STDOUT)
image=json.loads(subprocess.check_output(['docker','image','inspect','revision-live-robust:20261104-v1'],env=env))[0]
(lab/'reserved-image-before-training.json').write_text(json.dumps({'Id':image['Id'],'source':implementation_sha256(),'base':base_id},indent=2)+'\n')
subprocess.run(['docker','save','-o',str(lab/'frozen-runtime.tar'),'revision-live-robust:20261104-v1'],env=env,check=True)
(out/'live-protocol.json').write_bytes((lab/'reserved-protocol-before-training.json').read_bytes())
print('ROBUST LIVE CASE RESERVED',image['Id'],implementation_sha256(),flush=True)
