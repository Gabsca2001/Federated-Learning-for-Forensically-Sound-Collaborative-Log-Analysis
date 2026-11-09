"""Generate every predeclared new case only after all models are frozen."""
from pathlib import Path
import numpy as np
from study_data import Generator,read,export_observation
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

repo=Path.cwd();lab=repo/'artifacts/revision-state-conditioned-heldout-v1'
protocol=read(lab/'frozen-protocol-before-new-training.json')
model_closure=read(lab/'models/model-closure.json')
for name,digest in model_closure['files'].items():assert sha256_file(lab/'models'/name)==digest
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
partitions={'iid':repo/'artifacts/m3-data24-parquet-iid-local-test-v1','non-iid':repo/'artifacts/m3-data24-parquet-non-iid'}
cases=[]
for cohort,items in protocol['heldout'].items():
    for seed,attackers in items:
        for mode in ('clean','distributed'):cases.append({'cohort':cohort,'seed':seed,'mode':mode,'attackers':attackers if mode=='distributed' else []})
rng=np.random.default_rng(771593);rng.shuffle(cases)
for number,case in enumerate(cases):case['id']=f'case-{number:03d}'
save(lab/'private-evaluation-map-before-generation.json',{'cases':cases,'model_closure_sha256':sha256_file(lab/'models/model-closure.json'),
    'controller_sha256':sha256_file(Path(__file__)),'case_order_seed':771593})
index={'profile':'observable-only-heldout-inputs-v1','model_closure_sha256':sha256_file(lab/'models/model-closure.json'),
    'cohorts':{c:{'cohort_id':sha256_file(p/'manifest.json'),'cases':[]} for c,p in partitions.items()}}
generators={cohort:Generator(path,cfg) for cohort,path in partitions.items()}
for case in cases:
    path=lab/'private-generation/heldout'/case['id'];cohort=case['cohort']
    observation=generators[cohort].campaign(path,case['seed'],case['attackers'])
    destination=lab/'observable-inputs/heldout'/case['id'];export_observation(destination,observation)
    index['cohorts'][cohort]['cases'].append({'id':case['id'],'path':destination.relative_to(lab).as_posix()})
save(lab/'evaluation-input-index.json',index)
save(lab/'evaluation-input-closure.json',{'model_closure_sha256':sha256_file(lab/'models/model-closure.json'),
    'index_sha256':sha256_file(lab/'evaluation-input-index.json'),
    'observations':{p.relative_to(lab).as_posix():sha256_file(p) for p in (lab/'observable-inputs/heldout').rglob('*') if p.is_file()},
    'new_campaigns':len(cases),'local_training_calls':1800})
print('ALL HELDOUT OBSERVATIONS READY',len(cases),flush=True)
