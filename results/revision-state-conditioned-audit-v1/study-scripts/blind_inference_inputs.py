"""Derived opaque aliases for all primary and matched-state control observations."""
from pathlib import Path
import shutil
import numpy as np
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file
import json

repo=Path.cwd();lab=repo/'artifacts/revision-state-conditioned-heldout-v1'
source=json.loads((lab/'evaluation-with-matched-controls-input-index.json').read_bytes())
assert not (lab/'selections').exists()
records=[(cohort,case) for cohort,spec in source['cohorts'].items() for case in spec['cases']]
np.random.default_rng(991593).shuffle(records)
public={'profile':'blinded-observable-inference-v1','model_closure_sha256':sha256_file(lab/'models/model-closure.json'),
    'cohorts':{cohort:{'cohort_id':spec['cohort_id'],'cases':[]} for cohort,spec in source['cohorts'].items()}}
private=[]
for number,(cohort,case) in enumerate(records):
    alias=f'observation-{number:03d}';destination=lab/'observable-inference'/alias
    shutil.copytree(lab/case['path'],destination)
    public['cohorts'][cohort]['cases'].append({'id':alias,'path':destination.relative_to(lab).as_posix()})
    private.append({'alias':alias,'source_id':case['id'],'cohort':cohort})
save(lab/'blinded-evaluation-input-index.json',public)
save(lab/'private-inference-alias-map.json',{'aliases':private,'shuffle_seed':991593})
save(lab/'blinded-evaluation-input-closure.json',{'index_sha256':sha256_file(lab/'blinded-evaluation-input-index.json'),
    'files':{p.relative_to(lab).as_posix():sha256_file(p) for p in (lab/'observable-inference').rglob('*') if p.is_file()},
    'model_closure_sha256':sha256_file(lab/'models/model-closure.json')})
print('Blinded inference inputs ready',len(private),flush=True)
