"""Fit/infer using only mounted observable files; no dataset or truth access."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import numpy as np
from fl_forensics.state_conditioned_audit import (fit_state_reference,calibrate_state_threshold,
    detect_state_anomalies,save_model,load_model,model_identity)
from fl_forensics.state_conditioned_fusion import calibrate_dual_view,detect_dual_view


def read(path):return json.loads(path.read_bytes())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():raise ValueError('immutable detector output exists')
    path.write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n')


def observe(path,cohort):
    metadata=read(path/'metadata.json')
    if metadata['includes_raw_client_rows'] or metadata['includes_attack_labels']:raise ValueError('forbidden input export')
    assert sha(path/'observations.npz')==metadata['observations_sha256']
    with np.load(path/'observations.npz',allow_pickle=False) as arrays:
        assert set(arrays.files)=={'states','updates'}
        return {**metadata,'states':arrays['states'],'updates':arrays['updates'],'cohort_id':cohort}


parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=['fit','infer'],required=True)
args=parser.parse_args()
base=Path('/observations');models_root=Path('/models');results=Path('/results')
# Negative capability check: actual local datasets and private generation labels
# must not be reachable under either host paths or an accidental evidence mount.
for path in ('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis/artifacts',
             '/private-generation','/evidence','/app/artifacts'):
    assert not Path(path).exists(),('private filesystem unexpectedly mounted',path)
capability={'raw_dataset_paths_unavailable':True,'network_disabled_by_launcher':True,
    'numpy_version':np.__version__,'python_version':sys.version,'phase':args.phase}
if args.phase=='fit':
    index=read(base/'fit-input-index.json');binding=read(base/'fit-input-closure.json')
    assert sha(base/'fit-input-index.json')==binding['index_sha256']
    for relative,digest in binding['files'].items():assert sha(base/relative)==digest
    for cohort,spec in index['cohorts'].items():
        fit=[observe(base/path,spec['cohort_id']) for path in spec['fit']]
        cal=[observe(base/path,spec['cohort_id']) for path in spec['calibration']]
        models={};calibrations={}
        destination=models_root/cohort;destination.mkdir(parents=True,exist_ok=False)
        for key,condition in (('conditioned',True),('state-disabled',False)):
            model=fit_state_reference(fit,condition_on_state=condition);calibration=calibrate_state_threshold(cal,model)
            save_model(destination/f'{key}.npz',model);save(destination/f'{key}-calibration.json',calibration)
            models[key]=model;calibrations[key]=calibration
        joint=calibrate_dual_view(cal,models,calibrations);save(destination/'fusion-calibration.json',joint)
        del models,calibrations
        print('Fitted clean-only cohort',cohort,flush=True)
    save(models_root/'model-closure.json',{'profile':'observable-only-frozen-models-v1',
        'fit_input_closure_sha256':sha(base/'fit-input-closure.json'),
        'files':{p.relative_to(models_root).as_posix():sha(p) for p in models_root.rglob('*') if p.is_file()},
        'capability':capability,'code_sha256':{p.name:sha(p) for p in Path('/code/fl_forensics').glob('*.py')}})
else:
    closure=read(models_root/'model-closure.json')
    for relative,digest in closure['files'].items():assert sha(models_root/relative)==digest
    index=read(base/'evaluation-input-index.json')
    summary=[]
    for cohort,spec in index['cohorts'].items():
        directory=models_root/cohort
        models={key:load_model(directory/f'{key}.npz') for key in ('conditioned','state-disabled')}
        calibrations={key:read(directory/f'{key}-calibration.json') for key in models}
        joint=read(directory/'fusion-calibration.json')
        for case in spec['cases']:
            observation=observe(base/case['path'],spec['cohort_id'])
            leaves={key:detect_state_anomalies(observation,model,calibrations[key]) for key,model in models.items()}
            result=detect_dual_view(observation,models,calibrations,joint)
            save(results/f'{case["id"]}-selection.json',{'case_id':case['id'],'cohort':cohort,
                'observable_sha256':sha(base/case['path']/'observations.npz'),'methods':{**leaves,'fusion':result}})
            summary.append({'case_id':case['id'],'cohort':cohort,'selection_sha256':sha(results/f'{case["id"]}-selection.json')})
        del models,calibrations
    save(results/'selection-closure.json',{'model_closure_sha256':sha(models_root/'model-closure.json'),
        'evaluation_input_index_sha256':sha(base/'evaluation-input-index.json'),
        'cases':summary,'capability':capability,'attack_labels_accessed':False,'raw_client_data_accessed':False})
    print('All observable-only selections closed',len(summary),flush=True)
