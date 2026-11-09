"""Persistent isolated worker: the inbox has only the current observable input."""
import hashlib
import io
import json
from pathlib import Path
import sys
import numpy as np

from fl_forensics.state_conditioned_audit import load_model,residual_scores
from fl_forensics.current_evidence_policy import CurrentEvidencePolicy


def read(path):return json.loads(path.read_bytes())
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def emit(value):print(json.dumps(value,sort_keys=True,allow_nan=False),flush=True)


for path in ('/private-calibration','/private-episodes','/evidence','/app/artifacts',
             '/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis/artifacts'):
    assert not Path(path).exists(),('private input unexpectedly accessible',path)
root=Path('/models');closure=read(root/'model-closure.json')
for relative,digest in closure['files'].items():assert sha(root/relative)==digest
model_pin=sha(root/'model-closure.json');models={};base_limits={};sessions={}
emit({'ready':True,'model_closure_sha256':model_pin,'numpy_version':np.__version__,
    'raw_client_data_accessible':False,'attack_plans_accessible':False,'future_round_files_accessible':False})


def score(request):
    cohort=request['cohort']
    if cohort not in ('iid','non-iid'):raise ValueError('unknown cohort')
    if cohort not in models:
        models[cohort]={v:load_model(root/cohort/f'{v}.npz') for v in ('conditioned','state-disabled')}
        for model in models[cohort].values():
            for value in model.values():
                if isinstance(value,np.ndarray):value.flags.writeable=False
        base_limits[cohort]={v:read(root/cohort/f'{v}-calibration.json')['state_support_limit'] for v in models[cohort]}
    metadata=read(Path('/inbox/current/metadata.json'))
    if metadata['includes_raw_client_rows'] or metadata['includes_attack_labels']:raise ValueError('forbidden observable export')
    data=Path('/inbox/current/observations.npz').read_bytes()
    if hashlib.sha256(data).hexdigest()!=request['observation_sha256'] or metadata['observations_sha256']!=request['observation_sha256']:raise ValueError('changed observable input')
    with np.load(io.BytesIO(data),allow_pickle=False) as arrays:
        if set(arrays.files)!={'states','updates'}:raise ValueError('unexpected array fields')
        observation={**metadata,'states':arrays['states'],'updates':arrays['updates'],
            'cohort_id':models[cohort]['conditioned']['schema']['cohort_id']}
    results={view:residual_scores(observation,model) for view,model in models[cohort].items()}
    assert results['conditioned']['frame_ids']==results['state-disabled']['frame_ids']
    return {'clients':observation['clients'],'cohort_id':observation['cohort_id'],
        'risk':{v:r['risk'].tolist() for v,r in results.items()},
        'state_distances':{v:r['state_support_distance'].tolist() for v,r in results.items()},
        'frame_ids':results['conditioned']['frame_ids'],'base_support_limits':base_limits[cohort]}


for line in sys.stdin:
    try:
        request=json.loads(line)
        allowed={'op','request_id','cohort','observation_sha256','stream','round','previous','masses','mandatory_gate'}
        if set(request)-allowed:raise ValueError('unexpected request fields')
        op=request['op']
        if op=='stop':emit({'stopped':True});break
        if op not in ('score','step'):raise ValueError('unknown worker operation')
        scored=score(request)
        if op=='score':
            emit({'request_id':request['request_id'],'scored':scored,'source_observation_sha256':request['observation_sha256']});continue
        if len(scored['frame_ids'])!=1:raise ValueError('online decisions accept only one current frame')
        stream=request['stream'];cohort=request['cohort']
        if stream not in sessions:
            calibration=read(Path('/policy')/f'{cohort}.json')
            binding=read(Path('/policy/closure.json'))
            assert binding['model_closure_sha256']==model_pin
            assert sha(Path('/policy')/f'{cohort}.json')==binding['files'][f'{cohort}.json']
            sessions[stream]=(cohort,CurrentEvidencePolicy(calibration,minimum_contributors=8))
        bound_cohort,policy=sessions[stream]
        if cohort!=bound_cohort:raise ValueError('stream cohort changed')
        supported=all(scored['state_distances'][v][0]<=policy.cal['state_support_limits'][v]*(1+1e-12)+1e-12 for v in ('conditioned','state-disabled'))
        decision=policy.step(request['round'],{v:values[0] for v,values in scored['risk'].items()},
            context_supported=supported,mandatory_gate=request['mandatory_gate'],masses=request['masses'],
            expected_previous_digest=request['previous'],source_observation_sha256=request['observation_sha256'])
        emit({'request_id':request['request_id'],'decision':decision,'scored':scored})
    except Exception as exc:
        emit({'error':type(exc).__name__+': '+str(exc)});raise
