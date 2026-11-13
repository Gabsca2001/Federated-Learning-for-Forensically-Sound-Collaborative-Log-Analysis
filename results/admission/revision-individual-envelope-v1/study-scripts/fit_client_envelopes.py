"""Isolated clean observable fitting; no original rows or attack labels mounted."""
from pathlib import Path
import hashlib
import json
import numpy as np
from fl_forensics.state_conditioned_audit import load_model,residual_scores,model_identity

def read(p):return json.loads(p.read_bytes())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):
    if p.exists():raise ValueError('immutable fit output exists')
    p.write_text(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n')
for name in ('/private-episodes','/private-calibration','/evidence','/app/artifacts'):assert not Path(name).exists()
inputs=Path('/fit-observables');binding=read(inputs/'closure.json')
for rel,value in binding['files'].items():assert sha(inputs/rel)==value
modelsroot=Path('/models');mc=read(modelsroot/'model-closure.json')
for rel,value in mc['files'].items():assert sha(modelsroot/rel)==value
for cohort in ('iid','non-iid'):
    schema=read(inputs/cohort/'schema.json');models={v:load_model(modelsroot/cohort/f'{v}.npz') for v in ('conditioned','state-disabled')}
    maximum=[];supports={};ids={}
    for view,model in models.items():
        null=[];all_support=[];ids[view]={'normalizer':[],'null':[]}
        for role in ('normalizer','null'):
            for p in sorted((inputs/cohort/role).glob('*.npz')):
                with np.load(p,allow_pickle=False) as arrays:
                    o={'states':arrays['states'],'updates':arrays['updates'],'clients':schema['clients'],
                        'sizes':schema['sizes'],'cohort_id':schema['cohort_id']}
                result=residual_scores(o,model);all_support.extend(result['state_support_distance']);ids[view][role].extend(result['frame_ids'])
                if role=='null':null.append(result['risk'])
        assert not set(ids[view]['normalizer'])&set(ids[view]['null'])
        maximum.append(np.concatenate(null).max(axis=0)+.05);supports[view]=float(max(all_support))
    assert ids['conditioned']==ids['state-disabled']
    envelope={'profile':'clean-client-risk-envelope-v1','cohort_id':schema['cohort_id'],'clients':schema['clients'],
        'tensor_risk_limits':np.stack(maximum,axis=1).tolist(),'retained_peak_fraction':.5,
        'state_support_limits':supports,'normalizer_frame_ids':sorted(set(ids['conditioned']['normalizer'])),
        'threshold_frame_ids':sorted(set(ids['conditioned']['null'])),
        'model_ids':{v:model_identity(m) for v,m in models.items()},'fit_input_closure_sha256':sha(inputs/'closure.json'),
        'calibration_rule':'Per-client, per-view clean null maximum plus .05 in raw log1p tensor-risk units. No searched threshold grid.',
        'automatic_deployment_validated':False,'raw_client_rows_used':False,'attack_labels_used':False}
    save(Path('/policy-out')/f'{cohort}-envelope.json',envelope)
    print('FITTED INDIVIDUAL CLEAN ENVELOPE',cohort,flush=True)
save(Path('/policy-out/envelope-closure.json'),{'profile':'individual-envelope-fit-closure-v1',
    'model_closure_sha256':sha(modelsroot/'model-closure.json'),'fit_input_closure_sha256':sha(inputs/'closure.json'),
    'files':{f'{c}-envelope.json':sha(Path('/policy-out')/f'{c}-envelope.json') for c in ('iid','non-iid')},
    'source_policy_sha256':sha(Path('/code/fl_forensics/client_envelope_policy.py')),
    'raw_client_rows_accessible':False,'attack_labels_accessible':False,'numpy_version':np.__version__})
