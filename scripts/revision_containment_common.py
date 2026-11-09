"""Frozen numerical containment adapter for the offline controlled experiment."""
from pathlib import Path
import sys,json
import numpy as np
out=Path(__file__).parent

from revision_policy_data import Generator,current_observation,aggregate_selected
from revision_dba_experiment import save,model_with_arrays,outcomes,predict
from fl_forensics.bounded_aggregation import aggregate_bounded,verify_bounded,digest
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.state_conditioned_audit import load_model,residual_scores
from fl_forensics.canonical import sha256_file
from fl_forensics.client_envelope_policy import ClientEnvelopePolicy
repo=Path.cwd();lab=repo/'artifacts/revision-bounded-influence-v1'
def read(p):return json.loads(Path(p).read_bytes())

def context(cohort):
    cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
    gen=Generator(repo/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if cohort=='iid' else 'm3-data24-parquet-non-iid'),cfg)
    p=repo/'artifacts/revision-geometry-detector-v1/policy-calibration'
    cal=read(p/f'{cohort}.json');envelope=read(p/f'{cohort}-envelope.json')
    modelroot=repo/'artifacts/revision-state-conditioned-heldout-v1/models'/cohort
    models={v:load_model(modelroot/f'{v}.npz') for v in ('conditioned','state-disabled')}
    rows=read(cfg['validation_path'])['rows']['validation'];pred,_=predict(gen.initial,rows,gen.deps)
    return gen,cal,envelope,models,rows,[p==r['label'] for p,r in zip(pred,rows,strict=True)]

def score(base,deltas,gen,cal,env,models,policy,number,pin):
    obs=current_observation(base,deltas,gen.clients,{})
    obs.pop('source',None);obs['cohort_id']=sha256_file(gen.root/'manifest.json')
    scores={v:residual_scores(obs,m) for v,m in models.items()}
    supported=all(scores[v]['state_support_distance'][0]<=min(cal['state_support_limits'][v],env['state_support_limits'][v])*(1+1e-12)+1e-12 for v in models)
    risk={v:scores[v]['risk'][0].tolist() for v in models}
    args=dict(context_supported=supported,mandatory_gate=dict.fromkeys(gen.clients,True),masses={c:len(gen.rows[c]) for c in gen.clients},source_observation_sha256=pin)
    return policy.step(number,risk,expected_previous_digest=policy.head,**args),risk,args

def aggregate(base,exports,gen,excluded,bounded,reference):
    if not bounded:return aggregate_selected(gen,base,exports,excluded),None,None
    arrays=arrays_from_export(base,np=np);updates={c:arrays_from_export(e,np=np) for c,e in zip(gen.clients,exports,strict=True)}
    args=dict(masses={c:0 if c in excluded else len(gen.rows[c]) for c in gen.clients},mandatory_gates=dict.fromkeys(gen.clients,True),
              limits=reference['limits'],reference_digest=digest(reference),minimum_contributors=8)
    pre,report=aggregate_bounded(arrays,updates,**args)
    replay=verify_bounded(arrays,updates,report,**args)
    if pre is None:return None,report,None
    assert all(np.array_equal(a,b) for a,b in zip(pre,replay,strict=True))
    model=model_with_arrays(base,pre);actual=arrays_from_export(model,np=np)
    rounding=np.array([np.linalg.norm(a.astype(float)-b) for a,b in zip(actual,pre,strict=True)])
    delta=[a-b.astype(float) for a,b in zip(pre,arrays,strict=True)]
    certificates={}
    from fractions import Fraction
    for c,item in report['contributions'].items():
        alpha=float(Fraction(item['normalized_weight']))
        if alpha==0:continue
        local=[np.asarray(x['values']).reshape(x['shape']) for x in item['derived_float64_delta']]
        mu=[(a-alpha*b)/(1-alpha) for a,b in zip(delta,local,strict=True)]
        reduced=[b.astype(float)+a for b,a in zip(arrays,mu,strict=True)]
        reduced32=[a.astype(np.float32) for a in reduced]
        eps=np.array([np.linalg.norm(a.astype(float)-b) for a,b in zip(reduced32,reduced,strict=True)])
        measured=np.array([np.linalg.norm(a.astype(float)-b.astype(float)) for a,b in zip(actual,reduced32,strict=True)])
        bound=2*alpha*np.asarray(reference['limits'])+rounding+eps
        assert np.all(measured<=bound+1e-12), (c,measured,bound)
        certificates[c]={'alpha':alpha,'actual_exported_removal_distances':measured.tolist(),
                         'bounds_including_both_export_rounding_errors':bound.tolist()}
    return model,report,{'profile':'fixed-input-direct-removal-norm-certificate-v1','per_client':certificates,
        'pre_export_to_actual_rounding_L2':rounding.tolist(),'scope':'fixed base, fixed clipping map, fixed survivor masses; not policy rescoring or future retraining and not an ASR guarantee'}

from fl_forensics.preprocessing import derived_json_bytes
