"""Replay every adaptive query and certify fixed-final-weight robust removals."""
from pathlib import Path
from fractions import Fraction
import copy
import hashlib
import json
import sys

import numpy as np

OUT=Path(__file__).parent
sys.path.insert(0,str(OUT.parent/'bounded-influence-20261104'))
from common import context,score,aggregate as old_aggregate,read
from revision_dba_experiment import save,model_with_arrays,outcomes,authenticate
from fl_forensics.bounded_aggregation import digest
from fl_forensics.byzantine import model_delta
from fl_forensics.canonical import sha256_file
from fl_forensics.client_envelope_policy import ClientEnvelopePolicy
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded,verify_robust_bounded
from fl_forensics.round_derivation import implementation_sha256

REPO=Path.cwd();ROOT=REPO/'artifacts/revision-research-closure-v1';lab=ROOT/'robust-evaluation'
protocol=read(lab/'protocol-before-training.json');assert implementation_sha256()==protocol['source']
assert sha256_file(lab/'controller.py')==protocol['controller_sha256']==sha256_file(OUT/'robust_study.py')
import time
def closed_cases():
    observed={}
    for index,task in enumerate(protocol['tasks']):
        name=f"case-{index:02d}-{task['cohort']}-{task['strategy']}-{task['mode']}"
        manifest=lab/'cases'/name/'manifest.json'
        while True:
            try:
                read(manifest)
                break
            except (FileNotFoundError,json.JSONDecodeError):
                time.sleep(1)
        observed[name]=sha256_file(manifest)
        yield {'name':name,'task':task,'manifest_sha256':observed[name]}
    while not (lab/'results.json').exists():time.sleep(1)
    final=read(lab/'results.json')
    assert len(final['cases'])==len(observed)
    assert all(observed[c['name']]==c['manifest_sha256'] for c in final['cases'])

counts={'cases':0,'queries':0,'selected_aggregates':0,'failed_contexts':0,'local_training_repeats':0,
        'frozen_robust_removal_certificates':0,'conditional_mean_only_certificates':0}

def worst(metric):
    return max([metric['complete_trigger']['asr'],*[x['asr'] for x in metric['component_triggers'].values()]])

def aggregate(base,exports,gen,excluded,reference,robust):
    if not robust:return old_aggregate(base,exports,gen,excluded,True,reference)[:2]
    arrays=arrays_from_export(base,np=np)
    updates={c:arrays_from_export(e,np=np) for c,e in zip(gen.clients,exports,strict=True)}
    args=dict(masses={c:0 if c in excluded else len(gen.rows[c]) for c in gen.clients},
              mandatory_gates=dict.fromkeys(gen.clients,True),limits=reference['limits'],
              reference_digest=digest(reference),minimum_contributors=8)
    pre,report=aggregate_robust_bounded(arrays,updates,**args)
    repeated=verify_robust_bounded(arrays,updates,report,**args)
    if pre is None:return None,report
    assert all(np.array_equal(a,b) for a,b in zip(pre,repeated,strict=True))
    return model_with_arrays(base,pre),report

def removal_certificates(base,model,report,reference):
    arrays=arrays_from_export(base,np=np);actual=arrays_from_export(model,np=np)
    core=report['final_bounded_derivation'];contributions=core['contributions']
    positive=[c for c,x in contributions.items() if Fraction(x['normalized_weight'])>0]
    clipped={c:[np.asarray(t['values'],dtype=float).reshape(t['shape']) for t in contributions[c]['derived_float64_delta']] for c in contributions}
    delta=[sum((clipped[c][i]*float(Fraction(contributions[c]['normalized_weight'])) for c in sorted(contributions)),np.zeros_like(a,dtype=float)) for i,a in enumerate(arrays)]
    parameters=[a.astype(float)+d for a,d in zip(arrays,delta,strict=True)]
    eps=np.asarray([np.linalg.norm(a.astype(float)-p) for a,p in zip(actual,parameters,strict=True)])
    certs={}
    for c in positive:
        beta=float(Fraction(contributions[c]['normalized_weight']))
        assert beta<1
        mu=[(d-beta*v)/(1-beta) for d,v in zip(delta,clipped[c],strict=True)]
        reduced=[b.astype(float)+m for b,m in zip(arrays,mu,strict=True)]
        exported=[r.astype(a.dtype) for r,a in zip(reduced,actual,strict=True)]
        removed_eps=np.asarray([np.linalg.norm(e.astype(float)-r) for e,r in zip(exported,reduced,strict=True)])
        measured=np.asarray([np.linalg.norm(a.astype(float)-e.astype(float)) for a,e in zip(actual,exported,strict=True)])
        bound=2*beta*np.asarray(reference['limits'])+eps+removed_eps
        assert np.all(measured<=bound+1e-12),(c,measured,bound)
        valid=len(positive)-1>=8
        certs[c]={'beta':contributions[c]['normalized_weight'],'measured_tensor_L2':measured.tolist(),
                  'bound_with_both_export_errors':bound.tolist(),'survivor_quorum_satisfied':valid}
        counts['frozen_robust_removal_certificates']+=1
        if not valid:counts['conditional_mean_only_certificates']+=1
    return {'profile':'frozen-final-robust-coefficient-removal-v1','per_client':certs,
            'scope':'Original base, clipping map and final robust coefficients frozen. Not policy rescoring, recomputed geometric-median weights, later retraining or ASR. Failed survivor quorum only permits an algebraic mean, not a valid checkpoint.'}

for case in closed_cases():
    task=case['task'];workspace=lab/'cases'/case['name']
    authenticate(workspace,case['manifest_sha256'])
    gen,cal,env,models,rows,correct=context(task['cohort']);policy=ClientEnvelopePolicy(cal,env)
    reference=read(REPO/'artifacts/revision-bounded-influence-v1'/f'{task["cohort"]}-bounds.json')
    plan=DistributedBackdoorPlan.model_validate({**gen.cfg['attack_plan'],'seed':task['seed'],
        'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True)),'attack_rounds':list(range(1,11))})
    robust=task['strategy']=='robust-bounded-envelope';previous=gen.initial
    for prefix in sorted((workspace/'rounds').glob('round-*')):
        number=int(prefix.name[-3:]);base=read(prefix/'base-model.json')
        assert base==previous
        active=task['mode']=='adaptive' and number<=10
        if active:
            clean=[read(prefix/'endpoints/clean'/f'{c}.json') for c in gen.clients]
            poison=[read(prefix/'endpoints/poison'/f'{c}.json') for c in gen.clients]
            ca=[arrays_from_export(e,np=np) for e in clean];pa=[arrays_from_export(e,np=np) for e in poison]
        else:
            if (prefix/'updates').exists():
                clean=[read(prefix/'updates'/f'{c}.json') for c in gen.clients]
            else:
                assert (prefix/'failure.json').exists()
                _,_,clean,_=gen.execute(base,task['seed'],number)
                counts['local_training_repeats']+=15
        if number in (1,10,15):
            _,_,repeat,_=gen.execute(base,task['seed'],number);assert repeat==clean
            counts['local_training_repeats']+=15
            if active:
                _,_,repeat,_=gen.execute(base,task['seed'],number,plan);assert repeat==poison
                counts['local_training_repeats']+=15
        transcript=read(prefix/'query-transcript.json');candidates=[]
        for query in transcript:
            alpha=query['alpha']
            exports=[model_with_arrays(clean[i],[a+alpha*(b.astype(float)-a) for a,b in zip(ca[i],pa[i],strict=True)]) if c in task['attackers'] else clean[i]
                     for i,c in enumerate(gen.clients)] if active else clean
            ba=arrays_from_export(base,np=np);ds=[model_delta(ba,arrays_from_export(e,np=np)) for e in exports]
            pin=hashlib.sha256(b''.join(derived_json_bytes(e) for e in [base,*exports])).hexdigest()
            trial=copy.deepcopy(policy);decision,_,_=score(base,ds,gen,cal,env,models,trial,number,pin)
            assert decision==query['decision']
            model,report=aggregate(base,exports,gen,decision['quarantine_current_round'],reference,robust) if decision['supported'] else (None,None)
            assert (model is not None)==query['feasible']
            if model is not None:
                metric=outcomes(model,rows,plan,correct,gen.deps)
                assert worst(metric)==query['worst_trigger_asr']
                assert metric['complete_trigger']['asr']==query['full_trigger_asr']
                assert {c:x['asr'] for c,x in metric['component_triggers'].items()}==query['component_asr']
                q=len(set(decision['quarantine_current_round'])&set(task['attackers']))
                candidates.append(((worst(metric),-q,alpha),trial,model,report,metric,exports))
            counts['queries']+=1
        if not candidates:
            assert (prefix/'failure.json').exists();counts['failed_contexts']+=1
            continue
        _,policy,model,report,metric,exports=max(candidates,key=lambda x:x[0])
        assert derived_json_bytes(model)==(prefix/'global-model.json').read_bytes()
        assert report==read(prefix/'bounded-derivation.json')
        assert metric==read(prefix/'round.json')['validation']
        assert all(derived_json_bytes(e)==(prefix/'updates'/f'{c}.json').read_bytes() for c,e in zip(gen.clients,exports,strict=True))
        if robust:
            cert=removal_certificates(base,model,report,reference)
            save(ROOT/'robust-verification'/case['name']/f'round-{number:03d}.json',cert)
        counts['selected_aggregates']+=1;previous=model
    counts['cases']+=1
    print(json.dumps({'verified_robust_case':case['name'],'counts':counts}),flush=True)
record={'status':'verified','source':implementation_sha256(),'counts':counts,
        'scope':'Separate replay using the same implementation, every candidate and selected aggregate. Local training independently repeated at rounds1/10/15. Not an external audit, new dataset or fresh TPM evidence.'}
save(ROOT/'robust-replay.json',record);(OUT/'robust-replay.json').write_bytes((ROOT/'robust-replay.json').read_bytes())
print('ROBUST REPLAY COMPLETE',json.dumps(counts),flush=True)
