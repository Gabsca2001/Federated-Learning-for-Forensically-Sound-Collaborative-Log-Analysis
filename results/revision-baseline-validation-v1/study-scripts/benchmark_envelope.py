"""Time actual stateful inference, not fast retries, on the secondary inputs."""
import json
import os
import resource
import sys
import time
import numpy as np
from audit_common import *
from fl_forensics.state_conditioned_audit import load_model,residual_scores
from fl_forensics.client_envelope_policy import ClientEnvelopePolicy

cohort=sys.argv[1];protocol=read(LAB/'secondary-protocol-before-comparison.json');source=Path(protocol['source_root'])
deps=dependencies();deps[1].set_num_threads(1)
modelroot=REPO/'artifacts/revision-state-conditioned-heldout-v1/models'
models={v:load_model(modelroot/cohort/f'{v}.npz') for v in ('conditioned','state-disabled')}
cal=read(source/'policy-calibration'/f'{cohort}.json');env=read(source/'policy-calibration'/f'{cohort}-envelope.json')
for model in models.values():
    for v in model.values():
        if isinstance(v,np.ndarray):v.flags.writeable=False
samples=[];contexts=0;warm=False
for task in protocol['cases']:
    if task['cohort']!=cohort:continue
    policies=[ClientEnvelopePolicy(cal,env,minimum_contributors=8) for _ in range(3)]
    for number in range(1,16):
        p=source/'private-episodes'/task['stream']/'rounds'/f'round-{number:03d}'
        response=read(p/'worker-response.json');request=read(p/'worker-request.json');metadata=read(p/'observable/metadata.json')
        base=arrays_from_export(read(p/'base-model.json'),np=np)
        clients=metadata['clients'];local_models=[arrays_from_export(read(p/'updates'/f'{c}.json'),np=np) for c in clients]
        with np.load(p/'observable/observations.npz',allow_pickle=False) as arrays:
            observation={**metadata,'states':arrays['states'],'updates':arrays['updates'],'cohort_id':models['conditioned']['schema']['cohort_id']}
        def operation(policy):
            scores={v:residual_scores(observation,m) for v,m in models.items()}
            risk={v:s['risk'][0].tolist() for v,s in scores.items()}
            supported=all(scores[v]['state_support_distance'][0]<=min(cal['state_support_limits'][v],env['state_support_limits'][v])*(1+1e-12)+1e-12 for v in scores)
            decision=policy.step(number,risk,context_supported=bool(supported),mandatory_gate=request['mandatory_gate'],masses=request['masses'],
                expected_previous_digest=policy.head,source_observation_sha256=request['observation_sha256'])
            chosen=[i for i,c in enumerate(clients) if c not in decision['quarantine_current_round']]
            assert len(chosen)>=8
            result=apply_delta(base,aggregate_deltas([model_delta(base,local_models[i]) for i in chosen],strategy='fedavg',f=0,
                weights=[request['masses'][clients[i]] for i in chosen]))
            return decision,risk,result
        if not warm:
            operation(ClientEnvelopePolicy(cal,env,minimum_contributors=8));warm=True
        for repeat,policy in enumerate(policies):
            wall=time.perf_counter_ns();cpu=time.process_time_ns();decision,risk,result=operation(policy)
            cpu=time.process_time_ns()-cpu;wall=time.perf_counter_ns()-wall
            original=response['comparison_decisions']['envelope']
            assert decision['quarantine_current_round']==original['quarantine_current_round']
            assert decision['review_required']==original['review_required'] and decision['supported']==original['supported']
            for v in risk:assert np.allclose(risk[v],response['scored']['risk'][v][0],rtol=0,atol=1e-12)
            assert all(np.isfinite(a).all() for a in result)
            samples.append({'stream':task['stream'],'round':number,'repeat':repeat,'wall_ns':wall,'cpu_ns':cpu})
        contexts+=1
    print(json.dumps({'envelope_cost_cohort':cohort,'finished_stream':task['stream']}),flush=True)
result={'profile':'actual-stateful-envelope-cost-v1','cohort':cohort,'contexts':contexts,'samples':samples,
    'repetitions':'Three independent policy chains; each timed operation advances its own state. No retry timings.',
    'warmup_calls':1,'process_peak_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    'median_wall_ms':float(np.median([s['wall_ns']/1e6 for s in samples])),
    'p95_wall_ms':float(np.quantile([s['wall_ns']/1e6 for s in samples],.95)),
    'qualification':'Preloaded frozen predictors and common application runtime. Include predictor inference, policy decisions and selected-contributor FedAvg aggregation; exclude first model loading, input loading, transport and TPM. Original actions agree; risk tolerance 1e-12 only accommodates reduction roundoff.'}
save(LAB/'benchmark'/f'envelope-full-{cohort}.json',result)
print(json.dumps({k:v for k,v in result.items() if k!='samples'}),flush=True)
