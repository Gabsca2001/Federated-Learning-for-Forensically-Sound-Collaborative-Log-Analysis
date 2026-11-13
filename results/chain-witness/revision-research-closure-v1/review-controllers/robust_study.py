"""Frozen multi-trigger independent-seed validation; no defense retuning."""
from pathlib import Path
import copy,hashlib,json,sys
import numpy as np

out=Path(__file__).parent
sys.path.insert(0,str(out.parent/'bounded-influence-20261104'))
import common as shared
from common import context,score,aggregate as old_aggregate,read
from revision_dba_experiment import save,model_with_arrays,outcomes
from fl_forensics.byzantine import model_delta
from fl_forensics.canonical import sha256_file
from fl_forensics.client_envelope_policy import ClientEnvelopePolicy
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256

import argparse
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded,verify_robust_bounded
from fl_forensics.bounded_aggregation import digest

parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=['development','evaluation'],required=True)
phase=parser.parse_args().phase
repo=Path.cwd();lab=repo/'artifacts/revision-research-closure-v1'/('robust-'+phase)

def aggregate(base,exports,gen,excluded,bounded,reference):
    if task['strategy']=='bounded-envelope':
        return old_aggregate(base,exports,gen,excluded,True,reference)
    arrays=arrays_from_export(base,np=np)
    updates={c:arrays_from_export(e,np=np) for c,e in zip(gen.clients,exports,strict=True)}
    args=dict(masses={c:0 if c in excluded else len(gen.rows[c]) for c in gen.clients},
              mandatory_gates=dict.fromkeys(gen.clients,True),limits=reference['limits'],
              reference_digest=digest(reference),minimum_contributors=8)
    parameters,report=aggregate_robust_bounded(arrays,updates,**args)
    repeated=verify_robust_bounded(arrays,updates,report,**args)
    if parameters is None:return None,report,None
    assert all(np.array_equal(a,b) for a,b in zip(parameters,repeated,strict=True))
    model=model_with_arrays(base,parameters)
    # No old certificate is silently assigned to recomputed robust weights.
    certificate={'profile':'robust-convex-coefficient-certificate-v1','per_client':{},
        'weights':report['final_coefficients'],
        'scope':'Finite robust output replay. Fixed-coefficient removal certificates are constructed separately; no dynamic robust reweighting bound is claimed.'}
    return model,report,certificate

assert not lab.exists(),'One-shot reservation; retain partial evidence if interrupted'
lab.mkdir()
frozen_source=implementation_sha256()
assignments=([('non-iid',2026110406,['client04','client07','client11'])] if phase=='development' else
             [('iid',2026110451,['client03','client08','client13']),
              ('iid',2026110452,['client02','client07','client15']),
              ('iid',2026110453,['client01','client09','client12']),
              ('non-iid',2026110454,['client02','client08','client14']),
              ('non-iid',2026110455,['client04','client06','client15']),
              ('non-iid',2026110456,['client03','client07','client12'])])

tasks=[dict(cohort=c,seed=s,attackers=a,strategy=v,mode=m) for c,s,a in assignments
       for v in ('bounded-envelope','robust-bounded-envelope') for m in ('clean','adaptive')]
alphas=[0.,.03125,.0625,.125,.25,.5,.75,1.,2.,4.]
protocol={'profile':'robust-convex-containment-comparison-v1','phase':phase,'tasks':tasks,'horizon':15,
    'attack_rounds':list(range(1,11)),'unmodified_continuation_rounds':list(range(11,16)),
    'alphas':alphas,'selection':'Supported context and quorum required. Maximize worst ASR across complete and each of three component triggers after actual defended aggregation, then fewer attacker quarantines, then larger alpha. Shared alpha for the three attackers; ten candidates per active attack round.',
    'independence':'Development reuses one disclosed earlier counterexample; evaluation reserves six new seed/identity assignments after development. Same Data24 partitions, not an independent dataset.',
    'information':'Privileged white-box attack with validation oracle and clean/poisoned local endpoints from the actual current base. No test-split access. Raw rows/attacker IDs are not detector inputs.',
    'criteria':'Never treat an unsupported/quorum failure or absent checkpoint as ASR zero. Report every case. Clean paired macro-F1 loss <=.02 at every fixed endpoint, complete bounded clean histories, and numerical certificates are guardrails. Uniform mitigation may only be claimed if every completed attack-effective matched case has lower worst-trigger ASR with containment. Otherwise retain an experimental claim and report counterexamples; no defense retuning.',
    'effective_control':'At least one fixed round with >=.20 worst-trigger ASR increase relative to its matched clean endpoint, and <=.05 clean macro-F1 loss at that endpoint. Other controls remain reported as inconclusive for mitigation.',
    'verification':'Separate prefix-policy replay, exact aggregate/report/certificate replay from saved originals, selected endpoint metrics repeated. Repeat all local training at rounds1 and15 (including poisoned endpoints if active). All candidate transcripts retained for independent query replay.',
    'source':implementation_sha256(),'controller_sha256':sha256_file(Path(__file__)),
    'shared_adapter_sha256':sha256_file(out.parent/'bounded-influence-20261104/common.py'),
    'bounds':{c:sha256_file(shared.lab/f'{c}-bounds.json') for c in ('iid','non-iid')},
    'defense_fitting_performed':False,'robust_operator':'Fixed 50-iteration-cap smoothed geometric-median reweighting of the same bounded deltas. Same mandatory/envelope gates. New convex weights are recorded; no malicious-client classification claim.','new_TPM_Quotes':0}
save(lab/'protocol-before-training.json',protocol)
(out/f'robust-{phase}-protocol.json').write_bytes((lab/'protocol-before-training.json').read_bytes())
(lab/'controller.py').write_bytes(Path(__file__).read_bytes())
counts=dict(generation_trainings=0,repeated_trainings=0,queries=0,completed_rounds=0,bounded_certificates=0)
results=[]
def worst(metric):return max([metric['complete_trigger']['asr'],*[v['asr'] for v in metric['component_triggers'].values()]])
for index,task in enumerate(tasks):
    name=f"case-{index:02d}-{task['cohort']}-{task['strategy']}-{task['mode']}"
    case=lab/'cases'/name;save(case/'task.json',task)
    gen,cal,env,models,rows,correct=context(task['cohort']);base=gen.initial
    policy=ClientEnvelopePolicy(cal,env);verifier=ClientEnvelopePolicy(cal,env)
    reference=read(shared.lab/f'{task["cohort"]}-bounds.json');bounded=True
    plan=DistributedBackdoorPlan.model_validate({**gen.cfg['attack_plan'],'seed':task['seed'],
        'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True)),'attack_rounds':list(range(1,11))})
    rounds=[];failure=None
    for number in range(1,16):
        active=task['mode']=='adaptive' and number<=10
        target=case/'rounds'/f'round-{number:03d}';save(target/'base-model.json',base)
        _,_,clean,clean_training=gen.execute(base,task['seed'],number);counts['generation_trainings']+=15
        if number in (1,15):
            _,_,repeated,_=gen.execute(base,task['seed'],number);assert repeated==clean;counts['repeated_trainings']+=15
        if active:
            _,_,poison,poison_training=gen.execute(base,task['seed'],number,plan);counts['generation_trainings']+=15
            if number in (1,15):
                _,_,repeated,_=gen.execute(base,task['seed'],number,plan);assert repeated==poison;counts['repeated_trainings']+=15
            for role,items in [('clean',clean),('poison',poison)]:
                for c,e in zip(gen.clients,items,strict=True):save(target/'endpoints'/role/f'{c}.json',e)
            ca=[arrays_from_export(e,np=np) for e in clean];pa=[arrays_from_export(e,np=np) for e in poison]
        candidates=[];transcript=[]
        for alpha in alphas if active else [0.]:
            exports=[model_with_arrays(clean[i],[a+alpha*(b.astype(float)-a) for a,b in zip(ca[i],pa[i],strict=True)]) if c in task['attackers'] else clean[i] for i,c in enumerate(gen.clients)] if active else clean
            ba=arrays_from_export(base,np=np);deltas=[model_delta(ba,arrays_from_export(e,np=np)) for e in exports]
            pin=hashlib.sha256(b''.join(derived_json_bytes(e) for e in [base,*exports])).hexdigest()
            trial=copy.deepcopy(policy);decision,risk,args=score(base,deltas,gen,cal,env,models,trial,number,pin)
            replay=copy.deepcopy(verifier);assert replay.step(number,risk,expected_previous_digest=replay.head,**args)==decision
            model,report,certificate=aggregate(base,exports,gen,decision['quarantine_current_round'],bounded,reference) if decision['supported'] else (None,None,None)
            metric=outcomes(model,rows,plan,correct,gen.deps) if model is not None else None
            objective=worst(metric) if metric else None;q=len(set(decision['quarantine_current_round'])&set(task['attackers']))
            transcript.append({'alpha':alpha,'supported':decision['supported'],'decision':decision,
                'feasible':model is not None,'worst_trigger_asr':objective,'attacker_quarantines':q,
                'full_trigger_asr':metric['complete_trigger']['asr'] if metric else None,
                'component_asr':{c:v['asr'] for c,v in metric['component_triggers'].items()} if metric else None})
            if active:counts['queries']+=1
            if model is not None:candidates.append(((objective,-q,alpha),alpha,exports,trial,replay,decision,model,report,certificate,metric))
        save(target/'query-transcript.json',transcript)
        if not candidates:
            failure={'round':number,'reason':'unsupported context or quorum loss','all_candidates_supported':all(t['supported'] for t in transcript)}
            save(target/'failure.json',failure);print(json.dumps({'case':name,'failure':failure}),flush=True);break
        _,alpha,exports,policy,verifier,decision,model,report,certificate,metric=max(candidates,key=lambda c:c[0])
        for c,e in zip(gen.clients,exports,strict=True):save(target/'updates'/f'{c}.json',e)
        duplicate,rpt,cert=aggregate(base,[read(target/'updates'/f'{c}.json') for c in gen.clients],gen,decision['quarantine_current_round'],bounded,reference)
        assert duplicate==model and rpt==report and cert==certificate
        assert outcomes(duplicate,rows,plan,correct,gen.deps)==metric
        save(target/'decision.json',decision);save(target/'global-model.json',model)
        if report is not None:
            save(target/'bounded-derivation.json',report);save(target/'removal-certificate.json',certificate)
            counts['bounded_certificates']+=len(certificate['per_client'])
        qset=set(decision['quarantine_current_round']);active_ids=set(task['attackers']) if active and alpha!=0 else set()
        row={'round':number,'alpha':alpha,'attack_active':active,'actual_manipulated_clients':sorted(active_ids),
            'quarantined':sorted(qset),'currently_clean_exclusions':len(qset-active_ids),
            'worst_trigger_asr':worst(metric),'validation':metric,
            'clean_endpoint_training':clean_training,'poison_endpoint_training':poison_training if active else None}
        save(target/'round.json',row);rounds.append(row);counts['completed_rounds']+=1;base=model
        print(json.dumps({'case':name,'round':number,'alpha':alpha,'worst_ASR':row['worst_trigger_asr'],'full_ASR':metric['complete_trigger']['asr']}),flush=True)
    gen.close(case);results.append({'name':name,'task':task,'complete':len(rounds)==15,'failure':failure,
        'rounds':rounds,'manifest_sha256':sha256_file(case/'manifest.json')})
    (lab/'progress.json').write_text(json.dumps({'completed_cases':len(results),'total_cases':len(tasks),'counts':counts},sort_keys=True)+'\n')
save(lab/'results.json',{'protocol_sha256':sha256_file(lab/'protocol-before-training.json'),'cases':results,'counts':counts})
(out/f'robust-{phase}-results.json').write_bytes((lab/'results.json').read_bytes())
print('ROBUST COMPARISON COMPLETE',json.dumps(counts),flush=True)
