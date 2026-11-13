"""Separate Byzantine endpoint DBA study; original one-step failures are preserved."""
from pathlib import Path
from collections import Counter
import argparse,json,time
import numpy as np
import revision_coherent_gradient_pilot as pilot
from coherent_gradient_protocol import *
from coherent_dba_selection import poison_commitment,worst_asr
from endpoint_attack_selection import FACTORS as ALPHAS,select_endpoint_query as select_query,poisoned_endpoint
from reference_objective_diagnostic import matched_root_weights
from revision_study_data import read,Generator
from revision_dba_experiment import save,authenticate,outcomes,predict,model_with_arrays,environment
from fl_forensics.federated_model import dependencies,arrays_from_export
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows
from fl_forensics.canonical import sha256_file

R=pilot.R;D=R/'results/revision-coherent-endpoint-dba-v1'
O=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/coherent-dba-20261107/endpoint-study')
ASSIGNMENTS={6116104:['client01','client06','client13'],6116105:['client05','client10','client14']}
MODES=('clean','distributed','complete-trigger')
def allocated(p):return pilot.allocated(p)
def guard():
    s=__import__('os').statvfs('/mnt/c');free=s.f_bavail*s.f_frsize;used=allocated(D)+allocated(O/'published')
    if free<8*1024**3 or used>64*1024**2:raise RuntimeError('Fixed space guard failed')
    return {'host_free_bytes':free,'output_allocated_bytes':used}
def locks():
    paths=[R/'scripts'/n for n in ('coherent_dba_selection.py','endpoint_attack_selection.py','revision_coherent_endpoint_dba.py','coherent_gradient_protocol.py',
        'revision_coherent_gradient_pilot.py','fltrust_screen_aggregation.py','revision_dba_experiment.py')]
    paths.extend([R/'tests/test_coherent_dba_selection.py',R/'tests/test_endpoint_attack_selection.py'])
    return {str(f.relative_to(R)):sha256_file(f) for f in paths}
def check(p):
    assert locks()==p['source_locks']
    pp=read(pilot.D/'protocol-before-clean-training.json');op,old=pilot.check(pp)
    assert sha256_file(pilot.D/'protocol-before-clean-training.json')==p['coherent_source_protocol_sha256']
    assert read(R/'results/revision-coherent-gradient-recovery-v1/verification.json')['all_recovery_branches_qualify']
    return pp,op,old

def prepare():
    assert not D.exists();storage=guard();pp=read(pilot.D/'protocol-before-clean-training.json');op,old=pilot.check(pp)
    recovered=read(R/'results/revision-coherent-gradient-recovery-v1/verification.json');assert recovered['all_recovery_branches_qualify']
    tasks=[]
    for mode in MODES:
        for seed,attackers in ASSIGNMENTS.items():
            for method in ('coherent_fedavg','coherent_fltrust'):
                tasks.append({'name':f's{seed}-{method}-{mode}','seed':seed,'attackers':attackers,'method':method,'mode':mode})
    p={'profile':'coherent60-root-byzantine-endpoint-dba-v1','source_locks':locks(),'coherent_source_protocol_sha256':sha256_file(pilot.D/'protocol-before-clean-training.json'),
       'tasks':tasks,'horizon':15,'attack_rounds':list(range(1,11)),'clean_continuation_rounds':list(range(11,16)),
       'methods':['coherent_fedavg','coherent_fltrust'],'root_rows':60,'root_ids':op['root_pool_ids'],
       'root_policy':'The complete already reserved60-row root is active from the start. No further reserved root exists. Failed quorum pauses without retry/fallback/checkpoint. This is the validated post-expansion ready profile, not an initial48-root policy.',
       'clean_controls':'Four newly executed clean histories; must reproduce known coherent baseline/full60 recovery checkpoints. They are mechanism replications, not independent clean validation.',
       'training':'One full-batch float64 evaluation-mode gradient at each CURRENT parent,common globally normalized weighted arithmetic-mean loss,eta.001,exportfloat32. Honest updates are gradients; malicious updates are explicitly forged endpoint vectors, never labelled honest gradients.',
       'loss_contract':pp['loss_contract'],'loss_contract_sha256':pp['loss_contract_sha256'],
       'attacker_budget':'Three fixed identities,ceil(.50*n_i) hash-ranked rows each,standardized coordinates13/17/24=12,target benign,rounds1-10. Distributed assigns one component per identity; complete-trigger assigns all three. Row budgets match, feature-edit budgets differ.',
       'adaptive_alphas':list(ALPHAS),'adaptive_definition':'Poisoned10-epoch Adam endpoint minus current parent. Export clean_gradient_delta+alpha*(poison_endpoint_delta-clean_gradient_delta) with six fixed factors. All attacked modes are defender-adaptive Byzantine endpoint submissions, not pure data-only SGD or TPM-attested training.',
       'adaptive_selection':'Six fixed queries against each ACTUAL defender; among defined candidates with at most.05 macro-F1 loss versus its own same-round clean branch, maximize worst(full,single-components) ASR,then largest alpha. No feasible query selects explicit unmodified alpha0,which may still pause or exceed utility after prior contamination.',
       'oracle_access':'Privileged reused-validation and own matched-clean oracle. No production attacker access or secret-root/adaptive-security guarantee is implied. Undefined candidate outputs are not assigned zero ASR; blocked queries are retained as availability diagnostics.',
       'effectiveness':'Raw coherent-FedAvg control must show >=.20 paired worst-trigger ASR increase with <=.05 clean F1 loss at the SAME committed round. Ineffective controls remain reported and cannot establish successful mitigation.',
       'evaluation':'Only the3163 validation rows disjoint from all60 root examples. Labels unchanged for evaluation triggers. Full trigger and all three individual components; no two-component trigger claim. Test remains unpredicted. Data,partitions and warm start already observed: exploratory.',
       'admission_and_influence':'All15 mandatory trust facts are assumed passed in software. Minimum10 positive coefficient contributors. Admission mass remains distinct from zero-scored coefficient mass. No1/3 group budget or80% sample-mass retention guarantee is imposed on this FLTrust rule.',
       'trust_scope':'No fresh TPM Quote or client signature; no production M5 gradient adapter or proof that measured training permits Byzantine scaling is claimed.',
       'development':'Chosen after a separate warm-parent feasibility probe. Keep both predefined seeds and distributed/full variants, including ineffective outcomes. Development is not independent confirmation.',
       'attacker_optimizer':{'name':'Adam','epochs':10,'batch_size':128,'learning_rate':.001},
       'development_probe_protocol_sha256':sha256_file(R/'results/revision-coherent-endpoint-feasibility-v1/protocol-before-endpoint-probe.json'),
       'original_one_step_protocol_sha256':sha256_file(R/'results/revision-coherent-dba-v1/protocol-before-training.json'),
       'environment':environment(),'maximum_combined_output_bytes':64*1024**2,'minimum_host_free_bytes':8*1024**3,
       'storage':'Metadata,journals,query metrics and final committed checkpoints only; poisoning row-ID lists are committed by digest rather than copied. No duplicated datasets or per-round client tensors.',
       'storage_before':storage}
    D.mkdir();save(D/'protocol-before-training.json',p);print(json.dumps({'prepared_histories':len(tasks),'adaptive_queries_per_round':6,'storage':storage}),flush=True)

def compact(v):
    return {**{k:x for k,x in v.items() if k!='clean'},'clean':{k:v['clean'][k] for k in ('accuracy','macro_f1_all_model_classes','per_class','confusion_matrix')}}
def plan_for(task):
    return DistributedBackdoorPlan(target_label='benign',client_components=dict(zip(task['attackers'],[[13],[17],[24]],strict=True)),
        trigger_values_decimal={'13':'12','17':'12','24':'12'},poisoned_fraction_decimal='.50',attack_rounds=list(range(1,11)),seed=task['seed'])
def clean_reference(task):return D/'evidence/histories'/f"s{task['seed']}-{task['method']}-clean/result.json"

def execute(task,p,pp,op,old,deps,*,expected=None,write=True):
    guard();model=read(Path(pp['initial_model_path']));rows,_,_=pilot.data_source.seed_data(task['seed'],model['class_names']);clients=sorted(rows)
    validation=read(Path(old['training']['validation_path']))['rows']['validation'];byid={r['window_id']:r for r in validation}
    pool=set(p['root_ids']);evaluation=[r for r in validation if r['window_id'] not in pool];assert len(evaluation)==3163
    root_rows=[byid[i] for i in p['root_ids']]
    root_weights=matched_root_weights(p['loss_contract']['normalized_target_class_mass'],Counter(r['label'] for r in root_rows))
    root_id=digest({'source_validation_sha256':old['training']['validation_sha256'],'window_ids':p['root_ids'],
        'weights':root_weights,'loss_contract':p['loss_contract_sha256']}) if task['method']=='coherent_fltrust' else None
    pid=sha256_file(D/'protocol-before-training.json');state=initial_state(pilot.old_study.export_digest(model),pid)
    initial_predictions,_=predict(model,evaluation,deps);correct=[x==r['label'] for x,r in zip(initial_predictions,evaluation,strict=True)]
    plan=plan_for(task);journal=[]
    controls=read(clean_reference(task)) if task['mode']!='clean' else None
    clean_by_round={r['round']:r['validation'] for r in controls['journal'] if r['event']['decision']=='commit'} if controls else {}
    if controls:assert controls['complete'],'Cannot evaluate attack against incomplete clean reference'
    for number in range(1,16):
        guard();start=time.perf_counter();base=arrays_from_export(model,np=np);active=task['mode']!='clean' and number<=10
        clean={};poison={};poison_records={};losses={};gradient_start=time.perf_counter()
        for c in clients:
            clean[c],losses[c]=pilot.gradient_step(model,rows[c],p['loss_contract']['client_effective_class_weights'],deps)
            if active and c in task['attackers']:
                changed,record=poison_local_rows(rows=rows[c],plan=plan,client_id=c,round_number=number,distributed=task['mode']!='complete-trigger')
                endpoint=poisoned_endpoint(model,changed,p['loss_contract']['client_effective_class_weights'],task['seed']+number*10000+int(c[6:])-1,deps)
                poison[c]=[a.astype(float)-b for a,b in zip(arrays_from_export(endpoint,np=np),base,strict=True)]
                poison_records[c]=poison_commitment(record)
            else:poison[c]=clean[c]
        gradient_seconds=time.perf_counter()-gradient_start;root=None;root_loss=None
        if root_id is not None:root,root_loss=pilot.gradient_step(model,root_rows,root_weights,deps)
        def attempt(alpha,label):
            deltas={c:(clean[c] if alpha==0 else poison[c] if alpha==1 else [a+alpha*(b-a) for a,b in zip(clean[c],poison[c],strict=True)]) if active and c in task['attackers'] else clean[c] for c in clients}
            context=make_context(parent_model_sha256=pilot.old_study.export_digest(model),base_tensor_digest=digest(array_record([a.astype(float) for a in base])),
                round_number=number,attempt_id=f"{task['name']}-r{number:03d}-{label}",protocol_sha256=pid,
                loss_contract_sha256=p['loss_contract_sha256'],roster=clients,method=task['method'],root_reference_sha256=root_id)
            updates={c:update_record(c,context,deltas[c],len(rows[c]),True) for c in clients}
            ref={'context_digest':context['context_digest'],'reference_sha256':root_id,'delta':root,'delta_digest':delta_digest(root)} if root is not None else None
            params,event=assess_round(base,updates,ref,context)
            next_model=model_with_arrays(model,params) if params is not None else None
            return params,event,next_model,updates,ref
        queries=[];selection=None;search_start=time.perf_counter()
        if active:
            for alpha in ALPHAS:
                params,event,candidate,_,_=attempt(alpha,f'query-{alpha:g}')
                m=outcomes(candidate,evaluation,plan,correct,deps) if candidate is not None else None
                queries.append({'alpha':alpha,'defined':candidate is not None,'positive_contributors':event['positive_contributors'],
                    'decision':event['decision'],'reasons':event['reasons'],'candidate_model_sha256':pilot.old_study.export_digest(candidate) if candidate else None,
                    'metrics':compact(m) if m else None})
            alpha,selection=select_query(queries,clean_by_round[number]['clean']['macro_f1_all_model_classes'])
        else:alpha=1. if active else 0.
        search_seconds=time.perf_counter()-search_start
        params,event,next_model,updates,ref=attempt(alpha,'selected')
        verify_round(base,updates,ref,event['context'],event)
        modified=[c for c in task['attackers'] if updates[c]['delta_digest']!=delta_digest(clean[c])] if active else []
        before=dict(state);checkpoint=pilot.old_study.export_digest(next_model) if next_model is not None else None
        state=transition(state,event,checkpoint)
        row={'round':number,'state_before':before,'state_after':state,'event':event,'selected_alpha':alpha,
            'actually_manipulated_clients':modified,'poisoning':poison_records,'client_clean_losses':losses,'root_loss':root_loss,
            'root_delta_digest':delta_digest(root) if root is not None else None,'queries':queries,'selection':selection,
            'exported_checkpoint_sha256':checkpoint}
        if next_model is not None:
            row['validation']=compact(outcomes(next_model,evaluation,plan,correct,deps))
            if task['mode']=='clean':
                if task['method']=='coherent_fedavg':known=read(pilot.D/'evidence/histories'/f"s{task['seed']}-coherent-fedavg/result.json")
                else:
                    previous_root=7110703 if task['seed']==6116104 else 7110701
                    known=read(R/'results/revision-coherent-gradient-recovery-v1/evidence/histories'/f"s{task['seed']}-coherent-fltrust-root{previous_root}/result.json")
                match=next(r for r in known['journal'] if r['event']['decision']=='commit' and r['state_after']['last_committed_round']==number)
                assert checkpoint==match['exported_checkpoint_sha256'],'Known clean numerical trajectory changed'
            model=next_model
        else:row['retained_parent_metrics']=compact(outcomes(model,evaluation,plan,correct,deps))
        if expected is not None:
            target={k:v for k,v in expected['journal'][len(journal)].items() if k!='timing'};assert row==target,('Replay mismatch',task['name'],number)
        row['timing']={'client_clean_and_poison_gradients_seconds':gradient_seconds,'adaptive_search_seconds':search_seconds,
            'whole_round_seconds':time.perf_counter()-start}
        if expected is not None:row['timing']=expected['journal'][len(journal)]['timing']
        journal.append(row)
        if number%5==0 or state['phase']=='paused':print(json.dumps({'history':task['name'],'replay':not write,'round':number,'decision':event['decision'],'alpha':alpha,'storage':guard()}),flush=True)
        if state['phase']=='paused':break
    result={'task':task,'complete':state['last_committed_round']==15,'committed_rounds':state['last_committed_round'],'state':state,'journal':journal,
        'last_committed_model_sha256':pilot.old_study.export_digest(model),'new_TPM_quotes':0,'test_inference':False}
    if expected is not None:assert result==expected
    if write:
        f=D/'evidence/histories'/task['name'];save(f/'result.json',result)
        if state['last_committed_round']:save(f/'last-committed-checkpoint.json',model)
    return result,model

def run():
    p=read(D/'protocol-before-training.json');pp,op,old=check(p);assert not (D/'evidence').exists();save(D/'evidence/protocol.json',p)
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True);results=[]
    for task in p['tasks']:
        r,_=execute(task,p,pp,op,old,deps);results.append({'task':task,'complete':r['complete'],'committed_rounds':r['committed_rounds']})
        guard()
    check(p);Generator.close(D/'evidence');save(D/'closure.json',{'protocol_sha256':sha256_file(D/'protocol-before-training.json'),
        'evidence_manifest_sha256':sha256_file(D/'evidence/manifest.json'),'histories':results,'test_inference':False})
    print(json.dumps({'status':'all_histories_terminal','histories':len(results),'complete':sum(r['complete'] for r in results),'storage':guard()},indent=2))

def verify():
    p=read(D/'protocol-before-training.json');pp,op,old=check(p);cl=read(D/'closure.json')
    assert cl['protocol_sha256']==sha256_file(D/'protocol-before-training.json');authenticate(D/'evidence',cl['evidence_manifest_sha256'])
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True);counts={'histories':0,'committed_rounds':0,'queries':0,'pauses':0}
    for task in p['tasks']:
        expected=read(D/'evidence/histories'/task['name']/'result.json');r,model=execute(task,p,pp,op,old,deps,expected=expected,write=False)
        if r['committed_rounds']:assert model==read(D/'evidence/histories'/task['name']/'last-committed-checkpoint.json')
        counts['histories']+=1;counts['committed_rounds']+=r['committed_rounds'];counts['queries']+=sum(len(row['queries']) for row in r['journal']);counts['pauses']+=r['state']['phase']=='paused'
    check(p);save(D/'verification.json',{'status':'full_trajectory_and_query_replay_verified',**counts,'software_manifest_authenticated':True,
        'same_implementation_replay':True,'fresh_TPM_attestation':False,'test_inference':False,'storage_after':guard()})
    print(json.dumps(read(D/'verification.json'),indent=2))

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('phase',choices=('prepare','run','verify'));arg=a.parse_args()
    {'prepare':prepare,'run':run,'verify':verify}[arg.phase]()
