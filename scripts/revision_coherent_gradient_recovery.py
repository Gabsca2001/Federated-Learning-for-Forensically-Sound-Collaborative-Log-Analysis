"""One linked clean recovery using all previously reserved root rows."""
from pathlib import Path
from collections import Counter
import argparse,json
import numpy as np
import revision_coherent_gradient_pilot as pilot
from coherent_gradient_protocol import *
from coherent_gradient_recovery import resume_after_root_expansion
from reference_objective_diagnostic import matched_root_weights
from revision_study_data import read,Generator
from revision_dba_experiment import save,authenticate,model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import dependencies,arrays_from_export

R=pilot.R;PRIMARY=pilot.D;D=R/'results/admission/revision-coherent-gradient-recovery-v1'

def locks():
    return {str(p.relative_to(R)):sha256_file(p) for p in (R/'scripts/coherent_gradient_recovery.py',R/'scripts/revision_coherent_gradient_recovery.py',R/'tests/test_coherent_gradient_recovery.py')}
def check(p):
    pp=read(PRIMARY/'protocol-before-clean-training.json');op,old=pilot.check(pp)
    assert locks()==p['source_locks'] and sha256_file(PRIMARY/'protocol-before-clean-training.json')==p['primary_protocol_sha256']
    closure=read(PRIMARY/'training-closure.json');assert closure['evidence_manifest_sha256']==p['primary_manifest_sha256']
    authenticate(PRIMARY/'evidence',p['primary_manifest_sha256'])
    return pp,op,old
def guard():
    s=pilot.guard();fs=__import__('os').statvfs('/mnt/c')
    used=pilot.allocated(PRIMARY)+pilot.allocated(pilot.O/'published')+pilot.allocated(D)+pilot.allocated(pilot.O/'recovery')
    assert used<64*1024**2 and fs.f_bavail*fs.f_frsize>=8*1024**3
    return {'host_free_bytes':fs.f_bavail*fs.f_frsize,'combined_pilot_recovery_allocated_bytes':used}

def prepare():
    assert not D.exists();pp=read(PRIMARY/'protocol-before-clean-training.json');op,old=pilot.check(pp)
    v=read(PRIMARY/'verification.json');assert v['status']=='verified_clean_pilot'
    histories=[r for r in read(PRIMARY/'training-closure.json')['histories'] if not r['complete'] and r['task']['method']=='coherent_fltrust']
    assert len(histories)==2
    p={'profile':'coherent-gradient-root-expansion-recovery-v1','source_locks':locks(),
       'primary_protocol_sha256':sha256_file(PRIMARY/'protocol-before-clean-training.json'),
       'primary_manifest_sha256':read(PRIMARY/'training-closure.json')['evidence_manifest_sha256'],
       'histories':[h['task'] for h in histories],'root_ids':op['root_pool_ids'],
       'policy':'One explicit linked policy revision. On each recorded pause, add all12 remaining reserved root rows, preserving all old rows. Same parent,loss,eta,clients and quorum10. Fresh context bindings. No second expansion or fallback.',
       'selection':'Both original paused clean histories. Full60-row pool fixed before recovery gradient computation; no search over additional subsets and no attack metrics.',
       'qualification':'Both linked branches must reach15 committed rounds with no new pause and <=.02 F1 loss versus original coherent-FedAvg at10/15. This does not rewrite the primary four-of-six result or constitute independent confirmation.',
       'scope':'Clean-only recovery test; original60 rows were already excluded from evaluation. No newly acquired external root, fresh TPM, production integration, attack or test inference.',
       'storage_before':guard()}
    D.mkdir();save(D/'protocol-before-recovery.json',p);print(json.dumps({'recovery_branches':len(histories),'root_rows':60,'expansion_budget':1}))

def execute(task,p,pp,op,old,deps,expected=None):
    source=read(PRIMARY/'evidence/histories'/task['name']/'result.json');assert source['state']['phase']=='paused'
    initial=read(PRIMARY/'evidence/histories'/task['name']/'last-committed-checkpoint.json') if source['committed_rounds'] else read(Path(pp['initial_model_path']))
    assert pilot.old_study.export_digest(initial)==source['state']['parent_model_sha256']
    validation=read(Path(old['training']['validation_path']))['rows']['validation'];byid={r['window_id']:r for r in validation}
    evaluation=[r for r in validation if r['window_id'] not in set(op['root_pool_ids'])]
    old_ids=op['root_draws'][str(task['root_seed'])];old_rows=[byid[i] for i in old_ids];new_rows=[byid[i] for i in p['root_ids']]
    target=pp['loss_contract']['normalized_target_class_mass']
    old_manifest={'source_validation_sha256':old['training']['validation_sha256'],'window_ids':old_ids,
        'weights':matched_root_weights(target,Counter(r['label'] for r in old_rows)),'loss_contract':pp['loss_contract_sha256']}
    new_manifest={**old_manifest,'window_ids':p['root_ids'],'weights':matched_root_weights(target,Counter(r['label'] for r in new_rows))}
    paused_context=source['journal'][-1]['event']['context'];pid=sha256_file(D/'protocol-before-recovery.json')
    state,proof=resume_after_root_expansion(source['state'],paused_context,old_manifest,new_manifest,pid)
    assert len(proof['additional_root_ids'])==12
    rows,_,_=pilot.data_source.seed_data(task['seed'],initial['class_names']);clients=sorted(rows);model=initial;journal=[]
    for number in range(state['last_committed_round']+1,pilot.HORIZON+1):
        guard();base=arrays_from_export(model,np=np)
        context=make_context(parent_model_sha256=pilot.old_study.export_digest(model),base_tensor_digest=digest(array_record([a.astype(float) for a in base])),
            round_number=number,attempt_id=f"linked-recovery-{task['name']}-{number:03d}",protocol_sha256=pid,
            loss_contract_sha256=pp['loss_contract_sha256'],roster=clients,method='coherent_fltrust',root_reference_sha256=digest(new_manifest))
        updates={};losses={}
        for c in clients:
            delta,loss=pilot.gradient_step(model,rows[c],pp['loss_contract']['client_effective_class_weights'],deps)
            updates[c]=update_record(c,context,delta,len(rows[c]),True);losses[c]=loss
        if not journal:
            assert {c:u['delta_digest'] for c,u in updates.items()}==source['journal'][-1]['event']['input_delta_digests']
        rd,rl=pilot.gradient_step(model,new_rows,new_manifest['weights'],deps)
        root={'context_digest':context['context_digest'],'reference_sha256':digest(new_manifest),'delta':rd,'delta_digest':delta_digest(rd)}
        params,event=assess_round(base,updates,root,context);verify_round(base,updates,root,context,event)
        before=dict(state);next_model=model_with_arrays(model,params) if params is not None else None
        checkpoint=pilot.old_study.export_digest(next_model) if next_model is not None else None
        state=transition(state,event,checkpoint)
        row={'event':event,'state_before':before,'state_after':state,'root_delta_digest':root['delta_digest'],'root_loss':rl,
             'client_common_losses':losses,'exported_checkpoint_sha256':checkpoint}
        if next_model is not None:
            row['clean_validation']=pilot.metric(next_model,evaluation,deps);model=next_model
        else:row['retained_parent_validation']=pilot.metric(model,evaluation,deps)
        journal.append(row)
        if expected is not None:assert row==expected['journal'][len(journal)-1]
        print(json.dumps({'recovery_history':task['name'],'round':number,'replay':expected is not None,'decision':event['decision'],'positive_contributors':event['positive_contributors']}),flush=True)
        if state['phase']=='paused':break
    result={'task':task,'primary_parent_state':source['state'],'recovery_proof':proof,'new_root_manifest':new_manifest,
        'state':state,'journal':journal,'complete':state['last_committed_round']==pilot.HORIZON,'committed_rounds':state['last_committed_round'],
        'last_committed_model_sha256':pilot.old_study.export_digest(model),'test_inference':False,'attack_inference':False}
    if expected is not None:assert result==expected
    return result,model

def run():
    p=read(D/'protocol-before-recovery.json');pp,op,old=check(p);assert not (D/'evidence').exists();save(D/'evidence/protocol.json',p)
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    for task in p['histories']:
        result,model=execute(task,p,pp,op,old,deps);folder=D/'evidence/histories'/task['name']
        save(folder/'result.json',result)
        if result['committed_rounds']:save(folder/'last-committed-checkpoint.json',model)
    check(p);Generator.close(D/'evidence');save(D/'closure.json',{'evidence_manifest_sha256':sha256_file(D/'evidence/manifest.json'),'protocol_sha256':sha256_file(D/'protocol-before-recovery.json')})

def verify():
    p=read(D/'protocol-before-recovery.json');pp,op,old=check(p);cl=read(D/'closure.json')
    authenticate(D/'evidence',cl['evidence_manifest_sha256']);assert cl['protocol_sha256']==sha256_file(D/'protocol-before-recovery.json')
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True);cases=[]
    for task in p['histories']:
        expected=read(D/'evidence/histories'/task['name']/'result.json');result,model=execute(task,p,pp,op,old,deps,expected)
        if result['committed_rounds']:assert model==read(D/'evidence/histories'/task['name']/'last-committed-checkpoint.json')
        baseline=read(PRIMARY/'evidence/histories'/f"s{task['seed']}-coherent-fedavg/result.json")
        refs={r['state_after']['last_committed_round']:r for r in baseline['journal'] if r['event']['decision']=='commit'}
        actual={r['state_after']['last_committed_round']:r for r in result['journal'] if r['event']['decision']=='commit'};points=[]
        for n in (10,15):
            defined=n in actual and n in refs;loss=refs[n]['clean_validation']['macro_f1']-actual[n]['clean_validation']['macro_f1'] if defined else None
            points.append({'round':n,'defined':defined,'f1_loss':loss,'passes':defined and loss<=.02})
        cases.append({'history':task['name'],'complete':result['complete'],'committed_rounds':result['committed_rounds'],
            'first_recovery_positive_contributors':result['journal'][0]['event']['positive_contributors'],'final_phase':result['state']['phase'],
            'endpoints':points,'qualified':result['complete'] and all(z['passes'] for z in points)})
    check(p);save(D/'verification.json',{'status':'verified_linked_recovery','branches':cases,'all_recovery_branches_qualify':all(c['qualified'] for c in cases),
        'primary_result_rewritten':False,'quorum_lowered':False,'extra_root_rows_per_branch':12,'full_replay':True,
        'software_experiment_manifest_authenticated':True,'fresh_TPM_attestation':False,'test_inference':False,'new_attack_inference':False,'storage_after':guard()})
    print(json.dumps(read(D/'verification.json'),indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('prepare','run','verify'));args=parser.parse_args()
    {'prepare':prepare,'run':run,'verify':verify}[args.phase]()
