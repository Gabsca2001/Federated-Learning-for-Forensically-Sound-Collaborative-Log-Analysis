"""Fresh clean multiround research pilot; fixed quorum and explicit pauses."""
from __future__ import annotations
import os
for k in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ.setdefault(k,'1')
from pathlib import Path
from collections import Counter
import argparse,json,time,hashlib
import numpy as np
from coherent_gradient_protocol import *
from reference_objective_diagnostic import matched_root_weights
import revision_reference_coherence as data_source
import revision_fltrust_screen as old_study
from revision_study_data import read,Generator
from revision_dba_experiment import save,model_with_arrays,evaluate,authenticate
from fl_forensics.federated_model import dependencies,arrays_from_export
from fl_forensics.secure_round import _model_from_export
from fl_forensics.canonical import sha256_file

R=Path(__file__).resolve().parents[1]
D=R/'results/admission/revision-coherent-gradient-pilot-v1'
O=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'coherent-gradient-20261107')
ETA=.001;HORIZON=15

def allocated(p):return sum(f.stat().st_blocks*512 for f in p.rglob('*') if f.is_file()) if p.exists() else 0
def guard():
    s=os.statvfs('/mnt/c');free=s.f_bavail*s.f_frsize;used=allocated(D)+allocated(O/'published')
    if free<8*1024**3 or used>64*1024**2:raise RuntimeError('Fixed storage budget/floor failed')
    return {'host_free_bytes':free,'new_result_allocated_bytes':used}
def locks():
    paths=[R/'scripts'/n for n in ('coherent_gradient_protocol.py','revision_coherent_gradient_pilot.py','reference_objective_diagnostic.py',
        'fltrust_screen_aggregation.py','revision_reference_coherence.py','revision_fltrust_screen.py','revision_study_data.py','revision_dba_experiment.py')]
    paths.append(R/'tests/test_coherent_gradient_protocol.py')
    return {str(f.relative_to(R)):sha256_file(f) for f in paths}
def check(p):
    assert locks()==p['source_locks'],'New protocol source drift'
    op=read(R/'results/admission/revision-fltrust-screen-v1/protocol-before-root-training.json');old=old_study.check(op)
    assert sha256_file(R/'results/admission/revision-fltrust-screen-v1/protocol-before-root-training.json')==p['prior_root_protocol_sha256']
    return op,old

def prepare():
    assert not D.exists(),'Preserve previous pilot';storage=guard()
    op=read(R/'results/admission/revision-fltrust-screen-v1/protocol-before-root-training.json');old=old_study.check(op)
    initial=read(Path(old['training']['base_model_path']));classes=initial['class_names'];population=None;weights=None
    for seed in (6116104,6116105):
        rows,counts,w=data_source.seed_data(seed,classes)
        totals={c:sum(v[c] for v in counts.values()) for c in classes}
        if population is not None:assert population==totals and weights==w
        population=totals;weights=w
    n=sum(population.values());mean_weight=sum(population[c]*weights[c] for c in classes)/n
    effective={c:weights[c]/mean_weight for c in classes}
    target={c:population[c]/n*effective[c] for c in classes}
    loss={'profile':'common-pooled-weighted-arithmetic-mean-v1','population_class_counts':population,
        'original_class_weights':weights,'population_mean_weight':mean_weight,'client_effective_class_weights':effective,
        'normalized_target_class_mass':target,'client_loss':'mean_j[(w_y/population_mean_weight)*cross_entropy_j]; no client-local weight-sum denominator',
        'root_loss':'mean_j[(target_class_mass_y/root_frequency_y)*cross_entropy_j]',
        'gradient':'Float64 full-batch, eval mode with dropout disabled, single descent step eta=.001 for both roles.',
        'metadata_origin':'Pinned original simulation preprocessing population counts/weights; assumed trusted aggregate metadata, not unauthenticated per-round class claims.'}
    tasks=[]
    for seed in (6116104,6116105):
        tasks.append({'name':f's{seed}-coherent-fedavg','seed':seed,'method':'coherent_fedavg','root_seed':None})
        for root_seed in op['root_seeds']:
            tasks.append({'name':f's{seed}-coherent-fltrust-root{root_seed}','seed':seed,'method':'coherent_fltrust','root_seed':root_seed})
    p={'profile':PROFILE,'source_locks':locks(),'prior_root_protocol_sha256':sha256_file(R/'results/admission/revision-fltrust-screen-v1/protocol-before-root-training.json'),
        'loss_contract':loss,'loss_contract_sha256':digest(loss),'tasks':tasks,'maximum_committed_rounds':HORIZON,'learning_rate':ETA,
        'minimum_positive_contributors':QUORUM,'initial_model_path':old['training']['base_model_path'],'initial_model_sha256':old['training']['base_model_sha256'],
        'availability':'Stop on first failed quorum/undefined reference. Parent and committed round counter remain unchanged. No automatic retry with identical evidence, root-only fallback, lower quorum or reuse of stale gradients.',
        'comparison':'Two separately trained coherent FedAvg baselines shared within their seed; six FLTrust histories. Every committed round recomputes all gradients from its current parent.',
        'qualification':'All six FLTrust histories must complete15 committed rounds, change parameters at least once and lose at most.02 macro-F1 against their own seed coherent-FedAvg baseline at rounds10 and15. Any pause fails availability; missing endpoints stay undefined.',
        'scope':'Exploratory reused Data24 partitions/root/evaluation; no new attacker training, attack/test inference or independent-data claim. Fresh coherent gradient histories, not historical Adam-delta replay or full original FLTrust reproduction.',
        'trust':'Software research assumption for prerequisite gates; fresh context/content bindings are checked. No fresh TPM Quote, client signature or production M5 gradient adapter is claimed.',
        'sampling':'Use the previously frozen three48-row roots from the60-row pool; evaluate only the disjoint3163 rows. Draws overlap and two baseline histories are not three independent replicates.',
        'storage':'Only gradient digests/scalars, event journals and final committed checkpoints. Full client tensors and datasets are not copied.',
        'maximum_new_output_bytes':64*1024**2,'minimum_host_free_bytes':8*1024**3,'storage_before':storage}
    D.mkdir();save(D/'protocol-before-clean-training.json',p)
    print(json.dumps({'prepared_clean_histories':len(tasks),'maximum_committed_rounds_each':15,'quorum':10,'storage':storage}),flush=True)

def gradient_step(initial,rows,class_weights,deps):
    torch=deps[1];model=_model_from_export(initial,torch=torch,np=np).double();model.eval()
    assert [n for n,_ in model.named_parameters()]==[x['name'] for x in initial['parameters']]
    features=torch.tensor([r['features'] for r in rows],dtype=torch.float64)
    labels=torch.tensor([initial['class_names'].index(r['label']) for r in rows],dtype=torch.long)
    weights=torch.tensor([class_weights[c] for c in initial['class_names']],dtype=torch.float64)
    gradients,loss=common_loss_gradient(model,features,labels,weights,torch)
    return [-ETA*g for g in gradients],loss

def metric(model,rows,deps):
    v=evaluate(model,rows,deps);cm=v['confusion_matrix']['values'];f=[]
    for i in range(len(cm)):
        den=sum(cm[i])+sum(cm[j][i] for j in range(len(cm)));f.append(2*cm[i][i]/den if den else 0.)
    assert abs(sum(f)/len(f)-v['macro_f1_all_model_classes'])<1e-12
    return {'macro_f1':v['macro_f1_all_model_classes'],'accuracy':v['accuracy'],'confusion_matrix':v['confusion_matrix']}

def execute_history(task,p,op,old,deps,*,expected=None,write=True):
    guard();initial=read(Path(p['initial_model_path']));assert old_study.export_digest(initial)==p['initial_model_sha256']
    rows,counts,_=data_source.seed_data(task['seed'],initial['class_names']);clients=sorted(rows)
    validation=read(Path(old['training']['validation_path']))['rows']['validation'];byid={r['window_id']:r for r in validation}
    pool=set(op['root_pool_ids']);evaluation=[r for r in validation if r['window_id'] not in pool];assert len(evaluation)==3163
    root_rows=None;root_weights=None;root_ref=None
    if task['root_seed'] is not None:
        root_ids=op['root_draws'][str(task['root_seed'])];root_rows=[byid[i] for i in root_ids]
        root_weights=matched_root_weights(p['loss_contract']['normalized_target_class_mass'],Counter(r['label'] for r in root_rows))
        root_ref=digest({'source_validation_sha256':old['training']['validation_sha256'],'window_ids':root_ids,'weights':root_weights,'loss_contract':p['loss_contract_sha256']})
    protocol_hash=sha256_file(D/'protocol-before-clean-training.json')
    state=initial_state(old_study.export_digest(initial),protocol_hash);model=initial;journal=[];changed=0
    for number in range(1,HORIZON+1):
        guard();base=arrays_from_export(model,np=np)
        context=make_context(parent_model_sha256=old_study.export_digest(model),base_tensor_digest=digest(array_record([a.astype(float) for a in base])),
            round_number=number,attempt_id=f"{task['name']}-attempt-{number:03d}",protocol_sha256=protocol_hash,
            loss_contract_sha256=p['loss_contract_sha256'],roster=clients,method=task['method'],root_reference_sha256=root_ref)
        updates={};losses={}
        for c in clients:
            delta,loss=gradient_step(model,rows[c],p['loss_contract']['client_effective_class_weights'],deps)
            updates[c]=update_record(c,context,delta,len(rows[c]),True);losses[c]=loss
        root=None;root_loss=None
        if root_rows is not None:
            delta,root_loss=gradient_step(model,root_rows,root_weights,deps)
            root={'context_digest':context['context_digest'],'reference_sha256':root_ref,'delta':delta,'delta_digest':delta_digest(delta)}
        params,event=assess_round(base,updates,root,context)
        verified=verify_round(base,updates,root,context,event)
        if params is not None:
            for a,b in zip(params,verified,strict=True):np.testing.assert_array_equal(a,b)
        before=dict(state);next_model=model_with_arrays(model,params) if params is not None else None
        export_sha=old_study.export_digest(next_model) if next_model is not None else None
        state=transition(state,event,export_sha)
        row={'attempt_number':number,'state_before':before,'event':event,'root_delta_digest':root['delta_digest'] if root else None,
            'root_loss':root_loss,'client_common_losses':losses,'state_after':state,'exported_checkpoint_sha256':export_sha}
        if next_model is not None:
            row['parameters_changed']=export_sha!=context['parent_model_sha256'];changed+=row['parameters_changed']
            actual=arrays_from_export(next_model,np=np)
            row['float32_export_rounding_norms']=[float(np.linalg.norm(a.astype(float)-b)) for a,b in zip(actual,params,strict=True)]
            row['clean_validation']=metric(next_model,evaluation,deps);model=next_model
        else:
            assert state['last_committed_round']==before['last_committed_round'] and state['parent_model_sha256']==before['parent_model_sha256']
            row['retained_parent_validation']=metric(model,evaluation,deps)
        journal.append(row)
        if expected is not None:assert row==expected['journal'][len(journal)-1],('History replay mismatch',task['name'],number)
        print(json.dumps({'history':task['name'],'replay':not write,'attempt':number,'decision':event['decision'],
            'positive_contributors':event['positive_contributors'],'committed_rounds':state['last_committed_round']}),flush=True)
        if state['phase']=='paused':break
    result={'task':task,'complete':state['last_committed_round']==HORIZON,'attempts':len(journal),
        'committed_rounds':state['last_committed_round'],'parameter_change_rounds':changed,'state':state,'journal':journal,
        'last_committed_model_sha256':old_study.export_digest(model),'retained_initial_parent':state['last_committed_round']==0,
        'new_TPM_quotes':0,'test_inference':False,'attack_inference':False}
    if expected is not None:assert result==expected
    if write:
        folder=D/'evidence/histories'/task['name'];save(folder/'result.json',result)
        if state['last_committed_round']>0:save(folder/'last-committed-checkpoint.json',model)
    return result,model

def run():
    p=read(D/'protocol-before-clean-training.json');op,old=check(p)
    assert not (D/'evidence').exists(),'Preserve interrupted/completed pilot'
    save(D/'evidence/protocol.json',p)
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    histories=[]
    for task in p['tasks']:
        result,_=execute_history(task,p,op,old,deps);histories.append(result);guard()
    check(p);Generator.close(D/'evidence')
    closure={'status':'clean_training_terminal','histories':[{'task':r['task'],'complete':r['complete'],'committed_rounds':r['committed_rounds'],'attempts':r['attempts']} for r in histories],
        'protocol_sha256':sha256_file(D/'protocol-before-clean-training.json'),'evidence_manifest_sha256':sha256_file(D/'evidence/manifest.json'),'storage_after':guard()}
    save(D/'training-closure.json',closure);print(json.dumps(closure,indent=2))

def verify():
    p=read(D/'protocol-before-clean-training.json');op,old=check(p);closure=read(D/'training-closure.json')
    assert closure['protocol_sha256']==sha256_file(D/'protocol-before-clean-training.json')
    authenticate(D/'evidence',closure['evidence_manifest_sha256'])
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    results=[]
    for task in p['tasks']:
        expected=read(D/'evidence/histories'/task['name']/'result.json')
        result,model=execute_history(task,p,op,old,deps,expected=expected,write=False)
        if result['committed_rounds']>0:assert model==read(D/'evidence/histories'/task['name']/'last-committed-checkpoint.json')
        results.append(result)
    baseline={r['task']['seed']:r for r in results if r['task']['method']=='coherent_fedavg'}
    checks=[]
    for r in results:
        if r['task']['method']!='coherent_fltrust':continue
        defined={row['state_after']['last_committed_round']:row for row in r['journal'] if row['event']['decision']=='commit'}
        controls={row['state_after']['last_committed_round']:row for row in baseline[r['task']['seed']]['journal'] if row['event']['decision']=='commit'}
        points=[]
        for n in (10,15):
            valid=n in defined and n in controls
            loss=controls[n]['clean_validation']['macro_f1']-defined[n]['clean_validation']['macro_f1'] if valid else None
            points.append({'round':n,'defined':valid,'f1_loss':loss,'passes':valid and loss<=.02})
        checks.append({'history':r['task']['name'],'complete':r['complete'],'committed_rounds':r['committed_rounds'],
            'parameter_change_rounds':r['parameter_change_rounds'],'endpoints':points,
            'qualified':r['complete'] and r['parameter_change_rounds']>0 and all(x['passes'] for x in points)})
    record={'status':'verified_clean_pilot','histories':len(results),'committed_rounds':sum(r['committed_rounds'] for r in results),
        'attempts':sum(r['attempts'] for r in results),'paused_histories':sum(r['state']['phase']=='paused' for r in results),
        'complete_fltrust_histories':sum(r['complete'] for r in results if r['task']['method']=='coherent_fltrust'),
        'planned_fltrust_histories':6,'fltrust_qualification':checks,'all_clean_guards_pass':all(c['qualified'] for c in checks),
        'actual_new_parent_training_each_commit':True,'full_history_replay':True,'software_experiment_manifest_authenticated':True,
        'fresh_TPM_attestation':False,'test_inference':False,'new_attack_inference':False,'storage_after':guard()}
    check(p);save(D/'verification.json',record);print(json.dumps(record,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('prepare','run','verify'));args=parser.parse_args()
    {'prepare':prepare,'run':run,'verify':verify}[args.phase]()
