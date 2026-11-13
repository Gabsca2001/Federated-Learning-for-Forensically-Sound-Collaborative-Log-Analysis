"""Bounded development probe of explicit Byzantine endpoint submissions."""
from pathlib import Path
import sys,json,time,hashlib
import numpy as np
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;D=R/'results/revision-coherent-endpoint-feasibility-v1'
sys.path.insert(0,str(R/'scripts'))
import revision_coherent_dba as base
from revision_dba_experiment import save,outcomes,predict,model_with_arrays
from revision_study_data import read
from fl_forensics.federated_model import dependencies,arrays_from_export,train_local,export_state
from fl_forensics.secure_round import _model_from_export
from fl_forensics.distributed_backdoor import poison_local_rows
from coherent_gradient_protocol import *
from coherent_dba_selection import poison_commitment,worst_asr
from fl_forensics.canonical import sha256_file

FACTORS=(0.,.125,.5,1.,2.,4.)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def guard():
    s=__import__('os').statvfs('/mnt/c');free=s.f_bavail*s.f_frsize
    used=base.allocated(base.D)+base.allocated(D)+base.allocated(O/'published')+base.allocated(O/'endpoint-feasibility')
    assert free>=8*1024**3 and used<64*1024**2
    return {'host_free_bytes':free,'combined_result_bytes':used}

def poisoned_endpoint(initial,rows,weights,seed,deps):
    torch=deps[1];model=_model_from_export(initial,torch=torch,np=np)
    train_local(model=model,rows=rows,class_names=initial['class_names'],class_weights=weights,epochs=10,batch_size=128,
        learning_rate=.001,seed=seed,device_name='cpu',torch=torch,np=np)
    return export_state(model,architecture=initial['architecture'],class_names=initial['class_names'])

def main():
    assert not D.exists(),'Preserve prior feasibility probe'
    original=read(base.D/'protocol-before-training.json');pp,op,old=base.check(original)
    assert read(base.D/'verification.json')['status']=='full_trajectory_and_query_replay_verified'
    D.mkdir();save(D/'protocol-before-endpoint-probe.json',{'profile':'byzantine-endpoint-dba-feasibility-v1','source_script_sha256':sha(Path(__file__)),
        'source_dba_protocol_sha256':sha(base.D/'protocol-before-training.json'),
        'selection':'Both predefined non-IID partitions, initial warm checkpoint only, distributed and complete-trigger variants. No defense metric or test inference.',
        'optimizer':'Malicious clients use10 Adam epochs,batch128,lr.001 on the same50% poisoned-row budgets. Honest clients retain the declared one-step common gradient.',
        'submission':'clean_gradient_delta+alpha*(poisoned_Adam_endpoint_minus_parent-clean_gradient_delta). Explicit Byzantine model-update submissions, not valid honest SGD gradients or TPM-attested data-only training.',
        'alphas':list(FACTORS),'attackers':{str(k):v for k,v in base.ASSIGNMENTS.items()},
        'criterion':'At least20pp worst-trigger ASR increase with<=5pp clean F1 loss against same-input unmodified coherent FedAvg.',
        'scope':'Post-hoc attack development after the ineffective one-step DBA campaign. It does not alter or independently confirm that campaign. All four contexts retained.',
        'storage_before':guard()})
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    initial=read(Path(pp['initial_model_path']));arrays=arrays_from_export(initial,np=np)
    validation=read(Path(old['training']['validation_path']))['rows']['validation'];pool=set(op['root_pool_ids']);evaluation=[r for r in validation if r['window_id'] not in pool]
    labels,_=predict(initial,evaluation,deps);correct=[v==r['label'] for v,r in zip(labels,evaluation,strict=True)]
    contexts=[]
    for seed,attackers in base.ASSIGNMENTS.items():
        rows,_,_=base.pilot.data_source.seed_data(seed,initial['class_names']);clients=sorted(rows);n=sum(map(len,rows.values()))
        clean={c:base.pilot.gradient_step(initial,rows[c],pp['loss_contract']['client_effective_class_weights'],deps)[0] for c in clients}
        for mode in ('distributed','complete-trigger'):
            task={'seed':seed,'attackers':attackers};plan=base.plan_for(task);endpoint={};commitments={};pins={}
            for c in attackers:
                poisoned,record=poison_local_rows(rows=rows[c],plan=plan,client_id=c,round_number=1,distributed=mode=='distributed')
                model=poisoned_endpoint(initial,poisoned,pp['loss_contract']['client_effective_class_weights'],seed+10000+int(c[6:])-1,deps)
                endpoint[c]=[a.astype(float)-b for a,b in zip(arrays_from_export(model,np=np),arrays,strict=True)]
                commitments[c]=poison_commitment(record);pins[c]=base.pilot.old_study.export_digest(model)
            values=[]
            for factor in FACTORS:
                deltas={c:(clean[c] if factor==0 else endpoint[c] if factor==1 else [a+factor*(b-a) for a,b in zip(clean[c],endpoint[c],strict=True)]) if c in attackers else clean[c] for c in clients}
                delta=[sum((len(rows[c])/n*deltas[c][k] for c in clients),np.zeros_like(b)) for k,b in enumerate(arrays)]
                model=model_with_arrays(initial,[b+d for b,d in zip(arrays,delta,strict=True)])
                m=base.compact(outcomes(model,evaluation,plan,correct,deps));values.append({'alpha':factor,'model_sha256':base.pilot.old_study.export_digest(model),'metrics':m})
            clean_metric=values[0]['metrics'];feasible=[]
            for v in values:
                loss=clean_metric['clean']['macro_f1_all_model_classes']-v['metrics']['clean']['macro_f1_all_model_classes']
                increase=worst_asr(v['metrics'])-worst_asr(clean_metric)
                v['paired_f1_loss']=loss;v['paired_worst_asr_increase']=increase;v['effective']=increase>=.20 and loss<=.05
                if loss<=.05:feasible.append(v)
            best=max(feasible,key=lambda v:(worst_asr(v['metrics']),v['alpha']))
            contexts.append({'seed':seed,'mode':mode,'poisoning':commitments,'poisoned_endpoint_hashes':pins,'queries':values,
                'best_guard_compliant_alpha':best['alpha'],'best_worst_asr':worst_asr(best['metrics']),
                'any_effective':any(v['effective'] for v in values)})
            print(json.dumps({'endpoint_probe_seed':seed,'mode':mode,'effective':contexts[-1]['any_effective'],
                'best_alpha':best['alpha'],'worst_asr':worst_asr(best['metrics']),'clean_f1_loss':best['paired_f1_loss']}),flush=True)
            guard()
    assert sha(Path(__file__))==read(D/'protocol-before-endpoint-probe.json')['source_script_sha256']
    base.check(original);save(D/'results.json',contexts)
    save(D/'summary.json',{'status':'feasibility_complete','contexts':len(contexts),'malicious_optimizer_fits':12,'queries':24,
        'effective_contexts':sum(c['any_effective'] for c in contexts),'scope':'Development probe of Byzantine endpoint DBA, not a defended trajectory or pure data-only SGD attack.',
        'test_inference':False,'storage_after':guard()})
    print(json.dumps(read(D/'summary.json'),indent=2))
if __name__=='__main__':main()
