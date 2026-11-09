"""Clean-only decomposition of objective, sampling and endpoint drift.

Full private training rows and exact honest aggregate gradients are accessible
to this experiment controller only. Oracle controls are not deployment methods.
"""
from __future__ import annotations
import os
for k in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ.setdefault(k,'1')
from pathlib import Path
from collections import Counter
from fractions import Fraction as F
import argparse,json,time,hashlib
import numpy as np
from reference_objective_diagnostic import target_distributions,matched_root_weights,loss_gradient
from fltrust_screen_aggregation import fltrust_delta
import revision_fltrust_screen as previous
from revision_study_data import read
from revision_dba_experiment import save,evaluate,model_with_arrays
from fl_forensics.federated_model import dependencies,arrays_from_export
from fl_forensics.secure_round import _model_from_export
from fl_forensics.canonical import sha256_file

R=Path(__file__).resolve().parents[1]
S=R/'results/revision-fltrust-screen-v1';A=R/'artifacts/revision-capped-final-v1'
D=R/'results/revision-reference-coherence-v1'
M=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/defense-consolidation-20261107/coherence')

def flat(v):return np.concatenate([a.ravel() for a in v])
def norm(v):return float(np.linalg.norm(flat(v)))
def cos(a,b):
    x=flat(a);y=flat(b);den=np.linalg.norm(x)*np.linalg.norm(y)
    return float(np.clip(np.dot(x,y)/den,-1,1)) if den else None
def allocated(p):return sum(f.stat().st_blocks*512 for f in p.rglob('*') if f.is_file()) if p.exists() else 0
def guard():
    s=os.statvfs('/mnt/c');free=s.f_bavail*s.f_frsize;used=allocated(D)+allocated(M)
    assert free>=8*1024**3 and used<64*1024**2,'Fixed storage guard failed'
    return {'host_free_bytes':free,'new_result_allocated_bytes':used}
def locks():
    paths=[R/'scripts'/n for n in ('reference_objective_diagnostic.py','revision_reference_coherence.py',
        'fltrust_screen_aggregation.py','revision_fltrust_screen.py')]+[R/'tests/test_reference_objective_diagnostic.py']
    return {str(f.relative_to(R)):sha256_file(f) for f in paths}
def seed_data(seed,classes):
    folder=A/'partitions'/str(seed);m=read(folder/'manifest.json');rows={};counts={}
    for e in m['clients']:
        f=folder/e['dataset_path'];assert sha256_file(f)==e['dataset_sha256']
        rs=read(f)['rows']['train'];assert len(rs)==e['train_row_count']
        rows[e['client_id']]=rs;co=Counter(r['label'] for r in rs);counts[e['client_id']]={c:co[c] for c in classes}
    return rows,counts,{c:float(v) for c,v in m['global_class_weights'].items()}
def check(p):
    assert locks()==p['source_locks'];oldp=read(S/'protocol-before-root-training.json');old=previous.check(oldp)
    assert sha256_file(S/'protocol-before-root-training.json')==p['prior_protocol_sha256']
    for n,h in p['prior_clean_cases'].items():assert sha256_file(S/'cases'/n)==h
    return oldp,old

def prepare():
    assert not D.exists(),'Preserve previous diagnosis';storage=guard()
    oldp=read(S/'protocol-before-root-training.json');old=previous.check(oldp)
    entries=[e for e in oldp['cases'] if e['task']['mode']=='clean'];assert len(entries)==4
    classes=read(Path(old['training']['base_model_path']))['class_names'];targets={}
    for seed in (6116104,6116105):
        rows,counts,w=seed_data(seed,classes);pooled,mix=target_distributions(counts,w)
        targets[str(seed)]={'class_counts':counts,'original_weights':w,'pooled_weighted_target':pooled,'fedavg_local_risk_target':mix}
    p={'profile':'clean-reference-coherence-v1','source_locks':locks(),
       'prior_protocol_sha256':sha256_file(S/'protocol-before-root-training.json'),
       'prior_clean_cases':{e['task']['name']+'.json':sha256_file(S/'cases'/(e['task']['name']+'.json')) for e in entries},
       'cases':entries,'rounds':oldp['rounds'],'root_seeds':oldp['root_seeds'],'targets':targets,
       'root_objectives':['inherited','unweighted','pooled_corrected','local_mixture_corrected'],
       'root_training':'Same48 original root rows, same10 Adam epochs,batch128,lr.001; only class weights differ for two corrected objectives.',
       'gradient_definition':'Float64 deterministic evaluation-mode full-batch weighted-mean cross-entropy. This is not the stochastic training-mode Adam gradient. Descent sign is negative gradient.',
       'diagnostics':'Compare root gradients against pooled and sample-weighted local-risk gradients; compare honest full-batch steps to historical Adam endpoints. Direction controls rescale roots to their matched honest baseline step norm.',
       'privacy_scope':'Controller-only analysis reads original honest client rows/classes and computes exact aggregate gradients. Oracle directions and local-mixture weights are not deployable server observations or new privacy assumptions.',
       'candidate':'Only pooled_corrected Adam root on actual historical Adam updates is eligible for prospective continuation. No oracle or direction-only norm control qualifies.',
       'continuation_guard':'All48 clean context/draw results defined, at least10 positive contributors and at most.02 macro-F1 loss against BOTH original robust and capped same-input controls. No parameter/root is selected from attack metrics.',
       'scope':'Post-hoc clean-only diagnosis, reused root/evaluation split; no new attack inference or test predictions, no new operational default.',
       'storage_before':storage,'maximum_new_output_bytes':64*1024**2,'minimum_host_free_bytes':8*1024**3}
    D.mkdir();save(D/'protocol-before-gradient-diagnosis.json',p)
    print(json.dumps({'prepared':True,'clean_contexts':16,'candidate_root_fits':48,'oracle_fits_not_candidates':True,'storage':storage}),flush=True)

def model_gradient(initial,rows,weights,deps,finite=False):
    torch=deps[1];model=_model_from_export(initial,torch=torch,np=np).double();model.eval()
    assert [n for n,_ in model.named_parameters()]==[p['name'] for p in initial['parameters']]
    x=torch.tensor([r['features'] for r in rows],dtype=torch.float64)
    y=torch.tensor([initial['class_names'].index(r['label']) for r in rows],dtype=torch.long)
    w=torch.tensor([weights[c] for c in initial['class_names']],dtype=torch.float64)
    grad,loss=loss_gradient(model,x,y,w,torch);probe=None
    if finite:
        bias=list(model.parameters())[-1];assert bias.ndim==1 and bias.numel()==len(initial['class_names'])
        direction=np.arange(1,len(initial['class_names'])+1,dtype=float);direction/=np.linalg.norm(direction)
        t=torch.tensor(direction,dtype=torch.float64);eps=1e-5
        with torch.no_grad():
            original=bias.clone();bias.copy_(original+eps*t)
            plus=float(torch.nn.functional.cross_entropy(model(x),y,weight=w))
            bias.copy_(original-eps*t);minus=float(torch.nn.functional.cross_entropy(model(x),y,weight=w));bias.copy_(original)
        numeric=(plus-minus)/(2*eps);analytic=float(np.dot(grad[-1],direction))
        assert abs(numeric-analytic)<1e-7
        probe={'numeric':numeric,'analytic':analytic,'absolute_error':abs(numeric-analytic)}
    return grad,loss,probe

def measure(initial,delta,evaluation,deps):
    base=arrays_from_export(initial,np=np);model=model_with_arrays(initial,[a+b for a,b in zip(base,delta,strict=True)])
    v=evaluate(model,evaluation,deps)
    cm=v['confusion_matrix']['values'];f=[]
    for i in range(len(cm)):
        den=sum(cm[i])+sum(cm[j][i] for j in range(len(cm)));f.append(2*cm[i][i]/den if den else 0.)
    assert abs(sum(f)/len(f)-v['macro_f1_all_model_classes'])<1e-12
    return {'model_sha256':previous.export_digest(model),'clean_f1':v['macro_f1_all_model_classes'],'accuracy':v['accuracy'],'confusion_matrix':v['confusion_matrix']}

def fl_measure(initial,updates,root,evaluation,deps):
    try:delta,report=fltrust_delta(updates,root,{c:True for c in updates})
    except ValueError as exc:return {'defined':False,'reason':str(exc)}
    return {'defined':True,'derivation':report,'measurement':measure(initial,delta,evaluation,deps)}

def run():
    p=read(D/'protocol-before-gradient-diagnosis.json');oldp,old=check(p)
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    validation=read(Path(old['training']['validation_path']))['rows']['validation'];byid={r['window_id']:r for r in validation}
    pool=set(oldp['root_pool_ids']);evaluation=[r for r in validation if r['window_id'] not in pool]
    assert len(evaluation)==3163
    records=[];gradient_evaluations=0;root_fits=0;finite_checks=0
    for entry in p['cases']:
        task=entry['task'];name=task['name'];source_case=read(S/'cases'/f'{name}.json')
        rows,counts,weights=seed_data(task['seed'],list(p['targets'][str(task['seed'])]['original_weights']))
        clients=sorted(rows);total=sum(len(rs) for rs in rows.values());alpha={c:len(rows[c])/total for c in clients}
        weighted_mass={c:sum(weights[r['label']] for r in rows[c]) for c in clients};wm=sum(weighted_mass.values())
        for source_row in source_case['rows']:
            guard();number=source_row['round'];folder=A/'cases'/name/'evidence/rounds'/f'round-{number:03d}'
            initial=read(folder/'base-model.json');base=arrays_from_export(initial,np=np)
            for rel,h in source_row['input_locks'].items():assert sha256_file(A/'cases'/name/'evidence'/rel)==h
            raw={c:[a.astype(float)-b for a,b in zip(arrays_from_export(read(folder/'updates'/f'{c}.json'),np=np),base,strict=True)] for c in clients}
            grads={}
            for c in clients:
                grads[c],_,_=model_gradient(initial,rows[c],weights,deps);gradient_evaluations+=1
            mix=[sum((alpha[c]*grads[c][k] for c in clients),np.zeros_like(b)) for k,b in enumerate(base)]
            pooled=[sum((weighted_mass[c]/wm*grads[c][k] for c in clients),np.zeros_like(b)) for k,b in enumerate(base)]
            honest_steps={c:[-.001*a for a in grads[c]] for c in clients}
            honest_mean=[-.001*a for a in mix]
            mean_adam=[sum((alpha[c]*raw[c][k] for c in clients),np.zeros_like(b)) for k,b in enumerate(base)]
            state=read(folder/'gate-state.json')['selected_aggregation_derivation']
            prior=state['final_coefficients'] if task['method']=='robust_bounded' else state['projection']['normalized_proposal']
            clipped={c:[np.asarray(t['values']).reshape(t['shape']) for t in state['final_bounded_derivation']['contributions'][c]['derived_float64_delta']] for c in clients}
            robust_step=[sum((float(F(prior[c]))*clipped[c][k] for c in clients),np.zeros_like(b)) for k,b in enumerate(base)]
            target=p['targets'][str(task['seed'])];recs=[]
            for root_seed in p['root_seeds']:
                root_rows=[byid[i] for i in oldp['root_draws'][str(root_seed)]];q=Counter(r['label'] for r in root_rows)
                choices={'inherited':weights,'unweighted':{c:1. for c in weights},
                    'pooled_corrected':matched_root_weights(target['pooled_weighted_target'],q),
                    'local_mixture_corrected':matched_root_weights(target['fedavg_local_risk_target'],q)}
                for objective,root_weights in choices.items():
                    g0,loss,probe=model_gradient(initial,root_rows,root_weights,deps,finite=objective=='pooled_corrected' and root_seed==p['root_seeds'][0])
                    gradient_evaluations+=1;finite_checks+=probe is not None
                    direction=[-a for a in g0];rd={}
                    for kind,updates,target_norm in (('historical_adam',raw,norm(robust_step)),('honest_fullbatch_gradient',honest_steps,norm(honest_mean))):
                        root=[a*(target_norm/norm(direction)) for a in direction] if norm(direction) else direction
                        rd[kind]=fl_measure(initial,updates,root,evaluation,deps)
                    rec={'root_seed':root_seed,'objective':objective,'weights':root_weights,'root_loss':loss,
                        'cosine_to_pooled_gradient':cos(g0,pooled),'cosine_to_local_risk_mixture':cos(g0,mix),
                        'cosine_to_historical_mean_adam_descent':cos(direction,mean_adam),'finite_difference':probe,
                        'direction_only_controls':rd}
                    if objective in ('pooled_corrected','local_mixture_corrected'):
                        rm,indices=previous.root_update(initial,root_rows,'adam10',root_seed,deps,root_weights)
                        root_fits+=1;root_delta=[a.astype(float)-b for a,b in zip(arrays_from_export(rm,np=np),base,strict=True)]
                        out=fl_measure(initial,raw,root_delta,evaluation,deps)
                        out['root_model_sha256']=previous.export_digest(rm)
                        if out['defined']:
                            f1=out['measurement']['clean_f1']
                            out['loss_against_original_controls']={m:source_row['baselines'][m]['validation']['clean']['macro_f1_all_model_classes']-f1 for m in ('robust','capped')}
                        rec['actual_adam_root']=out
                    recs.append(rec)
            oracle={}
            for kind,updates,target_norm in (('historical_adam',raw,norm(robust_step)),('honest_fullbatch_gradient',honest_steps,norm(honest_mean))):
                root=[-a*(target_norm/norm(mix)) for a in mix] if norm(mix) else [-a for a in mix]
                oracle[kind]=fl_measure(initial,updates,root,evaluation,deps)
            records.append({'case':name,'seed':task['seed'],'source_operator':task['method'],'round':number,
                'source_model_sha256':previous.export_digest(initial),'original_baseline_f1':{m:source_row['baselines'][m]['validation']['clean']['macro_f1_all_model_classes'] for m in ('robust','capped')},
                'mean_adam_to_local_risk_descent_cosine':cos(mean_adam,[-a for a in mix]),
                'pooled_to_local_risk_gradient_cosine':cos(pooled,mix),
                'honest_gradient_fedavg':measure(initial,honest_mean,evaluation,deps),
                'root_objectives':recs,'oracle_reference':oracle})
            print(json.dumps({'clean_context':len(records),'case':name,'round':number,'gradient_evaluations':gradient_evaluations,'storage':guard()}),flush=True)
    check(p)
    candidates=[z['actual_adam_root'] for r in records for z in r['root_objectives'] if z['objective']=='pooled_corrected']
    failures=[not v['defined'] or v['derivation']['positive_contributors']<10 or max(v['loss_against_original_controls'].values())>.02 for v in candidates]
    summary={'status':'clean_diagnosis_complete','clean_contexts':len(records),'candidate_results':len(candidates),
        'gradient_evaluations':gradient_evaluations,'root_optimizer_fits':root_fits,'head_directional_finite_difference_checks':finite_checks,
        'candidate_undefined':sum(not v['defined'] for v in candidates),
        'candidate_below_quorum10':sum(v['defined'] and v['derivation']['positive_contributors']<10 for v in candidates),
        'candidate_f1_failures':{m:sum(v['defined'] and v['loss_against_original_controls'][m]>.02 for v in candidates) for m in ('robust','capped')},
        'candidate_worst_f1_loss_points':{m:100*max(v['loss_against_original_controls'][m] for v in candidates if v['defined']) for m in ('robust','capped')},
        'candidate_all_continuation_guards_pass':not any(failures),'combined_failed_results':sum(failures),
        'new_attack_inference':False,'test_inference':False,'new_operational_defaults':False,'oracle_is_deployable':False,'storage_after':guard()}
    save(D/'records.json',records);save(D/'summary.json',summary)
    print(json.dumps(summary,indent=2),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('prepare','run'));args=parser.parse_args()
    if args.phase=='prepare':prepare()
    else:run()
