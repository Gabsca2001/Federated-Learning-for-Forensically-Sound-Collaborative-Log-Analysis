from pathlib import Path
from collections import defaultdict
import json,hashlib,copy,statistics,sys
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');O=Path(__file__).parent
D=R/'results/revision-reference-coherence-v1'
sys.path.insert(0,str(R/'scripts'))
import revision_reference_coherence as study
from reference_objective_diagnostic import loss_gradient
from revision_dba_experiment import model_with_arrays
from fl_forensics.federated_model import dependencies,arrays_from_export
def read(p):return json.loads(p.read_bytes())
def save(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def near(a,b):assert abs(a-b)<1e-10,(a,b)
def metric(v):
    cm=v['confusion_matrix']['values'];n=len(cm);f=[]
    for i in range(n):
        den=sum(cm[i])+sum(cm[j][i] for j in range(n));f.append(2*cm[i][i]/den if den else 0.)
    near(v['clean_f1'],sum(f)/n)
    near(v['accuracy'],sum(cm[i][i] for i in range(n))/sum(map(sum,cm)))
def result(v):
    if not v['defined']:return
    scores=v['derivation']['scores'];assert sum(s>0 for s in scores.values())==v['derivation']['positive_contributors']
    metric(v['measurement'])
def weight_check(weights,counts,target):
    total=sum(counts[c]*weights[c] for c in counts)
    for c in counts:near(counts[c]*weights[c]/total,target[c])
def stats(v):return {'minimum':min(v),'mean':statistics.fmean(v),'maximum':max(v)}

def main():
    p=read(D/'protocol-before-gradient-diagnosis.json');oldp,old=study.check(p);records=read(D/'records.json');s=read(D/'summary.json')
    save(D/'analysis-before-reading.json',{'analyzer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'records_sha256':hashlib.sha256((D/'records.json').read_bytes()).hexdigest()})
    metrics=0;gradients=defaultdict(list);direction=defaultdict(list);fit=defaultdict(list);oracle=defaultdict(list);finite=0
    for r in records:
        assert r['source_model_sha256']==study.previous.export_digest(read(study.A/'cases'/r['case']/'evidence/rounds'/f"round-{r['round']:03d}"/'base-model.json'))
        metric(r['honest_gradient_fedavg']);metrics+=1
        for kind,v in r['oracle_reference'].items():
            result(v);metrics+=v['defined'];oracle[kind].append((r,v))
        for z in r['root_objectives']:
            key=z['objective'];gradients[key].append(z['cosine_to_local_risk_mixture'])
            if z['finite_difference']:
                near(z['finite_difference']['numeric'],z['finite_difference']['analytic']);finite+=1
            for kind,v in z['direction_only_controls'].items():
                result(v);metrics+=v['defined'];direction[(key,kind)].append((r,v))
            if key in ('pooled_corrected','local_mixture_corrected'):
                target_key='pooled_weighted_target' if key=='pooled_corrected' else 'fedavg_local_risk_target'
                weight_check(z['weights'],dict.fromkeys(z['weights'],8),p['targets'][str(r['seed'])][target_key])
                v=z['actual_adam_root'];result(v);metrics+=v['defined'];fit[key].append((r,v))
                if v['defined']:
                    for m in ('robust','capped'):near(v['loss_against_original_controls'][m],r['original_baseline_f1'][m]-v['measurement']['clean_f1'])
    # Replay independent selected contexts through the original pinned trainer.
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    original=read(Path(old['training']['validation_path']))['rows']['validation'];byid={r['window_id']:r for r in original}
    evaluation=[r for r in original if r['window_id'] not in set(oldp['root_pool_ids'])]
    replay_client=0;replay_root=0;replay_fit=0
    for r in (records[0],records[-1]):
        folder=study.A/'cases'/r['case']/'evidence/rounds'/f"round-{r['round']:03d}"
        initial=read(folder/'base-model.json');base=arrays_from_export(initial,np=study.np)
        rows,counts,weights=study.seed_data(r['seed'],initial['class_names']);clients=sorted(rows);n=sum(map(len,rows.values()));g={}
        for c in clients:g[c],_,_=study.model_gradient(initial,rows[c],weights,deps);replay_client+=1
        mixture=[sum((len(rows[c])/n*g[c][k] for c in clients),study.np.zeros_like(a)) for k,a in enumerate(base)]
        raw={c:[a.astype(float)-b for a,b in zip(arrays_from_export(read(folder/'updates'/f'{c}.json'),np=study.np),base,strict=True)] for c in clients}
        for z in r['root_objectives']:
            if z['objective'] not in ('pooled_corrected','local_mixture_corrected'):continue
            rs=[byid[i] for i in oldp['root_draws'][str(z['root_seed'])]]
            grad,_,_=study.model_gradient(initial,rs,z['weights'],deps);replay_root+=1
            near(study.cos(grad,mixture),z['cosine_to_local_risk_mixture'])
            if z['objective']=='pooled_corrected':
                model,_=study.previous.root_update(initial,rs,'adam10',z['root_seed'],deps,z['weights']);replay_fit+=1
                assert study.previous.export_digest(model)==z['actual_adam_root']['root_model_sha256']
                rd=[a.astype(float)-b for a,b in zip(arrays_from_export(model,np=study.np),base,strict=True)]
                v=study.fl_measure(initial,raw,rd,evaluation,deps)
                assert v['defined']==z['actual_adam_root']['defined']
                if v['defined']:assert v['measurement']==z['actual_adam_root']['measurement']
    candidate=[v for r,v in fit['pooled_corrected']]
    assert sum(v['defined'] and v['derivation']['positive_contributors']<10 for v in candidate)==s['candidate_below_quorum10']
    # Meaningful record mutations must fail the separate accounting checks.
    probes=0
    v=copy.deepcopy(candidate[0]);v['measurement']['clean_f1']+=.001
    try:result(v)
    except AssertionError:probes+=1
    else:raise AssertionError('Changed F1 accepted')
    v=copy.deepcopy(candidate[0]);v['derivation']['positive_contributors']+=1
    try:result(v)
    except AssertionError:probes+=1
    else:raise AssertionError('Changed quorum accepted')
    z=next(z for z in records[0]['root_objectives'] if z['objective']=='pooled_corrected');w=dict(z['weights']);w[next(iter(w))]*=2
    try:weight_check(w,dict.fromkeys(w,8),p['targets'][str(records[0]['seed'])]['pooled_weighted_target'])
    except AssertionError:probes+=1
    else:raise AssertionError('Wrong objective weights accepted')
    analysis={'status':'verified','clean_contexts':len(records),'metric_sets_checked':metrics,'finite_differences_checked':finite,
       'client_gradient_replays':replay_client,'root_gradient_replays':replay_root,'root_optimizer_and_metric_replays':replay_fit,
       'record_mutations_rejected':probes,
       'historical_adam_to_honest_descent_cosine':stats([r['mean_adam_to_local_risk_descent_cosine'] for r in records]),
       'pooled_to_local_risk_gradient_cosine':stats([r['pooled_to_local_risk_gradient_cosine'] for r in records]),
       'root_gradient_to_local_risk_cosines':{k:stats(v) for k,v in gradients.items()},
       'oracle_reference':{kind:{'contexts':len(vs),'undefined':sum(not v['defined'] for r,v in vs),
          'below_positive_quorum10':sum(v['defined'] and v['derivation']['positive_contributors']<10 for r,v in vs),
          'loss_over_two_points_against_matched_baseline':sum(v['defined'] and ((r['honest_gradient_fedavg']['clean_f1'] if kind=='honest_fullbatch_gradient' else r['original_baseline_f1']['robust'])-v['measurement']['clean_f1'])>.02 for r,v in vs)} for kind,vs in oracle.items()},
       'corrected_root_fits':{kind:{'results':len(vs),'below_positive_quorum10':sum(v['defined'] and v['derivation']['positive_contributors']<10 for r,v in vs),
          'losses_over_two_points':{m:sum(v['defined'] and v['loss_against_original_controls'][m]>.02 for r,v in vs) for m in ('robust','capped')}} for kind,vs in fit.items()},
       'scope':'Clean-only objective/direction decomposition. Private-data oracle controls and deterministic gradients are not operational server capabilities or stochastic Adam-training gradients.'}
    study.check(p);save(D/'analysis.json',analysis)
    print(json.dumps(analysis,indent=2))

if __name__=='__main__':main()
