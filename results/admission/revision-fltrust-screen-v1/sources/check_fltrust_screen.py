"""Replay root fits, independently check formula arithmetic and selected metrics."""
from pathlib import Path
import sys,json,hashlib,copy
import numpy as np
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;D=R/'results/revision-fltrust-screen-v1';S=R/'artifacts/revision-capped-final-v1'
sys.path.insert(0,str(R/'scripts'))
import revision_fltrust_screen as study
from capped_final_aggregation import project_coefficients
from fractions import Fraction as F
from revision_dba_experiment import outcomes,model_with_arrays,predict
from fl_forensics.federated_model import dependencies,arrays_from_export
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.canonical import sha256_file

def read(p):return json.loads(p.read_bytes())
def save(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def near(a,b):assert abs(a-b)<=1e-11*max(1,abs(a),abs(b)),(a,b)
def metrics(v):
    cm=v['clean']['confusion_matrix']['values'];n=len(cm);f=[]
    for i in range(n):
        tp=cm[i][i];denom=sum(cm[i])+sum(cm[j][i] for j in range(n));f.append(2*tp/denom if denom else 0.)
    near(v['clean']['macro_f1_all_model_classes'],sum(f)/n)
    near(v['clean']['accuracy'],sum(cm[i][i] for i in range(n))/sum(map(sum,cm)))
    for t in (v['complete_trigger'],*v['component_triggers'].values()):
        near(t['asr'],t['target_predictions']/t['non_target_denominator'])
        if t['reference_correct_denominator']:near(t['reference_correct_asr'],t['reference_correct_target_predictions']/t['reference_correct_denominator'])

def formula(d):
    scores=d['scores'];total=sum(scores.values());near(total,d['score_sum']);assert total>0
    assert d['positive_contributors']==sum(v>0 for v in scores.values())
    for c,v in scores.items():
        near(v,max(0.,d['cosines'][c]));near(d['normalized_scores'][c],v/total)
        expected=d['root_norm']/d['local_norms'][c] if v else 0.
        near(d['norm_scales'][c],expected)
        near(d['effective_raw_delta_coefficients'][c],d['normalized_scores'][c]*expected)
    assert d['aggregate_norm']<=d['root_norm']*(1+1e-12)

def main():
    p=read(D/'protocol-before-root-training.json');old=study.check(p);completion=read(D/'completion.json')
    assert completion['contexts']==64
    save(D/'verification-before-reading.json',{'checker_sha256':sha256_file(Path(__file__)),'completion_sha256':sha256_file(D/'completion.json'),
        'scope':'Same root-training implementation replay; separate vector arithmetic and metric-count checks. Repeated selected inference uses original classifier implementation.'})
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    original=read(Path(old['training']['validation_path']))['rows']['validation'];byid={r['window_id']:r for r in original}
    pool=set(p['root_pool_ids']);evaluation=[r for r in original if r['window_id'] not in pool]
    assert len(pool)==60 and len(evaluation)==3163 and not pool&{r['window_id'] for r in evaluation}
    labels,_=predict(read(Path(old['training']['base_model_path'])),evaluation,deps)
    correct=[v==r['label'] for v,r in zip(labels,evaluation,strict=True)]
    root_replays=metric_sets=prediction_replays=source_rehashes=0;sample=None;fingerprints={}
    for case_index,entry in enumerate(p['cases']):
        task=entry['task'];name=task['name'];case=read(D/'cases'/f'{name}.json');assert len(case['rows'])==4
        part=read(S/'partitions'/str(task['seed'])/'manifest.json');weights={c:float(v) for c,v in part['global_class_weights'].items()}
        plan=DistributedBackdoorPlan.model_validate({**old['training']['attack_plan'],'seed':task['seed'],'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True))})
        for row in case['rows']:
            folder=S/'cases'/name/'evidence/rounds'/f"round-{row['round']:03d}"
            initial=read(folder/'base-model.json');base=arrays_from_export(initial,np=np)
            clients=sorted(item['client_id'] for item in part['clients'])
            raw={c:[a.astype(float)-b for a,b in zip(arrays_from_export(read(folder/'updates'/f'{c}.json'),np=np),base,strict=True)] for c in clients}
            for rel,h in row['input_locks'].items():assert sha256_file(S/'cases'/name/'evidence'/rel)==h;source_rehashes+=1
            state=read(folder/'gate-state.json')['selected_aggregation_derivation']
            prior={c:F(v) for c,v in (state['final_coefficients'] if task['method']=='robust_bounded' else state['projection']['normalized_proposal']).items()}
            cap,_=project_coefficients(prior,cap=F(1,9))
            limits=read(R/old['tensor_references']['non-iid']['path'])['limits']
            clipped={c:[d*min(1.,limits[k]/np.linalg.norm(d.ravel())) if np.linalg.norm(d.ravel()) else d for k,d in enumerate(raw[c])] for c in clients}
            robust_delta=[sum((float(prior[c])*clipped[c][k] for c in clients),np.zeros_like(b)) for k,b in enumerate(base)]
            replay_predictions=case_index in (0,15) and row['round']==10
            for method,beta in (('robust',prior),('capped',cap)):
                params=[b+sum((float(beta[c])*clipped[c][k] for c in clients),np.zeros_like(b)) for k,b in enumerate(base)]
                model=model_with_arrays(initial,params)
                assert study.export_digest(model)==row['baselines'][method]['model_sha256'];metrics(row['baselines'][method]['validation']);metric_sets+=1
                if replay_predictions:
                    assert study.compact(outcomes(model,evaluation,plan,correct,deps))==row['baselines'][method]['validation'];prediction_replays+=1
            for ref in row['references']:
                root_rows=[byid[i] for i in p['root_draws'][str(ref['root_seed'])]]
                root_model,indices=study.root_update(initial,root_rows,ref['root_method'],ref['root_seed'],deps,weights)
                assert study.export_digest(root_model)==ref['root_model_sha256'] and indices==ref['executed_root_indices'];root_replays+=1
                key=(study.export_digest(initial),ref['root_method'],ref['root_seed'])
                if key in fingerprints:assert fingerprints[key]==ref['root_model_sha256']
                fingerprints[key]=ref['root_model_sha256']
                root_arrays=arrays_from_export(root_model,np=np);rd=[a.astype(float)-b for a,b in zip(root_arrays,base,strict=True)]
                rv=np.concatenate([a.ravel() for a in rd]);rn=np.linalg.norm(rv);near(rn,ref['root_delta_norm'])
                assert ref['root_only']['model_sha256']==ref['root_model_sha256'];metrics(ref['root_only']['validation']);metric_sets+=1
                if replay_predictions:
                    assert study.compact(outcomes(root_model,evaluation,plan,correct,deps))==ref['root_only']['validation'];prediction_replays+=1
                if not ref['defined']:
                    assert ref['fltrust'] is None
                    # Independently establish actual degeneracy; no result imputation.
                    alignment=[max(0.,float(np.dot(np.concatenate([a.ravel() for a in raw[c]]),rv))) for c in clients]
                    assert rn==0 or max(alignment)==0
                    continue
                d=ref['derivation'];formula(d);sample=sample or copy.deepcopy(d);near(d['root_norm'],rn)
                matrix=np.stack([np.concatenate([a.ravel() for a in raw[c]]) for c in clients])
                lengths=np.linalg.norm(matrix,axis=1)
                cos=np.divide(matrix@rv,lengths*rn,out=np.zeros(len(clients)),where=lengths>0)
                for j,c in enumerate(clients):near(d['cosines'][c],float(np.clip(cos[j],-1,1)));near(d['local_norms'][c],lengths[j])
                assert ref['meets_positive_quorum10']==(d['positive_contributors']>=10)
                delta=[sum((raw[c][k]*d['effective_raw_delta_coefficients'][c] for c in clients),np.zeros_like(b)) for k,b in enumerate(base)]
                model=model_with_arrays(initial,[b+a for b,a in zip(base,delta,strict=True)])
                assert study.export_digest(model)==ref['fltrust']['model_sha256'];metrics(ref['fltrust']['validation']);metric_sets+=1
                if replay_predictions:
                    assert study.compact(outcomes(model,evaluation,plan,correct,deps))==ref['fltrust']['validation'];prediction_replays+=1
                if ref['norm_matched_robust']:
                    scaled=[a*ref['matched_robust_scale'] for a in robust_delta]
                    near(study.norm(scaled),d['aggregate_norm'])
                    model=model_with_arrays(initial,[b+a for b,a in zip(base,scaled,strict=True)])
                    assert study.export_digest(model)==ref['norm_matched_robust']['model_sha256'];metrics(ref['norm_matched_robust']['validation']);metric_sets+=1
                    if replay_predictions:
                        assert study.compact(outcomes(model,evaluation,plan,correct,deps))==ref['norm_matched_robust']['validation'];prediction_replays+=1
            print(json.dumps({'verified_case':name,'round':row['round'],'root_replays':root_replays}),flush=True)
    # Mutating stored coefficients or a metric must be rejected.
    a=copy.deepcopy(sample);c=next(c for c,v in a['scores'].items() if v>0);a['effective_raw_delta_coefficients'][c]+=.01
    try:formula(a)
    except AssertionError:pass
    else:raise AssertionError('Coefficient mutation accepted')
    any_case=read(D/'cases'/f"{p['cases'][0]['task']['name']}.json")
    a=copy.deepcopy(any_case['rows'][0]['baselines']['robust']['validation']);a['complete_trigger']['asr']+=.001
    try:metrics(a)
    except AssertionError:pass
    else:raise AssertionError('ASR mutation accepted')
    study.check(p)
    result={'status':'verified','root_training_replays':root_replays,'unique_parent_method_seed_root_fits':len(fingerprints),
       'exported_metric_sets_checked':metric_sets,'selected_prediction_metric_sets_replayed':prediction_replays,
       'input_references_rehashed':source_rehashes,'formula_and_metric_mutations_rejected':2,
       'scope':'Independent arithmetic, same numerical dependencies/root trainer and same classifier for selected repeats; not independent-implementation or general-security certification.'}
    save(D/'verification.json',result)
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
