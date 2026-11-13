"""Separate count accounting, paired effectiveness and availability reporting."""
from pathlib import Path
from collections import defaultdict
import json,csv,hashlib,copy,sys
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');D=R/'results/revision-coherent-dba-v1'
sys.path.insert(0,str(R/'scripts'))
import revision_coherent_dba as study
from coherent_dba_selection import select_query,worst_asr,ALPHAS
def read(p):return json.loads(p.read_bytes())
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def save(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def near(a,b):assert abs(a-b)<1e-12,(a,b)
def metric(v):
    cm=v['clean']['confusion_matrix']['values'];n=len(cm);f=[]
    for i in range(n):
        denom=sum(cm[i])+sum(cm[j][i] for j in range(n));f.append(2*cm[i][i]/denom if denom else 0.)
    near(v['clean']['macro_f1_all_model_classes'],sum(f)/n)
    near(v['clean']['accuracy'],sum(cm[i][i] for i in range(n))/sum(map(sum,cm)))
    for t in (v['complete_trigger'],*v['component_triggers'].values()):
        near(t['asr'],t['target_predictions']/t['non_target_denominator'])
        if t['reference_correct_denominator']:near(t['reference_correct_asr'],t['reference_correct_target_predictions']/t['reference_correct_denominator'])

def main():
    p=read(D/'protocol-before-training.json');study.check(p);v=read(D/'verification.json')
    assert v['status']=='full_trajectory_and_query_replay_verified'
    save(D/'report-before-reading.json',{'reporter_sha256':sha(Path(__file__)),'verification_sha256':sha(D/'verification.json')})
    results={t['name']:read(D/'evidence/histories'/t['name']/'result.json') for t in p['tasks']}
    rounds=[];cases=[];query_count=blocked_queries=metric_count=0;effects={};controls={}
    for result in results.values():
        t=result['task'];name=t['name']
        if t['mode']=='clean':controls[(t['seed'],t['method'])]={r['round']:r['validation'] for r in result['journal'] if r['event']['decision']=='commit'}
    for result in results.values():
        t=result['task'];name=t['name'];clean=controls[(t['seed'],t['method'])];observed=[];effective=[];previous=None
        for row in result['journal']:
            event=row['event'];number=row['round'];gate=event['decision']=='commit'
            assert event['eligible_count']==15 and all(event['mandatory_gates'].values())
            if gate:
                assert row['state_after']['last_committed_round']==row['state_before']['last_committed_round']+1 and event['positive_contributors']>=10
                m=row['validation'];metric(m);metric_count+=1;observed.append((number,m));previous=m
                harm=worst_asr(m)-worst_asr(clean[number]);loss=clean[number]['clean']['macro_f1_all_model_classes']-m['clean']['macro_f1_all_model_classes']
                if harm>=.20 and loss<=.05:effective.append(number)
            else:
                assert row['exported_checkpoint_sha256'] is None and row['state_after']['parent_model_sha256']==row['state_before']['parent_model_sha256']
                assert row['state_after']['last_committed_round']==row['state_before']['last_committed_round']
                m=row['retained_parent_metrics'];metric(m);metric_count+=1
                if previous is not None:assert previous==m
                harm=loss=None
            if row['queries']:
                query_count+=len(row['queries']);blocked_queries+=sum(not q['defined'] for q in row['queries'])
                for q in row['queries']:
                    if q['defined']:metric(q['metrics']);metric_count+=1
                    else:assert q['metrics'] is None and q['candidate_model_sha256'] is None
                selected,selection=select_query(row['queries'],clean[number]['clean']['macro_f1_all_model_classes'])
                assert selected==row['selected_alpha'] and selection==row['selection']
            for c,poison in row['poisoning'].items():
                expected=(event['example_counts'][c]+1)//2
                assert poison['poisoned_row_count']==expected
                width=3 if t['mode']=='complete-trigger' else 1
                assert len(poison['feature_indices'])==width and poison['modified_feature_values']==expected*width
            scores=(event['aggregation'].get('scores') or event['aggregation'].get('coefficients')) if event['aggregation'] else None
            altered=set(row['actually_manipulated_clients']);zero_manip=sum(scores.get(c,0)==0 for c in altered) if scores is not None else None
            zero_unmodified=sum(scores.get(c,0)==0 for c in event['received_clients'] if c not in altered) if scores is not None else None
            normalized=(event['aggregation'].get('normalized_scores') or event['aggregation'].get('coefficients')) if event['aggregation'] else None
            positive_mass=sum(event['example_counts'][c] for c in scores if scores[c]>0)/sum(event['example_counts'].values()) if scores is not None else None
            rounds.append({'history':name,'seed':t['seed'],'method':t['method'],'mode':t['mode'],'round':number,'committed':gate,
                'alpha':row['selected_alpha'],'actually_manipulated':len(altered),'positive_contributors':event['positive_contributors'],
                'zero_score_manipulated':zero_manip,'zero_score_unmodified':zero_unmodified,
                'score_defined':scores is not None,'mandatory_admission_mass_retained':1.,'positive_coefficient_nominal_mass_fraction':positive_mass,
                'largest_three_normalized_score_share':sum(sorted(normalized.values(),reverse=True)[:3]) if normalized else None,
                'full_asr':m['complete_trigger']['asr'],'worst_asr':worst_asr(m),'clean_macro_f1':m['clean']['macro_f1_all_model_classes'],
                'paired_worst_asr_increase':harm,'paired_clean_f1_loss':loss,
                'metric_scope':'committed_checkpoint' if gate else 'retained_parent_only',
                'blocked_adaptive_queries':sum(not q['defined'] for q in row['queries']),
                **row['timing']})
        final=dict(observed).get(15)
        cases.append({'history':name,'seed':t['seed'],'method':t['method'],'mode':t['mode'],'complete':result['complete'],
            'committed_rounds':result['committed_rounds'],'availability_pause':result['state']['phase']=='paused',
            'observed_peak_full_asr':max((m['complete_trigger']['asr'] for _,m in observed),default=None),
            'observed_peak_worst_asr':max((worst_asr(m) for _,m in observed),default=None),
            'round15_full_asr':final['complete_trigger']['asr'] if final else None,'round15_worst_asr':worst_asr(final) if final else None,
            'retained_parent_worst_asr':worst_asr(result['journal'][-1]['retained_parent_metrics']) if result['state']['phase']=='paused' else None,
            'effective_paired_rounds':json.dumps(effective),
            'maximum_observed_paired_harm':max((worst_asr(m)-worst_asr(clean[n]) for n,m in observed),default=None),
            'maximum_observed_paired_clean_f1_loss':max((clean[n]['clean']['macro_f1_all_model_classes']-m['clean']['macro_f1_all_model_classes'] for n,m in observed),default=None)})
        effects[(t['seed'],t['method'],t['mode'])]=effective
    comparisons=[]
    for seed in (6116104,6116105):
        for mode in ('distributed','complete-trigger','adaptive-distributed'):
            raw=next(c for c in cases if c['seed']==seed and c['mode']==mode and c['method']=='coherent_fedavg')
            defended=next(c for c in cases if c['seed']==seed and c['mode']==mode and c['method']=='coherent_fltrust')
            status='availability_failure' if defended['availability_pause'] else 'effective_control_comparison' if effects[(seed,'coherent_fedavg',mode)] else 'ineffective_control_inconclusive'
            comparisons.append({'seed':seed,'mode':mode,'raw_attack_effective':bool(effects[(seed,'coherent_fedavg',mode)]),
                'raw_effective_rounds':raw['effective_paired_rounds'],'raw_peak_worst_asr':raw['observed_peak_worst_asr'],
                'raw_final_full_asr':raw['round15_full_asr'],'raw_final_worst_asr':raw['round15_worst_asr'],'defended_committed_rounds':defended['committed_rounds'],
                'defended_complete':defended['complete'],'defended_observed_peak_worst_asr':defended['observed_peak_worst_asr'],
                'defended_final_full_asr':defended['round15_full_asr'],'defended_final_worst_asr':defended['round15_worst_asr'],'defended_retained_parent_worst_asr':defended['retained_parent_worst_asr'],
                'status':status})
    # Poisoned row selection is identical across distributed/full branches within an operator.
    for seed in (6116104,6116105):
        for method in ('coherent_fedavg','coherent_fltrust'):
            a=results[f's{seed}-{method}-distributed'];b=results[f's{seed}-{method}-complete-trigger']
            for x,y in zip(a['journal'][:10],b['journal'][:10]):
                for client in x['poisoning']:
                    assert x['poisoning'][client]['poisoned_ids_sha256']==y['poisoning'][client]['poisoned_ids_sha256']
    sample=copy.deepcopy(next(r['validation'] for r in results[p['tasks'][0]['name']]['journal'] if r['event']['decision']=='commit'))
    sample['complete_trigger']['asr']+=.001
    try:metric(sample)
    except AssertionError:pass
    else:raise AssertionError('ASR mutation accepted')
    clean_cases=[c for c in cases if c['mode']=='clean'];assert len(clean_cases)==4 and all(c['complete'] for c in clean_cases)
    summary={'status':'verified_report','histories':len(cases),'committed_rounds':v['committed_rounds'],'pauses':v['pauses'],
        'adaptive_queries':query_count,'blocked_adaptive_queries':blocked_queries,'metric_sets_count_checked':metric_count,
        'effectiveness_rule':'At least20pp paired worst-trigger ASR increase with<=5pp own-clean F1 loss at same committed round.',
        'effective_raw_attack_histories':sum(c['raw_attack_effective'] for c in comparisons),'raw_attacked_histories':6,
        'defended_attacked_histories_complete':sum(c['defended_complete'] for c in comparisons),
        'defended_attacked_histories_paused':sum(c['status']=='availability_failure' for c in comparisons),
        'comparisons':comparisons,'clean_known_checkpoint_histories_reproduced':4,
        'scope':'Exploratory reused validation; fixed full60-root coherent gradient profile. Adaptive query feedback is privileged and restricted to distributed-gradient interpolation/scaling; blocked shadow queries do not constitute separately trained DoS histories.',
        'new_TPM_quotes':0,'test_inference':False,'default_changed':False}
    for name,records in [('rounds.csv',rounds),('cases.csv',cases),('comparisons.csv',comparisons)]:
        with (D/name).open('x',newline='') as h:
            w=csv.DictWriter(h,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
    save(D/'summary.json',summary);print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
