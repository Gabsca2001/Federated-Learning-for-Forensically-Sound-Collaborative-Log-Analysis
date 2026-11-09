"""Check coefficient/metric records and report all fixed-context comparisons."""
from pathlib import Path
from fractions import Fraction as F
import json,hashlib,csv,copy,shutil,math
from collections import defaultdict

R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
D=R/'results/revision-no-redistribution-screen-v1'
O=Path(__file__).parent
SOURCE=R/'artifacts/revision-capped-final-v1'
def read(p):return json.loads(p.read_bytes())
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def save(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def near(a,b):assert abs(a-b)<1e-12,(a,b)
def worst(v):return max(v['complete_trigger']['asr'],*[x['asr'] for x in v['component_triggers'].values()])

def verify_metrics(v):
    clean=v['clean'];cm=clean['confusion_matrix']['values'];n=len(cm)
    f1=[]
    for i in range(n):
        tp=cm[i][i];fp=sum(cm[j][i] for j in range(n))-tp;fn=sum(cm[i])-tp
        f1.append(2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.)
    near(clean['macro_f1_all_model_classes'],sum(f1)/n)
    near(clean['accuracy'],sum(cm[i][i] for i in range(n))/sum(map(sum,cm)))
    for t in (v['complete_trigger'],*v['component_triggers'].values()):
        near(t['asr'],t['target_predictions']/t['non_target_denominator'])
        if t['reference_correct_denominator']:
            near(t['reference_correct_asr'],t['reference_correct_target_predictions']/t['reference_correct_denominator'])

def verify_row(row):
    outputs=row['outputs'];p={c:F(v) for c,v in outputs['robust']['beta'].items()}
    cut={c:min(v,F(1,9)) for c,v in p.items()};s=sum(cut.values())
    assert sum(p.values())==1 and all(v>=0 for v in p.values())
    for method,out in outputs.items():
        beta={c:F(v) for c,v in out['beta'].items()};total=sum(beta.values())
        assert set(beta)==set(p) and all(v>=0 for v in beta.values())
        assert total+F(out['retained_checkpoint_weight'])==1
        assert total==F(out['client_step_mass'])
        top=sum(sorted(beta.values(),reverse=True)[:3])
        assert top==F(out['maximum_three_absolute_coefficients'])
        assert top/total==F(out['maximum_three_client_normalized_share'])
        if method=='no_redistribution':
            assert beta==cut and top<=F(1,3)
        if method=='matched_step':assert beta=={c:s*v for c,v in p.items()}
        if method=='capped':
            assert total==1 and all(v<=F(1,9) for v in beta.values())
            free=[c for c in p if p[c] and beta[c]<F(1,9)]
            assert free
            scale=beta[free[0]]/p[free[0]]
            assert all(beta[c]==min(F(1,9),scale*p[c]) for c in p)
        verify_metrics(out['validation'])
    assert sum(F(v) for v in outputs['no_redistribution']['beta'].values())==sum(F(v) for v in outputs['matched_step']['beta'].values())

def main():
    complete=read(D/'completion.json');assert complete['contexts']==240
    save(D/'report-before-reading.json',{'reporter_sha256':sha(Path(__file__)),'completion_sha256':sha(D/'completion.json'),'scope':'Separate formula/count accounting; not an independent neural-network implementation.'})
    p=read(D/'protocol-before-inference.json');all_rows=[];rehashes=0;metrics=0
    assert all(sha(R/name)==h for name,h in p['source_locks'].items())
    for entry in p['cases']:
        name=entry['task']['name'];case=read(D/'cases'/f'{name}.json')
        assert case['source_manifest_sha256']==entry['manifest_sha256']
        assert len(case['rows'])==15
        for row in case['rows']:
            verify_row(row);metrics+=len(row['outputs'])
            for relative,h in row['input_locks'].items():
                assert sha(SOURCE/'cases'/name/'evidence'/relative)==h;rehashes+=1
            state=read(SOURCE/'cases'/name/'evidence/rounds'/f"round-{row['round']:03d}"/'gate-state.json')['selected_aggregation_derivation']
            expected=state['final_coefficients'] if row['source_operator']=='robust_bounded' else state['projection']['normalized_proposal']
            assert {i:F(v) for i,v in expected.items()}=={i:F(v) for i,v in row['outputs']['robust']['beta'].items()}
            all_rows.append(row)
    # Actual mutation probes of recorded results, never of original evidence.
    sample=next(r for r in all_rows if F(r['outputs']['no_redistribution']['retained_checkpoint_weight'])>0)
    mutants=[]
    a=copy.deepcopy(sample);q=a['outputs']['no_redistribution'];s=sum(F(v) for v in q['beta'].values());q['beta']={i:str(F(v)/s) for i,v in q['beta'].items()};mutants.append(('hidden_client_renormalization',a))
    a=copy.deepcopy(sample);a['outputs']['no_redistribution']['validation']['complete_trigger']['asr']+=.001;mutants.append(('changed_trigger_metric',a))
    a=copy.deepcopy(sample);a['outputs']['no_redistribution']['validation']['clean']['macro_f1_all_model_classes']+=.001;mutants.append(('changed_clean_f1',a))
    for label,mutant in mutants:
        try:verify_row(mutant)
        except AssertionError:pass
        else:raise AssertionError('Mutation accepted: '+label)
    comparisons=[];groups=defaultdict(list);pairs=defaultdict(list);clean=[];unique={}
    lookup={(r['case'],r['round']):r for r in all_rows}
    for row in all_rows:
        out=row['outputs'];candidate=out['no_redistribution']['validation']
        pins=row['input_locks']
        key=(row['seed'],next(h for n,h in pins.items() if n.endswith('/base-model.json')),
             tuple(sorted((Path(n).name,h) for n,h in pins.items() if '/updates/' in n)))
        values={m:v['model_sha256'] for m,v in out.items()}
        if key in unique:assert unique[key]==values,'Same saved input produced different models'
        unique[key]=values
        for control in ('robust','capped','matched_step'):
            v=out[control]['validation'];diff=worst(candidate)-worst(v)
            f1loss=v['clean']['macro_f1_all_model_classes']-candidate['clean']['macro_f1_all_model_classes']
            entry={k:row[k] for k in ('case','source_operator','seed','mode','round')}
            previous=lookup.get((row['case'],row['round']-1))
            source_method='robust' if row['source_operator']=='robust_bounded' else 'capped'
            base_f1=previous['outputs'][source_method]['validation']['clean']['macro_f1_all_model_classes'] if previous else None
            entry.update(control=control,actually_manipulated=len(row['actually_manipulated_clients']),
                worst_trigger_asr_difference=diff,full_trigger_asr_difference=candidate['complete_trigger']['asr']-v['complete_trigger']['asr'],
                clean_f1_loss=f1loss,control_clean_f1=v['clean']['macro_f1_all_model_classes'],
                candidate_clean_f1=candidate['clean']['macro_f1_all_model_classes'],
                source_base_clean_f1=base_f1,checkpoint_retained=float(F(out['no_redistribution']['retained_checkpoint_weight'])))
            comparisons.append(entry)
            if row['mode']=='clean':clean.append(entry)
            elif row['round']<=10 and row['actually_manipulated_clients']:pairs[control].append(entry)
        for method,v in out.items():groups[(row['source_operator'],row['seed'],row['mode'],method)].append((row['round'],v['validation']))
    aggregates=[]
    for key,values in sorted(groups.items()):
        final=dict(values)[15]
        aggregates.append(dict(zip(('source_operator','seed','mode','method'),key))|{
            'contexts':len(values),'max_one_step_worst_trigger_asr':max(worst(v) for _,v in values),
            'max_one_step_full_trigger_asr':max(v['complete_trigger']['asr'] for _,v in values),
            'round15_one_step_worst_trigger_asr':worst(final),
            'minimum_one_step_clean_macro_f1':min(v['clean']['macro_f1_all_model_classes'] for _,v in values)})
    summary={'scope':'Post-hoc same-input validation-only screening on two selected non-IID seeds. Maxima are over one-step interventions on frozen source histories, not defended trajectory peaks.',
       'contexts':len(all_rows),'distinct_seed_base_update_input_sets':len(unique),'outputs':metrics,'input_files_rehashed':rehashes,'metric_and_coefficient_mutations_rejected':[n for n,_ in mutants],
       'comparisons_on_actually_manipulated_rounds':{c:{'rows':len(rs),'lower_worst_trigger_asr':sum(r['worst_trigger_asr_difference']<-1e-12 for r in rs),
            'higher_worst_trigger_asr':sum(r['worst_trigger_asr_difference']>1e-12 for r in rs),
            'unchanged_worst_trigger_asr':sum(abs(r['worst_trigger_asr_difference'])<=1e-12 for r in rs),
            'worst_clean_f1_loss_points':100*max(r['clean_f1_loss'] for r in rs)} for c,rs in pairs.items()},
       'clean_context_checks':{c:{'rows':len([r for r in clean if r['control']==c]),
            'loss_over_two_points':sum(r['clean_f1_loss']>.02 for r in clean if r['control']==c),
            'worst_clean_f1_loss_points':100*max(r['clean_f1_loss'] for r in clean if r['control']==c)} for c in ('robust','capped','matched_step')},
       'worst_clean_context_examples':{c:max((r for r in clean if r['control']==c),key=lambda r:r['clean_f1_loss']) for c in ('robust','capped','matched_step')},
       'new_training_runs':0,'test_inference':False,'new_defender_specific_attack_search':False,
       'current_defaults_changed':False,'checkpoint_inclusive_bound_not_client_normalized_bound':True,
       'numerical_claim':'All240 source checkpoints/metrics were reconstructed in generation. This checker independently recomputes metric arithmetic and coefficient equations, not the classifier predictions.'}
    for name,rows in [('comparisons.csv',comparisons),('aggregate.csv',aggregates)]:
        with (D/name).open('x',newline='') as h:
            w=csv.DictWriter(h,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    save(D/'summary.json',summary)
    shutil.copy2(__file__,D/Path(__file__).name)
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
