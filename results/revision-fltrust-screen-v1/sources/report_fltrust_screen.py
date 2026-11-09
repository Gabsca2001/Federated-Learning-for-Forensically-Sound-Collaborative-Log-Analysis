"""Describe every fixed root/configuration without selecting a winning fit."""
from pathlib import Path
from collections import defaultdict
import json,csv,hashlib,shutil
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
D=R/'results/revision-fltrust-screen-v1'
def read(p):return json.loads(p.read_bytes())
def worst(v):return max(v['complete_trigger']['asr'],*[x['asr'] for x in v['component_triggers'].values()])
def main():
    p=read(D/'protocol-before-root-training.json');verified=read(D/'verification.json');assert verified['status']=='verified'
    assert not (D/'summary.json').exists()
    rows=[];cells=defaultdict(list);unique={};rawrefs=[]
    for entry in p['cases']:
        case=read(D/'cases'/f"{entry['task']['name']}.json")
        for row in case['rows']:
            pins=row['input_locks'];key=(row['seed'],next(h for n,h in pins.items() if n.endswith('/base-model.json')),
                tuple(sorted((Path(n).name,h) for n,h in pins.items() if '/updates/' in n)))
            models={}
            for ref in row['references']:
                identity=(ref['root_method'],ref['root_seed']);rawrefs.append((row,ref))
                models[identity]=ref['fltrust']['model_sha256'] if ref['defined'] else None
                if not ref['defined']:continue
                candidate=ref['fltrust']['validation']
                controls={**row['baselines'],'root_only':ref['root_only'],'norm_matched_robust':ref['norm_matched_robust']}
                for control,model in controls.items():
                    if model is None:continue
                    v=model['validation']
                    pair={k:row[k] for k in ('case','source_operator','seed','mode','round')}
                    pair.update(root_method=ref['root_method'],root_seed=ref['root_seed'],control=control,
                        actually_manipulated=len(row['actually_manipulated_clients']),positive_support=ref['derivation']['positive_contributors'],
                        meets_positive_quorum10=ref['meets_positive_quorum10'],
                        candidate_worst_asr=worst(candidate),control_worst_asr=worst(v),
                        worst_asr_difference=worst(candidate)-worst(v),
                        full_asr_difference=candidate['complete_trigger']['asr']-v['complete_trigger']['asr'],
                        candidate_clean_f1=candidate['clean']['macro_f1_all_model_classes'],
                        control_clean_f1=v['clean']['macro_f1_all_model_classes'],
                        clean_f1_loss=v['clean']['macro_f1_all_model_classes']-candidate['clean']['macro_f1_all_model_classes'],
                        root_norm=ref['root_delta_norm'],aggregate_norm=ref['derivation']['aggregate_norm'])
                    rows.append(pair)
                    cells[(ref['root_method'],ref['root_seed'],control)].append(pair)
            if key in unique:assert unique[key]==models
            unique[key]=models
    aggregate=[]
    for key,values in sorted(cells.items()):
        active=[r for r in values if r['actually_manipulated'] and r['round']<=10]
        clean=[r for r in values if r['mode']=='clean']
        for operational in (False,True):
            a=[r for r in active if not operational or r['meets_positive_quorum10']]
            c=[r for r in clean if not operational or r['meets_positive_quorum10']]
            aggregate.append(dict(zip(('root_method','root_seed','control'),key))|{
                'only_positive_quorum10':operational,'active_comparisons':len(a),
                'lower_worst_asr':sum(r['worst_asr_difference']<-1e-12 for r in a),
                'higher_worst_asr':sum(r['worst_asr_difference']>1e-12 for r in a),
                'equal_worst_asr':sum(abs(r['worst_asr_difference'])<=1e-12 for r in a),
                'mean_difference_points':100*sum(r['worst_asr_difference'] for r in a)/len(a) if a else None,
                'largest_improvement_points':-100*min((r['worst_asr_difference'] for r in a),default=0.) if a else None,
                'largest_worsening_points':100*max((r['worst_asr_difference'] for r in a),default=0.) if a else None,
                'clean_comparisons':len(c),'clean_losses_over_two_points':sum(r['clean_f1_loss']>.02 for r in c),
                'worst_clean_f1_loss_points':100*max((r['clean_f1_loss'] for r in c),default=0.) if c else None})
    summary={'scope':'Fixed-context exploratory transfer on reused validation. Root seeds share a60-row pool and contexts inherit source histories; observations are not independent defended campaigns.',
        'contexts':64,'distinct_seed_base_update_input_sets':len(unique),'root_pool_rows':60,'evaluation_rows':3163,
        'root_configurations':[{'root_method':method,'root_seed':seed,
            'planned_contexts':sum(ref['root_method']==method and ref['root_seed']==seed for row,ref in rawrefs),
            'defined':sum(ref['root_method']==method and ref['root_seed']==seed and ref['defined'] for row,ref in rawrefs),
            'below_positive_quorum10':sum(ref['root_method']==method and ref['root_seed']==seed and ref['defined'] and not ref['meets_positive_quorum10'] for row,ref in rawrefs)}
            for method in p['root_methods'] for seed in p['root_seeds']],
        'pooled_by_reference_method':{},'no_reference_or_parameter_selected':True,'new_client_training':0,
        'new_defender_specific_attack_search':False,'test_inference':False,'current_defaults_changed':False,
        'verification':verified}
    for method in p['root_methods']:
        summary['pooled_by_reference_method'][method]={}
        for control in ('robust','capped','root_only','norm_matched_robust'):
            groups=[a for a in aggregate if a['root_method']==method and a['control']==control and not a['only_positive_quorum10']]
            qgroups=[a for a in aggregate if a['root_method']==method and a['control']==control and a['only_positive_quorum10']]
            summary['pooled_by_reference_method'][method][control]={k:sum(g[k] for g in groups) for k in ('active_comparisons','lower_worst_asr','higher_worst_asr','equal_worst_asr','clean_comparisons','clean_losses_over_two_points')}
            summary['pooled_by_reference_method'][method][control]['worst_clean_f1_loss_points']=max(g['worst_clean_f1_loss_points'] for g in groups if g['worst_clean_f1_loss_points'] is not None)
            summary['pooled_by_reference_method'][method][control]['positive_quorum10_active_comparisons']=sum(g['active_comparisons'] for g in qgroups)
            for k in ('lower_worst_asr','higher_worst_asr','equal_worst_asr','clean_comparisons','clean_losses_over_two_points'):
                summary['pooled_by_reference_method'][method][control]['positive_quorum10_'+k]=sum(g[k] for g in qgroups)
            active=[r for r in rows if r['root_method']==method and r['control']==control and r['actually_manipulated'] and r['round']<=10]
            summary['pooled_by_reference_method'][method][control]['mean_difference_points']=100*sum(r['worst_asr_difference'] for r in active)/len(active) if active else None
            summary['pooled_by_reference_method'][method][control]['largest_improvement_points']=-100*min((r['worst_asr_difference'] for r in active),default=0.)
            summary['pooled_by_reference_method'][method][control]['largest_worsening_points']=100*max((r['worst_asr_difference'] for r in active),default=0.)
        zero={'manipulated_zero_score':0,'manipulated_observations':0,'unmodified_zero_score':0,'unmodified_observations':0}
        for row,ref in rawrefs:
            if ref['root_method']!=method or not ref['defined']:continue
            manipulated=set(row['actually_manipulated_clients'])
            for c,score in ref['derivation']['scores'].items():
                prefix='manipulated' if c in manipulated else 'unmodified'
                zero[prefix+'_observations']+=1;zero[prefix+'_zero_score']+=score==0
        summary['pooled_by_reference_method'][method]['zero_score_observations']=zero
    for name,records in [('comparisons.csv',rows),('aggregate.csv',aggregate)]:
        with (D/name).open('x',newline='') as h:
            w=csv.DictWriter(h,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
    (D/'summary.json').write_text(json.dumps(summary,indent=2,allow_nan=False)+'\n')
    shutil.copy2(__file__,D/Path(__file__).name)
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
