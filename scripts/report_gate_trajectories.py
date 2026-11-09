"""Publish the locked gate comparison after all training and replay finish."""
from __future__ import annotations
import csv
import json
import statistics
from collections import Counter,defaultdict
from pathlib import Path
import revision_gate_trajectories as study
import numpy as np
from revision_study_data import read
from revision_dba_experiment import predict, save
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export,dependencies

ROOT,LAB=study.ROOT,study.LAB
OUT=ROOT/'results/revision-gate-trajectories-v1'


def write_csv(path,rows):
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with path.open('x',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)


def mean(values):
    values=[v for v in values if v is not None]
    return statistics.mean(values) if values else None


def run():
    study.require(not OUT.exists(),'Preserve published report; use a fresh version for a new publication')
    protocol=read(LAB/'protocol-before-training.json');study.assert_locks(protocol)
    audit=read(LAB/'post-training-evaluation-v2/summary.json')
    check_counts=Counter();summaries=[];round_rows=[];lookup={}
    for case in audit['cases']:
        task=case['task'];rows=case['rows'];by_round={r['round']:r for r in rows}
        lookup[(task['seed'],task['policy'],task['mode'])]=case
        for name,value in case['verification'].items():
            if isinstance(value,int) and not isinstance(value,bool):check_counts[name]+=value
        counts=Counter()
        for row in rows:
            for key,value in row.items():
                if key.endswith('_total') or key.endswith('_accepted') or key.endswith('_accepted_downweighted') or key.endswith('_quarantined'):
                    counts[key]+=value
            metric=row['test']
            round_rows.append(dict(case=task['name'],cohort=task['cohort'],seed=task['seed'],
                policy=task['policy'],mode=task['mode'],round=row['round'],attack_active=row['attack_active'],
                full_asr=metric['complete_trigger']['asr'],worst_trigger_asr=study.scalar_asr(metric),
                clean_macro_f1=metric['clean']['macro_f1_all_model_classes'],clean_accuracy=metric['clean']['accuracy'],
                component_asr_max=max(v['asr'] for v in metric['component_triggers'].values()),
                attacker_slot_normalized_share=row.get('attacker_slot_normalized_share'),
                selected_alpha=row['selected_alpha'],
                actual_manipulated_total=row.get('actual_manipulated_total',0),
                actual_manipulated_quarantined=row.get('actual_manipulated_statistically_quarantined',0),
                currently_unmodified_total=row.get('currently_unmodified_total',0),
                currently_unmodified_quarantined=row.get('currently_unmodified_statistically_quarantined',0),
                currently_unmodified_downweighted=row.get('currently_unmodified_accepted_downweighted',0)))
        complete=case['complete']
        def fixed(number,path):
            if number not in by_round:return None
            value=by_round[number]['test']
            for part in path:value=value[part]
            return value
        attack_rows=[r for r in rows if r['round']<=10]
        summary=dict(case=task['name'],cohort=task['cohort'],seed=task['seed'],policy=task['policy'],mode=task['mode'],
            complete=complete,completed_rounds=len(rows),failure=case.get('failure') or case.get('source_exception'),
            full_asr_round10=fixed(10,('complete_trigger','asr')),
            final_full_asr=fixed(15,('complete_trigger','asr')),
            full_horizon_peak_full_asr=max(r['test']['complete_trigger']['asr'] for r in rows) if complete else None,
            full_horizon_peak_worst_asr=max(study.scalar_asr(r['test']) for r in rows) if complete else None,
            observed_prefix_peak_full_asr=max((r['test']['complete_trigger']['asr'] for r in rows),default=None),
            attack_window_mean_full_asr=mean([r['test']['complete_trigger']['asr'] for r in attack_rows]) if len(attack_rows)==10 else None,
            clean_macro_f1_round10=fixed(10,('clean','macro_f1_all_model_classes')),
            final_clean_macro_f1=fixed(15,('clean','macro_f1_all_model_classes')),
            median_training_seconds=statistics.median(r['training_seconds'] for r in rows) if rows else None,
            median_statistics_seconds=statistics.median(r['indicator_geometry_seconds']+r['validation_inference_seconds']+
                r['score_and_all_policy_decisions_seconds'] for r in rows) if rows else None,
            median_aggregation_seconds=statistics.median(r['aggregation_seconds'] for r in rows) if rows else None,
            median_adaptive_search_seconds=statistics.median(r['attack_search_seconds'] for r in rows if r['attack_search_seconds'] is not None)
                if any(r['attack_search_seconds'] is not None for r in rows) else None,
            actual_manipulated_total=counts['actual_manipulated_total'],
            actual_manipulated_quarantined=counts['actual_manipulated_statistically_quarantined'],
            actual_manipulated_downweighted=counts['actual_manipulated_accepted_downweighted'],
            currently_unmodified_total=counts['currently_unmodified_total'],
            currently_unmodified_quarantined=counts['currently_unmodified_statistically_quarantined'],
            currently_unmodified_downweighted=counts['currently_unmodified_accepted_downweighted'],
            adaptive_zero_alpha_rounds=sum(r['selected_alpha']==0 for r in rows if r['attack_active']) if task['mode']=='adaptive' else 0)
        summary['mean_attack_window_attacker_slot_share']=mean([r.get('attacker_slot_normalized_share') for r in attack_rows])
        nominal=sum(r['currently_unmodified_nominal_examples'] for r in rows)
        summary['unmodified_nominal_weight_retention']=sum(r['currently_unmodified_effective_mass'] for r in rows)/nominal if nominal else None
        summaries.append(summary)
    groups=defaultdict(list)
    for row in summaries:groups[(row['cohort'],row['mode'],row['policy'])].append(row)
    aggregate=[]
    metrics=['full_asr_round10','final_full_asr','full_horizon_peak_full_asr','full_horizon_peak_worst_asr',
             'attack_window_mean_full_asr','clean_macro_f1_round10','final_clean_macro_f1',
             'median_training_seconds','median_statistics_seconds','median_aggregation_seconds','median_adaptive_search_seconds']
    metrics+=['mean_attack_window_attacker_slot_share','unmodified_nominal_weight_retention']
    for (cohort,mode,policy),rows in sorted(groups.items()):
        item=dict(cohort=cohort,mode=mode,policy=policy,planned_cases=len(rows),complete_cases=sum(r['complete'] for r in rows))
        for metric in metrics:
            values=[r[metric] for r in rows if r[metric] is not None]
            item[metric+'_mean']=mean(values)
            item[metric+'_sample_sd']=statistics.stdev(values) if len(values)>1 else None
            item[metric+'_n']=len(values)
        for name in ('actual_manipulated_total','actual_manipulated_quarantined','actual_manipulated_downweighted',
                     'currently_unmodified_total','currently_unmodified_quarantined','currently_unmodified_downweighted',
                     'adaptive_zero_alpha_rounds'):
            item[name]=sum(r[name] for r in rows)
        aggregate.append(item)
    # Paired fixed-endpoint clean utility and within-policy residual effects.
    pairs=[];residuals=[];effectiveness=[];deps=dependencies();deps[1].set_num_threads(1)
    deps[1].use_deterministic_algorithms(True)
    test_path=ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1/server/splits/test.json'
    test_rows=read(test_path)['rows']['test']
    cache={}
    def model_at(task,number):
        key=(task['name'],number)
        if key not in cache:
            model=read(LAB/'cases'/task['name']/'evidence/rounds'/f'round-{number:03d}'/'global-model.json')
            cache[key]=(model,predict(model,test_rows,deps)[0])
        return cache[key]
    for cohort,seed,_ in study.ASSIGNMENTS:
        clean_tpm=lookup[(seed,'tpm_only','clean')]
        for policy in study.POLICIES:
            clean=lookup[(seed,policy,'clean')]
            for number in (10,15):
                c=next((r for r in clean['rows'] if r['round']==number),None)
                t=next((r for r in clean_tpm['rows'] if r['round']==number),None)
                pairs.append(dict(cohort=cohort,seed=seed,policy=policy,round=number,
                    clean_utility_loss_vs_tpm=t['test']['clean']['macro_f1_all_model_classes']-c['test']['clean']['macro_f1_all_model_classes']
                        if c and t else None))
            for mode in ('distributed','complete-trigger','adaptive'):
                attacked=lookup[(seed,policy,mode)]
                cb={r['round']:r for r in clean['rows']}
                deltas=[]
                for row in attacked['rows']:
                    if row['round'] in cb:
                        cm=cb[row['round']]['test'];am=row['test']
                        deltas.append((row['round'],study.scalar_asr(am)-study.scalar_asr(cm),
                                       cm['clean']['macro_f1_all_model_classes']-am['clean']['macro_f1_all_model_classes']))
                effectiveness.append(dict(cohort=cohort,seed=seed,policy=policy,mode=mode,
                    max_paired_worst_trigger_asr_increase=max((v[1] for v in deltas),default=None),
                    effective_under_declared_control_rule=any(a>=.20 and loss<=.05 for _,a,loss in deltas),
                    qualifying_rounds=[n for n,a,loss in deltas if a>=.20 and loss<=.05]))
                for number in (10,15):
                    ar=next((r for r in attacked['rows'] if r['round']==number),None)
                    cr=cb.get(number)
                    if ar and cr:
                        am,ap=model_at(attacked['task'],number);cm,cp=model_at(clean['task'],number)
                        aa=arrays_from_export(am,np=np);ca=arrays_from_export(cm,np=np)
                        distance=float(np.sqrt(sum(np.square(a.astype(float)-c.astype(float)).sum() for a,c in zip(aa,ca,strict=True))))
                        disagreements=sum(a!=c for a,c in zip(ap,cp,strict=True))
                    else:distance=disagreements=None
                    residuals.append(dict(cohort=cohort,seed=seed,policy=policy,mode=mode,round=number,
                        model_l2_from_paired_clean=distance,test_prediction_disagreements=disagreements,
                        test_prediction_denominator=len(test_rows),
                        full_asr=ar['test']['complete_trigger']['asr'] if ar else None))
    summary=dict(profile='independent-original-gate-trajectories-report-v1',planned_cases=72,
        complete_cases=sum(r['complete'] for r in summaries),reconstructed_rounds=check_counts['saved_rounds_reconstructed'],
        verification_counts=dict(check_counts),protocol_sha256=sha256_file(LAB/'protocol-before-training.json'),
        training_closure_sha256=sha256_file(LAB/'training-complete.json'),
        post_training_audit_sha256=sha256_file(LAB/'post-training-evaluation-v2/summary.json'),
        test_split_sha256=sha256_file(test_path),aggregate=aggregate,clean_utility_pairs=pairs,
        control_effectiveness=effectiveness,residual_checks=residuals,
        max_clean_utility_loss_vs_tpm=max((p['clean_utility_loss_vs_tpm'] for p in pairs if p['clean_utility_loss_vs_tpm'] is not None),default=None),
        fresh_TPM_Quotes=0,independent_dataset=False,reused_test_exploratory=True,
        no_threshold_or_aggregator_changed=True)
    OUT.mkdir(parents=True)
    save(OUT/'summary.json',summary)
    for name,rows in [('cases.csv',summaries),('rounds.csv',round_rows),('aggregate.csv',aggregate),
                      ('clean-utility.csv',pairs),('control-effectiveness.csv',effectiveness),('residuals.csv',residuals)]:
        write_csv(OUT/name,rows)
    (OUT/'protocol-before-training.json').write_bytes((LAB/'protocol-before-training.json').read_bytes())
    # Scientific plot: descriptive mean and observed range of three assignments.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    colors=dict(tpm_only='#64748b',sequential='#0f766e',gated_composite='#7c3aed')
    fig,axes=plt.subplots(2,3,figsize=(13,7),sharex=True,sharey=True,layout='constrained')
    for i,cohort in enumerate(('iid','non-iid')):
        for j,mode in enumerate(('distributed','complete-trigger','adaptive')):
            ax=axes[i,j]
            for policy in study.POLICIES:
                data=[r for r in round_rows if r['cohort']==cohort and r['mode']==mode and r['policy']==policy]
                x=sorted({r['round'] for r in data})
                values=[[r['full_asr'] for r in data if r['round']==n] for n in x]
                ax.plot(x,[mean(v) for v in values],label=policy,color=colors[policy],linewidth=1.8)
                ax.fill_between(x,[min(v) for v in values],[max(v) for v in values],color=colors[policy],alpha=.10)
            ax.axvline(10.5,color='#a3a3a3',linestyle='--',linewidth=1)
            ax.set(title=f'{cohort} / {mode}',ylim=(-.02,1.02),xticks=[1,5,10,15])
            if i==1:ax.set_xlabel('Round; clean continuation after round 10')
            if j==0:ax.set_ylabel('Full-trigger test ASR')
    axes[0,0].legend(fontsize=8)
    fig.savefig(OUT/'full-trigger-trajectories.png',dpi=170)
    fig.savefig(OUT/'full-trigger-trajectories.svg')
    plt.close(fig)
    print(json.dumps({k:v for k,v in summary.items() if k not in ('aggregate','clean_utility_pairs','control_effectiveness','residual_checks')},indent=2))


if __name__=='__main__':run()
