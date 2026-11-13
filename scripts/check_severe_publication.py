"""Independently reconcile derived severe-gate tables with verified evidence.

This checker uses only the standard library and never imports the publisher,
controller, score implementation, or selection helper. Numerical update replay
is performed separately by the saved-update verifier, whose closure is pinned.
"""
from __future__ import annotations
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from fractions import Fraction
from pathlib import Path
import os
from statistics import mean, median, stdev

ROOT=Path(__file__).resolve().parents[1]
LAB=ROOT/'artifacts/revision-severe-tail-gate-v1'
OUT=ROOT/'results/gates-probes/revision-severe-tail-gate-v1'
LOCAL=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'severe-gate-20261106')
METHODS=('tpm_only','gated_composite','mean_control','severe_gate')


def read(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def table(name):
    with (OUT/name).open(newline='') as stream:return list(csv.DictReader(stream))
def equal(actual,expected):
    if expected is None:assert actual in ('',None), (actual,expected)
    elif isinstance(expected,bool):assert actual==str(expected), (actual,expected)
    elif isinstance(expected,(int,float,Fraction)):
        assert actual not in ('',None) and math.isclose(float(actual),float(expected),rel_tol=1e-12,abs_tol=1e-13), (actual,expected)
    else:assert actual==expected, (actual,expected)
def worst(row):
    return max(row['test']['complete_trigger']['asr'],*(x['asr'] for x in row['test']['component_triggers'].values()))
def budget(rows):
    if not rows:return None
    n=sum(len(x['statuses']) for x in rows)
    return dict(observations=n,
        quarantine_rate=sum(v.endswith('quarantined') for x in rows for v in x['statuses'].values())/n,
        downweight_rate=sum(v=='accepted_downweighted' for x in rows for v in x['statuses'].values())/n,
        nominal_mass_retention=float(sum((Fraction(v) for x in rows for v in x['masses'].values()),Fraction(0))/sum(sum(x['example_counts'].values()) for x in rows)),
        minimum_round_mass_retention=min(float(sum(map(Fraction,x['masses'].values()))/sum(x['example_counts'].values())) for x in rows))
def qualifies(b,losses,complete):
    return bool(complete and b['quarantine_rate']<=.05 and b['downweight_rate']<=.15
        and b['nominal_mass_retention']>=.90 and b['minimum_round_mass_retention']>=.80 and max(losses)<=.02)
def flatten(value):
    if isinstance(value,list):
        for child in value:yield from flatten(child)
    else:yield value


def run():
    summary=read(OUT/'summary.json');protocol=read(LAB/'protocol-before-clean-fitting.json')
    assert summary['root_protocol_sha256']==sha(LAB/'protocol-before-clean-fitting.json')
    for relative,digest in protocol['source_locks'].items():assert sha(ROOT/relative)==digest
    for relative,digest in protocol['source_snapshots'].items():assert sha(ROOT/relative)==digest
    for seed,digest in protocol['partitions'].items():assert sha(LAB/'partitions'/seed/'manifest.json')==digest
    for relative,digest in read(OUT/'inventory-final.json')['files'].items():assert sha(ROOT/relative)==digest
    assert not summary['automatic_production_promotion'] and not summary['thesis_edited']
    assert not summary['independent_dataset'] and summary['new_TPM_appraisals']==0
    choice=read(LAB/'selection-decision.json')
    assert summary['selection_sha256']==sha(LAB/'selection-decision.json')
    assert not choice['uses_attack_or_test_outcomes']
    assert choice['selected_candidate']==summary['selected_candidate']
    counts=Counter();verified={}
    for phase in ('fit','calibration','selection','evaluation'):
        path=LAB/phase/'verified/summary.json'
        if phase=='evaluation' and choice['selected_candidate'] is None:continue
        audit=read(path);verified[phase]=audit
        assert audit['status']=='verified'
        assert audit['test_accessed']==(phase=='evaluation')
        assert summary['phase_pins'][phase]==sha(path)
        assert audit['training_closure_sha256']==sha(LAB/phase/'training-complete.json')
        assert audit['verifier_sha256']==sha(ROOT/'scripts/revision_severe_gate_audit.py')
        closure=read(LAB/phase/'training-complete.json')
        assert not closure['test_inference_performed']
        p=read(LAB/phase/'protocol-before-training.json')
        assert closure['protocol_sha256']==sha(LAB/phase/'protocol-before-training.json')
        assert len(audit['cases'])==len(closure['results'])==len(p['tasks'])
        for candidate,digest in p['calibration_models'].items():assert sha(LAB/'models'/f'{candidate}.json')==digest
        assert {c['task']['name'] for c in audit['cases']}=={t['name'] for t in p['tasks']}
        for c in audit['cases']:
            assert c['source_manifest_sha256']==sha(LAB/phase/'cases'/c['task']['name']/'evidence/manifest.json')
            assert c['test_accessed']==(phase=='evaluation')
        if phase!='evaluation':counts['development_cases']+=len(audit['cases'])
        for c in audit['cases']:
            for name in ('rounds','queries','local_repeats'):
                counts[('evaluation_' if phase=='evaluation' else 'development_')+name]+=c['verification'][name]
    assert dict(counts)==summary['counts']
    # Recompute clean selection without importing the frozen selector.
    selection={(c['task']['seed'],c['task']['candidate']):c for c in verified['selection']['cases']}
    for candidate in choice['candidates']:
        model=read(LAB/'models'/f'{candidate["candidate"]}.json')
        for d in candidate['details']:
            c=selection[(d['seed'],candidate['candidate'])];control=selection[(d['seed'],None)]
            complete=c['complete'] and control['complete'];b=budget(c['rows']) if complete else None
            left={x['round']:x for x in c['rows']};right={x['round']:x for x in control['rows']}
            losses=[right[n]['validation_clean']['macro_f1_all_model_classes']-left[n]['validation_clean']['macro_f1_all_model_classes'] for n in (10,15)] if complete else []
            assert d['complete']==complete and d['budget']==b and d['validation_losses']==losses
            assert d['qualified']==(qualifies(b,losses,complete) and model['thresholds'][d['cohort']]['nonempty_quarantine_region'])
        assert candidate['qualified']==all(d['qualified'] for d in candidate['details'])
        assert candidate['worst_validation_loss']==max((v for d in candidate['details'] for v in d['validation_losses']),default=None)
        assert candidate['minimum_mass_retention']==min((d['budget']['nominal_mass_retention'] for d in candidate['details'] if d['budget']),default=None)
    candidates=list(protocol['candidates'])
    # The JSON object uses canonical key order; the controller's declared order
    # is retained explicitly here for the only potential exact-tie fallback.
    declared_order=['max_tail','max_tail_conservative'];assert set(candidates)==set(declared_order)
    feasible=sorted((c for c in choice['candidates'] if c['qualified']),key=lambda c:(c['worst_validation_loss'],-c['minimum_mass_retention'],declared_order.index(c['candidate'])))
    assert choice['selected_candidate']==(feasible[0]['candidate'] if feasible else None)
    refit=read(OUT/'models-refit-verification.json')
    assert refit==read(LAB/'models-refit-verification.json')
    assert refit['status']=='verified' and refit['models_independently_refitted']==3
    assert not refit['test_accessed'] and not refit['attack_results_accessed']
    assert refit['checker_sha256']==sha(ROOT/'scripts/check_severe_models.py')
    if choice['selected_candidate'] is None:
        assert not summary['research_guardrails_pass'] and not summary['evaluation_performed']
        case_count=round_count=group_count=0
    else:
        source=verified['evaluation']['cases'];assert len(source)==96
        lookup={(c['task']['seed'],c['task']['method'],c['task']['mode']):c for c in source}
        assert len(lookup)==96
        published={r['case']:r for r in table('cases.csv')};assert len(published)==96
        published_rounds={(r['case'],int(r['round'])):r for r in table('rounds.csv')}
        assert len(published_rounds)==counts['evaluation_rounds']
        pooled=defaultdict(Counter);times=defaultdict(lambda:defaultdict(list));alarms=Counter()
        severe_model=read(LAB/'models'/f'{choice["selected_candidate"]}.json')
        for c in source:
            t=c['task'];r=published[t['name']];rows=c['rows'];complete=c['complete']
            for name,value in dict(cohort=t['cohort'],method=t['method'],seed=t['seed'],mode=t['mode'],
                                   complete=complete,completed_rounds=len(rows)).items():equal(r[name],value)
            assert c['completed_rounds']==len(rows)
            assert [x['round'] for x in rows]==list(range(1,len(rows)+1))
            assert complete==(len(rows)==15)
            if t['method']=='severe_gate':assert t['candidate']==choice['selected_candidate']
            if t['method']=='mean_control':assert t['candidate']=='mean_control'
            equal(r['peak_full_asr'],max(x['test']['complete_trigger']['asr'] for x in rows) if complete else None)
            equal(r['peak_worst_asr'],max(worst(x) for x in rows) if complete else None)
            equal(r['observed_prefix_peak_asr'],max((x['test']['complete_trigger']['asr'] for x in rows),default=None))
            equal(r['final_full_asr'],rows[-1]['test']['complete_trigger']['asr'] if complete else None)
            equal(r['final_clean_macro_f1'],rows[-1]['test']['clean']['macro_f1_all_model_classes'] if complete else None)
            metrics=Counter()
            for x in rows:
                pr=published_rounds[(t['name'],x['round'])]
                for name,value in dict(full_asr=x['test']['complete_trigger']['asr'],worst_trigger_asr=worst(x),
                    clean_macro_f1=x['test']['clean']['macro_f1_all_model_classes'],selected_alpha=x['selected_alpha']).items():equal(pr[name],value)
                for client,status in x['statuses'].items():
                    prefix='manipulated' if client in x['actually_manipulated_clients'] else 'unmodified'
                    metrics[prefix+'_observations']+=1
                    metrics[prefix+'_quarantined']+=int(status.endswith('quarantined'))
                    metrics[prefix+'_downweighted']+=int(status=='accepted_downweighted')
                    metrics[prefix+'_nominal_examples']+=x['example_counts'][client]
                    metrics[prefix+'_retained_mass']+=Fraction(x['masses'][client])
                for name,value in x['timing'].items():
                    if value is not None:times[(t['cohort'],t['method'])][name].append(value)
                if t['method']=='severe_gate':
                    path=LAB/'evaluation/cases'/t['name']/'evidence/rounds'/f'round-{x["round"]:03d}'/'gate-state.json'
                    state=read(path);limits=severe_model['thresholds'][t['cohort']]
                    for client,detail in state['severe_tail_details'].items():
                        values=[];q=[]
                        for name,component in detail['components'].items():
                            direction=severe_model['references'][detail['reference_profile']][name]['direction']
                            raw=component['raw_value'];mu=component['reference_median']
                            scale=max(1.4826*component['reference_mad'],1e-9*max(1.,abs(mu)))
                            dev=max(0.,raw-mu if direction=='higher' else mu-raw)
                            value=math.log1p(dev/scale)/component['clean_tail_normalizer']
                            assert math.isclose(value,component['normalized_severity'],rel_tol=1e-12,abs_tol=1e-13)
                            values.append(value)
                            if value/(1+value)>limits['statistical_threshold']:q.append(name)
                        m=max(values);risk=m/(1+m)
                        assert math.isclose(detail['bounded_risk'],risk,rel_tol=1e-12,abs_tol=1e-13)
                        assert set(q)==set(detail['quarantine_alarm_indicators'])
                        assert state['calibrated_scores'][client]['components']==[]
                        if q:
                            assert x['statuses'][client]=='statistically_quarantined'
                            alarms['actual_component_alarm_decisions']+=1
                            for name in q:alarms[name]+=1
            for name,value in metrics.items():equal(r[name],value)
            if t['mode']!='clean':
                pooled[(t['cohort'],t['method'])].update(metrics)
                pooled[(t['cohort'],t['method'])]['completed_histories']+=int(complete)
        for r in table('interventions.csv'):
            expected=pooled[(r['cohort'],r['method'])]
            for name,value in expected.items():equal(r[name],value)
            for prefix in ('unmodified','manipulated'):
                n=expected[prefix+'_nominal_examples']
                equal(r[prefix+'_mass_retention'],expected[prefix+'_retained_mass']/n if n else None)
        assert len(table('interventions.csv'))==len(pooled)==8
        assert dict(alarms)==summary['actual_alarms']
        for r in table('costs.csv'):
            for name,values in times[(r['cohort'],r['method'])].items():
                if name in r:equal(r[name],median(values))
        groups=defaultdict(list)
        for c in source:groups[(c['task']['cohort'],c['task']['mode'],c['task']['method'])].append(c)
        aggregate=table('aggregate.csv');assert len(aggregate)==len(groups)==32
        for r in aggregate:
            cs=groups[(r['cohort'],r['mode'],r['method'])];equal(r['planned'],len(cs));equal(r['complete'],sum(c['complete'] for c in cs))
            values={name:[] for name in ('peak_full_asr','peak_worst_asr','final_full_asr','final_clean_macro_f1')}
            for c in cs:
                if not c['complete']:continue
                rs=c['rows'];values['peak_full_asr'].append(max(x['test']['complete_trigger']['asr'] for x in rs))
                values['peak_worst_asr'].append(max(worst(x) for x in rs))
                values['final_full_asr'].append(rs[-1]['test']['complete_trigger']['asr'])
                values['final_clean_macro_f1'].append(rs[-1]['test']['clean']['macro_f1_all_model_classes'])
            for name,vs in values.items():
                equal(r[name],mean(vs) if vs else None);equal(r[name+'_n'],len(vs))
                equal(r[name+'_sd'],stdev(vs) if len(vs)>1 else None)
        guards=read(OUT/'clean-guardrails.json');assert len(guards)==24
        for g in guards:
            key=(g['seed'],g['method'],'clean');c=lookup[key];rows=c['rows']
            b=budget(rows)
            assert g['budget']==b
            control=lookup[(g['seed'],'tpm_only','clean')];cb={x['round']:x for x in control['rows']};rb={x['round']:x for x in rows}
            losses=[cb[n]['test']['clean']['macro_f1_all_model_classes']-rb[n]['test']['clean']['macro_f1_all_model_classes'] for n in (10,15) if n in cb and n in rb]
            assert g['test_f1_losses']==losses
            good=qualifies(b,losses,c['complete'] and control['complete'])
            assert g['qualified']==good
        def effect(c):
            clean=lookup[(c['task']['seed'],c['task']['method'],'clean')];base={x['round']:x for x in clean['rows']}
            pairs=[(worst(x)-worst(base[x['round']]),base[x['round']]['test']['clean']['macro_f1_all_model_classes']-x['test']['clean']['macro_f1_all_model_classes']) for x in c['rows'] if x['round'] in base]
            return c['complete'] and clean['complete'],max((h for h,_ in pairs),default=None),any(h>=.20 and loss<=.05 for h,loss in pairs)
        comparisons=table('attack-comparison.csv');assert len(comparisons)==18
        mean_defined=old_defined=bad_mean=bad_old=benefits=non_iid_benefits=0
        for r in comparisons:
            seed=int(r['seed']);mode=r['mode'];a,ah,_=effect(lookup[(seed,'severe_gate',mode)])
            m,mh,_=effect(lookup[(seed,'mean_control',mode)]);o,oh,_=effect(lookup[(seed,'gated_composite',mode)]);t,th,e=effect(lookup[(seed,'tpm_only',mode)])
            defined=a and m;old=a and o;benefit=defined and e and ah<mh
            for name,value in dict(mean_comparison_defined=defined,original_comparison_defined=old,tpm_comparison_defined=a and t,
                proposed_harm=ah,mean_harm=mh,original_harm=oh,tpm_harm=th,effective_tpm_control=e,
                worse_than_mean=defined and ah>mh,worse_than_original=old and ah>oh,strict_mean_benefit_in_effective_control=benefit).items():equal(r[name],value)
            mean_defined+=defined;old_defined+=old;bad_mean+=defined and ah>mh;bad_old+=old and ah>oh
            benefits+=benefit;non_iid_benefits+=benefit and r['cohort']=='non-iid'
        complete={m:sum(c['complete'] for c in source if c['task']['method']==m) for m in METHODS}
        assert complete==summary['completed_by_method']
        clean_ok=all(g['qualified'] for g in guards if g['method']=='severe_gate')
        assert summary['clean_guardrails_pass']==clean_ok
        assert summary['proposed_cases_complete']==(complete['severe_gate']==24)
        assert summary['mean_comparisons_defined']==mean_defined and summary['original_comparisons_defined']==old_defined
        assert summary['worse_mean_cases']==bad_mean and summary['worse_original_cases']==bad_old
        assert summary['effective_control_mean_benefits']==benefits
        assert summary['research_guardrails_pass']==(clean_ok and complete['severe_gate']==24 and mean_defined==18 and bad_mean==0 and benefits>=2 and non_iid_benefits>=1)
        residuals=table('residuals.csv');expected=set()
        for seed,method,mode in lookup:
            if method=='severe_gate' and mode!='clean':
                clean=lookup[(seed,method,'clean')];attacked=lookup[(seed,method,mode)]
                if clean['complete'] and attacked['complete']:expected.add((seed,mode))
        assert {(int(r['seed']),r['mode']) for r in residuals}==expected
        assert len(residuals)==len(expected)
        for r in residuals:
            seed=int(r['seed']);mode=r['mode'];clean=lookup[(seed,'severe_gate','clean')];attacked=lookup[(seed,'severe_gate',mode)]
            cp=LAB/'evaluation/cases'/clean['task']['name']/'evidence/rounds/round-015/global-model.json'
            ap=LAB/'evaluation/cases'/attacked['task']['name']/'evidence/rounds/round-015/global-model.json'
            assert r['clean_model_sha256']==sha(cp) and r['attacked_model_sha256']==sha(ap)
            cmodel=read(cp);amodel=read(ap);squares=[]
            for left,right in zip(cmodel['parameters'],amodel['parameters'],strict=True):
                assert (left['name'],left['dtype'],left['shape'])==(right['name'],right['dtype'],right['shape'])
                squares.extend((x-y)**2 for x,y in zip(flatten(left['values']),flatten(right['values']),strict=True))
            equal(r['parameter_l2'],math.sqrt(math.fsum(squares)))
            assert int(r['test_denominator'])==4937 and 0<=int(r['prediction_disagreements'])<=4937
        diagnosis=read(LAB/'posthoc-diagnosis/summary.json')
        assert diagnosis==read(OUT/'diagnosis-summary.json')
        assert summary['posthoc_diagnosis_sha256']==sha(LAB/'posthoc-diagnosis/summary.json')
        assert diagnosis['source_verification_sha256']==summary['phase_pins']['evaluation']
        assert diagnosis['diagnostic_script_sha256']==sha(ROOT/'scripts/diagnose_severe_gate.py')
        assert diagnosis['posthoc'] and not diagnosis['later_retraining'] and not diagnosis['new_fitting_or_threshold_changes']
        for name,digest in read(OUT/'diagnosis-inventory.json')['files'].items():
            assert sha(OUT/('diagnosis-'+name))==digest
        clean_clients=table('diagnosis-clean-client-exclusions.csv');assert len(clean_clients)==90
        for r in clean_clients:
            seed=int(r['seed']);client=r['client'];c=lookup[(seed,'severe_gate','clean')];rows=c['rows']
            labels=json.loads(r['labels']);equal(r['examples'],sum(labels.values()))
            assert labels[r['largest_class']]==max(labels.values())
            equal(r['largest_class_fraction'],max(labels.values())/sum(labels.values()))
            equal(r['quarantined_rounds'],sum(x['statuses'][client].endswith('quarantined') for x in rows))
            equal(r['downweighted_rounds'],sum(x['statuses'][client]=='accepted_downweighted' for x in rows))
            nominal=sum(rows[0]['example_counts'].values())
            equal(r['nominal_fraction'],rows[0]['example_counts'][client]/nominal)
            equal(r['lost_nominal_mass_fraction'],sum(Fraction(x['example_counts'][client])-Fraction(x['masses'][client]) for x in rows)/(nominal*len(rows)))
        direct=table('diagnosis-same-input-counterfactuals.csv');assert len(direct)==72
        assert len({(r['seed'],r['mode'],r['same_input_alternate_method']) for r in direct})==72
        for r in direct:
            seed=int(r['seed']);c=lookup[(seed,'severe_gate',r['mode'])]
            peak=max(c['rows'],key=lambda x:(worst(x),-x['round']));equal(r['round'],peak['round'])
            source=LAB/'evaluation/cases'/c['task']['name']/'evidence/rounds'/f'round-{peak["round"]:03d}'
            assert r['source_parent_sha256']==sha(source/'base-model.json') and r['actual_checkpoint_sha256']==sha(source/'global-model.json')
            if r['same_input_alternate_method']=='severe_gate':
                equal(r['full_asr'],peak['test']['complete_trigger']['asr']);equal(r['worst_trigger_asr'],worst(peak))
                equal(r['clean_macro_f1'],peak['test']['clean']['macro_f1_all_model_classes'])
                masses={i:Fraction(v) for i,v in peak['masses'].items()};nominal=sum(peak['example_counts'].values())
                equal(r['retained_nominal_mass'],sum(masses.values())/nominal)
                equal(r['manipulated_coefficient_mass'],sum(masses[i] for i in peak['actually_manipulated_clients'])/sum(masses.values()))
        for d in diagnosis['clean_mass_failures']:
            g=next(g for g in guards if g['method']=='severe_gate' and g['seed']==d['seed'])
            assert g['budget']['nominal_mass_retention']==d['pooled_mass_retention']
            assert g['budget']['minimum_round_mass_retention']==d['minimum_round_mass_retention']
        case_count=len(lookup);round_count=len(published_rounds);group_count=len(aggregate)
    receipt=dict(status='verified',checker_sha256=sha(Path(__file__)),summary_sha256=sha(OUT/'summary.json'),
        report_inventory_sha256=sha(OUT/'inventory-final.json'),published_cases=case_count,published_rounds=round_count,
        aggregate_groups=group_count,independent_standard_library_reconciliation=True,
        numerical_replay_separate=True,thesis_edited=False)
    target=OUT/'publication-verification.json'
    assert not target.exists(),'Preserve closed publication verification'
    target.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    (LOCAL/target.name).write_bytes(target.read_bytes())
    print(json.dumps(receipt,indent=2))


if __name__=='__main__':run()
