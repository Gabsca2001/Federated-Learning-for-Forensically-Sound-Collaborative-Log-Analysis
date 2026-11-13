"""Authenticate and numerically consolidate the preserved DBA comparison."""
from collections import defaultdict,Counter
from pathlib import Path
import json
import csv
import numpy as np
from audit_common import *
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan

protocol=read(LAB/'protocol-before-audit-and-benchmark.json');deps=dependencies();deps[1].set_num_threads(1)
records=[];endpoint_rows=[];source_index={};verified=Counter();aux_hashes=set();budget_pairs=[];flags=Counter()
for case,expected in sorted(protocol['source_cases'].items()):
    workspace=ROOT/case
    assert sha256_file(workspace/'manifest.json')==expected['manifest_sha256']
    assert sha256_file(workspace/'experiment-authority.public.pem')==expected['public_key_sha256']
    authenticate(workspace,expected['manifest_sha256'])
    cfg=read(workspace/'protocol-before-training.json');assert cfg['recurrence']=='fedavg'
    aux_hashes.add(sha256_file(workspace/'fixed-auxiliary-validation-set.json'))
    for number in range(1,16):
        d=load_case(case,number);comp=d['comparison'];r=d['record'];p=d['prefix']
        assert d['clients']==comp['same_frozen_client_order']
        assert sha256_file(p/'base-model.json')==comp['base_model_sha256']==r['base_model_sha256']
        update_hashes=[sha256_file(p/'updates'/f'{c}.json') for c in d['clients']]
        assert update_hashes==comp['update_sha256']==[q['local_model_sha256'] for q in r['local_training_records']]
        if number<15:
            assert (p/'aggregates/fedavg.json').read_bytes()==(workspace/'rounds'/f'round-{number+1:03d}'/'base-model.json').read_bytes()
        poison=read(p/'poisoning-evaluation-only.json')
        assert [q['client_id'] for q in poison]==d['clients']
        active={q['client_id'] for q in poison if q['modified_feature_values']>0 or q['label_flip_count']>0}
        intended=set(cfg['attack_plan']['client_components']) if cfg['attack_mode']!='clean' else set()
        assert active<=intended
        phase='clean' if cfg['attack_mode']=='clean' else 'active' if active else 'post-attack'
        assert set(comp['comparisons'])==set(METHODS)
        for method in METHODS:
            source=comp['comparisons'][method];value=kernel(method,d)
            modelpath=p/'aggregates'/f'{method}.json'
            if value is None:
                assert source['status']=='failed_without_model' and not modelpath.exists();flags['failed_aggregates']+=1
            else:
                assert sha256_file(modelpath)==source['model_sha256']
                assert derived_json_bytes(model_with_arrays(d['base'],value))==modelpath.read_bytes(),(case,number,method)
            selected=None;flagged=None;down=set();clipped=set()
            if method in ('flame','weidetect'):
                selected=set(source['aggregation']['selected_client_ids']);flagged=set(d['clients'])-selected
                if method=='flame':
                    clipped={c for c,f in zip(d['clients'],source['aggregation'].get('clipping_factors',[1.]*15),strict=True) if f<1 and c in selected}
                    assert source['aggregation']['noise_sigma']>0
                else:
                    report=source['aggregation'];assert len(selected)==cfg['weidetect_keep_count']==12
                    scores=report['validation_f1'];priorities=np.random.default_rng(cfg['seed']+number).permutation(15)
                    rank=sorted(range(15),key=lambda i:(-scores[i],int(priorities[i])))[:12]
                    assert selected=={d['clients'][i] for i in rank}
                    flags['weidetect_equal_to_F1_top_K']+=1
                    flags['weidetect_degenerate_fit']+=int(report['fit_status']!='fitted_positive_scores_location_zero')
            elif method=='gated_composite':
                decisions=d['calibration']['decisions'];assert not d['calibration']['attacker_identities_used']
                selected={q['client_id'] for q in decisions if q['mass']>0}
                down={q['client_id'] for q in decisions if q['decision']['status']=='accepted_downweighted'}
                flagged=down|(set(d['clients'])-selected)
            elif method=='fedavg':selected=set(d['clients']);flagged=set()
            excluded=set(d['clients'])-selected if selected is not None else None
            clean=set(d['clients'])-active
            row={'case':case,'mode':cfg['attack_mode'],'seed':cfg['seed'],'round':number,'phase':phase,'method':method,
                'status':source['status'],'model_sha256':source.get('model_sha256'),'actually_poisoned_clients':sorted(active),
                'selection_metric_available':selected is not None,
                'poisoned_opportunities':len(active),'clean_update_opportunities':len(clean),'never_attacker_opportunities':15-len(intended),
                'poisoned_excluded':None if excluded is None else len(excluded&active),
                'clean_excluded':None if excluded is None else len(excluded&clean),
                'never_attacker_excluded':None if excluded is None else len(excluded-intended),
                'currently_clean_scheduled_excluded':None if excluded is None else len((excluded&intended)-active),
                'poisoned_flagged':None if flagged is None else len(flagged&active),
                'clean_flagged':None if flagged is None else len(flagged&clean),
                'poisoned_downweighted':len(down&active),'clean_downweighted':len(down&clean),
                'selected_clipped_clients':len(clipped),'validation':source.get('validation'),
                'gated_clean_quarantine_in_sample':method=='gated_composite' and cfg['attack_mode']=='clean'}
            records.append(row);verified['recomputed_aggregates']+=int(value is not None)
        verified['source_rounds']+=1;verified['source_updates']+=15
        source_index[f'{case}/round-{number:03d}']={'case_manifest_sha256':expected['manifest_sha256'],
            'base_model_sha256':r['base_model_sha256'],'update_sha256':update_hashes,'comparison_sha256':sha256_file(p/'comparison.json')}
    print(json.dumps({'audited_source_case':case,'rounds':15}),flush=True)
assert len(aux_hashes)==1
# Verify equal example selection budgets, while retaining the different edit budget.
for seed in (341593,342593,343593):
    counts=Counter()
    for number in range(1,16):
        a=read(ROOT/f'distributed-s{seed}/rounds/round-{number:03d}/poisoning-evaluation-only.json')
        b=read(ROOT/f'complete-trigger-s{seed}/rounds/round-{number:03d}/poisoning-evaluation-only.json')
        for left,right in zip(a,b,strict=True):
            assert left['client_id']==right['client_id'] and left['poisoned_window_ids']==right['poisoned_window_ids']
            counts['equal_selected_example_ids']+=len(left['poisoned_window_ids'])
            counts['distributed_feature_edits']+=left['modified_feature_values'];counts['complete_feature_edits']+=right['modified_feature_values']
    budget_pairs.append({'seed':seed,**dict(counts)})
# Recompute the fixed, previously opened test endpoints without selecting new models.
endpoints=read(ROOT/'fixed-endpoint-test.json');assert sha256_file(ROOT/'fixed-endpoint-test.json')==protocol['fixed_test_report_sha256']
cfg=read(ROOT/'clean-s341593/protocol-before-training.json')
testpath=Path(cfg['partition_workspace'])/'server/splits/test.json'
test=read_pinned(testpath,endpoints['test_snapshot_sha256'])['rows']['test']
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256']);pred,_=predict(initial,test,deps)
correct=[p==r['label'] for p,r in zip(pred,test,strict=True)]
for case,rounds in sorted(endpoints['fixed_endpoint_results'].items()):
    casecfg=read(ROOT/case/'protocol-before-training.json');plan=DistributedBackdoorPlan.model_validate(casecfg['attack_plan'])
    for number,methods in rounds.items():
        for method,value in methods.items():
            path=ROOT/case/'rounds'/f'round-{int(number):03d}'/'aggregates'/f'{method}.json'
            assert sha256_file(path)==value['source_model_sha256']
            actual=outcomes(read(path),test,plan,correct,deps)
            assert actual==value['test'],(case,number,method)
            endpoint_rows.append({'case':case,'mode':casecfg['attack_mode'],'seed':casecfg['seed'],'round':int(number),
                'method':method,'model_sha256':value['source_model_sha256'],'test':actual})
            verified['recomputed_test_endpoints']+=1
    print(json.dumps({'recomputed_test_case':case,'endpoint_rounds':sorted(rounds)}),flush=True)
summary=[]
for mode in ('clean','distributed','complete-trigger'):
    for phase in ('clean',) if mode=='clean' else ('active','post-attack'):
        for method in METHODS:
            rows=[r for r in records if r['mode']==mode and r['phase']==phase and r['method']==method]
            s={'mode':mode,'phase':phase,'method':method,'contexts':len(rows),'selection_metric_available':rows[0]['selection_metric_available']}
            keys=('poisoned_opportunities','clean_update_opportunities','never_attacker_opportunities','poisoned_excluded','clean_excluded',
                'never_attacker_excluded','currently_clean_scheduled_excluded','poisoned_flagged','clean_flagged','poisoned_downweighted','clean_downweighted','selected_clipped_clients')
            for key in keys:s[key]=sum(r[key] for r in rows) if rows[0][key] is not None else None
            s['excluded_poison_recall']=s['poisoned_excluded']/s['poisoned_opportunities'] if s['poisoned_excluded'] is not None and s['poisoned_opportunities'] else None
            s['clean_exclusion_rate']=s['clean_excluded']/s['clean_update_opportunities'] if s['clean_excluded'] is not None and s['clean_update_opportunities'] else None
            summary.append(s)
endpoint_summary=[]
for mode in ('clean','distributed','complete-trigger'):
    for number in (10,15):
        for method in METHODS:
            rows=[r for r in endpoint_rows if r['mode']==mode and r['round']==number and r['method']==method]
            values={'accuracy':[r['test']['clean']['accuracy'] for r in rows],
                'macro_f1':[r['test']['clean']['macro_f1_all_model_classes'] for r in rows],
                'ASR':[r['test']['complete_trigger']['asr'] for r in rows]}
            s={'mode':mode,'round':number,'method':method,'seeds':len(rows)}
            for key,v in values.items():s[key+'_mean']=float(np.mean(v));s[key+'_sample_std']=float(np.std(v,ddof=1))
            s['component_ASR_means']={c:float(np.mean([r['test']['component_triggers'][c]['asr'] for r in rows])) for c in rows[0]['test']['component_triggers']}
            endpoint_summary.append(s)
result={'profile':'authenticated-common-input-DBA-consolidation-v1','verification':dict(verified),
    'auxiliary_set_sha256':next(iter(aux_hashes)),'auxiliary_rows':len(read(ROOT/'clean-s341593/fixed-auxiliary-validation-set.json')['window_ids']),
    'budget_pairs':budget_pairs,'operational_selection_summary':summary,'fixed_test_endpoint_summary':endpoint_summary,'adapter_diagnostics':dict(flags),
    'classification_scope':'Operational exclusion/downweight counts, not semantic malicious-intent classification. No detector metric inferred for methods without stored selection decisions.',
    'calibration_limit':'Clean gated strict-quarantine rate is in-sample; attack cases use paired clean campaign references. These references are an experimental assumption.',
    'new_client_training_calls':0,'fresh_TPM_attestation':False,'new_test_selection_or_tuning':False}
save(LAB/'consolidated-results.json',result);save(LAB/'round-metrics.json',{'rows':records});save(LAB/'fixed-test-endpoints.json',{'rows':endpoint_rows});save(LAB/'source-input-index.json',source_index)
for name in ('consolidated-results.json','fixed-test-endpoints.json'):(OUT/name).write_bytes((LAB/name).read_bytes())
print('CONSOLIDATION COMPLETE',json.dumps(dict(verified)),flush=True)
