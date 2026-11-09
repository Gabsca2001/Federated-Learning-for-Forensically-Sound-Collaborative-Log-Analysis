"""Reuse fixed methods on common updates; remove the original in-sample clean calibration."""
from collections import defaultdict
import numpy as np
from audit_common import *
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan

protocol=read(LAB/'secondary-protocol-before-comparison.json');source=Path(protocol['source_root'])
deps=dependencies();deps[1].set_num_threads(1)
cfg=read(ROOT/'clean-s341593/protocol-before-training.json');validation,auxiliary=validation_inputs(cfg)
test=read_pinned(Path(cfg['partition_workspace'])/'server/splits/test.json',read(ROOT/'fixed-endpoint-test.json')['test_snapshot_sha256'])['rows']['test']
initial=read(cfg['base_model_path']);pred,_=predict(initial,validation,deps);vc=[p==r['label'] for p,r in zip(pred,validation,strict=True)]
pred,_=predict(initial,test,deps);tc=[p==r['label'] for p,r in zip(pred,test,strict=True)]
settings=read_yaml(cfg['composite_config_path']);specs=settings['statistics']['indicators']
directions={n:s['direction'] for n,s in specs.items()};weights={n:s['weight'] for n,s in specs.items()}
def indicators(base,exports,clients):
    arrays=arrays_from_export(base,np=np);models=[arrays_from_export(m,np=np) for m in exports]
    values=update_indicators([model_delta(arrays,m) for m in models],client_ids=clients)
    base_f1=evaluate(base,validation,deps)['macro_f1_all_model_classes']
    for r,m in zip(values,exports,strict=True):r['validation_impact']=base_f1-evaluate(m,validation,deps)['macro_f1_all_model_classes']
    return arrays,models,values
refs={};ref_index={}
for cohort,relative in protocol['historical_clean_references'].items():
    workspace=REPO/relative;authenticate(workspace,sha256_file(workspace/'manifest.json'))
    refs[cohort]={}
    for number in range(1,16):
        p=workspace/'rounds'/f'round-{number:03d}';base=read(p/'base-model.json')
        clients=read(p/'round.json')['clients'];exports=[read(p/'updates'/f'{c}.json') for c in clients]
        _,_,values=indicators(base,exports,clients)
        references=build_indicator_references(values,directions=directions)
        score=score_statistical_indicators(values,references=references,weights=weights,z_cap=settings['statistics']['robust_z_cap'])
        pc=settings['policies'];cc=pc['calibration']
        thresholds=calibrate_policy_thresholds(list(score.values()),trust_weight=pc['composite_trust_weight'],statistical_margin=cc['statistical_max_margin'],
            composite_margin=cc['composite_max_margin'],downweight_quantile=cc['composite_downweight_quantile'])
        refs[cohort][number]=(references,thresholds)
    ref_index[cohort]={'path':relative,'manifest_sha256':sha256_file(workspace/'manifest.json')}
save(LAB/'secondary-reference-index.json',ref_index)
rows=[];test_rows=[];counts=defaultdict(int)
for task in protocol['cases']:
    workspace=source/'private-episodes'/task['stream'];authenticate(workspace,sha256_file(workspace/'manifest.json'))
    generation=read(workspace/'generation-protocol.json');plan=DistributedBackdoorPlan.model_validate(generation['attack_plan_for_simulator_and_evaluation_only'])
    partitionroot=REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid')
    mass={r['client_id']:r['train_row_count'] for r in read(partitionroot/'manifest.json')['clients']}
    for number in range(1,16):
        p=workspace/'rounds'/f'round-{number:03d}';record=read(p/'round.json');base=read(p/'base-model.json');clients=record['clients']
        exports=[read(p/'updates'/f'{c}.json') for c in clients]
        arrays,models,values=indicators(base,exports,clients);references,thresholds=refs[task['cohort']][number]
        scored=score_statistical_indicators(values,references=references,weights=weights,z_cap=settings['statistics']['robust_z_cap'])
        trust=TrustSignal(raw_status='software-experiment-admissibility-assumption',admissible=True,risk=0,evaluated_checks=[],failed_checks=[],reasons=['No fresh TPM attestation claimed.'])
        composite_masses=[]
        for c in clients:
            dec=next(x for x in decide_admission_policies(trust=trust,statistics=scored[c],statistical_threshold=thresholds.statistical_threshold,
                composite_threshold=thresholds.composite_threshold,composite_downweight_threshold=thresholds.composite_downweight_threshold,
                trust_weight=thresholds.trust_weight) if x.policy=='gated_composite')
            composite_masses.append(mass[c]*cfg['accepted_downweight_factor'] if dec.status=='accepted_downweighted' else float(mass[c]) if dec.contributes else 0.)
        f,fr=flame_aggregate(base=arrays,models=models,client_ids=clients,noise_factor=.01,seed=task['seed']+number)
        ws=[evaluate(m,auxiliary,deps)['macro_f1_all_model_classes'] for m in exports]
        w,wr=weidetect_aggregate(models=models,client_ids=clients,validation_f1=ws,keep_count=12,seed=task['seed']+number)
        response=read(p/'worker-response.json');new=set(response['comparison_decisions']['envelope']['quarantine_current_round'])
        def weighted(excluded,custom=None):
            indices=[i for i,c in enumerate(clients) if c not in excluded and (custom is None or custom[i]>0)]
            if len(indices)<8:return None
            result=apply_delta(arrays,aggregate_deltas([model_delta(arrays,models[i]) for i in indices],strategy='fedavg',f=0,
                weights=[mass[clients[i]] if custom is None else custom[i] for i in indices]))
            return result
        choices={'fedavg':(arrays_from_export(read(p/'global-model.json'),np=np),set()),
            'flame':(f,set(clients)-set(fr['selected_client_ids'])),
            'weidetect':(w,set(clients)-set(wr['selected_client_ids'])),
            'gated_fixed_reference':(weighted(set(),composite_masses),{c for c,m in zip(clients,composite_masses,strict=True) if m<=0}),
            'client_envelope':(weighted(new),new)}
        intended=set(task['attackers']) if task['mode']=='distributed' else set()
        active=intended if number in task['attack_rounds'] else set()
        for method,(model,excluded) in choices.items():
            status='aggregated' if model is not None else 'failed_without_model'
            model_export=model_with_arrays(base,model) if model is not None else None
            result=outcomes(model_export,validation,plan,vc,deps) if model_export is not None else None
            rows.append({'stream':task['stream'],'cohort':task['cohort'],'seed':task['seed'],'mode':task['mode'],'round':number,'method':method,
                'status':status,'poisoned_opportunities':len(active),'clean_opportunities':15-len(active),
                'poisoned_excluded':len(excluded&active),'currently_clean_excluded':len(excluded-active),
                'never_attacker_excluded':len(excluded-intended),'outcomes':result})
            if number in (10,15) and model_export is not None:
                test_result=outcomes(model_export,test,plan,tc,deps)
                test_rows.append({'stream':task['stream'],'cohort':task['cohort'],'seed':task['seed'],'mode':task['mode'],'round':number,'method':method,
                    'model_sha256':sha256_bytes(derived_json_bytes(model_export)),'test':test_result})
            counts['conditional_model_outputs']+=int(model is not None)
        counts['source_contexts']+=1
    print(json.dumps({'secondary_case':task['stream'],'cohort':task['cohort'],'mode':task['mode'],'contexts':15}),flush=True)
summary=[]
for cohort in ('iid','non-iid'):
    for mode in ('clean','distributed'):
        for method in protocol['methods']:
            subset=[r for r in rows if r['cohort']==cohort and r['mode']==mode and r['method']==method]
            totals={k:sum(r[k] for r in subset) for k in ('poisoned_opportunities','clean_opportunities','poisoned_excluded','currently_clean_excluded','never_attacker_excluded')}
            summary.append({'cohort':cohort,'mode':mode,'method':method,'contexts':len(subset),**totals,'failed_contexts':sum(r['status']!='aggregated' for r in subset)})
save(LAB/'secondary-comparison.json',{'profile':'independent-clean-reference-secondary-comparison-v1','summary':summary,'counts':dict(counts),
    'source_references':ref_index,'raw_client_training_rows_used':False,'new_training_calls':0,
    'qualification':protocol['qualification']})
save(LAB/'secondary-round-results.json',{'rows':rows});save(LAB/'secondary-test-results.json',{'rows':test_rows})
for name in ('secondary-comparison.json','secondary-test-results.json'):(OUT/name).write_bytes((LAB/name).read_bytes())
print('SECONDARY COMMON-INPUT COMPARISON COMPLETE',json.dumps(dict(counts)),flush=True)
