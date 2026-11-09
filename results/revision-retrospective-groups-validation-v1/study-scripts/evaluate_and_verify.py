"""Verify payloads, branch recurrence and endpoint metrics; retain every outcome."""
from fractions import Fraction
from group_common import *
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows

protocol=read(LAB/'interventions-protocol-before-computation.json');result=read(LAB/'continuation-results.json')
direct=read(LAB/'direct-effects.json')['cases'];test_report=read(LAB/'test-endpoints.json')
deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
cfg=read(CFG);validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256']);pred,_=predict(initial,validation,deps)
correct=[r['label']==p for r,p in zip(validation,pred,strict=True)]
test=read_pinned(Path(cfg['partition_workspace'])/'server/splits/test.json',test_report['test_snapshot_sha256'])['rows']['test']
pred,_=predict(initial,test,deps);tc=[r['label']==p for r,p in zip(test,pred,strict=True)]
private=read(LAB/'private-alias-map.json');cases={c['alias']:c for c in protocol['cases']}
parts={};plans={};verified={'direct_model_reaggregations':0,'direct_outcome_recomputations':0,
    'branch_model_reaggregations':0,'new_local_input_commitments':0,'source_prefix_input_commitments':0,
    'new_no_intervention_models_matched':0,'new_no_intervention_local_outputs_matched':0,
    'final_validation_endpoints_recomputed':0,'test_endpoints_recomputed':0,'reference_comparisons':0}
for cohort,name in [('iid','m3-data24-parquet-iid-local-test-v1'),('non-iid','m3-data24-parquet-non-iid')]:
    root=REPO/'artifacts'/name;records={r['client_id']:r for r in read(root/'manifest.json')['clients']}
    parts[cohort]={'records':records,'manifest_sha256':sha256_file(root/'manifest.json'),
        'rows':{c:read_pinned(root/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()}}
for alias,item in private.items():
    authenticate(REPO/item['source'],item['manifest_sha256'])
    if item['role']=='evaluation':
        source=REPO/item['source'];generation=read(source/'generation-protocol.json')
        plans[alias]=DistributedBackdoorPlan.model_validate(generation['attack_plan_for_simulator_and_evaluation_only'])
        d=parts[item['cohort']];task=item['task']
        assert generation['partition_sha256']==d['manifest_sha256']
        assert generation['initial_model_sha256']==cfg['base_model_sha256']
        for number in range(1,11):
            for r in read(source/'rounds'/f'round-{number:03d}'/'round.json')['local_training_records']:
                rows=d['rows'][r['client_id']]
                if task['mode']=='distributed':rows,_=poison_local_rows(rows=rows,plan=plans[alias],client_id=r['client_id'],round_number=number,distributed=True)
                assert r['executed_rows_sha256']==sha256_bytes(derived_json_bytes(rows))
                assert r['snapshot_sha256']==d['records'][r['client_id']]['dataset_sha256']
                assert r['seed']==task['seed']+number*10000+int(d['records'][r['client_id']]['partition_id'])
                verified['source_prefix_input_commitments']+=1

def aggregate(base,exports,weights):
    a=arrays_from_export(base,np=np)
    ds=[model_delta(a,arrays_from_export(m,np=np)) for m in exports]
    return model_with_arrays(base,apply_delta(a,aggregate_deltas(ds,strategy='fedavg',f=0,weights=weights)))
def same_outcome(model,rows,plan,mask,expected):
    actual=outcomes(model,rows,plan,mask,deps)
    assert derived_json_bytes(actual)==derived_json_bytes(expected)
def flat(model):return np.concatenate([a.astype(np.float64).reshape(-1) for a in arrays_from_export(model,np=np)])
def distance(left,right):
    lp,_=predict(left,validation,deps);rp,_=predict(right,validation,deps)
    return {'parameter_L2':float(np.linalg.norm(flat(left)-flat(right))),
        'prediction_disagreements':sum(a!=b for a,b in zip(lp,rp,strict=True)),'prediction_denominator':len(lp),
        'model_bytes_equal':derived_json_bytes(left)==derived_json_bytes(right)}

for case in direct:
    alias=case['alias'];source=REPO/cases[alias]['source'];p=source/'rounds/round-010';base=read(p/'base-model.json')
    clients=sorted(cases[alias]['client_masses']);models={c:read(p/'updates'/f'{c}.json') for c in clients}
    for r in case['removals']:
        remaining=[c for c in clients if c not in r['removed']]
        model=aggregate(base,[models[c] for c in remaining],[cases[alias]['client_masses'][c] for c in remaining])
        path=LAB/'direct-models'/alias/f"{r['key']}.json"
        assert derived_json_bytes(model)==path.read_bytes() and sha256_file(path)==r['model_sha256']
        same_outcome(model,validation,plans[alias],correct,r['outcomes'])
        verified['direct_model_reaggregations']+=1;verified['direct_outcome_recomputations']+=1
    print('DIRECT EFFECTS VERIFIED',alias,len(case['removals']),flush=True)

branches={}
for branch in result['branches']:
    alias=branch['alias'];root=LAB/branch['path'];source=REPO/branch['source'];task=branch['task'];d=parts[branch['cohort']]
    authenticate(root,branch['manifest_sha256']);branch_protocol=read(root/'protocol-before-training.json')
    assert branch_protocol['intervention_protocol_sha256']==sha256_file(LAB/'interventions-protocol-before-computation.json')
    assert (root/'rounds/round-010/base-model.json').read_bytes()==(source/'rounds/round-010/base-model.json').read_bytes()
    for number in range(10,16):
        p=root/'rounds'/f'round-{number:03d}';r=read(p/'round.json');clients=r['clients']
        assert clients==[c for c in sorted(d['records']) if c not in branch['removed']]
        assert sum(Fraction(v) for v in r['weights'].values())==1
        if number>10:assert (p/'base-model.json').read_bytes()==(root/'rounds'/f'round-{number-1:03d}'/'global-model.json').read_bytes()
        origin=source/'rounds/round-010' if number==10 and branch['data_mode']=='original-script' else p
        exports=[read(origin/'updates'/f'{c}.json') for c in clients]
        recomputed=aggregate(read(p/'base-model.json'),exports,[len(d['rows'][c]) for c in clients])
        assert derived_json_bytes(recomputed)==(p/'global-model.json').read_bytes()
        assert sha256_file(p/'base-model.json')==r['base_model_sha256']
        assert sha256_file(p/'global-model.json')==r['global_model_sha256']
        verified['branch_model_reaggregations']+=1
        for training in r['local_training_records']:
            c=training['client_id'];rows=d['rows'][c]
            if branch['data_mode']=='original-script':rows,_=poison_local_rows(rows=rows,plan=plans[alias],client_id=c,round_number=number,distributed=True)
            assert sha256_bytes(derived_json_bytes(rows))==training['executed_rows_sha256']
            assert training['seed']==task['seed']+number*10000+int(d['records'][c]['partition_id'])
            assert sha256_file(origin/'updates'/f'{c}.json')==training['local_model_sha256']
            if origin==p:verified['new_local_input_commitments']+=1
        if not branch['removed'] and branch['data_mode']=='original-script' and number>10:
            assert (p/'global-model.json').read_bytes()==(source/'rounds'/f'round-{number:03d}'/'global-model.json').read_bytes()
            verified['new_no_intervention_models_matched']+=1
            for c in clients:
                assert (p/'updates'/f'{c}.json').read_bytes()==(source/'rounds'/f'round-{number:03d}'/'updates'/f'{c}.json').read_bytes()
                verified['new_no_intervention_local_outputs_matched']+=1
    same_outcome(read(root/'rounds/round-015/global-model.json'),validation,plans[alias],correct,branch['rounds'][-1]['validation'])
    verified['final_validation_endpoints_recomputed']+=1
    branches[(alias,branch['data_mode'],key(branch['removed']))]=branch
    print('CONTINUATION VERIFIED',alias,branch['branch'],flush=True)

for endpoint in test_report['endpoints']:
    alias=endpoint['alias'];number=endpoint['round'];k=key(endpoint['removed'])
    path=LAB/'direct-models'/alias/f'{k}.json' if number==10 else LAB/branches[(alias,endpoint['data_mode'],k)]['path']/'rounds/round-015/global-model.json'
    assert sha256_file(path)==endpoint['model_sha256']
    same_outcome(read(path),test,plans[alias],tc,endpoint['test']);verified['test_endpoints_recomputed']+=1

summaries=[]
for case in direct:
    alias=case['alias'];task=case['task'];spec=cases[alias];by_key={r['key']:r for r in case['removals']}
    for selected in spec['methods']:
        value={'alias':alias,'cohort':task['cohort'],'mode':task['mode'],'seed':task['seed'],
            **{k:v for k,v in selected.items() if k not in ('direct_benign_controls','individual_keys','continuation_benign_controls')}}
        if selected['eligible']:
            joint=by_key[selected['joint_key']];individual=[by_key[k] for k in selected['individual_keys']]
            controls=[by_key[key(g)] for g in selected['direct_benign_controls']]
            value['direct']={'original_ASR':case['original']['complete_trigger']['asr'],'joint_ASR':joint['outcomes']['complete_trigger']['asr'],
                'joint_reduction':joint['ASR_reduction'],'best_individual_reduction':max(r['ASR_reduction'] for r in individual),
                'joint_minus_best_individual_reduction':joint['ASR_reduction']-max(r['ASR_reduction'] for r in individual),
                'benign_control_count':len(controls),'benign_controls_at_least_as_effective':sum(r['ASR_reduction']>=joint['ASR_reduction'] for r in controls),
                'benign_control_reduction_range':[min(r['ASR_reduction'] for r in controls),max(r['ASR_reduction'] for r in controls)] if controls else None,
                'joint_clean_accuracy':joint['outcomes']['clean']['accuracy'],'joint_clean_macro_f1':joint['outcomes']['clean']['macro_f1_all_model_classes']}
            if task['mode']=='distributed':
                original=branches[(alias,'original-script',key([]))];joint_branch=branches[(alias,'original-script',selected['joint_key'])]
                matched=branches[(alias,'unmodified',selected['joint_key'])]
                individual_branches=[branches[(alias,'original-script',k)] for k in selected['individual_keys']]
                controls_b=[branches[(alias,'original-script',key(c['removed']))] for c in selected['continuation_benign_controls']]
                source_ASR=original['rounds'][-1]['validation']['complete_trigger']['asr']
                j_ASR=joint_branch['rounds'][-1]['validation']['complete_trigger']['asr']
                changes=[]
                for n in range(10,16):
                    left=LAB/joint_branch['path']/'rounds'/f'round-{n:03d}';right=LAB/matched['path']/'rounds'/f'round-{n:03d}'
                    lr=read(left/'round.json');rr=read(right/'round.json')
                    changes.append({'round':n,'global_model_equal':(left/'global-model.json').read_bytes()==(right/'global-model.json').read_bytes(),
                        'local_models_equal':[r['local_model_sha256'] for r in lr['local_training_records']]==[r['local_model_sha256'] for r in rr['local_training_records']],
                        'local_inputs_equal':[r['executed_rows_sha256'] for r in lr['local_training_records']]==[r['executed_rows_sha256'] for r in rr['local_training_records']]})
                paired=next(v for v in private.values() if v['role']=='evaluation' and v['task']['cohort']==task['cohort'] and v['task']['seed']==task['seed'] and v['task']['mode']=='clean')
                joint_model=read(LAB/joint_branch['path']/'rounds/round-015/global-model.json')
                reference_model=read(LAB/matched['path']/'rounds/round-015/global-model.json')
                clean_model=read(REPO/paired['source']/'rounds/round-015/global-model.json')
                individual_reductions=[source_ASR-r['rounds'][-1]['validation']['complete_trigger']['asr'] for r in individual_branches]
                control_reductions=[source_ASR-r['rounds'][-1]['validation']['complete_trigger']['asr'] for r in controls_b]
                value['continuation']={'source_R15_ASR':source_ASR,'joint_R15_ASR':j_ASR,'joint_R15_reduction':source_ASR-j_ASR,
                    'individual_R15_ASRs':[r['rounds'][-1]['validation']['complete_trigger']['asr'] for r in individual_branches],
                    'joint_minus_best_individual_R15_reduction':source_ASR-j_ASR-max(individual_reductions),
                    'benign_control_R15_ASRs':[r['rounds'][-1]['validation']['complete_trigger']['asr'] for r in controls_b],
                    'benign_controls_at_least_as_effective':sum(r>=source_ASR-j_ASR for r in control_reductions),
                    'joint_clean_accuracy':joint_branch['rounds'][-1]['validation']['clean']['accuracy'],
                    'joint_clean_macro_f1':joint_branch['rounds'][-1]['validation']['clean']['macro_f1_all_model_classes'],
                    'same_start_unmodified_reference_R15_ASR':matched['rounds'][-1]['validation']['complete_trigger']['asr'],
                    'same_start_unmodified_reference_round_comparisons':changes,
                    'same_start_reference_exact_entire_tail':all(all(r[k] for k in ('global_model_equal','local_models_equal','local_inputs_equal')) for r in changes),
                    'same_start_reference_distance':distance(joint_model,reference_model),
                    'all_client_clean_history_distance':distance(joint_model,clean_model),
                    'all_client_clean_history_has_different_participation':True,
                    'inherited_W9_was_not_reconstructed':True}
                verified['reference_comparisons']+=1
        summaries.append(value)
save(LAB/'verified-effect-summary.json',{'cases':summaries,'verification':verified,
    'intentional_collusion_proved':False,'automatic_live_exclusion_validated':False,
    'same_start_reference_is_uncontaminated_global_history':False,'secondary_existing_source_study':True})
save(OUT/'verified-effect-summary.json',read(LAB/'verified-effect-summary.json'))
for name in ('direct-effects.json','continuation-results.json','test-endpoints.json'):
    (OUT/name).write_bytes((LAB/name).read_bytes())
print('GROUP INTERVENTIONS AND ENDPOINTS VERIFIED',json.dumps(verified),flush=True)
