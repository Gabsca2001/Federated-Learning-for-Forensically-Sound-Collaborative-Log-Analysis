"""Re-read every full-rewind payload and check recurrence/reference equality."""
from group_common import *
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows

root=LAB/'full-rewind';protocol=read(root/'protocol-before-training.json');result=read(root/'result.json')
assert sha256_file(OUT/'rewind_hard_case.py')==protocol['script_sha256']
assert sha256_file(LAB/'verified-effect-summary.json')==protocol['triggering_effect_summary_sha256']
source=REPO/protocol['source'];clean=REPO/protocol['paired_clean_source']
authenticate(source,protocol['source_manifest_sha256']);authenticate(clean,protocol['paired_clean_manifest_sha256'])
task=read(source/'generation-protocol.json')['task'];cfg=read(CFG)
partition=REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid')
assert sha256_file(partition/'manifest.json')==protocol['partition_manifest_sha256']
records={r['client_id']:r for r in read(partition/'manifest.json')['clients']}
rows={c:read_pinned(partition/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()}
plan=DistributedBackdoorPlan.model_validate(read(source/'generation-protocol.json')['attack_plan_for_simulator_and_evaluation_only'])
deps=dependencies();deps[1].set_num_threads(1);initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256'])
validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
test_hash=read(REPO/'artifacts/revision-dba-three-seed-v1/fixed-endpoint-test.json')['test_snapshot_sha256']
test=read_pinned(Path(cfg['partition_workspace'])/'server/splits/test.json',test_hash)['rows']['test']
pred,_=predict(initial,validation,deps);vc=[p==r['label'] for p,r in zip(pred,validation,strict=True)]
pred,_=predict(initial,test,deps);tc=[p==r['label'] for p,r in zip(pred,test,strict=True)]
counts={'aggregate_exports_recomputed':0,'input_commitments_checked':0,'source_or_clean_reference_local_matches':0,
    'source_or_clean_reference_checkpoint_matches':0,'validation_endpoints_recomputed':0,'test_endpoints_recomputed':0}
by_name={b['job']['name']:b for b in result['branches']}
for branch in result['branches']:
    workspace=LAB/branch['path'];authenticate(workspace,branch['manifest_sha256']);job=branch['job']
    for number in range(1,16):
        p=workspace/'rounds'/f'round-{number:03d}';r=read(p/'round.json');base=read(p/'base-model.json');arrays=arrays_from_export(base,np=np)
        if number==1:assert (p/'base-model.json').read_bytes()==Path(cfg['base_model_path']).read_bytes()
        else:assert (p/'base-model.json').read_bytes()==(workspace/'rounds'/f'round-{number-1:03d}'/'global-model.json').read_bytes()
        assert r['clients']==[c for c in sorted(records) if c not in job['removed']]
        deltas=[]
        for t in r['local_training_records']:
            c=t['client_id'];actual=rows[c]
            if not job['unmodified']:actual,_=poison_local_rows(rows=actual,plan=plan,client_id=c,round_number=number,distributed=True)
            assert t['executed_rows_sha256']==sha256_bytes(derived_json_bytes(actual))
            assert t['seed']==task['seed']+number*10000+int(records[c]['partition_id'])
            assert t['snapshot_sha256']==records[c]['dataset_sha256']
            assert t['local_model_sha256']==sha256_file(p/'updates'/f'{c}.json')
            deltas.append(model_delta(arrays,arrays_from_export(read(p/'updates'/f'{c}.json'),np=np)))
            counts['input_commitments_checked']+=1
        model=model_with_arrays(base,apply_delta(arrays,aggregate_deltas(deltas,strategy='fedavg',f=0,weights=[len(rows[c]) for c in r['clients']])))
        assert derived_json_bytes(model)==(p/'global-model.json').read_bytes();counts['aggregate_exports_recomputed']+=1
        expected=source if job['name']=='source-control' else clean if job['name']=='all-client-unmodified' else None
        if expected is not None:
            assert (p/'global-model.json').read_bytes()==(expected/'rounds'/f'round-{number:03d}'/'global-model.json').read_bytes();counts['source_or_clean_reference_checkpoint_matches']+=1
            for c in r['clients']:
                assert (p/'updates'/f'{c}.json').read_bytes()==(expected/'rounds'/f'round-{number:03d}'/'updates'/f'{c}.json').read_bytes();counts['source_or_clean_reference_local_matches']+=1
    final=read(workspace/'rounds/round-015/global-model.json')
    assert derived_json_bytes(outcomes(final,validation,plan,vc,deps))==derived_json_bytes(branch['rounds'][-1]['validation']);counts['validation_endpoints_recomputed']+=1
    assert derived_json_bytes(outcomes(final,test,plan,tc,deps))==derived_json_bytes(branch['final_test']);counts['test_endpoints_recomputed']+=1
    print('FULL REWIND VERIFIED',job['name'],flush=True)
matches=[]
left=LAB/by_name['selected-original-script']['path'];right=LAB/by_name['selected-unmodified-reference']['path']
for number in range(1,16):
    a=left/'rounds'/f'round-{number:03d}';b=right/'rounds'/f'round-{number:03d}';ar=read(a/'round.json');br=read(b/'round.json')
    matches.append({'round':number,'global_equal':(a/'global-model.json').read_bytes()==(b/'global-model.json').read_bytes(),
        'inputs_equal':[t['executed_rows_sha256'] for t in ar['local_training_records']]==[t['executed_rows_sha256'] for t in br['local_training_records']],
        'local_models_equal':[t['local_model_sha256'] for t in ar['local_training_records']]==[t['local_model_sha256'] for t in br['local_training_records']]})
check={'profile':'post-selection-full-rewind-verification-v1','counts':counts,'selected_membership_unchanged':True,
    'selected_full_history_reference_equal':all(all(r[k] for k in ('global_equal','inputs_equal','local_models_equal')) for r in matches),
    'selected_reference_rounds':matches,'all_client_unmodified_exact_original_clean_history':True,
    'privileged_unmodified_snapshots_required':True,'post_hoc_case_choice_not_independent_discovery_validation':True,
    'branches':[{'name':b['job']['name'],'validation_final':b['rounds'][-1]['validation'],'test_final':b['final_test']} for b in result['branches']]}
assert counts['aggregate_exports_recomputed']==60 and counts['input_commitments_checked']==810
assert counts['source_or_clean_reference_local_matches']==450 and counts['source_or_clean_reference_checkpoint_matches']==30
save(root/'verification.json',check);save(OUT/'full-rewind-verification.json',check)
(OUT/'full-rewind-protocol-before-training.json').write_bytes((root/'protocol-before-training.json').read_bytes())
(OUT/'full-rewind-result.json').write_bytes((root/'result.json').read_bytes())
print('FULL REWIND VERIFICATION COMPLETE',json.dumps(counts),flush=True)
