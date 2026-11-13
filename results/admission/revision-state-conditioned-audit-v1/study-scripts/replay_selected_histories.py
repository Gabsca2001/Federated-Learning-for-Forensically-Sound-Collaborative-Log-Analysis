"""Full fixed-behavior replay for the exact closed primary fusion selections."""
from pathlib import Path
from study_data import Generator,read,flat
from revision_dba_experiment import save,outcomes,predict
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.remediation_validation import compare_replay_histories
from fl_forensics.federated_model import dependencies

repo=Path.cwd();lab=repo/'artifacts/revision-state-conditioned-heldout-v1'
root=lab/'full-selected-replay';assert not root.exists();root.mkdir()
evaluation=read(lab/'post-selection-evaluation.json')
cases=[r for r in evaluation['rows'] if r['mode']=='distributed' and r['method']=='fusion']
save(root/'protocol-before-training.json',{'profile':'state-audit-selected-full-history-replay-v1',
    'selection_closure_sha256':sha256_file(lab/'selections/selection-closure.json'),
    'model_closure_sha256':sha256_file(lab/'models/model-closure.json'),
    'selected_sets':[{k:c[k] for k in ('alias','source_case_id','cohort','seed','flagged_clients')} for c in cases],
    'intervention':'Omit exactly the closed fusion-flagged clients from rounds 1–10. No benign candidate pruning or missing-attacker addition. Retain scripted poisoning of any remaining attackers.',
    'reference':'Independent unmodified-row replay with the identical participation, initial checkpoint, seeds and optimizer state.',
    'control':'No-intervention replay of non-IID seed 441593; require all 150 local models and 10 checkpoints to match source bytes.',
    'scope':'Offline CPU FedAvg under fixed scripted adversary behavior and a clean warm-prefix assumption. No new attestation or live secure admission claimed.',
    'controller_sha256':sha256_file(Path(__file__))})
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
partitions={c:repo/'artifacts'/d for c,d in [('iid','m3-data24-parquet-iid-local-test-v1'),('non-iid','m3-data24-parquet-non-iid')]}
generators={c:Generator(p,cfg) for c,p in partitions.items()}
deps=dependencies();deps[1].set_num_threads(1)
validation=read(cfg['validation_path'])['rows']['validation']
initial=generators['iid'].initial
predicted,_=predict(initial,validation,deps);correct=[p==r['label'] for p,r in zip(predicted,validation,strict=True)]
calls=0;rounds_count=0;results=[]
for case in cases:
    generator=generators[case['cohort']];all_clients=sorted(generator.records)
    source=lab/'private-generation/heldout'/case['source_case_id']
    plan=DistributedBackdoorPlan.model_validate(read(source/'generation-protocol.json')['attack_plan_for_generation_and_evaluation_only'])
    selected=sorted(set(all_clients)-set(case['flagged_clients']))
    if len(selected)<8:
        results.append({**case,'replay_status':'quorum-insufficient'});continue
    branch_records={};branch_outcomes={}
    branches=['selected-removal','matched-clean']
    if case['cohort']=='non-iid' and case['seed']==441593:branches.insert(0,'no-intervention-control')
    for branch in branches:
        generator.clients=all_clients if branch=='no-intervention-control' else selected
        base=generator.initial;records=[]
        for number in range(1,11):
            prefix=root/case['source_case_id']/branch/f'round-{number:03d}'
            save(prefix/'base-model.json',base)
            result,deltas,exports,training=generator.execute(base,case['seed'],number,plan if branch!='matched-clean' else None)
            for client,model,record in zip(generator.clients,exports,training,strict=True):
                save(prefix/'updates'/f'{client}.json',model)
                record['local_model_sha256']=sha256_file(prefix/'updates'/f'{client}.json')
                record['training_rows_sha256']=record['executed_rows_sha256']
                if branch=='no-intervention-control':
                    assert (prefix/'updates'/f'{client}.json').read_bytes()==(source/'rounds'/f'round-{number:03d}'/'updates'/f'{client}.json').read_bytes()
            save(prefix/'global-model.json',result)
            if branch=='no-intervention-control':
                assert (prefix/'global-model.json').read_bytes()==(source/'rounds'/f'round-{number:03d}'/'global-model.json').read_bytes()
            record={'round_number':number,'base_model_sha256':sha256_file(prefix/'base-model.json'),
                'global_model_sha256':sha256_file(prefix/'global-model.json'),'selected_clients':generator.clients.copy(),
                'local_training_records':training}
            save(prefix/'record.json',record);records.append(record);base=result
            calls+=len(generator.clients);rounds_count+=1
            print({'case':case['source_case_id'],'branch':branch,'round':number},flush=True)
        branch_records[branch]=records
        branch_outcomes[branch]=outcomes(base,validation,plan,correct,deps)
    comparison=compare_replay_histories(branch_records['selected-removal'],branch_records['matched-clean'],
        initial_model_sha256=cfg['base_model_sha256'],expected_rounds=10)
    results.append({k:case[k] for k in ('alias','cohort','seed','source_case_id','flagged_clients','active_poisoning_clients','tp','fp','fn')}|{
        'replay_status':'completed','matched_clean_comparison':comparison,'outcomes':branch_outcomes,
        'no_intervention_control_byte_equal':True if 'no-intervention-control' in branches else None,
        'interpretation':'Clean-reference equality concerns the declared remaining population; it does not justify removing benign false candidates.'})
save(root/'evaluation.json',{'profile':'state-audit-selected-full-history-replay-v1','cases':results,
    'new_local_training_calls':calls,'new_aggregation_rounds':rounds_count,
    'no_intervention_local_models_byte_equal':150,'no_intervention_checkpoints_byte_equal':10,
    'new_attestation_performed':False})
save(root/'closure.json',{'files':{p.relative_to(root).as_posix():sha256_file(p) for p in root.rglob('*') if p.is_file()}})
out=Path(__file__).parent
(out/'selected-full-history-evaluation.json').write_bytes((root/'evaluation.json').read_bytes())
print('FULL SELECTED HISTORIES COMPLETE',calls,rounds_count,flush=True)
