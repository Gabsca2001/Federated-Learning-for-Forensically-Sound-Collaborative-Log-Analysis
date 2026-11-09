"""Labelled mechanistic follow-up: replay the largest residual from W0."""
from group_common import *
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows
from fl_forensics.federated_model import train_local,export_state
from fl_forensics.secure_round import _model_from_export
from fl_forensics.crypto import SoftwareECDSASigner
from revision_dba_experiment import signature

effects=read(LAB/'verified-effect-summary.json')
candidates=[r for r in effects['cases'] if r['mode']=='distributed' and r['method']=='envelope-prefix-set']
case=sorted(candidates,key=lambda r:(-r['continuation']['joint_R15_ASR'],r['alias']))[0]
source_case=next(c for c in read(LAB/'interventions-protocol-before-computation.json')['cases'] if c['alias']==case['alias'])
task=source_case['task'];private=read(LAB/'private-alias-map.json')
paired=next(v for v in private.values() if v['role']=='evaluation' and v['task']['cohort']==task['cohort'] and v['task']['seed']==task['seed'] and v['task']['mode']=='clean')
source=REPO/source_case['source'];clean_source=REPO/paired['source'];lab=LAB/'full-rewind';assert not lab.exists()
cfg=read(CFG);deps=dependencies();torch=deps[1];torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
root=REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid')
part=read(root/'manifest.json');records={r['client_id']:r for r in part['clients']}
snapshots={c:read_pinned(root/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()}
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256']);weights={c:float(part['global_class_weights'][c]) for c in initial['class_names']}
validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
test_hash=read(REPO/'artifacts/revision-dba-three-seed-v1/fixed-endpoint-test.json')['test_snapshot_sha256']
test=read_pinned(Path(cfg['partition_workspace'])/'server/splits/test.json',test_hash)['rows']['test']
pred,_=predict(initial,validation,deps);vc=[p==r['label'] for p,r in zip(pred,validation,strict=True)]
pred,_=predict(initial,test,deps);tc=[p==r['label'] for p,r in zip(pred,test,strict=True)]
plan=DistributedBackdoorPlan.model_validate(read(source/'generation-protocol.json')['attack_plan_for_simulator_and_evaluation_only'])
jobs=[{'name':'source-control','removed':[],'unmodified':False},
    {'name':'selected-original-script','removed':case['selected'],'unmodified':False},
    {'name':'selected-unmodified-reference','removed':case['selected'],'unmodified':True},
    {'name':'all-client-unmodified','removed':[],'unmodified':True}]
protocol={'profile':'post-selection-hard-case-full-rewind-v1','status':'Post-hoc mechanistic follow-up, not an additional independent discovery validation.',
    'selection_rule':'Largest observed R15 residual ASR among the already frozen envelope-prefix selected sets; ties by alias. No change to membership or thresholds.',
    'triggering_effect_summary_sha256':sha256_file(LAB/'verified-effect-summary.json'),'case':case,'source':source_case['source'],
    'source_manifest_sha256':source_case['source_manifest_sha256'],'paired_clean_source':paired['source'],
    'paired_clean_manifest_sha256':paired['manifest_sha256'],'jobs':jobs,'rounds':15,
    'start':'Original committed W0 before any scripted poisoning in this experiment. This is a declared reference checkpoint, not a proof of semantic purity.',
    'selected_intervention':'Remove the same previously selected clients from all rounds, including before attack onset. Fresh remaining-client training at every round.',
    'all_client_unmodified_intervention':'Privileged replay of every original unmodified snapshot; requires those snapshots and does not follow merely from excluding clients.',
    'partition_manifest_sha256':sha256_file(root/'manifest.json'),'script_sha256':sha256_file(Path(__file__)),
    'fresh_TPM_attestation':False,'production_policy_changed':False,'thesis_changed':False}
save(lab/'protocol-before-training.json',protocol)
branches=[];calls=0
for job in jobs:
    workspace=lab/job['name'];base=initial;clients=[c for c in sorted(records) if c not in job['removed']];rounds=[]
    save(workspace/'protocol.json',{'job':job,'full_rewind_protocol_sha256':sha256_file(lab/'protocol-before-training.json')})
    for number in range(1,16):
        p=workspace/'rounds'/f'round-{number:03d}';save(p/'base-model.json',base);exports=[];training=[]
        for c in clients:
            rows=snapshots[c]
            if not job['unmodified']:rows,_=poison_local_rows(rows=rows,plan=plan,client_id=c,round_number=number,distributed=True)
            model=_model_from_export(base,torch=torch,np=np);seed=task['seed']+number*10000+int(records[c]['partition_id'])
            train_local(model=model,rows=rows,class_names=base['class_names'],class_weights=weights,epochs=cfg['local_epochs'],
                batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'],seed=seed,device_name='cpu',torch=torch,np=np)
            export=export_state(model,architecture=base['architecture'],class_names=base['class_names']);exports.append(export)
            save(p/'updates'/f'{c}.json',export);training.append({'client_id':c,'seed':seed,'snapshot_sha256':records[c]['dataset_sha256'],
                'executed_rows_sha256':sha256_bytes(derived_json_bytes(rows)),'local_model_sha256':sha256_file(p/'updates'/f'{c}.json')});calls+=1
            expected_source=source if job['name']=='source-control' else clean_source if job['name']=='all-client-unmodified' else None
            if expected_source is not None:assert (p/'updates'/f'{c}.json').read_bytes()==(expected_source/'rounds'/f'round-{number:03d}'/'updates'/f'{c}.json').read_bytes()
        arrays=arrays_from_export(base,np=np)
        ds=[model_delta(arrays,arrays_from_export(m,np=np)) for m in exports]
        result=model_with_arrays(base,apply_delta(arrays,aggregate_deltas(ds,strategy='fedavg',f=0,weights=[len(snapshots[c]) for c in clients])))
        save(p/'global-model.json',result)
        if expected_source is not None:assert (p/'global-model.json').read_bytes()==(expected_source/'rounds'/f'round-{number:03d}'/'global-model.json').read_bytes()
        record={'round':number,'clients':clients,'base_model_sha256':sha256_file(p/'base-model.json'),
            'global_model_sha256':sha256_file(p/'global-model.json'),'local_training_records':training}
        save(p/'round.json',record)
        rounds.append({'round':number,'global_model_sha256':record['global_model_sha256'],'validation':outcomes(result,validation,plan,vc,deps)})
        base=result;print(json.dumps({'full_rewind_branch':job['name'],'round':number,'new_calls':calls}),flush=True)
    save(workspace/'evaluation.json',{'rounds':rounds,'final_test':outcomes(base,test,plan,tc,deps)})
    signer=SoftwareECDSASigner.generate();(workspace/'experiment-authority.public.pem').write_bytes(signer.public_pem())
    core={'profile':'full-rewind-software-branch-v1','artifacts':{p.relative_to(workspace).as_posix():sha256_file(p) for p in workspace.rglob('*') if p.is_file()},'fresh_TPM_attestation':False}
    d=digest_object(core);save(workspace/'manifest.json',{'core':core,'core_digest':d,'signature':signature(signer,d)})
    authenticate(workspace,sha256_file(workspace/'manifest.json'))
    branches.append({'job':job,'path':workspace.relative_to(LAB).as_posix(),'manifest_sha256':sha256_file(workspace/'manifest.json'),
        'rounds':rounds,'final_test':read(workspace/'evaluation.json')['final_test']})
save(lab/'result.json',{'profile':'post-selection-full-rewind-result-v1','branches':branches,'new_local_training_calls':calls,
    'new_genuinely_trained_rounds':60,'selected_membership_unchanged':True,'new_independent_discovery_evaluation':False})
print('FULL REWIND COMPLETED',calls,flush=True)
