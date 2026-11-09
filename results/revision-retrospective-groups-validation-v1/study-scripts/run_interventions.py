"""Direct removals and genuine fixed-membership continuation from corrected R10."""
from fractions import Fraction
from group_common import *
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows
from fl_forensics.federated_model import train_local,export_state
from fl_forensics.secure_round import _model_from_export
from fl_forensics.crypto import SoftwareECDSASigner
from revision_dba_experiment import signature

protocol=read(LAB/'interventions-protocol-before-computation.json')
for n,h in protocol['code_sha256'].items():assert sha256_file(OUT/n)==h
cfg=read(CFG);deps=dependencies();torch=deps[1];torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256']);pred,_=predict(initial,validation,deps)
correct=[r['label']==p for r,p in zip(validation,pred,strict=True)]
test_path=REPO/'artifacts/revision-dba-three-seed-v1/fixed-endpoint-test.json'
fixed=read(test_path)
# The test artifact records its pinned split path/hash; preserve that binding.
test=read_pinned(Path(cfg['partition_workspace'])/'server/splits/test.json',fixed['test_snapshot_sha256'])['rows']['test']
pred,_=predict(initial,test,deps);test_correct=[r['label']==p for r,p in zip(test,pred,strict=True)]
test_endpoints=[]

partitions={'iid':'m3-data24-parquet-iid-local-test-v1','non-iid':'m3-data24-parquet-non-iid'}
data={}
for cohort,name in partitions.items():
    root=REPO/'artifacts'/name;manifest=read(root/'manifest.json');records={r['client_id']:r for r in manifest['clients']}
    data[cohort]={'root':root,'manifest':manifest,'records':records,
        'rows':{c:read_pinned(root/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()},
        'weights':{c:float(manifest['global_class_weights'][c]) for c in initial['class_names']}}

def aggregate(base,models,counts):
    arrays=arrays_from_export(base,np=np)
    ds=[model_delta(arrays,arrays_from_export(m,np=np)) for m in models]
    return model_with_arrays(base,apply_delta(arrays,aggregate_deltas(ds,strategy='fedavg',f=0,weights=counts)))

direct_index=[];direct_models={};plans={}
for case in protocol['cases']:
    alias=case['alias'];workspace=REPO/case['source'];task=case['task'];p=workspace/'rounds/round-010'
    generation=read(workspace/'generation-protocol.json');plan=DistributedBackdoorPlan.model_validate(generation['attack_plan_for_simulator_and_evaluation_only']);plans[alias]=plan
    base=read(p/'base-model.json');clients=sorted(case['client_masses']);models={c:read(p/'updates'/f'{c}.json') for c in clients}
    original=outcomes(read(p/'global-model.json'),validation,plan,correct,deps)
    result=[]
    for item in case['direct_removals']:
        removed=item['removed'];remaining=[c for c in clients if c not in removed];assert len(remaining)>=8
        model=aggregate(base,[models[c] for c in remaining],[case['client_masses'][c] for c in remaining])
        destination=LAB/'direct-models'/alias/f'{key(removed)}.json';save(destination,model);direct_models[(alias,key(removed))]=destination
        if not removed:assert destination.read_bytes()==(p/'global-model.json').read_bytes()
        value=outcomes(model,validation,plan,correct,deps)
        if any(role=='no-intervention' or ':joint' in role or ':individual:' in role or ':benign-continuation:' in role for role in item['roles']):
            test_endpoints.append({'alias':alias,'round':10,'removed':removed,'data_mode':'original-script',
                'model_sha256':sha256_file(destination),'test':outcomes(model,test,plan,test_correct,deps)})
        result.append({'removed':removed,'key':key(removed),'roles':item['roles'],'model_sha256':sha256_file(destination),
            'original_mass_fraction_removed':sum(case['client_masses'][c] for c in removed)/sum(case['client_masses'].values()),
            'outcomes':value,'ASR_reduction':original['complete_trigger']['asr']-value['complete_trigger']['asr']})
    direct_index.append({'alias':alias,'task':task,'original':original,'removals':result})
    print(json.dumps({'direct_case_completed':alias,'removals':len(result)}),flush=True)
save(LAB/'direct-effects.json',{'cases':direct_index,'future_retraining_performed_in_this_file':False})

completed=[];new_calls=0;new_rounds=0;reproduced=0
for jindex,job in enumerate(protocol['jobs']):
    alias=job['alias'];workspace=REPO/job['source'];task=job['task'];d=data[job['cohort']]
    root=LAB/'continuations'/alias/job['branch'];plan=plans[alias] if job['data_mode']=='original-script' else None
    clients=[c for c in sorted(d['records']) if c not in job['removed']];counts=[len(d['rows'][c]) for c in clients]
    assert len(clients)>=8;assert not root.exists(),f'partial branch requires explicit recovery: {root}'
    save(root/'protocol-before-training.json',{'job':job,'intervention_protocol_sha256':sha256_file(LAB/'interventions-protocol-before-computation.json'),
        'source_manifest_sha256':next(c['source_manifest_sha256'] for c in protocol['cases'] if c['alias']==alias),
        'incoming_R10_model_sha256':sha256_file(workspace/'rounds/round-010/base-model.json'),
        'partition_manifest_sha256':sha256_file(d['root']/'manifest.json'),
        'optimizer':'fresh Adam per local call','seed_schedule':'source_seed+round*10000+partition_id',
        'new_TPM_attestation':False,'first_round_uses_preserved_updates':plan is not None})
    base=read(workspace/'rounds/round-010/base-model.json');rounds=[]
    for number in range(10,16):
        p=root/'rounds'/f'round-{number:03d}';save(p/'base-model.json',base);training=[]
        if number==10 and plan is not None:
            model=read(direct_models[(alias,key(job['removed']))]);source_round=read(workspace/'rounds/round-010/round.json')
            training=[r for r in source_round['local_training_records'] if r['client_id'] in clients]
            origin='preserved source local outputs, R10 only'
        else:
            exports=[];origin='new branch-specific local training'
            for c in clients:
                rows=d['rows'][c]
                if plan is not None:rows,_=poison_local_rows(rows=rows,plan=plan,client_id=c,round_number=number,distributed=True)
                model_object=_model_from_export(base,torch=torch,np=np);seed=task['seed']+number*10000+int(d['records'][c]['partition_id'])
                train_local(model=model_object,rows=rows,class_names=base['class_names'],class_weights=d['weights'],epochs=cfg['local_epochs'],
                    batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'],seed=seed,device_name='cpu',torch=torch,np=np)
                local=export_state(model_object,architecture=base['architecture'],class_names=base['class_names'])
                save(p/'updates'/f'{c}.json',local);exports.append(local)
                training.append({'client_id':c,'seed':seed,'snapshot_sha256':d['records'][c]['dataset_sha256'],
                    'executed_rows_sha256':sha256_bytes(derived_json_bytes(rows)),'local_model_sha256':sha256_file(p/'updates'/f'{c}.json')})
                new_calls+=1
                if not job['removed'] and plan is not None:
                    assert (p/'updates'/f'{c}.json').read_bytes()==(workspace/'rounds'/f'round-{number:03d}'/'updates'/f'{c}.json').read_bytes()
                    expected=next(r for r in read(workspace/'rounds'/f'round-{number:03d}'/'round.json')['local_training_records'] if r['client_id']==c)
                    assert training[-1]==expected
                    reproduced+=1
            model=aggregate(base,exports,counts);new_rounds+=1
        save(p/'global-model.json',model)
        if not job['removed'] and plan is not None:assert (p/'global-model.json').read_bytes()==(workspace/'rounds'/f'round-{number:03d}'/'global-model.json').read_bytes()
        total=sum(counts);weights={c:str(Fraction(len(d['rows'][c]),total)) for c in clients}
        assert sum(Fraction(v) for v in weights.values())==1 and not set(weights)&set(job['removed'])
        record={'round':number,'clients':clients,'removed':job['removed'],'base_model_sha256':sha256_file(p/'base-model.json'),
            'global_model_sha256':sha256_file(p/'global-model.json'),'local_training_records':training,'local_output_origin':origin,'weights':weights}
        save(p/'round.json',record)
        rounds.append({'round':number,'model_sha256':record['global_model_sha256'],'validation':outcomes(model,validation,plans[alias],correct,deps)})
        base=model
        if number==15:
            test_endpoints.append({'alias':alias,'round':15,'removed':job['removed'],'data_mode':job['data_mode'],
                'model_sha256':record['global_model_sha256'],'test':outcomes(model,test,plans[alias],test_correct,deps)})
        print(json.dumps({'branch':f"{alias}/{job['branch']}",'round':number,'job':jindex+1,'total_jobs':len(protocol['jobs']),'new_calls':new_calls}),flush=True)
    signer=SoftwareECDSASigner.generate();save(root/'evaluation.json',{'rounds':rounds})
    (root/'experiment-authority.public.pem').write_bytes(signer.public_pem())
    core={'profile':'retrospective-selected-continuation-v1','artifacts':{p.relative_to(root).as_posix():sha256_file(p) for p in root.rglob('*') if p.is_file()},
        'fresh_TPM_attestation':False,'future_historical_local_outputs_reused':False}
    digest=digest_object(core);save(root/'manifest.json',{'core':core,'core_digest':digest,'signature':signature(signer,digest)})
    authenticate(root,sha256_file(root/'manifest.json'))
    completed.append({**job,'path':root.relative_to(LAB).as_posix(),'manifest_sha256':sha256_file(root/'manifest.json'),'rounds':rounds})
    (LAB/'progress.json').write_text(json.dumps({'completed_branches':len(completed),'total_branches':len(protocol['jobs']),'new_calls':new_calls})+'\n')
save(LAB/'continuation-results.json',{'branches':completed,'new_local_training_calls':new_calls,'new_aggregated_training_rounds':new_rounds,
    'no_intervention_local_outputs_reproduced':reproduced,'source_updates_used_only_for_R10':True,'fixed_membership_intervention':True})
save(LAB/'test-endpoints.json',{'endpoints':test_endpoints,'test_snapshot_sha256':fixed['test_snapshot_sha256'],
    'existing_previously_evaluated_test_fold':True,'used_for_selection_or_tuning':False})
print('ALL DIRECT AND CONTINUATION INTERVENTIONS COMPLETE',json.dumps({'branches':len(completed),'new_calls':new_calls,'new_rounds':new_rounds}),flush=True)
