"""Evaluate closed blinded selections; labels are accessible only in this role."""
import json
from pathlib import Path
from collections import defaultdict
import numpy as np
from study_data import read,get_observation,load_observation
from revision_dba_experiment import read_pinned,outcomes,predict,model_with_arrays,authenticate,save
from fl_forensics.canonical import sha256_file,sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.federated_model import dependencies,arrays_from_export
from fl_forensics.byzantine import aggregate_deltas,apply_delta,model_delta

repo=Path.cwd();lab=repo/'artifacts/revision-state-conditioned-heldout-v1';out=Path(__file__).parent
closure=read(lab/'selections/selection-closure.json')
model_pin=sha256_file(lab/'models/model-closure.json')
assert closure['model_closure_sha256']==model_pin
assert closure['evaluation_input_index_sha256']==sha256_file(lab/'blinded-evaluation-input-index.json')
assert read(lab/'private-evaluation-map-before-generation.json')['model_closure_sha256']==model_pin
assert read(lab/'evaluation-input-closure.json')['model_closure_sha256']==model_pin
assert read(lab/'matched-state-control-input-closure.json')['model_closure_sha256']==model_pin
for name in ('fit','infer'):
    inspection=read(lab/f'{name}-runtime-inspection.json')
    assert inspection['HostConfig']['NetworkMode']=='none' and inspection['HostConfig']['ReadonlyRootfs']
    assert all('/private-generation' not in m.get('Source','') for m in inspection['Mounts'])
assert closure['capability']['raw_dataset_paths_unavailable']
for source in ('fit-input-closure.json','evaluation-input-closure.json','matched-state-control-input-closure.json','blinded-evaluation-input-closure.json'):
    binding=read(lab/source)
    for relative,digest in binding.get('files',binding.get('observations',{})).items():assert sha256_file(lab/relative)==digest
model_closure=read(lab/'models/model-closure.json')
for name,digest in model_closure['files'].items():assert sha256_file(lab/'models'/name)==digest
aliases={c['alias']:c for c in read(lab/'private-inference-alias-map.json')['aliases']}
truth_cases={c['id']:c for c in read(lab/'private-evaluation-map-before-generation.json')['cases']}
truth_cases.update({c['id']:c for c in read(lab/'private-matched-state-control-map.json')['cases']})
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
deps=dependencies();deps[1].set_num_threads(1)
validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256'])
prediction,_=predict(initial,validation,deps);correct=[p==r['label'] for p,r in zip(prediction,validation,strict=True)]
partitions={c:read(repo/'artifacts'/d/'manifest.json') for c,d in [('iid','m3-data24-parquet-iid-local-test-v1'),('non-iid','m3-data24-parquet-non-iid')]}
row_digests={};preflight={}
for cohort,partition in partitions.items():
    directory=repo/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if cohort=='iid' else 'm3-data24-parquet-non-iid')
    ids=[];row_digests[cohort]={}
    for record in partition['clients']:
        rows=read_pinned(directory/record['dataset_path'],record['dataset_sha256'])['rows']['train']
        assert len(rows)==record['train_row_count']
        ids.extend(r['window_id'] for r in rows)
        row_digests[cohort][record['client_id']]=sha256_bytes(derived_json_bytes(rows))
    assert len(ids)==len(set(ids))==7096 and not set(ids)&{r['window_id'] for r in validation}
    preflight[cohort]={'unique_training_windows':len(ids),'validation_overlap':0,'manifest_sha256':sha256_file(directory/'manifest.json')}
rows=[];endpoints={};verified_updates=0;verified_aggregates=0
for entry in closure['cases']:
    path=lab/'selections'/f'{entry["case_id"]}-selection.json';assert sha256_file(path)==entry['selection_sha256']
    selection=read(path);alias=aliases[entry['case_id']];case=truth_cases[alias['source_id']]
    cohort=case['cohort'];partition=partitions[cohort];counts={r['client_id']:r['train_row_count'] for r in partition['clients']}
    if case['mode']=='matched-state-clean':
        workspace=lab/'private-generation/matched-state-controls'/case['id'];active=set()
        for number in range(1,11):
            prefix=workspace/f'context-{number:03d}'
            for record in read(prefix/'execution.json'):
                assert record['executed_rows_sha256']==row_digests[cohort][record['client_id']]
        endpoint=None
    else:
        workspace=lab/'private-generation/heldout'/case['id'];active=set()
        # Reconstruct every aggregate from the source model payloads and check
        # each exported observation against those signed, pinned model bytes.
        authenticated=authenticate(workspace,sha256_file(workspace/'manifest.json'))
        observed=load_observation(workspace)
        exported=get_observation(lab/'observable-inference'/entry['case_id'])
        assert np.array_equal(observed['states'],exported['states']) and np.array_equal(observed['updates'],exported['updates'])
        for number in range(1,11):
            prefix=workspace/'rounds'/f'round-{number:03d}';record=read(prefix/'round.json')
            base=read(prefix/'base-model.json');arrays=arrays_from_export(base,np=np)
            local=[arrays_from_export(read(prefix/'updates'/f'{c}.json'),np=np) for c in record['client_ids']]
            result=model_with_arrays(base,apply_delta(arrays,aggregate_deltas([model_delta(arrays,m) for m in local],strategy='fedavg',f=0,weights=[counts[c] for c in record['client_ids']])))
            assert derived_json_bytes(result)==(prefix/'global-model.json').read_bytes()
            if number<10:assert (prefix/'global-model.json').read_bytes()==(workspace/'rounds'/f'round-{number+1:03d}'/'base-model.json').read_bytes()
            for training in record['local_training_records']:
                if training['executed_rows_sha256']!=row_digests[cohort][training['client_id']]:active.add(training['client_id'])
            verified_updates+=len(local);verified_aggregates+=1
        private=read(workspace/'generation-protocol.json')['attack_plan_for_generation_and_evaluation_only']
        plan=DistributedBackdoorPlan.model_validate(private if private else {**cfg['attack_plan'],'seed':case['seed']})
        endpoint=outcomes(read(workspace/'rounds/round-010/global-model.json'),validation,plan,correct,deps)
        endpoints[case['id']]={'case_id':case['id'],'cohort':cohort,'seed':case['seed'],'mode':case['mode'],
            'declared_attackers':case['attackers'],'active_poisoning_clients':sorted(active),'outcomes':endpoint}
    for method,result in selection['methods'].items():
        flagged=set(result['flagged_clients']);tp=len(flagged&active);fp=len(flagged-active);fn=len(active-flagged)
        supported=result.get('supported_frames') if method!='fusion' else min(v.get('supported_frames',0) for v in result['views'].values())
        rows.append({'alias':entry['case_id'],'source_case_id':case['id'],'cohort':cohort,'seed':case['seed'],'mode':case['mode'],
            'method':method,'status':result['status'],'flagged_clients':sorted(flagged),'declared_attackers':case['attackers'],
            'active_poisoning_clients':sorted(active),'tp':tp,'fp':fp,'fn':fn,
            'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,
            'exact_active_membership':flagged==active,'supported_frames':supported,
            'original_ASR':endpoint['complete_trigger']['asr'] if endpoint else None})
aggregate=[]
for cohort in ('iid','non-iid'):
    for mode in ('clean','distributed','matched-state-clean'):
        for method in ('conditioned','state-disabled','fusion'):
            cases=[r for r in rows if r['cohort']==cohort and r['mode']==mode and r['method']==method]
            tp=sum(r['tp'] for r in cases);fp=sum(r['fp'] for r in cases);fn=sum(r['fn'] for r in cases)
            aggregate.append({'cohort':cohort,'mode':mode,'method':method,'cases':len(cases),
                'evaluated':sum(r['status']=='evaluated' for r in cases),'abstained':sum(r['status']!='evaluated' for r in cases),
                'tp':tp,'fp':fp,'fn':fn,'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,
                'exact_cases':sum(r['exact_active_membership'] for r in cases),'campaign_alarms':sum(bool(r['flagged_clients']) for r in cases)})
report={'profile':'frozen-dual-view-state-audit-evaluation-v1','selection_closure_sha256':sha256_file(lab/'selections/selection-closure.json'),
    'model_closure_sha256':model_pin,'rows':rows,'aggregate':aggregate,'endpoints':list(endpoints.values()),
    'preflight':preflight,'independently_verified_model_updates':verified_updates,'independently_recomputed_aggregates':verified_aggregates,
    'detector_raw_data_access':False,'detector_attack_label_access':False,'final_test_used':False,
    'qualification':'12 new autoregressive campaigns and 6 paired conditional response banks. Banks are correlated controls, not independent extra FL campaigns. No score or threshold adjustment after these outcomes.'}
save(lab/'post-selection-evaluation.json',report)
(out/'heldout-evaluation.json').write_bytes((lab/'post-selection-evaluation.json').read_bytes())
for summary in aggregate:print(json.dumps(summary),flush=True)
print('PRIMARY FUSION CASES',flush=True)
for row in rows:
    if row['method']=='fusion':print(json.dumps(row),flush=True)
