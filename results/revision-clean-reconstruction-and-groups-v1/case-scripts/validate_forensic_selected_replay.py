"""Bind label-blind selected groups to direct and full-history interventions."""
import json
from itertools import combinations
from pathlib import Path

import numpy as np
from revision_dba_experiment import authenticate,read_pinned,save,model_with_arrays,outcomes,predict
from fl_forensics.canonical import sha256_file,sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows
from fl_forensics.federated_model import dependencies,arrays_from_export,train_local,export_state
from fl_forensics.secure_round import _model_from_export
from fl_forensics.byzantine import model_delta,aggregate_deltas,apply_delta
from fl_forensics.remediation_validation import compare_replay_histories

repo=Path.cwd(); source=repo/'artifacts/revision-conditioned-groups-v2-fixed-serialization'
selector=repo/'artifacts/revision-same-base-execution-audit-v1'
lab=repo/'artifacts/revision-forensic-selected-remediation-v1'
assert not lab.exists(); lab.mkdir()


def read(path): return json.loads(path.read_bytes())


closure=read(source/'closure.json')
for name,digest in closure['artifacts'].items(): assert sha256_file(source/name)==digest
audit_closure=read(selector/'closure.json')
for name,digest in audit_closure['artifacts'].items(): assert sha256_file(selector/name)==digest
choices=[]
for seed in (361593,362593,363593):
    for mode in ('clean','distributed'):
        path=selector/f'{mode}-s{seed}-selection-before-labels.json'
        result=read(path)
        selected=result['deviating_clients']
        choices.append({'seed':seed,'mode':mode,'selected_group':selected,'selection_sha256':sha256_file(path)})
save(lab/'protocol-before-interventions.json',{'profile':'privileged-forensic-selected-remediation-v1',
    'source_closure_sha256':sha256_file(source/'closure.json'),'choices':choices,
    'selection':'Exact same-base clean-reference execution deviations, requiring original unmodified snapshots. No attack identities or ASR enter selection. This is not update-only detection.', 'execution_audit_closure_sha256':sha256_file(selector/'closure.json'),
    'interventions':'Direct final-round group and single-member reaggregation. Full history omission of the selected group during rounds 1–10; independent clean matched participation branch.',
    'acceptance':'Full-history equality to matched clean reference. Non-equality is reported, not hidden by ASR zero.',
    'runner_sha256':sha256_file(Path(__file__)),'fresh_attestation_performed':False})
# Only now access experiment training labels and raw snapshots.
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
partition_root=Path(cfg['partition_workspace']); partition=read_pinned(partition_root/'manifest.json',cfg['partition_manifest_sha256'])
records={r['client_id']:r for r in partition['clients']}; clients=sorted(records)
snapshots={c:read_pinned(partition_root/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()}
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256'])
validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
weights={c:float(partition['global_class_weights'][c]) for c in initial['class_names']}
deps=dependencies(); torch=deps[1]; torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
predicted,_=predict(initial,validation,deps); correct=[p==r['label'] for p,r in zip(predicted,validation,strict=True)]
evaluations=[]; calls=0
for choice in choices:
    seed,mode,group=choice['seed'],choice['mode'],choice['selected_group']
    if not group or len(clients)-len(group)<cfg['minimum_contributors']:
        evaluations.append({**choice,'status':'no-candidate' if not group else 'quorum-insufficient'}); continue
    workspace=source/f'{mode}-s{seed}'
    authenticate(workspace,sha256_file(workspace/'manifest.json'))
    plan=DistributedBackdoorPlan.model_validate(read(workspace/'protocol.json')['attack_plan'])
    truth=set(plan.client_components) if mode=='distributed' else set()
    last=workspace/'rounds/round-010'; original=read(last/'global-model.json')
    before=outcomes(original,validation,plan,correct,deps)
    base=read(last/'base-model.json'); base_arrays=arrays_from_export(base,np=np)
    local={c:arrays_from_export(read(last/'updates'/f'{c}.json'),np=np) for c in clients}
    direct=[]
    for removed in (group,*[[c] for c in group]):
        selected=sorted(set(clients)-set(removed)); deltas=[model_delta(base_arrays,local[c]) for c in selected]
        model=model_with_arrays(base,apply_delta(base_arrays,aggregate_deltas(deltas,strategy='fedavg',f=0,weights=[len(snapshots[c]) for c in selected])))
        outcome=outcomes(model,validation,plan,correct,deps)
        direct.append({'removed':removed,'ASR':outcome['complete_trigger']['asr'],
            'ASR_reduction':before['complete_trigger']['asr']-outcome['complete_trigger']['asr']})
    trajectories={}; final_outcomes={}
    selected=sorted(set(clients)-set(group))
    for branch in ('selected-removal','matched-clean'):
        base=initial; rounds=[]
        for number in range(1,11):
            prefix=lab/f'{mode}-s{seed}'/branch/f'round-{number:03d}'
            base_arrays=arrays_from_export(base,np=np); models=[];counts=[];training=[]
            for client in selected:
                rows=snapshots[client]
                if branch=='selected-removal' and mode=='distributed':
                    rows,_=poison_local_rows(rows=rows,plan=plan,client_id=client,round_number=number,distributed=True)
                model=_model_from_export(base,torch=torch,np=np)
                train_local(model=model,rows=rows,class_names=base['class_names'],class_weights=weights,
                    epochs=cfg['local_epochs'],batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'],
                    seed=seed+number*10000+int(records[client]['partition_id']),device_name='cpu',torch=torch,np=np)
                calls+=1
                local_export=export_state(model,architecture=base['architecture'],class_names=base['class_names'])
                save(prefix/'updates'/f'{client}.json',local_export)
                models.append(arrays_from_export(local_export,np=np)); counts.append(len(rows))
                training.append({'client_id':client,'training_rows_sha256':sha256_bytes(derived_json_bytes(rows)),
                    'local_model_sha256':sha256_file(prefix/'updates'/f'{client}.json')})
            result=model_with_arrays(base,apply_delta(base_arrays,aggregate_deltas([model_delta(base_arrays,m) for m in models],strategy='fedavg',f=0,weights=counts)))
            save(prefix/'global-model.json',result)
            record={'round_number':number,'base_model_sha256':sha256_bytes(derived_json_bytes(base)),
                'global_model_sha256':sha256_file(prefix/'global-model.json'),'selected_clients':selected,'local_training_records':training}
            save(prefix/'record.json',record); rounds.append(record);base=result
            print(json.dumps({'seed':seed,'mode':mode,'branch':branch,'round':number}),flush=True)
        trajectories[branch]=rounds; final_outcomes[branch]=outcomes(base,validation,plan,correct,deps)
    comparison=compare_replay_histories(trajectories['selected-removal'],trajectories['matched-clean'],initial_model_sha256=cfg['base_model_sha256'],expected_rounds=10)
    evaluations.append({**choice,'status':'evaluated','selected_attack_overlap_for_evaluation_only':sorted(set(group)&truth),
        'original_ASR':before['complete_trigger']['asr'],'direct_interventions':direct,
        'joint_direct_reduction_minus_largest_single':direct[0]['ASR_reduction']-max(d['ASR_reduction'] for d in direct[1:]),
        'full_history_outcomes':final_outcomes,'matched_clean_comparison':comparison,
        'intentional_collusion_proved':False})
save(lab/'evaluation.json',{'profile':'privileged-forensic-selected-remediation-v1','cases':evaluations,
    'actual_new_local_training_calls':calls,'fresh_TPM_attestation_performed':False})
save(lab/'closure.json',{'artifacts':{p.relative_to(lab).as_posix():sha256_file(p) for p in lab.rglob('*') if p.is_file()}})
out=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/residual-poisoning-20261103')
(out/'forensic-selected-remediation-evaluation.json').write_bytes((lab/'evaluation.json').read_bytes())
(out/'forensic-selected-protocol-before-interventions.json').write_bytes((lab/'protocol-before-interventions.json').read_bytes())
print('SELECTED GROUP REPLAYS COMPLETED',calls,flush=True)
