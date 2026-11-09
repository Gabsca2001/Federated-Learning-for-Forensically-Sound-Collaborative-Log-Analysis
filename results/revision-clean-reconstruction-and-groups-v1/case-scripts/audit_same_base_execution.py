"""Privileged forensic audit against unmodified snapshots at the SAME round base.

Requires access to the original committed unmodified local data. This is not an
update-only detector and deviation is not independently proof of malicious intent.
"""
import json
from pathlib import Path

import numpy as np
from revision_dba_experiment import read_pinned,authenticate,save,environment
from fl_forensics.canonical import sha256_file,sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.federated_model import dependencies,train_local,export_state
from fl_forensics.secure_round import _model_from_export

repo=Path.cwd(); source=repo/'artifacts/revision-conditioned-groups-v2-fixed-serialization'
lab=repo/'artifacts/revision-same-base-execution-audit-v1'
assert not lab.exists(); lab.mkdir()


def read(path): return json.loads(path.read_bytes())


cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
save(lab/'protocol-before-audit.json',{'profile':'privileged-same-base-clean-execution-audit-v1',
    'seeds':[361593,362593,363593],'modes':['clean','distributed'],'horizon':10,
    'reference_data_assumption':'Available original committed, unmodified local snapshots and a clean reference training algorithm. Dataset commitments do not independently prove semantic cleanliness.',
    'rule':'Replay each client from its actual historical round base, exact seed, fresh Adam, CPU environment and unmodified snapshot. Record exact local model deviations. Select clients with one or more deviations; labels and ASR are excluded from selection.',
    'classification':'Reference-execution deviations; not proof of intent or a result under update-only privacy constraints.',
    'environment':environment(),'runner_sha256':sha256_file(Path(__file__)),
    'source_closure_sha256':sha256_file(source/'closure.json'),
    'partition_manifest_sha256':cfg['partition_manifest_sha256'],'fresh_TPM_attestation':False})
partition_root=Path(cfg['partition_workspace']); partition=read_pinned(partition_root/'manifest.json',cfg['partition_manifest_sha256'])
records={r['client_id']:r for r in partition['clients']}; clients=sorted(records)
snapshots={c:read_pinned(partition_root/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()}
deps=dependencies(); torch=deps[1]; torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
cases=[]
for seed in (361593,362593,363593):
    for mode in ('clean','distributed'):
        workspace=source/f'{mode}-s{seed}'; authenticate(workspace,sha256_file(workspace/'manifest.json'))
        deviations={c:[] for c in clients}; rounds=[]
        for number in range(1,11):
            prefix=workspace/'rounds'/f'round-{number:03d}'
            record=read(prefix/'round.json'); base=read_pinned(prefix/'base-model.json',record['base_model_sha256'])
            weights={c:float(partition['global_class_weights'][c]) for c in base['class_names']}
            checks=[]
            for client in clients:
                model=_model_from_export(base,torch=torch,np=np)
                seed_local=seed+number*10000+int(records[client]['partition_id'])
                stored=next(r for r in record['local_training_records'] if r['client_id']==client)
                assert seed_local==stored['seed']
                train_local(model=model,rows=snapshots[client],class_names=base['class_names'],class_weights=weights,
                    epochs=cfg['local_epochs'],batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'],
                    seed=seed_local,device_name='cpu',torch=torch,np=np)
                expected=export_state(model,architecture=base['architecture'],class_names=base['class_names'])
                save(lab/f'{mode}-s{seed}'/f'round-{number:03d}'/f'{client}.json',expected)
                digest=sha256_bytes(derived_json_bytes(expected)); observed=sha256_file(prefix/'updates'/f'{client}.json')
                assert observed==stored['model_sha256']
                if digest!=observed: deviations[client].append(number)
                checks.append({'client_id':client,'base_model_sha256':record['base_model_sha256'],
                    'original_snapshot_sha256':records[client]['dataset_sha256'],'seed':seed_local,
                    'clean_reference_local_sha256':digest,'observed_local_sha256':observed,'equal':digest==observed})
            rounds.append({'round':number,'checks':checks})
            print(json.dumps({'seed':seed,'mode':mode,'audit_round':number}),flush=True)
        selected=sorted(c for c,numbers in deviations.items() if numbers)
        # Close selection before consulting the experiment's identity plan.
        result={'profile':'privileged-same-base-clean-execution-audit-v1',
            'candidate_groups':[selected] if len(selected)>=2 else [],'deviating_clients':selected,
            'deviation_rounds':deviations,'rounds':rounds,'labels_used_for_selection':False,
            'private_unmodified_snapshot_access_required':True,'intentional_collusion_proved':False}
        save(lab/f'{mode}-s{seed}-selection-before-labels.json',result)
        cases.append({'seed':seed,'mode':mode,'deviating_clients':selected})
evaluation=[]
for item in cases:
    truth=set(read(source/f'{item["mode"]}-s{item["seed"]}'/'protocol.json')['attack_plan']['client_components']) if item['mode']=='distributed' else set()
    flagged=set(item['deviating_clients'])
    evaluation.append({**item,'tp':len(flagged&truth),'fp':len(flagged-truth),'fn':len(truth-flagged),
        'exact_experimental_membership_recovered':flagged==truth})
save(lab/'evaluation.json',{'profile':'privileged-same-base-clean-execution-audit-v1','cases':evaluation,
    'local_reference_training_calls':900,'private_unmodified_snapshot_access_required':True,
    'general_update_only_detection_validated':False})
save(lab/'closure.json',{'artifacts':{p.relative_to(lab).as_posix():sha256_file(p) for p in lab.rglob('*') if p.is_file()}})
out=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/residual-poisoning-20261103')
(out/'same-base-execution-audit-evaluation.json').write_bytes((lab/'evaluation.json').read_bytes())
(out/'same-base-execution-audit-protocol.json').write_bytes((lab/'protocol-before-audit.json').read_bytes())
print(json.dumps(evaluation),flush=True)
