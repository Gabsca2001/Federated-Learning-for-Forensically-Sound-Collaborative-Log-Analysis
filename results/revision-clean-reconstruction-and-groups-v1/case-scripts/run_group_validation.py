"""Frozen pilot with separate clean fit, clean calibration and held-out seeds."""
import json
from pathlib import Path
import time

import numpy as np
from revision_dba_experiment import (read_pinned, save, model_with_arrays, authenticate,
    signature, environment, outcomes, predict)
from revision_group_analysis import load_rounds
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.canonical import digest_object, sha256_file, sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan, poison_local_rows
from fl_forensics.federated_model import dependencies, arrays_from_export, train_local, export_state
from fl_forensics.secure_round import _model_from_export
from fl_forensics.byzantine import model_delta, aggregate_deltas, apply_delta, update_indicators
from group_calibration_v2 import fit_group_reference, calibrate_group_threshold, detect_conditioned_groups

repo=Path.cwd(); lab=repo/'artifacts/revision-conditioned-groups-v2-fixed-serialization'
source=repo/'artifacts/revision-dba-three-seed-v1'
FIT=(341593,342593,343593); CAL=(351593,352593,353593); TEST=(361593,362593,363593)
assert not lab.exists(); lab.mkdir()


def read(path):
    return json.loads(path.read_bytes())


base_cfg=read(source/'distributed-s341593/protocol-before-training.json')
fit=[]; fit_pins={}
for seed in FIT:
    workspace=source/f'clean-s{seed}'; creation=read(source/'reports'/f'clean-s{seed}.json')['creation']
    assert sha256_file(workspace/'experiment-authority.public.pem')==creation['public_key_sha256']
    authenticate(workspace,creation['manifest_sha256']); fit_pins[str(seed)]=creation
    fit.append(load_rounds(workspace)[:10])
reference=fit_group_reference(fit)
save(lab/'fit-reference.json',reference)
save(lab/'protocol-before-new-training.json',{'profile':'pair-conditioned-group-pilot-v2',
    'fit_seeds':list(FIT),'calibration_clean_seeds':list(CAL),'evaluation_paired_seeds':list(TEST),
    'fit_source_pins':fit_pins,'horizon':10,'base_model_sha256':base_cfg['base_model_sha256'],
    'partition_manifest_sha256':base_cfg['partition_manifest_sha256'],'validation_sha256':base_cfg['validation_sha256'],
    'reference_digest':sha256_bytes(derived_json_bytes(reference)),'detector_module_sha256':sha256_file(Path(__file__).parent/'group_calibration_v2.py'),
    'runner_sha256':sha256_file(Path(__file__)),'environment':environment(),
    'definition':'Pair-specific robust clean centers/scales; maximum standardized increase per pair; threshold=max across all pairs in each of three independent clean calibration trajectories; maximal cliques of strict exceedance edges.',
    'selection_firewall':'Only load_rounds observable deltas/indicators enter fit, calibrate and detect. Candidate outputs close before attack identities or ASR enter evaluation.',
    'development':'V2 designed after inspecting the already used three development seeds. New seeds and all decisions fixed here before their training; the dataset itself is previously used validation data.',
    'qualification':'Small pilot on the same fixed client partition. No 1% or 5% false-positive guarantee, non-IID robustness, proof of intent or fresh TPM attestation.'})
deps=dependencies(); torch=deps[1]; torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
partition_root=Path(base_cfg['partition_workspace'])
partition=read_pinned(partition_root/'manifest.json',base_cfg['partition_manifest_sha256'])
records={r['client_id']:r for r in partition['clients']}; clients=sorted(records)
snapshots={c:read_pinned(partition_root/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()}
initial=read_pinned(base_cfg['base_model_path'],base_cfg['base_model_sha256'])
validation=read_pinned(base_cfg['validation_path'],base_cfg['validation_sha256'])['rows']['validation']
weights={c:float(partition['global_class_weights'][c]) for c in initial['class_names']}


def train(seed,mode):
    workspace=lab/f'{mode}-s{seed}'
    plan=DistributedBackdoorPlan.model_validate({**base_cfg['attack_plan'],'seed':seed})
    save(workspace/'protocol.json',{'seed':seed,'attack_mode':mode,'attack_plan':plan.model_dump(mode='json')})
    base=initial
    for number in range(1,11):
        prefix=workspace/'rounds'/f'round-{number:03d}'
        arrays=arrays_from_export(base,np=np); models=[]; counts=[]; training=[]
        save(prefix/'base-model.json',base)
        for client in clients:
            rows=snapshots[client]
            if mode=='distributed':
                rows,_=poison_local_rows(rows=rows,plan=plan,client_id=client,round_number=number,distributed=True)
            model=_model_from_export(base,torch=torch,np=np)
            seed_local=seed+number*10000+int(records[client]['partition_id'])
            train_local(model=model,rows=rows,class_names=base['class_names'],class_weights=weights,
                epochs=base_cfg['local_epochs'],batch_size=base_cfg['batch_size'],learning_rate=base_cfg['learning_rate'],
                seed=seed_local,device_name='cpu',torch=torch,np=np)
            local=export_state(model,architecture=base['architecture'],class_names=base['class_names'])
            save(prefix/'updates'/f'{client}.json',local)
            models.append(arrays_from_export(local,np=np)); counts.append(len(rows))
            training.append({'client_id':client,'seed':seed_local,'snapshot_sha256':records[client]['dataset_sha256'],
                'training_rows_sha256':sha256_bytes(derived_json_bytes(rows)),'model_sha256':sha256_file(prefix/'updates'/f'{client}.json')})
        deltas=[model_delta(arrays,m) for m in models]
        indicators=update_indicators(deltas,client_ids=clients)
        base_f1=None
        from revision_dba_experiment import evaluate
        base_f1=evaluate(base,validation,deps)['macro_f1_all_model_classes']
        for i,item in enumerate(indicators):
            local=read(prefix/'updates'/f'{clients[i]}.json')
            item['validation_impact']=base_f1-evaluate(local,validation,deps)['macro_f1_all_model_classes']
        save(prefix/'indicators.json',indicators)
        result=model_with_arrays(base,apply_delta(arrays,aggregate_deltas(deltas,strategy='fedavg',f=0,weights=counts)))
        save(prefix/'global-model.json',result)
        save(prefix/'round.json',{'round_number':number,'client_ids':clients,'base_model_sha256':sha256_bytes(derived_json_bytes(base)),
            'local_training_records':training,'global_model_sha256':sha256_file(prefix/'global-model.json')})
        base=result
        print(json.dumps({'seed':seed,'mode':mode,'round':number}),flush=True)
    signer=SoftwareECDSASigner.generate()
    (workspace/'experiment-authority.public.pem').write_bytes(signer.public_pem())
    core={'profile':'software-observable-group-campaign-v2','artifacts':{p.relative_to(workspace).as_posix():sha256_file(p) for p in workspace.rglob('*') if p.is_file()},
        'fresh_TPM_attestation':False,'client_signatures_claimed':False}
    digest=digest_object(core)
    save(workspace/'manifest.json',{'core':core,'core_digest':digest,'signature':signature(signer,digest)})
    authenticate(workspace,sha256_file(workspace/'manifest.json'))
    return workspace


calibration_campaigns=[load_rounds(train(seed,'clean')) for seed in CAL]
calibration=calibrate_group_threshold(calibration_campaigns,reference)
save(lab/'frozen-calibration-before-evaluation.json',calibration)
selected=[]
for seed in TEST:
    for mode in ('clean','distributed'):
        workspace=train(seed,mode)
        observations=load_rounds(workspace)
        result=detect_conditioned_groups(observations,reference,calibration)
        save(lab/f'{mode}-s{seed}-selection-before-labels.json',result)
        selected.append((seed,mode,workspace,result))
# All candidate sets are closed before any truth/ASR is consulted for evaluation.
evaluation=[]
prediction,_=predict(initial,validation,deps)
correct=[p==row['label'] for p,row in zip(prediction,validation,strict=True)]
for seed,mode,workspace,result in selected:
    plan=DistributedBackdoorPlan.model_validate(read(workspace/'protocol.json')['attack_plan'])
    truth=set(plan.client_components) if mode=='distributed' else set()
    flagged={c for g in result['candidate_groups'] for c in g}
    tp,fp,fn=len(flagged&truth),len(flagged-truth),len(truth-flagged)
    outcome=outcomes(read(workspace/'rounds/round-010/global-model.json'),validation,plan,correct,deps)
    evaluation.append({'seed':seed,'mode':mode,'candidate_groups':result['candidate_groups'],
        'tp':tp,'fp':fp,'fn':fn,'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,
        'exact_group_recovered':any(set(g)==truth for g in result['candidate_groups']) if truth else None,
        'campaign_alarm':bool(flagged),'ASR_for_evaluation_only':outcome['complete_trigger']['asr'],
        'clean_macro_f1':outcome['clean']['macro_f1_all_model_classes'],
        'source_manifest_sha256':sha256_file(workspace/'manifest.json')})
save(lab/'evaluation.json',{'profile':'pair-conditioned-group-pilot-v2','cases':evaluation,'new_training_calls':1350,
    'new_campaigns':9,'intentional_collusion_proved':False})
save(lab/'closure.json',{'artifacts':{p.relative_to(lab).as_posix():sha256_file(p) for p in lab.rglob('*') if p.is_file()}})
out=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/residual-poisoning-20261103')
for name in ('protocol-before-new-training.json','fit-reference.json','frozen-calibration-before-evaluation.json','evaluation.json'):
    (out/('groups-v2-'+name)).write_bytes((lab/name).read_bytes())
print(json.dumps({'evaluation':evaluation}),flush=True)
