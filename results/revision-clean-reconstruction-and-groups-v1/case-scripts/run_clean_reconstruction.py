"""Explicit clean-reference contracts, not ASR-based erasure claims."""
import json
from pathlib import Path

import numpy as np
from revision_dba_experiment import authenticate, read_pinned, save, model_with_arrays, outcomes, predict, environment
from fl_forensics.canonical import sha256_file, sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.federated_model import dependencies, arrays_from_export, train_local, export_state
from fl_forensics.secure_round import _model_from_export
from fl_forensics.byzantine import model_delta, aggregate_deltas, apply_delta

REPO = Path.cwd()
LAB = REPO/'artifacts/revision-clean-reconstruction-v1'
OLD = REPO/'artifacts/revision-effective-influence-v1/replay'
SOURCE = REPO/'artifacts/revision-dba-three-seed-v1'
SEEDS = (341593,342593,343593)
BRANCHES = ('clean-matched-group','repair-all-poisoning')
GROUP = {'client01','client06','client11'}


def read(path):
    return json.loads(path.read_bytes())


assert not LAB.exists()
LAB.mkdir()
old_closure = read(OLD/'closure.json')
previous = Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/effective-influence-20261103')
assert sha256_file(previous/'completion-closure.json')=='9803d5b46fcca8dcededad8255a3d4e9360adb088c189e9e6327ad91cc0c10fa'
assert sha256_file(OLD/'closure.json')==read(previous/'completion-closure.json')['core']['replay_artifact_closure_sha256']
for name,digest in old_closure['artifacts'].items():
    assert sha256_file(OLD/name)==digest
pins={}
for seed in SEEDS:
    source = SOURCE/f'clean-s{seed}'
    creation = read(SOURCE/'reports'/f'clean-s{seed}.json')['creation']
    assert sha256_file(source/'experiment-authority.public.pem')==creation['public_key_sha256']
    authenticate(source,creation['manifest_sha256'])
    pins[str(seed)]=creation
protocol={'profile':'clean-reconstruction-reference-contract-v1','seeds':list(SEEDS),'branches':list(BRANCHES),
    'source_pins':pins,'old_replay_closure_sha256':sha256_file(OLD/'closure.json'),
    'clean_matched_group':'Use only committed unmodified local snapshots; omit client01/06/11 during rounds 1–10, return them clean during 11–15. Compare every update and checkpoint with old group-removal trajectory.',
    'repair_all_poisoning':'All 15 clients participate. Use committed unmodified local snapshots without the experimental poisoning transformation in every round. Compare every update and checkpoint with the original all-participant clean campaign.',
    'clean_assumption':'Initial warm checkpoint and the supplied committed snapshots are assumed clean. This certifies an explicit experimental reference, not unknown real-world input cleanliness.',
    'equivalence_rule':'Exact participation, base, local model and global model hashes for every round; ASR plays no role in acceptance.',
    'environment':environment(),'implementation_files':{str(p):sha256_file(p) for p in sorted((REPO/'src/fl_forensics').glob('*.py'))},
    'runner_sha256':sha256_file(Path(__file__)),'fresh_attestation_performed':False}
save(LAB/'protocol-before-training.json',protocol)
deps=dependencies(); torch=deps[1]; torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
summary=[]
for seed in SEEDS:
    source=SOURCE/f'clean-s{seed}'
    cfg=read(source/'protocol-before-training.json')
    partition_root=Path(cfg['partition_workspace'])
    partition=read_pinned(partition_root/'manifest.json',cfg['partition_manifest_sha256'])
    records={r['client_id']:r for r in partition['clients']}
    rows={c:read_pinned(partition_root/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()}
    initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256'])
    val=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
    weights={c:float(partition['global_class_weights'][c]) for c in initial['class_names']}
    for branch in BRANCHES:
        base=initial
        rounds=[]
        for number in range(1,16):
            selected=sorted(set(records)-(GROUP if branch=='clean-matched-group' and number<=10 else set()))
            prefix=LAB/f'seed-{seed}'/branch/f'round-{number:03d}'
            arrays=arrays_from_export(base,np=np)
            models=[]; counts=[]; local_records=[]
            reference=OLD/f'seed-{seed}/remove-group-history/round-{number:03d}' if branch=='clean-matched-group' else source/f'rounds/round-{number:03d}'
            reference_round=read(reference/'record.json') if branch=='clean-matched-group' else read(reference/'round.json')
            reference_clients=reference_round['selected_clients'] if branch=='clean-matched-group' else reference_round['client_ids']
            assert selected==reference_clients
            base_hash=sha256_bytes(derived_json_bytes(base))
            assert base_hash==reference_round['base_model_sha256']
            for client in selected:
                model=_model_from_export(base,torch=torch,np=np)
                train_local(model=model,rows=rows[client],class_names=base['class_names'],class_weights=weights,
                    epochs=cfg['local_epochs'],batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'],
                    seed=seed+number*10000+int(records[client]['partition_id']),device_name='cpu',torch=torch,np=np)
                local=export_state(model,architecture=base['architecture'],class_names=base['class_names'])
                data=derived_json_bytes(local)
                assert data==(reference/'updates'/f'{client}.json').read_bytes(),(seed,branch,number,client)
                save(prefix/'updates'/f'{client}.json',local)
                models.append(arrays_from_export(local,np=np)); counts.append(len(rows[client]))
                local_records.append({'client_id':client,'source_snapshot_sha256':records[client]['dataset_sha256'],
                    'training_rows_sha256':sha256_bytes(derived_json_bytes(rows[client])),'local_model_sha256':sha256_file(prefix/'updates'/f'{client}.json')})
            result=model_with_arrays(base,apply_delta(arrays,aggregate_deltas([model_delta(arrays,m) for m in models],strategy='fedavg',f=0,weights=counts)))
            reference_model=reference/'global-model.json' if branch=='clean-matched-group' else reference/'aggregates/fedavg.json'
            assert derived_json_bytes(result)==reference_model.read_bytes(),(seed,branch,number,'global mismatch')
            save(prefix/'global-model.json',result)
            record={'round_number':number,'selected_clients':selected,'base_model_sha256':base_hash,
                'local_training_records':local_records,'global_model_sha256':sha256_file(prefix/'global-model.json'),
                'reference_global_model_sha256':sha256_file(reference_model),'all_local_models_byte_equal':True}
            save(prefix/'record.json',record); rounds.append(record); base=result
            print(json.dumps({'seed':seed,'branch':branch,'round':number,'reference_byte_equal':True}),flush=True)
        summary.append({'seed':seed,'branch':branch,'rounds':rounds,'clean_reference_equivalence_verified':True})
save(LAB/'summary.json',{'profile':protocol['profile'],'cases':summary,'rounds':90,
    'local_training_calls':1260,'all_local_models_and_checkpoints_byte_equal':True,
    'scope':protocol['clean_assumption'],'no_ASR_based_acceptance':True})
artifacts={p.relative_to(LAB).as_posix():sha256_file(p) for p in LAB.rglob('*') if p.is_file()}
save(LAB/'closure.json',{'profile':protocol['profile'],'artifacts':artifacts,'fresh_attestation_performed':False})
print('CLEAN REFERENCE CONTRACTS VERIFIED',flush=True)
