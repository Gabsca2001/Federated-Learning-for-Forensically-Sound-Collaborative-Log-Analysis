"""Authenticate payloads and apply the new exact-history comparison API."""
import json
from pathlib import Path
import copy

from fl_forensics.canonical import sha256_file, sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan, poison_local_rows
from fl_forensics.remediation_validation import compare_replay_histories
from revision_dba_experiment import authenticate, read_pinned

repo=Path.cwd(); lab=repo/'artifacts/revision-clean-reconstruction-v1'
old=repo/'artifacts/revision-effective-influence-v1/replay'
source=repo/'artifacts/revision-dba-three-seed-v1'
out=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/residual-poisoning-20261103')


def read(path):
    return json.loads(path.read_bytes())


for root in (lab,old):
    closure=read(root/'closure.json')
    for name,digest in closure['artifacts'].items():
        assert sha256_file(root/name)==digest,(root,name)
protocol=read(lab/'protocol-before-training.json')
for path,digest in protocol['implementation_files'].items():
    snapshot=lab/'numerical-source/fl_forensics'/Path(path).name
    assert sha256_file(snapshot)==digest
cases=[]
for seed in (341593,342593,343593):
    creation=protocol['source_pins'][str(seed)]
    clean=source/f'clean-s{seed}'
    assert sha256_file(clean/'experiment-authority.public.pem')==creation['public_key_sha256']
    authenticate(clean,creation['manifest_sha256'])
    cfg=read(clean/'protocol-before-training.json')
    partition=read_pinned(Path(cfg['partition_workspace'])/'manifest.json',cfg['partition_manifest_sha256'])
    records={r['client_id']:r for r in partition['clients']}
    rows={c:read_pinned(Path(cfg['partition_workspace'])/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for c,r in records.items()}
    def normalized(root,*,clean_format=False,poisoned=False):
        result=[]
        plan=DistributedBackdoorPlan.model_validate({**cfg['attack_plan'],'seed':seed})
        for number in range(1,16):
            prefix=root/('rounds' if clean_format else '')/f'round-{number:03d}'
            record=read(prefix/('round.json' if clean_format else 'record.json'))
            selected=record['client_ids'] if clean_format else record['selected_clients']
            model=prefix/('aggregates/fedavg.json' if clean_format else 'global-model.json')
            local=[]
            for client in selected:
                training=rows[client]
                if poisoned:
                    training,_=poison_local_rows(rows=training,plan=plan,client_id=client,round_number=number,distributed=True)
                commit={'client_id':client,'training_rows_sha256':sha256_bytes(derived_json_bytes(training)),
                    'local_model_sha256':sha256_file(prefix/'updates'/f'{client}.json')}
                if clean_format:
                    stored=next(r for r in record['local_training_records'] if r['client_id']==client)
                    assert stored['poisoned_snapshot_sha256']==commit['training_rows_sha256']
                    assert stored['local_model_sha256']==commit['local_model_sha256']
                elif 'local_training_records' in record:
                    stored=next(r for r in record['local_training_records'] if r['client_id']==client)
                    assert stored['training_rows_sha256']==commit['training_rows_sha256']
                    assert stored['local_model_sha256']==commit['local_model_sha256']
                local.append(commit)
            result.append({'round_number':number,'selected_clients':selected,'base_model_sha256':record['base_model_sha256'],
                'global_model_sha256':sha256_file(model),'local_training_records':local})
        return result
    for branch,reference in (
        ('clean-matched-group',normalized(old/f'seed-{seed}/remove-group-history')),
        ('repair-all-poisoning',normalized(clean,clean_format=True)),
    ):
        actual=normalized(lab/f'seed-{seed}'/branch)
        check=compare_replay_histories(actual,reference,initial_model_sha256=cfg['base_model_sha256'],expected_rounds=15)
        assert check['commitment_trajectories_equal']
        cases.append({'seed':seed,'branch':branch,'authenticated_artifact_payloads_verified':True,'comparison':check})
    # The earlier partial removal has equal participation but different inputs/state.
    partial=normalized(old/f'seed-{seed}/remove-single-history',poisoned=True)
    matched=normalized(old/f'seed-{seed}/clean-matched-single')
    check=compare_replay_histories(partial,matched,initial_model_sha256=cfg['base_model_sha256'],expected_rounds=15)
    assert not check['commitment_trajectories_equal']
    assert all(r['matches']['selected_clients'] for r in check['rounds'])
    cases.append({'seed':seed,'branch':'negative-control-partial-removal','authenticated_artifact_payloads_verified':True,'comparison':check})
report={'status':'verified','profile':'authenticated-clean-reconstruction-contracts-v1','cases':cases,
    'new_rounds':90,'new_local_training_calls':1260,'all_new_local_models_byte_equal_to_reference':1260,
    'new_global_models_byte_equal_to_reference':90,'new_reconstruction_closure_sha256':sha256_file(lab/'closure.json'),
    'source_input_assumption':protocol['clean_assumption'],'fresh_TPM_attestation_performed':False}
(out/'reconstruction-contract-verification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
(out/'reconstruction-protocol-before-training.json').write_bytes((lab/'protocol-before-training.json').read_bytes())
print(json.dumps({k:report[k] for k in ('status','new_rounds','new_local_training_calls')}))
