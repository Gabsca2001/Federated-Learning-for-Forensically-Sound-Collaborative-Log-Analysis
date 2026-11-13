"""Exact history comparison for a declared clean-reference intervention.

The caller must authenticate source artifacts and normalize committed input/model
hashes. Equality here is relative to that reference, not a claim that unknown raw
data or a warm starting checkpoint were clean.
"""
import re


def compare_replay_histories(candidate, reference, *, initial_model_sha256, expected_rounds):
    def require_hash(value):
        if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None:
            raise ValueError('invalid input/model commitment')
    def normalized(records):
        if expected_rounds <= 0 or len(records) != expected_rounds:
            raise ValueError('the complete declared replay horizon is required')
        result=[]; previous=initial_model_sha256
        for number,record in enumerate(records,1):
            if record['round_number'] != number:
                raise ValueError('replay rounds must be consecutive from one')
            require_hash(record['base_model_sha256']); require_hash(record['global_model_sha256'])
            if record['base_model_sha256'] != previous:
                raise ValueError('replay base does not follow the previous checkpoint')
            clients=record['selected_clients']
            local=record['local_training_records']
            if not clients or clients != sorted(set(clients)) or [x['client_id'] for x in local] != clients:
                raise ValueError('ambiguous ordered participation or local input population')
            commits=[]
            for item in local:
                require_hash(item['training_rows_sha256']); require_hash(item['local_model_sha256'])
                commits.append({k:item[k] for k in ('client_id','training_rows_sha256','local_model_sha256')})
            result.append({'round_number':number,'base_model_sha256':record['base_model_sha256'],
                'global_model_sha256':record['global_model_sha256'],'selected_clients':clients,'local_training_records':commits})
            previous=record['global_model_sha256']
        return result
    require_hash(initial_model_sha256)
    left,right=normalized(candidate),normalized(reference)
    comparisons=[]
    for a,b in zip(left,right,strict=True):
        fields={key:a[key]==b[key] for key in ('base_model_sha256','global_model_sha256','selected_clients','local_training_records')}
        comparisons.append({'round_number':a['round_number'],'matches':fields,'equal':all(fields.values())})
    return {'profile':'exact-replay-history-comparison-v1','commitment_trajectories_equal':all(x['equal'] for x in comparisons),
        'compared_rounds':expected_rounds,'rounds':comparisons,'ASR_used_for_acceptance':False,
        'source_payload_authentication_performed_by_this_function':False,
        'interpretation':'Equality of complete normalized committed histories under the declared intervention. Caller must authenticate the artifacts. Cleanliness of the reference and warm prefix is an explicit external assumption.'}
