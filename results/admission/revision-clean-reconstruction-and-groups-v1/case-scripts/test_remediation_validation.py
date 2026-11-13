import copy
import pytest
from fl_forensics.remediation_validation import compare_replay_histories


def history():
    return [{'round_number':n,'selected_clients':['a'],'base_model_sha256':str(n-1)*64,
        'global_model_sha256':str(n)*64,'local_training_records':[{'client_id':'a',
        'training_rows_sha256':'a'*64,'local_model_sha256':str(n)*64}]} for n in (1,2)]


def compare(a,b):
    return compare_replay_histories(a,b,initial_model_sha256='0'*64,expected_rounds=2)


def test_exact_full_history_matches_without_ASR():
    result=compare(history(),history())
    assert result['commitment_trajectories_equal']
    assert not result['ASR_used_for_acceptance']


def test_equal_final_model_does_not_hide_different_intermediate_history():
    a,b=history(),history()
    b[0]['global_model_sha256']='f'*64; b[1]['base_model_sha256']='f'*64
    assert a[-1]['global_model_sha256']==b[-1]['global_model_sha256']
    assert not compare(a,b)['commitment_trajectories_equal']


def test_ASR_zero_cannot_hide_remaining_poisoned_inputs():
    a,b=history(),history()
    a[0]['local_training_records'][0]['training_rows_sha256']='f'*64
    a[0]['asr']=b[0]['asr']=0
    assert not compare(a,b)['commitment_trajectories_equal']


@pytest.mark.parametrize('kind',['missing','broken-chain','bad-hash','client-mismatch','round-order'])
def test_incomplete_or_inconsistent_history_is_rejected(kind):
    a=history()
    if kind=='missing': a.pop()
    if kind=='broken-chain': a[1]['base_model_sha256']='f'*64
    if kind=='bad-hash': a[0]['local_training_records'][0]['local_model_sha256']='garbage'
    if kind=='client-mismatch': a[0]['selected_clients']=['b']
    if kind=='round-order': a.reverse()
    with pytest.raises(ValueError): compare(a,history())
