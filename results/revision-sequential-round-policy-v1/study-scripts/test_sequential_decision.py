import copy
import pytest
from fl_forensics.sequential_decision import SequentialRoundPolicy,digest,calibrate_sequential_policy


def calibration():
    return {'profile':'sequential-round-decision-v1','cohort_id':'toy','clients':['a','b','c'],
        'horizon':15,'drift':.5,'minimum_consecutive':2,'centers':[[0,0]]*3,'scales':[[1,1]]*3,
        'instantaneous_limits':[2,2],'cumulative_limits':[3,3],
        'review_instantaneous_limits':[1,1],'review_cumulative_limits':[2,2]}


def frame(policy,round_number,a,b=None,*,support=True,gates=None,masses=None,head=None,source='a'*64):
    return policy.step(round_number,{'conditioned':[a,0,0],'state-disabled':[a if b is None else b,0,0]},
        context_supported=support,mandatory_gate=gates or {c:True for c in 'abc'},
        masses=masses or dict.fromkeys('abc',1),expected_previous_digest=policy.head if head is None else head,
        source_observation_sha256=source)


def test_disagreement_is_preserved_as_review_not_malice():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=2)
    for t in range(1,8):result=frame(policy,t,10,0)
    assert result['clients']['a']['action']=='review_required'
    assert result['clients']['a']['view_disagreement']
    assert result['quarantine_current_round']==[] and not result['clients']['a']['semantic_malice_proved']


def test_persistent_moderate_evidence_accumulates_without_instant_exceedance():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=2)
    for t in range(1,5):result=frame(policy,t,1.5)
    assert result['quarantine_current_round']==['a']
    assert not result['clients']['a']['instantaneous_proposal']


def test_one_spike_is_not_sufficient_and_quarantine_is_not_a_ban():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=2)
    assert frame(policy,1,10)['quarantine_current_round']==[]
    assert frame(policy,2,10)['quarantine_current_round']==['a']
    result=frame(policy,3,0)
    assert result['quarantine_current_round']==[] and not result['client_ban_performed']


def test_retry_does_not_double_count_evidence_and_changed_retry_fails():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=2);previous=policy.head
    result=frame(policy,1,2,head=previous)
    assert frame(policy,1,2,head=previous)==result
    with pytest.raises(ValueError,match='retry'):frame(policy,1,3,head=previous)
    with pytest.raises(ValueError,match='retry'):frame(policy,1,2,head=previous,source='b'*64)
    with pytest.raises(ValueError,match='retry'):frame(policy,1,2)


def test_future_values_cannot_change_decisions_of_an_existing_prefix():
    a=SequentialRoundPolicy(calibration(),minimum_contributors=2);b=SequentialRoundPolicy(calibration(),minimum_contributors=2)
    first=[frame(a,t,1.5 if t<8 else 50) for t in range(1,16)]
    second=[frame(b,t,1.5 if t<8 else 0) for t in range(1,16)]
    assert first[:7]==second[:7]


def test_weight_changes_priority_but_not_quarantine_votes():
    a=SequentialRoundPolicy(calibration(),minimum_contributors=2);b=SequentialRoundPolicy(calibration(),minimum_contributors=2)
    for t in range(1,5):
        x=frame(a,t,1.5,masses={'a':1,'b':100,'c':100})
        y=frame(b,t,1.5,masses={'a':1000,'b':1,'c':1})
    assert x['quarantine_current_round']==y['quarantine_current_round']
    assert y['clients']['a']['review_priority']>x['clients']['a']['review_priority']


def test_failed_mandatory_gate_cannot_be_compensated_by_any_statistic():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=2)
    result=frame(policy,1,0,gates={'a':False,'b':True,'c':True},masses={'a':999,'b':1,'c':1})
    assert result['mandatory_rejections']==['a'] and result['proposed_effective_masses']['a']=='0'
    assert not result['supported'] and result['clients']['b']['action']=='abstain_requires_review'


def test_unsupported_context_resets_accumulation_and_requires_review():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=2)
    frame(policy,1,10);result=frame(policy,2,10,support=False)
    assert result['quarantine_current_round']==[] and result['review_required']==list('abc')
    assert result['clients']['a']['cumulative_evidence']['conditioned']==0
    assert frame(policy,3,10)['quarantine_current_round']==[]


def test_quorum_failure_does_not_readmit_proposed_quarantines():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=3)
    frame(policy,1,10);result=frame(policy,2,10)
    assert not result['proposal_quorum_satisfied']
    assert result['quarantine_current_round']==['a'] and result['proposed_effective_masses']['a']=='0'


def test_wrong_round_or_anchor_is_rejected_before_state_mutation():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=2)
    with pytest.raises(ValueError):frame(policy,2,10)
    with pytest.raises(ValueError):frame(policy,1,10,head='f'*64)
    assert policy.round==0 and policy.head=='0'*64


def test_decision_digest_binds_actions_and_evidence():
    policy=SequentialRoundPolicy(calibration(),minimum_contributors=2);result=frame(policy,1,10)
    core={k:v for k,v in result.items() if k!='decision_digest'}
    assert digest(core)==result['decision_digest']
    core['clients']['a']['action']='quarantine_current_round'
    assert digest(core)!=result['decision_digest']


def test_sequential_calibration_excludes_private_labels_and_data_reuse():
    def seq(name,value):
        return {'sequence_id':name,'cohort_id':'toy','clients':list('abc'),
            'risk':{v:[[value]*3]*3 for v in ('conditioned','state-disabled')},
            'supported':[True]*3,'frame_ids':[f'{name}-{i}' for i in range(3)]}
    normal=seq('norm',0);threshold=seq('null',.1)
    result=calibrate_sequential_policy([normal],[threshold],horizon=15)
    assert result['including_cyclic_null_stress_sequences']==3
    with pytest.raises(ValueError,match='overlap'):calibrate_sequential_policy([normal],[normal])
    threshold['attack_plan']={}
    with pytest.raises(ValueError,match='observable'):calibrate_sequential_policy([normal],[threshold])
