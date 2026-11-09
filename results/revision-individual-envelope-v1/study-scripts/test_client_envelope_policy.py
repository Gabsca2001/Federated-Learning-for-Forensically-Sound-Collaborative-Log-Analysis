import copy
import pytest
from fl_forensics.client_envelope_policy import ClientEnvelopePolicy
from fl_forensics.sequential_decision import digest


def policy(minimum=2):
    c={'profile':'sequential-round-decision-v1','cohort_id':'toy','clients':list('abc'),'horizon':15,'drift':.5,'minimum_consecutive':2,
        'centers':[[0,0]]*3,'scales':[[1,1]]*3,'instantaneous_limits':[100,100],'cumulative_limits':[100,100],
        'review_instantaneous_limits':[1,1],'review_cumulative_limits':[2,2]}
    e={'profile':'clean-client-risk-envelope-v1','cohort_id':'toy','clients':list('abc'),'tensor_risk_limits':[[2,2]]*3,'retained_peak_fraction':.5}
    return ClientEnvelopePolicy(c,e,minimum_contributors=minimum)


def step(p,t,x,y=None,*,support=True,gates=None,previous=None,source='a'*64,masses=None):
    return p.step(t,{'conditioned':[x,0,0],'state-disabled':[x if y is None else y,0,0]},context_supported=support,
        mandatory_gate=gates or dict.fromkeys('abc',True),masses=masses or dict.fromkeys('abc',1),
        expected_previous_digest=p.head if previous is None else previous,source_observation_sha256=source)


def test_weak_individual_departure_can_be_caught_below_old_global_limit():
    p=policy();assert not step(p,1,5)['quarantine_current_round'];r=step(p,2,5)
    assert r['quarantine_current_round']==['a'] and not r['baseline_quarantine_current_round']


def test_evidence_halving_releases_while_still_above_individual_limit():
    p=policy();step(p,1,10);step(p,2,10);r=step(p,3,2.2)
    assert r['quarantine_current_round']==[] and r['clients']['a']['client_envelope_retreat_detected']
    assert r['quarantine_transitions']['a']=='released'
    assert step(p,4,2.2)['quarantine_current_round']==[]


def test_episode_peak_is_not_a_rolling_one_frame_peak():
    p=policy();step(p,1,10);step(p,2,10);step(p,3,5)
    assert step(p,4,5)['quarantine_current_round']==[]


def test_gap_resets_peak_and_reentry_requires_fresh_confirmation():
    p=policy();step(p,1,10);step(p,2,10);step(p,3,0)
    assert step(p,4,3)['quarantine_current_round']==[]
    assert step(p,5,3)['quarantine_current_round']==['a']


def test_single_view_and_single_peak_do_not_authorize_client_envelope():
    p=policy();step(p,1,10,0);assert step(p,2,10,0)['quarantine_current_round']==[]
    step(p,3,10);assert step(p,4,0)['quarantine_current_round']==[]


def test_mandatory_gate_failure_still_has_zero_mass():
    p=policy();step(p,1,5);step(p,2,5);r=step(p,3,5,gates={'a':False,'b':True,'c':True},masses={'a':1000,'b':1,'c':1})
    assert r['mandatory_rejections']==['a'] and r['proposed_effective_masses']['a']=='0'


def test_unsupported_context_breaks_peak_and_confirmation():
    p=policy();step(p,1,5);step(p,2,5);r=step(p,3,5,support=False)
    assert r['quarantine_current_round']==[] and r['clients']['a']['action']=='abstain_requires_review'
    assert step(p,4,5)['quarantine_current_round']==[]


def test_retries_bind_observation_and_do_not_double_count():
    p=policy();head=p.head;r=step(p,1,5,previous=head)
    assert step(p,1,5,previous=head)==r
    with pytest.raises(ValueError):step(p,1,5,previous=head,source='b'*64)
    assert step(p,2,5)['quarantine_current_round']==['a']


def test_quorum_failure_does_not_restore_excluded_mass():
    p=policy(3);step(p,1,5);r=step(p,2,5)
    assert not r['proposal_quorum_satisfied'] and r['proposed_effective_masses']['a']=='0'


def test_future_values_do_not_change_existing_decisions():
    p=policy();q=policy();a=[step(p,t,5 if t<8 else 0) for t in range(1,16)];b=[step(q,t,5) for t in range(1,16)]
    assert a[:7]==b[:7]


def test_digest_binds_individual_envelope_evidence_and_releases():
    p=policy();r=step(p,1,5);core={k:v for k,v in r.items() if k!='decision_digest'}
    assert digest(core)==r['decision_digest']
    core['clients']['a']['client_envelope_episode_peak_excess']=99
    assert digest(core)!=r['decision_digest']


def test_other_clients_mass_does_not_change_quarantine():
    p=policy();q=policy()
    for t in range(1,4):
        a=step(p,t,5);b=step(q,t,5,masses={'a':1000,'b':1,'c':1})
        assert a['quarantine_current_round']==b['quarantine_current_round']
