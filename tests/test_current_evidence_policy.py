import pytest

from fl_forensics.current_evidence_policy import CurrentEvidencePolicy
from fl_forensics.sequential_decision import digest


def cal():
    return {'profile':'sequential-round-decision-v1','cohort_id':'toy','clients':['a','b','c'],
        'horizon':15,'drift':.5,'minimum_consecutive':2,'centers':[[0,0]]*3,'scales':[[1,1]]*3,
        'instantaneous_limits':[2,2],'cumulative_limits':[3,3],
        'review_instantaneous_limits':[1,1],'review_cumulative_limits':[2,2]}


def step(p,t,x,y=None,*,supported=True,gates=None,masses=None,previous=None,source='a'*64):
    return p.step(t,{'conditioned':[x,0,0],'state-disabled':[x if y is None else y,0,0]},
        context_supported=supported,mandatory_gate=gates or dict.fromkeys('abc',True),
        masses=masses or dict.fromkeys('abc',1),expected_previous_digest=p.head if previous is None else previous,
        source_observation_sha256=source)


def test_isolated_current_peak_requires_review_only():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    assert step(p,1,100)['clients']['a']['quarantine_transition']=='confirmation_pending'
    assert step(p,2,0)['quarantine_current_round']==[]


def test_two_current_high_rounds_enter_and_lost_current_evidence_releases():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    step(p,1,100);r=step(p,2,100)
    assert r['quarantine_current_round']==['a'] and r['quarantine_transitions']['a']=='entered'
    r=step(p,3,1.5)
    assert r['quarantine_current_round']==[] and r['quarantine_transitions']['a']=='released'
    assert r['clients']['a']['cumulative_evidence']['conditioned']>190
    assert r['clients']['a']['action']=='review_required'


def test_reentry_after_release_requires_new_confirmation():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    for t,x in enumerate([10,10,0,10,10],1):r=step(p,t,x)
    assert r['quarantine_current_round']==['a'] and r['quarantine_transitions']['a']=='entered'
    assert r['clients']['a']['consecutive_current_high_rounds']==2


def test_one_view_cannot_sustain_quarantine():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    step(p,1,10);step(p,2,10);r=step(p,3,10,0)
    assert r['quarantine_current_round']==[] and r['clients']['a']['action']=='review_required'


def test_large_cumulative_history_never_substitutes_for_current_high():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    for t in range(1,16):r=step(p,t,1.5)
    assert r['clients']['a']['sequential_proposal']
    assert r['quarantine_current_round']==[]


def test_unsupported_frame_releases_and_breaks_confirmation():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    step(p,1,10);step(p,2,10);r=step(p,3,10,supported=False)
    assert r['quarantine_transitions']['a']=='released' and not r['supported']
    assert step(p,4,10)['quarantine_current_round']==[]


def test_gate_failure_overrides_history_and_large_mass():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    step(p,1,10);step(p,2,10)
    r=step(p,3,10,gates={'a':False,'b':True,'c':True},masses={'a':999,'b':1,'c':1})
    assert r['mandatory_rejections']==['a'] and r['proposed_effective_masses']['a']=='0'
    assert r['quarantine_current_round']==[]


def test_exact_retry_does_not_advance_confirmation_or_chain():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2);head=p.head
    r=step(p,1,10,previous=head)
    assert step(p,1,10,previous=head)==r
    with pytest.raises(ValueError):step(p,1,10,previous=head,source='b'*64)
    with pytest.raises(ValueError):step(p,1,10)
    assert p.round==1
    assert step(p,2,10)['quarantine_current_round']==['a']


def test_prefixes_are_invariant_to_future_changes():
    a=CurrentEvidencePolicy(cal(),minimum_contributors=2);b=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    x=[step(a,t,10 if t<5 else 0) for t in range(1,16)]
    y=[step(b,t,10) for t in range(1,16)]
    assert x[:4]==y[:4]


def test_quarantines_always_require_current_dual_high_and_confirmation():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    for t,(x,y) in enumerate([(3,3),(3,3),(100,0),(1.5,1.5),(3,3),(3,3),(0,0)],1):
        r=step(p,t,x,y)
        assert all(r['clients'][c]['current_high_in_both_views'] and r['clients'][c]['consecutive_current_high_rounds']>=2 for c in r['quarantine_current_round'])


def test_quorum_failure_does_not_readmit_confirmed_contribution():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=3)
    step(p,1,10);r=step(p,2,10)
    assert not r['proposal_quorum_satisfied'] and r['proposed_effective_masses']['a']=='0'


def test_weights_change_review_priority_but_not_entry_or_release():
    a=CurrentEvidencePolicy(cal(),minimum_contributors=2);b=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    for t,x in enumerate([10,10,0],1):
        ra=step(a,t,x);rb=step(b,t,x,masses={'a':1000,'b':1,'c':1})
        assert ra['quarantine_current_round']==rb['quarantine_current_round']
    assert rb['clients']['a']['review_priority']>ra['clients']['a']['review_priority']


def test_decision_digest_binds_release_and_evidence():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2);step(p,1,10);step(p,2,10);r=step(p,3,0)
    core={k:v for k,v in r.items() if k!='decision_digest'}
    assert digest(core)==r['decision_digest']
    core['quarantine_transitions']['a']='continued'
    assert digest(core)!=r['decision_digest']


def test_invalid_order_and_noninteger_round_do_not_mutate_state():
    p=CurrentEvidencePolicy(cal(),minimum_contributors=2)
    for t in (True,1.0,0,2):
        with pytest.raises(ValueError):step(p,t,10)
    assert p.head=='0'*64 and p.round==0
