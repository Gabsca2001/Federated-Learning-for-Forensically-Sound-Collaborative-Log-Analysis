"""Finite current-release cross-checks; universal claims need the manual proofs."""
from collections import Counter
from fractions import Fraction as F
from itertools import combinations,product
from pathlib import Path
from types import SimpleNamespace as NS
import json
import numpy as np
from fl_forensics.canonical import sha256_file
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.composite_admission import decide_admission_policies
from fl_forensics.composite_admission_models import TrustSignal,StatisticalSignal
from fl_forensics.counterfactual_round import _proposal_metrics
from fl_forensics.influence_diagnostics import influence_diagnostics
from fl_forensics.current_evidence_policy import CurrentEvidencePolicy
from fl_forensics.client_envelope_policy import ClientEnvelopePolicy
from fl_forensics.preprocessing import derived_json_bytes

out=Path(__file__).parent;repo=Path.cwd();counts=Counter()
snapshot=json.loads((out/'before-review.json').read_bytes())
revision=json.loads((out/'source-correction.json').read_bytes())
assert implementation_sha256()==revision['after_implementation_sha256']
for name,value in snapshot['sources'].items():
    expected=revision['source_changes'].get(name,{}).get('after_sha256',value)
    assert sha256_file(repo/name)==expected
grid=[0.,.25,.5,.75,1.]
for down,quarantine,trust_weight,trust_risk,stat_risk,gate in product(grid,grid,grid,grid,grid,(False,True)):
    if down>quarantine:continue
    trust=TrustSignal(raw_status='formal-review-example',admissible=gate,risk=trust_risk,evaluated_checks=[],failed_checks=[] if gate else ['veto'],reasons=[])
    stat=StatisticalSignal(client_id='k',risk=stat_risk,components=[])
    decision=next(d for d in decide_admission_policies(trust=trust,statistics=stat,statistical_threshold=.5,
        composite_threshold=quarantine,composite_downweight_threshold=down,trust_weight=trust_weight) if d.policy=='gated_composite')
    risk=trust_weight*trust_risk+(1-trust_weight)*stat_risk
    expected='trust_quarantined' if not gate else 'statistically_quarantined' if risk>quarantine else 'accepted_downweighted' if risk>down else 'accepted'
    assert decision.status==expected and (gate or not decision.contributes)
    counts['gated_composite_boundary_instances']+=1

def metric_case(masses,removed,after_masses=None):
    clients=[f'k{i}' for i in range(len(masses))];sids=[f's{i}' for i in range(len(masses))]
    status=lambda m:'accepted' if m>0 else 'statistically_quarantined'
    entries=[{'client_id':c,'submission_id':sids[i],'runtime':NS(core=NS(final_status=status(masses[i])))} for i,c in enumerate(clients)]
    dispositions=[NS(client_id=c,kind='runtime_admission',final_status=status(masses[i])) for i,c in enumerate(clients)]
    dispositions.append(NS(client_id='rejected',kind='protocol_rejection',final_status='rejected_conflict'))
    total=sum(masses,F());before={sids[i]:v/total for i,v in enumerate(masses)}
    survivors=[i for i in range(len(masses)) if i not in removed]
    after_mass={i:masses[i] for i in survivors} if after_masses is None else dict(zip(survivors,after_masses,strict=True))
    remaining=sum(after_mass.values(),F());after={sids[i]:v/remaining for i,v in after_mass.items()} if remaining else None
    actions={sids[i]:status(v) for i,v in after_mass.items()}
    result=_proposal_metrics(clients+['missing','rejected'],dispositions,entries,{sids[i] for i in removed},before,after,actions)
    assert result['j_any_action_change']==int(bool(removed) or any(status(masses[i])!=actions[sids[i]] for i in survivors))
    assert result['actions_before']['rejected']==result['actions_after']['rejected']
    if after is None:
        assert result['delta_l1'] is None and result['coefficients_after'] is None;counts['undefined_metric_domains']+=1;return
    delta=F(int(result['delta_l1']['numerator']),int(result['delta_l1']['denominator']))
    beta=sum((before[sids[i]] for i in removed),F())
    survivor_delta=sum((abs(after[sids[i]]-before[sids[i]]) for i in survivors),F())
    assert delta==survivor_delta+beta and 2*beta<=delta<=2
    if after_masses is None:
        assert delta==2*beta
        u=[F((-1)**i*(i+1)) for i in range(len(masses))]
        original=sum((before[sids[i]]*u[i] for i in range(len(masses))),F())
        changed=sum((after[sids[i]]*u[i] for i in survivors),F())
        assert changed==(original-sum((before[sids[i]]*u[i] for i in removed),F()))/(1-beta)
        assert abs(original-changed)<=sum((before[sids[i]]*abs(u[i]-original) for i in removed),F())/(1-beta)
        counts['ideal_frozen_identity_and_bound']+=1
mass_grid=[F(),F(1,2),F(1),F(2)]
for n in range(1,5):
    for masses in product(mass_grid,repeat=n):
        if not sum(masses):continue
        for length in range(n+1):
            for selected in combinations(range(n),length):metric_case(masses,set(selected));counts['fixed_population_frozen_metrics']+=1
for masses in product(mass_grid,repeat=3):
    if not sum(masses):continue
    for length in (1,2):
        for selected in combinations(range(3),length):
            for after in product(mass_grid,repeat=3-length):metric_case(masses,set(selected),after);counts['rescored_metrics']+=1

cal={'profile':'sequential-round-decision-v1','cohort_id':'formal-example','clients':list('abc'),'horizon':15,'drift':.5,'minimum_consecutive':2,
    'centers':[[0,0]]*3,'scales':[[1,1]]*3,'instantaneous_limits':[10,10],'cumulative_limits':[30,30],
    'review_instantaneous_limits':[1,1],'review_cumulative_limits':[2,2]}
envelope={'profile':'clean-client-risk-envelope-v1','cohort_id':'formal-example','clients':list('abc'),
    'tensor_risk_limits':[[2,2]]*3,'retained_peak_fraction':.5}
factories={'current':lambda minimum=2:CurrentEvidencePolicy(cal,minimum_contributors=minimum),
    'envelope':lambda minimum=2:ClientEnvelopePolicy(cal,envelope,minimum_contributors=minimum)}
symbols={'low':(0,0,True,True),'small':(2.0625,2.0625,True,True),'moderate':(2.25,2.25,True,True),
    'peak':(2.5,2.5,True,True),'both':(12,12,True,True),'one-view':(12,0,True,True),
    'unsupported':(None,None,False,True),'gate-failure':(None,None,True,False)}
def advance(policy,number,symbol):
    a,b,support,gate=symbols[symbol];risk=None if a is None else {'conditioned':[a,0,0],'state-disabled':[b,0,0]}
    return policy.step(number,risk,context_supported=support,mandatory_gate={'a':gate,'b':True,'c':True},masses={'a':1,'b':2,'c':3},
        expected_previous_digest=policy.head,source_observation_sha256=f'{number:064x}')
for name,factory in factories.items():
    for sequence in product(symbols,repeat=4):
        policy=factory();previous_high=False;previous_retained=False;peak=F()
        for number,symbol in enumerate(sequence,1):
            left,right,support,gate=symbols[symbol];supported=support and gate
            high=bool(supported and left>10 and right>10)
            if supported:
                excess=min(F(left)-2,F(right)-2);positive=excess>0;peak=max(peak,excess) if positive else F()
                retained=positive and excess>=peak/2
            else:peak=F();retained=False
            expected=high and previous_high or name=='envelope' and retained and previous_retained
            result=advance(policy,number,symbol)
            assert ('a' in result['quarantine_current_round'])==bool(expected)
            assert all(c=='a' for c in result['quarantine_current_round'])
            assert F(result['proposed_effective_masses']['a'])==(0 if expected or not gate else 1)
            assert result['clients']['a']['action']=='protocol_reject' if not gate else True
            previous_high=high;previous_retained=retained
            counts[name+'_oracle_round_transitions']+=1
    # A common prefix yields identical decisions under different continuations.
    for prefix in product(symbols,repeat=2):
        for future in symbols:
            first=factory();second=factory();a=[advance(first,i,s) for i,s in enumerate(prefix+('low','low'),1)]
            b=[advance(second,i,s) for i,s in enumerate(prefix+(future,future),1)]
            assert derived_json_bytes(a[:2])==derived_json_bytes(b[:2]);counts[name+'_prefix_pairs']+=1
    p=factory();first=advance(p,1,'moderate');head=p.head
    retry=p.step(1,{'conditioned':[2.25,0,0],'state-disabled':[2.25,0,0]},context_supported=True,
        mandatory_gate=dict.fromkeys('abc',True),masses={'a':1,'b':2,'c':3},expected_previous_digest='0'*64,source_observation_sha256=f'{1:064x}')
    assert first==retry and p.head==head;counts['exact_retry_checks']+=1
    p=factory(3);advance(p,1,'both');result=advance(p,2,'both')
    assert result['quarantine_current_round']==['a'] and not result['proposal_quorum_satisfied']
    assert F(result['proposed_effective_masses']['a'])==0;counts['quorum_no_readmission_checks']+=1

# Constructive scope counterexamples, not malicious-model realization claims.
unsupported={}
for name,factory in factories.items():
    d=advance(factory(),1,'unsupported')
    assert not d['supported'] and d['proposal_quorum_satisfied'] and d['quarantine_current_round']==[]
    assert d['proposed_effective_masses']=={'a':'1','b':'2','c':'3'}
    unsupported[name]={'supported':d['supported'],'quorum':d['proposal_quorum_satisfied'],
        'actions':{c:v['action'] for c,v in d['clients'].items()},'proposed_masses':d['proposed_effective_masses']}
peak_case=[];p=factories['envelope']()
for number,symbol in enumerate(['peak']+['small']*14,1):
    d=advance(p,number,symbol);assert d['quarantine_current_round']==[] and d['clients']['a']['client_envelope_current_high']
    peak_case.append({'round':number,'action':d['clients']['a']['action'],'peak':d['clients']['a']['client_envelope_episode_peak_excess'],
        'current_excess':d['clients']['a']['client_envelope_current_minimum_excess']})
before={'a':F(1,2),'b':F(1,4),'c':F(1,4)};frozen={'b':F(1,2),'c':F(1,2)};after={'b':F(1),'c':F()}
local={'a':np.array([-1.,0.]),'b':np.array([0.,0.]),'c':np.array([2.,0.])}
weighted=lambda coefficients:[sum((float(w)*local[c] for c,w in coefficients.items()),np.zeros(2))]
diag=influence_diagnostics(before_coefficients=before,frozen_coefficients=frozen,after_coefficients=after,
    before_actions={'a':'accepted','b':'accepted','c':'accepted'},after_actions={'b':'accepted','c':'statistically_quarantined'},removed_ids={'a'},
    original_model=weighted(before),frozen_model=weighted(frozen),after_model=weighted(after))
assert diag['direct_removal_model_l2']==diag['additional_policy_model_l2']==1 and diag['total_model_l2']==0
assert diag['vector_decomposition_residual_l2']==0
from flwr.server.strategy.aggregate import aggregate
u=[np.asarray([2.,5.],dtype=np.float32)]
assert aggregate([(u,1.),(u,3.)])[0].tobytes()==aggregate([(u,3.),(u,1.)])[0].tobytes()
summary={'profile':'current-release-formal-finite-cross-checks-v2','status':'passed','implementation_sha256':implementation_sha256(),
    'counts':dict(counts),'proof_assistant_certified':False,'production_code_changed':False,
    'scope_counterexamples':{'unsupported_context_can_preserve_eligible_proposed_mass':unsupported,
        'persistent_positive_envelope_excess_need_not_quarantine':peak_case,
        'model_norm_scalars_are_not_additive':diag,
        'different_coefficients_can_share_actual_Flower_model_bytes':True},
    'qualification':'Finite checks support implementation correspondence. They do not prove universal accuracy, eventual detection, live admission or a clean reference. Synthetic risk sequences are not demonstrated realizable attacks.'}
(out/'current-obligation-checks.json').write_bytes(derived_json_bytes(summary))
print('CURRENT OBLIGATION CHECKS PASSED',json.dumps(dict(counts)),flush=True)
