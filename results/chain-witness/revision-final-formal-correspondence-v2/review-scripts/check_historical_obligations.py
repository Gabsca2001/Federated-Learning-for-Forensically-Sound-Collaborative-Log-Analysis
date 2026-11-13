"""Finite cross-checks for manual conditional proofs; not a proof assistant.

Exercise the real policy/metric functions, and independently check typed paths
in the sealed attacked case. Never rewrite experimental or thesis artifacts.
"""
from collections import Counter, defaultdict, deque
from fractions import Fraction as F
from itertools import combinations, product
from pathlib import Path
from types import SimpleNamespace as NS
import hashlib
import json
import zipfile

from fl_forensics.canonical import digest_object
from fl_forensics.composite_admission import decide_admission_policies
from fl_forensics.composite_admission_models import TrustSignal, StatisticalSignal
from fl_forensics.counterfactual_round import _proposal_metrics
from fl_forensics.crypto import load_public_key, verify_digest_signature
from fl_forensics.round_derivation import implementation_sha256

out=Path(__file__).resolve().parent
case=out.parent/'attack-replay-20261103'
closure_data=(case/'case-closure.json').read_bytes()
assert hashlib.sha256(closure_data).hexdigest()=='f265b12d1d331cdf913eb2c21eab4555684ed79550ab0fd6630bec07d5d6759c'
closure=json.loads(closure_data)
assert digest_object(closure['core'])==closure['core_digest']
assert hashlib.sha256((case/'case-authority.public.pem').read_bytes()).hexdigest()==closure['core']['coordinator_public_key_sha256']
assert verify_digest_signature(load_public_key((case/'case-authority.public.pem').read_bytes()),
                              closure['core_digest'],closure['signature']['value_b64'])
assert closure['core']['source_implementation_sha256']==implementation_sha256()
archive=case/'public-key-verification-evidence.zip'
assert hashlib.sha256(archive.read_bytes()).hexdigest()==closure['core']['verification_evidence_sha256']
z=zipfile.ZipFile(archive)
read=lambda name:json.loads(z.read(name))

counts=Counter()
grid=[0.,.25,.5,.75,1.]
for down,quarantine,trust_weight,trust_risk,stat_risk,gate in product(grid,grid,grid,grid,grid,(False,True)):
    if down>quarantine: continue
    trust=TrustSignal(raw_status='review-example',admissible=gate,risk=trust_risk,
                      evaluated_checks=[],failed_checks=[] if gate else ['veto'],reasons=[])
    statistics=StatisticalSignal(client_id='k',risk=stat_risk,components=[])
    decision=next(d for d in decide_admission_policies(trust=trust,statistics=statistics,
                  statistical_threshold=.5,composite_threshold=quarantine,
                  composite_downweight_threshold=down,trust_weight=trust_weight)
                  if d.policy=='gated_composite')
    risk=trust_weight*trust_risk+(1-trust_weight)*stat_risk
    expected='trust_quarantined' if not gate else 'statistically_quarantined' if risk>quarantine else 'accepted_downweighted' if risk>down else 'accepted'
    assert decision.status==expected
    assert gate or not decision.contributes
    counts['finite_policy_boundary_instances']+=1

def fr(value): return F(int(value['numerator']),int(value['denominator']))

def metric_case(masses,removed,after_masses=None):
    n=len(masses);clients=[f'k{i}' for i in range(n)]
    sids=[f's{i}' for i in range(n)]
    status=lambda m:'accepted' if m>0 else 'statistically_quarantined'
    entries=[{'client_id':clients[i],'submission_id':sids[i],
              'runtime':NS(core=NS(final_status=status(masses[i])))} for i in range(n)]
    dispositions=[NS(client_id=clients[i],kind='runtime_admission',final_status=status(masses[i])) for i in range(n)]
    dispositions.append(NS(client_id='rejected',kind='protocol_rejection',final_status='rejected_conflict'))
    total=sum(masses,F(0))
    old={sids[i]:masses[i]/total for i in range(n)}
    survivors=[i for i in range(n) if i not in removed]
    new_masses={i:masses[i] for i in survivors} if after_masses is None else dict(zip(survivors,after_masses,strict=True))
    remaining=sum(new_masses.values(),F(0))
    new={sids[i]:new_masses[i]/remaining for i in survivors} if remaining else None
    actions={sids[i]:status(new_masses[i]) for i in survivors}
    result=_proposal_metrics(clients+['missing','rejected'],dispositions,entries,
                            {sids[i] for i in removed},old,new,actions)
    assert result['j_any_action_change']==int(bool(removed) or any(status(masses[i])!=actions[sids[i]] for i in survivors))
    assert result['coefficients_before']['missing']=={'numerator':'0','denominator':'1'}
    assert result['actions_before']['rejected']==result['actions_after']['rejected']
    if remaining:
        beta=sum((old[sids[i]] for i in removed),F(0))
        survivor_delta=sum((abs(new[sids[i]]-old[sids[i]]) for i in survivors),F(0))
        delta=fr(result['delta_l1'])
        assert delta==survivor_delta+beta
        assert 2*beta<=delta<=2
        if after_masses is None:
            assert delta==2*beta
            # Exact ideal-arithmetic model identity and its triangle bound.
            u=[F((-1)**i*(i+1)) for i in range(n)]
            model=sum((old[sids[i]]*u[i] for i in range(n)),F(0))
            model_after=sum((new[sids[i]]*u[i] for i in survivors),F(0))
            removed_model=sum((old[sids[i]]*u[i] for i in removed),F(0))
            assert model_after==(model-removed_model)/(1-beta)
            assert model-model_after==sum((old[sids[i]]*(u[i]-model) for i in removed),F(0))/(1-beta)
            assert abs(model-model_after)<=sum((old[sids[i]]*abs(u[i]-model) for i in removed),F(0))/(1-beta)
            counts['ideal_identity_and_bound_instances']+=1
    else:
        assert result['delta_l1'] is None and result['coefficients_after'] is None
        counts['undefined_normalization_instances']+=1
    return result

mass_grid=[F(0),F(1,2),F(1),F(2)]
for n in range(1,5):
    for masses in product(mass_grid,repeat=n):
        if not sum(masses): continue
        for length in range(n+1):
            for chosen in combinations(range(n),length):
                metric_case(masses,set(chosen))
                counts['frozen_metric_instances']+=1
for masses in product(mass_grid,repeat=3):
    if not sum(masses): continue
    for length in (1,2):
        for chosen in combinations(range(3),length):
            for altered in product(mass_grid,repeat=3-length):
                metric_case(masses,set(chosen),altered)
                counts['rescored_mass_vector_instances']+=1

# Actual backend counterexample: coefficient inequality can be hidden by equal updates.
import numpy as np
from flwr.server.strategy.aggregate import aggregate
local=[np.asarray([2.,5.],dtype=np.float32)]
first=aggregate([(local,1.),(local,3.)])
second=aggregate([(local,3.),(local,1.)])
assert first[0].tobytes()==second[0].tobytes()
assert [F(1,4),F(3,4)]!=[F(3,4),F(1,4)]

# Independent topological dynamic programming on (node, exact edge-type set).
graph_data=z.read('graph/manifest.json')
assert hashlib.sha256(graph_data).hexdigest()==closure['core']['graph_manifest_sha256']
graph=json.loads(graph_data)['core']
nodes={n['node_id'] for n in graph['nodes']}
successors=defaultdict(list);degree=dict.fromkeys(nodes,0);edge_set=set()
flags={'num':1,'dec':2,'audit':4}
for edge in graph['edges']:
    a,b,kind=edge['source'],edge['target'],edge['kind']
    assert a in nodes and b in nodes
    successors[a].append((b,flags[kind]));degree[b]+=1;edge_set.add((a,b,kind))
pending=deque(n for n,d in degree.items() if d==0);order=[]
while pending:
    a=pending.popleft();order.append(a)
    for b,_ in successors[a]:
        degree[b]-=1
        if degree[b]==0:pending.append(b)
assert len(order)==len(nodes)
origins={sid:node for r in graph['rounds'] for sid,node in r['submissions'].items()}
cache={}
def distances(sid):
    if sid in cache:return cache[sid]
    result=defaultdict(dict);result[origins[sid]][0]=0
    for a in order:
        for b,flag in successors[a]:
            for mask,length in result[a].items():
                target=mask|flag
                result[b][target]=min(result[b].get(target,len(nodes)+1),length+1)
    result={n:values for n,values in result.items() if values and n!=origins[sid]}
    cache[sid]=result;return result
paths_verified=0
for name in ('analysis/remove-client01-round1-radius.json','analysis/remove-client01-rounds1-3-radius.json','postchecks/zero-weight-radius.json'):
    radius=read(name)
    selected=radius.get('selected_submission_ids',[radius.get('submission_id')])
    assert {n['node_id'] for n in radius['reachable']}==set().union(*(set(distances(sid)) for sid in selected))
    for node in radius['reachable']:
        found=set()
        for path in node['paths']:
            sid=path.get('origin_submission_id',radius.get('submission_id'))
            assert sid in selected and path['nodes'][0]==origins[sid] and path['nodes'][-1]==node['node_id']
            assert len(path['edge_kinds'])==len(path['nodes'])-1
            mask=0
            for a,b,kind in zip(path['nodes'][:-1],path['nodes'][1:],path['edge_kinds'],strict=True):
                assert (a,b,kind) in edge_set;mask|=flags[kind]
            assert len(path['edge_kinds'])==distances(sid)[node['node_id']][mask]
            expected='documentary_dependency' if mask&4 else 'decision_dependency' if mask&2 else 'numerical_dependency'
            assert path['category']==expected and (sid,mask) not in found
            found.add((sid,mask));paths_verified+=1
        assert found=={(sid,mask) for sid in selected for mask in distances(sid).get(node['node_id'],{})}
    assert radius['numerical_effect_demonstrated'] is False
    counts['sealed_radius_reports_verified']+=1

real_metrics=[]
for directory in ('counterfactuals/frozen_decisions','counterfactuals/rescore_round',
                  'postchecks/zero-weight-counterfactuals/frozen_decisions','postchecks/zero-weight-counterfactuals/rescore_round'):
    analysis=read(directory+'/analysis.json');p=analysis['proposal_metrics']
    real_metrics.append({'artifact':directory,'mode':analysis['mode'],'delta_K':p['delta_l1'],
                         'J_K':p['j_any_action_change'],'J_survivors':int(bool(analysis['survivor_action_changes'])),
                         'model_bytes_equal':analysis['model_bytes_equal'],
                         'additional_coefficient_l1_delta_from_rescoring':analysis['additional_coefficient_l1_delta_from_rescoring']})
    assert p['j_any_action_change']==1
    assert fr(p['delta_l1'])==sum((abs(fr(p['coefficients_after'][k])-fr(p['coefficients_before'][k])) for k in p['expected_client_ids']),F(0))
    counts['sealed_counterfactual_metric_reports_checked']+=1
summary={'status':'passed','method':'finite exact-arithmetic examples, real policy calls, independent DAG dynamic programming, and authenticated retained artifacts',
         'machine_checked_universal_proof':False,'implementation_sha256':implementation_sha256(),
         'sealed_case_closure_sha256':hashlib.sha256(closure_data).hexdigest(),'counts':dict(counts),
         'shortest_typed_witnesses_verified':paths_verified,'source_graph_nodes':len(nodes),
         'equal_local_models_hide_changed_coefficients_in_real_flower_backend':True,'retained_counterfactual_metrics':real_metrics}
(out/'obligation-checks.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
