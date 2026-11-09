"""Research-only candidate selection and explicit late-removal accounting."""
from itertools import combinations
import hashlib, json
from coherent_gradient_protocol import assess_round, verify_round
from fl_forensics.group_calibration_v2 import detect_conditioned_groups
from fl_forensics.group_calibration_v3 import detect_tree_groups


def group_key(group):
    return hashlib.sha256(json.dumps(sorted(group),separators=(',',':')).encode()).hexdigest()[:20]


def select_groups(rounds, reference, calibration_v2, calibration_v3):
    """No identity truth, attack outcome or future frame enters this function."""
    v2=detect_conditioned_groups(rounds,reference,calibration_v2)
    scores={tuple(p['clients']):p['conditioned_score'] for p in v2['pairs']}
    ranked=sorted(v2['candidate_groups'],key=lambda g:(
        -min(scores[tuple(p)] for p in combinations(sorted(g),2)),tuple(g)))
    feasible=[g for g in ranked if len(rounds[0]['client_ids'])-len(g)>=10]
    v2['selected_group']=feasible[0] if feasible else []
    v3=detect_tree_groups(rounds,reference,calibration_v3,minimum_survivors=10)
    return {'v2':v2,'v3':v3}


def removal_plan(selected, clients, counts, attackers):
    """Called only after selection closes. Truth labels controls and oracle only."""
    clients=sorted(clients);truth=set(attackers);benign=sorted(set(clients)-truth)
    if not truth<=set(clients) or set(counts)!=set(clients):raise ValueError('invalid population')
    requested={():{'roles':['no-removal']}};comparisons=[]
    groups=[(name,list(selected[name])) for name in ('v2','v3')]
    if attackers:groups.append(('oracle-diagnostic',sorted(truth)))
    for method,group in groups:
        if not group:continue
        if len(set(group))!=len(group) or not set(group)<=set(clients):raise ValueError('invalid selected group')
        if len(clients)-len(group)<10:raise ValueError('selected group violates quorum')
        joint=tuple(sorted(group))
        requested.setdefault(joint,{'roles':[]})['roles'].append(method+'-joint')
        for c in group:requested.setdefault((c,),{'roles':[]})['roles'].append(method+'-individual')
        controls=list(combinations(benign,len(group)))
        if not controls:raise ValueError('no size-matched benign controls')
        mass=sum(counts[c] for c in group)
        matched=min(controls,key=lambda g:(abs(sum(counts[c] for c in g)-mass),group_key(g)))
        ranked=sorted(controls,key=group_key)[:5]
        for g in sorted(set(ranked+[matched])):
            requested.setdefault(g,{'roles':[]})['roles'].append(method+'-benign-control')
        requested[matched]['roles'].append(method+'-mass-matched-control')
        comparisons.append(dict(method=method,group=sorted(group),hash_controls=[list(g) for g in ranked],
            mass_matched_control=list(matched),group_sample_count=mass,
            control_sample_count=sum(counts[c] for c in matched)))
    return {'removals':[dict(removed=list(g),key=group_key(g),**meta) for g,meta in sorted(requested.items())],
            'comparisons':comparisons,'controls_selected_without_effects':True}


def remove_and_aggregate(base, updates, context, removed):
    """Same-parent reaggregation; never reuse this as a future-training replay."""
    if len(set(removed))!=len(removed) or not set(removed)<=set(context['roster']):
        raise ValueError('invalid removal set')
    if context['method']!='coherent_fedavg':raise ValueError('this intervention requires its declared raw operator')
    kept={c:u for c,u in updates.items() if c not in removed}
    params,event=assess_round(base,kept,None,context)
    verify_round(base,kept,None,context,event)
    return params,event
