"""Post-hoc frozen V2/V3 comparison using identical retained pair descriptors.

The adapter must reproduce every published predecessor selection before use.
"""
from itertools import combinations
import copy
from fl_forensics.group_calibration_v2 import _maximal_cliques
from fl_forensics.group_calibration_v3 import candidate_scores

def select_from_pairs(raw_pairs,reference,c2,c3,clients):
    pairs=copy.deepcopy(raw_pairs)
    for pair in pairs:
        channels=reference['references'][','.join(pair['clients'])]
        increases={name:max(0.,(pair[name]-v['center'])/v['scale'])
            for name,v in channels.items() if pair[name] is not None}
        pair['conditioned_score']=max(increases.values()) if increases else None
    scores={tuple(p['clients']):p['conditioned_score'] for p in pairs}
    edges=[p['clients'] for p in pairs if p['conditioned_score'] is not None and p['conditioned_score']>c2['threshold']]
    groups=_maximal_cliques(clients,edges)
    feasible=[g for g in groups if len(clients)-len(g)>=10]
    ranked=sorted(feasible,key=lambda g:(-min(scores[tuple(p)] for p in combinations(sorted(g),2)),tuple(g)))
    v2=ranked[0] if ranked else []
    candidates=[]
    for g in candidate_scores(pairs):
        threshold=c3['families'][str(g['size'])]['threshold']
        if g['score']>threshold:candidates.append({**g,'ratio':g['score']/max(threshold,.05)})
    candidates.sort(key=lambda g:(-g['size'],-g['ratio'],tuple(g['clients'])))
    feasible=[g for g in candidates if len(clients)-g['size']>=10]
    return dict(v2=v2,v3=feasible[0]['clients'] if feasible else [])
