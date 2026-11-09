"""FLTrust numerical rule on endpoint deltas; research-only transfer helper.

Positive cosine scores are normalized WITHOUT sample-count weights. Each local
delta is normalized to the server-reference norm over the entire parameter
vector. Input authentication, reference provenance and admission are caller
obligations. Undefined references/scores fail explicitly, without a fallback.
"""
import numpy as np

def tensors(value):
    result=[np.asarray(a,dtype=np.float64) for a in value]
    if not result or any(a.size==0 or not np.isfinite(a).all() for a in result):raise ValueError('invalid tensors')
    return result

def fltrust_delta(local_deltas,root_delta,mandatory_gates):
    clients=sorted(local_deltas)
    if not clients or set(clients)!=set(mandatory_gates):raise ValueError('inconsistent roster')
    if any(type(mandatory_gates[c]) is not bool for c in clients):raise ValueError('invalid gate')
    root=tensors(root_delta);shape=[a.shape for a in root];rv=np.concatenate([a.ravel() for a in root])
    root_norm=float(np.linalg.norm(rv))
    if not np.isfinite(root_norm) or root_norm==0:raise ValueError('zero or invalid root reference')
    values={};norms={};cosines={};scores={}
    for c in clients:
        values[c]=tensors(local_deltas[c])
        if [a.shape for a in values[c]]!=shape:raise ValueError('changed tensor schema')
        v=np.concatenate([a.ravel() for a in values[c]]);norm=float(np.linalg.norm(v));norms[c]=norm
        if not np.isfinite(norm):raise ValueError('invalid delta norm')
        cosine=float(np.dot(v/norm,rv/root_norm)) if norm else 0.
        cosine=float(np.clip(cosine,-1.,1.));cosines[c]=cosine
        scores[c]=max(0.,cosine) if mandatory_gates[c] and norm else 0.
    total=sum(scores.values())
    if total==0:raise ValueError('no positive aligned eligible updates')
    weights={c:scores[c]/total for c in clients}
    scales={c:root_norm/norms[c] if scores[c]>0 else 0. for c in clients}
    result=[sum((values[c][k]*(weights[c]*scales[c]) for c in clients),np.zeros_like(a)) for k,a in enumerate(root)]
    aggregate_norm=float(np.linalg.norm(np.concatenate([a.ravel() for a in result])))
    if not np.isfinite(aggregate_norm) or aggregate_norm>root_norm*(1+1e-12):raise ValueError('invalid normalized aggregate')
    return result,{'root_norm':root_norm,'local_norms':norms,'cosines':cosines,'scores':scores,
        'score_sum':total,'normalized_scores':weights,'norm_scales':scales,
        'effective_raw_delta_coefficients':{c:weights[c]*scales[c] for c in clients},
        'positive_contributors':sum(s>0 for s in scores.values()),'aggregate_norm':aggregate_norm,
        'coefficient_scope':'Scores sum to one on normalized local deltas. Effective coefficients on original deltas need not sum to one and are not FedAvg sample masses.'}

def norm_matched_delta(delta,target_norm):
    delta=tensors(delta)
    if not np.isfinite(target_norm) or target_norm<0:raise ValueError('invalid target norm')
    norm=float(np.linalg.norm(np.concatenate([a.ravel() for a in delta])))
    if norm==0 and target_norm:raise ValueError('cannot norm-match a zero direction')
    scale=target_norm/norm if norm else 0.
    return [a*scale for a in delta],scale
