"""Research-only subnormalized delta blending with explicit checkpoint retention.

Callers authenticate inputs and establish admission/quorum before using this
numerical helper. Its coefficients concern the whole step including the old
checkpoint, not client-only renormalized influence. It is not an admission gate.
"""
from fractions import Fraction
import numpy as np

def exact(value):
    if isinstance(value,bool):raise ValueError('boolean coefficient')
    return Fraction(str(value))

def coefficient_variants(proposal,cap=Fraction(1,9)):
    cap=exact(cap)
    if not 0<cap<=1:raise ValueError('invalid cap')
    if not proposal or any(not isinstance(i,str) or not i for i in proposal):raise ValueError('invalid roster')
    values={i:exact(v) for i,v in sorted(proposal.items())}
    if any(v<0 for v in values.values()) or sum(values.values())<=0:raise ValueError('invalid proposal')
    total=sum(values.values());prior={i:v/total for i,v in values.items()}
    cut={i:min(v,cap) for i,v in prior.items()}
    step=sum(cut.values());matched={i:step*v for i,v in prior.items()}
    assert 0<step<=1 and all(cut[i]<=prior[i] for i in prior)
    assert sum(cut.values())==sum(matched.values())==step
    return prior,cut,matched,1-step

def blend_clipped_deltas(base,clipped,coefficients,mandatory_gates):
    """Compute base + sum(beta_i*clipped_delta_i), without renormalizing beta."""
    clients=sorted(clipped)
    if not clients or set(coefficients)!=set(clients) or set(mandatory_gates)!=set(clients):
        raise ValueError('inconsistent roster')
    beta={i:exact(coefficients[i]) for i in clients}
    if any(v<0 for v in beta.values()) or sum(beta.values())>1:raise ValueError('invalid step mass')
    if any(type(mandatory_gates[i]) is not bool for i in clients):raise ValueError('invalid mandatory gate')
    if any(beta[i] and not mandatory_gates[i] for i in clients):raise ValueError('positive coefficient after veto')
    base=[np.asarray(a,dtype=np.float64) for a in base]
    if not base or any(a.size==0 or not np.isfinite(a).all() for a in base):raise ValueError('invalid base')
    local={i:[np.asarray(a,dtype=np.float64) for a in clipped[i]] for i in clients}
    for tensors in local.values():
        if len(tensors)!=len(base) or any(a.shape!=b.shape or not np.isfinite(a).all() for a,b in zip(tensors,base,strict=True)):
            raise ValueError('invalid clipped tensor schema')
    result=[a+sum((float(beta[i])*local[i][k] for i in clients),np.zeros_like(a)) for k,a in enumerate(base)]
    if not all(np.isfinite(a).all() for a in result):raise ValueError('nonfinite blend')
    return result
