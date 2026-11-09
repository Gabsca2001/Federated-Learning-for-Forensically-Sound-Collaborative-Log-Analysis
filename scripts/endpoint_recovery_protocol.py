"""Explicit Byzantine endpoint families with a measured relative-radius variant."""
import numpy as np

def whole_norm(delta):return float(np.linalg.norm(np.concatenate([a.ravel() for a in delta])))

def forged_delta(clean,poisoned,alpha,family):
    if family not in ('unrestricted','relative-radius'):raise ValueError('unknown attacker family')
    if alpha not in (0.,.125,.5,1.,2.,4.):raise ValueError('changed query factors')
    if len(clean)!=len(poisoned) or any(a.shape!=b.shape for a,b in zip(clean,poisoned,strict=True)):
        raise ValueError('changed tensor schema')
    if any(not np.isfinite(a).all() for a in [*clean,*poisoned]):raise ValueError('nonfinite update')
    direction=[b-a for a,b in zip(clean,poisoned,strict=True)]
    direction_norm=whole_norm(direction);clean_norm=whole_norm(clean)
    scale=1. if family=='unrestricted' else clean_norm/direction_norm if direction_norm else 0.
    result=[a+alpha*scale*d for a,d in zip(clean,direction,strict=True)] if alpha else [a.copy() for a in clean]
    norm=whole_norm(result)
    if family=='relative-radius' and norm>(1+alpha)*clean_norm*(1+1e-12):raise ValueError('relative norm budget violated')
    return result,dict(family=family,alpha=alpha,clean_norm=clean_norm,submitted_norm=norm,
        perturbation_norm=alpha*scale*direction_norm,relative_bound=(1+alpha)*clean_norm if family=='relative-radius' else None)
