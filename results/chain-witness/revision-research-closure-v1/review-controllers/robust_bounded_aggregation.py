"""Replayable smoothed geometric-median weighting of bounded tensor deltas.

This is a separately named aggregation adaptation, not a malicious-client
classifier. Its final convex coefficients differ from the input sample masses.
The old fixed-coefficient removal bound applies only when these coefficients
are frozen; recomputing the robust weights is a different intervention.
"""
from fractions import Fraction
import math

import numpy as np

from .bounded_aggregation import aggregate_bounded, digest, record

PROFILE = 'robust-bounded-geometric-median-v1'


def aggregate_robust_bounded(base,updates,*,masses,mandatory_gates,limits,reference_digest,
                             minimum_contributors=8,max_iterations=50):
    if type(max_iterations) is not int or not 1 <= max_iterations <= 500:
        raise ValueError('invalid geometric-median iteration cap')
    initial, bounded = aggregate_bounded(base,updates,masses=masses,mandatory_gates=mandatory_gates,
        limits=limits,reference_digest=reference_digest,minimum_contributors=minimum_contributors)
    if initial is None:
        core={'profile':PROFILE,'input_bounded_derivation':bounded,'quorum_satisfied':False,
              'parameters_digest':None,'final_coefficients':{c:'0' for c in sorted(updates)}}
        return None,{**core,'derivation_digest':digest(core)}
    clients=[c for c in sorted(updates) if Fraction(bounded['contributions'][c]['effective_mass']) > 0]
    values=[]
    for c in clients:
        tensors=bounded['contributions'][c]['derived_float64_delta']
        values.append(np.concatenate([np.asarray(t['values'],dtype=np.float64).ravel() for t in tensors]))
    matrix=np.stack(values)
    weight=np.asarray([float(Fraction(bounded['contributions'][c]['normalized_weight'])) for c in clients])
    weight=weight/weight.sum()
    center=np.sum(matrix*weight[:,None],axis=0)
    smoothing=max(1e-8,1e-6*float(np.median(np.linalg.norm(matrix,axis=1))))
    converged=False
    trace=[]
    for iteration in range(max_iterations):
        distances=np.linalg.norm(matrix-center,axis=1)
        proposal=weight/np.sqrt(distances**2+smoothing**2)
        proposal=proposal/proposal.sum()
        updated=np.sum(matrix*proposal[:,None],axis=0)
        step=float(np.linalg.norm(updated-center))
        trace.append(step)
        center=updated
        if step <= 1e-8*max(1.,float(np.linalg.norm(center))):
            converged=True
            break
    # The finite last iterate is the declared operator even if not converged.
    final_masses={c:repr(float(proposal[clients.index(c)])) if c in clients else '0' for c in sorted(updates)}
    parameters, derived=aggregate_bounded(base,updates,masses=final_masses,mandatory_gates=mandatory_gates,
        limits=limits,reference_digest=reference_digest,minimum_contributors=minimum_contributors)
    if parameters is None or not all(np.isfinite(a).all() for a in parameters):
        raise ValueError('invalid robust bounded output')
    final={c:derived['contributions'][c]['normalized_weight'] for c in sorted(updates)}
    core={'profile':PROFILE,'input_bounded_derivation':bounded,'final_bounded_derivation':derived,
          'quorum_satisfied':True,'final_coefficients':final,'smoothing':smoothing,
          'max_iterations':max_iterations,'iterations':len(trace),'converged':converged,
          'iterate_step_norms':trace,'parameters_digest':digest(record(parameters)),
          'scope':'Finite deterministic convex reweighting of clipped deltas. No semantic malice, general ASR or dynamic-reweighting removal guarantee.'}
    return parameters,{**core,'derivation_digest':digest(core)}


def verify_robust_bounded(base,updates,report,**kwargs):
    parameters,expected=aggregate_robust_bounded(base,updates,**kwargs)
    if report != expected:
        raise ValueError('robust bounded derivation does not reconstruct')
    return parameters
