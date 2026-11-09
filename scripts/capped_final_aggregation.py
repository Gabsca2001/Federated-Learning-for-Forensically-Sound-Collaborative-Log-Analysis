"""Explicit final-coefficient projection, separate from admission mass.

Original tensors and admission masses are never relabelled or restored. The
new operator clips deltas, obtains sample or finite robust proposals, projects
their coefficients, and records the actual final convex combination. It is a
separate research profile, not ordinary FedAvg or a semantic client classifier.
"""
from __future__ import annotations
from fractions import Fraction
import numpy as np
from admission_mass_safety import exact
from fl_forensics.bounded_aggregation import aggregate_bounded,digest,record,arrays
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded

PROFILE='capped-final-bounded-aggregation-v1'


def project_coefficients(weights,*,cap):
    """Exact water filling beta_i=min(cap,lambda*p_i), preserving zero support."""
    cap=exact(cap)
    if not 0<cap<=1:raise ValueError('coefficient cap outside (0,1]')
    if not weights or any(not isinstance(i,str) or not i for i in weights):raise ValueError('invalid coefficient roster')
    weights={i:exact(v) for i,v in weights.items()}
    if any(v<0 for v in weights.values()):raise ValueError('negative proposal')
    total=sum(weights.values(),Fraction());positive={i for i,v in weights.items() if v>0}
    if total==0 or len(positive)*cap<1:raise ValueError('positive support cannot carry capped simplex')
    prior={i:v/total for i,v in weights.items()};final={i:Fraction() for i in weights};free=set(positive)
    remaining=Fraction(1);saturated=[];scale=None
    while free:
        subtotal=sum(prior[i] for i in free)
        scale=remaining/subtotal
        above={i for i in free if scale*prior[i]>cap}
        if not above:
            for i in free:final[i]=scale*prior[i]
            break
        for i in sorted(above):final[i]=cap;saturated.append(i)
        remaining-=len(above)*cap;free-=above
    assert sum(final.values())==1 and all(0<=v<=cap for v in final.values())
    assert all(final[i]==0 for i,v in prior.items() if v==0)
    report=dict(cap=str(cap),normalized_proposal={i:str(prior[i]) for i in sorted(prior)},
        final_coefficients={i:str(final[i]) for i in sorted(final)},saturated=sorted(saturated),
        free_scale=str(scale),proposal_total_variation=str(sum(abs(final[i]-prior[i]) for i in prior)/2))
    return final,report


def aggregate_capped_final(base,updates,*,nominal_counts,masses,mandatory_gates,limits,reference_digest,
        proposal='robust',minimum_contributors=10,minimum_retained_mass=Fraction(4,5),
        maximum_group_size=3,maximum_group_share=Fraction(1,3),max_iterations=50):
    if proposal not in ('sample','robust'):raise ValueError('unknown coefficient proposal')
    clients=sorted(updates)
    if not clients or any(set(v)!=set(clients) for v in (nominal_counts,masses,mandatory_gates)):
        raise ValueError('incomplete original roster')
    if type(maximum_group_size) is not int or maximum_group_size<1:raise ValueError('invalid group size')
    if type(minimum_contributors) is not int or minimum_contributors<1:raise ValueError('invalid quorum')
    floor=exact(minimum_retained_mass);budget=exact(maximum_group_share)
    if not 0<floor<=1 or not 0<budget<=1:raise ValueError('invalid mass or group budget')
    if any(type(nominal_counts[i]) is not int or nominal_counts[i]<=0 for i in clients):raise ValueError('invalid bound counts')
    if any(type(mandatory_gates[i]) is not bool for i in clients):raise ValueError('invalid mandatory gate')
    original={i:exact(masses[i]) for i in clients}
    if any(not 0<=original[i]<=nominal_counts[i] for i in clients):raise ValueError('admission mass outside bound count')
    effective={i:original[i] if mandatory_gates[i] else Fraction() for i in clients}
    total=sum(effective.values());retained=total/sum(nominal_counts.values())
    alpha={i:effective[i]/total for i in clients} if total else None
    cap=budget/maximum_group_size
    policy=dict(proposal=proposal,minimum_contributors=minimum_contributors,minimum_retained_mass=str(floor),
        maximum_group_size=maximum_group_size,maximum_group_share=str(budget),individual_cap=str(cap),max_iterations=max_iterations)
    admission=dict(nominal_counts={i:nominal_counts[i] for i in clients},input_masses={i:str(original[i]) for i in clients},
        effective_masses={i:str(effective[i]) for i in clients},mandatory_gates={i:mandatory_gates[i] for i in clients},
        retained_nominal_mass=str(retained),alpha={i:str(alpha[i]) for i in clients} if alpha else None)
    reasons=[]
    if sum(v>0 for v in effective.values())<minimum_contributors:reasons.append('insufficient_contributors')
    if retained<floor:reasons.append('insufficient_admission_mass')
    if sum(v>0 for v in effective.values())*cap<1:reasons.append('infeasible_positive_support')
    common=dict(profile=PROFILE,policy=policy,admission=admission,base_digest=digest(record(arrays(base))),
        reference_digest=reference_digest,limits=[float(v) for v in limits])
    if reasons:
        core={**common,'defined':False,'reasons':reasons,'beta':None,'pre_export_parameters_digest':None}
        return None,{**core,'derivation_digest':digest(core)}
    arguments=dict(masses={i:str(effective[i]) for i in clients},mandatory_gates=mandatory_gates,
        limits=limits,reference_digest=reference_digest,minimum_contributors=minimum_contributors)
    robust_details=None
    if proposal=='robust':
        _,parent=aggregate_robust_bounded(base,updates,**arguments,max_iterations=max_iterations)
        if not parent['quorum_satisfied']:raise ValueError('robust proposal unexpectedly undefined')
        proposed=parent['final_coefficients']
        robust_details={k:parent[k] for k in ('smoothing','max_iterations','iterations','converged','iterate_step_norms')}
        robust_details['parent_derivation_digest']=parent['derivation_digest']
    else:proposed={i:str(alpha[i]) for i in clients}
    beta,projection=project_coefficients(proposed,cap=cap)
    parameters,derived=aggregate_bounded(base,updates,masses={i:str(beta[i]) for i in clients},
        mandatory_gates=mandatory_gates,limits=limits,reference_digest=reference_digest,minimum_contributors=minimum_contributors)
    if parameters is None:raise ValueError('projected positive support lost quorum')
    actual_beta={i:Fraction(derived['contributions'][i]['normalized_weight']) for i in clients}
    assert actual_beta==beta and all(beta[i]==0 for i in clients if effective[i]==0)
    worst=sum(sorted(beta.values(),reverse=True)[:maximum_group_size])
    assert worst<=budget
    core={**common,'defined':True,'reasons':[],
        'beta':{i:str(beta[i]) for i in clients},'projection':projection,'robust_proposal':robust_details,
        'maximum_at_most_k_beta_share':str(worst),
        'alpha_beta_total_variation':str(sum(abs(beta[i]-alpha[i]) for i in clients)/2),
        'final_bounded_derivation':derived,'pre_export_parameters_digest':digest(record(parameters)),
        'scope':'Admission retention describes original accepted counts; beta changes their relative numerical importance. No original FedAvg identity, semantic malice or ASR guarantee is asserted.'}
    return parameters,{**core,'derivation_digest':digest(core)}


def verify_capped_final(base,updates,report,**kwargs):
    result,expected=aggregate_capped_final(base,updates,**kwargs)
    if expected!=report:raise ValueError('capped final derivation does not reconstruct')
    return result
