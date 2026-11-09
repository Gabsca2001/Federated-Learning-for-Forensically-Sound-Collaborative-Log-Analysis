"""Opt-in authorization of sample-weighted FedAvg; never restore rejected mass.

This research guard is independent of tensor clipping and of semantic labels.
The caller must authenticate the eligible roster, counts, trust and decisions.
Assessment authorizes or defers aggregation; it does not create a checkpoint.
"""
from __future__ import annotations
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json

PROFILE='fedavg-admission-mass-safety-v1'
STATUSES={'accepted','accepted_downweighted','statistically_quarantined','trust_quarantined'}


def exact(value):
    if isinstance(value,bool) or not isinstance(value,(str,int,Fraction)):
        raise ValueError('mass and policy ratios must be exact integers or rationals')
    try:return Fraction(value)
    except (ValueError,ZeroDivisionError) as exc:raise ValueError('invalid exact ratio') from exc


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class MassSafetyPolicy:
    minimum_contributors:int=10
    minimum_retained_mass:Fraction=Fraction(4,5)
    maximum_group_size:int=3
    maximum_group_share:Fraction=Fraction(1,3)
    downweight_factor:Fraction=Fraction(1,2)

    def __post_init__(self):
        for name in ('minimum_contributors','maximum_group_size'):
            if type(getattr(self,name)) is not int or getattr(self,name)<1:raise ValueError('invalid positive policy count')
        for name in ('minimum_retained_mass','maximum_group_share','downweight_factor'):
            value=exact(getattr(self,name))
            if not 0<value<=1:raise ValueError('policy fraction outside (0,1]')
            object.__setattr__(self,name,value)

    def record(self):
        return dict(profile=PROFILE,minimum_contributors=self.minimum_contributors,
            minimum_retained_mass=str(self.minimum_retained_mass),maximum_group_size=self.maximum_group_size,
            maximum_group_share=str(self.maximum_group_share),downweight_factor=str(self.downweight_factor))


def assess_mass_safety(*,nominal_counts,effective_masses,mandatory_gates,statuses,policy):
    """Check actual proposed masses on a complete predecision eligible roster.

    Largest-weight IDs are an extremal numerical subset, NOT detected attackers.
    The cap applies to any at-most-k subset only under the stated identity bound.
    Deferred rounds have no authorized coefficients, even with positive proposals.
    """
    if not isinstance(policy,MassSafetyPolicy):raise ValueError('explicit mass policy required')
    clients=sorted(nominal_counts)
    if not clients or any(not isinstance(c,str) or not c for c in clients):raise ValueError('invalid eligible roster')
    if any(set(x)!=set(clients) for x in (effective_masses,mandatory_gates,statuses)):
        raise ValueError('incomplete or substituted eligible roster')
    if any(type(nominal_counts[c]) is not int or nominal_counts[c]<=0 for c in clients):
        raise ValueError('counts must be positive authenticated integers')
    masses={c:exact(effective_masses[c]) for c in clients}
    for c in clients:
        if type(mandatory_gates[c]) is not bool or statuses[c] not in STATUSES:raise ValueError('invalid trust or action')
        if masses[c]<0:raise ValueError('negative effective mass')
        if not mandatory_gates[c] and statuses[c]!='trust_quarantined':raise ValueError('mandatory veto/action mismatch')
        factor=(Fraction(1) if statuses[c]=='accepted' else policy.downweight_factor
                if statuses[c]=='accepted_downweighted' else Fraction(0))
        if masses[c]!=nominal_counts[c]*factor:raise ValueError('mass/action/count mismatch')
        if not mandatory_gates[c] and masses[c]!=0:raise ValueError('mandatory veto bypass')
    nominal=sum(nominal_counts.values());total=sum(masses.values(),Fraction(0))
    coefficients={c:masses[c]/total for c in clients} if total else None
    ordered=sorted(clients,key=lambda c:(-coefficients[c],c)) if coefficients else []
    largest=ordered[:policy.maximum_group_size]
    group=sum((coefficients[c] for c in largest),Fraction(0)) if coefficients else None
    contributors=sum(masses[c]>0 for c in clients);retained=total/nominal
    reasons=[]
    if contributors<policy.minimum_contributors:reasons.append('insufficient_contributors')
    if total==0:reasons.append('zero_effective_mass')
    if retained<policy.minimum_retained_mass:reasons.append('insufficient_retained_mass')
    if group is not None and group>policy.maximum_group_share:reasons.append('excessive_group_share')
    inputs=dict(nominal_counts={c:nominal_counts[c] for c in clients},effective_masses={c:str(masses[c]) for c in clients},
                mandatory_gates={c:mandatory_gates[c] for c in clients},statuses={c:statuses[c] for c in clients})
    core=dict(profile=PROFILE,policy=policy.record(),policy_sha256=digest(policy.record()),input_sha256=digest(inputs),
        eligible_clients=clients,contributing_clients=contributors,nominal_mass=str(nominal),effective_mass=str(total),
        retained_mass_fraction=str(retained),largest_weight_subset=largest,
        maximum_at_most_k_share=str(group) if group is not None else None,
        proposed_coefficients={c:str(coefficients[c]) for c in clients} if coefficients else None,
        aggregation_authorized=not reasons,decision='defer' if reasons else 'ready',reasons=reasons,
        authorized_coefficients={c:str(coefficients[c]) for c in clients} if not reasons else None,
        scope='Bound authenticated original FedAvg mass, not semantic malice, ASR, robust beta or later causal influence.')
    return {**core,'assessment_sha256':digest(core)}


def verify_mass_safety(report,**inputs):
    expected=assess_mass_safety(**inputs)
    if report!=expected:raise ValueError('mass safety assessment does not reconstruct')
    return expected['aggregation_authorized']


def guarded_aggregation(aggregate,**inputs):
    """Call the numerical backend only after authorization, with exact weights."""
    report=assess_mass_safety(**inputs)
    if not report['aggregation_authorized']:return None,report
    result=aggregate({c:Fraction(v) for c,v in report['authorized_coefficients'].items()})
    if result is None:raise ValueError('authorized numerical backend returned no checkpoint')
    return result,report
