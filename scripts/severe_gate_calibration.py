"""Non-compensatory clean-calibrated tails; a separate admission research profile.

Uncapped adverse deviations are log-scaled and normalized per indicator using
clean calibration tails. Their maximum is monotone in each component: normal
components cannot cancel another component's severe alarm. Empirical calibration
budgets are not future false-positive guarantees or maliciousness probabilities.
"""
from __future__ import annotations
import math
from collections import defaultdict
import clean_gate_calibration as legacy
from fl_forensics.composite_admission_models import StatisticalSignal

NAMES=legacy.NAMES
DIRECTIONS=legacy.DIRECTIONS
stage=legacy.stage
size_bucket=legacy.size_bucket
clean_record=legacy.clean_record
empirical_quantile=legacy.empirical_quantile
budget_summary=legacy.budget_summary
CANDIDATES={
    'max_tail':dict(conditioned=True,quarantine_quantile='0.975',downweight_quantile='0.90'),
    'max_tail_conservative':dict(conditioned=True,quarantine_quantile='0.99',downweight_quantile='0.95'),
}


def bounded(value):
    legacy.require(math.isfinite(value) and value>=0,'invalid maximum tail severity')
    return value/(1+value)


def fit_references(records,candidate):
    legacy.require(candidate in CANDIDATES,'unknown severe-tail candidate')
    bank=legacy.fit_references(records,'conditioned')
    return dict(profile='noncompensatory-log-tail-gate-v1',candidate=candidate,settings=CANDIDATES[candidate],
        references=bank['references'],reference_resolution=bank['reference_resolution'],
        relative_scale_floor=1e-9,component_tail_quantile='0.95',component_limits=None,thresholds=None,
        fusion='max(log(1+adverse/robust_scale)/clean_component_tail_limit)',
        bounded_display='M/(1+M); monotone map, not a probability',
        scope='Conditioned clean empirical calibration. No automatic semantic label or hardware appraisal.')


def log_components(model,cohort,number,examples,cohort_median,indicators):
    legacy.require(set(indicators)==set(NAMES),'indicator schema mismatch')
    key=legacy.group_key(cohort,number,examples,cohort_median,True)
    legacy.require(key in model['reference_resolution'],'unsupported severe-tail reference')
    selected=model['reference_resolution'][key];details={}
    for name in NAMES:
        raw=indicators[name];reference=model['references'][selected][name]
        legacy.require(isinstance(raw,(int,float)) and not isinstance(raw,bool) and math.isfinite(raw),'nonfinite indicator')
        mu=reference['median'];mad=reference['mad']
        scale=max(1.4826*mad,model['relative_scale_floor']*max(1.,abs(mu)))
        deviation=max(0.,raw-mu if reference['direction']=='higher' else mu-raw)
        legacy.require(math.isfinite(deviation) and math.isfinite(scale) and scale>0,'invalid adverse deviation')
        if deviation==0:severity=0.
        else:
            ratio_log=math.log(deviation)-math.log(scale)
            severity=ratio_log+math.log1p(math.exp(-ratio_log)) if ratio_log>50 else math.log1p(math.exp(ratio_log))
        details[name]=dict(raw_value=float(raw),reference_median=mu,reference_mad=mad,
                          robust_scale=scale,adverse_deviation=deviation,log_severity=severity)
    return details,selected


def diagnostics(model,cohort,number,examples,cohort_median,indicators):
    details,selected=log_components(model,cohort,number,examples,cohort_median,indicators)
    legacy.require(model['component_limits'] is not None,'uncalibrated component limits')
    for name,value in details.items():
        denominator=model['component_limits'][cohort][name]
        legacy.require(math.isfinite(denominator) and denominator>=1,'invalid clean tail normalizer')
        value['clean_tail_normalizer']=denominator
        value['normalized_severity']=value['log_severity']/denominator
    maximum=max(v['normalized_severity'] for v in details.values())
    return dict(reference_profile=selected,components=details,maximum_severity=maximum,
                bounded_risk=bounded(maximum),active_indicators=[n for n in NAMES if details[n]['normalized_severity']==maximum])


def score(model,cohort,number,examples,cohort_median,indicators,client_id):
    if model['profile']=='clean-reference-gated-admission-v1':
        return legacy.score(model,cohort,number,examples,cohort_median,indicators,client_id)
    result=diagnostics(model,cohort,number,examples,cohort_median,indicators)
    # The original additive component schema is deliberately not reused to
    # describe a maximum. Full per-indicator tail details are stored separately
    # by the controller; only the bounded risk enters the unchanged gate API.
    return StatisticalSignal(client_id=client_id,risk=result['bounded_risk'],components=[]),result['reference_profile']


def fit_thresholds(model,records):
    populations=defaultdict(list)
    for record in map(clean_record,records):
        logs,_=log_components(model,record['cohort'],record['round'],record['examples'],record['cohort_median'],record['indicators'])
        populations[record['cohort']].append((logs,record['examples']))
    limits={};thresholds={}
    for cohort in ('iid','non-iid'):
        population=populations[cohort];legacy.require(len(population)>=100,'insufficient clean tail population')
        weights=[n for _,n in population];limits[cohort]={}
        for name in NAMES:
            values=[r[name]['log_severity'] for r,_ in population]
            limits[cohort][name]=max(1.,empirical_quantile(values,[1]*len(values),model['component_tail_quantile']),
                                        empirical_quantile(values,weights,model['component_tail_quantile']))
        maxima=[max(r[n]['log_severity']/limits[cohort][n] for n in NAMES) for r,_ in population]
        def cut(q):return max(empirical_quantile(maxima,[1]*len(maxima),q),empirical_quantile(maxima,weights,q))
        q=cut(model['settings']['quarantine_quantile']);d=min(q,cut(model['settings']['downweight_quantile']))
        thresholds[cohort]=dict(statistical_threshold=bounded(q),composite_threshold=bounded(q)/2,
            composite_downweight_threshold=bounded(d)/2,trust_weight=.5,
            maximum_severity_quarantine=q,maximum_severity_downweight=d,
            clean_observations=len(population),clean_nominal_examples=sum(weights),
            nonempty_quarantine_region=math.isfinite(q) and bounded(q)<1.)
    return {**model,'component_limits':limits,'thresholds':thresholds}
