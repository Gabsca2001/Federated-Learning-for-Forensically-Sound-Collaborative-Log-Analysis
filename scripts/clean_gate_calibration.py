"""Clean-only calibration primitives for an explicitly separate research gate.

Empirical tail budgets concern the retained calibration observations only.
Dependent client/round observations do not yield an exchangeability guarantee.
No attacker identity, poisoning label, trigger outcome or test result is accepted.
"""
from __future__ import annotations
import math
from collections import defaultdict
from fractions import Fraction
from statistics import median
from fl_forensics.composite_admission import build_indicator_references, score_statistical_indicators
from fl_forensics.composite_admission_models import IndicatorReference

NAMES=('relative_norm','cosine_to_median','coordinate_median_distance','mad_score','validation_impact')
DIRECTIONS={name:'lower' if name=='cosine_to_median' else 'higher' for name in NAMES}
WEIGHTS={name:.2 for name in NAMES}
CANDIDATES={
    'global':dict(conditioned=False,quarantine_quantile='0.975',downweight_quantile='0.90'),
    'conditioned':dict(conditioned=True,quarantine_quantile='0.975',downweight_quantile='0.90'),
    'conditioned_conservative':dict(conditioned=True,quarantine_quantile='0.99',downweight_quantile='0.95'),
}


def require(condition,detail):
    if not condition:raise ValueError(detail)


def stage(number):
    require(isinstance(number,int) and not isinstance(number,bool) and 1<=number<=15,'unsupported round')
    return (number-1)//5


def size_bucket(mass,cohort_median):
    require(isinstance(mass,int) and not isinstance(mass,bool) and mass>0 and
            isinstance(cohort_median,(int,float)) and not isinstance(cohort_median,bool) and
            math.isfinite(cohort_median) and cohort_median>0,'invalid bound example count')
    return 'small' if mass/cohort_median<.5 else 'large' if mass/cohort_median>1.5 else 'middle'


def group_key(cohort,number,mass,cohort_median,conditioned):
    require(cohort in ('iid','non-iid'),'unsupported declared cohort')
    bucket=stage(number)
    return f'{cohort}/{bucket}/{size_bucket(mass,cohort_median)}' if conditioned else cohort


def clean_record(record):
    # A strict allowlist prevents a future caller from accidentally fitting on
    # attacker labels, candidate outcomes, test scores or poisoning metadata.
    require(set(record)=={'cohort','round','examples','cohort_median','indicators'},'unexpected fitting fields')
    require(set(record['indicators'])==set(NAMES),'indicator schema mismatch')
    for value in record['indicators'].values():require(math.isfinite(value),'nonfinite clean indicator')
    size_bucket(record['examples'],record['cohort_median'])
    return record


def empirical_quantile(scores,weights,quantile):
    require(scores and len(scores)==len(weights),'empty or mismatched quantile population')
    q=Fraction(quantile);require(0<q<=1,'quantile outside (0,1]')
    require(all(math.isfinite(s) for s in scores) and all(isinstance(w,int) and w>0 for w in weights),
            'invalid empirical quantile input')
    population=sorted(zip(scores,weights),key=lambda x:x[0]);total=sum(weights);cumulative=0
    for score,weight in population:
        cumulative+=weight
        if cumulative>=q*total:return score
    raise AssertionError('unreachable quantile tail')


def fit_references(records,candidate):
    require(candidate in CANDIDATES,'unknown candidate')
    settings=CANDIDATES[candidate];groups=defaultdict(list);parents=defaultdict(list)
    for record in map(clean_record,records):
        key=group_key(record['cohort'],record['round'],record['examples'],record['cohort_median'],settings['conditioned'])
        groups[key].append(record['indicators'])
        parents[f"{record['cohort']}/{stage(record['round'])}"].append(record['indicators'])
    def refs(rows):
        require(len(rows)>=30,'insufficient clean reference support')
        population=[dict(client_id=f'clean-occurrence-{i}',**row) for i,row in enumerate(rows)]
        return {name:value.model_dump(mode='json') for name,value in
                build_indicator_references(population,directions=DIRECTIONS).items()}
    bank={};fallbacks={}
    if settings['conditioned']:
        for cohort in ('iid','non-iid'):
            for bucket in range(3):
                parent=f'{cohort}/{bucket}';bank[parent]=refs(parents[parent])
                for size in ('small','middle','large'):
                    key=parent+'/'+size
                    if len(groups[key])>=30:bank[key]=refs(groups[key]);fallbacks[key]=key
                    else:fallbacks[key]=parent
    else:
        for cohort in ('iid','non-iid'):bank[cohort]=refs(groups[cohort]);fallbacks[cohort]=cohort
    return dict(profile='clean-reference-gated-admission-v1',candidate=candidate,settings=settings,
                references=bank,reference_resolution=fallbacks,robust_z_cap=3.,
                indicator_weights=WEIGHTS,thresholds=None,
                scope='Research empirical calibration, not a maliciousness probability or a future false-positive guarantee.')


def score(model,cohort,number,examples,cohort_median,indicators,client_id):
    require(set(indicators)==set(NAMES),'indicator schema mismatch')
    key=group_key(cohort,number,examples,cohort_median,model['settings']['conditioned'])
    require(key in model['reference_resolution'],'unsupported clean profile')
    selected=model['reference_resolution'][key]
    require(selected in model['references'],'missing clean reference')
    refs={name:IndicatorReference.model_validate(v) for name,v in model['references'][selected].items()}
    signal=score_statistical_indicators([dict(client_id=client_id,**indicators)],references=refs,
                 weights=model['indicator_weights'],z_cap=model['robust_z_cap'])[client_id]
    return signal,selected


def fit_thresholds(model,records):
    by_cohort=defaultdict(list)
    for r in map(clean_record,records):
        signal,_=score(model,r['cohort'],r['round'],r['examples'],r['cohort_median'],r['indicators'],'clean-calibration')
        by_cohort[r['cohort']].append((signal.risk,r['examples']))
    thresholds={}
    for cohort in ('iid','non-iid'):
        rows=by_cohort[cohort];require(len(rows)>=100,'insufficient clean threshold calibration')
        scores=[s for s,_ in rows];masses=[n for _,n in rows]
        def cut(q):
            return max(empirical_quantile(scores,[1]*len(rows),q),empirical_quantile(scores,masses,q))
        q=cut(model['settings']['quarantine_quantile']);d=min(q,cut(model['settings']['downweight_quantile']))
        thresholds[cohort]=dict(statistical_threshold=q,composite_threshold=q/2,
            composite_downweight_threshold=d/2,trust_weight=.5,
            clean_observations=len(rows),clean_nominal_examples=sum(masses),
            nonempty_quarantine_region=q<1.)
    model={**model,'thresholds':thresholds}
    return model


def budget_summary(rows):
    require(rows,'empty clean validation history')
    total=q=d=nominal=effective=0;minimum_round_retention=1.
    for row in rows:
        statuses=row['statuses'];masses=row['masses'];counts=row['example_counts']
        require(set(statuses)==set(masses)==set(counts),'clean budget populations differ')
        total+=len(statuses);q+=sum(s.endswith('quarantined') for s in statuses.values())
        d+=sum(s=='accepted_downweighted' for s in statuses.values())
        round_nominal=sum(counts.values());round_effective=sum(Fraction(masses[c]) for c in masses)
        nominal+=round_nominal;effective+=round_effective
        minimum_round_retention=min(minimum_round_retention,float(round_effective/round_nominal))
    return dict(observations=total,quarantine_rate=q/total,downweight_rate=d/total,
                nominal_mass_retention=float(effective/nominal),minimum_round_mass_retention=minimum_round_retention)
