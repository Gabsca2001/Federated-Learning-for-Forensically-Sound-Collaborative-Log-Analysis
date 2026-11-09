"""Re-fit frozen severe/mean models and verify empirical tail budgets."""
from fractions import Fraction
from pathlib import Path
import json
import revision_severe_gate_study as study
import severe_gate_calibration as cal
import clean_gate_calibration as legacy
from revision_study_data import read
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

p=read(study.LAB/'protocol-before-clean-fitting.json');study.assert_locks(p)
fit,fp=study.clean_records('fit');observations,cp=study.clean_records('calibration');checks=[]
for candidate in cal.CANDIDATES:
    model=cal.fit_thresholds(cal.fit_references(fit,candidate),observations)
    model['source_clean_manifests']=dict(fit=fp,calibration=cp)
    model['fit_observations']=len(fit);model['threshold_observations']=len(observations)
    path=study.LAB/'models'/f'{candidate}.json';assert read(path)==model
    for cohort in ('iid','non-iid'):
        rows=[r for r in observations if r['cohort']==cohort];scores=[]
        for r in rows:
            detail=cal.diagnostics(model,cohort,r['round'],r['examples'],r['cohort_median'],r['indicators'])
            signal,_=cal.score(model,cohort,r['round'],r['examples'],r['cohort_median'],r['indicators'],'refit-check')
            assert not signal.components
            assert signal.risk==max(cal.bounded(v['normalized_severity']) for v in detail['components'].values())
            scores.append((signal.risk,r['examples']))
        limits=model['thresholds'][cohort];q=limits['statistical_threshold'];d=2*limits['composite_downweight_threshold']
        n=len(scores);mass=sum(w for _,w in scores)
        qn=sum(s>q for s,_ in scores);dn=sum(s>d for s,_ in scores)
        qm=sum(w for s,w in scores if s>q);dm=sum(w for s,w in scores if s>d)
        eq=1-Fraction(model['settings']['quarantine_quantile']);ed=1-Fraction(model['settings']['downweight_quantile'])
        assert Fraction(qn,n)<=eq and Fraction(qm,mass)<=eq
        assert Fraction(dn,n)<=ed and Fraction(dm,mass)<=ed
        retained=1-(Fraction(qm,mass)+Fraction(dm-qm,2*mass));bound=1-(eq+(ed-eq)/2)
        assert retained>=bound
        checks.append(dict(candidate=candidate,cohort=cohort,model_sha256=sha256_file(path),observations=n,
            count_quarantine_rate=qn/n,mass_quarantine_rate=qm/mass,count_intervention_rate=dn/n,
            mass_intervention_rate=dm/mass,empirical_mass_retained=float(retained),empirical_lower_bound=float(bound),
            per_component_noncompensation_checked=True,maximum_quarantine_threshold=limits['maximum_severity_quarantine']))
mean=legacy.fit_thresholds(legacy.fit_references(fit,'conditioned_conservative'),observations)
mean['candidate']='mean_control';mean['source_clean_manifests']=dict(fit=fp,calibration=cp)
mean['fit_observations']=len(fit);mean['threshold_observations']=len(observations)
mean['control_semantics']='Same fresh clean data, original capped average and conservative quantiles; never selectable as the proposed severe gate.'
assert read(study.LAB/'models/mean_control.json')==mean
receipt=dict(status='verified',models_independently_refitted=3,fit_observations=len(fit),calibration_observations=len(observations),
             test_accessed=False,attack_results_accessed=False,checks=checks,checker_sha256=sha256_file(Path(__file__)))
save(study.LAB/'models-refit-verification.json',receipt)
print(json.dumps(receipt,indent=2))
