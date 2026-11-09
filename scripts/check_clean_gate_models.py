"""Re-fit every frozen model and check empirical count/mass calibration tails."""
from fractions import Fraction
from pathlib import Path
import json
import revision_clean_gate_study as study
import clean_gate_calibration as cal
from revision_study_data import read
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

root=read(study.LAB/'protocol-before-clean-fitting.json');study.assert_locks(root)
fit,fit_pins=study.clean_records('fit');calibration,cal_pins=study.clean_records('calibration')
checks=[]
for candidate in cal.CANDIDATES:
    rebuilt=cal.fit_thresholds(cal.fit_references(fit,candidate),calibration)
    rebuilt['source_clean_manifests']=dict(fit=fit_pins,calibration=cal_pins)
    rebuilt['fit_observations']=len(fit);rebuilt['threshold_observations']=len(calibration)
    path=study.LAB/'models'/f'{candidate}.json'
    study.base.require(rebuilt==read(path),'Frozen model differs from independent refit')
    for cohort in ('iid','non-iid'):
        rows=[r for r in calibration if r['cohort']==cohort];limits=rebuilt['thresholds'][cohort]
        scored=[(cal.score(rebuilt,cohort,r['round'],r['examples'],r['cohort_median'],r['indicators'],'calibration-check')[0].risk,r['examples']) for r in rows]
        total=sum(n for _,n in scored);q=limits['statistical_threshold'];d=2*limits['composite_downweight_threshold']
        q_count=sum(s>q for s,_ in scored);d_count=sum(s>d for s,_ in scored)
        q_mass=sum(n for s,n in scored if s>q);d_mass=sum(n for s,n in scored if s>d)
        q_budget=1-Fraction(rebuilt['settings']['quarantine_quantile']);d_budget=1-Fraction(rebuilt['settings']['downweight_quantile'])
        assert Fraction(q_count,len(rows))<=q_budget and Fraction(q_mass,total)<=q_budget
        assert Fraction(d_count,len(rows))<=d_budget and Fraction(d_mass,total)<=d_budget
        retained=1-(Fraction(q_mass,total)+Fraction(d_mass-q_mass,2*total))
        lower=1-(q_budget+(d_budget-q_budget)/2)
        assert retained>=lower
        checks.append(dict(candidate=candidate,cohort=cohort,model_sha256=sha256_file(path),observations=len(rows),
            count_quarantine_rate=q_count/len(rows),mass_quarantine_rate=q_mass/total,
            count_intervention_rate=d_count/len(rows),mass_intervention_rate=d_mass/total,
            empirical_nominal_mass_retained=float(retained),empirical_lower_bound=float(lower),
            statistical_downweight_cut=d,statistical_quarantine_cut=q,
            any_zero_component_forces_full_acceptance_at_passed_trust=d>=.8,
            interpretation='Empirical calibration budget and risk upper-bound diagnostic only; not future coverage or attack success.'))
receipt=dict(status='verified',models_refitted=3,fit_observations=len(fit),calibration_observations=len(calibration),
             test_accessed=False,attack_results_accessed=False,checks=checks,checker_sha256=sha256_file(Path(__file__)))
save(study.LAB/'models-refit-verification.json',receipt)
print(json.dumps(receipt,indent=2))
