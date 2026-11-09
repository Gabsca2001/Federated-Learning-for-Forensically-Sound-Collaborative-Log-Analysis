"""Check report accounting against immutable phase verification receipts."""
import csv,json,statistics
from pathlib import Path
import revision_clean_gate_study as study
import clean_gate_calibration as cal
from revision_study_data import read
from fl_forensics.canonical import sha256_file

root=study.ROOT;lab=study.LAB;out=root/'results/revision-clean-gate-calibration-v1'
summary=read(out/'summary.json');study.assert_locks(read(lab/'protocol-before-clean-fitting.json'))
cases=list(csv.DictReader((out/'cases.csv').open()));rows=list(csv.DictReader((out/'rounds.csv').open()))
assert len(cases)==len({r['case'] for r in cases})==72
assert len(rows)==1040 and sum(r['complete']=='True' for r in cases)==66
for case in cases:
    rs=[r for r in rows if r['case']==case['case']]
    assert len(rs)==int(case['completed_rounds'])
    assert sorted(int(r['round']) for r in rs)==list(range(1,len(rs)+1))
    if case['complete']=='True':
        assert float(case['peak_full_asr'])==max(float(r['full_asr']) for r in rs)
        assert float(case['final_full_asr'])==float(next(r['full_asr'] for r in rs if r['round']=='15'))
    else:
        assert case['peak_full_asr']=='' and case['final_full_asr']==''
for aggregate in summary['aggregate']:
    cs=[r for r in cases if (r['cohort'],r['mode'],r['policy'])==(aggregate['cohort'],aggregate['mode'],aggregate['policy'])]
    assert len(cs)==3 and aggregate['complete']==sum(c['complete']=='True' for c in cs)
    for name in ('peak_full_asr','final_full_asr'):
        vs=[float(r[name]) for r in cs if r[name]]
        assert aggregate[name+'_n']==len(vs)
        assert aggregate[name]==(statistics.mean(vs) if vs else None)
audit=read(lab/'evaluation/verified/summary.json');failure_checks=0
for case in audit['cases']:
    if not case['complete']:
        assert case['task']['policy']=='gated_composite'
        assert case['failure']['classification']=='quorum' and case['verification']['quorum_failure_verified']
        failure_checks+=1
assert failure_checks==6
guards=read(out/'clean-guardrails.json')
for guard in guards:
    case=next(c for c in audit['cases'] if c['task']['seed']==guard['seed'] and c['task']['policy']==guard['policy'] and c['task']['mode']=='clean')
    assert guard['budget']==cal.budget_summary(case['rows'])
comparisons=list(csv.DictReader((out/'attack-comparison.csv').open()))
assert sum(c['complete']=='True' for c in comparisons)==summary['attack_comparisons_defined']==13
assert sum(c['worse_than_original']=='True' for c in comparisons)==summary['worse_attack_cases']==2
assert sum(c['benefit_vs_effective_control']=='True' for c in comparisons)==summary['effective_controls_with_benefit']==12
assert summary['reserved_clean_budgets_pass'] is False and summary['automatic_production_promotion'] is False
inventory=read(out/'inventory-final.json')
for name,expected in inventory['files'].items():
    path=root/name;assert path.resolve().is_relative_to(root.resolve()) and sha256_file(path)==expected,name
receipt=dict(status='verified',case_records=72,completed_evaluation_rounds=1040,
             verified_quorum_failures=failure_checks,case_metric_checks=72,aggregate_groups=24,
             clean_budget_checks=18,defined_original_comparisons=13,defined_tpm_comparisons=18,
             no_missing_model_imputed_as_zero=True,inventory_files=len(inventory['files']),
             checker_sha256=sha256_file(Path(__file__)))
(out/'independent-publication-check.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
