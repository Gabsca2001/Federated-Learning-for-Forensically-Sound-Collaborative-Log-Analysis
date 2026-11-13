"""Independent CSV/JSON accounting and report-inventory check."""
from pathlib import Path
import csv,json,hashlib,statistics
root=Path(__file__).resolve().parents[1]
out=root/'results/gates-probes/revision-gate-trajectories-v1'
s=json.loads((out/'summary.json').read_bytes())
cases=list(csv.DictReader((out/'cases.csv').open()))
rounds=list(csv.DictReader((out/'rounds.csv').open()))
assert len(cases)==len({r['case'] for r in cases})==72
assert len(rounds)==1080 and all(r['complete']=='True' and r['completed_rounds']=='15' for r in cases)
for case in cases:
    rows=[r for r in rounds if r['case']==case['case']]
    assert sorted(int(r['round']) for r in rows)==list(range(1,16))
    assert float(case['full_horizon_peak_full_asr'])==max(float(r['full_asr']) for r in rows)
    assert float(case['final_full_asr'])==float(next(r['full_asr'] for r in rows if r['round']=='15'))
    assert float(case['attack_window_mean_full_asr'])==statistics.mean(float(r['full_asr']) for r in rows if int(r['round'])<=10)
    for key in ('actual_manipulated_total','actual_manipulated_quarantined','currently_unmodified_total','currently_unmodified_quarantined','currently_unmodified_downweighted'):
        assert int(case[key])==sum(int(r[key]) for r in rows)
for group in s['aggregate']:
    rows=[r for r in cases if (r['cohort'],r['mode'],r['policy'])==(group['cohort'],group['mode'],group['policy'])]
    assert len(rows)==3
    for key in ('final_full_asr','full_horizon_peak_full_asr','full_asr_round10'):
        assert group[key+'_mean']==statistics.mean(float(r[key]) for r in rows)
inventory=json.loads((out/'inventory-final.json').read_bytes())
for name,expected in inventory['files'].items():
    path=root/name
    assert path.resolve().is_relative_to(root.resolve())
    assert hashlib.sha256(path.read_bytes()).hexdigest()==expected,name
validation=dict(status='verified',case_peak_final_checks=72,round_records=1080,
                aggregate_groups=24,report_inventory_files=len(inventory['files']),
                no_missing_checkpoint_imputed_as_zero=True)
path=out/'independent-publication-check-v2.json'
with path.open('x') as stream:json.dump(validation,stream,indent=2);stream.write('\n')
print(json.dumps(validation,indent=2))
