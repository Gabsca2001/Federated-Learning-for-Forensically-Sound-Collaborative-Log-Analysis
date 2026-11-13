"""Explain individual/joint controls from verified, fixed V5 results."""
import os
for name in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ[name]='1'
from pathlib import Path
import sys,csv,ast,hashlib
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');sys.path.insert(0,str(R/'scripts'))
import revision_episode_attribution as study
from revision_study_data import read
from revision_dba_experiment import save
D=study.D
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
p=read(D/'protocol-before-training.json');study.check(p)
summary=read(D/'summary.json');assert summary['status']=='verified_v5_separated_episode_assessment'
with (D/'origin-branches.csv').open() as h:branches=list(csv.DictReader(h))
rows=[]
for comp in summary['origin_comparisons']:
    if comp['method']!='v5':continue
    singles=[x for x in branches if x['alias']==comp['alias'] and len(ast.literal_eval(x['removed']))==1
             and ast.literal_eval(x['removed'])[0] in comp['group']]
    assert len(singles)==len(comp['group'])
    individual_asrs=sorted(float(x['final_worst_asr']) for x in singles)
    assert individual_asrs==sorted(comp['individual_final_worst_asrs'])
    rows.append(dict(alias=comp['alias'],joint_asr=comp['joint_final_worst_asr'],
        best_individual_asr=min(individual_asrs),worst_individual_asr=max(individual_asrs),
        closest_mass_benign_asr=comp['mass_control_final_worst_asr'],hash_benign_asr=comp['hash_control_final_worst_asr'],
        strictly_lower_than_all_individuals=comp['joint_final_worst_asr']<min(individual_asrs),
        zero_asr_single_removals=[dict(removed=ast.literal_eval(x['removed']),
            final_parameter_l2=float(x['final_parameter_l2_to_same_roster_clean']),
            all_checkpoints_equal_clean=x['all_checkpoints_equal_clean']=='True')
            for x in singles if float(x['final_worst_asr'])==0.]))
n=len(rows);better=sum(x['strictly_lower_than_all_individuals'] for x in rows)
zero_singles=[(r['alias'],x) for r in rows for x in r['zero_asr_single_removals']]
record=dict(status='derived_from_verified_origin_controls',source_summary_sha256=sha(D/'summary.json'),
    source_branch_table_sha256=sha(D/'origin-branches.csv'),interpreter_sha256=sha(Path(__file__)),
    comparisons=rows,joint_strictly_better_than_every_individual=better,total_selected_groups=n,
    zero_asr_single_removals_with_nonzero_parameter_residual=sum(x['final_parameter_l2']>0 for _,x in zero_singles),
    statistical_significance_claimed=False,intentional_collusion_proved=False,automatic_exclusion_authorized=False)
save(D/'group-interpretation.json',record)
table='\n'.join(f"| {x['alias']} | {100*x['best_individual_asr']:.2f}% | {100*x['worst_individual_asr']:.2f}% | {100*x['joint_asr']:.2f}% | {100*x['closest_mass_benign_asr']:.2f}% |" for x in rows)
zero_table='\n'.join(f"| {alias} | {', '.join(x['removed'])} | {x['final_parameter_l2']:.9g} | {'yes' if x['all_checkpoints_equal_clean'] else 'no'} |" for alias,x in zero_singles)
report=f'''# What the individual/joint controls support

These are derived comparisons of the completed V5 assessment, not additional
training runs or a policy change. All six effective raw cases remain included.

In {better}/{n} selected-group comparisons, full-origin joint removal reaches
zero final worst-trigger ASR and is strictly better than every single-member
removal. Closest-mass benign group removal leaves a nonzero ASR in all six.
Surviving attackers retrain and readapt at corrected parents in every branch.

| Case | Best individual-removal ASR | Worst individual-removal ASR | Joint-removal ASR | Closest-mass benign-removal ASR |
| --- | ---: | ---: | ---: | ---: |
{table}

This supports a group-level counterfactual effect under the declared attack and
training protocol. It does not establish statistical significance, superadditive
synergy, necessity of distributed trigger composition or intentional collusion.
In the other {n-better} cases, a single removal also reaches zero: the full group
is not necessary for that final ASR criterion. The original source graph and
the numerical counterfactual remain different kinds of evidence.

## Zero ASR and model restoration remain distinct

All selected joint removals match every same-excluded-roster clean checkpoint.
For the single removals that reach zero ASR, the parameter comparison is:

| Case | Removed client | Final L2 to same-roster clean | Every checkpoint equals same-roster clean |
| --- | --- | ---: | --- |
{zero_table}

The comparison does not restore the original full-roster model or selectively
erase only poisoned rows. The main report retains full-roster utility loss and
per-class outcomes, including rare-class support, for that reason.

## Meaning for the professor's agreed retrospective analysis

The experiment now includes groups selected without attacker labels, individual
and joint omissions, two benign group controls, and full retraining of subsequent
rounds. Oracle-known groups are explicitly diagnostic and share a numerical
branch when they equal the selected group. These results support the qualified
description "groups compatible with coordinated behavior" in these cases.
They do not authorize general automatic exclusion: V5 still misses scheduled
roles, and ineffective norm-limited attacks do not test successful evasion.
'''
with (D/'GROUP_INTERPRETATION.md').open('x') as h:h.write(report)
study.check(p)
print(f'{better}/{n} joint removals outperform every individual; {len(zero_singles)} single removals reach zero ASR.')
