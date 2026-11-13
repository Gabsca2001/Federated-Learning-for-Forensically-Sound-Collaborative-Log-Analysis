"""Readable report and final source inventory; parameters are never modified."""
from pathlib import Path
import os
import json,csv,statistics,hashlib,shutil
import sys
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'scripts'))
import revision_gate_trajectories as study
from revision_study_data import read
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

out=root/'results/gates-probes/revision-gate-trajectories-v1';lab=study.LAB
local=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'gate-trajectories-20261106')
s=read(out/'summary.json');p=read(lab/'protocol-before-training.json')
a={(r['cohort'],r['mode'],r['policy']):r for r in s['aggregate']}
def pc(value):return 'undefined' if value is None else f'{100*value:.2f}'
def score(r,name):return pc(r[name+'_mean'])
lines=['# Independent admission-gate trajectories', '',
       'Completed 2026-11-06. All 72 planned campaigns completed 15 rounds: 1,080 deployed transitions and 16,200 retained local update exports. This is a software numerical research profile with mandatory trust assumed passed, not a new TPM campaign. The operational gate source, original calibration and thesis are unchanged.', '',
       '## Decision supported by this study', '',
       'Gated Composite provides an observed containment benefit over Sequential for the complete-trigger attack in these independently trained histories. The benefit comes from graded weighting and the resulting later trajectory, not a different no-warning same-input quarantine boundary. This is a scenario-specific numerical result, not a universal superiority or detection theorem.', '',
       'The original calibration does not meet the predeclared clean-utility guardrail on every assignment. At non-IID seed2026110605, round10, clean macro-F1 falls by6.07 percentage points for Sequential and5.94 points for Composite relative to paired TPM-only. At round15, the Composite loss is still2.74 points. Improved cohort means do not erase this counterexample.', '',
       'The hardest Composite complete-trigger case (the same non-IID assignment) reaches71.20% full-trigger ASR and ends at2.89%. Its distributed and adaptive full-trigger ASR is zero, but worst component-trigger peaks reach10.38% and7.89%, respectively. Full-trigger zero must not be presented as zero for all trigger variants.', '',
       'On clean non-IID campaigns, Composite quarantines127/675 honest contributions and downweights377/675: intervention on74.67% of observations. Only35.74% of repeated nominal honest mass is retained. This is not a normalized-influence percentage, and it does not itself prove poor predictive performance. It does show a substantial intervention cost.', '',
       'Do not promote either statistical policy as operationally validated under this frozen calibration. A subsequent clean-only calibration study must address heterogeneous clients and explicitly budget benign intervention and worst-assignment utility; it must use separately declared evaluation assignments. The present unfavorable outcomes remain part of the evidence. No new threshold is installed here.', '',
       '## Protocol and interpretation', '',
       '- Three original gates: TPM-only, Sequential and Gated Composite. Each drives its own subsequent local training. The original Flower full-model weighted FedAvg backend is fixed for every arm; no robust/clipped operator is mixed into this comparison.',
       '- Six newly reserved seed/identity assignments and fresh training allocations: three IID and three label-Dirichlet alpha 0.3, using the same 7,096 global Data24 training occurrences. The source scaler and global class weights are preserved. These are training-only research allocations using the M3 allocation algorithms, not complete new M3 release profiles.',
       '- Same fixed clean warm-start checkpoint for all cases, rather than six independently initialized models. Fifteen clients; ten local Adam epochs; batch128; learning rate0.001. The preflight seed is excluded.',
       '- Four conditions per policy/assignment: clean, fixed distributed DBA, fixed complete-trigger attack and defender-specific adaptive distributed attack. Poison50% of hash-selected local training rows at three clients; target benign; trigger features13/17/24 at standardized value12. Distributed/full variants share selected row budgets but differ in feature-edit budgets. This is a feature-space attack, with no primary-log realizability claim.',
       '- Attack rounds1–10; unmodified continuation11–15. Adaptive candidates alpha={0,.25,.5,1,2,4} interpolate/amplify clean and poisoned local endpoints. Six validation queries per active round, optimized separately against each defender, maximize worst full/component-trigger ASR after its actual aggregation. Ties prefer fewer attacker-slot quarantines, then larger alpha. Alpha0 is reported as no actual manipulated exports.',
       '- Frozen original references, five equal indicator weights, statistical quarantine threshold0.8183094063145846, composite threshold half that value, factor0.5 and minimum10 contributors. No calibration or parameter fitting was performed. The inherited source-training JSON also contains historical ancillary fields, including minimum_contributors8; those fields are unused by this runner. The bound runtime-admission settings govern the actual gate/quorum.',
       '- Fixed endpoints at rounds10 and15, full-horizon peak and attack-window mean ASR were declared before execution. Test inference occurred only after all72 training cases had terminal evidence. The test split was used in earlier research: this is exploratory reuse, not untouched confirmation or independent-dataset evidence. Neither test outcomes nor these charts select a model or change a threshold.',
       '- Full/component ASR targets benign among all3,497 non-benign test examples, not just the reconnaissance subset used in some earlier studies. Clean accuracy/F1 uses all4,937 test examples. The independent repetition unit is the seed/partition assignment; each cohort has three. Rounds and client decisions are not independent detection trials.', '',
       'The retained protocol has SHA-256 `'+s['protocol_sha256']+'`. Its case evidence is preserved under `artifacts/revision-gate-trajectories-v1`; source files and original update bytes are not overwritten.', '',
       '## Full-trigger outcomes', '',
       'Cells show **mean peak / mean final full-trigger test ASR (%)**, across three assignments per cohort. Every case is reported, including controls that fail the declared attack-effectiveness criterion. Final zero after five clean continuation rounds does not by itself show that a defense prevented the attack.', '',
       '| Cohort | Attack | TPM-only | Sequential | Gated Composite |',
       '|---|---|---:|---:|---:|']
for cohort in ('iid','non-iid'):
    for mode in ('distributed','complete-trigger','adaptive'):
        cells=[]
        for policy in study.POLICIES:
            row=a[(cohort,mode,policy)]
            cells.append(score(row,'full_horizon_peak_full_asr')+' / '+score(row,'final_full_asr'))
        lines.append('| '+' | '.join([cohort,mode,*cells])+' |')
lines+=['','Exact per-seed round10, final, peak and attack-window means are in `cases.csv`; `aggregate.csv` also includes component/worst-trigger outcomes, denominators, sample SDs and available-case counts. No equivalence or significance claim is made from three assignments per cohort.','',
        '![Full-trigger test trajectories](full-trigger-trajectories.png)','',
        'Lines are the descriptive means; shaded bands are the observed range of three assignments, not confidence intervals. The dashed line separates attack and clean-continuation rounds. All branches completed, so no absent checkpoint is plotted as ASR zero.','',
        '## Clean utility and benign intervention cost','',
        'Clean campaigns contain no poisoned training. Quarantine/downweight counts below pool675 repeated client/round observations per cohort/policy. A downweight retains half nominal mass and is not an exclusion or proof of maliciousness.','',
        '| Cohort | Policy | Final clean macro-F1 (%) | Quarantines /675 | Downweights /675 | Nominal mass retained (%) |',
        '|---|---|---:|---:|---:|---:|']
for cohort in ('iid','non-iid'):
    for policy in study.POLICIES:
        row=a[(cohort,'clean',policy)]
        lines.append('| '+' | '.join([cohort,policy,score(row,'final_clean_macro_f1'),
            str(row['currently_unmodified_quarantined']),str(row['currently_unmodified_downweighted']),
            score(row,'unmodified_nominal_weight_retention')])+' |')
lines+=['',f'The largest paired fixed-endpoint clean macro-F1 loss against TPM-only is **{pc(s["max_clean_utility_loss_vs_tpm"])} percentage points**. The predeclared clean-utility guardrail was2 points. `clean-utility.csv` contains every seed and both fixed endpoints; a negative loss means higher observed F1. Nominal mass retention counts repeated training-sample weight, not unique data coverage or normalized influence.','',
        '## Admission during attacked campaigns','',
        'The following counts pool the six assignments in each attack/policy cell. “Unmodified” includes the continuation rounds and alpha0 adaptive exports. Labels are evaluation-only and do not enter gate scoring. Quarantining a poisoned export is not proof that every retained export caused damage; admitting one is not proof of benignity.','',
        '| Attack | Policy | Manipulated exports | Manipulated quarantined | Manipulated downweighted | Unmodified quarantined / total | Unmodified downweighted |',
        '|---|---|---:|---:|---:|---:|---:|']
for mode in ('distributed','complete-trigger','adaptive'):
    for policy in study.POLICIES:
        rows=[a[(cohort,mode,policy)] for cohort in ('iid','non-iid')]
        sums={k:sum(r[k] for r in rows) for k in ('actual_manipulated_total','actual_manipulated_quarantined','actual_manipulated_downweighted',
                 'currently_unmodified_total','currently_unmodified_quarantined','currently_unmodified_downweighted')}
        lines.append('| '+' | '.join([mode,policy,str(sums['actual_manipulated_total']),str(sums['actual_manipulated_quarantined']),
            str(sums['actual_manipulated_downweighted']),f"{sums['currently_unmodified_quarantined']} / {sums['currently_unmodified_total']}",
            str(sums['currently_unmodified_downweighted'])])+' |')
effect=s['control_effectiveness']
lines+=['','The predeclared effective-control rule requires at least one same-round paired increase of20 percentage points in worst-trigger ASR, with at most5 points clean macro-F1 loss. The TPM-only controls meeting it are:']
for mode in ('distributed','complete-trigger','adaptive'):
    selected=[r for r in effect if r['policy']=='tpm_only' and r['mode']==mode]
    lines.append(f'- {mode}: {sum(r["effective_under_declared_control_rule"] for r in selected)}/{len(selected)}.')
lines+=['','`control-effectiveness.csv` retains every case and qualifying rounds. A control failing this joint criterion is inconclusive for the declared mitigation comparison; it is not silently discarded or declared impossible to attack.','',
        '## Residual differences from paired clean trajectories','']
final=[r for r in s['residual_checks'] if r['round']==15]
zero=[r for r in final if r['full_asr']==0]
nonzero=sum(r['model_l2_from_paired_clean'] is not None and r['model_l2_from_paired_clean']>0 for r in zero)
disagree=sum(r['test_prediction_disagreements'] is not None and r['test_prediction_disagreements']>0 for r in zero)
lines += [f'Among the **{len(zero)} final attacked endpoints with zero full-trigger ASR**, {nonzero} have nonzero parameter L2 distance from their own paired clean model and {disagree} have at least one different untriggered test prediction. `residuals.csv` also gives round10 results, exact disagreement counts and denominators.', '',
          'A parameter difference is not by itself evidence of remaining harmful poisoning. It can include the defense response and changes in later honest training. These checks prevent “ASR zero” from being misrepresented as model restoration or removal of every attack-induced trajectory difference.','',
          '## Computational cost','',
          'Per-case stage medians are retained in `cases.csv`. Statistical work includes geometry, validation inference and all policy decisions; it is performed even for TPM-only to match the current in-round wrapper. A legacy TPM-only path without those calculations is not benchmarked here. Offline trust appraisal is assumed, so its real TPM/Quote latency is unavailable, not measured as zero. Aggregation timings measure a repeated reconstruction call. Adaptive-search timing includes poisoned endpoint training and candidate scoring/aggregation/evaluation; its selected candidate timings overlap and must not be added again as independent elapsed cost. Three concurrent single-threaded CPU workers were used; these are observed wall timings under that execution load.','']
case_costs=list(csv.DictReader((out/'cases.csv').open()))
lines+=['The following are medians across per-case medians, with adaptive search restricted to the six adaptive cases per policy. Different trajectories/workloads remain visible in the raw stage records.','',
        '| Policy | Local population training (s) | Statistics and decisions (ms) | Aggregation replay (ms) | Six-query adaptive search (s) |',
        '|---|---:|---:|---:|---:|']
for policy in study.POLICIES:
    rows=[r for r in case_costs if r['policy']==policy]
    columns=[]
    for key,scale in [('median_training_seconds',1),('median_statistics_seconds',1000),
                      ('median_aggregation_seconds',1000),('median_adaptive_search_seconds',1)]:
        values=[float(r[key])*scale for r in rows if r[key]]
        columns.append(f'{statistics.median(values):.3f}' if values else 'unavailable')
    lines.append('| '+' | '.join([policy,*columns])+' |')
lines+=['',
          '## Verification and limits','',
          f'- Reconstructed {s["verification_counts"]["saved_rounds_reconstructed"]} deployed rounds from saved original model updates, including cohort indicators, validation impacts, policy vectors, exact masses, normalized coefficients and the Flower checkpoint bytes.',
          f'- Reconstructed {s["verification_counts"]["candidates_reconstructed"]} adaptive queries, including candidate update hashes, decisions, feasibility, full/component validation ASR objectives and selected alpha.',
          f'- Verified {s["verification_counts"]["no_band_controls"]} exact numerical no-band/Sequential controls and {s["verification_counts"]["independent_local_training_repeats"]} independent local-training repetitions at fixed rounds1and15.',
          '- Verified software experiment manifest signatures and all inventoried file hashes for every case. No fresh TPM Quotes or per-client hardware signatures are claimed by this study; prior live TPM integration evidence is separate.',
          '- All24 focused tests passed, including exact-weight, quorum and no-band numerical controls. The existing two Typer/Click deprecation warnings remain unrelated.',
          '- During validation-only auditor smoke, NumPy was initially initialized before the single-thread environment; fixing import order restored exact reconstruction. The first full-audit attempt stopped before test reading because a manifest pin had an absolute key while its lookup used a relative key. The corrected audit is preserved as `post-training-evaluation-v2`; the original failed attempt and log remain. Training and its frozen controller were not changed.',
          '- One dataset, one fixed warm start, three new allocations per cohort, a limited six-query adaptive family and assumed passed trust do not establish universal robustness, calibrated maliciousness probabilities, warning-value utility or permanent client exclusion. ToN-IoT remains deferred.', '',
          '## Reproduction','',
          'Use `inventory-final.json` for the final reviewed report. The earlier inventory and initial publication check are retained as intermediate publication receipts. Numerical CSV/JSON results and signed campaign evidence were not rewritten.', '',
          'The generation controller refuses an existing fresh destination and preserves completed case results. Do not delete prior evidence to rerun it. The immutable protocol and controller copy record exact inputs and the actual stage resolution. A new full generation requires a separately versioned destination/lock.', '',
          '```bash',
          '.venv/bin/python scripts/revision_gate_trajectories.py prepare',
          '.venv/bin/python scripts/revision_gate_trajectories.py run --workers 3',
          '.venv/bin/python scripts/revision_gate_trajectories_audit.py --workers 3 --output-root artifacts/revision-gate-trajectories-v1/post-training-evaluation-v2',
          '.venv/bin/python scripts/report_gate_trajectories.py',
          '.venv/bin/python -m pytest -q tests/test_gate_trajectories.py tests/test_gate_mechanism_properties.py tests/test_composite_admission.py tests/test_admission.py',
          '```','',
          'All destinations above already exist after this completed run. To repeat the saved-input audit, use a fresh `--output-root`; retain every previous audit. The publication binds the selected audit summary explicitly rather than automatically choosing a favorable result. The thesis remains unchanged.','']
text='\n'.join(lines)
for before,after in {'all72':'all 72','batch128':'batch size 128','rate0.001':'rate 0.001',
    'Poison50%':'Poison 50%','rounds1':'rounds 1','continuation11':'continuation 11',
    'features13':'features 13','value12':'value 12','threshold0.818':'threshold 0.818',
    'factor0.5':'factor 0.5','minimum10':'minimum 10','all3,497':'all 3,497','all4,937':'all 4,937',
    'pool675':'pool 675','was2':'was 2','of20':'of 20','most5':'most 5','All24':'All 24',
    'rounds 1and15':'rounds 1 and 15','seed2026110605':'seed 2026110605',
    'round10':'round 10','round15':'round 15','by6.07':'by 6.07','and5.94':'and 5.94',
    'still2.74':'still 2.74','reaches71.20':'reaches 71.20','at2.89':'at 2.89',
    'reach10.38':'reach 10.38','and7.89':'and 7.89','quarantines127':'quarantines 127',
    'downweights377':'downweights 377','on74.67':'on 74.67','Only35.74':'Only 35.74'}.items():
    text=text.replace(before,after)
(out/'README.md').write_text(text)
study.assert_locks(p)
validation=dict(status='verified',planned_cases=72,complete_cases=s['complete_cases'],
    rounds_reconstructed=s['reconstructed_rounds'],verification_counts=s['verification_counts'],focused_tests_passed=24,
    all_frozen_source_hashes_unchanged=True,thesis_changed=False,new_TPM_Quotes=0,
    protocol_sha256=s['protocol_sha256'],test_reused_exploratory=True)
if (out/'validation.json').exists():assert read(out/'validation.json')==validation
else:save(out/'validation.json',validation)
guardrails=dict(all_cases_complete=s['complete_cases']==72,clean_loss_limit=.02,
    max_clean_loss_by_policy={policy:max(r['clean_utility_loss_vs_tpm'] for r in s['clean_utility_pairs'] if r['policy']==policy)
                             for policy in study.POLICIES},automatic_promotion_justified=False,
    reason='Both statistical policies exceed the predeclared worst-assignment clean-utility limit; substantial benign intervention and residual attack outcomes remain.')
if (out/'guardrails.json').exists():assert read(out/'guardrails.json')==guardrails
else:save(out/'guardrails.json',guardrails)
files=[f for f in out.iterdir() if f.is_file() and f.name!='inventory-final.json']
files += [root/'scripts/revision_gate_trajectories.py',root/'scripts/revision_gate_trajectories_audit.py',
          root/'scripts/report_gate_trajectories.py',root/'scripts/publish_gate_trajectories.py',
          root/'scripts/check_gate_publication.py',root/'tests/test_gate_trajectories.py']
save(out/'inventory-final.json',dict(profile='gate-trajectory-final-report-inventory-v1',
    files={str(f.relative_to(root)):sha256_file(f) for f in files}))
for path in out.iterdir():
    if path.is_file() and (not (local/path.name).exists() or sha256_file(path)!=sha256_file(local/path.name)):
        shutil.copy2(path,local/path.name)
shutil.copy2(out/'README.md',local/'REPORT.md')
print(json.dumps(dict(report=str(out/'README.md'),complete_cases=s['complete_cases'],
    maximum_clean_utility_loss=s['max_clean_utility_loss_vs_tpm'],zero_final_asr_endpoints=len(zero),
    zero_asr_with_parameter_difference=nonzero,zero_asr_with_prediction_disagreement=disagree),indent=2))
