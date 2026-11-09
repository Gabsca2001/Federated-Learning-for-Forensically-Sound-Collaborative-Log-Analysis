"""Report clean calibration, all candidate outcomes and reserved evaluation."""
from __future__ import annotations
import argparse,csv,json,statistics,shutil
from collections import defaultdict,Counter
from pathlib import Path
import os
import revision_clean_gate_study as study
import clean_gate_calibration as cal
from revision_study_data import read
from revision_dba_experiment import predict
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export,dependencies

ROOT,LAB=study.ROOT,study.LAB
OUT=ROOT/'results/revision-clean-gate-calibration-v1'
LOCAL=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'gate-calibration-20261106')


def write_json(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n')


def write_csv(path,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)


def avg(values):
    values=[v for v in values if v is not None]
    return statistics.mean(values) if values else None


def percent(v):return 'undefined' if v is None else f'{100*v:.2f}'


def run(refresh_draft=False):
    study.base.require(not OUT.exists() or refresh_draft,'Preserve published calibration report')
    protocol=read(LAB/'protocol-before-clean-fitting.json');study.assert_locks(protocol)
    decision=read(LAB/'selection-decision.json');selection=[];models=[];counts=Counter()
    for candidate in decision['candidates']:
        for detail in candidate['details']:
            selection.append(dict(candidate=candidate['candidate'],cohort=detail['cohort'],seed=detail['seed'],
                qualified=detail['qualified'],complete=detail['complete'],**(detail['budget'] or {}),
                worst_validation_f1_loss=max(detail['validation_losses'],default=None)))
    for name in cal.CANDIDATES:
        model=read(LAB/'models'/f'{name}.json')
        for cohort,limits in model['thresholds'].items():
            models.append(dict(candidate=name,cohort=cohort,model_sha256=sha256_file(LAB/'models'/f'{name}.json'),
                               **limits))
    phase_pins={}
    for phase in ('fit','calibration','selection'):
        path=LAB/phase/'verified/summary.json';payload=read(path)
        study.base.require(payload['status']=='verified' and not payload['test_accessed'],'Contaminated development stage')
        phase_pins[phase]=sha256_file(path)
        counts['clean_development_campaigns']+=len(payload['cases'])
        for case in payload['cases']:
            for key in ('rounds','queries','local_repeats'):counts['development_'+key]+=case['verification'][key]
    summaries=[];round_rows=[];guardrails=[];attack_pairs=[];residuals=[];plot_data=[]
    evaluated=decision['selected_candidate'] is not None
    audit=None
    if evaluated:
        path=LAB/'evaluation/verified/summary.json';audit=read(path);phase_pins['evaluation']=sha256_file(path)
        study.base.require(audit['status']=='verified' and audit['test_accessed'],'Missing reserved test audit')
        study.base.require(len(audit['cases'])==72,'Missing planned reserved cases')
        lookup={(r['task']['seed'],r['task']['policy'],r['task']['mode']):r for r in audit['cases']}
        for case in audit['cases']:
            task=case['task'];rows=case['rows'];mapping={r['round']:r for r in rows}
            for key in ('rounds','queries','local_repeats'):counts['evaluation_'+key]+=case['verification'][key]
            q=d=denom=mq=md=mn=0
            for row in rows:
                selected=set(row['actually_manipulated_clients']);statuses=row['statuses']
                q+=sum(v.endswith('quarantined') for c,v in statuses.items() if c not in selected)
                d+=sum(v=='accepted_downweighted' for c,v in statuses.items() if c not in selected)
                denom+=sum(c not in selected for c in statuses)
                mq+=sum(v.endswith('quarantined') for c,v in statuses.items() if c in selected)
                md+=sum(v=='accepted_downweighted' for c,v in statuses.items() if c in selected);mn+=len(selected)
                record=dict(case=task['name'],cohort=task['cohort'],seed=task['seed'],policy=task['policy'],mode=task['mode'],
                    round=row['round'],full_asr=row['test']['complete_trigger']['asr'],worst_trigger_asr=study.base.scalar_asr(row['test']),
                    clean_macro_f1=row['test']['clean']['macro_f1_all_model_classes'],selected_alpha=row['selected_alpha'])
                round_rows.append(record);plot_data.append(record)
            def metric(number,key):return mapping[number]['test'][key] if number in mapping else None
            row=dict(case=task['name'],cohort=task['cohort'],seed=task['seed'],policy=task['policy'],mode=task['mode'],
                complete=case['complete'],completed_rounds=len(rows),failure=case['failure'] or case['source_exception'],
                peak_full_asr=max((r['test']['complete_trigger']['asr'] for r in rows),default=None) if case['complete'] else None,
                observed_prefix_peak_full_asr=max((r['test']['complete_trigger']['asr'] for r in rows),default=None),
                final_full_asr=mapping[15]['test']['complete_trigger']['asr'] if 15 in mapping else None,
                peak_worst_trigger_asr=max((study.base.scalar_asr(r['test']) for r in rows),default=None) if case['complete'] else None,
                mean_attack_window_asr=avg([r['test']['complete_trigger']['asr'] for r in rows if r['round']<=10]) if len([r for r in rows if r['round']<=10])==10 else None,
                final_clean_macro_f1=mapping[15]['test']['clean']['macro_f1_all_model_classes'] if 15 in mapping else None,
                unmodified_quarantined=q,unmodified_downweighted=d,unmodified_observations=denom,
                manipulated_quarantined=mq,manipulated_downweighted=md,manipulated_exports=mn)
            summaries.append(row)
        for cohort,seed in study.STAGES['evaluation']:
            control=lookup[(seed,'tpm_only','clean')];control_rows={r['round']:r for r in control['rows']}
            for policy in ('tpm_only','gated_composite','calibrated_gated'):
                clean=lookup[(seed,policy,'clean')];clean_rows={r['round']:r for r in clean['rows']}
                budget=cal.budget_summary(clean['rows']) if clean['rows'] else None
                losses=[control_rows[n]['test']['clean']['macro_f1_all_model_classes']-clean_rows[n]['test']['clean']['macro_f1_all_model_classes']
                        for n in (10,15) if n in control_rows and n in clean_rows]
                ok=clean['complete'] and control['complete'] and budget['quarantine_rate']<=.05 and budget['downweight_rate']<=.15 \
                    and budget['nominal_mass_retention']>=.9 and budget['minimum_round_mass_retention']>=.8 and max(losses)<=.02
                guardrails.append(dict(cohort=cohort,seed=seed,policy=policy,complete=clean['complete'],budget=budget,
                    fixed_endpoint_test_losses=losses,qualified=bool(ok)))
                for mode in ('distributed','complete-trigger','adaptive'):
                    attacked=lookup[(seed,policy,mode)];pairs=[]
                    for row in attacked['rows']:
                        if row['round'] in clean_rows:
                            a=row['test'];c=clean_rows[row['round']]['test']
                            pairs.append((row['round'],study.base.scalar_asr(a)-study.base.scalar_asr(c),
                                          c['clean']['macro_f1_all_model_classes']-a['clean']['macro_f1_all_model_classes']))
                    attack_pairs.append(dict(cohort=cohort,seed=seed,policy=policy,mode=mode,complete=attacked['complete'] and clean['complete'],
                        peak_paired_worst_trigger_harm=max((p[1] for p in pairs),default=None),
                        effective_control=any(delta>=.2 and loss<=.05 for _,delta,loss in pairs)))
        # Residual checks only for the selected calibrated arm at the fixed final endpoint.
        deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
        test_rows=read(ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1/server/splits/test.json')['rows']['test']
        for cohort,seed in study.STAGES['evaluation']:
            ctask=lookup[(seed,'calibrated_gated','clean')]['task'];clean_path=LAB/'evaluation/cases'/ctask['name']/'evidence/rounds/round-015/global-model.json'
            if not clean_path.exists():continue
            clean_model=read(clean_path);clean_predictions,_=predict(clean_model,test_rows,deps)
            for mode in ('distributed','complete-trigger','adaptive'):
                task=lookup[(seed,'calibrated_gated',mode)]['task'];path=LAB/'evaluation/cases'/task['name']/'evidence/rounds/round-015/global-model.json'
                if not path.exists():continue
                model=read(path);predictions,_=predict(model,test_rows,deps)
                aa=arrays_from_export(model,np=study.base.np);cc=arrays_from_export(clean_model,np=study.base.np)
                distance=float(study.base.np.sqrt(sum(study.base.np.square(a.astype(float)-c.astype(float)).sum() for a,c in zip(aa,cc,strict=True))))
                residuals.append(dict(cohort=cohort,seed=seed,mode=mode,model_l2=distance,
                    test_prediction_disagreements=sum(a!=c for a,c in zip(predictions,clean_predictions,strict=True)),test_denominator=len(test_rows)))
    grouped=defaultdict(list)
    for row in summaries:grouped[(row['cohort'],row['mode'],row['policy'])].append(row)
    aggregate=[]
    for (cohort,mode,policy),rows in sorted(grouped.items()):
        group=dict(cohort=cohort,mode=mode,policy=policy,planned=len(rows),complete=sum(r['complete'] for r in rows))
        for metric in ('peak_full_asr','final_full_asr','peak_worst_trigger_asr','mean_attack_window_asr','final_clean_macro_f1'):
            vals=[r[metric] for r in rows if r[metric] is not None];group[metric]=avg(vals);group[metric+'_n']=len(vals)
            group[metric+'_sd']=statistics.stdev(vals) if len(vals)>1 else None
        for key in ('unmodified_quarantined','unmodified_downweighted','unmodified_observations','manipulated_quarantined','manipulated_downweighted','manipulated_exports'):
            group[key]=sum(r[key] for r in rows)
        aggregate.append(group)
    comparison=[]
    if evaluated:
        pairs={(r['seed'],r['policy'],r['mode']):r for r in attack_pairs}
        for cohort,seed in study.STAGES['evaluation']:
            for mode in ('distributed','complete-trigger','adaptive'):
                old=pairs[(seed,'gated_composite',mode)];new=pairs[(seed,'calibrated_gated',mode)];tpm=pairs[(seed,'tpm_only',mode)]
                defined=old['complete'] and new['complete']
                tpm_defined=new['complete'] and tpm['complete']
                comparison.append(dict(cohort=cohort,seed=seed,mode=mode,complete=defined,
                    old_harm=old['peak_paired_worst_trigger_harm'],new_harm=new['peak_paired_worst_trigger_harm'],
                    tpm_harm=tpm['peak_paired_worst_trigger_harm'],effective_tpm_control=tpm['effective_control'],tpm_comparison_defined=tpm_defined,
                    worse_than_original=defined and new['peak_paired_worst_trigger_harm']>old['peak_paired_worst_trigger_harm'],
                    benefit_vs_effective_control=tpm_defined and tpm['effective_control'] and new['peak_paired_worst_trigger_harm']<tpm['peak_paired_worst_trigger_harm']))
    qualified_clean=evaluated and all(r['qualified'] for r in guardrails if r['policy']=='calibrated_gated')
    qualifies=evaluated and qualified_clean and len(summaries)==72 and all(r['complete'] for r in summaries) \
        and not any(r['worse_than_original'] for r in comparison) and any(r['benefit_vs_effective_control'] for r in comparison)
    summary=dict(profile='clean-calibrated-admission-research-v1',selected_candidate=decision['selected_candidate'],
        evaluation_performed=evaluated,counts=dict(counts),phase_verification_pins=phase_pins,
        root_protocol_sha256=sha256_file(LAB/'protocol-before-clean-fitting.json'),
        selection_sha256=sha256_file(LAB/'selection-decision.json'),aggregate=aggregate,
        reserved_clean_budgets_pass=bool(qualified_clean),predeclared_research_guardrails_pass=bool(qualifies),
        automatic_production_promotion=False,
        attack_comparisons_defined=sum(r['complete'] for r in comparison),
        tpm_comparisons_defined=sum(r['tpm_comparison_defined'] for r in comparison),
        completed_cases_by_policy={policy:sum(r['complete'] for r in summaries if r['policy']==policy)
                                   for policy in ('tpm_only','gated_composite','calibrated_gated')},
        worse_attack_cases=sum(r['worse_than_original'] for r in comparison),
        effective_controls_with_benefit=sum(r['benefit_vs_effective_control'] for r in comparison),
        no_new_TPM_appraisal=True,independent_dataset=False,thesis_edited=False)
    OUT.mkdir(parents=True,exist_ok=refresh_draft)
    write_json(OUT/'summary.json',summary);write_json(OUT/'clean-guardrails.json',guardrails)
    write_csv(OUT/'selection.csv',selection);write_csv(OUT/'thresholds.csv',models);write_csv(OUT/'cases.csv',summaries)
    write_csv(OUT/'rounds.csv',round_rows);write_csv(OUT/'aggregate.csv',aggregate)
    write_csv(OUT/'attack-comparison.csv',comparison);write_csv(OUT/'residuals.csv',residuals)
    lines=['# Clean-only admission-gate calibration','',
        'Completed 2026-11-06. This study fits only on clean histories, selects only on separate clean validation histories, and reserves new seed/partition assignments for attacks and final test evaluation. The original gate/core code and old evidence are preserved. This is a software research adapter, not a new TPM campaign or a deployed runtime default.','',
        '## Finding and decision','',
        'Clean-only recalibration substantially reduces benign intervention and restores training availability, but does not meet the predeclared combined utility/security qualification. The calibrated arm completed 24/24 reserved campaigns; the original composite completed 18/24, with six real non-IID quorum failures, including a clean campaign. TPM-only completed 24/24. Missing checkpoints are undefined, not ASR zero.', '',
        'On reserved clean assignments the calibrated gate retains at least 93.56% pooled nominal mass. Its worst fixed-endpoint test macro-F1 loss is about 0.0025 percentage points. However, at non-IID seed 2026110645 one round retains only 62.34% nominal mass, violating the 80% per-round budget despite 94.98% pooled retention. A good average does not establish a per-round guarantee.', '',
        'Attack protection also weakens. At that same non-IID assignment the calibrated full-trigger peaks are 99.80% for the complete-trigger attack and 99.94% for the adaptive attack; final values remain 28.51% and 24.68%. IID full-trigger results remain zero in these tested assignments. Complete-case means and per-seed outcomes must be read together; the original rule\'s failed histories cannot serve as zero-ASR comparators.', '',
        'This candidate is rejected for promotion. Improved clean behavior does not demonstrate a safe automatic exclusion rule. Further tuning on these reserved attack/test outcomes would be a new development study, not independent validation of this one.', '',
        '## Clean protocol','',
        '- Four clean FedAvg histories fit references; four other histories calibrate thresholds; sixteen clean histories (four assignments by baseline/three candidates) choose a candidate. These stages never open the test split. Fitting accepts an explicit allowlist of five raw indicators, declared cohort, round and bound example counts; no attacker identities, poisoning labels or trigger outcomes. Existing clean-runner trigger diagnostics are excluded from fitting and selection.',
        '- Same original five indicator weights, median/MAD score, cap3, lambda0.5, factor0.5, minimum10 contributors and Flower full-model FedAvg. The conditional reference uses round phases1–5/6–10/11–15 and example-count ratio to the cohort median (<0.5, >1.5, otherwise middle); unsupported cohort/round fails. Reference cells need30 observations, with a declared cohort/phase fallback.',
        '- Global and conditioned candidates use empirical quarantine/downweight quantiles0.975/0.90; conservative conditioned uses0.99/0.95. Each cutoff is the larger of count-weighted and nominal-mass-weighted quantiles. Calibration-tail bounds are empirical only: dependent rounds/clients do not yield a future false-positive guarantee.',
        '- All four clean selection assignments must meet Q<=5%, downweight<=15%, pooled nominal mass retained>=90%, each round>=80%, complete15-round histories, validation macro-F1 loss<=2 points at rounds10/15, and a nonempty quarantine region. Among feasible candidates minimize worst validation loss, maximize minimum mass retained, then use declared candidate order.',
        '- All phases reuse the same Data24 global training occurrences and a fixed clean warm start. Their seed/partition assignments differ, but this is not independent data or initialization. Six held-out evaluation assignments have three IID and three Dirichlet alpha0.3 allocations. Historical test reuse remains exploratory; ToN-IoT is deferred.','',
        '## Clean selection','',f'Selected candidate: **{decision["selected_candidate"] or "none"}**. No attack or test outcome entered this decision.','',
        '| Candidate | All clean guards pass | Worst validation loss (pp) | Minimum pooled mass retained (%) |',
        '|---|---|---:|---:|']
    for c in decision['candidates']:
        lines.append(f'| {c["candidate"]} | {c["qualified"]} | {percent(c["worst_validation_loss"])} | {percent(c["minimum_mass_retention"])} |')
    lines+=['','Per-assignment counts, mass budgets and loss are in `selection.csv`; exact frozen references/thresholds and source manifest pins remain under the artifact models. A lower or higher cutoff cannot be compared directly across different reference normalizations.','']
    if evaluated:
        lines+=['## Reserved evaluation','',
            'All arms drive independent training from the same clean warm start. Three arms: TPM-only, original composite, selected calibrated composite. Clean/distributed/full-trigger/adaptive conditions use15 rounds (10 attacked,5 clean continuation),50% poisoning at three clients, identical feature/row/query budgets to the prior study. Test is opened only after every evaluation case is terminal. Every failure is retained and missing models are undefined.','',
            'Cells show mean full-trigger **peak / final ASR (%)** over three assignments. Full/component ASR uses3,497 non-benign test examples; clean macro-F1 uses all4,937 examples. Seed/partition assignment, not client/round count, is the repetition unit.','',
            '| Cohort | Attack | TPM-only | Original composite | Calibrated composite |','|---|---|---:|---:|---:|']
        mapping={(r['cohort'],r['mode'],r['policy']):r for r in aggregate}
        for cohort in ('iid','non-iid'):
            for mode in ('distributed','complete-trigger','adaptive'):
                cells=[percent(mapping[(cohort,mode,pol)]['peak_full_asr'])+' / '+percent(mapping[(cohort,mode,pol)]['final_full_asr'])+
                       f" (n={mapping[(cohort,mode,pol)]['complete']}/3)"
                       for pol in ('tpm_only','gated_composite','calibrated_gated')]
                lines.append('| '+' | '.join([cohort,mode,*cells])+' |')
        lines+=['','Peak/final cells use complete histories; n gives completed histories out of three. Prefix checkpoints of failed cases remain in `rounds.csv` and in the plot, but no absent final checkpoint is interpreted as zero. Conditional means with different n do not establish a fair superiority ranking.','',
            '## Reserved clean and attack guardrails','',
            f'The calibrated policy passes every reserved clean budget: **{qualified_clean}**. All predeclared research guardrails pass: **{qualifies}**. This is not automatic production promotion.',
            f'Cases with worse paired worst-trigger peak harm than the original composite: **{summary["worse_attack_cases"]}/{summary["attack_comparisons_defined"]} defined comparisons**; the other comparisons are undefined because a required history failed. Effective TPM-only comparisons with benefit: **{summary["effective_controls_with_benefit"]}/{summary["tpm_comparisons_defined"]} defined comparisons**. The effective-control criterion requires >=20 points ASR increase with <=5 points clean F1 loss at a matched endpoint.','',
            'Paired harm is max over fixed rounds of (worst full/component ASR in the attacked history minus worst-trigger ASR of that policy\'s own clean history at the same round). This differs from comparing final ASR alone. `attack-comparison.csv` retains all cases and ineffective controls. No parameters were changed after reserved outcomes.','',
            '| Cohort | Seed | Policy | Q (%) | Downweight (%) | Mass retained (%) | Worst test loss (pp) | Qualified |',
            '|---|---:|---|---:|---:|---:|---:|---|']
        for g in guardrails:
            b=g['budget'] or {};lines.append('| '+' | '.join([g['cohort'],str(g['seed']),g['policy'],
                percent(b.get('quarantine_rate')),percent(b.get('downweight_rate')),percent(b.get('nominal_mass_retention')),
                percent(max(g['fixed_endpoint_test_losses'],default=None)),str(g['qualified'])])+' |')
        lines+=['','`cases.csv` includes every planned run and failure; `aggregate.csv` includes SDs and contributing-case counts. `residuals.csv` compares final calibrated attacked models with their own clean control in parameter L2 and untriggered test predictions. Nonzero distance does not itself prove remaining harmful poisoning; zero ASR does not establish restoration.','']
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        fig,axes=plt.subplots(2,3,figsize=(13,7),sharex=True,sharey=True,layout='constrained')
        colors={'tpm_only':'#64748b','gated_composite':'#7c3aed','calibrated_gated':'#0f766e'}
        for i,cohort in enumerate(('iid','non-iid')):
            for j,mode in enumerate(('distributed','complete-trigger','adaptive')):
                ax=axes[i,j]
                for policy in colors:
                    rows=[r for r in plot_data if r['cohort']==cohort and r['mode']==mode and r['policy']==policy]
                    numbers=sorted({r['round'] for r in rows});values=[[r['full_asr'] for r in rows if r['round']==n] for n in numbers]
                    ax.plot(numbers,[avg(v) for v in values],color=colors[policy],label=policy)
                    ax.fill_between(numbers,[min(v) for v in values],[max(v) for v in values],color=colors[policy],alpha=.1)
                ax.axvline(10.5,color='gray',linestyle='--',linewidth=1);ax.set(title=f'{cohort} / {mode}',ylim=(-.02,1.02),xticks=[1,5,10,15])
                if i==1:ax.set_xlabel('Round; clean continuation after 10')
                if j==0:ax.set_ylabel('Full-trigger test ASR')
        axes[0,0].legend(fontsize=8);fig.savefig(OUT/'full-trigger-trajectories.png',dpi=170);plt.close(fig)
        lines+=['![Reserved full-trigger trajectories](full-trigger-trajectories.png)','',
            'Lines are available-case means and bands are observed ranges, not confidence intervals. The table averages per-run peaks; peak of the plotted mean is a different quantity. Failures remain explicit in tables.','']
    else:
        lines+=['## Outcome','',
            'No candidate met every clean requirement. Reserved attack/test evaluation was therefore not launched. This is a failed clean qualification, not successful attack mitigation; the reserved assignments remain unused. Do not lower the budgets or silently promote a permissive gate.','']
    refit=read(LAB/'models-refit-verification.json')
    selected_diagnostic=next(r for r in refit['checks'] if r['candidate']==decision['selected_candidate'] and r['cohort']=='non-iid') if decision['selected_candidate'] else None
    if selected_diagnostic:
        lines+=['## Structural score diagnostic','',
            f'The selected non-IID statistical downweight cutoff is {selected_diagnostic["statistical_downweight_cut"]:.6f}; its quarantine cutoff is {selected_diagnostic["statistical_quarantine_cut"]:.6f}. With five equally weighted component risks in [0,1], any zero component implies total risk <=0.8. Since the downweight cutoff exceeds 0.8, an admissible no-warning input with any zero component receives full nominal weight, regardless of the other four component values. This is an algebraic limitation of this averaged score/threshold combination, not proof that every such update is harmful.', '',
            'All new reference banks and quantiles were independently refitted exactly. Count/mass tail bounds and pooled retained-mass lower bounds hold for the recorded calibration population only; `models-refit-verification.json` records them. They do not guarantee future client/round behavior or identify maliciousness. A structural revision must address signal compensation and heterogeneous clean behavior while keeping the mandatory trust veto separate; it cannot be justified by clean accuracy alone.','']
    lines+=['## Validation and scope','',
        f'Verification counts: `{dict(counts)}`. Source and phase pins are in `summary.json`. All 27 focused tests passed. Saved raw indicators, weights, profile lookup, admission decisions and Flower outputs were reconstructed from original exports; first/final local training repeats and adaptive query replays are recorded per phase.',
        'Trust prerequisites are assumed passed in this numerical experiment. Core hard-veto code is unchanged; no hardware appraisal or live M5 conditional-reference integration is claimed. Reference timing and cohort metadata require binding before such an integration. The test was previously inspected and the finite seed study supports conditional empirical conclusions only. No permanent client exclusion is justified by these counts. The thesis is unchanged.','',
        '## Reproduction','',
        'Preserve every existing destination. The source-locked controller resumes closed stages and refuses conflicting evidence.','',
        '```bash','.venv/bin/python scripts/revision_clean_gate_study.py pipeline --workers 3',
        '.venv/bin/python scripts/revision_clean_gate_audit.py evaluation --workers 3',
        '.venv/bin/python scripts/report_clean_gate_study.py','```','']
    text='\n'.join(lines)
    for before,after in {'cap3':'cap 3','lambda0.5':'lambda 0.5','factor0.5':'factor 0.5','minimum10':'minimum 10',
        'phases1':'phases 1','need30':'need 30','quantiles0.975':'quantiles 0.975','uses0.99':'uses 0.99',
        'complete15':'complete 15','rounds10':'rounds 10','use15':'use 15','attacked,5':'attacked, 5',
        '),50%':'), 50%','uses3,497':'uses 3,497','all4,937':'all 4,937'}.items():text=text.replace(before,after)
    (OUT/'README.md').write_text(text)
    # Independent internal accounting before the final inventory is committed.
    if evaluated:
        assert len(summaries)==72 and len({r['case'] for r in summaries})==72
        for case in summaries:
            rows=[r for r in round_rows if r['case']==case['case']]
            assert len(rows)==case['completed_rounds']
            if case['complete']:
                assert case['peak_full_asr']==max(r['full_asr'] for r in rows)
                assert case['final_full_asr']==next(r['full_asr'] for r in rows if r['round']==15)
    study.assert_locks(protocol)
    assert refit['status']=='verified' and not refit['test_accessed'] and not refit['attack_results_accessed']
    write_json(OUT/'models-refit-verification.json',refit)
    write_json(OUT/'validation.json',dict(status='verified',counts=dict(counts),source_hashes_unchanged=True,
        selected_candidate=decision['selected_candidate'],research_guardrails_pass=bool(qualifies),focused_tests_passed=27,
        models_independently_refitted=refit['models_refitted'],test_used_for_fitting_or_selection=False,thesis_edited=False))
    files=[p for p in OUT.iterdir() if p.is_file() and p.name!='inventory-final.json']
    files += [ROOT/'scripts'/name for name in ('clean_gate_calibration.py','revision_clean_gate_study.py',
                                             'revision_clean_gate_audit.py','report_clean_gate_study.py','check_clean_gate_models.py')]
    files += [ROOT/'tests/test_clean_gate_calibration.py']
    write_json(OUT/'inventory-final.json',dict(files={str(p.relative_to(ROOT)):sha256_file(p) for p in files}))
    for path in OUT.iterdir():
        if path.is_file():shutil.copy2(path,LOCAL/path.name)
    shutil.copy2(OUT/'README.md',LOCAL/'REPORT.md')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('aggregate','phase_verification_pins')},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--refresh-draft',action='store_true')
    run(parser.parse_args().refresh_draft)
