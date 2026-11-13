"""Publish every staged result of the structural severe-tail gate study."""
from __future__ import annotations
import argparse,csv,json,statistics,shutil
from collections import defaultdict,Counter
from fractions import Fraction
from pathlib import Path
import os
import revision_severe_gate_study as study
import severe_gate_calibration as cal
from revision_study_data import read
from revision_dba_experiment import predict
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import dependencies,arrays_from_export

ROOT,LAB=study.ROOT,study.LAB
OUT=ROOT/'results/gates-probes/revision-severe-tail-gate-v1'
LOCAL=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'severe-gate-20261106')
METHODS=('tpm_only','gated_composite','mean_control','severe_gate')


def js(path,data):path.write_text(json.dumps(data,indent=2,sort_keys=True,allow_nan=False)+'\n')
def avg(values):
    values=[x for x in values if x is not None]
    return statistics.mean(values) if values else None
def pc(v):return 'undefined' if v is None else f'{100*v:.2f}'
def table(path,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)
def copy_preserved(source,destination):
    # Immutable diagnostic copies can be read-only on both filesystems.
    # An identical copy needs no rewrite and retains its original attributes.
    if destination.exists() and sha256_file(source)==sha256_file(destination):return
    shutil.copy2(source,destination)


def run(refresh=False):
    assert not (OUT/'publication-verification.json').exists(),'Preserve independently closed publication'
    assert not OUT.exists() or refresh,'Preserve published study'
    protocol=read(LAB/'protocol-before-clean-fitting.json');study.assert_locks(protocol)
    decision=read(LAB/'selection-decision.json');refit=read(LAB/'models-refit-verification.json')
    assert refit['status']=='verified' and not refit['test_accessed'] and not refit['attack_results_accessed']
    assert '33 passed, 2 warnings' in (LAB/'focused-tests.log').read_text(),'Focused test receipt missing'
    counts=Counter();phase_pins={};selection=[];thresholds=[]
    for candidate in decision['candidates']:
        for detail in candidate['details']:
            selection.append(dict(candidate=candidate['candidate'],seed=detail['seed'],cohort=detail['cohort'],
                complete=detail['complete'],qualified=detail['qualified'],**(detail['budget'] or {}),
                worst_validation_loss=max(detail['validation_losses'],default=None)))
    for candidate in (*cal.CANDIDATES,'mean_control'):
        path=LAB/'models'/f'{candidate}.json';model=read(path)
        for cohort,limits in model['thresholds'].items():
            thresholds.append(dict(candidate=candidate,cohort=cohort,profile=model['profile'],model_sha256=sha256_file(path),**limits))
    for phase in ('fit','calibration','selection'):
        path=LAB/phase/'verified/summary.json';verified=read(path);assert verified['status']=='verified' and not verified['test_accessed']
        phase_pins[phase]=sha256_file(path);counts['development_cases']+=len(verified['cases'])
        for case in verified['cases']:
            for key in ('rounds','queries','local_repeats'):counts['development_'+key]+=case['verification'][key]
    evaluated=decision['selected_candidate'] is not None
    cases=[];rounds=[];guards=[];effects=[];comparisons=[];residuals=[];alarms=Counter()
    if evaluated:
        path=LAB/'evaluation/verified/summary.json';audit=read(path);assert audit['status']=='verified' and audit['test_accessed']
        phase_pins['evaluation']=sha256_file(path);assert len(audit['cases'])==96
        lookup={(c['task']['seed'],c['task']['method'],c['task']['mode']):c for c in audit['cases']}
        for case in audit['cases']:
            task=case['task'];method=task['method'];rows=case['rows'];mapping={r['round']:r for r in rows}
            for key in ('rounds','queries','local_repeats'):counts['evaluation_'+key]+=case['verification'][key]
            metrics=Counter();timings=defaultdict(list)
            for row in rows:
                modified=set(row['actually_manipulated_clients'])
                for c,status in row['statuses'].items():
                    prefix='manipulated' if c in modified else 'unmodified'
                    metrics[prefix+'_observations']+=1
                    metrics[prefix+'_quarantined']+=int(status.endswith('quarantined'))
                    metrics[prefix+'_downweighted']+=int(status=='accepted_downweighted')
                    metrics[prefix+'_nominal_examples']+=row['example_counts'][c]
                    metrics[prefix+'_retained_mass']+=Fraction(row['masses'][c])
                for key,value in row['timing'].items():
                    if value is not None:timings[key].append(value)
                rounds.append(dict(case=task['name'],cohort=task['cohort'],seed=task['seed'],method=method,mode=task['mode'],
                    round=row['round'],full_asr=row['test']['complete_trigger']['asr'],worst_trigger_asr=study.base.scalar_asr(row['test']),
                    clean_macro_f1=row['test']['clean']['macro_f1_all_model_classes'],selected_alpha=row['selected_alpha']))
                if method=='severe_gate':
                    source=LAB/'evaluation/cases'/task['name']/'evidence/rounds'/f'round-{row["round"]:03d}'/'gate-state.json'
                    state=read(source)
                    for c,detail in state['severe_tail_details'].items():
                        assert state['calibrated_scores'][c]['components']==[]
                        assert detail['bounded_risk']==state['calibrated_scores'][c]['risk']
                        if detail['quarantine_alarm_indicators']:
                            assert row['statuses'][c]=='statistically_quarantined'
                            alarms['actual_component_alarm_decisions']+=1
                            for name in detail['quarantine_alarm_indicators']:alarms[name]+=1
            summary=dict(case=task['name'],cohort=task['cohort'],seed=task['seed'],method=method,
                decision_policy=task['policy'],candidate=task['candidate'],mode=task['mode'],
                complete=case['complete'],completed_rounds=len(rows),failure=case['failure'] or case['source_exception'],
                peak_full_asr=max((r['test']['complete_trigger']['asr'] for r in rows),default=None) if case['complete'] else None,
                peak_worst_asr=max((study.base.scalar_asr(r['test']) for r in rows),default=None) if case['complete'] else None,
                observed_prefix_peak_asr=max((r['test']['complete_trigger']['asr'] for r in rows),default=None),
                final_full_asr=mapping[15]['test']['complete_trigger']['asr'] if 15 in mapping else None,
                final_clean_macro_f1=mapping[15]['test']['clean']['macro_f1_all_model_classes'] if 15 in mapping else None,
                **{name:metrics[name] for name in ('unmodified_observations','unmodified_quarantined','unmodified_downweighted',
                                                  'manipulated_observations','manipulated_quarantined','manipulated_downweighted',
                                                  'unmodified_nominal_examples','manipulated_nominal_examples')},
                unmodified_retained_mass=float(metrics['unmodified_retained_mass']),
                manipulated_retained_mass=float(metrics['manipulated_retained_mass']),
                **{'median_'+name:statistics.median(values) for name,values in timings.items()})
            cases.append(summary)
        for cohort,seed in study.STAGES['evaluation']:
            tpm_clean=lookup[(seed,'tpm_only','clean')];tpm_rows={r['round']:r for r in tpm_clean['rows']}
            for method in METHODS:
                clean=lookup[(seed,method,'clean')];cb={r['round']:r for r in clean['rows']}
                budget=cal.budget_summary(clean['rows']) if clean['rows'] else None
                losses=[tpm_rows[n]['test']['clean']['macro_f1_all_model_classes']-cb[n]['test']['clean']['macro_f1_all_model_classes']
                        for n in (10,15) if n in tpm_rows and n in cb]
                qualified=clean['complete'] and tpm_clean['complete'] and budget['quarantine_rate']<=.05 and budget['downweight_rate']<=.15 \
                    and budget['nominal_mass_retention']>=.90 and budget['minimum_round_mass_retention']>=.80 and max(losses)<=.02
                guards.append(dict(cohort=cohort,seed=seed,method=method,complete=clean['complete'],budget=budget,
                                   test_f1_losses=losses,qualified=bool(qualified)))
                for mode in ('distributed','complete-trigger','adaptive'):
                    attacked=lookup[(seed,method,mode)];pairs=[]
                    for row in attacked['rows']:
                        if row['round'] in cb:
                            a=row['test'];c=cb[row['round']]['test']
                            pairs.append((study.base.scalar_asr(a)-study.base.scalar_asr(c),
                                c['clean']['macro_f1_all_model_classes']-a['clean']['macro_f1_all_model_classes']))
                    effects.append(dict(cohort=cohort,seed=seed,method=method,mode=mode,
                        complete=clean['complete'] and attacked['complete'],
                        observed_peak_paired_harm=max((p[0] for p in pairs),default=None),
                        effective_control=any(h>=.20 and loss<=.05 for h,loss in pairs)))
        effect={(r['seed'],r['method'],r['mode']):r for r in effects}
        for cohort,seed in study.STAGES['evaluation']:
            for mode in ('distributed','complete-trigger','adaptive'):
                proposed=effect[(seed,'severe_gate',mode)];mean=effect[(seed,'mean_control',mode)]
                old=effect[(seed,'gated_composite',mode)];tpm=effect[(seed,'tpm_only',mode)]
                defined=proposed['complete'] and mean['complete'];old_defined=proposed['complete'] and old['complete']
                tpm_defined=proposed['complete'] and tpm['complete']
                comparisons.append(dict(cohort=cohort,seed=seed,mode=mode,mean_comparison_defined=defined,
                    original_comparison_defined=old_defined,tpm_comparison_defined=tpm_defined,
                    proposed_harm=proposed['observed_peak_paired_harm'],mean_harm=mean['observed_peak_paired_harm'],
                    original_harm=old['observed_peak_paired_harm'],tpm_harm=tpm['observed_peak_paired_harm'],
                    effective_tpm_control=tpm['effective_control'],
                    worse_than_mean=defined and proposed['observed_peak_paired_harm']>mean['observed_peak_paired_harm'],
                    worse_than_original=old_defined and proposed['observed_peak_paired_harm']>old['observed_peak_paired_harm'],
                    strict_mean_benefit_in_effective_control=defined and tpm['effective_control'] and
                        proposed['observed_peak_paired_harm']<mean['observed_peak_paired_harm']))
        # A zero ASR is not silently called model restoration.
        deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
        test_rows=read(ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1/server/splits/test.json')['rows']['test']
        for cohort,seed in study.STAGES['evaluation']:
            clean=lookup[(seed,'severe_gate','clean')];cp=LAB/'evaluation/cases'/clean['task']['name']/'evidence/rounds/round-015/global-model.json'
            if not cp.exists():continue
            cmodel=read(cp);pred,_=predict(cmodel,test_rows,deps);ca=arrays_from_export(cmodel,np=study.base.np)
            for mode in ('distributed','complete-trigger','adaptive'):
                attacked=lookup[(seed,'severe_gate',mode)];path=LAB/'evaluation/cases'/attacked['task']['name']/'evidence/rounds/round-015/global-model.json'
                if not path.exists():continue
                model=read(path);p,_=predict(model,test_rows,deps);a=arrays_from_export(model,np=study.base.np)
                residuals.append(dict(cohort=cohort,seed=seed,mode=mode,
                    clean_model_sha256=sha256_file(cp),attacked_model_sha256=sha256_file(path),
                    parameter_l2=float(study.base.np.sqrt(sum(study.base.np.square(x.astype(float)-y.astype(float)).sum() for x,y in zip(a,ca,strict=True)))),
                    prediction_disagreements=sum(x!=y for x,y in zip(p,pred,strict=True)),test_denominator=len(test_rows)))
    groups=defaultdict(list)
    for case in cases:groups[(case['cohort'],case['mode'],case['method'])].append(case)
    aggregate=[]
    for (cohort,mode,method),values in sorted(groups.items()):
        r=dict(cohort=cohort,mode=mode,method=method,planned=len(values),complete=sum(v['complete'] for v in values))
        for name in ('peak_full_asr','peak_worst_asr','final_full_asr','final_clean_macro_f1'):
            vs=[v[name] for v in values if v[name] is not None];r[name]=avg(vs);r[name+'_n']=len(vs)
            r[name+'_sd']=statistics.stdev(vs) if len(vs)>1 else None
        aggregate.append(r)
    interventions=[];costs=[]
    for cohort in ('iid','non-iid'):
        for method in METHODS:
            attacked=[c for c in cases if c['cohort']==cohort and c['method']==method and c['mode']!='clean']
            if not attacked:continue
            total={key:sum(c[key] for c in attacked) for key in (
                'manipulated_observations','manipulated_quarantined','manipulated_downweighted',
                'unmodified_observations','unmodified_quarantined','unmodified_downweighted',
                'unmodified_nominal_examples','manipulated_nominal_examples',
                'unmodified_retained_mass','manipulated_retained_mass')}
            interventions.append(dict(cohort=cohort,method=method,completed_histories=sum(c['complete'] for c in attacked),
                **total,unmodified_mass_retention=total['unmodified_retained_mass']/total['unmodified_nominal_examples'],
                manipulated_mass_retention=total['manipulated_retained_mass']/total['manipulated_nominal_examples']
                    if total['manipulated_nominal_examples'] else None))
            rs=[r for c in audit['cases'] if c['task']['cohort']==cohort and c['task']['method']==method for r in c['rows']]
            costs.append(dict(cohort=cohort,method=method,observed_rounds=len(rs),**{
                key:statistics.median(r['timing'][key] for r in rs if r['timing'].get(key) is not None)
                for key in ('indicator_geometry_seconds','validation_inference_seconds','score_and_all_policy_decisions_seconds',
                            'clean_calibration_seconds','aggregation_seconds','attack_search_seconds')
                if any(r['timing'].get(key) is not None for r in rs)}))
    clean_ok=evaluated and all(g['qualified'] for g in guards if g['method']=='severe_gate')
    full=evaluated and sum(c['complete'] for c in cases if c['method']=='severe_gate')==24
    mean_defined=sum(c['mean_comparison_defined'] for c in comparisons)
    benefits=[c for c in comparisons if c['strict_mean_benefit_in_effective_control']]
    qualified=bool(evaluated and clean_ok and full and mean_defined==18 and not any(c['worse_than_mean'] for c in comparisons)
                   and len(benefits)>=2 and any(c['cohort']=='non-iid' for c in benefits))
    reasons=[]
    if not evaluated:reasons.append('No candidate passed every clean selection guard; reserved evaluation was not launched.')
    else:
        if not full:reasons.append('At least one proposed history did not complete all 15 rounds.')
        if not clean_ok:reasons.append('At least one reserved clean utility, intervention or mass budget failed.')
        if mean_defined!=18:reasons.append(f'Only {mean_defined}/18 matched-average comparisons are fully defined.')
        if any(c['worse_than_mean'] for c in comparisons):reasons.append('The proposed gate has greater paired peak harm than the matched average in at least one reserved case.')
        if len(benefits)<2:reasons.append('Fewer than two strict improvements over the matched average occur in effective-control cases.')
        if not any(c['cohort']=='non-iid' for c in benefits):reasons.append('No strict matched-average benefit is demonstrated in an effective non-IID control case.')
    summary=dict(profile='structural-severe-tail-gate-report-v1',selected_candidate=decision['selected_candidate'],
        evaluation_performed=evaluated,counts=dict(counts),phase_pins=phase_pins,
        root_protocol_sha256=sha256_file(LAB/'protocol-before-clean-fitting.json'),selection_sha256=sha256_file(LAB/'selection-decision.json'),
        posthoc_diagnosis_sha256=sha256_file(LAB/'posthoc-diagnosis/summary.json') if evaluated else None,
        clean_guardrails_pass=bool(clean_ok),proposed_cases_complete=bool(full),research_guardrails_pass=qualified,
        failed_research_criteria=reasons,
        automatic_production_promotion=False,mean_comparisons_defined=mean_defined,
        original_comparisons_defined=sum(c['original_comparison_defined'] for c in comparisons),
        worse_mean_cases=sum(c['worse_than_mean'] for c in comparisons),worse_original_cases=sum(c['worse_than_original'] for c in comparisons),
        effective_control_mean_benefits=len(benefits),completed_by_method={m:sum(c['complete'] for c in cases if c['method']==m) for m in METHODS},
        actual_alarms=dict(alarms),aggregate=aggregate,new_TPM_appraisals=0,thesis_edited=False,
        models_refitted=refit['models_independently_refitted'],independent_dataset=False)
    OUT.mkdir(parents=True,exist_ok=refresh)
    for name,rows in [('selection.csv',selection),('thresholds.csv',thresholds),('cases.csv',cases),('rounds.csv',rounds),
                      ('aggregate.csv',aggregate),('attack-comparison.csv',comparisons),('residuals.csv',residuals),
                      ('interventions.csv',interventions),('costs.csv',costs)]:table(OUT/name,rows)
    js(OUT/'summary.json',summary);js(OUT/'clean-guardrails.json',guards);js(OUT/'models-refit-verification.json',refit)
    diagnosis=read(LAB/'posthoc-diagnosis/summary.json') if evaluated else None
    if diagnosis:
        assert diagnosis['status']=='verified' and diagnosis['posthoc'] and not diagnosis['new_fitting_or_threshold_changes']
        assert diagnosis['source_verification_sha256']==sha256_file(LAB/'evaluation/verified/summary.json')
        with (LAB/'posthoc-diagnosis/same-input-counterfactuals.csv').open(newline='') as stream:
            same_input=list(csv.DictReader(stream))
    lines=['# Non-compensatory severe-tail admission study','',
        'Completed 2026-11-06. This is a structural research revision of statistical admission, with the original mandatory trust veto and full-model Flower FedAvg retained. Production defaults, old experimental evidence and the thesis were not edited. Trust validity is assumed in these numerical experiments; no new TPM appraisal is claimed.','',
        '**Outcome:** '+('All predeclared research guards passed in this bounded study. This does not automatically promote the profile into production.' if qualified else 'The proposed profile does not meet every predeclared research guard. '+' '.join(reasons)), '',
        '## Rule and precise property','',
        'The previous capped equal-weight mean had a concrete blind region: if one of five components was zero, the average could not exceed0.8 even when the other four saturated. A quarantine cutoff above0.8 therefore could not fire in that situation. This revision removes both the former saturation and the averaging step. It does not assume that every successful attack creates a severe statistical tail.',
        'For each original server-visible indicator, compute an adverse deviation from its conditioned clean median. Scale by max(1.4826*MAD,1e-9*max(1,abs(median))), retain log(1+deviation/scale) without the former z cap, and divide by its clean per-indicator 95th-tail normalizer (at least1). Fuse the five values by their maximum M. The bounded display score M/(1+M) is monotone and is not a probability.',
        'A component above the operational quarantine threshold forces the maximum above it regardless of the other four components. A normal component cannot cancel a severe alarm. The original G=0 trust veto remains prior to statistical acceptance. These are conditional algebraic/implementation properties, not guarantees that every poison update is an outlier or every outlier malicious.',
        'Full per-component evidence is stored in severe_tail_details. The additive weighted-component schema is intentionally absent from the new signal; it would misdescribe a maximum. Reference/profile/model hashes, decisions and actual ordered weights remain replayable.','',
        '## Frozen clean-only protocol','',
        '- Eight clean FedAvg histories fit references, eight other clean histories calibrate per-indicator and joint tails; eighteen clean histories select between max_tail and max_tail_conservative against TPM-only on six separate assignments. None of these stages opens test. No attacker identities or trigger outcomes enter fitting/selection.',
        '- Reference groups use declared cohort, campaign-round phase (1–5/6–10/11–15) and example count relative to the cohort median (<.5, >1.5, otherwise middle), with minimum30 clean observations and declared fallback. Counts must be bound metadata, not unverified client claims. Unknown cohort/round is unsupported.',
        '- Tail cutoffs use the larger count- and nominal-mass-weighted empirical quantiles. max_tail uses Q=.975,D=.90; conservative uses Q=.99,D=.95. These yield arithmetic bounds for the recorded calibration population, not future false-positive guarantees under dependent client/round observations.',
        '- Every clean selection assignment must have Q<=5%,D<=15%,pooled nominal mass retained>=90%,each round>=80%,complete training and <=2 percentage-point validation F1 loss at rounds10/15. Rank feasible candidates by worst validation loss, then minimum mass retained, then fixed order. Failed candidates remain reported.',
        '- Same Data24 global training rows, fixed clean warm start, scaler and class weights; independently reserved seed/partition assignments per stage, not independent datasets or initializations. Three IID and three Dirichlet alpha.3 evaluation assignments. The historical test split was previously inspected, so results are exploratory.', '',
        f'Selected candidate: **{decision["selected_candidate"] or "none"}**.','',
        '| Candidate | Clean qualification | Worst validation loss (pp) | Minimum pooled mass retained (%) |',
        '|---|---|---:|---:|']
    for c in decision['candidates']:lines.append(f'| {c["candidate"]} | {c["qualified"]} | {pc(c["worst_validation_loss"])} | {pc(c["minimum_mass_retention"])} |')
    if evaluated:
        mapping={(a['cohort'],a['mode'],a['method']):a for a in aggregate}
        lines+=['','## Reserved four-method evaluation','',
            'Four methods drive independent histories: TPM-only, original composite, the previous conservative capped-average recipe fitted on the SAME fresh clean histories, and the selected severe-tail gate. This tests the combined tail/fusion revision; it does not independently isolate every changed subcomponent. The mean control is never selectable as the proposed gate.',
            'Each method/assignment has clean, distributed DBA, complete-trigger and defender-specific adaptive branches:96 planned histories,15 rounds each,attacks1–10 then5 clean continuation. Same50% poisoned row budget at three clients,features13/17/24 at12,and six adaptive alpha queries0,.25,.5,1,2,4. Adaptive exports interpolate/extrapolate from clean toward poisoned local models; alpha=0 is an unmodified export and alpha>1 is model scaling beyond the poisoned endpoint. The search maximizes worst full/component validation ASR, breaking ties by fewer attacker quarantines and larger alpha; it does not constrain clean F1. Effective-control qualification checks clean F1 separately. Triggers act in standardized feature space; PCAP realizability is not claimed. Test is evaluated only after all training cases are terminal.','',
            'Cells show **mean full-trigger peak / final ASR (%) [completed/3]**. Means exclude undefined full histories; prefix results/failures are preserved, never imputed as zero. Full/component ASR uses3,497 non-benign test examples; clean F1 uses4,937.','',
            '| Cohort | Attack | TPM-only | Original composite | Fresh mean control | Severe-tail gate |','|---|---|---:|---:|---:|---:|']
        for cohort in ('iid','non-iid'):
            for mode in ('distributed','complete-trigger','adaptive'):
                cells=[]
                for m in METHODS:
                    a=mapping[(cohort,mode,m)];cells.append(pc(a['peak_full_asr'])+' / '+pc(a['final_full_asr'])+f' [{a["complete"]}/3]')
                lines.append('| '+' | '.join([cohort,mode,*cells])+' |')
        failures=[c for c in cases if not c['complete']]
        if failures:
            lines+=['','Incomplete histories (no full-horizon ASR is inferred):','']
            for c in failures:
                failure=c['failure']
                reason=f'{failure["reason"]} at attempted round {failure["round"]}' if isinstance(failure,dict) else str(failure)
                lines.append(f'- `{c["case"]}`: {c["completed_rounds"]} completed rounds; {reason}.')
        lines+=['','## Predeclared guards','',f'Proposed histories all complete: **{full}**. Every reserved clean/test budget passes: **{clean_ok}**. Combined research guards pass: **{qualified}**. No automatic production promotion.',
            f'Primary mean-control comparisons defined: **{mean_defined}/18**; proposed harm is worse in **{summary["worse_mean_cases"]}**. Strict mean-control benefits in effective-control cases: **{len(benefits)}**, including **{sum(c["cohort"]=="non-iid" for c in benefits)}** non-IID cases. Original-composite comparisons defined: **{summary["original_comparisons_defined"]}/18**; proposed harm is worse in **{summary["worse_original_cases"]}**. Undefined original comparisons cannot establish equivalence or superiority.',
            'Paired harm is the maximum over fixed rounds of attacked worst full/component-trigger ASR minus the same method\'s own clean worst-trigger ASR at that round. An effective TPM-only control needs at least20 points paired ASR increase with at most5 points clean F1 loss. Do not infer prevention from final ASR alone. Negative clean F1 loss means improvement; mass and intervention budgets are still checked independently.','',
            '| Cohort | Seed | Method | Complete | Q (%) | Downweight (%) | Mass retained (%) | Minimum round (%) | Worst test loss (pp) | Qualified |',
            '|---|---:|---|---|---:|---:|---:|---:|---:|---|']
        for g in guards:
            b=g['budget'] or {};lines.append('| '+' | '.join([g['cohort'],str(g['seed']),g['method'],str(g['complete']),
                pc(b.get('quarantine_rate')),pc(b.get('downweight_rate')),pc(b.get('nominal_mass_retention')),
                pc(b.get('minimum_round_mass_retention')),pc(max(g['test_f1_losses'],default=None)),str(g['qualified'])])+' |')
        lines+=['','## Post-hoc failure diagnosis','',
            'This analysis was added after the reserved evaluation closed. It explains observed failures; it is not clean calibration or validation of another tuned gate. No model, cutoff or production setting was changed.', '',
            'The clean mass failures concentrate on large, highly skewed but unmodified clients. Client counts alone do not protect nominal FedAvg mass:', '',
            '| Non-IID seed | Clean pooled mass retained (%) | Minimum round (%) | Main excluded clean client | Nominal share (%) | Q rounds /15 | Downweight rounds /15 | Largest local class (%) |',
            '|---:|---:|---:|---|---:|---:|---:|---|']
        for r in diagnosis['clean_mass_failures']:
            c=r['largest_loss_client']
            lines.append('| '+' | '.join([str(r['seed']),pc(r['pooled_mass_retention']),pc(r['minimum_round_mass_retention']),
                c['client'],pc(c['nominal_fraction']),str(c['quarantined_rounds']),str(c['downweighted_rounds']),
                c['largest_class']+' ('+pc(c['largest_class_fraction'])+')'])+' |')
        lines+=['','Conditioning on cohort, phase and size did not cover these held-out clean trajectories. Local class composition is inspected here only to describe the failure; it was not an extra admission input. This supports further work on representative clean references and influence concentration, without proving class skew is the sole cause.', '',
            'For each of all18 attacked proposed histories, a separate diagnostic selects its first worst-trigger checkpoint and applies four numerical rules to the **same saved updates and parent checkpoint**. The table below shows the two histories that worsened against the matched-average trajectory. These direct alternatives do not retrain later rounds and must not be substituted for complete alternate trajectories.', '',
            '| Seed | Attack | Round | Same-input alternative | Full ASR (%) | Manipulated coefficient mass (%) | Unmodified nominal mass lost (%) |',
            '|---:|---|---:|---|---:|---:|---:|']
        worsened={(r['seed'],r['mode']) for r in comparisons if r['worse_than_mean']}
        for r in same_input:
            if (int(r['seed']),r['mode']) in worsened:
                lines.append('| '+' | '.join([r['seed'],r['mode'],r['round'],r['same_input_alternate_method'],
                    pc(float(r['full_asr'])) if r['full_asr'] else 'undefined',
                    pc(float(r['manipulated_coefficient_mass'])) if r['manipulated_coefficient_mass'] else 'undefined',
                    pc(float(r['unmodified_nominal_mass_lost']))])+' |')
        lines+=['','For seed2026110735, the direct proposed reweighting at round10 raises full-trigger ASR from59.88% with all same-input nominal weights to66.63%, while manipulated coefficient mass rises from12.08% to14.50%. The much larger difference between complete trajectories also includes their earlier training histories; this one-round comparison does not attribute that entire difference to a single exclusion.',
            'For seed2026110734 adaptive, manipulated updates still hold45.95% of the proposed round10 coefficient mass and the worst-trigger ASR is99.97%. Three designated clients are20% of identities but45.69% of nominal example mass in this assignment. The same-input original rule assigns them zero coefficient mass, yet full-trigger ASR remains98.46% on that already affected parent/updates. Retrospective removal in a late round is not clean multi-round recovery.',
            'The actionable distinction is between indicator non-compensation, representativeness of clean calibration, concentration of actual influence, and accumulated contamination. A maximum repairs the first item. This study does not resolve the other three. A future rule must specify a mass/concentration safeguard and a visible defer/reject outcome when its support is inadequate, then validate any robust aggregation or recovery path on newly reserved histories. Forced admission to satisfy a mass floor would contradict the current severe-alarm guarantee.','']
        lines+=['','## Residual difference from the paired clean model','',
            'Each proposed attacked endpoint is compared with the same seed/partition\'s independently trained proposed clean branch at round 15. A low or zero ASR is not a claim of exact restoration or unlearning. Parameter L2 and clean-test prediction disagreements are descriptive paired measurements, not causal attribution of individual parameters. All compared endpoints must exist; absent endpoints remain absent.', '',
            '| Cohort | Attack | Endpoints | Mean parameter L2 | Maximum parameter L2 | Nonidentical models | Clean prediction disagreements (min–max /4,937) |',
            '|---|---|---:|---:|---:|---:|---:|']
        for cohort in ('iid','non-iid'):
            for mode in ('distributed','complete-trigger','adaptive'):
                rs=[r for r in residuals if r['cohort']==cohort and r['mode']==mode]
                if rs:
                    lines.append('| '+' | '.join([cohort,mode,str(len(rs)),f'{avg(r["parameter_l2"] for r in rs):.6g}',
                        f'{max(r["parameter_l2"] for r in rs):.6g}',str(sum(r['parameter_l2']>0 for r in rs)),
                        f'{min(r["prediction_disagreements"] for r in rs)}–{max(r["prediction_disagreements"] for r in rs)}'])+' |')
        lines+=['','## Exported-update interventions and measured cost','',
            'The following counts pool the three attack branches, including clean continuation. A manipulated observation means an actually modified exported update, not an attacker identity. Adaptive alpha=0 and continuation updates are unmodified. Quarantine is a round decision, not permanent identity exclusion. These are conditional measurements with known experimental interventions; they do not establish a semantic classifier.',
            'For interrupted histories, only the verified prefix is counted; observation denominators and completed histories remain explicit.', '',
            '| Cohort | Method | Complete /9 | Manipulated Q / observations | Manipulated downweighted | Unmodified Q / observations | Unmodified downweighted | Unmodified mass retained (%) |',
            '|---|---|---:|---:|---:|---:|---:|---:|']
        for r in interventions:
            lines.append('| '+' | '.join([r['cohort'],r['method'],str(r['completed_histories']),
                f'{r["manipulated_quarantined"]}/{r["manipulated_observations"]}',str(r['manipulated_downweighted']),
                f'{r["unmodified_quarantined"]}/{r["unmodified_observations"]}',str(r['unmodified_downweighted']),
                pc(r['unmodified_mass_retention'])])+' |')
        lines+=['','Cost cells are median milliseconds per observed round with three concurrent workers on the same machine. They are observed wall-clock costs, not isolated CPU benchmarks. All arms run the same diagnostic harness, which computes original indicators and all original policies even for TPM-only. Thus geometry and original-policy timings describe the harness, not an isolated deployment baseline; the new-profile column is its additional score/decision calculation. Aggregation is timed separately. Adaptive search includes candidate calculations and validation inference; it overlaps selected-candidate timing and must not be added to it. No TPM latency is measured.', '',
            '| Cohort | Method | Rounds | Geometry (ms) | Validation inference (ms) | Original decisions (ms) | New profile (ms) | FedAvg (ms) | Six-query search (ms) |',
            '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
        for r in costs:
            values=[f'{1000*r[key]:.3f}' if key in r else 'n/a' for key in (
                'indicator_geometry_seconds','validation_inference_seconds','score_and_all_policy_decisions_seconds',
                'clean_calibration_seconds','aggregation_seconds','attack_search_seconds')]
            lines.append('| '+' | '.join([r['cohort'],r['method'],str(r['observed_rounds']),*values])+' |')
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        colors=dict(tpm_only='#64748b',gated_composite='#7c3aed',mean_control='#ea580c',severe_gate='#0f766e')
        for metric,label,filename in (
            ('full_asr','Full-trigger test ASR','full-trigger-trajectories.png'),
            ('worst_trigger_asr','Worst full/component test ASR','worst-trigger-trajectories.png')):
            fig,axes=plt.subplots(2,3,figsize=(14,7),sharex=True,sharey=True,layout='constrained')
            for i,cohort in enumerate(('iid','non-iid')):
                for j,mode in enumerate(('distributed','complete-trigger','adaptive')):
                    ax=axes[i,j]
                    for method,color in colors.items():
                        rs=[r for r in rounds if r['cohort']==cohort and r['mode']==mode and r['method']==method]
                        ns=sorted({r['round'] for r in rs});vs=[[r[metric] for r in rs if r['round']==n] for n in ns]
                        ax.plot(ns,[avg(v) for v in vs],label=method,color=color)
                        ax.fill_between(ns,[min(v) for v in vs],[max(v) for v in vs],color=color,alpha=.08)
                    ax.axvline(10.5,color='gray',linestyle='--',linewidth=1);ax.set(title=f'{cohort} / {mode}',ylim=(-.02,1.02),xticks=[1,5,10,15])
                    if i==1:ax.set_xlabel('Round; clean continuation after 10')
                    if j==0:ax.set_ylabel(label)
            axes[0,0].legend(fontsize=7);fig.savefig(OUT/filename,dpi=170);plt.close(fig)
        lines+=['','![Reserved full-trigger trajectories](full-trigger-trajectories.png)','',
            '![Reserved worst full/component-trigger trajectories](worst-trigger-trajectories.png)','',
            'Lines are means of available checkpoints; bands are observed ranges, not confidence intervals. The table averages per-history peaks, which differs from the peak of the plotted mean. Failed histories remain explicitly counted.','']
    else:
        lines+=['','No proposed candidate passed every clean guard. Reserved attack/test evaluation was not launched; no mitigation success is claimed.','']
    lines+=['## Evidence and scope','',f'Verification counts: `{dict(counts)}`. All three severe/mean models refitted exactly; empirical count/mass tails checked. All33 focused tests passed. Source/phase/model pins and every candidate are retained. Saved indicators, complete component tails, weights, checkpoints and query objectives are replayed; first/final local training is repeated.',
        'Original source files/equations/evidence and production gate defaults remain unchanged. The proposed gate is a research adapter: live M5 profile binding and fresh TPM integration are separate work. No client semantic maliciousness proof follows from statistical quarantine. Trusted clean calibration, declared metadata and faithful execution are assumptions. No external dataset or universal robustness is established. The thesis is frozen.',
        'Cost observations are in per-case median timing fields; proposed calibration timing includes the new component calculations. Adaptive-search and selected-candidate times overlap and must not be added as independent elapsed costs. Actual TPM appraisal latency is not measured here.', '',
        '## Reproduction','',
        'Existing evidence is immutable. The staged controller resumes closed stages and refuses conflicts; the report requires a fresh destination unless --refresh-draft is explicitly used while reviewing derived prose/tables.','',
        '```bash','.venv/bin/python scripts/revision_severe_gate_study.py pipeline --workers 3',
        '.venv/bin/python scripts/check_severe_models.py','.venv/bin/python scripts/diagnose_severe_gate.py',
        '.venv/bin/python scripts/report_severe_gate.py',
        '.venv/bin/python scripts/check_severe_publication.py','```','']
    text='\n'.join(lines)
    for before,after in {'least1':'least 1','minimum30':'minimum 30','rounds10':'rounds 10','branches:96':'branches: 96',
        'histories,15':'histories, 15','each,attacks1':'each, attacks 1','then5':'then 5','Same50%':'Same 50%',
        'exceed0.8':'exceed 0.8','above0.8':'above 0.8','all18':'all 18','seed2026':'seed 2026',
        'round10':'round 10','from59':'from 59','to66':'to 66','from12':'from 12','to14':'to 14',
        'hold45':'hold 45','is99':'is 99','remains98':'remains 98','are20':'are 20','but45':'but 45',
        'clients,features13':'clients, features 13','at12,and':'at 12, and','queries0':'queries 0','uses3,497':'uses 3,497',
        'uses4,937':'uses 4,937','least20':'least 20','most5':'most 5','after10':'after 10','All33':'All 33'}.items():text=text.replace(before,after)
    (OUT/'README.md').write_text(text)
    shutil.copy2(ROOT/'docs/admission-gates/severe-tail-admission-research.md',OUT/'SPECIFICATION.md')
    shutil.copy2(LAB/'focused-tests.log',OUT/'focused-tests.log')
    if diagnosis:
        for path in (LAB/'posthoc-diagnosis').iterdir():
            if path.is_file():copy_preserved(path,OUT/('diagnosis-'+path.name))
    # Internal accounting, independently repeated by the publication checker.
    if evaluated:
        assert len(cases)==len({c['case'] for c in cases})==96
        assert len(rounds)==counts['evaluation_rounds']
        for case in cases:
            rs=[r for r in rounds if r['case']==case['case']];assert len(rs)==case['completed_rounds']
            if case['complete']:assert case['peak_full_asr']==max(r['full_asr'] for r in rs)
    study.assert_locks(protocol)
    js(OUT/'validation.json',dict(status='verified',counts=dict(counts),focused_tests_passed=33,models_refitted=3,
        source_hashes_unchanged=True,test_used_for_fitting_or_selection=False,research_guardrails_pass=qualified,thesis_edited=False))
    files=[p for p in OUT.iterdir() if p.is_file() and p.name!='inventory-final.json']
    files += [ROOT/'scripts'/n for n in ('severe_gate_calibration.py','revision_severe_gate_study.py','revision_severe_gate_audit.py',
                                         'check_severe_models.py','report_severe_gate.py','check_severe_publication.py','diagnose_severe_gate.py')]
    files += [ROOT/'tests/test_severe_gate.py']
    js(OUT/'inventory-final.json',dict(files={str(p.relative_to(ROOT)):sha256_file(p) for p in files}))
    for path in OUT.iterdir():
        if path.is_file():copy_preserved(path,LOCAL/path.name)
    shutil.copy2(OUT/'README.md',LOCAL/'REPORT.md')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('aggregate','phase_pins','actual_alarms')},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--refresh-draft',action='store_true')
    run(parser.parse_args().refresh_draft)
