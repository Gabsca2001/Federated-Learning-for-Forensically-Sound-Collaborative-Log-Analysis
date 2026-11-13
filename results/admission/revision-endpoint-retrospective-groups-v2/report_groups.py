"""Independent count accounting and qualified retrospective intervention report."""
from pathlib import Path
import sys,json,csv,shutil,hashlib,os
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;sys.path.insert(0,str(R/'scripts'))
import revision_endpoint_groups_v2 as study
from endpoint_group_protocol import group_key
from coherent_dba_selection import worst_asr
from revision_study_data import read
from revision_dba_experiment import save,authenticate
D=study.D;B=study.B

def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def near(a,b):assert abs(a-b)<1e-12,(a,b)
def metric(m):
    cm=m['clean']['confusion_matrix']['values'];n=len(cm);f=[]
    assert sum(map(sum,cm))==3163
    for i in range(n):
        den=sum(cm[i])+sum(cm[j][i] for j in range(n));f.append(2*cm[i][i]/den if den else 0.)
    near(sum(f)/n,m['clean']['macro_f1_all_model_classes'])
    near(sum(cm[i][i] for i in range(n))/3163,m['clean']['accuracy'])
    for t in (m['complete_trigger'],*m['component_triggers'].values()):
        assert t['non_target_denominator']==1733
        near(t['target_predictions']/1733,t['asr'])
        if t['reference_correct_denominator']:
            near(t['reference_correct_target_predictions']/t['reference_correct_denominator'],t['reference_correct_asr'])
def change(before,after):
    return dict(full_asr_reduction=before['complete_trigger']['asr']-after['complete_trigger']['asr'],
        worst_asr_reduction=worst_asr(before)-worst_asr(after),
        clean_f1_change=after['clean']['macro_f1_all_model_classes']-before['clean']['macro_f1_all_model_classes'])
def csv_write(name,rows):
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with (D/name).open('x',newline='') as h:
        w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(rows)
def pct(x):return 'undefined' if x is None else f'{100*x:.2f}%'

def main():
    p=read(D/'protocol-before-observation.json');_,_,_,old=study.check(p)
    verification=read(D/'verification.json');assert verification['status']=='observations_selection_and_interventions_fully_replayed'
    authenticate(D/'selection-evidence',read(D/'selection-closure.json')['manifest_sha256'])
    authenticate(D/'effects-evidence',read(D/'effects-closure.json')['manifest_sha256'])
    save(D/'report-before-reading.json',dict(reporter_sha256=sha(Path(__file__)),verification_sha256=sha(D/'verification.json')))
    members=read(D/'membership-evaluation.json')['cases'];summaries=[];effects=[];rounds=[];metric_sets=0
    for entry in p['cases']:
        alias=entry['alias'];task=entry['task'];result=read(D/'effects-evidence'/f'{alias}.json')
        bygroup={tuple(i['removed']):i for i in result['interventions']}
        baseline=bygroup[()];assert baseline['direct']['metrics']==result['source_R10']
        assert baseline['continuation'][-1]['metrics']==result['source_R15']
        for i in result['interventions']:
            metric(i['direct']['metrics']);metric_sets+=1
            event=i['direct']['event'];assert event['decision']=='commit' and event['positive_contributors']>=10
            assert event['missing_clients']==i['removed']
            for row in i['continuation']:
                metric(row['metrics']);metric_sets+=1
                assert row['event']['decision']=='commit' and row['event']['positive_contributors']>=10
                assert set(row['event']['received_clients']).isdisjoint(i['removed'])
                rounds.append(dict(alias=alias,seed=task['seed'],mode=task['mode'],removed=','.join(i['removed']),
                    roles=';'.join(i['roles']),round=row['round'],full_asr=row['metrics']['complete_trigger']['asr'],
                    worst_asr=worst_asr(row['metrics']),clean_f1=row['metrics']['clean']['macro_f1_all_model_classes']))
            if i['continuation']:
                assert [r['round'] for r in i['continuation']]==list(range(11,16))
            effects.append(dict(alias=alias,seed=task['seed'],mode=task['mode'],removed=','.join(i['removed']),roles=';'.join(i['roles']),
                R10_full_asr=i['direct']['metrics']['complete_trigger']['asr'],R10_worst_asr=worst_asr(i['direct']['metrics']),
                R15_full_asr=i['continuation'][-1]['metrics']['complete_trigger']['asr'] if i['continuation'] else None,
                R15_worst_asr=worst_asr(i['continuation'][-1]['metrics']) if i['continuation'] else None,
                final_parameter_l2_to_full_roster_clean=i.get('final_parameter_l2_to_full_roster_clean'),
                **change(result['source_R10'],i['direct']['metrics'])))
        for comp in result['plan']['comparisons']:
            group=comp['group'];joint=bygroup[tuple(group)];individuals=[bygroup[(c,)] for c in group]
            control_keys=sorted(set(tuple(g) for g in comp['hash_controls']+[comp['mass_matched_control']]))
            controls=[bygroup[g] for g in control_keys]
            mass=bygroup[tuple(comp['mass_matched_control'])]
            for stage in ('R10','R15'):
                def at(i):return i['direct']['metrics'] if stage=='R10' else i['continuation'][-1]['metrics']
                before=result['source_'+stage];joint_m=at(joint)
                changes=change(before,joint_m);single_changes=[change(before,at(i)) for i in individuals]
                available_controls=controls if stage=='R10' else [mass]
                control_changes=[change(before,at(i)) for i in available_controls]
                summaries.append(dict(alias=alias,seed=task['seed'],mode=task['mode'],method=comp['method'],stage=stage,
                    group=group,source_full_asr=before['complete_trigger']['asr'],source_worst_asr=worst_asr(before),
                    joint_full_asr=joint_m['complete_trigger']['asr'],joint_worst_asr=worst_asr(joint_m),
                    largest_individual_full_reduction=max(v['full_asr_reduction'] for v in single_changes),
                    largest_individual_worst_reduction=max(v['worst_asr_reduction'] for v in single_changes),
                    joint_minus_largest_individual_full_reduction=changes['full_asr_reduction']-max(v['full_asr_reduction'] for v in single_changes),
                    joint_minus_largest_individual_worst_reduction=changes['worst_asr_reduction']-max(v['worst_asr_reduction'] for v in single_changes),
                    benign_control_full_reductions=[v['full_asr_reduction'] for v in control_changes],
                    benign_control_worst_reductions=[v['worst_asr_reduction'] for v in control_changes],
                    mass_matched_benign_full_reduction=change(before,at(mass))['full_asr_reduction'],
                    mass_matched_benign_worst_reduction=change(before,at(mass))['worst_asr_reduction'],
                    removed_sample_count=comp['group_sample_count'],control_sample_count=comp['control_sample_count'],**changes))
    totals=[]
    for method in ('v2','v3'):
        attacked=[r for r in members if r['method']==method and r['mode']!='clean']
        clean=[r for r in members if r['method']==method and r['mode']=='clean']
        totals.append(dict(method=method,attacked_histories=4,selected_TP=sum(r['TP'] for r in attacked),
            selected_FP=sum(r['FP'] for r in attacked),selected_FN=sum(r['FN'] for r in attacked),
            clean_histories=2,clean_histories_with_candidates=sum(bool(r['selected_group']) for r in clean),
            clean_false_selected_clients=sum(r['FP'] for r in clean)))
    diagnostics=[];diagnostic_engine=study.Engine(p)
    for entry in p['cases']:
        selected=read(D/'selection-evidence/selection'/f"{entry['alias']}.json")
        task=entry['task'];truth=set(task['attackers']) if task['mode']!='clean' else set()
        pairs=selected['v2']['pairs'];largest=max(pairs,key=lambda x:x['conditioned_score'] if x['conditioned_score'] is not None else -1)
        truth_pairs=[x for x in pairs if set(x['clients'])<=truth]
        base,updates,meta=diagnostic_engine.load_inputs(entry['alias'])
        import numpy as np
        norms={c:float(np.linalg.norm(np.concatenate([a.ravel() for a in u['delta']]))) for c,u in updates.items()}
        benign_norms=[v for c,v in norms.items() if c not in truth]
        median_benign=float(np.median(benign_norms))
        diagnostics.append(dict(alias=entry['alias'],seed=task['seed'],mode=task['mode'],
            v2_threshold=selected['v2']['threshold'],largest_observed_pair=largest,
            labelled_attacker_pairs_for_evaluation_only=truth_pairs,
            R10_labelled_attacker_norm_to_benign_median={c:norms[c]/median_benign for c in sorted(truth)},
            interpretation='Pair-similarity increase is not an absolute update-magnitude anomaly. Scores below the frozen threshold are genuine missed hypotheses; clean threshold exceedances remain false positives. These diagnostics do not tune selection.'))
    save(D/'selection-diagnostics.json',dict(cases=diagnostics,post_selection_only=True,threshold_changed=False))
    summary=dict(status='verified_retrospective_group_and_late_removal_report',membership=members,membership_totals=totals,
        comparisons=summaries,metric_sets_count_checked=metric_sets,verification=verification,
        historical_allocation_audit=read(O/'allocation-audit.json'),
        interpretation='Current-round and R11-15 late correction effects; not removal of the R1-9 poisoned history, not proof of collusion or exact unlearning.',
        new_TPM_quotes=0,test_inference=False,default_changed=False)
    save(D/'summary.json',summary);csv_write('membership.csv',members);csv_write('interventions.csv',effects)
    csv_write('comparisons.csv',summaries);csv_write('continuation-rounds.csv',rounds)
    membership_table='\n'.join(f"| {m['seed']} | {m['mode']} | {m['method']} | {', '.join(m['selected_group']) or 'none'} | {m['TP']} | {m['FP']} | {m['FN']} |" for m in members)
    intervention_table='\n'.join(f"| {s['seed']} | {s['mode']} | {s['method']} | {s['stage']} | {pct(s['source_full_asr'])} | {pct(s['joint_full_asr'])} | {100*s['joint_minus_largest_individual_full_reduction']:.2f} |" for s in summaries if s['mode']!='clean')
    totals_text='\n'.join(f"- {t['method']}: attacked histories TP={t['selected_TP']}, FP={t['selected_FP']}, FN={t['selected_FN']}; clean selected groups in {t['clean_histories_with_candidates']}/2 histories." for t in totals)
    if all(t['selected_TP']==0 and t['selected_FN']==12 and t['clean_histories_with_candidates']==2 for t in totals):
        finding='Both selectors miss the attacker groups in all four attacked histories and select false groups in both clean histories. This is a failed transfer of the existing retrospective selection rules to these new endpoint histories; it does not validate automatic identification or exclusion.'
    else:
        finding='Membership results below retain missed attackers and false members. Selection quality and late-removal effects must be judged separately.'
    (D/'README.md').write_text(f'''# Retrospective groups on effective learned-endpoint DBA histories

{finding}

This completed study applies the existing V2/V3 retrospective selectors to the
four effective raw FedAvg endpoint attacks, plus two source clean controls.
It is separate from automatic containment by FLTrust or norm-only normalization.
All selection and intervention outputs were freshly reconstructed and checked.

## Candidate membership

{totals_text}

Counts are memberships across four histories, not independent client persons.
Both attack variants reuse each of two data assignments and attacker rosters.
False members and missed attackers remain explicit; an empty selection is not
replaced by the known attacker set. The separately labelled oracle diagnostic
cannot be presented as detector output or used to tune thresholds.

| Seed | Source | Method | Selected group | TP | FP | FN |
| --- | --- | --- | --- | ---: | ---: | ---: |
{membership_table}

## Direct and future interventions

R10 holds the actual source parent and surviving exported vectors fixed.
R15 follows five genuinely recomputed coherent-gradient rounds at the corrected
parents, keeping the same removed identities omitted from aggregation. Active
poisoning already ends at R10 in the declared source protocol. Every no-removal
branch reproduces all five original continuation checkpoints exactly.

| Seed | Source | Group method | Stage | Original full ASR | Joint-removal full ASR | Joint minus best individual reduction (points) |
| --- | --- | --- | --- | ---: | ---: | ---: |
{intervention_table}

The complete comparison includes all individual removals, full and three
individual triggers, clean F1, five hash-ranked equal-size benign controls and
one closest sample-mass control. Direct R10 benign-control distributions are
descriptive, not p-values. Only the closest-mass benign control receives future
training for each method; do not call that a distribution of R15 controls.
The full-versus-worst-trigger differences and sample-mass mismatch are retained
in comparisons.csv/summary.json. Cardinality matching does not ensure exact
sample-mass equality in non-IID data. Joint-versus-individual differences do not
alone establish a synergistic or intentional coordinated attack.

## Scope of the causal interpretation

R10 begins after nine potentially poisoned rounds. Removing an identified group
at R10 cannot retroactively clean that starting checkpoint. Residual ASR after
joint removal is a real limitation of late correction, not evidence that the
omitted current updates were reused. Conversely, zero ASR does not establish
exact parameter restoration. Parameter distance to the original full-roster clean
reference is descriptive: it also includes changed roster and lost benign data,
so it is not an isolated measure of residual poisoning.

The separate selection-diagnostics.json retains the actual frozen pair threshold,
largest observed pair score, labelled attacker-pair scores and R10 malicious
update norm ratios. The rule looks for increased pairwise similarity; it does
not directly threshold absolute update magnitude. Large updates therefore need
not produce a candidate group. Clean non-IID distribution changes can instead
exceed the pair reference. These observed score failures require a separately
designed validation protocol before changing the selector, not lowering the
threshold after consulting attacker identities.

The attacker's original R10 factor and other submissions remain fixed during
direct removal. This is a conditional intervention on retained evidence, not a
new attack that adapts to exclusion. R11-15 are the already-declared unmodified
continuation. No claim is made about removing a group from the first attack round
or replaying an adversary that continually adapts after discovery.

## Clean calibration and duplicate-allocation finding

Two fresh clean allocation histories fit the reference; three separate clean
allocations calibrate empirical maxima. All seven actual memberships (five
fit/calibration and two source evaluation assignments) were checked distinct
before training. They reuse the same7096 training occurrences, initial model
and3163 root-disjoint validation rows; they are not independent datasets or
population samples. Three calibration histories cannot establish a population
false-positive guarantee. The V2/V3 algorithms are unchanged; recalibration is
necessary because historical Adam endpoint references do not match the new
coherent-gradient honest protocol.

The initial v1 attempt stopped before selection/effects because adjacent nominal
seeds converged to duplicate allocations through the historical generator's
seed+attempt retry. It is preserved, not counted as a completed calibration.
The separate allocation audit also finds historical seeds6116105/6116106 have
identical memberships; their different attacker identities/training seeds do
not make them distinct data distributions. The two actual source assignments
6116104/6116105 used here are distinct. No historical evidence was rewritten.

## Verification and preservation

66 focused tests passed, including ten new control/allocation guard tests and
existing retrospective, counterfactual and actual-retraining checks.
Fresh replay covers50 fit/calibration rounds,90 selected source rounds,
{verification['direct_outputs']} direct outputs and{verification['continuation_rounds']}
corrected-parent continuation rounds in{verification['continuation_branches']}
branches. Separate arithmetic accounting reconstructs{metric_sets} metric sets.
It is same-implementation numerical replay, not independent classifier code.
The previously verified unselected adaptive source queries were not rerun here.
Source publication checksums, all original generation pins and the130-module
core digest remain unchanged. The new evidence uses software research authority
signatures, not client signatures or TPM evidence. No test inference, thesis
change, operational default change or independent-data claim is introduced.
''')
    # Compact, readable scientific comparison of the discovered group and oracle.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(2,2,figsize=(11,7),sharey=True)
    attacks=[e for e in p['cases'] if e['task']['mode']!='clean']
    for ax,entry in zip(axes.ravel(),attacks,strict=True):
        result=read(D/'effects-evidence'/f"{entry['alias']}.json");bygroup={tuple(i['removed']):i for i in result['interventions']}
        no=bygroup[()];ax.plot([10]+[r['round'] for r in no['continuation']],
            [100*worst_asr(no['direct']['metrics'])]+[100*worst_asr(r['metrics']) for r in no['continuation']],label='No removal',color='#b45309')
        for method,color,style in [('v2','#2563eb','-'),('v3','#0f766e','--'),('oracle-diagnostic','#7c3aed',':')]:
            c=next((c for c in result['plan']['comparisons'] if c['method']==method),None)
            if c:
                i=bygroup[tuple(c['group'])]
                ax.plot([10]+[r['round'] for r in i['continuation']],
                    [100*worst_asr(i['direct']['metrics'])]+[100*worst_asr(r['metrics']) for r in i['continuation']],label=method,color=color,linestyle=style)
        ax.set_title(f"{entry['task']['seed']} / {entry['task']['mode']}",fontsize=10)
        ax.set_xticks(range(10,16));ax.set_ylim(-2,103);ax.grid(alpha=.2);ax.set_xlabel('Round after late correction')
    for ax in axes[:,0]:ax.set_ylabel('Worst measured trigger ASR (%)')
    handles,labels=axes[0,0].get_legend_handles_labels();fig.legend(handles,labels,loc='lower center',ncol=4)
    fig.suptitle('Oracle-known attacker removal: R10 correction and fresh continuation')
    fig.tight_layout(rect=(0,.06,1,.95));fig.savefig(D/'late-group-removal.png',dpi=150);plt.close(fig)
    study.check(p)
    original=R/'results/revision-capped-final-v1'
    assert all(sha(original/n)==h for n,h in read(original/'publication-manifest.json')['files'].items())
    save(D/'source-integrity.json',dict(original_generation_pins_verified=len(old['source_locks']),
        implementation_sha256=study.implementation_sha256(),old_capped_publication_unchanged=True,
        source_endpoint_publication_unchanged=True,defaults_changed=False))
    for name in ('allocation-audit.json','allocation_audit.py','report_groups.py','observe-v2.log','plan-v2.log','effects-v2.log','verify-v2.log','tests-v2.log'):
        shutil.copy2(O/name,D/name)
    shutil.copy2(O/'NEXT_STEPS.md',D/'NEXT_STEPS.md')
    sources=D/'sources';sources.mkdir()
    for name in ('revision_endpoint_groups_v2.py','endpoint_group_protocol.py','endpoint_group_allocation_guard.py'):
        shutil.copy2(R/'scripts'/name,sources/name)
    for name in ('test_endpoint_group_protocol.py','test_endpoint_group_allocation_guard.py'):
        shutil.copy2(R/'tests'/name,sources/name)
    blocked=D/'blocked-v1-attempt';blocked.mkdir()
    failed=R/'results/revision-endpoint-retrospective-groups-v1'
    shutil.copy2(failed/'protocol-before-observation.json',blocked/'protocol-before-observation.json')
    shutil.copy2(O/'observe.log',blocked/'observe.log');shutil.copy2(R/'scripts/revision_endpoint_groups.py',blocked/'revision_endpoint_groups.py')
    pins={str(f.relative_to(D)):sha(f) for f in D.rglob('*') if f.is_file()}
    save(D/'file-checksums.json',pins)
    mirror=O/'published';assert not mirror.exists();shutil.copytree(D,mirror)
    assert all(sha(mirror/n)==h for n,h in pins.items())
    storage=study.guard();save(O/'final-storage-check.json',dict(status='verified_and_mirrored',**storage))
    print(json.dumps(dict(membership_totals=totals,verification=verification,metric_sets_count_checked=metric_sets,
        storage=storage,comparisons=summaries),indent=2))

if __name__=='__main__':main()
