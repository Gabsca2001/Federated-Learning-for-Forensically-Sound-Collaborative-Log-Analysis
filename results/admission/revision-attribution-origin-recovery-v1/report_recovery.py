"""Count-based validation and qualified reporting after complete numerical replay."""
from pathlib import Path
import sys,json,csv,hashlib,shutil
from itertools import combinations
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;sys.path.insert(0,str(R/'scripts'))
import revision_attribution_recovery as study
from revision_study_data import read
from revision_dba_experiment import save,authenticate
from coherent_dba_selection import worst_asr
from endpoint_attack_selection import select_endpoint_query
from endpoint_group_protocol import group_key
D=study.D;S=D/'source-evidence';E=D/'recovery-evidence'

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
    if 'complete_trigger' in m:
        for t in (m['complete_trigger'],*m['component_triggers'].values()):
            assert t['non_target_denominator']==1733;near(t['target_predictions']/1733,t['asr'])
            if t['reference_correct_denominator']:near(t['reference_correct_target_predictions']/t['reference_correct_denominator'],t['reference_correct_asr'])

def control(seed,removed):
    name=f's{seed}-{group_key(removed)}.json';paths=[root/name for root in (S/'clean-controls',E/'clean-controls') if (root/name).exists()]
    assert len(paths)==1;return read(paths[0])

def csv_write(name,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with (D/name).open('x',newline='') as h:
        w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(rows)

def compact_case(h,c):
    ms=[r['metrics'] for r in h['journal']];cs=[r['metrics'] for r in c['journal']]
    losses=[b['clean']['macro_f1_all_model_classes']-a['clean']['macro_f1_all_model_classes'] for a,b in zip(ms,cs,strict=True)]
    return dict(peak_full_asr=max(m['complete_trigger']['asr'] for m in ms),peak_worst_asr=max(worst_asr(m) for m in ms),
        final_full_asr=ms[-1]['complete_trigger']['asr'],final_worst_asr=worst_asr(ms[-1]),
        max_same_roster_clean_f1_loss=max(losses),final_same_roster_clean_f1_loss=losses[-1],
        final_parameter_l2_to_same_roster_clean=h['final_parameter_l2_to_same_roster_clean'],
        all_checkpoints_equal_same_roster_clean=all(a['model_sha256']==b['model_sha256'] for a,b in zip(h['journal'],c['journal'],strict=True)))

def main():
    p=read(D/'protocol-before-training.json');study.check(p);v=read(D/'verification.json')
    assert v['status']=='fresh_histories_selection_and_origin_recovery_replayed'
    authenticate(S,read(D/'source-closure.json')['manifest_sha256']);authenticate(E,read(D/'recovery-closure.json')['manifest_sha256'])
    assert p==read(S/'protocol.json') and read(D/'recovery-plan-before-effects.json')==read(E/'plan.json')
    definition=read(D/'verification-definition-before-replay.json')
    assert sha(O/'verify_parallel.py')==definition['verifier_sha256']
    save(D/'report-before-reading.json',dict(reporter_sha256=sha(Path(__file__)),verification_sha256=sha(D/'verification.json')))
    initial=study.prior.source.pilot.old_study.export_digest(study.Engine(p,write=False).initial)
    metric_sets=queries=relative_proofs=0
    def check_history(h):
        nonlocal metric_sets,queries,relative_proofs
        task=h['task'];previous=initial;expected_clients=sorted(set(f'client{i:02d}' for i in range(1,16))-set(h['removed']))
        clean=control(task['seed'],h['removed']) if task['mode']!='clean' else None
        for r in h['journal']:
            number=r['round'];event=r['event'];ctx=event['context']
            assert ctx['parent_model_sha256']==previous and ctx['round_number']==number
            assert event['decision']=='commit' and event['positive_contributors']>=10
            assert event['received_clients']==expected_clients and event['missing_clients']==h['removed']
            assert all(event['mandatory_gates'].values())
            counts=event['example_counts'];total=sum(counts.values())
            for c,coefficient in event['aggregation']['coefficients'].items():near(coefficient,counts[c]/total)
            previous=r['model_sha256'];metric(r['metrics']);metric_sets+=1
            for q in r['queries']:
                queries+=1
                if q['defined']:metric(q['metrics']);metric_sets+=1
                else:assert q['metrics'] is None and q['candidate_model_sha256'] is None
            if r['queries']:
                alpha,selection=select_endpoint_query(r['queries'],clean['journal'][number-1]['metrics']['clean']['macro_f1_all_model_classes'])
                assert alpha==r['selected_alpha'] and selection==r['selection']
            active=task['mode']!='clean' and number<=10
            expected_poison=set(task['attackers'])-set(h['removed']) if active else set()
            assert set(r['poisoning'])==expected_poison
            for c,poison in r['poisoning'].items():
                width=3 if task['mode']=='complete-trigger' else 1
                assert poison['poisoned_row_count']==(counts[c]+1)//2 and len(poison['feature_indices'])==width
                assert poison['modified_feature_values']==width*poison['poisoned_row_count']
            for proof in r['relative_radius_proofs'].values():
                assert proof['alpha']==r['selected_alpha'] and proof['family']==task['family']
                if task['family']=='relative-radius':
                    near(proof['relative_bound'],(1+proof['alpha'])*proof['clean_norm'])
                    assert proof['submitted_norm']<=proof['relative_bound']*(1+1e-12)
                    near(proof['perturbation_norm'],proof['alpha']*proof['clean_norm'])
                    relative_proofs+=1
        assert previous==h['final_model_sha256']
    # Validate every persisted unique control, calibration, source and replay file.
    for root in (S/'calibration-histories',S/'clean-controls',E/'clean-controls'):
        for path in sorted(root.glob('*.json')):check_history(read(path))
    members=read(D/'membership-evaluation.json')['cases'];cases=[];branches=[];comparisons=[];coordination=[]
    for task in p['tasks']:
        alias=task['alias'];h=read(S/'histories'/alias/'result.json');check_history(h)
        c=control(task['seed'],[]);stats=compact_case(h,c);m=next(m for m in members if m['alias']==alias)
        actual=sum(proof['perturbation_norm']>0 for r in h['journal'] for proof in r['relative_radius_proofs'].values())
        selection=read(S/'selection'/f'{alias}.json')
        truth=set(task['attackers']) if task['mode']!='clean' else set()
        selected_set=set(selection['selected_group']);individual_set=set(selection['individual_anomalies'])
        assert (m['TP'],m['FP'],m['FN'])==(len(selected_set&truth),len(selected_set-truth),len(truth-selected_set))
        assert (m['individual_TP'],m['individual_FP'],m['individual_FN'])==(len(individual_set&truth),len(individual_set-truth),len(truth-individual_set))
        effective=[a['round'] for a,b in zip(h['journal'],c['journal'],strict=True)
            if worst_asr(a['metrics'])-worst_asr(b['metrics'])>=.20 and
            b['metrics']['clean']['macro_f1_all_model_classes']-a['metrics']['clean']['macro_f1_all_model_classes']<=.05]
        assert effective==m['effective_rounds']
        pool=set(c for g in selection['candidate_groups'] for c in g)
        coactive={tuple(x['clients']):x for x in selection['pair_coactivity']}
        for pair in selection['descriptive_tensor_pairs']:
            co=coactive[tuple(pair['clients'])]
            coordination.append(dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'],
                left=pair['clients'][0],right=pair['clients'][1],coactive_fraction=co['coactive_fraction'],
                coactive_candidate_edge=co['candidate'],median_centered_cosine=pair['median_centered_cosine'],
                tensor_deviation_profile_correlation=pair['tensor_deviation_profile_correlation'],
                temporal_indicator_correlation=pair['temporal_indicator_correlation'],
                both_scheduled_adversaries_for_evaluation_only=bool(truth) and set(pair['clients'])<=truth))
        infeasible=[g for g in selection['candidate_groups'] if 15-len(g)<10]
        reason=('selected' if selection['selected_group'] else 'only_oversized_candidates' if infeasible else 'no_candidate_group')
        cases.append(dict(**m,**stats,actually_manipulated_exports=actual,
            alpha0_active_rounds=sum(r['selected_alpha']==0 for r in h['journal'][:10]) if task['mode']!='clean' else 0,
            candidate_groups=selection['candidate_groups'],candidate_pool_TP=len(pool&truth),candidate_pool_FP=len(pool-truth),
            candidate_pool_FN=len(truth-pool),infeasible_candidate_sizes=[len(g) for g in infeasible],selection_status=reason))
        plan=read(E/f'{alias}.json')['plan'];bygroup={}
        if plan['eligible_for_recovery']:
            for removal in plan['removals']:
                replay=read(E/'histories'/alias/f"{removal['key']}.json");check_history(replay)
                if not removal['removed']:assert replay==h
                clean=control(task['seed'],removal['removed']);stats=compact_case(replay,clean)
                if task['mode']!='clean' and set(task['attackers'])<=set(removal['removed']):
                    assert stats['all_checkpoints_equal_same_roster_clean'] and stats['final_parameter_l2_to_same_roster_clean']==0
                row=dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'],removed=removal['removed'],roles=removal['roles'],**stats)
                branches.append(row);bygroup[tuple(removal['removed'])]=row
            for comp in plan['comparisons']:
                counts=h['journal'][0]['event']['example_counts'];benign=sorted(set(counts)-truth)
                for key in ('mass_matched_control','hash_control'):
                    assert len(comp[key])==len(comp['group']) and set(comp[key]).isdisjoint(truth)
                possible=list(combinations(benign,len(comp['group'])))
                mass=sum(counts[x] for x in comp['group'])
                matched=min(possible,key=lambda g:(abs(sum(counts[x] for x in g)-mass),group_key(g)))
                assert list(matched)==comp['mass_matched_control'] and list(min(possible,key=group_key))==comp['hash_control']
                joint=bygroup[tuple(comp['group'])];individuals=[bygroup[(x,)] for x in comp['group']]
                mass=bygroup[tuple(comp['mass_matched_control'])];hashed=bygroup[tuple(comp['hash_control'])]
                comparisons.append(dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'],method=comp['method'],group=comp['group'],
                    source_final_full_asr=compact_case(h,c)['final_full_asr'],source_final_worst_asr=compact_case(h,c)['final_worst_asr'],
                    joint_final_full_asr=joint['final_full_asr'],joint_final_worst_asr=joint['final_worst_asr'],
                    joint_peak_worst_asr=joint['peak_worst_asr'],
                    individual_final_full_asrs=[x['final_full_asr'] for x in individuals],
                    individual_final_worst_asrs=[x['final_worst_asr'] for x in individuals],
                    mass_matched_benign_final_full_asr=mass['final_full_asr'],mass_matched_benign_final_worst_asr=mass['final_worst_asr'],
                    hash_benign_final_full_asr=hashed['final_full_asr'],hash_benign_final_worst_asr=hashed['final_worst_asr'],
                    final_parameter_l2_to_same_roster_clean=joint['final_parameter_l2_to_same_roster_clean'],
                    all_checkpoints_equal_same_roster_clean=joint['all_checkpoints_equal_same_roster_clean'],
                    final_same_roster_clean_f1_loss=joint['final_same_roster_clean_f1_loss'],
                    max_same_roster_clean_f1_loss=joint['max_same_roster_clean_f1_loss'],
                    group_sample_count=comp['group_sample_count'],control_sample_count=comp['control_sample_count']))
    totals=[]
    for family in ('unrestricted','relative-radius'):
        rows=[c for c in cases if c['family']==family and c['mode']!='clean']
        totals.append(dict(family=family,histories=len(rows),effective_raw_controls=sum(bool(c['effective_rounds']) for c in rows),
            selected_TP=sum(c['TP'] for c in rows),selected_FP=sum(c['FP'] for c in rows),selected_FN=sum(c['FN'] for c in rows),
            individual_TP=sum(c['individual_TP'] for c in rows),individual_FP=sum(c['individual_FP'] for c in rows),individual_FN=sum(c['individual_FN'] for c in rows)))
    clean=[c for c in cases if c['mode']=='clean'];v4=[x for x in comparisons if x['method']=='v4' and next(c for c in cases if c['alias']==x['alias'])['effective_rounds']]
    summary=dict(status='verified_v4_and_full_origin_recovery',cases=cases,family_totals=totals,comparisons=comparisons,
        clean_histories_with_selected_group=sum(bool(c['selected_group']) for c in clean),
        clean_false_group_members=sum(c['FP'] for c in clean),clean_individual_false_positives=sum(c['individual_FP'] for c in clean),
        selected_group_recoveries_with_effective_controls=len(v4),selected_group_recoveries_zero_full_and_component_ASR=sum(c['joint_final_worst_asr']==0 for c in v4),
        selected_group_recoveries_equal_same_roster_clean=sum(c['all_checkpoints_equal_same_roster_clean'] for c in v4),
        metric_sets_count_checked=metric_sets,relative_radius_proofs_checked=relative_proofs,verification=v,
        new_TPM_quotes=0,test_inference=False,default_changed=False)
    from paired_group_comparison import select_from_pairs
    P=study.prior.D/'selection-evidence'
    old_ref=read(P/'calibration/reference.json');old_c2=read(P/'calibration/v2-calibration.json');old_c3=read(P/'calibration/v3-calibration.json')
    roster=[f'client{i:02d}' for i in range(1,16)];validated=0
    for entry in read(study.prior.D/'protocol-before-observation.json')['cases']:
        pairs=read(P/'observations'/f"{entry['alias']}.json")['pairs'];expected=read(P/'selection'/f"{entry['alias']}.json")
        selected=select_from_pairs(pairs,old_ref,old_c2,old_c3,roster)
        assert selected=={m:expected[m]['selected_group'] for m in ('v2','v3')};validated+=1
    paired=[]
    for task in p['tasks']:
        current=read(S/'selection'/f"{task['alias']}.json")
        old=select_from_pairs(current['descriptive_tensor_pairs'],old_ref,old_c2,old_c3,roster)
        old['v4']=current['selected_group'];truth=set(task['attackers']) if task['mode']!='clean' else set()
        for method,selected in old.items():
            g=set(selected);paired.append(dict(alias=task['alias'],seed=task['seed'],mode=task['mode'],family=task['family'],
                method=method,selected_group=selected,TP=len(g&truth),FP=len(g-truth),FN=len(truth-g)))
    save(D/'paired-method-comparison.json',dict(cases=paired,predecessor_selections_reproduced=validated,
        prospective_comparison=False,thresholds_retuned=False,scope='Post-hoc common-observation comparison. Descriptor adapter reproduces six predecessor selections; frozen thresholds unchanged.'))
    csv_write('paired-method-memberships.csv',paired)
    paired_totals=[]
    for method in ('v2','v3','v4'):
        clean_rows=[x for x in paired if x['method']==method and x['mode']=='clean']
        row=dict(method=method,clean_histories_with_group=sum(bool(x['selected_group']) for x in clean_rows),clean_false_members=sum(x['FP'] for x in clean_rows))
        for family in ('unrestricted','relative-radius'):
            selected=[x for x in paired if x['method']==method and x['mode']!='clean' and x['family']==family]
            row[family]={name:sum(x[name] for x in selected) for name in ('TP','FP','FN')}
        paired_totals.append(row)
    summary['paired_method_totals']=paired_totals
    save(D/'summary.json',summary);csv_write('source-cases.csv',cases);csv_write('origin-branches.csv',branches);csv_write('origin-comparisons.csv',comparisons)
    csv_write('coordination-evidence.csv',coordination)
    def pc(x):return f'{100*x:.2f}%'
    source_table='\n'.join(f"| {c['seed']} | {c['family']} | {c['mode']} | {'yes' if c['effective_rounds'] else 'no'} | {pc(c['peak_worst_asr'])} | {', '.join(c['selected_group']) or 'none'} | {c['TP']}/{c['FP']}/{c['FN']} |" for c in cases)
    recovery_table='\n'.join(f"| {c['seed']} | {c['mode']} | {c['method']} | {pc(c['source_final_worst_asr'])} | {pc(c['joint_final_worst_asr'])} | {pc(c['mass_matched_benign_final_worst_asr'])} | {'yes' if c['all_checkpoints_equal_same_roster_clean'] else 'no'} |" for c in comparisons if c['family']=='unrestricted')
    family_text='\n'.join(f"- {t['family']}: {t['effective_raw_controls']}/{t['histories']} effective raw controls; group memberships TP={t['selected_TP']},FP={t['selected_FP']},FN={t['selected_FN']}; individual memberships TP={t['individual_TP']},FP={t['individual_FP']},FN={t['individual_FN']}." for t in totals)
    paired_table='\n'.join(f"| {r['method']} | {r['clean_histories_with_group']}/2 | {r['unrestricted']['TP']}/{r['unrestricted']['FP']}/{r['unrestricted']['FN']} | {r['relative-radius']['TP']}/{r['relative-radius']['FP']}/{r['relative-radius']['FN']} |" for r in paired_totals)
    residuals=[x for x in v4 if x['joint_final_worst_asr']==0 and not x['all_checkpoints_equal_same_roster_clean']]
    residual_text='\n'.join(f"- Allocation {x['seed']} / {x['mode']}: zero final worst-trigger ASR, but final parameter L2 distance {x['final_parameter_l2_to_same_roster_clean']:.8f} to the same-roster clean model." for x in residuals) or 'No selected zero-ASR recovery differs from its same-roster clean trajectory in this study.'
    (D/'README.md').write_text(f'''# V4 retrospective attribution and full-origin recovery

The completed frozen study distinguishes individual anomaly, coincident group
activity and actual corrected-parent recovery. It does not authorize automatic
exclusion. The existing V2/V3 failures, late-R10 failures and preventive numerical
containment results remain unchanged, with separate evidence and interpretation.

## New assessment results

{family_text}

The two fresh clean histories yield selected groups in
{summary['clean_histories_with_selected_group']}/2 cases, with
{summary['clean_false_group_members']} false group members and
{summary['clean_individual_false_positives']} individually flagged benign clients.
Membership counts repeat three scheduled adversarial identities across variants;
they are not independent persons. Actual altered export counts and alpha0 active
rounds are retained. A scheduled attacker may export an unmodified alpha0 update.

| Allocation | Family | Variant | Effective raw attack | Peak worst ASR | Selected group | TP/FP/FN |
| --- | --- | --- | --- | ---: | --- | --- |
{source_table}

Ineffective relative-radius controls remain included. Low ASR in those cases is
not evidence of resistance or a successful recovered model. A small constrained
attack may still be identified as anomalous or may escape attribution; neither
outcome validates a general stealth-adversary guarantee.

## Recovery from before the first attack round

For effective raw controls, selected-group recovery reaches zero measured full
and individual-trigger ASR in
{summary['selected_group_recoveries_zero_full_and_component_ASR']}/{len(v4)}
selected-group comparisons; {summary['selected_group_recoveries_equal_same_roster_clean']}/{len(v4)}
match every checkpoint of the independently executed same-excluded-roster clean
counterfactual. Oracle-known groups remain a separate diagnostic, even when they
coincide with the detector output; deduplicated numerical branches are not
independent replications of these two roles.

| Allocation | Variant | Group role | Original final worst ASR | Origin joint-removal ASR | Matched benign-removal ASR | All checkpoints equal same-roster clean |
| --- | --- | --- | ---: | ---: | ---: | --- |
{recovery_table}

Every replay starts at the preserved W0 before R1. Each surviving honest client
recomputes its gradient at the actual corrected parent. Every surviving attacker
relearns its poisoned Adam endpoint and reruns all six adaptive queries at that
parent in R1-10; R11-15 use the declared unmodified continuation. No historical
client tensor or original selected alpha is reused as a future update.
No-removal branches reproduce the complete new source histories. Individual,
joint, hash-ranked benign and closest-mass benign removals are all retained.
There is one hash and one closest-mass control per group role, not a calibrated
distribution of intervention effects or an inferential p-value.
Some individual removals also reach zero final ASR. Joint-removal zero alone
therefore cannot prove that all members were necessary, that the full trigger
requires all components, or that the group intentionally colluded. Read the
retained individual effects and same-roster parameter residuals together.

The clean comparison excludes exactly the same clients during R1-15 and retrains
from the same W0. Earlier benign influence already in W0 remains in both models.
The comparison accounts for omitted benign as well as poisoned replay-period
contributions. Equality
with that reference is conditional exact reproduction under this deterministic
simulation, not certified unlearning of only poisoned rows, restoration of the
original full-roster model or proof that a real deployment's W0 is clean.
Correct attribution, clean W0 and complete removal of all active attackers are
essential assumptions. Authenticity of a checkpoint alone does not prove its
semantic cleanliness. Missing/false members stay visible in membership results.

### Residual effect despite zero ASR

{residual_text}

Because this comparison holds the omitted roster, initial checkpoint, honest
data and training rule fixed, the remaining difference isolates the declared
adversarial submissions within this deterministic protocol. It is not a claim
that the residual is harmful on untested inputs or a general certified-unlearning
measure. It does demonstrate why zero tested ASR cannot establish exact recovery.

## Why this differs from V2/V3 and late correction

V4 fits a pooled clean reference for log1p(relative norm) and validation impact,
with robust scales and fixed floors. A client's median ten-round maximum channel
increase is its persistent anomaly score. The individual threshold is the maximum
clean calibration campaign/client persistence. Two anomalous clients form a
candidate edge only when their threshold exceedances coincide in a fraction of
rounds strictly above the larger of .3 and all clean calibration pair fractions.
Maximal cliques yield investigative groups; no expected attacker count is forced.
Tensor direction/profile/correlation descriptors are retained as separate evidence.
Common benign causes can create concurrent anomalies. This is not proof of
intentional collusion and is not itself an admission policy.
coordination-evidence.csv exposes all105 pairs per history, including coactivity
and the three tensor/temporal descriptors. Scheduled adversary annotations there
are post-selection evaluation labels, never inputs to the selector.

An empty selected group can mean that every candidate is too large to omit while
retaining ten contributors. source-cases.csv distinguishes this from no candidate
evidence and retains candidate-pool membership errors. No oversized group is
silently truncated to the known attacker count. Benign clients flagged inside an
attacked history remain false members even when both clean control histories are
unflagged. A ten-round median can also miss an intermittent attacker; actual
alpha0 exports and per-round scores remain available for that diagnosis.

V2/V3 looked for increases over client-pair similarity references and missed the
earlier effective endpoint attacks while flagging both earlier clean histories.
The current method is explicitly developed after that finding. Its assessment
uses two new allocations and new adversarial rosters frozen before outcomes,
with actual membership uniqueness checked across all nine relevant allocations.
The five clean fitting/calibration roles are reused development resources, not
new independent clean validation. All allocations reuse the same 7096 training
rows, W0 and 3163 validation rows (1733 non-target ASR rows), so no independent
dataset or statistically guaranteed false-positive rate is established.

paired-method-comparison.json also applies the frozen predecessor rules to exactly
the same new pair observations as V4. It is a post-hoc common-input comparison,
not a separately preregistered experiment. The descriptor adapter reproduces all
six original V2/V3 selected groups before use; thresholds remain unchanged.
Comparing different allocations alone would not isolate the rule's effect.

| Method on identical new observations | Clean histories with selected group | Unrestricted memberships TP/FP/FN | Relative-radius memberships TP/FP/FN |
| --- | ---: | ---: | ---: |
{paired_table}

Late R10 removal in the previous study retained R1-9 contamination. This study
instead rebuilds the entire affected history from W0. Those are different
interventions; origin recovery does not retroactively turn the earlier late
correction failure into a success.

## Attacker and remaining limits

Unrestricted Byzantine vectors interpolate/extrapolate a poisoned 10-epoch Adam
endpoint from an honest one-step coherent delta. Relative-radius vectors instead
limit the perturbation to alpha times the client's own clean delta norm, with
submitted norm at most five times that norm. Both use factors 0/.125/.5/1/2/4 and
a privileged reused-validation/same-roster-clean oracle. Defined candidates must
retain F1 within five points of that control; selection maximizes worst full or
three single-component ASR, then alpha. Attacks optimize the raw FedAvg model,
not an unrestricted evasion objective against the retrospective V4 selector.
No data-only honest-training, raw-traffic trigger realizability, cold-start or
long-horizon guarantee follows. Full-trigger composition necessity is not proven.

## Verification and storage

74 focused tests pass, including eight new persistence/coactivity, leakage and
whole-vector relative-radius tests. Full fresh replay checks 50 fit/calibration
rounds, {v['source_rounds']} source rounds and {v['recovery_rounds']} origin-recovery
rounds across {v['recovery_branches']} branches, including {v['adaptive_queries']}
adaptive queries. Separate arithmetic checks reconstruct{metric_sets} metric
sets, sample-mass coefficients, poisoned-row budgets, utility-constrained query
selections and{relative_proofs} relative-radius bounds. Replay uses the same
numerical implementation; it is not independent classifier reimplementation.

Experimental manifests use software research authorities, not TPM/client keys.
All predecessor publication indexes and the 130-module measured core remain
unchanged. No test inference, operational default, thesis text, ToN-IoT acquisition
or independent witness deployment changes. Metadata and final source checkpoints
are retained without dataset copies, under the 64 MiB combined output ceiling and
8 GiB host free-space floor.
''')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(2,2,figsize=(11,7),sharex=True,sharey=True)
    strong=[t for t in p['tasks'] if t['family']=='unrestricted' and t['mode']!='clean']
    for ax,task in zip(axes.ravel(),strong,strict=True):
        original=read(S/'histories'/task['alias']/'result.json')
        ax.plot(range(1,16),[100*worst_asr(r['metrics']) for r in original['journal']],color='#b45309',label='Original attack')
        plan=read(E/f"{task['alias']}.json")['plan']
        for role,color,style in [('v4-joint','#0f766e','-'),('oracle-diagnostic-joint','#7c3aed','--'),('v4-mass-matched-benign','#2563eb',':')]:
            request=next((r for r in plan['removals'] if role in r['roles']),None)
            if request and plan['eligible_for_recovery']:
                replay=read(E/'histories'/task['alias']/f"{request['key']}.json")
                ax.plot(range(1,16),[100*worst_asr(r['metrics']) for r in replay['journal']],color=color,linestyle=style,label=role)
        suffix='\nIneffective raw control; no recovery claim' if not plan['eligible_for_recovery'] else ''
        ax.set_title(f"{task['seed']} / {task['mode']}"+suffix,fontsize=10);ax.set_ylim(-2,103);ax.grid(alpha=.2)
    for ax in axes[:,0]:ax.set_ylabel('Worst measured trigger ASR (%)')
    for ax in axes[-1,:]:ax.set_xlabel('Round retrained from pre-attack W0')
    handles={}
    for ax in axes.ravel():
        for h,label in zip(*ax.get_legend_handles_labels(),strict=True):handles[label]=h
    fig.legend(list(handles.values()),list(handles),loc='lower center',ncol=2,fontsize=8)
    fig.suptitle('Full-origin recovery with adaptive surviving attackers')
    fig.tight_layout(rect=(0,.09,1,.95));fig.savefig(D/'origin-recovery.png',dpi=150);plt.close(fig)
    study.check(p)
    for name in ('report_recovery.py','paired_group_comparison.py','verify_parallel.py','tests.log','calibration.log','assessment.log','plan.log','recovery.log','verify.log'):
        shutil.copy2(O/name,D/name)
    shutil.copy2(O/'METHOD.md',D/'METHOD.md')
    sources=D/'sources';sources.mkdir()
    for name in ('revision_attribution_recovery.py','retrospective_anomaly_groups.py','endpoint_recovery_protocol.py'):
        shutil.copy2(R/'scripts'/name,sources/name)
    shutil.copy2(R/'tests/test_retrospective_anomaly_groups.py',sources/'test_retrospective_anomaly_groups.py')
    save(D/'source-integrity.json',dict(measured_core_sha256=study.prior.implementation_sha256(),predecessor_publications_unchanged=True,defaults_changed=False))
    pins={str(f.relative_to(D)):sha(f) for f in D.rglob('*') if f.is_file()};save(D/'file-checksums.json',pins)
    mirror=O/'published';assert not mirror.exists();shutil.copytree(D,mirror)
    assert all(sha(mirror/n)==h for n,h in pins.items())
    save(O/'final-storage-check.json',dict(status='verified_and_mirrored',**study.guard()))
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
