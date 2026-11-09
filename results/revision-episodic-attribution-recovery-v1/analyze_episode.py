"""Independent accounting and readable V5 report after complete fresh replay."""
import os
for name in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ[name]='1'
from pathlib import Path
import sys,json,csv,hashlib,shutil
from itertools import combinations
import numpy as np
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');sys.path.insert(0,str(R/'scripts'))
import revision_episode_attribution as study
from revision_study_data import read
from revision_dba_experiment import save,authenticate
from endpoint_group_protocol import group_key
from coherent_dba_selection import worst_asr
from endpoint_attack_selection import select_endpoint_query
O=Path(__file__).parent;D=study.D;S=D/'source-evidence';E=D/'recovery-evidence'

def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def near(a,b):assert abs(a-b)<1e-12,(a,b)
def median(v):
    v=sorted(v);return v[len(v)//2] if len(v)%2 else (v[len(v)//2-1]+v[len(v)//2])/2
def metric(m):
    cm=m['clean']['confusion_matrix']['values'];n=len(cm);f=[];assert sum(map(sum,cm))==3163
    for i in range(n):
        den=sum(cm[i])+sum(cm[j][i] for j in range(n));f.append(2*cm[i][i]/den if den else 0.)
    near(sum(f)/n,m['clean']['macro_f1_all_model_classes']);near(sum(cm[i][i] for i in range(n))/3163,m['clean']['accuracy'])
    if 'complete_trigger' in m:
        for t in (m['complete_trigger'],*m['component_triggers'].values()):
            assert t['non_target_denominator']==1733;near(t['target_predictions']/1733,t['asr'])
            if t['reference_correct_denominator']:near(t['reference_correct_target_predictions']/t['reference_correct_denominator'],t['reference_correct_asr'])
def control(seed,removed):
    name=f's{seed}-{group_key(removed)}.json';paths=[x/name for x in (S/'clean-controls',E/'clean-controls') if (x/name).exists()]
    assert len(paths)==1;return read(paths[0])
def csv_write(name,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with (D/name).open('x',newline='') as h:
        w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(rows)
def stats(h,c,full_clean=None):
    full_clean=c if full_clean is None else full_clean
    ms=[r['metrics'] for r in h['journal']];losses=[b['metrics']['clean']['macro_f1_all_model_classes']-a['clean']['macro_f1_all_model_classes'] for a,b in zip(ms,c['journal'],strict=True)]
    full_losses=[b['metrics']['clean']['macro_f1_all_model_classes']-a['clean']['macro_f1_all_model_classes'] for a,b in zip(ms,full_clean['journal'],strict=True)]
    return dict(peak_full_asr=max(m['complete_trigger']['asr'] for m in ms),peak_worst_asr=max(worst_asr(m) for m in ms),
        final_full_asr=ms[-1]['complete_trigger']['asr'],final_worst_asr=worst_asr(ms[-1]),
        final_macro_f1=ms[-1]['clean']['macro_f1_all_model_classes'],final_accuracy=ms[-1]['clean']['accuracy'],
        maximum_full_roster_clean_f1_loss=max(full_losses),final_full_roster_clean_f1_loss=full_losses[-1],
        maximum_same_roster_clean_f1_loss=max(losses),final_same_roster_clean_f1_loss=losses[-1],
        final_parameter_l2_to_same_roster_clean=h['final_parameter_l2_to_same_roster_clean'],
        all_checkpoints_equal_clean=all(a['model_sha256']==b['model_sha256'] for a,b in zip(h['journal'],c['journal'],strict=True)))

def classwise_rows(h,c,phase,full_clean=None):
    full_clean=c if full_clean is None else full_clean
    rows=[]
    for actual,clean,full in zip(h['journal'],c['journal'],full_clean['journal'],strict=True):
        a=actual['metrics']['clean']['confusion_matrix'];b=clean['metrics']['clean']['confusion_matrix'];base=full['metrics']['clean']['confusion_matrix']
        assert a['labels']==b['labels']==base['labels']
        for i,label in enumerate(a['labels']):
            def values(cm):
                tp=cm[i][i];support=sum(cm[i]);predicted=sum(row[i] for row in cm)
                return tp,predicted-tp,support-tp,support,2*tp/(support+predicted) if support+predicted else 0.
            tp,fp,fn,support,f1=values(a['values']);ctp,cfp,cfn,csupport,cf1=values(b['values'])
            _,_,_,full_support,full_f1=values(base['values']);assert support==csupport==full_support
            rows.append(dict(phase=phase,alias=h['task']['alias'],removed=h['removed'],round=actual['round'],
                label=label,support=support,TP=tp,FP=fp,FN=fn,F1=f1,
                same_roster_clean_TP=ctp,same_roster_clean_FP=cfp,same_roster_clean_FN=cfn,
                same_roster_clean_F1=cf1,F1_loss_vs_same_roster_clean=cf1-f1,
                full_roster_clean_F1=full_f1,F1_loss_vs_full_roster_clean=full_f1-f1))
    return rows

def main():
    p=read(D/'protocol-before-training.json');study.check(p);verification=read(D/'verification.json')
    assert verification['status']=='v5_histories_selection_and_origin_recovery_replayed'
    assert p==read(S/'protocol.json') and read(D/'recovery-plan-before-effects.json')==read(E/'plan.json')
    authenticate(S,read(D/'source-closure.json')['manifest_sha256']);authenticate(E,read(D/'recovery-closure.json')['manifest_sha256'])
    assert sha(O/'verify_episode.py')==read(D/'verification-definition-before-replay.json')['verifier_sha256']
    save(D/'report-before-accounting.json',dict(reporter_sha256=sha(Path(__file__)),verification_sha256=sha(D/'verification.json')))
    cal=read(S/'calibration.json');tau=cal['episode_score_threshold'];k=cal['minimum_excess_rounds']
    assert k==3 and tau==max(cal['clean_campaign_episode_maxima'])
    assert cal['coactive_round_count_threshold']==max(2,max(cal['clean_campaign_coactivity_maxima']))
    initial=study.prior.source.pilot.old_study.export_digest(study.Engine(p,write=False).initial)
    metric_sets=queries=selections=relative_proofs=0
    def check_history(h):
        nonlocal metric_sets,queries,selections,relative_proofs
        task=h['task'];previous=initial;expected=sorted(set(f'client{i:02d}' for i in range(1,16))-set(h['removed']))
        c=control(task['seed'],h['removed']) if task['mode']!='clean' else None
        for r in h['journal']:
            event=r['event'];number=r['round'];ctx=event['context']
            assert ctx['round_number']==number and ctx['parent_model_sha256']==previous
            assert event['decision']=='commit' and event['positive_contributors']>=10 and all(event['mandatory_gates'].values())
            assert event['received_clients']==expected and event['missing_clients']==h['removed']
            counts=event['example_counts'];total=sum(counts.values())
            assert set(counts)==set(expected)==set(event['aggregation']['coefficients'])
            assert event['positive_contributors']==len(expected)
            for client,weight in event['aggregation']['coefficients'].items():near(weight,counts[client]/total)
            near(sum(event['aggregation']['coefficients'].values()),1.)
            previous=r['model_sha256'];metric(r['metrics']);metric_sets+=1
            for q in r['queries']:
                queries+=1
                if q['defined']:metric(q['metrics']);metric_sets+=1
                else:assert q['metrics'] is None and q['candidate_model_sha256'] is None
            if r['queries']:
                selections+=1
                alpha,selection=select_endpoint_query(r['queries'],c['journal'][number-1]['metrics']['clean']['macro_f1_all_model_classes'])
                assert alpha==r['selected_alpha'] and selection==r['selection']
            active=task['mode']!='clean' and number in task.get('attack_rounds',list(range(1,11)))
            assert set(r['poisoning'])==(set(task['attackers'])-set(h['removed']) if active else set())
            assert [q['alpha'] for q in r['queries']]==([0.,.125,.5,1.,2.,4.] if r['poisoning'] else [])
            if not active:assert not r['queries'] and r['selected_alpha']==0.
            for client,poison in r['poisoning'].items():
                width=3 if task['mode']=='complete-trigger' else 1
                component=[13,17,24][task['attackers'].index(client)]
                assert poison['feature_indices']==([13,17,24] if width==3 else [component])
                assert poison['client_id']==client and poison['round_number']==number and poison['source_row_count']==counts[client]
                assert 0<=poison['label_flip_count']<=poison['poisoned_row_count']
                assert poison['poisoned_row_count']==(counts[client]+1)//2 and len(poison['feature_indices'])==width
                assert poison['modified_feature_values']==width*poison['poisoned_row_count']
            for proof in r['relative_radius_proofs'].values():
                assert proof['alpha']==r['selected_alpha'] and proof['family']==task['family']
                if task['family']=='relative-radius':
                    near(proof['relative_bound'],(1+proof['alpha'])*proof['clean_norm'])
                    assert proof['submitted_norm']<=proof['relative_bound']*(1+1e-12);relative_proofs+=1
        assert previous==h['final_model_sha256']
    for root in (S/'calibration-histories',S/'clean-controls',E/'clean-controls'):
        for f in sorted(root.glob('*.json')):check_history(read(f))
    source_cases=[];members=[];rounds=[];branch_rows=[];comparisons=[];decisions={};signals=[];classwise=[]
    for task in p['tasks']:
        alias=task['alias'];h=read(S/'histories'/alias/'result.json');check_history(h);c=control(task['seed'],[])
        classwise.extend(classwise_rows(h,c,'source'))
        d=read(S/'selection'/f'{alias}.json');decisions[alias]=d
        roster=sorted(h['journal'][0]['event']['received_clients']);norm=np.asarray(d['magnitude_round_scores']);utility=np.asarray(d['utility_round_scores'])
        assert norm.shape==(10,15) and utility.shape==(10,15)
        episode={client:sorted(norm[:,i])[-3] for i,client in enumerate(roster)}
        for i,client in enumerate(roster):
            near(episode[client],d['episode_scores'][client])
            assert d['magnitude_excess_rounds'][client]==[t+1 for t in range(10) if norm[t,i]>tau]
            near(median(list(utility[:,i])),d['utility_persistent_scores'][client])
        assert d['individual_anomalies']==[client for client in roster if episode[client]>tau]
        assert d['utility_risk_clients']==[client for i,client in enumerate(roster) if median(list(utility[:,i]))>cal['utility_score_threshold']]
        assert all(pair['shared_mechanism']=='repeated_magnitude_excess' for pair in d['pair_evidence'])
        for pair in d['pair_evidence']:
            i,j=[roster.index(client) for client in pair['clients']]
            times=[t+1 for t in range(10) if norm[t,i]>tau and norm[t,j]>tau]
            assert pair['coexceedance_rounds']==times
            assert pair['candidate']==(all(client in d['individual_anomalies'] for client in pair['clients']) and len(times)>cal['coactive_round_count_threshold'])
        v4=d['v4_comparison'];combined=np.maximum(norm,utility)
        np.testing.assert_allclose(combined,np.asarray(v4['round_scores']),rtol=0,atol=1e-12)
        for i,client in enumerate(roster):near(median(list(combined[:,i])),v4['persistent_scores'][client])
        truth=set(task['attackers']) if task['mode']!='clean' else set()
        effective=[a['round'] for a,b in zip(h['journal'],c['journal'],strict=True) if worst_asr(a['metrics'])-worst_asr(b['metrics'])>=.20
            and b['metrics']['clean']['macro_f1_all_model_classes']-a['metrics']['clean']['macro_f1_all_model_classes']<=.05]
        altered={client:[r['round'] for r in h['journal'] if r['relative_radius_proofs'].get(client,{}).get('perturbation_norm',0)>0] for client in task['attackers']} if truth else {}
        case=dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'],schedule=task['schedule'],attack_rounds=task['attack_rounds'],
            effective_rounds=effective,actually_modified_rounds=altered,utility_risk_clients=d['utility_risk_clients'],
            benign_utility_risk_clients=sorted(set(d['utility_risk_clients'])-truth),**stats(h,c))
        source_cases.append(case)
        for client in roster:
            signals.append(dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'],schedule=task['schedule'],client=client,
                v5_actor_anomaly=client in d['individual_anomalies'],episode_score=d['episode_scores'][client],
                magnitude_excess_rounds=d['magnitude_excess_rounds'][client],utility_risk=client in d['utility_risk_clients'],
                utility_score=d['utility_persistent_scores'][client],v4_combined_anomaly=client in v4['individual_anomalies'],
                scheduled_adversary_for_evaluation_only=client in truth,actually_modified_rounds=altered.get(client,[])))
        for method,decision in [('v4',v4),('v5',d)]:
            selected=set(decision['selected_group']);individual=set(decision['individual_anomalies'])
            members.append(dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'],schedule=task['schedule'],method=method,
                selected_group=sorted(selected),TP=len(selected&truth),FP=len(selected-truth),FN=len(truth-selected),
                individual_TP=len(individual&truth),individual_FP=len(individual-truth),individual_FN=len(truth-individual),
                candidate_sizes=[len(g) for g in decision['candidate_groups']],effective_raw_control=bool(effective)))
        for r in h['journal']:
            rounds.append(dict(alias=alias,round=r['round'],alpha=r['selected_alpha'],full_asr=r['metrics']['complete_trigger']['asr'],
                worst_asr=worst_asr(r['metrics']),macro_f1=r['metrics']['clean']['macro_f1_all_model_classes']))
        request=read(E/f'{alias}.json')['plan'];bygroup={}
        if request['eligible_for_recovery']:
            for removal in request['removals']:
                value=read(E/'histories'/alias/f"{removal['key']}.json");check_history(value)
                if not removal['removed']:assert value==h
                clean=control(task['seed'],removal['removed']);s=stats(value,clean,c)
                classwise.extend(classwise_rows(value,clean,'origin-replay',c))
                if truth<=set(removal['removed']) and truth:assert s['all_checkpoints_equal_clean'] and s['final_parameter_l2_to_same_roster_clean']==0.
                row=dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'],schedule=task['schedule'],removed=removal['removed'],roles=removal['roles'],**s)
                branch_rows.append(row);bygroup[tuple(removal['removed'])]=row
            for comp in request['comparisons']:
                joint=bygroup[tuple(comp['group'])];singles=[bygroup[(x,)] for x in comp['group']]
                mass=bygroup[tuple(comp['mass_matched_control'])];hashed=bygroup[tuple(comp['hash_control'])]
                counts=h['journal'][0]['event']['example_counts'];benign=sorted(set(counts)-truth)
                candidates=list(combinations(benign,len(comp['group'])));group_mass=sum(counts[x] for x in comp['group'])
                closest=min(candidates,key=lambda g:(abs(sum(counts[x] for x in g)-group_mass),group_key(g)))
                assert list(closest)==comp['mass_matched_control'] and list(min(candidates,key=group_key))==comp['hash_control']
                comparisons.append(dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'],schedule=task['schedule'],method=comp['method'],group=comp['group'],
                    source_final_worst_asr=case['final_worst_asr'],joint_final_worst_asr=joint['final_worst_asr'],joint_peak_worst_asr=joint['peak_worst_asr'],
                    individual_final_worst_asrs=[x['final_worst_asr'] for x in singles],mass_control_final_worst_asr=mass['final_worst_asr'],
                    hash_control_final_worst_asr=hashed['final_worst_asr'],exact_same_roster_clean=joint['all_checkpoints_equal_clean'],
                    final_parameter_l2_to_same_roster_clean=joint['final_parameter_l2_to_same_roster_clean'],
                    joint_final_macro_f1=joint['final_macro_f1'],joint_final_accuracy=joint['final_accuracy'],
                    joint_final_full_roster_clean_f1_loss=joint['final_full_roster_clean_f1_loss'],
                    max_same_roster_clean_f1_loss=joint['maximum_same_roster_clean_f1_loss'],
                    group_sample_count=comp['group_sample_count'],control_sample_count=comp['control_sample_count']))
    totals=[]
    for method in ('v4','v5'):
        for family,schedule in [('unrestricted','persistent'),('unrestricted','intermittent'),('relative-radius','persistent')]:
            chosen=[x for x in members if x['method']==method and x['mode']!='clean' and x['family']==family and x['schedule']==schedule]
            totals.append(dict(method=method,family=family,schedule=schedule,histories=len(chosen),effective_raw_controls=sum(x['effective_raw_control'] for x in chosen),
                **{key:sum(x[key] for x in chosen) for key in ('TP','FP','FN','individual_TP','individual_FP','individual_FN')}))
    clean_totals=[]
    for method in ('v4','v5'):
        chosen=[x for x in members if x['method']==method and x['mode']=='clean']
        clean_totals.append(dict(method=method,histories=len(chosen),histories_with_selected_group=sum(bool(x['selected_group']) for x in chosen),
            false_group_members=sum(x['FP'] for x in chosen),false_individual_flags=sum(x['individual_FP'] for x in chosen)))
    selected_recoveries=[x for x in comparisons if x['method']=='v5' and next(c for c in source_cases if c['alias']==x['alias'])['effective_rounds']]
    overall=[]
    for method in ('v4','v5'):
        chosen=[x for x in members if x['method']==method and x['mode']!='clean']
        overall.append(dict(method=method,**{key:sum(x[key] for x in chosen) for key in ('TP','FP','FN','individual_TP','individual_FP','individual_FN')}))
    summary=dict(status='verified_v5_separated_episode_assessment',calibration=cal,method_totals=totals,clean_totals=clean_totals,
        overall_attribution_totals=overall,
        source_cases=source_cases,memberships=members,origin_comparisons=comparisons,verification=verification,
        v5_selected_recoveries=len(selected_recoveries),v5_selected_zero_final_worst_asr=sum(x['joint_final_worst_asr']==0 for x in selected_recoveries),
        v5_selected_exact_same_roster_clean=sum(x['exact_same_roster_clean'] for x in selected_recoveries),
        checked_metric_sets=metric_sets,checked_query_selections=selections,checked_adaptive_query_candidates=queries,
        checked_relative_radius_proofs=relative_proofs,
        original_defaults_changed=False,thesis_changed=False,new_TPM_quotes=0,test_inference=False)
    save(D/'summary.json',summary);csv_write('method-memberships.csv',members);csv_write('source-cases.csv',source_cases)
    csv_write('source-rounds.csv',rounds);csv_write('origin-branches.csv',branch_rows);csv_write('origin-comparisons.csv',comparisons)
    csv_write('separated-client-signals.csv',signals)
    csv_write('classwise-utility.csv',classwise)
    def pct(x):return f'{100*x:.2f}%'
    table='\n'.join(f"| {x['method']} | {x['family']} | {x['schedule']} | {x['effective_raw_controls']}/{x['histories']} | {x['TP']}/{x['FP']}/{x['FN']} | {x['individual_TP']}/{x['individual_FP']}/{x['individual_FN']} |" for x in totals)
    clean_table='\n'.join(f"| {x['method']} | {x['histories_with_selected_group']}/{x['histories']} | {x['false_group_members']} | {x['false_individual_flags']} |" for x in clean_totals)
    case_table='\n'.join(f"| {c['alias']} | {c['seed']} | {c['mode']} | {c['family']} | {c['schedule']} | {pct(c['peak_worst_asr'])} | {'yes' if c['effective_rounds'] else 'no'} | {', '.join(decisions[c['alias']]['selected_group']) or 'none'} |" for c in source_cases)
    recovery_table='\n'.join(f"| {x['alias']} | {x['method']} | {pct(x['source_final_worst_asr'])} | {pct(x['joint_final_worst_asr'])} | {pct(x['mass_control_final_worst_asr'])} | {'yes' if x['exact_same_roster_clean'] else 'no'} |" for x in comparisons)
    quality_table='\n'.join(f"| {x['alias']} | {pct(x['joint_final_accuracy'])} | {pct(x['joint_final_macro_f1'])} | {100*x['joint_final_full_roster_clean_f1_loss']:+.4f} |" for x in selected_recoveries)
    (D/'README.md').write_text(f'''# V5: separate utility risk and repeated actor-anomaly episodes

This completed study implements the correction proposed after the frozen V4
diagnosis. V5 does not let macro-F1 utility risk create an actor anomaly or group
edge. Identity evidence uses repeated magnitude excess; groups require temporal
coexceedance on that SAME mechanism. Utility risk and tensor descriptors remain
visible as separate investigative evidence. No operational policy changes.

## Common-input V4/V5 assessment

Both methods observe the exact same fourteen source histories on two new actual
allocation memberships and different scheduled adversarial rosters. They share
the same two clean fitting and three clean calibration histories. The V4 rule is
unchanged and recalibrated on those same clean observations, rather than comparing
methods on different attacks or hiding the previous failures.

| Method | Family | Schedule | Effective raw controls | Selected group TP/FP/FN | Individual TP/FP/FN |
| --- | --- | --- | ---: | ---: | ---: |
{table}

Across all 36 scheduled adversarial client-history roles, V4 selects
{overall[0]['TP']} true and {overall[0]['FP']} benign memberships while missing
{overall[0]['FN']}; V5 selects {overall[1]['TP']} true and {overall[1]['FP']} benign
memberships while missing {overall[1]['FN']}. This is an observed precision/recall
trade-off, not uniform dominance. Separate utility risks are not hidden:
separated-client-signals.csv preserves them alongside both actor assessments.
classwise-utility.csv reconstructs per-class TP, FP, FN, support and F1 from every
source/replay confusion matrix, together with the same-excluded-roster clean
comparison. This retains the rare-class impact instead of hiding it in accuracy.
The original full-roster clean comparison is also exported, so the utility cost
of omitting clients is not cancelled by choosing an already-excluded reference.

Memberships count client-history entries, not independent persons. The same three
scheduled identities recur across each allocation's variants. Actual modified
rounds and threshold-exceedance rounds remain available; a scheduled attacker can
export an honest alpha0 update. Ineffective raw controls remain reported and
cannot establish resistance or recovery success.

| Method | Clean histories with selected group | False clean group members | False clean individual flags |
| --- | ---: | ---: | ---: |
{clean_table}

## New source histories

| Case | Allocation | Variant | Family | Schedule | Peak worst ASR | Effective raw control | V5 selected group |
| --- | --- | --- | --- | --- | ---: | --- | --- |
{case_table}

Raw source training remains count-weighted FedAvg; retrospective V5 does not
block its updates. Those ASRs measure the attack under the source protocol, not
online mitigation by V5. Full and each individual trigger are measured; worst
ASR is their maximum. Trigger composition necessity is not established.

## Episode rule and separate utility output

V5 uses the THIRD-largest standardized log1p(relative norm) over ten rounds as
each client's episode statistic. Its strict clean-calibrated threshold is
{tau:.9f}, obtained as the maximum of the calibration campaign/client statistics.
This is a new statistic with its own calibration, not V4's median threshold
reused or lowered after consulting attacker identities. Pair edges require more
than {cal['coactive_round_count_threshold']} common exceedance rounds and both
individual episode flags. No known group size is forced; a selected clique must
leave ten contributors. One or two, staggered, small or norm-constrained adverse
submissions can escape this contract. Genuine benign large updates may qualify.

The unchanged macro-F1 channel has a separate utility-risk output at threshold
{cal['utility_score_threshold']:.9f}. A benign contribution can really harm a
rare class and still not justify a malicious-identity hypothesis. V5 retains that
risk rather than erasing it from evaluation. Coactivity on unlike channels no
longer makes a V5 group. Shared magnitude/time behavior still does not prove
intentional collusion or authorize automatic permanent exclusion.

Continuous validation loss and model-state-aware utility calibration remain
separate proposed extensions, not new validated inputs of V5. The earlier
diagnosis already showed why replacing macro-F1 with loss alone cannot establish
malicious identity: some honest updates also increase validation loss.

## Full-origin replay of selected and oracle-known groups

On effective raw controls, V5 selected groups have zero final full/component ASR
in {summary['v5_selected_zero_final_worst_asr']}/{len(selected_recoveries)} comparisons;
{summary['v5_selected_exact_same_roster_clean']}/{len(selected_recoveries)} match EVERY
checkpoint of their same-excluded-roster clean reference. Oracle-labelled roles
are separate diagnostics; when a selected group equals the oracle, the shared
numerical branch is not an independent replication.

| Case | Group role | Original final worst ASR | Origin joint-removal ASR | Closest-mass benign-removal ASR | Every checkpoint equals same-roster clean |
| --- | --- | ---: | ---: | ---: | --- |
{recovery_table}

All fifteen rounds are retrained from preserved pre-attack W0. Surviving attackers
relearn endpoints and requery each corrected parent on their DECLARED active
dates, including the intermittent schedule. Historical vectors and original
alphas are never reused at changed parents. No-removal reproduces the source.
Individual, joint, closest-mass and hash-ranked benign removals remain reported.
Some single removals may reach zero ASR too; joint zero alone cannot demonstrate
synergy, composition necessity or intentional coordination.
The offline runner retains client rows and deterministic training; live-client
availability and cooperation for such replay are not established by this study.

Exact clean matching assumes clean W0, correct attribution, complete removal of
active attackers and the frozen deterministic training/data contract. The clean
reference omits the SAME clients during the replay interval; earlier benign
influence already in W0 remains in both. This is conditional restoration to the
client-exclusion counterfactual, not selective erasure of only poisoned rows or
restoration to the original full-roster model. Nonzero parameter residuals and
utility losses are retained even when all tested ASRs are zero.
origin-branches.csv and classwise-utility.csv retain utility loss to BOTH clean
references. Equality to the same-excluded-roster reference does not by itself
establish harmless removal relative to ordinary training with all clients.

| V5 selected replay | Final clean accuracy | Final macro-F1 | F1 loss to full-roster clean (percentage points) |
| --- | ---: | ---: | ---: |
{quality_table}

Negative loss denotes an improvement. Per-class changes and worst intermediate
utility loss remain in the CSVs; final utility alone is not the entire trajectory.

## Protocol, interruption and verification

Schedules and cases were frozen before new assessment outcomes. Persistent
attacks are active in R1-10; intermittent attacks in [1,2,4,7,10]; R11-15 are
unmodified continuation. Per-active-round poisoned-row budgets match between
distributed/full variants; feature-edit and total row-round budgets differ across
variant/schedule. All adversaries use the restricted six-factor poisoned-Adam
endpoint families and privileged validation/same-roster-clean feedback. They
optimize raw ASR with a five-point F1 guard, not unrestricted evasion of V5.
The relative-radius family bounds submitted norm by five times its own honest
gradient norm; ineffective controls do not validate stealth resistance.

The external run stopped after twelve completed source cases without a recorded
numerical exception. Only the two missing cases were resumed. The completed
files were hashed before resumption and checked unchanged before closure; full
fresh replay then checked ALL cases and branches. The cause of the interruption
is unknown. No incomplete case was silently overwritten or counted complete.

40 focused tests pass, including eight new episode, channel-separation, limited-
support, overlap and quorum cases. Fresh deterministic replay covers 50 clean
fit/calibration rounds, {verification['source_rounds']} source rounds and
{verification['recovery_rounds']} origin-replay rounds in
{verification['recovery_branches']} branches, including
{verification['adaptive_queries']} adaptive queries and
{verification['clean_reference_histories_checked']} clean references. Separate
accounting reconstructs {metric_sets} metric sets, validates {queries} candidate
queries and {selections} parent-specific selections, schedules, budgets,
sample-weight coefficients, episode scores, utility
outputs, group support and {relative_proofs} relative-radius bounds.
Replay uses the same numerical implementation; it is not independent classifier
reimplementation. Numerical threads are fixed at one for both compared methods.

Both new allocations reuse the same 7096 Data24 training rows, W0 and 3163 reused
root-disjoint validation rows (1733 non-target ASR rows). All eleven relevant
allocation memberships were checked distinct; this does not make them independent
datasets or establish population error rates. The five clean roles are reused
development resources. Old V4 diagnosis, failed selectors/late recovery and all
predecessor publications remain intact. Experimental manifests use software
research keys; there is no fresh TPM Quote, physical-TPM validation, client
signature, new policy default, independent dataset or thesis edit.
''')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,3,figsize=(12,4.5),sharey=True)
    strata=[('unrestricted','persistent','Persistent endpoint'),('unrestricted','intermittent','Intermittent endpoint'),('relative-radius','persistent','Relative-radius endpoint')]
    for ax,(family,schedule,title) in zip(axes,strata,strict=True):
        pos=np.arange(3);width=.35
        for offset,method,color in [(-width/2,'v4','#2563eb'),(width/2,'v5','#0f766e')]:
            item=next(x for x in totals if x['method']==method and x['family']==family and x['schedule']==schedule)
            ax.bar(pos+offset,[item[k] for k in ('TP','FP','FN')],width,label=method.upper(),color=color)
        ax.set_xticks(pos,['TP','FP','FN']);ax.set_title(title,fontsize=10);ax.grid(axis='y',alpha=.2)
    axes[0].set_ylabel('Client-history memberships')
    handles,labels=axes[0].get_legend_handles_labels();fig.legend(handles,labels,loc='lower center',ncol=2)
    fig.suptitle('Common-input V4/V5 attribution: true, false and missed memberships')
    fig.tight_layout(rect=(0,.08,1,.94));fig.savefig(D/'episode-memberships.png',dpi=150);plt.close(fig)
    # Plot only actual recovery comparisons, retain the source for every case.
    recovered=[x for x in comparisons if x['method']=='v5' and x['family']=='unrestricted']
    if recovered:
        fig,ax=plt.subplots(figsize=(10,4.5));pos=np.arange(len(recovered));width=.25
        for offset,key,label,color in [(-width,'source_final_worst_asr','Original source','#b45309'),(0,'joint_final_worst_asr','Selected-group replay','#0f766e'),(width,'mass_control_final_worst_asr','Benign-control replay','#2563eb')]:
            ax.bar(pos+offset,[100*x[key] for x in recovered],width,label=label,color=color)
        ax.set_xticks(pos,[x['alias'] for x in recovered]);ax.set_ylabel('Final worst measured ASR (%)');ax.set_ylim(0,105)
        ax.set_title('Full-origin replay: selected groups and benign controls');ax.legend(fontsize=8);ax.grid(axis='y',alpha=.2)
        fig.tight_layout();fig.savefig(D/'episode-origin-recovery.png',dpi=150);plt.close(fig)
    study.check(p)
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
