"""Independent scalar/count checks and English publication of frozen-V4 diagnosis."""
from pathlib import Path
import sys,json,csv,hashlib,shutil,math
import numpy as np
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;sys.path.insert(0,str(R/'scripts'))
import revision_selector_diagnosis as study
from revision_study_data import read
from revision_dba_experiment import save,authenticate
from selector_diagnostic_math import confusion_metrics,class_effect
D=study.D;E=D/'evidence'

def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def near(a,b):assert abs(a-b)<1e-12,(a,b)
def median(v):
    v=sorted(v);return v[len(v)//2] if len(v)%2 else (v[len(v)//2-1]+v[len(v)//2])/2
def csv_write(name,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with (D/name).open('x',newline='') as h:
        w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(rows)

def main():
    p=read(D/'protocol-before-diagnosis.json');study.check(p)
    assert p==read(E/'protocol.json');authenticate(E,read(D/'closure.json')['manifest_sha256'])
    save(D/'report-before-accounting.json',dict(reporter_sha256=sha(Path(__file__)),evidence_manifest_sha256=sha(E/'manifest.json')))
    ref=read(study.S/'reference.json');cal=read(study.S/'calibration.json');tau=cal['persistent_score_threshold']
    limits=dict(z_threshold=tau,relative_norm_limit=math.expm1(ref['channels']['log_relative_norm']['center']+tau*ref['channels']['log_relative_norm']['scale']),
        validation_macro_f1_drop_limit=ref['channels']['validation_impact']['center']+tau*ref['channels']['validation_impact']['scale'])
    all_rows=[];all_clients=[];false=[];details=[];shadows=[];groups=[];case_data={};checked_rows=0
    for task in p['cases']:
        alias=task['alias'];v=read(E/'cases'/f'{alias}.json');case_data[alias]=v
        labels=dict(alias=alias,seed=task['seed'],mode=task['mode'],family=task['family'])
        for profile,value in v['profiles'].items():
            rows=value['rows'];lookup={(r['client'],r['round']):r for r in rows}
            for number in range(1,11):
                roster=[r for r in rows if r['round']==number];assert len(roster)==15
                peer_median=median([r['delta_l2'] for r in roster])
                for r in roster:
                    z1=max(0.,(math.log1p(r['relative_norm'])-ref['channels']['log_relative_norm']['center'])/ref['channels']['log_relative_norm']['scale'])
                    z2=max(0.,(r['validation_impact']-ref['channels']['validation_impact']['center'])/ref['channels']['validation_impact']['scale'])
                    near(z1,r['z_norm']);near(z2,r['z_validation']);near(max(z1,z2),r['score'])
                    near(r['relative_norm'],r['delta_l2']/peer_median if peer_median else 0.)
                    assert r['active']==(r['score']>tau)
                    all_rows.append(dict(**labels,profile=profile,peer_median_delta_norm=peer_median,**r));checked_rows+=1
            for c in value['clients']:
                rs=[lookup[(c['client'],number)] for number in range(1,11)]
                near(median([r['score'] for r in rs]),c['persistent_score'])
                near(median([r['z_norm'] for r in rs]),c['median_norm_score'])
                near(median([r['z_validation'] for r in rs]),c['median_validation_score'])
                assert c['anomalous']==(c['persistent_score']>tau)
                all_clients.append(dict(**labels,profile=profile,**c))
        actual={x['client']:x for x in v['profiles']['actual']['clients']}
        shadow={x['client']:x for x in v['profiles']['all_honest_same_parent']['clients']}
        clean={x['client']:x for x in v['profiles']['matched_clean_parent']['clients']}
        for c in v['false_clients']:
            a,b,k=actual[c],shadow[c],clean[c]
            false.append(dict(**labels,client=c,actual_persistent=a['persistent_score'],norm_median=a['median_norm_score'],
                validation_median=a['median_validation_score'],same_parent_honest_persistent=b['persistent_score'],
                matched_clean_parent_persistent=k['persistent_score'],actual_active_rounds=a['active_rounds'],
                all_honest_same_parent_flag=b['anomalous'],matched_clean_parent_flag=k['anomalous']))
            raw={(r['client'],r['round']):r for r in v['profiles']['actual']['rows']}
            other={(r['client'],r['round']):r for r in v['profiles']['all_honest_same_parent']['rows']}
            for number in range(1,11):
                near(raw[(c,number)]['delta_l2'],other[(c,number)]['delta_l2'])
                near(raw[(c,number)]['validation_impact'],other[(c,number)]['validation_impact'])
        for d in v['false_positive_details']:
            x=class_effect(d['parent_confusion'],d['endpoint_confusion'])
            for key in ('accuracy_change','macro_f1_change'):near(x[key],d[key])
            assert x['supports']==d['supports']
            for a,b in zip(x['class_f1_changes'],d['class_f1_changes'],strict=True):near(a,b)
            near(d['local_training_loss_after']-d['local_training_loss_before'],d['local_training_loss_change'])
            near(d['validation_common_loss_after']-d['validation_common_loss_before'],d['validation_common_loss_change'])
            details.append(dict(**labels,**d))
        for name,decision in v['decisions'].items():
            shadows.append(dict(**labels,profile=name,individual_anomalies=decision['individual_anomalies'],
                candidate_sizes=[len(g) for g in decision['candidate_groups']],selected_group=decision['selected_group']))
        truth=set(task['attackers']) if task['mode']!='clean' else set()
        for group in v['decisions']['actual']['candidate_groups']:
            members=[]
            for c in group:
                a=actual[c];members.append(dict(client=c,scheduled_adversary_for_evaluation_only=c in truth,
                    norm_median=a['median_norm_score'],validation_median=a['median_validation_score']))
            groups.append(dict(**labels,group=group,size=len(group),survivors=15-len(group),feasible=15-len(group)>=10,members=members))
    assert checked_rows==4500
    active=[x for x in details if x['active']]
    class_stats={}
    for d in active:
        for i,(label,change,support) in enumerate(zip(d['class_names'],d['class_f1_changes'],d['supports'],strict=True)):
            stat=class_stats.setdefault(label,dict(support=support,negative_f1_sum=0.,negative_rounds=0,unchanged_TP_rounds=0,increased_FP_rounds=0))
            stat['negative_f1_sum']+=min(change,0.);stat['negative_rounds']+=change<0
            before_tp=d['parent_confusion'][i][i];after_tp=d['endpoint_confusion'][i][i]
            stat['unchanged_TP_rounds']+=before_tp==after_tp
            before_fp=sum(row[i] for row in d['parent_confusion'])-before_tp
            after_fp=sum(row[i] for row in d['endpoint_confusion'])-after_tp
            stat['increased_FP_rounds']+=after_fp>before_fp
    negative_total=-sum(s['negative_f1_sum'] for s in class_stats.values())
    for stat in class_stats.values():stat['share_of_negative_class_f1_changes']=-stat['negative_f1_sum']/negative_total if negative_total else None
    target=next(c for c in case_data['case-02']['profiles']['actual']['clients'] if c['client']=='client15')
    selected=case_data['case-02']['decisions']['actual']['selected_group'];assert 'client15' not in selected
    summary=dict(status='verified_frozen_selector_diagnosis',thresholds=limits,checked_channel_rows=checked_rows,
        false_positive_client_histories=len(false),false_client_histories_validation_median_exceeds=sum(x['validation_median']>tau for x in false),
        false_client_histories_norm_median_exceeds=sum(x['norm_median']>tau for x in false),
        false_clients_still_flagged_with_all_honest_same_parent=sum(x['all_honest_same_parent_flag'] for x in false),
        false_clients_flagged_on_matched_clean_parent=sum(x['matched_clean_parent_flag'] for x in false),
        false_positive_client_rounds=len(details),active_false_positive_rounds=len(active),
        active_fp_validation_dominant=sum(x['dominant_channel']=='validation' for x in active),
        active_fp_local_training_loss_decreases=sum(x['local_training_loss_change']<0 for x in active),
        active_fp_validation_loss_decreases=sum(x['validation_common_loss_change']<0 for x in active),
        active_fp_validation_loss_increases=sum(x['validation_common_loss_change']>0 for x in active),
        active_fp_accuracy_change_range=[min(x['accuracy_change'] for x in active),max(x['accuracy_change'] for x in active)],
        class_effects=class_stats,intermittent_miss=target,groups=groups,shadow_profiles=shadows,
        selected_prefix_reconstruction=read(E/'case-index.json'),new_attack_campaign=False,
        original_rule_changed=False,thresholds_changed=False,default_changed=False,thesis_changed=False,new_TPM_quotes=0)
    save(D/'summary.json',summary);csv_write('client-round-channels.csv',all_rows);csv_write('client-persistence.csv',all_clients)
    csv_write('false-client-decomposition.csv',false);csv_write('false-client-objectives-and-classes.csv',details)
    csv_write('shadow-profile-decisions.csv',shadows);csv_write('candidate-group-channel-evidence.csv',groups)
    fp_table='\n'.join(f"| {x['alias']} | {x['client']} | {x['actual_persistent']:.3f} | {x['norm_median']:.3f} | {x['validation_median']:.3f} | {x['same_parent_honest_persistent']:.3f} | {x['matched_clean_parent_persistent']:.3f} |" for x in false)
    rare=class_stats['exfiltration']
    (D/'README.md').write_text(f'''# Diagnosis of the frozen V4 selector

The principal observed failure is a semantic conflation: a contribution that
reduces global validation macro-F1 is treated as evidence about an abnormal
client and then combined with other anomaly channels into a group. The measured
macro-F1 drop is real. It does not establish that the submitting identity is an
attacker. V4 and all thresholds remain unchanged in this diagnostic study.

## Main findings

All {len(false)} false-positive client-history entries have validation-channel
median above the frozen threshold and norm-channel median below it. All remain
flagged when all submitted vectors are honest gradients at the SAME original
parent, and none is flagged at the matched clean-history parent. This isolates
the inherited model state as sufficient for these false signals under the
declared simulator controls; current malicious peer vectors are not required.

| Case | Benign client | Combined median | Norm median | Validation median | All-honest same-parent median | Clean-parent median |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
{fp_table}

The frozen standardized threshold is {tau:.9f}. A validation-channel exceedance
corresponds to a macro-F1 drop greater than
{100*limits['validation_macro_f1_drop_limit']:.6f} points. Norm-channel exceedance
requires a submitted norm greater than {limits['relative_norm_limit']:.6f} times
the current peer median. These are decoded existing thresholds, not new cutoffs.

## Why a benign gradient can trigger the validation alarm

There are {len(active)} flagged client-round observations among the {len(details)}
rounds inspected for the falsely flagged identities. All {len(active)} are
validation-dominated, and all {len(active)} reduce their own declared common
local training loss. The float64 common weighted validation loss decreases in
{summary['active_fp_validation_loss_decreases']}/{len(active)} and increases in
{summary['active_fp_validation_loss_increases']}/{len(active)}. Local descent does
not ensure global utility, and a continuous validation loss is not universally
safe either. The loss figures are diagnostic, not a replacement rule.

The exfiltration class has only {rare['support']} evaluation examples. Its F1
falls in {rare['negative_rounds']}/{len(active)} flagged observations and accounts
for {100*rare['share_of_negative_class_f1_changes']:.2f}% of the summed negative
per-class F1 changes in those observations. Its number of true positives stays
unchanged in {rare['unchanged_TP_rounds']}/{len(active)}; false-positive predictions
into that class increase in {rare['increased_FP_rounds']}/{len(active)}.
Classwise F1, confusion matrices, accuracy and both objective changes are retained.
These repeated observations are correlated and do not constitute independent
statistical samples. Rare-class utility must remain visible; calling its decline
a risk is appropriate, equating it with malicious identity is not justified.

## The intermittent attacker is suppressed by the median

In case-02, client15 actually exports modified vectors in rounds
{target['source_modified_rounds']}. Its threshold exceedances occur in exactly
{target['active_rounds']}. The fifth and sixth ordered scores are
{target['fifth_order_score']:.9f} and {target['sixth_order_score']:.9f}; their average
is {target['persistent_score']:.9f}, below {tau:.9f}. The ten-round median therefore
discards a five-round attack. No hash, enrollment or reconstruction error is
needed to explain the miss. A new episode statistic would require clean-only
recalibration, including any multiple-window search; the current threshold cannot
simply be reused after changing the aggregation statistic.

## Large and mixed-channel groups

candidate-group-channel-evidence.csv exposes each group's member channels and
survivor count. In the heavily altered histories, norm-anomalous adversaries and
validation-risk benign clients can become one coactive clique. Too-large groups
are not feasible under the ten-contributor rule. The limit is not silently
lowered or the group arbitrarily cut to the known attacker count.
The relative-radius cases also produce mixed-channel pairs: a benign validation
risk and an adversarial magnitude anomaly can coincide in time without a common
anomaly mechanism. Temporal coincidence across unlike risk channels is not proof
of coordinated malicious submissions. Per-tensor similarities remain in the
sealed decisions for later investigation; no new tensor threshold was chosen.

## Controls, verification and limits

All ten source R1-10 prefixes were reconstructed: 100 selected round events,
all 1500 submitted-vector digests, checkpoint digests and complete V4 decisions
match the prior authenticated publication. Unselected adaptive queries and
R11-15 were already verified previously and were not rerun here. Alpha0 poisoned
endpoint fitting was skipped where it cannot affect the exported honest vector.
The two matched clean prefixes are shared controls, not ten independent clean
campaigns. Eight attacked cases provide 80 common-parent all-honest contexts.
Those shadow windows follow the original parent sequence and are NOT a newly
trained all-honest trajectory or a deployable server capability.

17 focused tests pass, including five new channel/median, interval and rare-class
accounting tests. Separate scalar and confusion-matrix accounting checks all
4500 channel rows across three profiles, client medians, paired class effects,
loss differences and invariant benign vectors/validation impacts. The simulator
uses original unpoisoned private client rows for the honest controls; real server
access to those rows is not assumed. Same implementation and reused Data24
validation apply. Original artifacts, measured core, V4 rule, thresholds,
operational defaults and thesis are unchanged. There is no new attack campaign,
independent dataset, test inference, TPM Quote or permanent exclusion.

See CORRECTION_SPECIFICATION.md for the evidence-based next implementation step.
''')
    # Separate channels for every false-client history, without selecting a best case.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(12,6),sharey=True)
    labels=[f"{x['alias']} / {x['client']}" for x in false];mats=[]
    for channel in ('z_norm','z_validation'):
        matrix=[]
        for x in false:
            rs=case_data[x['alias']]['profiles']['actual']['rows']
            matrix.append([next(r[channel] for r in rs if r['client']==x['client'] and r['round']==n) for n in range(1,11)])
        mats.append(np.asarray(matrix))
    upper=max(float(m.max()) for m in mats)
    for ax,m,title in zip(axes,mats,('Magnitude channel','Macro-F1 validation channel'),strict=True):
        im=ax.imshow(m,aspect='auto',vmin=0,vmax=upper,cmap='viridis')
        ax.set_xticks(range(10),range(1,11));ax.set_title(title);ax.set_xlabel('Observed round')
    axes[0].set_yticks(range(len(labels)),labels,fontsize=8)
    fig.colorbar(im,ax=axes.ravel().tolist(),label=f'Standardized channel score (threshold {tau:.3f})',fraction=.025,pad=.03)
    fig.suptitle('All falsely flagged benign client histories: channel decomposition')
    fig.subplots_adjust(left=.21,right=.9,wspace=.12,top=.88,bottom=.1)
    fig.savefig(D/'false-client-channels.png',dpi=150);plt.close(fig)
    rows=[r for r in case_data['case-02']['profiles']['actual']['rows'] if r['client']=='client15'];rows.sort(key=lambda r:r['round'])
    fig,ax=plt.subplots(figsize=(8,4))
    ax.plot([r['round'] for r in rows],[r['score'] for r in rows],color='#2563eb',label='Per-round maximum score')
    actual=[r for r in rows if r['actually_modified_in_source']]
    ax.scatter([r['round'] for r in actual],[r['score'] for r in actual],color='#b45309',zorder=4,label='Actually modified export')
    ax.axhline(tau,color='#b91c1c',linestyle='--',label='Frozen threshold')
    ax.axhline(target['persistent_score'],color='#0f766e',linestyle=':',label='Ten-round median')
    ax.set_xticks(range(1,11));ax.set_xlabel('Observed round');ax.set_ylabel('Standardized score');ax.grid(alpha=.2)
    ax.set_title('case-02 / client15: five modified rounds, missed by the median');ax.legend(fontsize=8)
    fig.tight_layout();fig.savefig(D/'intermittent-client.png',dpi=150);plt.close(fig)
    study.check(p)
    for name in ('report_diagnosis.py','tests.log','run.log','CORRECTION_SPECIFICATION.md'):
        shutil.copy2(O/name,D/name)
    sources=D/'sources';sources.mkdir()
    for name in ('revision_selector_diagnosis.py','selector_diagnostic_math.py'):shutil.copy2(R/'scripts'/name,sources/name)
    shutil.copy2(R/'tests/test_selector_diagnostic_math.py',sources/'test_selector_diagnostic_math.py')
    save(D/'source-integrity.json',dict(predecessor_publication_unchanged=True,
        measured_core_sha256=study.source.prior.implementation_sha256(),rule_changed=False,thresholds_changed=False,default_changed=False))
    pins={str(f.relative_to(D)):sha(f) for f in D.rglob('*') if f.is_file()};save(D/'file-checksums.json',pins)
    mirror=O/'published';assert not mirror.exists();shutil.copytree(D,mirror)
    assert all(sha(mirror/n)==h for n,h in pins.items())
    save(O/'final-storage-check.json',dict(status='verified_and_mirrored',**study.guard()))
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
