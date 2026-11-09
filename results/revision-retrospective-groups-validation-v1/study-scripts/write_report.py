"""Write the English group-validation result with all negative cases retained."""
import csv
from collections import defaultdict
from itertools import combinations
import xml.etree.ElementTree as ET
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from group_common import *

selection=read(OUT/'selection-summary.json')['cases']
summary=read(LAB/'verified-effect-summary.json');effects=summary['cases']
continuations=read(LAB/'continuation-results.json');direct=read(LAB/'direct-effects.json')['cases']
protocol=read(LAB/'interventions-protocol-before-computation.json');test=read(LAB/'test-endpoints.json')['endpoints']
rewind=read(LAB/'full-rewind/result.json');rewind_check=read(OUT/'full-rewind-verification.json')
rewind_protocol=read(LAB/'full-rewind/protocol-before-training.json')
attacked=sorted([r for r in effects if r['mode']=='distributed'],key=lambda r:(r['cohort'],r['seed'],r['method']))
labels={'pair-v2':'Pair V2','envelope-prefix-set':'Envelope prefix set'}
def table(headers,rows):return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |',*['| '+' | '.join(map(str,r))+' |' for r in rows]])+'\n'
def pct(v):return f'{v*100:.2f}'
def yes(v):return 'Yes' if v else 'No'
def clients(g):return '/'.join(c.replace('client','') for c in g) or 'None'
selection_table=table(['Partition / seed','V2 pool TP / FP / FN','Priority V2 group','V2 TP / FP / FN','Envelope set','Envelope TP / FP / FN'],[
    [f"{r['task']['cohort']} / {r['task']['seed']}",f"{r['primary_pool']['tp']} / {r['primary_pool']['fp']} / {r['primary_pool']['fn']}",
        clients(next(m['selected'] for m in r['methods'] if m['method']=='pair-v2')),
        ' / '.join(str(next(m[k] for m in r['methods'] if m['method']=='pair-v2')) for k in ('tp','fp','fn')),
        clients(next(m['selected'] for m in r['methods'] if m['method']=='envelope-prefix-set')),
        ' / '.join(str(next(m[k] for m in r['methods'] if m['method']=='envelope-prefix-set')) for k in ('tp','fp','fn'))]
    for r in sorted(selection,key=lambda r:(r['task']['cohort'],r['task']['seed'])) if r['task']['mode']=='distributed'])
direct_table=table(['Partition / seed','Method','Source R10 ASR (%)','Joint R10 ASR (%)','Joint beyond best individual (pp)','Benign controls ≥ joint / total'],[
    [f"{r['cohort']} / {r['seed']}",labels[r['method']],pct(r['direct']['original_ASR']),pct(r['direct']['joint_ASR']),
        pct(r['direct']['joint_minus_best_individual_reduction']),f"{r['direct']['benign_controls_at_least_as_effective']}/{r['direct']['benign_control_count']}"] for r in attacked])
tail_table=table(['Partition / seed','Method','Source R15 ASR (%)','Joint R15 ASR (%)','Individual R15 ASRs (%)','Benign R15 ASRs (%)','Joint beyond best individual (pp)'],[
    [f"{r['cohort']} / {r['seed']}",labels[r['method']],pct(r['continuation']['source_R15_ASR']),pct(r['continuation']['joint_R15_ASR']),
        ', '.join(pct(v) for v in r['continuation']['individual_R15_ASRs']),', '.join(pct(v) for v in r['continuation']['benign_control_R15_ASRs']),
        pct(r['continuation']['joint_minus_best_individual_R15_reduction'])] for r in attacked])
reference_table=table(['Partition / seed','Method','Exact same-start unmodified tail?','Reference R15 ASR (%)','Distance to reference (L2)','Distance to all-client clean history (L2)','Clean-history prediction differences / 3223'],[
    [f"{r['cohort']} / {r['seed']}",labels[r['method']],yes(r['continuation']['same_start_reference_exact_entire_tail']),
        pct(r['continuation']['same_start_unmodified_reference_R15_ASR']),f"{r['continuation']['same_start_reference_distance']['parameter_L2']:.5f}",
        f"{r['continuation']['all_client_clean_history_distance']['parameter_L2']:.5f}",r['continuation']['all_client_clean_history_distance']['prediction_disagreements']] for r in attacked])
mass_rows=[]
for r in attacked:
    case=next(c for c in protocol['cases'] if c['alias']==r['alias']);method=next(m for m in case['methods'] if m['method']==r['method'])
    closest=next(c['removed'] for c in method['continuation_benign_controls'] if c['role']=='closest-mass')
    total=sum(case['client_masses'].values());cmass=sum(case['client_masses'][c] for c in closest)/total
    mass_rows.append([f"{r['cohort']} / {r['seed']}",labels[r['method']],pct(method['selected_original_mass_fraction']),clients(closest),pct(cmass),pct(cmass-method['selected_original_mass_fraction'])])
mass_table=table(['Partition / seed','Method','Selected mass removed (%)','Closest benign set','Benign mass removed (%)','Mass difference (pp)'],mass_rows)
test_rows=[]
for r in attacked:
    for number in (10,15):
        ep=next(t for t in test if t['alias']==r['alias'] and t['round']==number and t['data_mode']=='original-script' and t['removed']==r['selected'])
        comp=max(x['asr'] for x in ep['test']['component_triggers'].values())
        test_rows.append([f"{r['cohort']} / {r['seed']}",labels[r['method']],number,pct(ep['test']['clean']['accuracy']),
            pct(ep['test']['clean']['macro_f1_all_model_classes']),pct(ep['test']['complete_trigger']['asr']),pct(comp)])
test_table=table(['Partition / seed','Method','Round','Test accuracy (%)','Test macro-F1 (%)','Complete ASR (%)','Largest component ASR (%)'],test_rows)
(OUT/'TEST_SELECTED_ENDPOINTS.md').write_text('# Selected-set test endpoints\n\nEach row is a fixed-method selected set. R10 is a direct conditional reaggregation; R15 follows genuinely retrained R11–15. The fold was already evaluated by earlier studies. Raw results also include individuals, benign controls, unmodified references and no intervention. No model selection uses this table.\n\n'+test_table)

# Export compact machine-readable rows without losing the nested raw evidence.
with (OUT/'effect-summary.csv').open('w',newline='') as stream:
    fields=['cohort','seed','method','selected','tp','fp','fn','R10_source_ASR','R10_joint_ASR','R10_joint_beyond_best_individual',
        'R15_source_ASR','R15_joint_ASR','R15_joint_beyond_best_individual','same_start_reference_exact','all_client_clean_parameter_L2']
    writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
    for r in attacked:writer.writerow({'cohort':r['cohort'],'seed':r['seed'],'method':r['method'],'selected':','.join(r['selected']),
        'tp':r['tp'],'fp':r['fp'],'fn':r['fn'],'R10_source_ASR':r['direct']['original_ASR'],'R10_joint_ASR':r['direct']['joint_ASR'],
        'R10_joint_beyond_best_individual':r['direct']['joint_minus_best_individual_reduction'],
        'R15_source_ASR':r['continuation']['source_R15_ASR'],'R15_joint_ASR':r['continuation']['joint_R15_ASR'],
        'R15_joint_beyond_best_individual':r['continuation']['joint_minus_best_individual_R15_reduction'],
        'same_start_reference_exact':r['continuation']['same_start_reference_exact_entire_tail'],
        'all_client_clean_parameter_L2':r['continuation']['all_client_clean_history_distance']['parameter_L2']})

cal={c:read(LAB/'selections'/c/'calibration.json')['threshold'] for c in ('iid','non-iid')}
diagnosis=[]
for case in protocol['cases']:
    if case['task']['mode']!='distributed':continue
    selected=read(LAB/'selections'/f"{case['alias']}.json")
    by_pair={tuple(p['clients']):p for p in selected['pairs']}
    for pair in combinations(sorted(case['truth_for_evaluation_only']),2):
        p=by_pair[pair];channels=p['positive_standardized_increases']
        diagnosis.append({'alias':case['alias'],'cohort':case['task']['cohort'],'seed':case['task']['seed'],
            'experimental_true_pair':list(pair),'score':p['conditioned_score'],'threshold':cal[case['task']['cohort']],
            'candidate_edge':p['candidate_edge'],'strongest_channel':max(channels,key=channels.get),
            'standardized_channels':channels,'after_selection_labelled_diagnosis':True})
diagnosis_payload={'pairs':diagnosis,'used_to_revise_selection':False}
if (OUT/'pair-membership-diagnosis.json').exists():
    assert (OUT/'pair-membership-diagnosis.json').read_bytes()==derived_json_bytes(diagnosis_payload)
else:save(OUT/'pair-membership-diagnosis.json',diagnosis_payload)
(OUT/'PAIR_MEMBERSHIP_DIAGNOSIS.md').write_text('# Post-selection true-pair diagnosis\n\nThis labelled diagnosis explains the frozen clique outputs; it does not retune thresholds or add missed clients. A three-member clique requires all three pair edges. Experimental identity is consulted only after selection. Strong individual departures need not produce all three similarity exceedances.\n\n'+table(
    ['Partition / seed','Experimental true pair','Conditioned score','Frozen threshold','Candidate edge?','Strongest channel'],[
        [f"{r['cohort']} / {r['seed']}",clients(r['experimental_true_pair']),f"{r['score']:.5f}",f"{r['threshold']:.5f}",yes(r['candidate_edge']),r['strongest_channel']] for r in diagnosis]))
pool_totals={k:sum(r['primary_pool'][k] for r in selection if r['task']['mode']=='distributed') for k in ('tp','fp','fn')}
v=summary['verification'];suite=ET.parse(OUT/'targeted-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='31' and all(suite.attrib[k]=='0' for k in ('errors','failures','skipped'))
equal={m:sum(r['continuation']['same_start_reference_exact_entire_tail'] for r in attacked if r['method']==m) for m in labels}
nonzero_env=[f"{r['cohort']} {r['seed']}: {pct(r['continuation']['joint_R15_ASR'])}%" for r in attacked if r['method']=='envelope-prefix-set' and r['continuation']['joint_R15_ASR']>0]
rwcase=rewind_protocol['case'];rw_alias=rwcase['alias']
late_test=next(t for t in test if t['alias']==rw_alias and t['round']==15 and t['data_mode']=='original-script' and t['removed']==rwcase['selected'])
rwlabels={'source-control':'Original scripted attack, all clients','selected-original-script':'W0 replay excluding the selected set',
    'selected-unmodified-reference':'W0 matched unmodified reference, same exclusions','all-client-unmodified':'W0 privileged unmodified replay, all clients'}
rwtable=table(['Intervention','R15 validation ASR (%)','R15 test ASR (%)','R15 test accuracy (%)','R15 test macro-F1 (%)'],[
    ['Late R10 selected-set removal',pct(rwcase['continuation']['joint_R15_ASR']),pct(late_test['test']['complete_trigger']['asr']),
        pct(late_test['test']['clean']['accuracy']),pct(late_test['test']['clean']['macro_f1_all_model_classes'])],
    *[[rwlabels[b['job']['name']],pct(b['rounds'][-1]['validation']['complete_trigger']['asr']),pct(b['final_test']['complete_trigger']['asr']),
        pct(b['final_test']['clean']['accuracy']),pct(b['final_test']['clean']['macro_f1_all_model_classes'])] for b in rewind['branches']]])
text=f'''# Retrospective group validation: selection and causal continuation

Date: 2026-11-03. Step 2, after baseline/DBA consolidation. Documentation is English.

## Findings and supported interpretation

The unchanged pair-conditioned V2 method is now evaluated on both IID and
non-IID histories with changed experimental attacker assignments. Its highest
ranked feasible group contains **two of three attackers in all six attacked
cases**. No priority group contains a benign client, but every one misses an
attacker. The complete candidate pool contains **{pool_totals['tp']} true,
{pool_totals['fp']} false and {pool_totals['fn']} missed client occurrences**.
All maximal cliques are retained; priority-group precision does not erase those
false candidates. No exact three-client clique is recovered.

The [post-selection true-pair diagnosis](PAIR_MEMBERSHIP_DIAGNOSIS.md) records
the three relevant edge scores in every attacked case. It explains which
frozen similarity requirements prevent complete clique recovery, without
lowering thresholds or inserting a missed member using identity truth.

A separately labelled secondary set, the union of frozen individual-envelope
quarantines through round 10, contains all three experimental attackers in each
case (18/18 client occurrences, zero false members). This is an anomaly-selected
set, **not a new pairwise collusion detector**. Both methods return no candidates
on the six ordinary clean histories. These are descriptive results on a small,
previously evaluated population; no general false-positive guarantee or malicious
intent follows.

The intervention study executes **{sum(len(c['removals']) for c in direct)} direct removals**, **{len(continuations['branches'])} continuation branches**,
**{continuations['new_local_training_calls']} new local training calls** and **{continuations['new_aggregated_training_rounds']} genuinely trained aggregation rounds**.
It separates immediate reaggregation from new local responses to the corrected
checkpoint. It also separates an unmodified future from a globally clean past.
The later, explicitly post-hoc hard-case rewind adds four full 15-round histories,
810 local training calls and 60 trained rounds. The **total for this step is
5,670 new local training calls and 432 genuinely trained aggregation rounds**.

Nonzero R15 ASR after joint envelope-set removal, if any: **{'; '.join(nonzero_env) or 'none in these six observed validation cases'}**.
The detailed tables below, including residual effects and adverse controls,
determine the conclusion; membership accuracy is not substituted for remediation.

## Frozen methods, source population and evidence boundary

This is a **secondary analysis of existing source trajectories**, not a fresh
untouched prospective evaluation. The group algorithm and its scale floor .05
are unchanged. All references, selection horizons, ranking/control rules and
interventions are recorded before their respective output computations.
No threshold is lowered to capture an observed missed client.

Each cohort uses three clean fitting histories and three disjoint clean
calibration histories. IID fitting uses original seeds 341593/342593/343593;
non-IID fitting uses 411593/412593/413593. Clean threshold calibration uses
451593/452593/453593 for IID and 454593/455593/456593 for non-IID. Only rounds
1–10 enter the fixed-horizon group reference and calibration. Thresholds are
{cal['iid']:.8f} (IID) and {cal['non-iid']:.8f} (non-IID), each the maximum
clean campaign score with strict exceedance. Campaigns/pairs are dependent;
105 pairs per history are not 105 independent false-alarm trials.

Evaluation uses twelve shadow-FedAvg histories from the earlier frozen persistent
attack study: clean/distributed × three seeds × two cohorts. Each has 15 rounds
and 15 clients. IID seeds are 501593/502593/503593, non-IID
511593/512593/513593, with assignments shown below. The known Data24 partitions,
trigger features and ten-epoch local Adam protocol are retained. Both data
distributions have separate clean references; this is not transfer of an IID
reference to an uncalibrated cohort or an independent-dataset result.

The envelope comparator retains two previously fitted clean response predictors
and individual clean envelopes, including the earlier controlled clean-state
perturbation banks. V2 uses the pair-reference/calibration histories declared
here. Their clean-reference information budgets and objectives differ, so the
membership comparison is not an equal-information superiority claim.

Only deltas, tensor shapes, server-validation indicators, cohort/clean-role
bindings and frozen prefix decisions enter the selector. Neutral aliases hide
evaluation mode and attacker assignments in its input index. No private client
rows, ASR, identity truth or rounds 11–15 enter selection. Selection outputs
close before the evaluator reads truth or creates benign controls. This is a
verified data-flow separation; no new OS/Docker isolation or TPM attestation
is claimed. The evaluator/retrainer later accesses committed private snapshots
to execute the declared experimental interventions and unmodified references.

V2 ranks maximal cliques by the weakest conditioned edge, breaking ties by
client tuple. It selects the first clique retaining eight contributors. All
other and oversized candidates remain visible; no candidate is pruned using
truth. Empty selections remain empty. The secondary envelope set uses only
past/current R1–10 quarantines; its fixed-set removal is an investigative
counterfactual, not the original online release/confirmation policy.

## Selection results

TP/FP/FN refer to current experimental local poisoning membership. A benign
response to an inherited poisoned checkpoint is not labelled an intentional
poisoning act. Executed-row commitments and seeds are checked against the
declared simulator inputs for every evaluation prefix.

{selection_table}

All six clean histories return no groups/secondary sets. False members in the
attacked V2 pools remain explicitly recorded in
[the selection summary](selection-summary.json). A top pair can be precise and
still incomplete. The envelope set's exact experimental membership does not
provide independent evidence of pairwise cooperation or malicious intent.

## Direct round-10 interventions

Each selected set is removed jointly and each selected client individually,
using exactly the same stored incoming checkpoint/local outputs. Weights of
remaining clients are renormalized; at least eight contributors are required.
No survivor admission rescoring is mixed into this effect. All 293 removal
outputs and their validation outcomes are recomputed from bound inputs in a
separate verification pass.

Up to twenty uniformly sampled benign subsets of equal size and the benign
subset closest in original sample mass are fixed before effects are inspected.
Truth is used only to identify benign controls. The identical selected subset
is excluded; overlaps with false benign members are allowed. The closest-mass
control is not chosen by ASR. Joint-minus-best-individual means
`ASR(best individual removal) - ASR(joint removal)`, in percentage points.
It is a descriptive contrast, not a theorem of statistical interaction.

{direct_table}

Control ranks include ties and are **not p-values**. If source ASR is zero,
zero joint ASR gives no demonstrated attack-success reduction. Such cases are
retained. More removed clients/sample mass, nonlinear inference and benign data
heterogeneity can affect these contrasts; observed joint improvement alone
does not prove collusion.

### Sample-mass controls

Equal client counts can remove very different aggregation weights under non-IID
data. These mass differences are therefore reported rather than hidden:

{mass_table}

## New training after the corrected checkpoint

Membership is fixed from R1–10. At R10 each original-script branch starts from
the direct corrected aggregate. For R11–15 all remaining clients train again
from that branch's actual global checkpoint, with source seeds, fresh Adam,
same data and original remaining-attack schedules. No historical future update
is reused. The two benign continuation controls are closest-mass and the first
hash-random subset; direct results contain the larger control pool.

No-intervention continuation reproduces all **450 local outputs** and **30 new
global checkpoints** of the six source tails byte-for-byte. Its six R10 starting
checkpoints are also exact copies. The source reproduction distinguishes an
intervention effect from a changed training implementation.

{tail_table}

Positive joint-minus-best-individual contrasts strengthen the descriptive
coordinated-effect hypothesis under these inputs. Zero/negative contrasts,
equally effective benign controls, unsuccessful source attacks and residual ASR
must remain visible. These are finite investigator interventions, not a rule
authorizing permanent bans.

## What exact reference equality means here

For each selected joint set, an independent branch starts from the same actual
incoming **W9**, uses the same remaining clients and seeds, and executes only
unmodified snapshots from R10 through R15. This reference has extra privileged
input evidence. Its incoming W9 can already contain poisoning. Equality to
this reference proves equality of that declared future execution; it does
**not** reconstruct a hypothetical globally clean history before W9.

Complete tail equality (inputs, local outputs and globals at every round) holds
in {equal['pair-v2']}/6 V2 selections and {equal['envelope-prefix-set']}/6 envelope selections.
The all-client clean history is a separate diagnostic with different participation.
Its model distance includes both poisoning history and the removal intervention,
so it cannot alone attribute residual differences to poisoning.

{reference_table}

The reference ASR can itself be nonzero when the starting checkpoint is already
affected. Conversely, ASR zero with unequal model/input histories is not proof
of clean-state recovery. These checks preserve precisely the separation between
structural exposure, numerical effect and semantic interpretation requested in
the supervisor correspondence.

## Complete rewind of the residual hard case

After the primary verification exposed residual ASR, an additional protocol
selected the **largest observed envelope-set R15 residual**, breaking ties by
alias: {rwcase['cohort']} seed {rwcase['seed']}. This is a labelled, post-hoc
mechanistic follow-up, not another independent discovery-validation case.
Its group membership and detector thresholds are unchanged. Four full 15-round
histories were specified before this additional training:

1. Reproduce the original all-client scripted attack from W0.
2. Exclude the same already selected set from R1–15, retraining every remaining
   client at every round under the original script.
3. Independently train an unmodified reference with those same exclusions.
4. Reconstruct the all-client unmodified history, using the original snapshots.

This adds 810 local calls and 60 newly trained aggregation rounds. All 60
aggregate exports and 810 input commitments are rechecked. The original-source
and all-client clean-reference arms match **450 stored local outputs and
30 checkpoints** byte-for-byte. The selected-exclusion arm and its matched
unmodified reference have complete 15-round equality:
**{yes(rewind_check['selected_full_history_reference_equal'])}**.

{rwtable}

The W0 exclusion replay concerns the reduced population, not the original
all-client clean model. The all-client unmodified replay is a different,
privileged intervention: it matches the original all-client clean history
exactly, but requires access to the correct original snapshots, seeds, code,
starting checkpoint and deterministic environment. Snapshot commitment alone
does not establish that its contents were semantically clean.

The comparison demonstrates why the starting point matters in this controlled
case. Excluding every selected attacker late can leave inherited behavior;
replaying from before the scripted poisoning removes that measured residual
under the declared reference assumptions. No actual production history is
rewritten and no universal recovery guarantee is inferred. See
[the frozen follow-up protocol](full-rewind-protocol-before-training.json)
and [full-rewind verification](full-rewind-verification.json).

## Test endpoints, checks and retained limitations

The existing 4,937-row isolated test fold is evaluated at R10/R15 for selected
sets, individuals, continuation benign controls and no intervention; unmodified
references also have R15 endpoints. It has been used in previous studies and is
not claimed as a pristine external holdout. No candidate or threshold is chosen
using these outcomes. [Selected test endpoint table](TEST_SELECTED_ENDPOINTS.md)
and [all endpoint records](test-endpoints.json) retain full/component ASR,
accuracy, macro-F1 and untriggered target rates with explicit denominators.

Verification counts:

- {v['source_prefix_input_commitments']} source-prefix local-input/seed commitments checked.
- {v['direct_model_reaggregations']} direct model exports and their complete validation outcomes recomputed.
- {v['branch_model_reaggregations']} branch recurrence/model exports recomputed, including R10 stored-output steps.
- {v['new_local_input_commitments']} newly executed local-input commitments checked.
- {v['new_no_intervention_local_outputs_matched']} no-intervention local outputs and {v['new_no_intervention_models_matched']} new checkpoints matched exactly.
- {v['final_validation_endpoints_recomputed']} final validation endpoints and {v['test_endpoints_recomputed']} test endpoints recomputed.
- {v['reference_comparisons']} full same-start unmodified-reference comparisons.

The separate hard-case rewind adds 60 verified aggregates, 810 input commitments,
four final validation/test endpoint pairs and the complete reference comparisons
above. Its existing-test-fold results are not used to retune the detector.

The relevant **31 tests pass**, with two existing Typer deprecation warnings.
Production source is unchanged across all 114 package files; the prior 631-pass
full-suite result remains applicable and is not represented as a fresh full run.
No detector algorithm, automatic policy, attestation protocol or thesis source
is changed. No ToN-IoT acquisition or new TPM campaign is performed.

New source selections/replays are signed and hash-bound as local software analyst
evidence, not independent witness registration or trusted time. Previous signed
campaigns and completion records remain preserved. The source archive, input
index, private source pins, selection closure, pre-intervention plan, full pools,
controls and every branch manifest are retained for review.

The study strengthens the agreed **retrospective** analysis across identities
and data distributions. It does not establish complete update-only collusion
discovery: V2 still misses a member in every priority group and flags benign
members in its wider pools. The successful anomaly-selected sets support
additional review/interventions, not semantic verdicts. Live automatic quarantine,
adaptive peak suppression, final formal correspondence and thesis integration
remain separate work. ToN-IoT remains deferred.

Figures: [all validation tails](continuation-asr.png),
[selection errors](group-selection-errors.png),
[direct versus subsequent joint effects](joint-effect-contrasts.png),
[late correction versus complete rewind](full-rewind-hard-case.png).
Each has a PDF export. [Compact numerical effects](effect-summary.csv).
'''
(OUT/'RETROSPECTIVE_GROUP_VALIDATION.md').write_text(text)

plt.rcParams.update({'font.size':9,'axes.titlesize':10,'savefig.dpi':180})
fig,axes=plt.subplots(2,3,figsize=(12.2,7),layout='constrained')
for ax,case in zip(axes.ravel(),sorted([c for c in protocol['cases'] if c['task']['mode']=='distributed'],key=lambda c:(c['task']['cohort'],c['task']['seed']))):
    for method,color in [('source','#777777'),('pair-v2','#c27e28'),('envelope-prefix-set','#276da8')]:
        removed=[] if method=='source' else next(m['selected'] for m in case['methods'] if m['method']==method)
        b=next(b for b in continuations['branches'] if b['alias']==case['alias'] and b['data_mode']=='original-script' and b['removed']==removed)
        ax.plot([r['round'] for r in b['rounds']],[r['validation']['complete_trigger']['asr']*100 for r in b['rounds']],marker='o',lw=1.7,color=color,label='No intervention' if method=='source' else labels[method])
    ax.set_ylim(-3,103);ax.set_xticks(range(10,16));ax.set_xlabel('Round');ax.set_ylabel('Full-trigger ASR (%)');ax.set_title(f"{case['task']['cohort'].upper()} · seed {case['task']['seed']}");ax.grid(alpha=.2)
handles,labs=axes[0,0].get_legend_handles_labels();fig.legend(handles,labs,loc='outside lower center',ncol=3)
fig.suptitle('Fixed prefix-selected interventions · R10 reaggregation, then genuine R11–15 retraining')
for suffix in ('png','pdf'):fig.savefig(OUT/f'continuation-asr.{suffix}')
plt.close(fig)

fig,axes=plt.subplots(1,2,figsize=(10.8,4.7),layout='constrained')
for ax,cohort in zip(axes,('iid','non-iid')):
    source=[c for c in selection if c['task']['cohort']==cohort and c['task']['mode']=='distributed']
    vals=[]
    for name in ('pool','pair-v2','envelope-prefix-set'):
        vals.append({k:sum(c['primary_pool'][k] if name=='pool' else next(m[k] for m in c['methods'] if m['method']==name) for c in source) for k in ('tp','fp','fn')})
    x=np.arange(3)
    for offset,k,color,label in [(-.23,'tp','#49876d','True selected'),(0,'fp','#a75755','Benign selected'),(.23,'fn','#c27e28','Missed attackers')]:ax.bar(x+offset,[v[k] for v in vals],width=.23,label=label,color=color)
    ax.set_xticks(x,['V2 full pool','V2 priority','Envelope set'],rotation=15,ha='right');ax.set_ylabel('Client occurrences across three cases');ax.set_title(cohort.upper());ax.set_ylim(0,15);ax.grid(axis='y',alpha=.2)
handles,labs=axes[0].get_legend_handles_labels();fig.legend(handles,labs,loc='outside lower center',ncol=3)
fig.suptitle('Selection errors · six clean histories have no alarms\nEnvelope membership is not pairwise evidence of collusion')
for suffix in ('png','pdf'):fig.savefig(OUT/f'group-selection-errors.{suffix}')
plt.close(fig)

fig,axes=plt.subplots(1,2,figsize=(12,4.5),layout='constrained')
ordered=sorted([r for r in attacked if r['method']=='pair-v2'],key=lambda r:(r['cohort'],r['seed']));x=np.arange(6)
for ax,method in zip(axes,labels):
    rr=[next(r for r in attacked if (r['cohort'],r['seed'],r['method'])==(q['cohort'],q['seed'],method)) for q in ordered]
    ax.bar(x-.18,[r['direct']['joint_minus_best_individual_reduction']*100 for r in rr],width=.34,label='Direct R10',color='#276da8')
    ax.bar(x+.18,[r['continuation']['joint_minus_best_individual_R15_reduction']*100 for r in rr],width=.34,label='Retrained R15',color='#c27e28')
    ax.set_xticks(x,[('I' if r['cohort']=='iid' else 'N')+str(r['seed']) for r in rr],rotation=35,ha='right');ax.set_title(labels[method]);ax.set_ylabel('Joint beyond best individual (pp)');ax.axhline(0,color='#444444',lw=.8);ax.grid(axis='y',alpha=.2)
handles,labs=axes[0].get_legend_handles_labels();fig.legend(handles,labs,loc='outside lower center',ncol=2)
fig.suptitle('Descriptive joint-removal contrasts · no p-value or proof of intent')
for suffix in ('png','pdf'):fig.savefig(OUT/f'joint-effect-contrasts.{suffix}')
plt.close(fig)
fig,ax=plt.subplots(figsize=(9,4.8),layout='constrained')
for name,color,label in [('source-control','#777777','Original scripted attack'),('selected-original-script','#276da8','Full W0 selected-set replay'),
    ('all-client-unmodified','#49876d','All-client unmodified reference')]:
    b=next(b for b in rewind['branches'] if b['job']['name']==name)
    ax.plot(range(1,16),[r['validation']['complete_trigger']['asr']*100 for r in b['rounds']],color=color,marker='o',label=label)
b=next(b for b in continuations['branches'] if b['alias']==rw_alias and b['data_mode']=='original-script' and b['removed']==rwcase['selected'])
ax.plot(range(10,16),[r['validation']['complete_trigger']['asr']*100 for r in b['rounds']],color='#c27e28',marker='s',label='Late R10 correction + new training')
ax.set_ylim(-3,103);ax.set_xticks(range(1,16));ax.set_xlabel('Round');ax.set_ylabel('Full-trigger validation ASR (%)');ax.grid(alpha=.2);ax.legend(loc='upper left')
ax.set_title(f"Post-hoc hard-case diagnosis · {rwcase['cohort'].upper()} seed {rwcase['seed']}\nSelected membership unchanged; W0 references require declared clean inputs")
for suffix in ('png','pdf'):fig.savefig(OUT/f'full-rewind-hard-case.{suffix}')
plt.close(fig)
print('ENGLISH GROUP REPORT AND FIGURES CREATED',len(text),flush=True)
