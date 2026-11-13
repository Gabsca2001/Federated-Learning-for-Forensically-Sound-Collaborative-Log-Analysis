"""Create the English baseline audit and export scientific figures."""
from pathlib import Path
import json
import statistics as st
from collections import defaultdict
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

OUT=Path(__file__).parent
REPO=Path.cwd();LAB=REPO/'artifacts/revision-baseline-closure-v1'
def read(n):return json.loads((OUT/n).read_bytes())
data=read('consolidated-results.json');secondary=read('secondary-comparison.json')
grad=read('gradient-audit.json');bench=read('benchmark-summary.json')['rows']
envelope=read('envelope-benchmark-summary.json')['rows']
labels={'fedavg':'FedAvg','coordinate_median':'Coordinate median','trimmed_mean':'Trimmed mean',
    'multikrum':'Multi-Krum','bulyan':'Bulyan','flame':'FLAME adaptation','weidetect':'WeiDetect adaptation',
    'gated_composite':'Original composite','gated_fixed_reference':'Fixed-reference composite','client_envelope':'Individual envelope'}
methods=list(labels)[:8]
def pm(r,key):return f"{r[key+'_mean']*100:.2f} ± {r[key+'_sample_std']*100:.2f}"
def table(headers,rows):return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |',*['| '+' | '.join(map(str,r))+' |' for r in rows]])+'\n'
def endpoint_table(mode,rounds=(10,)):
    return table(['Round','Method','Clean accuracy (%)','Macro-F1 (%)','Complete ASR (%)','Max mean component ASR (%)'],[
        [r['round'],labels[r['method']],pm(r,'accuracy'),pm(r,'macro_f1'),pm(r,'ASR'),f"{max(r['component_ASR_means'].values())*100:.3f}"]
        for r in data['fixed_test_endpoint_summary'] if r['mode']==mode and r['round'] in rounds])
full='# Fixed test endpoint summaries\n\nMean ± sample SD across three seeds. Each alternative output is a conditional reaggregation of the same FedAvg-driven incoming history. Component column is the largest of the three component-wise seed means, not a pooled full-trigger result. No hypothesis-test confidence intervals are inferred.\n\n'
for mode in ('clean','distributed','complete-trigger'):full+=f'## {mode}\n\n'+endpoint_table(mode,(10,15))+'\n'
(OUT/'TEST_ENDPOINT_SUMMARIES.md').write_text(full)

# Summarize every secondary endpoint and preserve sample dispersion.
groups=defaultdict(list)
for r in read('secondary-test-results.json')['rows']:groups[(r['cohort'],r['mode'],r['method'],r['round'])].append(r)
summary=[]
for key,rows in sorted(groups.items()):
    cohort,mode,method,number=key
    a=[r['test']['clean']['accuracy'] for r in rows];f=[r['test']['clean']['macro_f1_all_model_classes'] for r in rows]
    v=[r['test']['complete_trigger']['asr'] for r in rows]
    # Attacker identities vary across seeds. Preserve the labelled per-seed
    # components in raw records; summarize each model's worst component here.
    comp=[max(c['asr'] for c in r['test']['component_triggers'].values()) for r in rows]
    summary.append({'cohort':cohort,'mode':mode,'method':method,'round':number,'seeds':len(rows),
        'accuracy_mean':st.mean(a),'accuracy_sample_std':st.stdev(a),'macro_f1_mean':st.mean(f),'macro_f1_sample_std':st.stdev(f),
        'ASR_mean':st.mean(v),'ASR_sample_std':st.stdev(v),'maximum_component_ASR_mean':st.mean(comp),
        'maximum_component_ASR_sample_std':st.stdev(comp)})
payload={'profile':'secondary-conditional-test-summary-v1','summary':summary,'qualification':secondary['qualification']}
(OUT/'secondary-test-summary.json').write_text(json.dumps(payload,sort_keys=True,indent=2)+'\n')
(LAB/'secondary-test-summary.json').write_bytes((OUT/'secondary-test-summary.json').read_bytes())
secondary_md='# Secondary conditional test summaries\n\nPreviously evaluated IID/non-IID shadow-FedAvg histories; three seeds per cell. These are conditional outputs, not independent active defense trajectories. Same test fold as previous studies. Attacker identities vary across seeds: the final column averages each model\'s largest component ASR, without aligning different clients as if they were the same component. Raw records preserve component identities.\n\n'
for cohort in ('iid','non-iid'):
    for mode in ('clean','distributed'):
        secondary_md+=f'## {cohort}: {mode}\n\n'+table(['Round','Method','Clean accuracy (%)','Macro-F1 (%)','Complete ASR (%)','Mean maximum component ASR (%)'],[
            [r['round'],labels[r['method']],pm(r,'accuracy'),pm(r,'macro_f1'),pm(r,'ASR'),pm(r,'maximum_component_ASR')]
            for r in summary if r['cohort']==cohort and r['mode']==mode])+'\n'
(OUT/'SECONDARY_TEST_SUMMARIES.md').write_text(secondary_md)

sel=data['operational_selection_summary']
def selection(mode,phase):return [r for r in sel if r['mode']==mode and r['phase']==phase and r['selection_metric_available']]
def selection_table(mode,phase):return table(['Method','Poisoned excluded / opportunities','Currently clean excluded / opportunities','Clean downweighted','Poisoned downweighted'],[
    [labels[r['method']],f"{r['poisoned_excluded']}/{r['poisoned_opportunities']}",f"{r['clean_excluded']}/{r['clean_update_opportunities']}",r['clean_downweighted'],r['poisoned_downweighted']] for r in selection(mode,phase)])
secondary_table=table(['Cohort','Method','All-clean exclusions / 675','Attacked: poisoned exclusions / 108','Attacked: currently clean exclusions / 567'],[
    [cohort,labels[method],next(r['currently_clean_excluded'] for r in secondary['summary'] if (r['cohort'],r['mode'],r['method'])==(cohort,'clean',method)),
        next(r['poisoned_excluded'] for r in secondary['summary'] if (r['cohort'],r['mode'],r['method'])==(cohort,'distributed',method)),
        next(r['currently_clean_excluded'] for r in secondary['summary'] if (r['cohort'],r['mode'],r['method'])==(cohort,'distributed',method))]
    for cohort in ('iid','non-iid') for method in ('fedavg','flame','weidetect','gated_fixed_reference','client_envelope')])
cost_table=table(['Method','Scope','Contexts × repeats','Median wall (ms)','95th percentile (ms)','Process peak RSS (MiB)'],[
    [labels[r['method']],r['scope'],f"{r['contexts']} × 3",f"{r['median_wall_ms']:.3f}",f"{r['p95_wall_ms']:.3f}",f"{r['process_peak_RSS_MiB']:.1f}"]
    for r in sorted(bench,key=lambda r:(r['scope'],methods.index(r['method'])))])
envelope_table=table(['Cohort','Contexts × independent chains','Median wall (ms)','95th percentile (ms)','Process peak RSS (MiB)'],[
    [r['cohort'],f"{r['contexts']} × 3",f"{r['median_wall_ms']:.3f}",f"{r['p95_wall_ms']:.3f}",f"{r['process_peak_RSS_KiB']/1024:.1f}"] for r in envelope])
gradient_cost=[]
for method in ('gradient_fedavg','literal_eq2','literal_eq3'):
    values=[r['wall_ns']/1e6 for r in grad['server_aggregation_timing_samples'] if r['method']==method]
    gradient_cost.append([method,len(values),f'{st.median(values):.3f}',f'{np.percentile(values,95):.3f}'])
gradient_table=table(['Native gradient recurrence','Timed calls','Median server aggregation (ms)','95th percentile (ms)'],gradient_cost)
gradient_outcome=table(['Case','Completed rounds','Final clean accuracy (%)','Final complete ASR (%)','Untriggered non-target → target (%)','Coefficient sum'],[
    [r['case'],r['completed_rounds'],f"{r['endpoints'][-1]['validation']['clean']['accuracy']*100:.2f}",
        f"{r['endpoints'][-1]['validation']['complete_trigger']['asr']*100:.2f}",
        f"{r['endpoints'][-1]['validation']['untriggered_non_target_to_target_rate']*100:.2f}",f"{r['endpoints'][-1]['coefficient_sum']:.6g}"] for r in grad['cases']])
collection=st.median(r['wall_ns']/1e6 for r in grad['representative_gradient_collection']['timings'])
envnote='\n'.join(f"- {r['cohort']}: R{r['round']}, {labels[r['method']]} conditional test ASR {pm(r,'ASR')}%, clean accuracy {pm(r,'accuracy')}%." for r in summary if r['mode']=='distributed' and r['method'] in ('fedavg','client_envelope') and r['round']==10)

report=f'''# Baseline and DBA validation closure

Date: 2026-11-03. Step 1 of the agreed revision sequence. ToN-IoT is deferred.

## Result and unresolved empirical weaknesses

The baseline comparison is now consolidated with reproducible numerical checks,
operational selection counts, frozen-model test outcomes and measured cost.
The original composite succeeds on the retained distributed-trigger outputs but
does not remove an inherited complete-trigger backdoor: at round 10 its mean
test ASR is **88.21%**, versus **96.97%** for FedAvg. On separately referenced
clean histories it excludes **15/675 IID** and **16/675 non-IID** updates.
These negative outcomes remain part of the result.

The current individual-envelope policy has zero clean exclusions in the added
common-input check and better non-IID poisoned-update coverage than the old
fixed-reference composite. This comparison does not prove general superiority:
the methods have different clean-reference/data requirements, and reaggregating
one round cannot undo the poisoned incoming model. Automatic live deployment,
adaptive-attack resistance, group discovery and clean-state restoration remain
separate validation obligations.

## Preserved protocols and audit scope

The original nine authenticated cases cover clean, distributed and complete-trigger
conditions at three seeds (341593, 342593, 343593), 15 rounds and 15 clients.
Rounds 1–10 inject the attack; rounds 11–15 continue clean local training.
Clients 01/06/11 poison 50% of their selected examples toward the benign label.
The distributed trigger divides features 13/17/24 across clients; the complete
variant applies all three to each attacker's selected examples. Selected example
IDs and label-flip counts match between paired modes; their feature-edit budgets
differ. They are not equal feature-budget attacks.

The MLP, incoming initial checkpoint, partitions, scaler, local Adam protocol
(10 epochs, batch 128, learning rate .001), validation/test records and auxiliary
set are preserved. Server validation has 3,223 rows; test has 4,937 rows; the
fixed WeiDetect auxiliary subset has 2,238 rows selected using the initial
reference model. The experiment remains Data24, not an external-dataset study.

Only **FedAvg drives each source training history**. The other seven methods
reaggregate the same incoming checkpoint and local updates. Their outputs are
conditional single-round comparisons, not independently trained defense
trajectories. The original software admissibility assumption is retained;
there are no new TPM Quotes in this step.

Checks performed now:

- Authenticate all nine original cases and verify 2,025 updates across 135 rounds.
- Recompute **1,080 aggregate model exports byte-for-byte**.
- Recompute all **144 original fixed test endpoints**.
- Authenticate six actual-gradient cases and reproduce **53 aggregate exports byte-for-byte**.
- Add 180 common-input contexts, **900 conditional outputs** and **120 test endpoints** with independent historical clean references.
- Measure aggregation, scoring and current-policy costs in sequential, single-threaded jobs.

`protocol-before-audit-and-benchmark.json` and the later secondary protocol were
frozen before their respective execution. The old endpoint report is bound and
replayed now; no earlier signing or trusted creation time is implied. Original
reports and failed/partial executions are preserved.

## Original shared-update outcomes

All percentages below are mean ± sample standard deviation over three seeds.
The component column is the largest component-wise seed mean. It is not the
complete-trigger ASR. See [all clean and attacked R10/R15 endpoints](TEST_ENDPOINT_SUMMARIES.md)
and [machine-readable endpoint records](fixed-test-endpoints.json).

### Distributed trigger, round 10

{endpoint_table('distributed')}

Coordinate median and trimmed mean retain small nonzero ASRs; rounding them to
zero would be incorrect. All eight methods have zero complete-trigger ASR at
round 15 in this distributed source condition, including FedAvg after five
unpoisoned continuation rounds. That observation is neither a recovery proof
nor evidence of unique defense benefit.

### Complete trigger, round 10

{endpoint_table('complete-trigger')}

Every method retains substantial full-trigger ASR here despite small component
ASRs. The poisoned incoming state helps explain why excluding current poisoned
updates need not clear the full backdoor. At round 15 mean ASR remains 11.81%
for FedAvg, 2.69% for FLAME, 23.93% for WeiDetect and 11.37% for the original
composite. These are conditional outputs on the continuing source histories.
There is no claim of complete removal.

### Operational exclusions and downweights

Ground truth is the actual row-edit record for the current round. A client that
stops poisoning is currently clean; inherited contamination is not relabelled
as a new intentional poisoning action. JSON also separates never-attacker
clients. Strict exclusion means zero aggregation mass/absence from the selected
set. Downweighting and FLAME clipping are separate operations.

Distributed attack, rounds 1–10:

{selection_table('distributed','active')}

Complete-trigger attack, rounds 1–10:

{selection_table('complete-trigger','active')}

On the original clean cases, FLAME excludes 276/675 and WeiDetect 135/675.
The old composite excludes 0/675 but downweights 90/675. Its clean references
and thresholds are fitted to the same clean-round indicators being evaluated:
zero strict exclusions is an **in-sample calibration result**, not an independent
false-positive estimate. The attacked cases use paired clean histories as an
experimental prior. FedAvg's zero exclusions mean participation, not malicious
client detection. Client-level detection metrics are unavailable in the retained
coordinate median/trimmed mean/Multi-Krum/Bulyan reports and are not invented.

## Secondary comparison with separate clean references

To check the calibration weakness, a secondary analysis was predeclared on 12
previously evaluated shadow-FedAvg histories: IID/non-IID × clean/distributed ×
three seeds, 15 rounds each. Each attacked history has 12 attack rounds (108
poisoned opportunities pooled over three seeds). Client assignments differ
across cases. This is a secondary analysis of existing trajectories, not
new prospective training or an untouched external test.

The original composite uses the earliest predeclared historical clean calibration
seed in each cohort (451593 IID, 454593 non-IID), matched by round index.
References are not chosen by evaluation outcomes. Original hyperparameters,
FLAME noise .01, WeiDetect K=12, and the frozen individual-envelope policy stay
fixed. Envelope decisions are authenticated and rechecked in its cost benchmark.
Both weighted conditional variants use a common delta-FedAvg backend here;
the original nine-case composite uses its original Flower weighted-model backend.
This numerical profile difference is explicit.

{secondary_table}

The 15/675 and 16/675 old-composite clean exclusions correspond to **2.22%**
and **2.37%**. Zero envelope clean exclusions is limited to these observed
cases. In attacked non-IID contexts, FLAME excludes 58/108 poisoned updates
and 237/567 currently clean updates; WeiDetect 9/108 and 126/567; the old
composite 26/108 and 7/567; the envelope 77/108 and 0/567.

The richer envelope uses two frozen clean predictors and individual null banks;
the old composite uses one matched clean reference; WeiDetect needs labelled
auxiliary data; FLAME does not use those labelled references. These information
budgets differ. This is not an equal-information ranking of methods.

[All 120 secondary test outcomes](secondary-test-results.json) and their
[40 three-seed summaries](SECONDARY_TEST_SUMMARIES.md) include full/component
ASR, accuracy and macro-F1. Examples of conditional outputs on the attacked
source histories:

{envnote}

An envelope action applied to an already poisoned FedAvg history is different
from the active envelope trajectory in the earlier 36-episode study. The earlier
active zero-ASR result cannot be substituted for this common-input comparison.
Neither comparison demonstrates semantic malice or historical clean-state
reconstruction. The test fold has been used in earlier studies and is not
presented as a pristine new holdout.

## Literature fidelity and explicit adaptations

FLAME's model-cosine clustering, update-norm clipping, averaging and Gaussian
noise stages are represented. This MLP/Data24 adaptation uses fixed noise
factor .01 and deterministic execution seeds; no new differential-privacy
guarantee or full original experimental replication is claimed.
[Primary source: FLAME, Algorithm 1](https://www.usenix.org/system/files/sec22-nguyen.pdf).

WeiDetect's auxiliary F1, Weibull scoring and fixed top-K selection are represented.
K=12 of 15 forces three removals even in all-clean rounds; operational pruning
is not proof of maliciousness. All 135 retained rankings equal seeded F1 top-K.
**88/135** fits are degenerate and use the declared fallback, not successful
Weibull estimation. This dataset, architecture, zero/tie handling and optimizer
are explicit adaptations to the shared-update protocol.
[Primary source: WeiDetect v1, Algorithm 3](https://arxiv.org/html/2504.04367v1).

FedGradTrace's printed Eq. (2) and Eq. (3) define different recurrences: the former
has generally nonunit coefficient sum and rescales the incoming model; the latter
uses normalized trajectory norms in a gradient step. They are retained as
separate literal adaptations. The MLP adapter does not reproduce the full
DistilBERT/FedXLog system. It is not a native malicious-client classifier.
[Primary source: FedXLog/FedGradTrace](https://www.techscience.com/cmc/v87n3/66965/html).

### Actual-gradient cases and interrupted execution

The separate gradient experiment has 10% poison fraction, one actual full-snapshot
class-weighted gradient per client/round, three-snapshot histories and global
SGD learning rate .001. It uses no substituted Adam parameter deltas. Its
protocol differs from the 50%/local-Adam DBA study and is not pooled into that
efficacy table.

{gradient_outcome}

The attacked literal Eq. (2) completes only three of ten requested rounds.
At round 3, both triggered and untriggered non-target examples map to the target
at 100%; this is broad prediction collapse, not evidence of a selective stealth
backdoor. Its coefficient sum is about 10,247.55. The partial round-4 Eq. (2)
model reaches maximum absolute parameter 1.37e30. All three saved alternative
round-4 models have finite parameters but NaN validation loss on that unstable
incoming history. The failure is retained and not repaired by silently changing
the recurrence. No valid fourth-round or ten-round Eq. (2) result is claimed.

A simple source-equation check with incoming scalar 2, zero current gradients
and two trajectory norms of 2 returns 4 under literal Eq. (2), 2 under Eq. (3).
This documents the rescaling difference. The gradient FedAvg control already
has zero ASR throughout its attacked run; Eq. (3)'s zero ASR therefore does not
establish attack mitigation. The clean Eq. (2) accuracy collapse is also retained.

All 53 completed aggregate exports replay exactly. Floating diagnostic norms and
coefficients agree at declared relative tolerance 5e-14 / absolute 1e-15
(maximum observed relative discrepancy 2.16e-15); this tolerance is not applied
to model bytes. [Full diagnosis and records](gradient-audit.json).

## Measured computation cost

Measurements use one CPU thread, preloaded inputs and separate sequential
processes per method/scope. Timers cover both wall and process CPU time.
Kernel rows cover all 135 contexts × three repetitions; full scoring rows cover
the same nine cases at rounds 1/10/15 (27 contexts × three). One warm-up is
excluded per method/scope. Output equivalence is checked outside the timer.
There are **3,240 timed kernel calls** and **162 full scoring calls**.

{cost_table}

Kernel WeiDetect uses cached auxiliary F1 and kernel composite uses cached
masses. Full WeiDetect includes 15 model evaluations on 2,238 auxiliary rows;
full composite includes base/client inference on 3,223 validation rows,
indicators, scoring, policy and aggregation. Neither cached kernel latency nor
process peak RSS represents complete deployment cost. File loading, transport,
local training, clean-reference campaign generation, TPM and first imports are
outside these scopes. Process RSS includes common Torch/Flower libraries,
inputs and allocator retention; it is not incremental defense allocation.
Repeated contexts/samples are dependent; no statistical confidence interval
or production latency guarantee is inferred.

The latest policy is measured separately on its own 180 source contexts, using
three independent stateful chains per case. Each timed operation advances
exactly one round and includes both frozen predictors, support checks, current
envelope decisions and selected-contributor aggregation. It does not time an
idempotent retry. There are **540 timed operations**, two excluded warm-ups.

{envelope_table}

These current-policy contexts differ from the 27 original full-scoring contexts;
no paired speedup ratio is claimed. Initial predictor loading and the cost of
training/calibrating predictors are excluded.

Native-gradient server aggregation is timed separately on its 53 completed
contexts, three repetitions and one warm-up per context:

{gradient_table}

One representative clean full-snapshot collection over all 15 clients / 7,096
records takes median **{collection:.3f} ms** in a shared sequential runtime
(three timed collections after one warm-up). All resulting gradients exactly
match the preserved source. This performs **60 new gradient evaluations and
zero optimizer steps**. The audit process memory peak includes earlier work
and is not attributed to gradient collection alone. This limited acquisition
measurement does not estimate all network/client hardware costs.

## Evidence, implementation and next boundary

This step changes maintained reports and adds audit/measurement scripts. It does
not change production algorithms, thresholds or training protocols. The full
114-file implementation is checked against the preceding source archive. The
preceding **631-test** result remains source-applicable; the full suite is not
rerun here. New verification consists of the numerical/model/selection replays,
source authentication, benchmark checks and final integrity closure described above.

The signed completion is a local software analyst record, **not an independent
witness, trusted timestamp or TPM attestation**. Its closure binds protocols,
results, scripts, figures and source fingerprints. Earlier signed releases are
preserved. The thesis and git index remain unchanged in this step. No new
client-training campaign or ToN-IoT acquisition is performed.

The next agreed step is retrospective group validation: selected groups versus
individual removal, joint removal and benign controls, followed by genuinely
retrained later rounds where causal claims require them. Group membership
errors and the wording “compatible with coordinated behaviour” must remain
explicit. This baseline audit does not close that step, the adaptive envelope
weakness, live TPM integration, final formal alignment or thesis writing.

Figures: [test attack/utility](baseline-test-outcomes.png),
[operational exclusions](secondary-exclusions.png),
[measured cost scopes](measured-costs.png). Each also has a PDF export.
'''
(OUT/'BASELINE_DBA_VALIDATION.md').write_text(report)

plt.rcParams.update({'font.size':10,'axes.titlesize':11,'savefig.dpi':180})
short=['FedAvg','Median','Trimmed','Multi-Krum','Bulyan','FLAME','WeiDetect','Composite']
fig,axes=plt.subplots(2,2,figsize=(12,7.3),layout='constrained')
for j,mode in enumerate(('distributed','complete-trigger')):
    for i,metric in enumerate(('ASR','macro_f1')):
        ax=axes[i,j];x=np.arange(8)
        for offset,number,color in ((-.18,10,'#276da8'),(.18,15,'#d48032')):
            rr=[next(r for r in data['fixed_test_endpoint_summary'] if (r['mode'],r['round'],r['method'])==(mode,number,m)) for m in methods]
            ax.bar(x+offset,[r[metric+'_mean']*100 for r in rr],width=.34,color=color,label=f'Round {number}',
                yerr=[r[metric+'_sample_std']*100 for r in rr],capsize=2)
        ax.set_xticks(x,short,rotation=32,ha='right');ax.set_ylim((0,110) if i==0 else (80,100))
        ax.set_ylabel('Complete-trigger ASR (%)' if i==0 else 'Clean macro-F1 (%)');ax.set_title(mode.replace('-',' ').capitalize());ax.grid(axis='y',alpha=.2)
        if i==0 and j==0:ax.legend()
fig.suptitle('Conditional common-update outputs · three seeds (error bars: sample SD)')
for suffix in ('png','pdf'):fig.savefig(OUT/f'baseline-test-outcomes.{suffix}')
plt.close(fig)

fig,axes=plt.subplots(1,2,figsize=(11,4.7),layout='constrained')
sm=['flame','weidetect','gated_fixed_reference','client_envelope'];sl=['FLAME','WeiDetect','Fixed composite','Envelope'];x=np.arange(4)
for ax,cohort in zip(axes,('iid','non-iid')):
    clean=[next(r for r in secondary['summary'] if (r['cohort'],r['mode'],r['method'])==(cohort,'clean',m)) for m in sm]
    attacked=[next(r for r in secondary['summary'] if (r['cohort'],r['mode'],r['method'])==(cohort,'distributed',m)) for m in sm]
    ax.bar(x-.23,[r['currently_clean_excluded']/675*100 for r in clean],width=.23,label='All-clean excluded',color='#a75755')
    ax.bar(x,[r['poisoned_excluded']/108*100 for r in attacked],width=.23,label='Poisoned excluded',color='#276da8')
    ax.bar(x+.23,[r['currently_clean_excluded']/567*100 for r in attacked],width=.23,label='Currently clean excluded (attack)',color='#d48032')
    ax.set_xticks(x,sl,rotation=20,ha='right');ax.set_ylim(0,105);ax.set_title(cohort.upper());ax.set_ylabel('Update opportunities (%)');ax.grid(axis='y',alpha=.2)
handles,labs=axes[0].get_legend_handles_labels();fig.legend(handles,labs,loc='outside lower center',ncol=3)
fig.suptitle('Secondary common-input check · separate historical clean references\nDifferent information budgets; operational exclusion is not proof of malice')
for suffix in ('png','pdf'):fig.savefig(OUT/f'secondary-exclusions.{suffix}')
plt.close(fig)

fig,axes=plt.subplots(1,3,figsize=(12,4.6),layout='constrained',gridspec_kw={'width_ratios':[1.6,1,1]})
rr=sorted([r for r in bench if r['scope']=='kernel'],key=lambda r:methods.index(r['method']))
axes[0].barh(short,[r['median_wall_ms'] for r in rr],color='#276da8');axes[0].invert_yaxis();axes[0].set_title('Cached-input aggregation\n135 contexts × 3');axes[0].set_xlabel('Median wall time (ms)')
rr=[next(r for r in bench if r['scope']=='full' and r['method']==m) for m in ('weidetect','gated_composite')]
axes[1].bar(['WeiDetect','Original\ncomposite'],[r['median_wall_ms'] for r in rr],color='#d48032');axes[1].set_title('Scoring + aggregation\n27 contexts × 3');axes[1].set_ylabel('Median wall time (ms)')
axes[2].bar(['IID','Non-IID'],[r['median_wall_ms'] for r in envelope],color='#49876d');axes[2].set_title('Envelope + aggregation\n90 contexts/cohort × 3');axes[2].set_ylabel('Median wall time (ms)')
for ax in axes:ax.grid(axis='x' if ax==axes[0] else 'y',alpha=.2)
fig.suptitle('Measured CPU scopes · input loading, client training, transport and TPM excluded')
for suffix in ('png','pdf'):fig.savefig(OUT/f'measured-costs.{suffix}')
plt.close(fig)
print('REPORT AND FIGURES CREATED',len(report),len(summary))
