from pathlib import Path
import sys,json,hashlib,shutil,csv,os
import numpy as np
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');O=Path(__file__).parent
P=R/'results/revision-coherent-dba-v1';B=R/'results/revision-coherent-endpoint-dba-v1';F=R/'results/revision-coherent-endpoint-feasibility-v1'
def read(p):return json.loads(p.read_bytes())
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def save(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def allocated(p):return sum(f.stat().st_blocks*512 for f in p.rglob('*') if f.is_file())
def pct(v):return 'undefined' if v is None else f'{100*v:.2f}%'
sys.path.insert(0,str(R/'scripts'))
import revision_coherent_dba as ordinary
import revision_coherent_endpoint_dba as learned
p=read(P/'protocol-before-training.json');q=read(B/'protocol-before-training.json')
pp,op,old=ordinary.check(p);learned.check(q)
s=read(P/'summary.json');t=read(B/'summary.json')
assert s['effective_raw_attack_histories']==0 and t['effective_raw_attack_histories']==4
assert t['defended_attacked_histories_complete']==4
assert sha(O/'report_coherent_dba.py')==read(P/'report-before-reading.json')['reporter_sha256']
assert sha(O/'endpoint-study/report_endpoint_dba.py')==read(B/'report-before-reading.json')['reporter_sha256']
# Reproduce the feasibility probe through independently rerun raw first-round queries.
probe=read(F/'results.json');probe_matches=0
for context in probe:
    case=read(B/'evidence/histories'/f"s{context['seed']}-coherent_fedavg-{context['mode']}/result.json")
    for a,b in zip(context['queries'],case['journal'][0]['queries'],strict=True):
        assert a['alpha']==b['alpha'] and a['model_sha256']==b['candidate_model_sha256'] and a['metrics']==b['metrics']
        probe_matches+=1
save(F/'cross-study-reproduction.json',{'raw_first_round_query_models_and_metrics_reproduced':probe_matches,'scope':'Reconstructed by the complete endpoint campaign and its fresh replay, not independent unseen validation.'})

composition=[]
for c in t['comparisons']:
    raw=read(B/'evidence/histories'/f"s{c['seed']}-coherent_fedavg-{c['mode']}/result.json")
    at10=next(r['validation'] for r in raw['journal'] if r['round']==10);at15=raw['journal'][-1]['validation']
    composition.append({'seed':c['seed'],'mode':c['mode'],
        'peak_complete_asr':max(r['validation']['complete_trigger']['asr'] for r in raw['journal']),
        'peak_single_component_asr':max(v['asr'] for r in raw['journal'] for v in r['validation']['component_triggers'].values()),
        'round10_complete_asr':at10['complete_trigger']['asr'],'round10_components':{k:v['asr'] for k,v in at10['component_triggers'].items()},
        'round15_complete_asr':at15['complete_trigger']['asr'],'round15_components':{k:v['asr'] for k,v in at15['component_triggers'].items()},
        'scope':'Full-versus-single trigger measurements, not proof of group collusion or an individual/joint removal intervention.'})
save(B/'trigger-composition.json',composition)
case_csv=list(csv.DictReader((B/'cases.csv').open()))
max_def_loss=max(float(c['maximum_observed_paired_clean_f1_loss']) for c in case_csv if c['method']=='coherent_fltrust' and c['mode']!='clean')
obs=read(B/'submission-observations.json')['cases']
def_obs=[v for v in obs if v['method']=='coherent_fltrust']
parameters_nonidentical=sum(v['final_parameter_l2_to_own_clean']>0 for v in def_obs)

# A compact scientific figure; all curves are observed committed checkpoints.
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
fig,axes=plt.subplots(2,2,figsize=(11,7),sharex=True,sharey=True)
for ax,c in zip(axes.ravel(),t['comparisons'],strict=True):
    for method,color,name in (('coherent_fedavg','#b45309','FedAvg'),('coherent_fltrust','#0f766e','Defended')):
        r=read(B/'evidence/histories'/f"s{c['seed']}-{method}-{c['mode']}/result.json")
        rows=[v for v in r['journal'] if v['event']['decision']=='commit'];xs=[v['round'] for v in rows]
        ax.plot(xs,[100*v['validation']['complete_trigger']['asr'] for v in rows],color=color,label=name+' full trigger')
        ax.plot(xs,[100*max(z['asr'] for z in v['validation']['component_triggers'].values()) for v in rows],color=color,linestyle='--',label=name+' strongest component')
    ax.axvspan(10.5,15.5,color='#e2e8f0',alpha=.65,zorder=0)
    ax.set_title(f"Seed {c['seed']} / {c['mode']}",fontsize=10);ax.set_ylim(-2,103);ax.set_xlim(.5,15.5);ax.grid(alpha=.2)
for ax in axes[:,0]:ax.set_ylabel('Validation ASR (%)')
for ax in axes[-1,:]:ax.set_xlabel('Committed round')
handles,labels=axes[0,0].get_legend_handles_labels();handles.append(Patch(color='#e2e8f0'));labels.append('Unmodified continuation')
fig.legend(handles,labels,loc='lower center',ncol=3,fontsize=8)
fig.suptitle('Byzantine poisoned-endpoint DBA: full and component triggers',fontsize=12)
fig.tight_layout(rect=(0,.09,1,.95));fig.savefig(B/'attack-trajectories.png',dpi=160);plt.close(fig)

def table(summary):
    return '\n'.join(f"| {c['seed']} | {c['mode']} | {'yes' if c['raw_attack_effective'] else 'no'} | {pct(c['raw_peak_worst_asr'])} | {c['defended_committed_rounds']}/15 | {pct(c['defended_observed_peak_worst_asr'])} | {pct(c['defended_final_worst_asr'])} | {c['status']} |" for c in summary['comparisons'])

common='''
ASR is calculated on the1733 non-target validation rows. Worst-trigger ASR is
the maximum over the full trigger and the three individual components, not
every possible subset. Fixed-endpoint F1 uses the3163 root-disjoint validation
rows. Data and historical validation have been observed before; this is an
exploratory two-assignment study, not independent-data confirmation.

The complete trusted60-row root is active from round1, representing the ready
post-expansion profile. No further reserved root exists. Failed quorum pauses
without a new checkpoint or retry; a held parent is not an R15 endpoint. All15
mandatory trust facts are software assumptions. No fresh TPM quote, client
signature, production M5 gradient adapter or attested execution of the attack
optimizer is claimed. These studies do not change the measured core/defaults.

All committed rounds retrain on their actual current parent. Three attackers,
50% hash-ranked poisoned rows each, rounds1-10 and unmodified continuation11-15
are fixed. Distributed clients learn one assigned component; full-trigger
clients learn all three. Row selections match but feature-edit budgets differ.
Features13/17/24 are set to12 in standardized space and selected labels become
benign. Realizability in raw network logs is not demonstrated.

The attacker has a privileged reused-validation and matched-clean oracle. Only
defined candidates within five F1 points of own clean control are ranked, by
worst ASR and then largest alpha. Alpha0 is explicitly unmodified. A candidate
that pauses has no new-checkpoint ASR and is not ranked as zero. This optimizes
a restricted targeted backdoor family, not every Byzantine or DoS strategy.

The raw effectiveness criterion requires at least20 points of paired worst-ASR
increase and at most5 points of own-clean F1 loss at the SAME committed round.
All ineffective controls and pauses remain included. Zero ASR without an
effective control does not establish defense success.
'''
header='| Seed | Attack | Raw effective | Raw observed peak worst ASR | Defended rounds | Defended observed peak worst ASR | Defended R15 worst ASR | Interpretation |\n| --- | --- | --- | ---: | ---: | ---: | ---: | --- |\n'
(P/'README.md').write_text('''# One-step coherent DBA: negative controls and availability failures

The frozen16-history study and its full replay contain198 committed rounds,
three pauses and240 adaptive queries (20 blocked). Four clean histories
reproduce known checkpoints. All six raw attacked controls have zero ASR and
fail the declared effectiveness criterion. Three defended attacked histories
pause, and three complete; no backdoor-resistance conclusion is supported by
these ineffective controls. Availability failures are genuine observed results.

Pure distributed/full branches train the same one-step gradient on poisoned
data. The adaptive distributed branch additionally interpolates/extrapolates
clean/poisoned gradient deltas at factors0/1/4/16/64/256. Such scaling is an
explicit Byzantine model-update extension, not data-only attested training.

'''+header+table(s)+'\n'+common+'''
Evidence is preserved separately from the later endpoint attack development.
No failure was removed or relabelled after observing stronger attacks. Query
and full-trajectory replay uses the same numerical implementation; arithmetic
counts are checked separately. Per-case prefixes/held-parent ASR are in CSVs,
not substituted for missing R15 endpoints.
''')
comp_table='\n'.join(f"| {c['seed']} | {c['mode']} | {pct(c['round15_complete_asr'])} | {pct(max(c['round15_components'].values()))} |" for c in composition)
(B/'README.md').write_text(f'''# Learned Byzantine endpoint DBA: completed quantitative comparison

All12 histories complete15 rounds: four clean mechanism replications and eight
attacked histories. Full replay reconstructs180 rounds and480 adaptive queries;
no candidate or selected trajectory pauses. All four raw attacked histories
meet the fixed selective-attack effectiveness criterion. All four defended
attacked histories have ZERO observed full/component ASR at every committed
round, including unmodified continuation. This is a positive containment result
for the stated family and horizon, not a universal security guarantee.

## Explicitly stronger adversary

Honest clients retain one coherent gradient step. Malicious clients instead
train a poisoned endpoint with10 Adam epochs,batch128,lr.001 at each current
parent. They submit clean_delta+alpha*(endpoint_minus_parent-clean_delta),
querying0/.125/.5/1/2/4 against each actual defender. Every attacked mode is
defender-adaptive. These are forged Byzantine vectors constructed from DBA/full
poisoned datasets, NOT honest SGD gradients or pure data-only attested training.
The extra attacker training and different factor grid define a NEW protocol;
this is not an isolated causal ablation of epochs alone.

The separate four-context warm-parent feasibility probe preceded this protocol.
It found full-trigger controls effective; initial distributed controls were not.
Both modes and both assignments were retained. All24 probe query models/metrics
are reproduced by the raw first rounds here and the full fresh replay. This is
attack development on reused validation, not an independent confirmation set.

## Full trajectories

'''+header+table(t)+f'''

The largest observed attacked-versus-own-clean defended F1 loss is
{100*max_def_loss:.4f} points. All four defended final parameter vectors differ
from their own clean controls ({parameters_nonidentical}/4 nonidentical); zero
ASR therefore does not establish exact restoration or certified unlearning.
See submission-observations.json for actual manipulated exports and distances.
No malicious identity classification or permanent exclusion is inferred.

## Trigger composition required by the correspondence

Raw R15 results distinguish full trigger from the strongest individual component:

| Seed | Poisoned training variant | Full trigger ASR R15 | Strongest single ASR R15 |
| --- | --- | ---: | ---: |
{comp_table}

Construction uses disjoint assigned components for the distributed variant.
The complete trigger need not outperform each component in every assignment.
These measurements test compositional behavior; they do not prove collusion
or replace retrospective individual/joint group removal. Full per-component
values at rounds10/15 are in trigger-composition.json.

{common}

## Limits and verification

The rule combines a clean reference, magnitude normalization and cosine weights.
This two-arm comparison does not isolate which component caused mitigation.
Norm-only ablations and broader adaptive attacks would require a new protocol.
No1/3 three-client influence ceiling or80% sample-mass retention guarantee is
inherited from earlier capped experiments. Scores are convex weights on
normalized deltas, not sample masses or necessarily convex coefficients on
original raw deltas. Cold-start convergence and longer horizons are untested.

Thirty focused tests pass (three endpoint-selection tests, five original-query
and poison-budget tests,14 coherent-context tests and eight FLTrust numerical
tests). Full training/query replay uses the same implementation; separate
accounting recomputes F1/ASR from counts and verifies row-budget matching and
adaptive selections. The classifier is not independently reimplemented.
Experimental manifests have software research authority keys, not TPM identity.

The inherited timing field client_clean_and_poison_gradients_seconds includes
malicious Adam endpoint training in THIS study. Context wall times are measured
on the shared machine and are not isolated operator/TPM latency benchmarks.

The original one-step campaign remains negative/inconclusive for security and
retains its three availability failures. Those failures and the new positive
restricted-family result must be reported together. Code/data paths remain
required for reconstruction; model/client tensor histories were not copied.
''')
(F/'README.md').write_text('''# Byzantine endpoint attack development probe

Before the stronger trajectory protocol, both predefined non-IID assignments
and both distributed/full variants were tested on the pinned warm parent only.
Twelve poisoned Adam models and24 fixed-factor raw candidates were generated.
Both full-trigger contexts met20pp paired ASR increase with<=5pp F1 loss; neither
distributed context did at that first aggregation. All four contexts are kept.

This is development calibration, not a defended trajectory, independent data or
data-only honest-gradient DBA. Its24 candidate models/metrics are subsequently
reproduced in the stronger campaign and full replay. See the separate protocol,
results, summary and cross-study-reproduction.json. No test prediction occurred.
''')

mail_sources={}
for folder in ('70152b64-6d6e-455f-9a64-c1404d00b597','095d6d4c-485f-4f39-9cfa-bd11b2606b65'):
    f=Path('/mnt/c/Users/scama/.codex/attachments')/folder/'Pasted text.txt';mail_sources[str(f)]=sha(f)
save(B/'mail-source-index.json',mail_sources)
shutil.copy2(O/'DBA_EMAIL_AGREEMENT.md',B/'DBA_EMAIL_AGREEMENT.md')
from fl_forensics.round_derivation import implementation_sha256
assert implementation_sha256()=='8d7efa28b62a47d306a12958d66b3081d6527518f25641545cc81456640d2e64'
original=R/'results/revision-capped-final-v1'
assert all(sha(original/n)==h for n,h in read(original/'publication-manifest.json')['files'].items())
save(B/'source-integrity.json',{'original_generation_pins_verified':len(old['source_locks']),
    'implementation_sha256':implementation_sha256(),'original_publication_unchanged':True,'default_changed':False})

# Copy source/controller logs outside the immutable signed evidence directory.
for dest,files in ((P,[(O/'tests.log'),(O/'run.log'),(O/'verify.log'),(O/'report_coherent_dba.py')]),
                   (B,[(O/'endpoint-study/tests.log'),(O/'endpoint-study/run.log'),(O/'endpoint-study/verify.log'),(O/'endpoint-study/report_endpoint_dba.py')]),
                   (F,[(O/'endpoint-probe.log'),(O/'endpoint_attack_probe.py')])):
    for f in files:shutil.copy2(f,dest/f.name)
for dest,names in ((P,('coherent_dba_selection.py','revision_coherent_dba.py','test_coherent_dba_selection.py')),
                   (B,('endpoint_attack_selection.py','revision_coherent_endpoint_dba.py','test_endpoint_attack_selection.py'))):
    folder=dest/'sources';folder.mkdir()
    for n in names:shutil.copy2(R/('tests' if n.startswith('test_') else 'scripts')/n,folder/n)
shutil.copy2(O/'submission_observations.py',B/'sources/submission_observations.py');shutil.copy2(__file__,B/'sources/finalize_dba.py')

for source,mirror in ((P,O/'published'),(B,O/'endpoint-study/published'),(F,O/'endpoint-feasibility')):
    assert not mirror.exists();shutil.copytree(source,mirror)
    pins={str(f.relative_to(source)):sha(f) for f in source.rglob('*') if f.is_file()}
    save(source/'file-checksums.json',pins);shutil.copy2(source/'file-checksums.json',mirror/'file-checksums.json')
    assert all(sha(mirror/n)==h for n,h in pins.items())
overview='''# Coherent-gradient DBA follow-up: interpretation

The first single-step study cannot establish resistance: all six raw attack
controls are ineffective, while three defended histories pause. Keep it as
negative-control and availability evidence.

The separately developed Byzantine endpoint study is informative: all four
raw controls are effective, all four defended attacked histories complete15
rounds and retain zero measured full/component ASR. It tests a stronger model-
update attacker, not merely poisoned-data SGD. The two protocols, data budgets,
root information and remaining limits are documented separately.

- [One-step study and failures](published/README.md)
- [Learned-endpoint comparison](endpoint-study/published/README.md)
- [Full/component trajectories](endpoint-study/published/attack-trajectories.png)
- [Development feasibility probe](endpoint-feasibility/README.md)
- [Exact accepted DBA programme](DBA_EMAIL_AGREEMENT.md)

No default, thesis, independent dataset or external witness deployment changes.
These numerical trials claim no fresh TPM attestation or production integration.
The correspondence calls for compositional DBA evaluation and qualified
retrospective groups; new automatic-defense experiments are extensions.
'''
(O/'REPORT.md').write_text(overview)
used=sum(allocated(x) for x in (P,B,F,O/'published',O/'endpoint-study/published',O/'endpoint-feasibility'))
fs=os.statvfs('/mnt/c');free=fs.f_bavail*fs.f_frsize
assert used<64*1024**2 and free>=8*1024**3
final={'status':'all_studies_verified_and_mirrored','combined_result_allocated_bytes':used,'host_free_bytes':free,
    'original_one_step_histories':16,'original_effective_raw_controls':0,'original_availability_pauses':3,
    'endpoint_histories':12,'endpoint_effective_raw_controls':4,'endpoint_defended_complete':4,
    'endpoint_defended_peak_worst_asr':0.,'max_endpoint_defended_paired_clean_f1_loss_points':100*max_def_loss,
    'development_query_models_reproduced':probe_matches,'core_and_default_unchanged':True}
(O/'final-storage-check.json').write_text(json.dumps(final,indent=2)+'\n')
print(json.dumps(final,indent=2));print(json.dumps(composition,indent=2))
