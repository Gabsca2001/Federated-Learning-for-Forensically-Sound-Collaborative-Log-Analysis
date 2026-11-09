"""Recount metrics, compare frozen controls, and publish compact evidence."""
from pathlib import Path
import sys, json, csv, hashlib, shutil, os
import numpy as np

R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent
D=R/'results/revision-normonly-endpoint-dba-v1'
B=R/'results/revision-coherent-endpoint-dba-v1'
sys.path.insert(0,str(R/'scripts'))
import revision_normonly_endpoint_dba as study
from coherent_dba_selection import worst_asr
from endpoint_attack_selection import select_endpoint_query
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.federated_model import arrays_from_export

def read(p):return json.loads(p.read_bytes())
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def save(p,v):
    with p.open('x') as h:json.dump(v,h,indent=2,allow_nan=False);h.write('\n')
def near(a,b):assert abs(a-b)<1e-12,(a,b)
def metric(m):
    cm=m['clean']['confusion_matrix']['values'];n=len(cm);f=[]
    for i in range(n):
        den=sum(cm[i])+sum(cm[j][i] for j in range(n));f.append(2*cm[i][i]/den if den else 0.)
    near(m['clean']['macro_f1_all_model_classes'],sum(f)/n)
    near(m['clean']['accuracy'],sum(cm[i][i] for i in range(n))/sum(map(sum,cm)))
    assert sum(map(sum,cm))==3163
    for t in (m['complete_trigger'],*m['component_triggers'].values()):
        assert t['non_target_denominator']==1733
        near(t['asr'],t['target_predictions']/t['non_target_denominator'])
        if t['reference_correct_denominator']:
            near(t['reference_correct_asr'],t['reference_correct_target_predictions']/t['reference_correct_denominator'])

def hist(folder,seed,method,mode):
    return read(folder/'evidence/histories'/f's{seed}-{method}-{mode}'/'result.json')
def observed(h):return [r for r in h['journal'] if r['event']['decision']=='commit']
def peak(h):return max((worst_asr(r['validation']) for r in observed(h)),default=None)
def endpoint(h):return h['journal'][-1]['validation'] if h['complete'] else None

def main():
    p=read(D/'protocol-before-training.json');pp,op,old=study.check(p)
    v=read(D/'verification.json');assert v['status']=='full_trajectory_and_query_replay_verified'
    save(D/'report-before-reading.json',{'reporter_sha256':sha(Path(__file__)),'verification_sha256':sha(D/'verification.json')})
    initial_model=read(Path(pp['initial_model_path']))
    initial_arrays=arrays_from_export(initial_model,np=np)
    validation=read(Path(old['training']['validation_path']))['rows']['validation']
    evaluation=[r for r in validation if r['window_id'] not in set(p['root_ids'])]
    deps=study.dependencies();deps[1].set_num_threads(1)
    initial_metrics=study.outcomes(initial_model,evaluation,study.plan_for(p['tasks'][0]),[False]*len(evaluation),deps)
    initial_f1=initial_metrics['clean']['macro_f1_all_model_classes']
    cases=[];rounds=[];first_pairs=[];metric_sets=0;queries=blocked=0
    for task in p['tasks']:
        seed,mode=task['seed'],task['mode'];h=hist(D,seed,'coherent_normonly',mode)
        clean=hist(D,seed,'coherent_normonly','clean')
        clean_rows={r['round']:r['validation'] for r in observed(clean)}
        fed_clean=hist(B,seed,'coherent_fedavg','clean')
        fed_clean_rows={r['round']:r['validation'] for r in observed(fed_clean)}
        f_losses=[];baseline_losses=[];manip=benign_zero=0;effective=[]
        for r in h['journal']:
            e=r['event'];number=r['round'];commit=e['decision']=='commit'
            assert e['eligible_count']==15 and all(e['mandatory_gates'].values())
            if commit:
                assert r['state_after']['last_committed_round']==r['state_before']['last_committed_round']+1
                assert e['positive_contributors']>=10 and r['exported_checkpoint_sha256'] is not None
                m=r['validation']
                f_loss=clean_rows[number]['clean']['macro_f1_all_model_classes']-m['clean']['macro_f1_all_model_classes']
                base_loss=fed_clean_rows[number]['clean']['macro_f1_all_model_classes']-m['clean']['macro_f1_all_model_classes']
                f_losses.append(f_loss);baseline_losses.append(base_loss)
                if worst_asr(m)-worst_asr(clean_rows[number])>=.20 and f_loss<=.05:effective.append(number)
            else:
                m=r['retained_parent_metrics'];f_loss=base_loss=None
                assert r['exported_checkpoint_sha256'] is None
                assert r['state_after']['parent_model_sha256']==r['state_before']['parent_model_sha256']
                assert r['state_after']['last_committed_round']==r['state_before']['last_committed_round']
            metric(m);metric_sets+=1
            if r['queries']:
                queries+=len(r['queries']);blocked+=sum(not q['defined'] for q in r['queries'])
                for q in r['queries']:
                    if q['defined']:metric(q['metrics']);metric_sets+=1
                    else:assert q['metrics'] is None and q['candidate_model_sha256'] is None
                a,s=select_endpoint_query(r['queries'],clean_rows[number]['clean']['macro_f1_all_model_classes'])
                assert a==r['selected_alpha'] and s==r['selection']
            for c,poison in r['poisoning'].items():
                assert poison['poisoned_row_count']==(e['example_counts'][c]+1)//2
                width=3 if mode=='complete-trigger' else 1
                assert len(poison['feature_indices'])==width
                assert poison['modified_feature_values']==width*poison['poisoned_row_count']
                prior=hist(B,seed,'coherent_fltrust',mode)['journal'][number-1]['poisoning'][c]
                assert poison==prior,'Poisoned row identities/budget changed'
            a=e['aggregation'];altered=set(r['actually_manipulated_clients']);manip+=len(altered)
            zero_benign=sum(a['scores'][c]==0 for c in e['received_clients'] if c not in task['attackers']) if a else None
            if zero_benign is not None:benign_zero+=zero_benign
            if a:
                assert a['direction_filter'] is False
                assert all(score in (0.,1.) for score in a['scores'].values())
                near(sum(a['normalized_scores'].values()),1.)
                assert a['aggregate_norm']<=a['root_norm']*(1+1e-12)
            attacker_share=sum(a['normalized_scores'].get(c,0.) for c in task['attackers']) if a else None
            rounds.append(dict(seed=seed,mode=mode,round=number,committed=commit,alpha=r['selected_alpha'],
                full_asr=m['complete_trigger']['asr'],worst_asr=worst_asr(m),clean_f1=m['clean']['macro_f1_all_model_classes'],
                own_clean_f1_loss=f_loss,fedavg_clean_f1_loss=base_loss,positive_contributors=e['positive_contributors'],
                actually_manipulated=len(altered),zero_score_benign=zero_benign,
                assigned_attacker_normalized_share=attacker_share,
                scope='committed_checkpoint' if commit else 'retained_parent_only',**r['timing']))
        end=endpoint(h)
        l2=initial_l2=None
        if h['complete'] and clean['complete']:
            def params(t):return arrays_from_export(read(D/'evidence/histories'/t['task']['name']/'last-committed-checkpoint.json'),np=np)
            l2=float(np.linalg.norm(np.concatenate([(x.astype(float)-y).ravel() for x,y in zip(params(h),params(clean),strict=True)])))
            initial_l2=float(np.linalg.norm(np.concatenate([(x.astype(float)-y).ravel() for x,y in zip(params(h),initial_arrays,strict=True)])))
        root_norms=[r['event']['aggregation']['root_norm'] for r in observed(h)]
        case=dict(seed=seed,mode=mode,complete=h['complete'],committed_rounds=h['committed_rounds'],
            peak_full_asr=max((r['validation']['complete_trigger']['asr'] for r in observed(h)),default=None),
            peak_worst_asr=peak(h),round15_full_asr=end['complete_trigger']['asr'] if end else None,
            round15_worst_asr=worst_asr(end) if end else None,
            max_own_clean_f1_loss=max(f_losses,default=None),max_fedavg_clean_f1_loss=max(baseline_losses,default=None),
            actually_manipulated_exports=manip,benign_zero_scores=benign_zero,
            final_parameter_l2_to_own_clean=l2,effective_attack_rounds=effective,
            final_parameter_l2_to_initial=initial_l2,round15_f1_change_from_initial=end['clean']['macro_f1_all_model_classes']-initial_f1 if end else None,
            root_norm_min=min(root_norms,default=None),root_norm_max=max(root_norms,default=None),
            sum_reference_norm_bounds=sum(root_norms))
        if mode!='clean':
            raw=hist(B,seed,'coherent_fedavg',mode);fl=hist(B,seed,'coherent_fltrust',mode)
            case.update(raw_peak_worst_asr=peak(raw),fltrust_peak_worst_asr=peak(fl),fltrust_complete=fl['complete'])
            # Initial queries share the actual warm parent, root magnitude,
            # poisoning, optimizer seeds and factors. Later branches diverge.
            x=h['journal'][0];y=fl['journal'][0]
            assert x['state_before']['parent_model_sha256']==y['state_before']['parent_model_sha256']
            assert x['root_delta_digest']==y['root_delta_digest'] and x['poisoning']==y['poisoning']
            for qa,qb in zip(x['queries'],y['queries'],strict=True):
                assert qa['alpha']==qb['alpha']
                first_pairs.append(dict(seed=seed,mode=mode,alpha=qa['alpha'],normonly_defined=qa['defined'],fltrust_defined=qb['defined'],
                    normonly_worst_asr=worst_asr(qa['metrics']) if qa['defined'] else None,
                    fltrust_worst_asr=worst_asr(qb['metrics']) if qb['defined'] else None,
                    normonly_f1=qa['metrics']['clean']['macro_f1_all_model_classes'] if qa['defined'] else None,
                    fltrust_f1=qb['metrics']['clean']['macro_f1_all_model_classes'] if qb['defined'] else None))
        cases.append(case)
    assert queries==v['queries'] and sum(c['committed_rounds'] for c in cases)==v['committed_rounds']
    for name,rows in [('cases.csv',cases),('rounds.csv',rounds),('initial-paired-queries.csv',first_pairs)]:
        with (D/name).open('x',newline='') as h:
            fields=list(dict.fromkeys(k for row in rows for k in row))
            w=csv.DictWriter(h,fieldnames=fields);w.writeheader();w.writerows(rows)
    attacked=[c for c in cases if c['mode']!='clean']
    summary=dict(status='fully_replayed_and_count_checked',histories=len(cases),committed_rounds=v['committed_rounds'],
        pauses=v['pauses'],adaptive_queries=queries,blocked_queries=blocked,metric_sets_count_checked=metric_sets,
        initial_same_parent_paired_queries=len(first_pairs),attacked_histories_complete=sum(c['complete'] for c in attacked),
        attacked_peak_worst_asr=max(c['peak_worst_asr'] for c in attacked),
        max_attacked_own_clean_f1_loss=max(c['max_own_clean_f1_loss'] for c in attacked),
        max_all_fedavg_clean_f1_loss=max(c['max_fedavg_clean_f1_loss'] for c in cases),
        initial_macro_f1=initial_f1,
        cases=cases,core_implementation_sha256=implementation_sha256(),default_changed=False,new_TPM_quotes=0,test_inference=False)
    assert implementation_sha256()=='8d7efa28b62a47d306a12958d66b3081d6527518f25641545cc81456640d2e64'
    study.check(p)
    original=R/'results/revision-capped-final-v1'
    assert all(sha(original/n)==h for n,h in read(original/'publication-manifest.json')['files'].items())
    save(D/'source-integrity.json',dict(original_generation_pins_verified=len(old['source_locks']),
        implementation_sha256=implementation_sha256(),default_changed=False,prior_study_file_checksums_verified=True,
        capped_publication_unchanged=True))
    save(D/'summary.json',summary)
    def pc(x):return 'undefined' if x is None else f'{100*x:.2f}%'
    table='\n'.join(f"| {c['seed']} | {c['mode']} | {pc(c['raw_peak_worst_asr'])} | {pc(c['peak_worst_asr'])} | {pc(c['fltrust_peak_worst_asr'])} | {c['committed_rounds']}/15 | {100*c['max_own_clean_f1_loss']:.4f} |" for c in attacked)
    all_zero=summary['attacked_peak_worst_asr']==0
    interpretation=(
        'Removing cosine weighting does not produce a measured backdoor in these four trajectories. '
        'The existing zero-ASR result therefore does NOT identify cosine filtering as necessary: '
        'equal-weight root-norm normalization is already sufficient for observed containment in this fixed family.'
        if all_zero else
        'The normalization-only ablation has nonzero measured ASR in at least one trajectory. '
        'Read the per-case magnitudes, availability and clean utility before attributing a benefit to cosine weighting.')
    (D/'README.md').write_text(f'''# Root-norm-only DBA mechanism ablation

{interpretation}

The separate frozen protocol adds six histories: two clean and four attacked,
using the same two non-IID assignments, 15-client roster, three malicious clients,
warm checkpoint, full 60-row trusted root, 15 rounds, attack rounds 1-10 and
unmodified continuation 11-15 as the learned-endpoint study. The root contributes
only its gradient norm; every nonzero eligible client vector is normalized to
that magnitude and uniformly weighted. Cosine direction filtering and weighting
are removed. Normalization can enlarge small updates; it is not clipping.
The minimum remains ten positive contributors. Pauses cannot become R15 models.

## Matched comparison

All ASRs below are maxima over committed rounds and full/three individual triggers.

| Seed | Poisoned variant | Raw FedAvg peak | Norm-only peak | FLTrust peak | Norm-only rounds | Maximum own-clean F1 loss (points) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
{table}

Each attacker retrains a poisoned endpoint using 10 Adam epochs at its actual
current parent, then queries factors 0/.125/.5/1/2/4 against its own defender.
Among defined candidates within five F1 points of its own same-round clean
control, it maximizes full-or-single ASR, breaking ties by largest factor.
Undefined outputs stay undefined. Data poisoning and optimizer seeds match the
earlier protocol, but each defense has its own adaptive selections and trajectory.
This is a Byzantine endpoint family, not honest one-step poisoned-data training.

The raw and FLTrust comparators are the immutable previously replayed histories;
their protocol and complete publication checksums are checked before and after
the new run. They are reused controls, not new independent replications.
The 24 first-round factor pairs share the exact parent, root delta and poisoning;
initial-paired-queries.csv isolates operator comparisons before branch divergence.
Later trajectories measure the total effect of changing the operator.

## What this does and does not establish

The maximum attacked-versus-own-clean F1 loss is
{100*summary['max_attacked_own_clean_f1_loss']:.4f} points; maximum loss versus the
matching clean FedAvg trajectory across all six cases is
{100*summary['max_all_fedavg_clean_f1_loss']:.4f} points.
Own-clean F1 alone cannot establish that clean training progresses sufficiently.
The cases table includes both comparisons, availability and final parameter
distance to own clean. Zero ASR does not establish removal of every poison effect.

This ablation retains the trusted root for magnitude, changes cosine weighting
only, and does not prove root-free security or separate uniform averaging from
normalization. It also does not establish that all trigger components are
necessary: the preceding study found individual components independently
effective in some raw cases. Retrospective group discovery and individual/joint
removal are separate questions. The original ineffective one-step controls and
three pauses remain preserved and cannot be overwritten by this later result.

The starting checkpoint is already trained (initial macro-F1
{100*initial_f1:.4f}%). Cases include clean F1 change from that start, final
parameter displacement, reference-norm range and the sum of per-round magnitude
bounds. A short, small-step warm-start run can preserve an existing classifier
while restricting both useful adaptation and malicious change. It cannot
establish a favorable security-versus-learning trade-off from scratch.

Evaluation reuses 3163 validation rows disjoint from all 60 root rows, with 1733
non-target rows for ASR. There is no new test prediction or independent dataset.
Two assignments, finite factors and 15 rounds do not cover arbitrary adaptive
directions, denial of service, root poisoning, cold starts or long horizons.
Standardized feature values are not demonstrated realizable raw network traffic.
No production defaults, thesis text, TPM evidence or client signatures change.

## Verification and storage

38 focused tests passed: eight new analytical/failure-case tests and the existing
30 endpoint-selection, coherent-context and FLTrust tests. The complete fresh
replay checks {v['committed_rounds']} rounds and {queries} adaptive queries.
Independent arithmetic accounting reconstructs {metric_sets} clean/trigger metric
sets from confusion matrices and counts, verifies poisoning budgets and selection,
and checks first-round common-parent comparisons. Replay uses the same numerical
implementation; this is not independent classifier reimplementation.
Experimental evidence is signed by a software research authority, not TPM keys.
Core module hashes, 138 original generation pins and the old capped publication
are checked unchanged. Output retains metadata and final checkpoints only.
''')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(2,2,figsize=(10,6.5),sharex=True,sharey=True)
    for ax,c in zip(axes.ravel(),attacked,strict=True):
        for folder,method,label,color,style in [(B,'coherent_fedavg','Raw FedAvg','#b45309','-'),
            (D,'coherent_normonly','Norm only','#2563eb','-'),(B,'coherent_fltrust','FLTrust','#0f766e','--')]:
            rows=observed(hist(folder,c['seed'],method,c['mode']))
            ax.plot([r['round'] for r in rows],[100*worst_asr(r['validation']) for r in rows],label=label,color=color,linestyle=style)
        ax.set_title(f"{c['seed']} / {c['mode']}",fontsize=10)
        ax.axvspan(10.5,15.5,color='#e2e8f0',zorder=0);ax.grid(alpha=.2);ax.set_ylim(-2,103)
    for ax in axes[:,0]:ax.set_ylabel('Worst measured trigger ASR (%)')
    for ax in axes[-1,:]:ax.set_xlabel('Committed round')
    handles,labels=axes[0,0].get_legend_handles_labels()
    fig.legend(handles,labels,loc='lower center',ncol=3)
    fig.suptitle('Mechanism ablation: cosine weights versus equal normalized weights')
    fig.tight_layout(rect=(0,.06,1,.95));fig.savefig(D/'mechanism-ablation.png',dpi=150);plt.close(fig)
    sources=D/'sources';sources.mkdir()
    for n in ('normonly_aggregation.py','normonly_gradient_protocol.py','revision_normonly_endpoint_dba.py'):
        shutil.copy2(R/'scripts'/n,sources/n)
    shutil.copy2(R/'tests/test_normonly_ablation.py',sources/'test_normonly_ablation.py')
    for name in ('tests.log','run.log','verify.log','build_study.py','report_study.py'):
        shutil.copy2(O/name,D/name)
    for name in ('NEXT_STEPS.md','METHODOLOGY.md'):
        shutil.copy2(O/name,D/name)
    pins={str(f.relative_to(D)):sha(f) for f in D.rglob('*') if f.is_file()}
    save(D/'file-checksums.json',pins)
    mirror=O/'published';assert not mirror.exists();shutil.copytree(D,mirror)
    assert all(sha(mirror/n)==h for n,h in pins.items())
    allocated=lambda p:sum(f.stat().st_blocks*512 for f in p.rglob('*') if f.is_file())
    fs=os.statvfs('/mnt/c');free=fs.f_bavail*fs.f_frsize;used=allocated(D)+allocated(mirror)
    assert free>=8*1024**3 and used<64*1024**2
    save(O/'final-storage-check.json',dict(combined_result_allocated_bytes=used,host_free_bytes=free,
        prior_study_unchanged=True,core_and_defaults_unchanged=True,all_checksums_verified=True))
    print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
