"""Read-only extraction of locked paired M6 outcomes; no new model inference."""
from pathlib import Path
from collections import Counter
import hashlib, json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1]
PAIR=ROOT/'artifacts/m6-adaptive-paired-s341593-v4'
OUT=ROOT/'results/m6-adaptive-paired-v4'
SOURCES={}
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
    SOURCES[str(p.relative_to(ROOT))]=sha(p)
    return json.loads(p.read_text())
def save(name,value): (OUT/name).write_text(json.dumps(value,indent=2)+'\n')
def asr(m):
    c=m['confusion_matrix']; row=c['values'][c['labels'].index('reconnaissance')]
    n=sum(row); k=row[c['labels'].index('benign')]
    assert n>0
    return dict(numerator=k,denominator=n,value=k/n)
def figsave(fig,name):
    fig.savefig(OUT/(name+'.png'),dpi=180,bbox_inches='tight')
    fig.savefig(OUT/(name+'.pdf'),bbox_inches='tight'); plt.close(fig)
def main():
    if OUT.exists(): raise FileExistsError(OUT)
    complete=read(PAIR/'complete.json'); assert complete['status']=='verified'
    lock=read(PAIR/'execution-lock.json'); assert sha(PAIR/'execution-lock.json')==complete['execution_lock_sha256']
    for path,digest in lock['files'].items(): assert sha(ROOT/path)==digest,path
    rows=[]; searches=[]; endpoints={}; decisions=[]
    attackers=set(lock['attack_config']['attackers'])
    for arm in ['clean','adaptive']:
        w=PAIR/arm; manifest=read(w/'campaign-manifest.json')['core']
        assert manifest['round_count']==30
        e=read(w/'evaluation/selected-checkpoint-evaluation.json')
        assert sha(w/'evaluation/selected-checkpoint-evaluation.json')==manifest['final_evaluation_sha256']
        endpoints[arm]=dict(selected_round=e['selected_round'],test_macro_f1=e['metrics']['test']['macro_f1_all_model_classes'],test_asr=asr(e['metrics']['test']),validation_macro_f1=e['selection']['value'],test_confusion=e['metrics']['test']['confusion_matrix'])
        for rr in manifest['rounds']:
            n=rr['round_number']; rw=w/f'rounds/round-{n:03d}'
            cp=read(rw/'checkpoint/manifest.json')['core']
            assert sha(rw/'checkpoint/manifest.json')==rr['checkpoint_sha256']
            assert sha(rw/'checkpoint/global-model.json')==rr['global_model_sha256']
            vp=w/f'evaluation/round-{n:03d}-validation.json'; v=read(vp)
            assert sha(vp)==rr['validation_metrics_sha256'] and not v['test_data_observed']
            m=v['validation']; a=asr(m)
            rows.append(dict(arm=arm,round=n,macro_f1=m['macro_f1_all_model_classes'],asr=a['value'],target_rows=a['denominator']))
            ds=list((rw/'in-round-decisions').glob('*.json')); assert len(ds)==15
            bound={x['decision_sha256'] for x in cp['accepted_inputs']}|set(cp['quarantined_decision_sha256'])
            assert {sha(p) for p in ds}==bound
            for p in ds:
                d=read(p)['core']; decisions.append(dict(arm=arm,round=n,client=d['client_id'],group='attacker' if arm=='adaptive' and n>=11 and d['client_id'] in attackers else 'honest',status=d['final_status']))
            if arm=='adaptive' and n<=10:
                assert (rw/'checkpoint/global-model.json').read_bytes()==(PAIR/f'clean/rounds/round-{n:03d}/checkpoint/global-model.json').read_bytes()
            if arm=='adaptive' and n>=11:
                s=read(rw/'adaptive-search/summary.json'); sel=read(rw/'adaptive-selection.json')['core']
                assert sha(rw/'adaptive-search/summary.json')==sel['search_receipt_sha256']
                assert s['query_count']==66 and not s['test_data_accessed']
                for path,digest in s['source_bindings'].items(): assert sha(rw/path)==digest
                if s['selected_query'] is not None:
                    q=read(rw/f"adaptive-search/queries/{s['selected_query']:03d}/decision.json")
                    assert abs(q['validation_macro_f1']-m['macro_f1_all_model_classes'])<1e-12
                    assert q['targeted_asr']==a['value']
                searches.append(dict(round=n,**{k:v for k,v in s.items() if k not in ['source_bindings','knowledge','semantics','selection_rule']}))
        local=[x for x in rows if x['arm']==arm]
        best=max(local,key=lambda x:(x['macro_f1'],-x['round']))
        assert best['round']==e['selected_round']
    delta=endpoints['adaptive']['test_macro_f1']-endpoints['clean']['test_macro_f1']
    counts={arm:dict(Counter(d['status'] for d in decisions if d['arm']==arm and d['round']>=11 and d['group']=='honest')) for arm in endpoints}
    malicious=dict(Counter(d['status'] for d in decisions if d['group']=='attacker'))
    summary=dict(experiment='paired-v4',seed=341593,rounds_per_arm=30,pre_attack_exact_matches=10,endpoints=endpoints,test_macro_f1_delta_adaptive_minus_clean=delta,queries=sum(s['query_count'] for s in searches),successful_search_rounds=sum(s['success_on_optimization_validation'] for s in searches),honest_decisions_rounds11_30=counts,attacker_decisions=malicious,new_inference_performed=False,scope='Exploratory single paired seed; selected-checkpoint test only; not proof of universal robustness.')
    OUT.mkdir()
    save('summary.json',summary); save('trajectories.json',rows); save('searches.json',searches); save('admission-decisions.json',decisions)
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False})
    fig,axs=plt.subplots(2,1,figsize=(10,7),sharex=True)
    for arm,color in [('clean','#2471a3'),('adaptive','#c0392b')]:
        x=[r for r in rows if r['arm']==arm]
        axs[0].plot([r['round'] for r in x],[r['macro_f1'] for r in x],label=arm,color=color)
        axs[1].plot([r['round'] for r in x],[100*r['asr'] for r in x],label=arm,color=color,linestyle='--' if arm=='adaptive' else '-')
        chosen=next(r for r in x if r['round']==endpoints[arm]['selected_round'])
        axs[0].scatter(chosen['round'],chosen['macro_f1'],color=color,marker='*',s=140,zorder=5)
    for ax in axs: ax.axvspan(10.5,30,color='orange',alpha=.09); ax.grid(alpha=.2); ax.legend()
    axs[0].set(ylabel='Validation macro-F1',title='Paired trajectories — stars mark validation-selected checkpoints')
    axs[1].set(ylabel='Reconnaissance → benign ASR (%)',xlabel='Round')
    fig.tight_layout(); figsave(fig,'validation-trajectories')
    fig,ax=plt.subplots(figsize=(10,4))
    ax.bar([s['round'] for s in searches],[100*s['selected_validation_drop'] if s['selected_validation_drop'] is not None else 0 for s in searches],color='#c0392b')
    ax.axhline(0,color='black',linewidth=.7); ax.set(xlabel='Attacked round',ylabel='Macro-F1 drop (percentage points)',title='Immediate change vs untreated proposals on the adaptive arm state\nThis is not the separate clean trajectory comparison')
    fig.tight_layout(); figsave(fig,'within-round-validation-drop')
    fig,axs=plt.subplots(1,2,figsize=(12,5))
    for ax,arm in zip(axs,['clean','adaptive']):
        cm=endpoints[arm]['test_confusion']; ax.imshow(cm['values'],cmap='Blues')
        for i,row in enumerate(cm['values']):
            for j,value in enumerate(row): ax.text(j,i,str(value),ha='center',va='center',fontsize=8,color='white' if value>900 else 'black')
        ax.set_xticks(range(6),cm['labels'],rotation=45,ha='right'); ax.set_yticks(range(6),cm['labels']); ax.set(title=f"{arm}: selected round {endpoints[arm]['selected_round']}",xlabel='Predicted',ylabel='True')
    fig.tight_layout(); figsave(fig,'selected-test-confusion')
    fig,ax=plt.subplots(figsize=(9,4))
    groups=[('Clean honest (300)',counts['clean']),('Adaptive honest (240)',counts['adaptive']),('Adaptive attackers (60)',malicious)]
    statuses=sorted({s for _,c in groups for s in c}); bottoms=[0]*3
    for status in statuses:
        vals=[c.get(status,0) for _,c in groups]; bars=ax.bar([g[0] for g in groups],vals,bottom=bottoms,label=status)
        ax.bar_label(bars,label_type='center',labels=[str(v) if v else '' for v in vals]); bottoms=[a+b for a,b in zip(bottoms,vals)]
    ax.set(ylabel='Client-round decisions',title='Admission decisions, rounds 11–30 (different denominators)'); ax.legend(loc='upper left',bbox_to_anchor=(1,1))
    fig.tight_layout(); figsave(fig,'admission-outcomes')
    text=f'''# Paired adaptive M6 — completed v4\n\nExploratory IID seed 341593, 15 clients, 30 rounds per arm. Clients 02, 05 and 14\nperform targeted reconnaissance-to-benign model poisoning in rounds 11–30.\nThe original gated-composite policy and the fixed 66-query budget per attacked round\nare unchanged. The optimizer sees validation and all proposals, never test.\n\n## Selected-checkpoint results\n\n| Outcome | Clean | Adaptive |\n|---|---:|---:|\n| Selected round | {endpoints['clean']['selected_round']} | {endpoints['adaptive']['selected_round']} |\n| Test macro-F1 | {endpoints['clean']['test_macro_f1']:.6f} | {endpoints['adaptive']['test_macro_f1']:.6f} |\n| Targeted test errors / reconnaissance examples | {endpoints['clean']['test_asr']['numerator']}/{endpoints['clean']['test_asr']['denominator']} | {endpoints['adaptive']['test_asr']['numerator']}/{endpoints['adaptive']['test_asr']['denominator']} |\n\nAdaptive minus clean test macro-F1: {delta*100:+.4f} percentage points.\nAll first ten checkpoints match exactly. The attack performed {summary['queries']}\nqueries in twenty rounds; {summary['successful_search_rounds']} rounds met the prespecified\nvalidation success criterion. See searches.json for individual outcomes and controls.\n\n## Interpretation and boundaries\n\nASR is the number of true reconnaissance examples predicted benign divided by all\ntrue reconnaissance examples (343 validation, 669 pooled test). Other mistakes\nare not targeted attack successes. A zero targeted ASR does not mean perfect\nclassification: the confusion matrices show the other errors.\n\nAdmission and attack effectiveness are separate outcomes: authenticated malicious\nupdates can contribute without attaining their targeted objective. See admission\ncounts and the explicit honest/attacker denominators in the figure. Changes in\nmacro-F1 need not track changes in targeted ASR. The within-round drop compares\nthe selected candidate with untouched proposals at the SAME adaptive trajectory\nstate; it is not the effect relative to the separate clean trajectory.\n\nCheckpoint selection used maximum validation macro-F1 with earliest-round ties.\nTest was accessed only after both complete trajectories; this report reads stored\nmetrics and performs no new model inference or final-round test evaluation.\nOne paired seed cannot establish significance, superiority, universal robustness,\nor a general failure of adaptive poisoning. Prior dataset reuse makes this\nexploratory. No post-test tuning or attack-budget expansion is performed.\n\n## Evidence and reproducibility\n\nCompletion: 2026-09-28, local log final marker at 18:30. The detached recovery\nretained the original 10 clean/9 adaptive rounds, checked the original lock and\nreverified prior rounds. The completed runner stopped TPMs only after verification.\nThe failed v1–v3 workspaces and original v4 log remain preserved.\n\nGenerate once with `.venv/bin/python scripts/report_m6_adaptive_paired_v4.py`.\nThe generator refuses an existing result directory, checks locked source hashes,\ncheckpoint/evaluation/decision bindings, selected-search metrics and checkpoint\nselection. It does not rerun the expensive 1,320-query optimizer or replace the\nindependent per-round verifications already performed by the campaign.\n`manifest.json` binds input and report file hashes; no private signing keys are\nexported. Existing M8 closures do not cover these new experiment artifacts.\n\n## Figures\n\n- validation-trajectories: separate arms, treatment window and selected checkpoints.\n- within-round-validation-drop: immediate validation effect on the adaptive state.\n- selected-test-confusion: pooled test errors for the selected checkpoints only.\n- admission-outcomes: honest and malicious client-round interventions.\n\nFigures are provided as PNG and vector PDF. Underlying data are JSON.\n'''
    (OUT/'README.md').write_text(text)
    SOURCES[str(Path(__file__).relative_to(ROOT))]=sha(Path(__file__))
    save('manifest.json',dict(sources=SOURCES,outputs={p.name:sha(p) for p in sorted(OUT.iterdir())}))
    print(json.dumps(summary,indent=2))
if __name__=='__main__': main()