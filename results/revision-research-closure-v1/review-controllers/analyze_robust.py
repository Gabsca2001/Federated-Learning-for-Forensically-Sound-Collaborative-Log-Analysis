"""Expose complete and failed histories, utility, exclusions and final model distance."""
from pathlib import Path
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from fl_forensics.federated_model import arrays_from_export

OUT=Path(__file__).parent;root=Path.cwd()/'artifacts/revision-research-closure-v1/robust-evaluation'
data=json.loads((root/'results.json').read_bytes());cases=data['cases']
index={(c['task']['seed'],c['task']['strategy'],c['task']['mode']):c for c in cases}
assignments=json.loads((root/'protocol-before-training.json').read_bytes())['tasks'][::4]
rows=[]
for task in assignments:
    seed=task['seed']
    b=index[seed,'bounded-envelope','adaptive'];r=index[seed,'robust-bounded-envelope','adaptive']
    bc=index[seed,'bounded-envelope','clean'];rc=index[seed,'robust-bounded-envelope','clean']
    f1=lambda x:x['validation']['clean']['macro_f1_all_model_classes']
    full=lambda x:x['validation']['complete_trigger']['asr']
    prefix=min(len(b['rounds']),len(r['rounds']))
    tp=fn=fp=0
    for frame in r['rounds']:
        a=set(frame['actual_manipulated_clients']);q=set(frame['quarantined'])
        tp+=len(a&q);fn+=len(a-q);fp+=len(q-a)
    def final_arrays(c):
        return arrays_from_export(json.loads((root/'cases'/c['name']/'rounds/round-015/global-model.json').read_bytes()),np=np)
    distance=float(np.sqrt(sum(np.sum((a.astype(float)-b.astype(float))**2) for a,b in zip(final_arrays(r),final_arrays(rc),strict=True)))) if r['complete'] and rc['complete'] else None
    nonconverged=0
    for frame in r['rounds']:
        report=json.loads((root/'cases'/r['name']/'rounds'/f'round-{frame["round"]:03d}'/'bounded-derivation.json').read_bytes())
        nonconverged+=not report['converged']
    rows.append({'cohort':task['cohort'],'seed':seed,'attackers':task['attackers'],
        'bounded_rounds':len(b['rounds']),'robust_rounds':len(r['rounds']),
        'bounded_failure':b['failure'],'robust_failure':r['failure'],
        'bounded_peak_worst_ASR':max(x['worst_trigger_asr'] for x in b['rounds']),
        'robust_peak_worst_ASR':max(x['worst_trigger_asr'] for x in r['rounds']),
        'bounded_peak_full_ASR':max(map(full,b['rounds'])),'robust_peak_full_ASR':max(map(full,r['rounds'])),
        'common_prefix_rounds':prefix,
        'bounded_common_prefix_peak':max(x['worst_trigger_asr'] for x in b['rounds'][:prefix]),
        'robust_common_prefix_peak':max(x['worst_trigger_asr'] for x in r['rounds'][:prefix]),
        'robust_final_worst_ASR':r['rounds'][-1]['worst_trigger_asr'] if r['complete'] else None,
        'bounded_final_worst_ASR':b['rounds'][-1]['worst_trigger_asr'] if b['complete'] else None,
        'max_clean_F1_loss':max(f1(x)-f1(y) for x,y in zip(bc['rounds'],rc['rounds'],strict=True)),
        'bounded_control_effective':any(x['worst_trigger_asr']-bc['rounds'][i]['worst_trigger_asr']>=.20 and f1(bc['rounds'][i])-f1(x)<=.05 for i,x in enumerate(b['rounds'])),
        'robust_manipulated_intercepted':tp,'robust_manipulated_missed':fn,'robust_currently_unmodified_excluded':fp,
        'robust_final_parameter_L2_from_matched_clean':distance,'robust_nonconverged_rounds':nonconverged})
summary={'planned_cases':len(cases),'complete_cases':sum(c['complete'] for c in cases),'counts':data['counts'],
         'pairs':rows,'max_clean_F1_loss':max(x['max_clean_F1_loss'] for x in rows),
         'clean_utility_2pp_guardrail_passed':all(x['max_clean_F1_loss']<=.02 for x in rows),
         'all_robust_complete':all(c['complete'] for c in cases if c['task']['strategy']=='robust-bounded-envelope'),
         'interpretation':'Fresh assignments, same Data24 partitions and frozen references. Report ineffective controls and failed tails explicitly; finite convex cap does not imply ASR elimination, attacker identification or clean-state recovery.'}
(OUT/'ROBUST_SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
(root.parent/'ROBUST_SUMMARY.json').write_bytes((OUT/'ROBUST_SUMMARY.json').read_bytes())
plt.rcParams.update({'font.size':9,'axes.spines.top':False,'axes.spines.right':False})
fig,axes=plt.subplots(2,3,figsize=(8,5.2),sharex=True,sharey=True)
for ax,row in zip(axes.flat,rows,strict=True):
    for strategy,color,label in [('bounded-envelope','#9d3d25','Bounded mean'),('robust-bounded-envelope','#176f8a','Robust bounded')]:
        c=index[row['seed'],strategy,'adaptive'];frames=c['rounds']
        ax.plot([x['round'] for x in frames],[100*x['worst_trigger_asr'] for x in frames],color=color,label=label,lw=1.7)
        if not c['complete']:ax.scatter([frames[-1]['round']],[100*frames[-1]['worst_trigger_asr']],marker='x',color=color,s=55,zorder=5)
    ax.axvline(10.5,color='gray',ls='--',lw=.8)
    ax.set_title(f"{row['cohort'].upper()} / {str(row['seed'])[-2:]}")
    ax.set_ylim(-2,104);ax.set_xlim(1,15);ax.grid(alpha=.2)
for ax in axes[-1]:ax.set_xlabel('Round')
for ax in axes[:,0]:ax.set_ylabel('Worst-trigger ASR (%)')
handles,labels=axes[0,0].get_legend_handles_labels();fig.legend(handles,labels,loc='upper center',ncol=2,frameon=False)
fig.tight_layout(rect=(0,0,1,.95))
fig.savefig(OUT/'robust-reserved-asr.pdf',bbox_inches='tight')
fig.savefig(OUT/'robust-reserved-asr.png',dpi=180,bbox_inches='tight')
print(json.dumps(summary),flush=True)
