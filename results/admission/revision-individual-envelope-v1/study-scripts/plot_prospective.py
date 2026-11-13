from pathlib import Path
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

out=Path(__file__).parent;data=json.loads((out/'prospective-evaluation.json').read_bytes())
trajectories=json.loads((out/'prospective-trajectories.json').read_bytes())['rows']
fig,axes=plt.subplots(2,3,figsize=(11.5,7),sharex=True,sharey=True,layout='constrained')
for i,cohort in enumerate(('iid','non-iid')):
    seeds=sorted({c['task']['seed'] for c in data['cases'] if c['task']['cohort']==cohort})
    for j,seed in enumerate(seeds):
        ax=axes[i,j];task=next(c['task'] for c in data['cases'] if c['task']['cohort']==cohort and c['task']['seed']==seed)
        bursts=[]
        for t in task['attack_rounds']:
            if not bursts or t!=bursts[-1][-1]+1:bursts.append([t])
            else:bursts[-1].append(t)
        for b in bursts:ax.axvspan(b[0]-.4,b[-1]+.4,color='#e2e8f0',alpha=.55)
        for branch,color,label,style in [('shadow-FedAvg','#b91c1c','FedAvg, no intervention','-'),
            ('active-prior','#d97706','Previous confirmed-current policy','--'),
            ('active-envelope','#1d4ed8','Individual envelope + evidence retreat','-')]:
            rows=sorted([r for r in trajectories if r['cohort']==cohort and r['seed']==seed and r['mode']=='distributed' and r['branch']==branch],key=lambda r:r['round'])
            ax.plot([r['round'] for r in rows],[100*r['outcomes']['complete_trigger']['asr'] for r in rows],color=color,lw=1.7,ls=style,label=label)
        ax.set(title=f'{cohort.upper()} | seed {seed}',xticks=[1,5,10,15],ylim=(-2,102))
        ax.grid(alpha=.12);ax.spines[['top','right']].set_visible(False)
        if i==1:ax.set_xlabel('Round')
        if j==0:ax.set_ylabel('Complete-trigger ASR (%)')
h,l=axes[0,0].get_legend_handles_labels();fig.legend(h,l,loc='outside lower center',ncol=3,frameon=False,fontsize=8)
fig.suptitle('Frozen prospective study: three independently trained trajectories\nShading marks attack periods; scores and thresholds stay fixed',fontsize=11)
fig.savefig(out/'persistent-asr-trajectories.png',dpi=180);fig.savefig(out/'persistent-asr-trajectories.pdf');plt.close(fig)

fig,axes=plt.subplots(1,2,figsize=(10.5,4.7),sharey=True,layout='constrained')
for ax,cohort in zip(axes,('iid','non-iid'),strict=True):
    rows=[c for c in data['cases'] if c['task']['cohort']==cohort and c['task']['branch']=='shadow-FedAvg']
    tp=[sum(c['metrics'].get(f'{name}_poisoned_proposals',0) for c in rows) for name in ('prior','envelope')]
    fp=[sum(c['metrics'].get(f'{name}_never_attacker_proposals',0)+c['metrics'].get(f'{name}_currently_clean_scheduled_proposals',0) for c in rows) for name in ('prior','envelope')]
    denominator=sum(c['metrics'].get('poisoned_opportunities',0) for c in rows)
    x=np.arange(2);ax.bar(x,tp,width=.6,color=['#d97706','#1d4ed8']);ax.bar(x,fp,bottom=tp,width=.6,color='#dc2626')
    ax.axhline(denominator,color='#475569',ls='--',lw=1)
    for k,(a,b) in enumerate(zip(tp,fp,strict=True)):
        ax.text(k,a/2,str(a),ha='center',va='center',color='white',weight='bold')
        if b:ax.text(k,a+b/2,f'+{b} clean-source',ha='center',va='center',fontsize=8,color='white')
    ax.set(title=cohort.upper(),xticks=x,xticklabels=['Previous policy','Individual envelope'],ylim=(0,max(denominator+15,max(np.asarray(tp)+fp)+15)))
    ax.grid(axis='y',alpha=.12);ax.spines[['top','right']].set_visible(False)
axes[0].set_ylabel('Client-round quarantine proposals on identical shadow prefixes')
fig.suptitle('Poisoned updates caught and clean-source false proposals\nDashed line: all actually poisoned update opportunities',fontsize=11)
fig.savefig(out/'persistent-detection-comparison.png',dpi=180);fig.savefig(out/'persistent-detection-comparison.pdf')
print('PROSPECTIVE FIGURES SAVED')
