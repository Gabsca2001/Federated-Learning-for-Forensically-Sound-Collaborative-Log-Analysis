"""Export scientific figures from the frozen online evaluation."""
from pathlib import Path
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
import numpy as np

out=Path(__file__).parent;data=json.loads((out/'online-evaluation.json').read_text());rows=json.loads((out/'online-trajectories.json').read_text())['rows']
fig,axes=plt.subplots(2,3,figsize=(11,6.7),sharex=True,sharey=True,layout='constrained')
for i,cohort in enumerate(('iid','non-iid')):
    seeds=sorted({c['task']['seed'] for c in data['cases'] if c['task']['cohort']==cohort})
    for j,seed in enumerate(seeds):
        ax=axes[i,j]
        tasks=[c for c in data['cases'] if c['task']['cohort']==cohort and c['task']['seed']==seed and c['task']['mode']=='distributed']
        schedule=tasks[0]['task']['attack_rounds'];ax.axvspan(min(schedule)-.4,max(schedule)+.4,color='#e2e8f0',alpha=.55)
        for branch,color,label in [('shadow-FedAvg','#b91c1c','FedAvg, no intervention'),('active-sequential','#1d4ed8','Sequential current-round quarantine')]:
            values=sorted([r for r in rows if r['cohort']==cohort and r['seed']==seed and r['mode']=='distributed' and r['branch']==branch],key=lambda r:r['round'])
            ax.plot([r['round'] for r in values],[100*r['outcomes']['complete_trigger']['asr'] for r in values],color=color,label=label,lw=1.6)
        ax.set(title=f'{cohort.upper()} | seed {seed}',xticks=[1,5,10,15],ylim=(-2,102))
        ax.grid(alpha=.12);ax.spines[['top','right']].set_visible(False)
        if i==1:ax.set_xlabel('Round')
        if j==0:ax.set_ylabel('Complete-trigger ASR (%)')
handles,labels=axes[0,0].get_legend_handles_labels();fig.legend(handles,labels,loc='outside lower center',ncol=2,frameon=False,fontsize=9)
fig.suptitle('Frozen online study: intervention acts on current updates only\nShading marks the declared attack period; old checkpoint effects are retained',fontsize=11)
fig.savefig(out/'online-asr-trajectories.png',dpi=180);fig.savefig(out/'online-asr-trajectories.pdf')
plt.close(fig)

fig,axes=plt.subplots(2,3,figsize=(11.2,8),layout='constrained')
cmap=ListedColormap(['#f1f5f9','#fbbf24','#2563eb','#a855f7'])
for i,cohort in enumerate(('iid','non-iid')):
    seeds=sorted({c['task']['seed'] for c in data['cases'] if c['task']['cohort']==cohort})
    for j,seed in enumerate(seeds):
        case=next(c for c in data['cases'] if c['task']['cohort']==cohort and c['task']['seed']==seed and c['task']['mode']=='distributed' and c['task']['branch']=='active-sequential')
        clients=sorted(case['client_timeline']);matrix=np.zeros((15,15))
        selected=[r for r in rows if r['stream']==case['task']['stream']]
        for r in selected:
            for k,c in enumerate(clients):
                matrix[k,r['round']-1]=3 if not r['supported'] else (2 if c in r['quarantined'] else 1 if c in r['review_required'] else 0)
        ax=axes[i,j];ax.imshow(matrix,cmap=cmap,vmin=0,vmax=3,aspect='auto',interpolation='nearest',origin='upper')
        ax.set(title=f'{cohort.upper()} | seed {seed}',xticks=[0,4,9,14],xticklabels=[1,5,10,15],yticks=range(15),yticklabels=[c.replace('client','')+('*' if c in case['task']['attackers'] else '') for c in clients])
        ax.tick_params(axis='y',labelsize=7);ax.set_xlabel('Round');ax.set_ylabel('Client (* = scheduled attacker)')
from matplotlib.patches import Patch
fig.legend([Patch(facecolor=c) for c in cmap.colors],['No statistical alert','Review required','Current-round quarantine','Unsupported: review'],loc='outside lower center',ncol=4,frameon=False,fontsize=8)
fig.suptitle('Active branch decisions on all 15 clients\nScheduled identity is evaluation-only; it is never passed to the worker',fontsize=11)
fig.savefig(out/'online-decision-timelines.png',dpi=180);fig.savefig(out/'online-decision-timelines.pdf')
print('ONLINE FIGURES SAVED')
