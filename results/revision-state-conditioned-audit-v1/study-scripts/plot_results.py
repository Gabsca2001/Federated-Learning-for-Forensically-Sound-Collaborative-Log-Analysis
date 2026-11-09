import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

out=Path(__file__).parent;data=json.loads((out/'heldout-evaluation.json').read_text())
methods=['conditioned','state-disabled','fusion'];labels=['State\nconditioned','State\ndisabled','Dual view\n(frozen primary)']
fig,axes=plt.subplots(1,2,figsize=(10.5,4.9),sharey=True,layout='constrained')
for ax,cohort,title in zip(axes,['iid','non-iid'],['IID partition','Non-IID partition (Dirichlet alpha 0.3)'],strict=True):
    rows=[next(r for r in data['aggregate'] if r['cohort']==cohort and r['method']==m and r['mode']=='distributed') for m in methods]
    tp=np.array([r['tp'] for r in rows]);fp=np.array([r['fp'] for r in rows]);x=np.arange(3)
    ax.bar(x,tp,color='#2563eb',width=.58,label='Poisoning clients flagged')
    ax.bar(x,fp,bottom=tp,color='#ea580c',width=.58,label='Benign clients flagged')
    ax.axhline(9,color='#475569',ls='--',lw=1,label='9 actual poisoning clients')
    for i,(a,b) in enumerate(zip(tp,fp,strict=True)):
        ax.text(i,a/2,str(a),ha='center',va='center',color='white',fontweight='bold')
        if b:ax.text(i,a+b/2,f'+{b}',ha='center',va='center',color='white',fontweight='bold')
    ax.set(title=title,xticks=x,xticklabels=labels,ylim=(0,16),yticks=[0,3,6,9,12,15])
    ax.spines[['top','right']].set_visible(False);ax.grid(axis='y',alpha=.12)
axes[0].set_ylabel('Client classifications across 3 attacked campaigns')
handles,legend=axes[0].get_legend_handles_labels()
fig.legend(handles,legend,loc='outside lower center',ncol=3,frameon=False,fontsize=8)
fig.suptitle('Frozen evaluation: new training seeds and new attacker assignments',fontsize=12)
fig.savefig(out/'heldout-detection-results.png',dpi=185)
fig.savefig(out/'heldout-detection-results.pdf')
print('Figure saved')
