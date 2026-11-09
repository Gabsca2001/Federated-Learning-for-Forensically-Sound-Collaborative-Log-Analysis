"""Scientific plots for the prespecified target-domain comparison."""
from pathlib import Path
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
O=Path(__file__).resolve().parent;W=O/'study'
d=json.loads((W/'target-test-results.json').read_text());r=[r for r in d['results'] if r['status']=='trained']
modes=['source-standard','target-standard','target-log1p'];names=['Retrain, Data24 scaler','Retrain, ToN-IoT scaler','Retrain, log1p + ToN-IoT scaler']
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False})
fig,axes=plt.subplots(1,2,figsize=(12.8,5),constrained_layout=True)
for ax,metric,title in [(axes[0],'balanced_accuracy','Balanced accuracy'),(axes[1],'false_positive_rate','False-positive rate')]:
    positions=np.arange(3)
    for view,offset,color,label in [('occurrence',-.18,'#146b8c','Official occurrences'),('exact-projection',.18,'#dc8a1c','Exact-field sensitivity')]:
        values=[np.asarray([run['test'][metric] for run in r if run['mode']==mode and run['view']==view])*100 for mode in modes]
        means=np.asarray([v.mean() for v in values]);lower=np.asarray([v.mean()-v.min() for v in values]);upper=np.asarray([v.max()-v.mean() for v in values])
        ax.bar(positions+offset,means,width=.34,color=color,label=label,yerr=np.vstack([lower,upper]),capsize=4)
    baseline=d['frozen_source_baselines'][0]['test'][metric]*100
    ax.axhline(baseline,color='#a72d49',linestyle='--',label='Unchanged source model')
    ax.set_xticks(positions,names,rotation=17,ha='right',fontsize=9);ax.set_ylim(0,105);ax.set_ylabel(title+' (%)');ax.set_title(title+' on the same temporal test')
    ax.grid(axis='y',alpha=.2);ax.legend(fontsize=8,loc='upper left' if metric=='balanced_accuracy' else 'lower left')
fig.suptitle('Three paired seeds, fixed validation selection and 718 held-out target windows',fontsize=13)
fig.savefig(O/'target-retraining-comparison.png',dpi=180);plt.close(fig)
colors=['#6f55a8','#146b8c','#dc8a1c']
fig,axes=plt.subplots(1,2,figsize=(12.8,4.8),constrained_layout=True)
for mode,name,color in zip(modes,names,colors,strict=True):
    histories=[]
    for run in r:
        if run['mode']==mode and run['view']=='occurrence':
            history=json.loads((W/'runs'/run['run_id']/'history.json').read_text())
            values=[v['validation_macro_f1'] for v in history];histories.append(values)
            axes[0].plot(np.arange(1,31),values,color=color,alpha=.23)
            axes[0].scatter(run['selected_round'],run['selected_validation_macro_f1'],color=color,s=24,zorder=4)
    axes[0].plot(np.arange(1,31),np.mean(histories,axis=0),color=color,label=name)
    for view,marker in [('occurrence','o'),('exact-projection','^')]:
        values=[run for run in r if run['mode']==mode and run['view']==view]
        axes[1].scatter([v['test']['false_positive_rate']*100 for v in values],[v['test']['attack_recall']*100 for v in values],
                        color=color,marker=marker,s=55,alpha=.8,label=name if view=='occurrence' else None)
axes[0].set_xlabel('FedAvg round');axes[0].set_ylabel('Validation binary macro-F1');axes[0].set_title('Primary-view validation curves and selected rounds')
axes[0].legend(fontsize=8);axes[0].grid(alpha=.2)
axes[1].scatter([100],[100],marker='x',s=80,color='#a72d49',label='Unchanged source model')
axes[1].set_xlim(0,105);axes[1].set_ylim(75,102);axes[1].set_xlabel('False-positive rate (%)');axes[1].set_ylabel('Attack recall (%)')
axes[1].set_title('Test trade-off; circles = primary, triangles = sensitivity');axes[1].legend(fontsize=8,loc='lower right');axes[1].grid(alpha=.2)
fig.savefig(O/'target-retraining-selection.png',dpi=180);plt.close(fig)
print('Saved two target-retraining figures.')
