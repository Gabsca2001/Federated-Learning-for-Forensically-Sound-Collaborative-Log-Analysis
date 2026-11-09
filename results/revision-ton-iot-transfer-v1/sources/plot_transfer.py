"""Plot retained confusion matrices and descriptive transfer diagnostics."""
from pathlib import Path
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
O=Path(__file__).resolve().parent
result=json.loads((O/'transfer-results.json').read_text())
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False})
panels=[('Data24 source test',result['Data24_test_control']),
        ('ToN-IoT: official occurrences',result['results']['occurrence']['metrics']),
        ('ToN-IoT: exact-field sensitivity',result['results']['exact-projection']['metrics'])]
fig,axes=plt.subplots(1,3,figsize=(12.6,4.2),constrained_layout=True)
for ax,(title,metrics) in zip(axes,panels,strict=True):
    counts=np.asarray(metrics['confusion_matrix']['values'])
    normalized=counts/counts.sum(axis=1,keepdims=True)
    ax.imshow(normalized,vmin=0,vmax=1,cmap='Blues')
    for i in range(2):
        for j in range(2):
            ax.text(j,i,f'{counts[i,j]:,}\n{normalized[i,j]:.1%}',ha='center',va='center',color='white' if normalized[i,j]>.55 else '#17213b',fontsize=12)
    ax.set_xticks([0,1],['Benign','Attack']);ax.set_yticks([0,1],['Benign','Attack'])
    ax.set_xlabel('Predicted label');ax.set_ylabel('True label')
    ax.set_title(title+'\nBalanced accuracy '+format(metrics['balanced_accuracy'],'.1%'),fontsize=11,pad=12)
fig.suptitle('One frozen Data24 checkpoint and unchanged binary decisions',fontsize=14)
fig.savefig(O/'transfer-confusions.png',dpi=180)
plt.close(fig)
fig,axes=plt.subplots(1,2,figsize=(12.8,5.2),constrained_layout=True)
left=axes[0]
features=result['results']['occurrence']['feature_shift']['features']
features=sorted(features,key=lambda x:x['absolute_z_gt5_fraction'],reverse=True)[:8]
other={f['feature']:f for f in result['results']['exact-projection']['feature_shift']['features']}
position=np.arange(len(features))
left.barh(position-.18,[f['absolute_z_gt5_fraction']*100 for f in features],height=.34,color='#146b8c',label='Official occurrences')
left.barh(position+.18,[other[f['feature']]['absolute_z_gt5_fraction']*100 for f in features],height=.34,color='#dc8a1c',label='Exact-field sensitivity')
left.set_yticks(position,[f['feature'].replace('_',' ') for f in features]);left.invert_yaxis();left.set_xlim(0,100)
left.set_xlabel('Windows beyond five Data24 training standard deviations (%)')
left.set_title('Feature shift under the frozen Data24 scaler');left.legend(loc='lower right',fontsize=9)
daily=result['results']['occurrence']['per_day'];days=list(daily);x=np.arange(len(days))
for field,label,color,marker in [('attack_recall','Attack recall','#a72d49','o'),('benign_specificity','Benign specificity','#146b8c','s')]:
    values=[np.nan if daily[d][field] is None else daily[d][field] for d in days]
    axes[1].plot(x,values,color=color,marker=marker,label=label)
axes[1].set_ylim(-.03,1.03);axes[1].set_xticks(x,[d[5:] for d in days],rotation=45)
axes[1].set_xlabel('Observed capture date in 2019 (UTC)');axes[1].set_ylabel('Fraction of relevant true class')
axes[1].set_title('Daily primary-view detection and normal-class performance')
axes[1].legend(fontsize=9);axes[1].grid(axis='y',alpha=.2)
fig.savefig(O/'transfer-diagnostics.png',dpi=180)
print('Saved two scientific figures as high-resolution PNGs.')
