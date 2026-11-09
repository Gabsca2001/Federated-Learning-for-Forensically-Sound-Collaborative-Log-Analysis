"""Layout-only review of the completed V5 recovery figure; retain the first render."""
import os
for name in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ[name]='1'
from pathlib import Path
import sys,hashlib,shutil
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
sys.path.insert(0,str(R/'scripts'))
import revision_episode_attribution as study
from revision_study_data import read
from revision_dba_experiment import save
O=Path(__file__).parent;D=study.D
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
p=read(D/'protocol-before-training.json');study.check(p)
summary=read(D/'summary.json');assert summary['status']=='verified_v5_separated_episode_assessment'
assert sha(O/'analyze_episode.py')==read(D/'report-before-accounting.json')['reporter_sha256']
summary_hash=sha(D/'summary.json');figure=D/'episode-origin-recovery.png'
initial_hash=sha(figure);review=D/'layout-review';review.mkdir()
original=review/'initial-episode-origin-recovery.png';shutil.copy2(figure,original);original.chmod(0o444)
rows=[x for x in summary['origin_comparisons'] if x['method']=='v5' and x['family']=='unrestricted']
fig,ax=plt.subplots(figsize=(10,5));pos=np.arange(len(rows));width=.25
for offset,key,label,color in [(-width,'source_final_worst_asr','Original source','#b45309'),
        (0,'joint_final_worst_asr','Selected-group replay','#0f766e'),
        (width,'mass_control_final_worst_asr','Benign-control replay','#2563eb')]:
    values=[100*x[key] for x in rows];bars=ax.bar(pos+offset,values,width,label=label,color=color)
    ax.bar_label(bars,fmt='%.1f',padding=3,fontsize=8)
    for x,y in zip(pos+offset,values,strict=True):
        if y==0:ax.scatter(x,0,marker='s',s=15,color=color,clip_on=False,zorder=4)
ax.set_xticks(pos,[x['alias'] for x in rows]);ax.set_ylabel('Final worst measured ASR (%)');ax.set_ylim(0,108)
ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True)
fig.suptitle('Full-origin replay: selected groups and benign controls',fontsize=12)
handles,labels=ax.get_legend_handles_labels();fig.legend(handles,labels,loc='upper center',bbox_to_anchor=(.5,.93),ncol=3,fontsize=9)
fig.tight_layout(rect=(0,0,1,.84));fig.savefig(figure,dpi=150);plt.close(fig)
assert sha(original)==initial_hash and sha(D/'summary.json')==summary_hash
study.check(p)
save(D/'figure-layout-review.json',dict(status='layout_only_numbers_unchanged',
    reason='Move the legend outside the data axes and label zero-height replay bars.',
    source_summary_sha256=summary_hash,layout_script_sha256=sha(Path(__file__)),
    initial_figure_sha256=initial_hash,reviewed_figure_sha256=sha(figure)))
print('Recovery figure refined; original render and numerical evidence preserved.')
