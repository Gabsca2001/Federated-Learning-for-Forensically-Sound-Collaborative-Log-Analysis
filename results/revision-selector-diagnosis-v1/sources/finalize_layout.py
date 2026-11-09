"""Final visual QA: reserve a dedicated colorbar column; numerical evidence untouched."""
from pathlib import Path
import sys,json,shutil,hashlib
import numpy as np
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;sys.path.insert(0,str(R/'scripts'))
import revision_selector_diagnosis as study
from revision_study_data import read
from revision_dba_experiment import authenticate,save
D=study.D;M=O/'published'

def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()

old_index_sha=sha(D/'file-checksums.json');pins=read(D/'file-checksums.json')
assert all(sha(D/n)==v for n,v in pins.items())
evidence_sha=sha(D/'evidence/manifest.json')
authenticate(D/'evidence',read(D/'closure.json')['manifest_sha256'])
review=O/'layout-review';review.mkdir()
shutil.copy2(D/'false-client-channels.png',review/'initial-false-client-channels.png')
shutil.copy2(D/'file-checksums.json',review/'initial-file-checksums.json')
old_plot_sha=sha(D/'false-client-channels.png')
summary=read(D/'summary.json');records=[];data={}
for task in read(D/'protocol-before-diagnosis.json')['cases']:
    value=read(D/'evidence/cases'/f"{task['alias']}.json");data[task['alias']]=value
    for client in value['false_clients']:records.append((task['alias'],client))
matrices=[]
for channel in ('z_norm','z_validation'):
    matrix=[]
    for alias,client in records:
        rows=data[alias]['profiles']['actual']['rows']
        matrix.append([next(r[channel] for r in rows if r['client']==client and r['round']==n) for n in range(1,11)])
    matrices.append(np.asarray(matrix))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
fig=plt.figure(figsize=(12,6));grid=fig.add_gridspec(1,3,width_ratios=[1,1,.045],wspace=.18)
axes=[fig.add_subplot(grid[0,0]),fig.add_subplot(grid[0,1])];colorbar_ax=fig.add_subplot(grid[0,2])
upper=max(float(m.max()) for m in matrices)
for ax,m,title in zip(axes,matrices,('Magnitude channel','Macro-F1 validation channel'),strict=True):
    im=ax.imshow(m,aspect='auto',vmin=0,vmax=upper,cmap='viridis')
    ax.set_xticks(range(10),range(1,11));ax.set_title(title);ax.set_xlabel('Observed round')
axes[0].set_yticks(range(len(records)),[f'{a} / {c}' for a,c in records],fontsize=8)
axes[1].set_yticks(range(len(records)),[])
fig.colorbar(im,cax=colorbar_ax,label=f"Channel score (threshold {summary['thresholds']['z_threshold']:.3f})")
fig.suptitle('All falsely flagged benign client histories: channel decomposition')
fig.subplots_adjust(left=.21,right=.94,top=.86,bottom=.1)
fig.savefig(D/'false-client-channels.png',dpi=150);plt.close(fig)
assert sha(D/'evidence/manifest.json')==evidence_sha
authenticate(D/'evidence',read(D/'closure.json')['manifest_sha256'])
record=dict(change='Layout only: separate colorbar axis; all ten columns visible.',initial_plot_sha256=old_plot_sha,
    final_plot_sha256=sha(D/'false-client-channels.png'),initial_publication_index_sha256=old_index_sha,
    renderer_sha256=sha(Path(__file__)),numerical_evidence_changed=False,evidence_manifest_sha256=evidence_sha)
save(D/'layout-finalization.json',record);shutil.copy2(__file__,D/'sources/finalize_layout.py')
for name in ('false-client-channels.png','layout-finalization.json','sources/finalize_layout.py'):
    shutil.copy2(D/name,M/name)
new_pins={str(f.relative_to(D)):sha(f) for f in D.rglob('*') if f.is_file() and f!=D/'file-checksums.json'}
(D/'file-checksums.json').write_text(json.dumps(new_pins,sort_keys=True,separators=(',',':'))+'\n')
shutil.copy2(D/'file-checksums.json',M/'file-checksums.json')
assert all(sha(D/n)==h and sha(M/n)==h for n,h in new_pins.items())
study.check(read(D/'protocol-before-diagnosis.json'))
(O/'final-storage-check.json').write_text(json.dumps(dict(status='verified_and_mirrored_after_visual_QA',**study.guard()))+'\n')
print(json.dumps(record,indent=2))
