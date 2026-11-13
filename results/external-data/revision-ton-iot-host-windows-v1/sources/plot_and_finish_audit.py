"""Independently verify localization counters and render separately scoped plots."""
from pathlib import Path
import json
import numpy as np
from host_windows import pool_host_scores
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

O=Path(__file__).resolve().parent;S=O/'study'
load=lambda p:json.loads(p.read_text())
results=load(S/'results.json');diag=load(O/'localization-and-collision-diagnosis.json')
checked=0
for entry in diag['localization']:
    model=next(e for e in results['results'] if e['id']==entry['id'])
    with np.load(S/(entry['id']+'-test.npz'),allow_pickle=False) as a:
        bucket=a['bucket'];score=a['score'];actual=a['actual'];pred=(score>model['threshold']).astype(np.int64)
        common_b,any_alert,common_y=pool_host_scores(bucket,pred,actual)
        _,supported,_=pool_host_scores(bucket,pred*actual,actual)
    with np.load(S/(entry['id']+'-common-test.npz'),allow_pickle=False) as a:
        np.testing.assert_array_equal(common_b,a['bucket']);np.testing.assert_array_equal(any_alert.astype(bool),a['score']>model['threshold'])
        families=a['family']
    assert np.all(supported<=any_alert)
    for name,counts in entry['family_minutes'].items():
        ix=families==name
        assert int(any_alert[ix].sum())==counts['any_host_alert_minutes']
        assert int(supported[ix].sum())==counts['attacked_host_alert_minutes']
        assert int(((any_alert==1)&(supported==0)&ix).sum())==counts['benign_host_only_alert_minutes']
        assert int(ix.sum())==counts['attack_minutes'];checked+=1
with (O/'localization-verification.json').open('x') as f:
    json.dump(dict(status='verified',family_metric_sets=checked,method='Independent vectorized max pooling of positive predictions and positive predictions on attacked units; compared with scalar per-minute diagnosis.'),f,indent=2);f.write('\n')

plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False})
fig,axes=plt.subplots(1,2,figsize=(11,4.7),layout='constrained')
seeds=[341593,342593,343593]
for offset,profile in enumerate(('global','host')):
    entries=[e for e in results['results'] if e['scope']=='federated' and e['profile']==profile]
    for i,entry in enumerate(entries):
        axes[0].bar(i+(offset-.5)*.35,entry['test_common']['macro_f1'],width=.34,color=('#64748b' if offset==0 else '#0f766e'),label=(profile if i==0 else None))
axes[0].set(xticks=np.arange(3),xticklabels=[str(s) for s in seeds],ylim=(0,1),ylabel='Macro-F1',title='Same 718 global minutes: no material F1 gain');axes[0].legend()
native=results['summary']['host']['test_native'];names=['Macro-F1','Benign F1','Attack F1','Attack recall','Benign FPR'];keys=['macro_f1','benign_f1','attack_f1','attack_recall','false_positive_rate']
axes[1].bar(names,[native[k] for k in keys],color='#2563eb');axes[1].tick_params(axis='x',rotation=30)
axes[1].set(ylim=(0,1.06),title='Host/minute units: different population (4,093)')
fig.suptitle('Chronological source-IP windows | common-minute primary and native-host secondary metrics',fontsize=11)
fig.savefig(O/'host-versus-global.png',dpi=180);plt.close(fig)

fig,axes=plt.subplots(1,2,figsize=(11,4.6),layout='constrained')
fed=[e for e in diag['localization'] if e['scope']=='federated']
for i,e in enumerate(fed):
    counts=e['family_minutes']['mitm'];axes[0].bar(i,counts['attacked_host_alert_minutes'],color='#0f766e',label='Attacked host alerted' if i==0 else None)
    axes[0].bar(i,counts['benign_host_only_alert_minutes'],bottom=counts['attacked_host_alert_minutes'],color='#d97706',label='Only benign hosts alerted' if i==0 else None)
axes[0].set(xticks=np.arange(3),xticklabels=[str(s) for s in seeds],ylim=(0,102),ylabel='MITM minutes out of 102',title='A minute alert can fail to localize the attack');axes[0].legend(fontsize=8)
for i,e in enumerate(fed):
    axes[1].bar(i,e['family_minutes']['backdoor']['attacked_host_supported_recall'],width=.55,color='#7c3aed')
axes[1].set(xticks=np.arange(3),xticklabels=[str(s) for s in seeds],ylim=(0,1.07),ylabel='Attacked-host-supported minute recall',title='Backdoor: 586/586 minutes, validation-supported')
fig.savefig(O/'attack-localization.png',dpi=180);plt.close(fig)
print(json.dumps(dict(status='plots_and_localization_verified',metric_sets=checked)))
