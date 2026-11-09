"""Separate coincident minute alerts from detection of an attacked host unit."""
from pathlib import Path
from collections import Counter,defaultdict
import json
import numpy as np

O=Path(__file__).resolve().parent;ROOT=O.parent
load=lambda p:json.loads(p.read_text())
r=load(O/'study/results.json');entries=[]
for e in r['results']:
    if e['profile']!='host':continue
    a=np.load(O/'study'/(e['id']+'-test.npz'),allow_pickle=False)
    common=np.load(O/'study'/(e['id']+'-common-test.npz'),allow_pickle=False)
    pred=a['score'].astype(np.float64)>e['threshold'];bucket=a['bucket'];actual=a['actual'].astype(bool)
    families={int(b):str(f) for b,f in zip(common['bucket'],common['family'])};groups={}
    for name in sorted(set(families.values())-{'benign'}):
        selected=[b for b,f in families.items() if f==name]
        alerted=0;supported=0;coincident=0
        for b in selected:
            ix=bucket==b;any_alert=bool(pred[ix].any());attacked_host_alert=bool((pred[ix]&actual[ix]).any())
            alerted+=any_alert;supported+=attacked_host_alert;coincident+=any_alert and not attacked_host_alert
        groups[name]=dict(attack_minutes=len(selected),any_host_alert_minutes=alerted,attacked_host_alert_minutes=supported,
            benign_host_only_alert_minutes=coincident,any_host_alert_recall=alerted/len(selected),attacked_host_supported_recall=supported/len(selected))
    entries.append(dict(id=e['id'],scope=e['scope'],family_minutes=groups))

with np.load(O/'windows/host-windows.npz',allow_pickle=False) as packed:
    h={name:packed[name] for name in packed.files}
roles=load(ROOT/'ton-iot-retraining-20261109/study/split-and-partition.json')['splits']
train=np.flatnonzero(np.isin(h['bucket'],roles['train']['buckets']));test=np.flatnonzero(np.isin(h['bucket'],roles['test']['buckets']))
training=defaultdict(Counter)
for ix in train:training[h['features'][ix].astype('<f8').tobytes()][int(h['actual'][ix])]+=1
test_vectors=defaultdict(Counter)
for ix in test:test_vectors[h['features'][ix].astype('<f8').tobytes()][int(h['actual'][ix])]+=1
collisions={}
for family in sorted(set(h['family'][test])):
    ix=[i for i in test if h['family'][i]==family]
    collisions[family]=dict(windows=len(ix),exact_feature_vector_in_training_benign=sum(training[h['features'][i].astype('<f8').tobytes()][0]>0 for i in ix),
        exact_feature_vector_in_training_attack=sum(training[h['features'][i].astype('<f8').tobytes()][1]>0 for i in ix))
conflicting_groups=[c for c in test_vectors.values() if c[0] and c[1]]
result=dict(status='diagnostic_complete',localization=entries,exact_feature_training_overlap=collisions,
    test_identical_feature_groups_with_opposite_labels=len(conflicting_groups),minimum_test_errors_from_exact_opposite_label_groups=sum(min(c[0],c[1]) for c in conflicting_groups),
    interpretation='An any-host alert in an attacked minute is not evidence that the attacked host unit was detected. Supported recall requires a positive host unit that also has an attack ground-truth label. This is still host/minute classification, not causal detection of individual attack records.',
    collision_scope='Exact existing 25-field numeric vectors, with no rounding beyond the frozen window representation. These are descriptive collisions, not proof of a universal impossibility beyond this representation.')
with (O/'localization-and-collision-diagnosis.json').open('x') as f:json.dump(result,f,indent=2,allow_nan=False);f.write('\n')
print(json.dumps(result,indent=2))
