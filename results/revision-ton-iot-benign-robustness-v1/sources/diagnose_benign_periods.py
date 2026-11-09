"""Describe parent false alerts by capture day without changing model fitting."""
from pathlib import Path
from collections import Counter
import json
import numpy as np
O=Path(__file__).resolve().parent;P=O.parent/'ton-iot-f1-study-20261109/known-family'
load=lambda p:json.loads(p.read_text())
roles=load(P/'protocol-before-fitting.json')['roles']
lookup={r['window_start_epoch']//60:r for r in load(O.parent/'ton-iot-transfer-20261109/windows/occurrence-windows.json')['rows']}
support={role:dict(Counter(lookup[b]['capture_id'] for b,f in roles[role] if f=='benign')) for role in ('train','validation','test')}
entries=[]
for e in load(P/'closure-before-test.json')['entries']:
    if e['scope']!='federated' or e['family']!='binary-balanced' or e['view']!='occurrence':continue
    arrays=np.load(P/(e['id']+'-test.npz'),allow_pickle=False);scores=arrays['score'].astype(np.float64)
    by_day={}
    for date in sorted(support['test']):
        ix=[i for i,(b,f) in enumerate(roles['test']) if f=='benign' and lookup[b]['capture_id']==date]
        by_day[date]=dict(windows=len(ix),false_alerts=int((scores[ix]>e['threshold']).sum()),false_positive_rate=float((scores[ix]>e['threshold']).mean()))
    entries.append(dict(id=e['id'],benign_by_capture_day=by_day))
result=dict(benign_role_support_by_day=support,parent_results=entries,
    interpretation='Benign train/validation coverage is concentrated early in the capture schedule. Calendar separation is a confound even though dates are absent from predictor inputs. Per-day false alerts are descriptive, not a basis for changing test assignments.')
with (O/'parent-benign-period-diagnosis.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps(result,indent=2))
