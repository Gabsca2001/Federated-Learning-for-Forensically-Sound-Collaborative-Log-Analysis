"""Explicitly check source-role isolation and absence of MITM before test."""
from collections import Counter
from pathlib import Path
import json
import numpy as np
import run_host_novelty as run

O=Path(__file__).resolve().parent
data,chosen,spec,x=run.prepare()
assert not np.any(data['train']['y'][chosen])
for role in ('train','validation'):
    assert not np.any(data[role]['family']=='mitm')
    assert x[role].shape[1]==25
roles={role:set(map(str,values['ids'])) for role,values in data.items()}
assert not roles['train']&roles['validation'] and not roles['train']&roles['test'] and not roles['validation']&roles['test']
result=dict(status='verified',role_counts={role:dict(native_units=len(values['y']),benign=int((values['y']==0).sum()),attack_families=dict(Counter(values['family'][values['y']==1]))) for role,values in data.items()},
    benign_reference_units=len(chosen),attacked_reference_units=int(data['train']['y'][chosen].sum()),
    native_unit_id_roles_disjoint=True,mitm_training_and_validation_units=0,numeric_predictor_columns=25,
    caveat='The test remains previously examined and source addresses overlap across time; role isolation is not fresh blindness or host independence.')
with (O/'fit-boundary-audit.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps(result,indent=2))
