"""Cutoff fitting has access to risk summaries, never original client rows."""
import json
import hashlib
from pathlib import Path
import sys
import numpy as np
from fl_forensics.sequential_decision import calibrate_sequential_policy


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):
    if path.exists():raise ValueError('immutable policy output exists')
    path.write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n')


for path in ('/models','/private-calibration','/private-episodes','/app/artifacts','/evidence'):
    assert not Path(path).exists(),path
index=json.loads(Path('/risk-inputs/index.json').read_bytes())
for cohort,spec in index['cohorts'].items():
    source=Path('/risk-inputs')/spec['path'];assert sha(source)==spec['sha256']
    data=json.loads(source.read_bytes())
    records=data['normalizer']+data['threshold']
    limits={v:max(max(r['state_distances'][v]) for r in records) for v in ('conditioned','state-disabled')}
    def sequence(record):
        return {'sequence_id':record['sequence_id'],'cohort_id':record['cohort_id'],'clients':record['clients'],
            'risk':record['risk'],'frame_ids':record['frame_ids'],'source_commitment':record['source_commitment'],
            'supported':[all(record['state_distances'][v][i]<=limits[v]*(1+1e-12)+1e-12 for v in limits) for i in range(len(record['frame_ids']))]}
    policy=calibrate_sequential_policy([sequence(r) for r in data['normalizer']],
        [sequence(r) for r in data['threshold']],horizon=15)
    policy.update(state_support_limits=limits,base_model_closure_sha256=index['model_closure_sha256'],
        source_risk_sha256=spec['sha256'],numpy_version=np.__version__)
    save(Path('/policy-out')/f'{cohort}.json',policy)
    print('Calibrated policy',cohort,flush=True)
save(Path('/policy-out/closure.json'),{'profile':'clean-sequential-policy-calibration-v1',
    'model_closure_sha256':index['model_closure_sha256'],'risk_input_index_sha256':sha(Path('/risk-inputs/index.json')),
    'source_policy_sha256':sha(Path('/code/fl_forensics/sequential_decision.py')),
    'files':{p.name:sha(p) for p in Path('/policy-out').glob('*.json')},
    'raw_client_rows_accessible':False,'attack_labels_accessible':False,'python_version':sys.version,'numpy_version':np.__version__})
