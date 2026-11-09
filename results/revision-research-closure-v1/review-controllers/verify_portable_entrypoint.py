"""Targeted real-input smoke plus forced-invalid-fallback boundary check."""
from pathlib import Path
import builtins
import copy
import json
import numpy as np

import revision_native_gradient_study as study
from fl_forensics.canonical import sha256_file

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-research-closure-v1'
source=lab/'native-gradients-evaluation';original=study.read(source/'results.json')
task=next(c['task'] for c in original['cases'] if c['task']['name']=='iid-2026110421-gradient_fedavg-attack')
study.range=lambda *args:builtins.range(1,2) if args==(1,16) else builtins.range(*args)
study.ALPHAS=[0.,.125]
results=[]
for mode in ('custom-destination','forced-invalid-zero-fallback'):
    root=lab/'portable-entrypoint-smoke'/mode;assert not root.exists()
    ref=root/'iid-gradient_fedavg-clean/rounds/round-001/round.json'
    study.save(ref,study.read(source/'iid-gradient_fedavg-clean/rounds/round-001/round.json'))
    study.save(root/'smoke-protocol.json',{'scope':'One-round orchestration smoke on actual initial inputs; two scales. The second case deliberately forces invalid zero and below-guard nonzero outputs. Not a new attack efficacy campaign.',
      'harness_sha256':sha256_file(Path(__file__)),'portable_controller_sha256':sha256_file(Path(study.__file__)),'task':task})
    counts=dict(full_gradient_evaluations=0,gradient_repeats=0,queries=0,rounds=0)
    if mode.startswith('forced'):
        real_operation=study.operation;real_outcomes=study.outcomes;calls=0
        def operation(*args,**kwargs):
            global calls
            calls+=1
            if calls==1:raise ValueError('Deliberately invalid zero-factor smoke candidate')
            return real_operation(*args,**kwargs)
        def outcomes(*args,**kwargs):
            metric=copy.deepcopy(real_outcomes(*args,**kwargs));metric['clean']['macro_f1_all_model_classes']=0.
            return metric
        study.operation=operation;study.outcomes=outcomes
    case=study.run_case(task,root,counts)
    prefix=root/task['name']/'rounds/round-001'
    assert (prefix/'forged-gradient-training-records.json').exists()
    with np.load(prefix/'gradient-endpoints.npz',allow_pickle=False) as a,np.load(source/task['name']/'rounds/round-001/gradient-endpoints.npz',allow_pickle=False) as b:
        assert a.files==b.files and all(np.array_equal(a[k],b[k]) for k in a.files)
    if mode.startswith('forced'):
        assert not case['rounds'] and case['terminal_failure'] is not None
        assert 'fallback' in case['terminal_failure']['reason']
    else:
        assert len(case['rounds'])==1 and case['rounds'][0]['adversarial_endpoint_training_calls']==15
    results.append({'mode':mode,'counts':counts,'terminal_failure':case['terminal_failure'],'gradient_endpoints_exactly_match_original':True})
record={'status':'verified','cases':results,'scope':'Portable controller boundary checks, separate from preserved research campaigns. Harness explicitly limits horizon, scales and the second case\'s synthetic failure injection.'}
for p in (lab/'portable-entrypoint-verification.json',out/'portable-entrypoint-verification.json'):p.write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record),flush=True)
