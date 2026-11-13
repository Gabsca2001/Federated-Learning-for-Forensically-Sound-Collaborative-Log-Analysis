"""Exhaustive size-matched benign controls after frozen candidate selection."""
import json
from itertools import combinations
from pathlib import Path
import numpy as np
from revision_dba_experiment import read_pinned,predict,model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,apply_evaluation_trigger
from fl_forensics.federated_model import arrays_from_export,dependencies
from fl_forensics.byzantine import model_delta,aggregate_deltas,apply_delta

repo=Path.cwd(); source=repo/'artifacts/revision-conditioned-groups-v2-fixed-serialization'
selected=repo/'artifacts/revision-selected-group-remediation-v2'
out=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/residual-poisoning-20261103')


def read(path): return json.loads(path.read_bytes())


cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
partition=read_pinned(Path(cfg['partition_workspace'])/'manifest.json',cfg['partition_manifest_sha256'])
counts={r['client_id']:r['train_row_count'] for r in partition['clients']}
rows=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
deps=dependencies(); deps[1].set_num_threads(1)
result=[]
for case in read(selected/'evaluation.json')['cases']:
    if case['status']!='evaluated': continue
    seed,mode=case['seed'],case['mode']; workspace=source/f'{mode}-s{seed}'
    plan=DistributedBackdoorPlan.model_validate(read(workspace/'protocol.json')['attack_plan'])
    # Evaluation-only membership; never used for candidate selection.
    truth=set(plan.client_components) if mode=='distributed' else set()
    clean_clients=sorted(set(counts)-truth); size=len(case['selected_group'])
    last=workspace/'rounds/round-010'; base=read(last/'base-model.json'); arrays=arrays_from_export(base,np=np)
    models={c:arrays_from_export(read(last/'updates'/f'{c}.json'),np=np) for c in sorted(counts)}
    trigger=apply_evaluation_trigger(rows=rows,plan=plan)
    eligible=[i for i,row in enumerate(rows) if row['label']!=plan.target_label]
    effects=[]
    for group in combinations(clean_clients,size):
        keep=sorted(set(counts)-set(group))
        model=model_with_arrays(base,apply_delta(arrays,aggregate_deltas([model_delta(arrays,models[c]) for c in keep],strategy='fedavg',f=0,weights=[counts[c] for c in keep])))
        predictions,_=predict(model,trigger,deps)
        asr=sum(predictions[i]==plan.target_label for i in eligible)/len(eligible)
        effects.append({'group':list(group),'ASR_reduction':case['original_ASR']-asr})
    target=case['direct_interventions'][0]['ASR_reduction']
    result.append({'seed':seed,'mode':mode,'selected_group':case['selected_group'],
        'benign_controls':effects,'selected_group_direct_ASR_reduction':target,
        'benign_effect_quantiles':np.quantile([e['ASR_reduction'] for e in effects],[0,.5,.95,1]).tolist(),
        'benign_groups_at_least_as_effective':sum(e['ASR_reduction']>=target for e in effects),
        'interpretation':'Conditional final-round effect on the same stored models. Exhaustive control rank is descriptive; pair controls share a campaign and are not independent statistical tests.'})
report={'profile':'exhaustive-benign-size-matched-controls-v2','cases':result,
    'source_selection_protocol_sha256':sha256_file(selected/'protocol-before-interventions.json'),
    'source_remediation_evaluation_sha256':sha256_file(selected/'evaluation.json')}
(out/'benign-pair-controls.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps([{k:r[k] for k in ('seed','selected_group','selected_group_direct_ASR_reduction','benign_effect_quantiles','benign_groups_at_least_as_effective')} for r in result]))
