"""Shared paths, signed source checks and observable-only group inputs."""
from pathlib import Path
import json
import numpy as np
from revision_dba_experiment import (save,authenticate,read_pinned,evaluate,outcomes,predict,model_with_arrays)
from fl_forensics.canonical import sha256_file,sha256_bytes,digest_object
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.federated_model import arrays_from_export,dependencies
from fl_forensics.byzantine import model_delta,update_indicators,aggregate_deltas,apply_delta

REPO=Path.cwd();OUT=Path(__file__).parent;PROJECT=OUT.parent.parent
LAB=REPO/'artifacts/revision-retrospective-group-validation-v1'
SOURCE=REPO/'artifacts/revision-geometry-detector-v1'
CFG=REPO/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json'
def read(path):return json.loads(Path(path).read_bytes())
def key(group):return sha256_bytes(derived_json_bytes(sorted(group)))[:16]
def load_observable(path):
    meta=read(path/'metadata.json');assert sha256_file(path/'arrays.npz')==meta['arrays_sha256']
    with np.load(path/'arrays.npz',allow_pickle=False) as z:
        packed=z['deltas'].copy()
    shapes=meta['shapes'];sizes=[int(np.prod(s)) for s in shapes];cuts=np.cumsum([0]+sizes)
    return [{'round_number':n+1,'client_ids':meta['clients'],
        'deltas':[[packed[n,c,cuts[i]:cuts[i+1]].reshape(s).copy() for i,s in enumerate(shapes)] for c in range(len(meta['clients']))],
        'indicators':meta['indicators'][n]} for n in range(len(packed))]
def materialize_observable(workspace,destination,deps,validation,envelope=False):
    deltas=[];indicators=[];commitments=[];quarantines=[]
    for number in range(1,11):
        p=workspace/'rounds'/f'round-{number:03d}';record=read(p/'round.json')
        clients=record.get('clients',record.get('client_ids'));base=read(p/'base-model.json')
        arrays=arrays_from_export(base,np=np);exports=[read(p/'updates'/f'{c}.json') for c in clients]
        ds=[model_delta(arrays,arrays_from_export(m,np=np)) for m in exports]
        values=update_indicators(ds,client_ids=clients);base_f1=evaluate(base,validation,deps)['macro_f1_all_model_classes']
        for item,model in zip(values,exports,strict=True):item['validation_impact']=base_f1-evaluate(model,validation,deps)['macro_f1_all_model_classes']
        deltas.append(np.stack([np.concatenate([a.astype(np.float64).reshape(-1) for a in d]) for d in ds]));indicators.append(values)
        commitments.append({'base':sha256_file(p/'base-model.json'),'updates':[sha256_file(p/'updates'/f'{c}.json') for c in clients]})
        if envelope:quarantines.append(read(p/'worker-response.json')['comparison_decisions']['envelope']['quarantine_current_round'])
    destination.mkdir(parents=True,exist_ok=False);np.savez_compressed(destination/'arrays.npz',deltas=np.stack(deltas))
    meta={'profile':'observable-group-prefix-v1','clients':clients,'shapes':[list(a.shape) for a in arrays],
        'frames':10,'indicators':indicators,'source_commitments':commitments,'arrays_sha256':sha256_file(destination/'arrays.npz'),
        'raw_client_rows_included':False,'attack_labels_included':False,'future_rounds_included':False}
    if envelope:meta['frozen_envelope_quarantines_by_round']=quarantines
    save(destination/'metadata.json',meta)
    return {'metadata_sha256':sha256_file(destination/'metadata.json'),'arrays_sha256':meta['arrays_sha256']}
