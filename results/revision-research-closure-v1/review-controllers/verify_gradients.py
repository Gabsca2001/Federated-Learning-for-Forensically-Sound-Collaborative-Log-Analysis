"""Reconstruct native-gradient queries and regenerate all used adversarial exports."""
from pathlib import Path
import json
import sys
import time

import numpy as np

OUT=Path(__file__).parent
sys.path[:0]=[str(OUT),str(OUT.parent/'state-conditioned-detector-20261103')]
from gradient_study import operation,read,worst
from study_data import Generator
from revision_dba_experiment import full_gradient,outcomes,predict,authenticate,save
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows
from fl_forensics.federated_model import arrays_from_export,train_local,export_state
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _model_from_export
from fl_forensics.round_derivation import implementation_sha256

REPO=Path.cwd();root=REPO/'artifacts/revision-research-closure-v1/native-gradients-evaluation'
protocol=read(root/'protocol-before-execution.json')
assert protocol['source']==implementation_sha256()
assert sha256_file(root/'controller.py')==protocol['controller_sha256']==sha256_file(OUT/'gradient_study.py')
results=read(root/'results.json')
cfg=read(REPO/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
counts={'cases':0,'selected_aggregates':0,'candidate_queries':0,'true_clean_gradients_recomputed':0,
        'adversarial_local_models_retrained':0,'terminal_failures_replayed':0}
for case in results['cases']:
    task=case['task'];workspace=root/task['name']
    authenticate(workspace,case['manifest_sha256'])
    gen=Generator(REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid'),cfg)
    rows=read(cfg['validation_path'])['rows']['validation'];pred,_=predict(gen.initial,rows,gen.deps)
    correct=[p==r['label'] for p,r in zip(pred,rows,strict=True)]
    plan=DistributedBackdoorPlan.model_validate({**cfg['attack_plan'],'seed':task['seed'],
        'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True))})
    history=[[] for _ in gen.clients];sample_counts=[len(gen.rows[c]) for c in gen.clients]
    for prefix in sorted((workspace/'rounds').glob('round-*')):
        number=int(prefix.name[-3:]);base=read(prefix/'base-model.json');base_arrays=arrays_from_export(base,np=np)
        active=task['mode']=='adaptive-gradient' and number<=10
        with np.load(prefix/'gradient-endpoints.npz',allow_pickle=False) as packed:
            clean=[[packed[f'clean_{i}_{j}'].copy() for j in range(len(base_arrays))] for i in range(15)]
            poison={c:[packed[f'poison_{c}_{j}'].copy() for j in range(len(base_arrays))]
                    for c in task['attackers']} if active else {}
        for c,expected in zip(gen.clients,clean,strict=True):
            actual,_=full_gradient(base,gen.rows[c],gen.weights,gen.deps)
            assert all(np.array_equal(a,b) for a,b in zip(actual,expected,strict=True))
            counts['true_clean_gradients_recomputed']+=1
        for c,expected in poison.items():
            altered,_=poison_local_rows(rows=gen.rows[c],plan=plan,client_id=c,round_number=number,distributed=True)
            model=_model_from_export(base,torch=gen.torch,np=np)
            seed=task['seed']+number*10000+int(gen.records[c]['partition_id'])
            train_local(model=model,rows=altered,class_names=base['class_names'],class_weights=gen.weights,
                        epochs=cfg['local_epochs'],batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'],
                        seed=seed,device_name='cpu',torch=gen.torch,np=np)
            local=arrays_from_export(export_state(model,architecture=base['architecture'],class_names=base['class_names']),np=np)
            actual=[np.asarray((a.astype(np.float64)-b)/.001,dtype=a.dtype) for a,b in zip(base_arrays,local,strict=True)]
            assert all(np.array_equal(a,b) for a,b in zip(actual,expected,strict=True))
            counts['adversarial_local_models_retrained']+=1
        transcript=read(prefix/'queries.json');candidates=[]
        for query in transcript:
            alpha=query['alpha']
            gradients=[[np.asarray(a+alpha*(b.astype(np.float64)-a),dtype=a.dtype) for a,b in zip(g,poison[c],strict=True)]
                       if c in poison else g for c,g in zip(gen.clients,clean,strict=True)]
            hist=[(h+[np.concatenate([a.astype(np.float64).ravel() for a in g])])[-3:]
                  for h,g in zip(history,gradients,strict=True)]
            try:
                model,report=operation(base,gradients,hist,sample_counts,gen.clients,task['method'])
                metric=outcomes(model,rows,plan,correct,gen.deps)
                if not np.isfinite(metric['clean']['loss']):raise ValueError('nonfinite validation loss')
                valid=True
            except (ValueError,ArithmeticError,RuntimeError):valid=False
            assert valid==query['valid'],(task['name'],number,alpha)
            if valid:
                assert metric==query['metrics']
                assert report['coefficient_sum']==query['coefficient_sum']
                candidates.append((worst(metric),alpha,model,report,metric,hist))
            counts['candidate_queries']+=1
        if not candidates:
            assert (prefix/'terminal-failure.json').exists()
            counts['terminal_failures_replayed']+=1
            continue
        if active:
            ref=read(root/f"{task['cohort']}-gradient_fedavg-clean/rounds/round-{number:03d}/round.json")
            threshold=ref['metrics']['clean']['macro_f1_all_model_classes']-.05
            allowed=[x for x in candidates if x[4]['clean']['macro_f1_all_model_classes']>=threshold]
            if not allowed:allowed=[x for x in candidates if x[1]==0.]
            candidates=allowed or candidates
        _,alpha,model,report,metric,history=max(candidates,key=lambda x:(x[0],x[1]))
        frame=read(prefix/'round.json')
        assert alpha==frame['selected_alpha'] and metric==frame['metrics']
        assert derived_json_bytes(model)==(prefix/'global-model.json').read_bytes()
        assert report==read(prefix/'aggregation.json')
        counts['selected_aggregates']+=1
    counts['cases']+=1
    print(json.dumps({'verified_gradient_case':task['name'],'counts':counts}),flush=True)
record={'status':'verified','source':implementation_sha256(),'counts':counts,
        'interpretation':'Separate driver, same implementation. Every saved query and selected aggregate reconstructed; all true clean gradients and all three used forged-gradient endpoints regenerated. No external/independent implementation audit or fresh TPM quote.'}
save(root.parent/'native-gradient-replay.json',record)
(OUT/'native-gradient-replay.json').write_bytes((root.parent/'native-gradient-replay.json').read_bytes())
print('NATIVE GRADIENT REPLAY COMPLETE',json.dumps(counts),flush=True)
