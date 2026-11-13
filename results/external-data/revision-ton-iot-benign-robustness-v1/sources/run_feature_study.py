"""Fixed same-role traffic-feature ablations; all choices close before scoring."""
from pathlib import Path
from collections import Counter
import datetime as dt, hashlib, json, importlib.util, shutil, time
import numpy as np
import torch
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from threadpoolctl import threadpool_limits
from flwr.server.strategy.aggregate import aggregate
from fl_forensics.federated_model import build_model, seed_everything, model_to_ndarrays, load_ndarrays
from fl_forensics.ton_iot_retraining import tensor_digest
from traffic_features import MODES, derive_features, fit_standard, apply_standard
from threshold_margin import center_validation_plateau
from run_margin import quality

O=Path(__file__).resolve().parent;P=O.parent/'ton-iot-f1-study-20261109';K=P/'known-family';D=O/'feature-study';SEEDS=(341593,342593,343593)
def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def net(width,seed):
    seed_everything(seed,torch=torch,np=np)
    return build_model(input_features=width,class_count=2,hidden_layers=[128,64],embedding_size=32,dropout=0.,torch=torch)
def scores(model,x):
    model.eval()
    with torch.no_grad():return torch.softmax(model(torch.from_numpy(x)),dim=1).numpy()[:,1].astype(np.float64)
def main():
    assert not D.exists()
    assert shutil.disk_usage(O).free>=6*1024**3
    D.mkdir();parent=load(K/'protocol-before-fitting.json');roles=parent['roles']
    protocol=dict(name='ToN-IoT-same-role-scale-reduced-features-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        question='Can existing-window scale-reduced features reduce false alarms without changing the known-family data assignment?',
        parent_protocol_sha256=sha(K/'protocol-before-fitting.json'),parent_closure_sha256=sha(K/'closure-before-test.json'),
        roles_changed=False,views=['occurrence','exact-projection'],representations=list(MODES),seeds=list(SEEDS),
        features='Fractions15; rates26 (15 fractions, three log durations and eight log intensity/uniqueness ratios); augmented33 (original25 with log first10 plus eight log rates). No labels, dates, IPs or IDs in predictors.',
        model='15 numerical IID clients; binary-balanced weighted MLP128/64/32, Adam .001, 2 local epochs, batch128, 30 FedAvg rounds; training-only standard scaler.',
        selection='Each round fits a validation-only macro-F1 threshold subject to per-family recall >=.8, then centers its unchanged validation decision gap. Checkpoint max validation macro-F1 then earliest. Representation chosen by mean primary-view validation macro-F1 across three seeds, with original25 parent as a candidate; ties prefer original25 then declared order.',
        controls='Parent original25 federated scores retained, centralized Extra Trees256/minleaf2 and HistGB150/leaves15 references for each representation/view.',
        test='Same already observed 1592 known-family windows; exploratory repeated-test extension. Global chronology and host independence remain absent. Original unseen-family chronological task is untouched.',
        storage='Only selected new global tensors saved; every round tensor digest and validation history retained; raw CSVs not copied.',
        runner_sha256=sha(Path(__file__)),feature_code_sha256=sha(O/'traffic_features.py'),margin_code_sha256=sha(O/'threshold_margin.py'))
    save(D/'protocol-before-fitting.json',protocol)
    module=importlib.util.spec_from_file_location('b',P/'known_family_benchmark.py');b=importlib.util.module_from_spec(module);module.loader.exec_module(b)
    entries=[];objects={};data={}
    for view in protocol['views']:
        source=O.parent/'ton-iot-transfer-20261109/windows'/f'{view}-windows.json';assert sha(source)==parent['input_sha256'][view]
        lookup={r['window_start_epoch']//60:r for r in load(source)['rows']}
        raw={role:np.asarray([lookup[bucket]['features'] for bucket,_ in roles[role]],float) for role in ('train','validation','test')}
        f={role:np.asarray([name for _,name in roles[role]]) for role in raw};y={role:(f[role]!='benign').astype(np.int64) for role in raw}
        n=len(y['train']);weights=np.asarray([n/(2*int((y['train']==label).sum())) for label in y['train']])
        rng=np.random.default_rng(341593);partitions=[[] for _ in range(15)]
        for name in sorted(set(f['train'])):
            ix=np.flatnonzero(f['train']==name);rng.shuffle(ix)
            for i,index in enumerate(ix):partitions[i%15].append(int(index))
        for mode in MODES:
            derived={role:derive_features(value,mode)[0] for role,value in raw.items()}
            names=derive_features(raw['train'],mode)[1];spec=fit_standard(derived['train'])
            save(D/f'{view}-{mode}-transform.json',dict(names=names,**spec))
            x={role:apply_standard(value,spec) for role,value in derived.items()};data[(view,mode)]=(x,y,f)
            for seed in SEEDS:
                identifier=f'{view}-{mode}-s{seed}';directory=D/identifier;directory.mkdir();model=net(x['train'].shape[1],seed)
                history=[];best=None;best_arrays=None;start=time.monotonic()
                for number in range(1,31):
                    base=model_to_ndarrays(model,np=np);updates=[]
                    for client,indices in enumerate(partitions):
                        local=net(x['train'].shape[1],seed);load_ndarrays(local,base,torch=torch,np=np)
                        b.local_fit(local,x['train'][indices],y['train'][indices],weights[indices],seed+number*10000+client)
                        updates.append((model_to_ndarrays(local,np=np),len(indices)))
                    arrays=aggregate(updates);load_ndarrays(model,arrays,torch=torch,np=np)
                    vs=scores(model,x['validation']);left=b.threshold(y['validation'],vs,f['validation']);margin=center_validation_plateau(vs,left)
                    t=margin['threshold'];q=quality(y['validation'],vs,f['validation'],t)
                    record=dict(round=number,threshold=t,threshold_gap=margin,validation=q,tensor_sha256=tensor_digest(arrays))
                    history.append(record)
                    if best is None or q['macro_f1']>best['validation']['macro_f1']:
                        best=record;best_arrays=[a.copy() for a in arrays]
                save(directory/'history.json',history);np.savez_compressed(directory/'selected.npz',**{f'p{i:02d}':a for i,a in enumerate(best_arrays)})
                load_ndarrays(model,best_arrays,torch=torch,np=np);vs=scores(model,x['validation'])
                np.savez_compressed(D/(identifier+'-validation.npz'),actual=y['validation'],score=vs,family=f['validation'])
                entry=dict(id=identifier,view=view,representation=mode,scope='federated',seed=seed,selected_round=best['round'],threshold=best['threshold'],validation=best['validation'],tensor_sha256=best['tensor_sha256'],elapsed_seconds=time.monotonic()-start)
                entries.append(entry);objects[identifier]=('torch',model)
                print(json.dumps(dict(status='candidate_closed',id=identifier,round=best['round'],validation_macro_f1=best['validation']['macro_f1'])),flush=True)
            for kind,model in [('extra-trees',ExtraTreesClassifier(n_estimators=256,min_samples_leaf=2,max_features=1.,n_jobs=1,random_state=341593)),('histogram',HistGradientBoostingClassifier(max_iter=150,learning_rate=.05,max_leaf_nodes=15,l2_regularization=1.,early_stopping=False,random_state=341593))]:
                model.fit(x['train'],y['train'],sample_weight=weights);vs=model.predict_proba(x['validation'])[:,1]
                t=center_validation_plateau(vs,b.threshold(y['validation'],vs,f['validation']))['threshold'];q=quality(y['validation'],vs,f['validation'],t)
                identifier=f'central-{kind}-{view}-{mode}';entries.append(dict(id=identifier,view=view,representation=mode,scope='centralized-reference',seed=341593,threshold=t,validation=q))
                objects[identifier]=('sklearn',model);np.savez_compressed(D/(identifier+'-validation.npz'),actual=y['validation'],score=vs,family=f['validation'])
    baseline=[dict(**e,representation='original25') for e in load(K/'closure-before-test.json')['entries'] if e['scope']=='federated' and e['family']=='binary-balanced']
    options=['original25',*MODES];validation_means={mode:float(np.mean([e['validation']['macro_f1'] for e in entries+baseline if e['scope']=='federated' and e['view']=='occurrence' and e['representation']==mode])) for mode in options}
    selected=max(options,key=lambda mode:(validation_means[mode],-options.index(mode)))
    save(D/'closure-before-test.json',dict(protocol_sha256=sha(D/'protocol-before-fitting.json'),entries=entries,baseline=baseline,validation_means=validation_means,selected_federated_representation=selected,test_used_for_choices=False))
    results=[]
    for entry in entries:
        x,y,f=data[(entry['view'],entry['representation'])];kind,model=objects[entry['id']]
        value=scores(model,x['test']) if kind=='torch' else model.predict_proba(x['test'])[:,1]
        np.savez_compressed(D/(entry['id']+'-test.npz'),actual=y['test'],score=value,family=f['test'])
        results.append(dict(**entry,test=quality(y['test'],value,f['test'],entry['threshold']),selected=entry['scope']=='federated' and entry['representation']==selected))
    for entry in baseline:
        artifact=np.load(K/(entry['id']+'-test.npz'),allow_pickle=False)
        results.append(dict(**entry,test=quality(artifact['actual'],artifact['score'],artifact['family'],entry['threshold']),selected=selected=='original25'))
    save(D/'results.json',dict(status='complete',closure_sha256=sha(D/'closure-before-test.json'),selected_representation=selected,results=results))
    means={mode:{key:float(np.mean([r['test'][key] for r in results if r['scope']=='federated' and r['view']=='occurrence' and r['representation']==mode])) for key in ('macro_f1','benign_f1','attack_f1','false_positive_rate','attack_recall')} for mode in options}
    print(json.dumps(dict(status='feature_study_complete',validation_selected=selected,validation_means=validation_means,primary_view_test_means=means),indent=2),flush=True)
if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):main()
