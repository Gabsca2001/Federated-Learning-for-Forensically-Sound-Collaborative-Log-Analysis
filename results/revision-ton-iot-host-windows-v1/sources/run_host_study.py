"""Matched chronological global/host comparison, selected on common minutes."""
from pathlib import Path
from collections import Counter,defaultdict
import datetime as dt,hashlib,json,shutil,time,platform
import numpy as np
import torch,sklearn
from sklearn.ensemble import ExtraTreesClassifier,HistGradientBoostingClassifier
from threadpoolctl import threadpool_limits
from flwr.server.strategy.aggregate import aggregate
from fl_forensics.federated_model import build_model,seed_everything,model_to_ndarrays,load_ndarrays
from fl_forensics.preprocessing import FEATURE_NAMES
from fl_forensics.robust_preprocessing import fit_feature_transform,apply_feature_transform
from fl_forensics.ton_iot_retraining import iid_partitions,tensor_digest,verify_checkpoint,VALIDATION_START,TEST_START
from fl_forensics.ton_iot_calibration import metrics,fit_macro_threshold
from host_windows import pool_host_scores

O=Path(__file__).resolve().parent;ROOT=O.parent;S=O/'study';SEEDS=(341593,342593,343593)
def load(p):return json.loads(p.read_text())
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def net(seed):
    seed_everything(seed,torch=torch,np=np)
    return build_model(input_features=25,class_count=2,hidden_layers=[128,64],embedding_size=32,dropout=0.,torch=torch)
def scores(model,x):
    model.eval()
    with torch.no_grad():return torch.softmax(model(torch.from_numpy(x)),dim=1).numpy()[:,1].astype(np.float64)
def local_fit(model,x,y,class_weights,seed):
    seed_everything(seed,torch=torch,np=np);model.train()
    generator=torch.Generator().manual_seed(seed)
    loader=torch.utils.data.DataLoader(torch.utils.data.TensorDataset(torch.from_numpy(x),torch.from_numpy(y)),batch_size=256,shuffle=True,generator=generator,num_workers=0)
    optimizer=torch.optim.Adam(model.parameters(),lr=.001)
    criterion=torch.nn.CrossEntropyLoss(weight=torch.tensor(class_weights,dtype=torch.float32))
    for _ in range(2):
        for xb,yb in loader:
            optimizer.zero_grad();loss=criterion(model(xb),yb)
            if not torch.isfinite(loss):raise ValueError('Nonfinite local loss')
            loss.backward();optimizer.step()
def family(row):
    return 'benign' if row['label']=='benign' else min((-n,name) for name,n in row['source_type_counts'].items() if name!='normal')[1]
def quality(y,score,threshold,families):
    score=np.asarray(score,dtype=np.float64);q=metrics(y,score,threshold)
    q['attack_family_recall']={name:dict(windows=int((families==name).sum()),recall=float((score[families==name]>threshold).mean())) for name in sorted(set(families)-{'benign'})}
    return q
def common_quality(data,score,threshold):
    bucket,pooled,labels=pool_host_scores(data['bucket'],score,data['y'])
    assert np.array_equal(bucket,data['common_bucket']) and np.array_equal(labels,data['common_y'])
    return quality(labels,pooled,threshold,data['common_family'])
def prepare_inputs():
    prepared=load(O/'windows/preparation-summary.json');assert prepared['status']=='verified_host_windows_prepared'
    assert sha(O/'windows/host-windows.npz')==prepared['host_matrix_sha256']
    parent=ROOT/'ton-iot-retraining-20261109/study';splits=load(parent/'split-and-partition.json')['splits'];keep=load(parent/'flow-end-selection-v2/protocol-before-reselection.json')['retained_validation_indices']
    roles={role:splits[role]['buckets'] for role in ('train','validation','test')};roles['validation']=[roles['validation'][i] for i in keep]
    global_source=load(ROOT/'ton-iot-transfer-20261109/windows/occurrence-windows.json')
    global_lookup={r['window_start_epoch']//60:r for r in global_source['rows']}
    host=np.load(O/'windows/host-windows.npz',allow_pickle=False)
    result={};notes={}
    for profile in ('global','host'):
        data={}
        for role,buckets in roles.items():
            if profile=='global':
                rows=[global_lookup[b] for b in buckets]
                x=np.asarray([r['features'] for r in rows],float);y=np.asarray([r['label']=='attack' for r in rows],np.int64)
                bucket=np.asarray(buckets,np.int64);families=np.asarray([family(r) for r in rows]);ids=np.asarray([r['window_id'] for r in rows])
            else:
                ix=np.flatnonzero(np.isin(host['bucket'],buckets));x=host['features'][ix];y=host['actual'][ix].astype(np.int64);bucket=host['bucket'][ix];families=host['family'][ix]
                ids=np.asarray([str(b)+':'+str(h) for b,h in zip(bucket,host['host'][ix])])
            if set(y.tolist())!={0,1}:raise ValueError('Both binary classes required in each role')
            if role=='train':assert np.all(bucket*60+60+x[:,5]+1<=VALIDATION_START-3600)
            if role=='validation':assert np.all(bucket*60+60+x[:,5]+1<=TEST_START-3600)
            cb=np.asarray(buckets,np.int64);cy=np.asarray([global_lookup[b]['label']=='attack' for b in buckets],np.int64);cf=np.asarray([family(global_lookup[b]) for b in buckets])
            pooled_bucket,_,pooled_label=pool_host_scores(bucket,np.zeros(len(y)),y)
            assert np.array_equal(pooled_bucket,cb) and np.array_equal(pooled_label,cy)
            data[role]=dict(raw=x,y=y,bucket=bucket,family=families,ids=ids,common_bucket=cb,common_y=cy,common_family=cf)
        rng=np.random.default_rng(341593);train_indices=np.sort(rng.permutation(len(data['train']['y']))[:30000])
        assert len(set(data['train']['y'][train_indices].tolist()))==2
        spec=fit_feature_transform(train_features=data['train']['raw'][train_indices],feature_names=FEATURE_NAMES,mode='log1p')
        for role in data:
            data[role]['x']=np.round(apply_feature_transform(features=data[role]['raw'],feature_names=FEATURE_NAMES,specification=spec),12).astype(np.float32)
        train_y=data['train']['y'][train_indices];partitions=iid_partitions(train_y)
        counts=np.bincount(train_y,minlength=2);weights=(len(train_y)/(2*counts)).tolist()
        notes[profile]=dict(native_role_counts={role:dict(windows=len(d['y']),benign=int((d['y']==0).sum()),attack=int(d['y'].sum())) for role,d in data.items()},
            training_cap=30000,selected_training_indices=train_indices.tolist(),selected_training_labels=dict(benign=int(counts[0]),attack=int(counts[1])),class_weights=weights,
            client_indices=partitions,source_units_omitted_from_training_cap=len(data['train']['y'])-len(train_indices),
            role_id_sha256={role:hashlib.sha256(('\n'.join(d['ids'])+'\n').encode()).hexdigest() for role,d in data.items()})
        result[profile]=dict(data=data,train_indices=train_indices,partitions=partitions,weights=weights,specification=spec)
    return result,notes
def main():
    assert not S.exists();assert shutil.disk_usage(O).free>=6*1024**3;S.mkdir()
    inputs,notes=prepare_inputs()
    protocol=dict(name='ToN-IoT-chronological-host-window-comparison-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        source_preparation_sha256=sha(O/'protocol-before-source-processing.json'),host_preparation_sha256=sha(O/'windows/preparation-summary.json'),
        parent_split_sha256=sha(ROOT/'ton-iot-retraining-20261109/study/split-and-partition.json'),parent_correction_sha256=sha(ROOT/'ton-iot-retraining-20261109/study/flow-end-selection-v2/protocol-before-reselection.json'),
        primary='Compare fresh global and host classifiers on the same 718 chronological global minutes; host alarms are pooled with maximum score, equivalent to any host alarm at a fixed threshold.',
        secondary='Report native host-minute class F1, FPR, attack families, per-day support and attack-row dilution separately; different native units are not interchangeable.',
        global_role_counts=dict(train=6061,validation=1080,test=718),roles_changed=False,original_records_discarded_by_grouping=False,
        fitting='Target log1p + training-only standardization; deterministic at most30000 training units/profile, uniform training-only sample, same sample across seeds; all validation/test units retained.',
        fedavg='15 synthetic IID clients,MLP128/64/32 binary,Adam .001,binary-balanced CE,30 rounds,two local epochs,batch256,three fixed seeds; no TPM or Byzantine policy.',
        compute_boundary='Same optimizer/epochs/rounds; host unit counts and batches differ, so compute is not equalized. Time measured, one CPU thread.',
        selection='Fit macro-F1 threshold on the 1080 common validation minutes every round. Max common validation macro-F1, earliest checkpoint on ties. No test selection among seeds or profiles.',
        references='Extra Trees256/minleaf2 and HistGB150/lr.05/leaves15/l2=1, separately per profile, same training sample, class weights and common validation threshold.',
        native_label='Any constituent attack within its source-host/minute. Family recall uses dominant attack name; no minority-type or actor-identity inference.',
        test_reuse='Already examined source dates and minute inventory; this is a new exploratory representation assessment, not a newly blind test.',
        unresolved='Host independence, physical connection identity, exact-projection sensitivity for new grouping, operational calibration and general novel-family robustness are not established.',
        storage='Only selected global tensors, histories/digests and scores; no raw CSV copies.',seeds=list(SEEDS),input_notes=notes,
        runner_sha256=sha(Path(__file__)),host_module_sha256=sha(O/'host_windows.py'),
        environment=dict(python=platform.python_version(),numpy=np.__version__,torch=torch.__version__,sklearn=sklearn.__version__))
    save(S/'protocol-before-fitting.json',protocol)
    entries=[];objects={}
    for profile,info in inputs.items():
        data=info['data'];selected=info['train_indices'];x=data['train']['x'][selected];y=data['train']['y'][selected]
        save(S/(profile+'-transform.json'),info['specification'])
        for seed in SEEDS:
            start=time.monotonic();identifier=f'{profile}-s{seed}';directory=S/identifier;directory.mkdir();model=net(seed);history=[];best=None;best_arrays=None
            for number in range(1,31):
                base=model_to_ndarrays(model,np=np);updates=[]
                for client,ix in enumerate(info['partitions']):
                    local=net(seed);load_ndarrays(local,base,torch=torch,np=np);local_fit(local,x[ix],y[ix],info['weights'],seed+number*10000+client)
                    arrays=model_to_ndarrays(local,np=np);updates.append((arrays,len(ix)))
                arrays=aggregate(updates);load_ndarrays(model,arrays,torch=torch,np=np)
                val_score=scores(model,data['validation']['x']);bucket,pooled,labels=pool_host_scores(data['validation']['bucket'],val_score,data['validation']['y'])
                fitted=fit_macro_threshold(labels,pooled);t=fitted['threshold'];q=common_quality(data['validation'],val_score,t)
                record=dict(round=number,threshold=t,validation_common=q,tensor_sha256=tensor_digest(arrays));history.append(record)
                if best is None or q['macro_f1']>best['validation_common']['macro_f1']:best=record;best_arrays=[a.copy() for a in arrays]
                if number%5==0:print(json.dumps(dict(status='training',id=identifier,round=number,validation_common_macro_f1=q['macro_f1'])),flush=True)
            np.savez_compressed(directory/'selected.npz',**{f'p{i:02d}':a for i,a in enumerate(best_arrays)})
            save(directory/'history.json',history);load_ndarrays(model,best_arrays,torch=torch,np=np)
            val=scores(model,data['validation']['x']);np.savez_compressed(S/(identifier+'-validation.npz'),actual=data['validation']['y'],score=val,bucket=data['validation']['bucket'],family=data['validation']['family'])
            entries.append(dict(id=identifier,scope='federated',profile=profile,seed=seed,selected_round=best['round'],threshold=best['threshold'],validation_common=best['validation_common'],validation_native=quality(data['validation']['y'],val,best['threshold'],data['validation']['family']),tensor_sha256=best['tensor_sha256'],fit_seconds=time.monotonic()-start))
            objects[identifier]=('torch',model)
            print(json.dumps(dict(status='candidate_closed',id=identifier,selected_round=best['round'],validation_common_macro_f1=best['validation_common']['macro_f1'])),flush=True)
        for kind,model in [('extra-trees',ExtraTreesClassifier(n_estimators=256,min_samples_leaf=2,max_features=1.,n_jobs=1,random_state=341593)),('histogram',HistGradientBoostingClassifier(max_iter=150,learning_rate=.05,max_leaf_nodes=15,l2_regularization=1.,early_stopping=False,random_state=341593))]:
            start=time.monotonic();weights=np.asarray(info['weights'])[y];model.fit(x,y,sample_weight=weights)
            val=model.predict_proba(data['validation']['x'])[:,1];_,pooled,labels=pool_host_scores(data['validation']['bucket'],val,data['validation']['y']);t=fit_macro_threshold(labels,pooled)['threshold']
            identifier=f'central-{kind}-{profile}';np.savez_compressed(S/(identifier+'-validation.npz'),actual=data['validation']['y'],score=val,bucket=data['validation']['bucket'],family=data['validation']['family'])
            entries.append(dict(id=identifier,scope='centralized-reference',profile=profile,seed=341593,threshold=t,validation_common=common_quality(data['validation'],val,t),validation_native=quality(data['validation']['y'],val,t,data['validation']['family']),fit_seconds=time.monotonic()-start))
            objects[identifier]=('sklearn',model)
    save(S/'closure-before-test.json',dict(protocol_sha256=sha(S/'protocol-before-fitting.json'),entries=entries,test_used_for_choices=False,all_profiles_retained=True))
    results=[]
    for entry in entries:
        data=inputs[entry['profile']]['data']['test'];kind,model=objects[entry['id']];start=time.monotonic()
        value=scores(model,data['x']) if kind=='torch' else model.predict_proba(data['x'])[:,1]
        np.savez_compressed(S/(entry['id']+'-test.npz'),actual=data['y'],score=value,bucket=data['bucket'],family=data['family'])
        b,common,cy=pool_host_scores(data['bucket'],value,data['y']);np.savez_compressed(S/(entry['id']+'-common-test.npz'),actual=cy,score=common,bucket=b,family=data['common_family'])
        native=quality(data['y'],value,entry['threshold'],data['family']);pooled=common_quality(data,value,entry['threshold'])
        results.append(dict(**entry,test_native=native,test_common=pooled,inference_seconds=time.monotonic()-start))
    summary={profile:{level:{key:float(np.mean([r[level][key] for r in results if r['scope']=='federated' and r['profile']==profile])) for key in ('macro_f1','benign_f1','attack_f1','attack_recall','false_positive_rate')} for level in ('test_common','test_native')} for profile in inputs}
    save(S/'results.json',dict(status='complete',protocol_sha256=sha(S/'protocol-before-fitting.json'),closure_sha256=sha(S/'closure-before-test.json'),summary=summary,results=results,new_blind_test_claimed=False))
    print(json.dumps(dict(status='host_study_complete',summary=summary),indent=2),flush=True)
if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):main()
