"""Final pre-test refit after family selection, with a fixed recency control.

The old validation role is retired into training. No post-refit validation or
test-driven threshold fitting is permitted.
"""
from pathlib import Path
import datetime as dt,hashlib,json,statistics,time
import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from threadpoolctl import threadpool_limits
from flwr.server.strategy.aggregate import aggregate
from fl_forensics.federated_model import build_model,seed_everything,model_to_ndarrays,load_ndarrays
from fl_forensics.ton_iot_retraining import iid_partitions,tensor_digest,verify_checkpoint,TEST_START
from fl_forensics.ton_iot_calibration import fit_macro_threshold,metrics

O=Path(__file__).resolve().parent;S=O/'study';P=O.parent/'ton-iot-retraining-20261109/study';T=O.parent/'ton-iot-transfer-20261109'
F=O/'final-refit';SEEDS=(341593,342593,343593)
def load(path):return json.loads(path.read_text())
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as stream:json.dump(value,stream,indent=2,allow_nan=False);stream.write('\n')
def model(seed):
    seed_everything(seed,torch=torch,np=np)
    return build_model(input_features=25,class_count=2,hidden_layers=[128,64],embedding_size=32,dropout=0.,torch=torch)
def score(net,x):
    net.eval()
    with torch.no_grad():return torch.softmax(net(torch.from_numpy(x)),dim=1).numpy()[:,1]
def local_fit(net,x,y,example_weights,class_weights,seed):
    seed_everything(seed,torch=torch,np=np);net.train()
    dataset=torch.utils.data.TensorDataset(torch.from_numpy(x),torch.from_numpy(y),torch.tensor(example_weights,dtype=torch.float32))
    loader=torch.utils.data.DataLoader(dataset,batch_size=128,shuffle=True,generator=torch.Generator().manual_seed(seed),num_workers=0)
    optimizer=torch.optim.Adam(net.parameters(),lr=.001)
    cw=torch.tensor(class_weights,dtype=torch.float32)
    for _ in range(2):
        for xb,yb,wb in loader:
            optimizer.zero_grad();losses=torch.nn.functional.cross_entropy(net(xb),yb,weight=cw,reduction='none')
            loss=(losses*wb).sum()/(cw[yb]*wb).sum()
            if not torch.isfinite(loss):raise ValueError('Nonfinite weighted loss')
            loss.backward();optimizer.step()


def main():
    assert not F.exists();F.mkdir()
    closed=load(S/'selection-and-calibration-closure-before-test.json')
    selected=closed['selected_families'];assert selected['federated']=='fedavg-legacy-source-standard'
    assert selected['centralized-reference']=='central-logistic-target-log1p'
    split=load(P/'split-and-partition.json');v2=load(P/'flow-end-selection-v2/protocol-before-reselection.json');keep=v2['retained_validation_indices']
    train_buckets=split['splits']['train']['buckets'];val_buckets=[split['splits']['validation']['buckets'][i] for i in keep]
    pool_buckets=train_buckets+val_buckets
    data=load(T/'windows/occurrence-windows.json')['rows'];by_bucket={r['window_start_epoch']//60:r for r in data}
    assert all(by_bucket[b]['window_end_epoch']+by_bucket[b]['features'][5]+1<=TEST_START-3600 for b in pool_buckets)
    primary=[r for r in closed['candidates'] if r['family']==selected['federated'] and r['view']=='occurrence']
    rounds=int(statistics.median(r['metadata']['round'] for r in primary))
    assert rounds==9
    age_days=np.asarray([(TEST_START-by_bucket[b]['window_end_epoch'])/86400 for b in pool_buckets])
    recency=np.exp2(-age_days/2.)
    protocol=dict(name='ToN-IoT-final-pre-test-update-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                  source_selection_sha256=sha(S/'selection-and-calibration-closure-before-test.json'),
                  selected_families=selected,federated_rounds=rounds,round_budget_selection='Median primary-view round of the validation-selected family, frozen before final fitting.',
                  train_windows=len(pool_buckets),retired_validation_windows=len(val_buckets),test_windows=718,
                  role_change='Old corrected validation becomes training; no independent validation is claimed after this update.',
                  modes=['uniform','recency-48h'],primary_mode='recency-48h',
                  recency='Every pre-test window is retained; weight = 2**(-age_days/2) from its window end to the test boundary.',
                  weights='Weighted global sqrt-balanced class weights and normalized weighted local cross-entropy; sample-count FedAvg.',
                  primary_decision='New binary-head argmax (strict attack probability > .5), fixed without post-refit calibration.',
                  transferred_threshold='Diagnostic only: calibrate a train-only fixed-round control on the old validation before adding it to fitting, then transfer unchanged.',
                  preprocessing='Reuse parent train-fitted transforms unchanged; no test or pooled-scaler fitting.',
                  test_scope='Previously observed date. Exploratory pre-test adaptation, not fresh blind generalization or repair of the old frozen model.',
                  neural='Original 128/64/32 encoder, two-output head, Adam .001, two local epochs, 15 IID clients, seeds 341593/342593/343593.',
                  centralized='The validation-selected logistic/log1p reference is refitted separately with both weighting rules; not a federated defense.',
                  runner_sha256=sha(Path(__file__)),parent_protocol_sha256=sha(P/'protocol-before-training.json'),
                  all_test_results_reported=True,operational_readiness_claimed=False,manuscript_changed=False)
    save(F/'protocol-before-refit.json',protocol)
    models={};entries=[];controls=[]
    for view in ('occurrence','exact-projection'):
        path=P/'prepared'/(view+'-source-standard')/'train-validation.npz'
        with np.load(path,allow_pickle=False) as d:
            x_train,y_train,xv,yv=d['x_train'],d['y_train'],d['x_validation'][keep],d['y_validation'][keep]
        x=np.vstack([x_train,xv]);y=np.r_[y_train,yv];assert len(y)==7141
        partitions=iid_partitions(y);transferred={}
        for seed in SEEDS:
            parent_run=P/'runs'/f'{view}-source-standard-s{seed}'
            record=load(parent_run/'history.json')[rounds-1];net=model(seed)
            load_ndarrays(net,verify_checkpoint(parent_run/'checkpoints'/f'round-{rounds:03d}.npz',record['tensor_sha256']),torch=torch,np=np)
            fitted=fit_macro_threshold(yv,score(net,xv));transferred[seed]=fitted['threshold']
            controls.append(dict(view=view,seed=seed,round=rounds,threshold=fitted['threshold'],validation=fitted['validation'],tensor_sha256=record['tensor_sha256']))
        for weighting in ('uniform','recency-48h'):
            weights=np.ones(len(y)) if weighting=='uniform' else recency
            counts=[float(weights[y==label].sum()) for label in (0,1)];total=sum(counts)
            cw=[float(np.sqrt(total/(2*n))) for n in counts]
            for seed in SEEDS:
                identifier=f'refit-{weighting}-{view}-s{seed}';directory=F/identifier;directory.mkdir();net=model(seed);history=[]
                for round_number in range(1,rounds+1):
                    base=model_to_ndarrays(net,np=np);updates=[]
                    for client,indices in enumerate(partitions):
                        local=model(seed);load_ndarrays(local,base,torch=torch,np=np)
                        local_fit(local,x[indices],y[indices],weights[indices],cw,seed+round_number*10000+client)
                        arrays=model_to_ndarrays(local,np=np);tensor_digest(arrays);updates.append((arrays,len(indices)))
                    arrays=aggregate(updates);digest=tensor_digest(arrays);load_ndarrays(net,arrays,torch=torch,np=np)
                    path=directory/f'round-{round_number:03d}.npz';np.savez_compressed(path,**{f'p{i:02d}':a for i,a in enumerate(arrays)})
                    history.append(dict(round=round_number,tensor_sha256=digest,checkpoint_sha256=sha(path)))
                save(directory/'history.json',history);models[identifier]=('torch',net)
                entries.append(dict(id=identifier,scope='federated',view=view,weighting=weighting,seed=seed,mode='source-standard',
                                    threshold=.5,transferred_threshold=transferred[seed],class_weights=cw,rounds=rounds,tensor_sha256=history[-1]['tensor_sha256']))
                print(json.dumps(dict(status='refit_closed',id=identifier)),flush=True)
        with np.load(P/'prepared'/(view+'-target-log1p')/'train-validation.npz',allow_pickle=False) as d:
            xc=np.vstack([d['x_train'],d['x_validation'][keep]]);yc=np.r_[d['y_train'],d['y_validation'][keep]]
        baseline=next(r for r in closed['candidates'] if r['family']==selected['centralized-reference'] and r['view']==view)
        for weighting in ('uniform','recency-48h'):
            w=np.ones(len(yc)) if weighting=='uniform' else recency
            total=float(w.sum());cw=[float(np.sqrt(total/(2*w[yc==label].sum()))) for label in (0,1)]
            net=LogisticRegression(C=1,max_iter=3000,solver='lbfgs');net.fit(xc,yc,sample_weight=w*np.asarray(cw)[yc])
            identifier=f'central-refit-{weighting}-{view}';models[identifier]=('sklearn',net)
            entries.append(dict(id=identifier,scope='centralized-reference',view=view,weighting=weighting,seed=341593,mode='target-log1p',
                                threshold=.5,transferred_threshold=baseline['threshold'],class_weights=cw))
    save(F/'fitting-closure-before-test.json',dict(protocol_sha256=sha(F/'protocol-before-refit.json'),entries=entries,train_only_fixed_round_controls=controls,test_used_for_choices=False))
    results=[];control_results=[]
    for entry in entries:
        with np.load(P/'prepared'/(entry['view']+'-'+entry['mode'])/'test.npz',allow_pickle=False) as d:xt,yt=d['x'],d['y']
        kind,net=models[entry['id']];values=score(net,xt) if kind=='torch' else net.predict_proba(xt)[:,1]
        np.savez_compressed(F/(entry['id']+'-test.npz'),actual=yt,score=values)
        results.append(dict(**entry,test=metrics(yt,values),test_transferred_threshold=metrics(yt,values,entry['transferred_threshold'])))
    for entry in controls:
        view=entry['view'];seed=entry['seed'];net=model(seed)
        load_ndarrays(net,verify_checkpoint(P/'runs'/f'{view}-source-standard-s{seed}'/'checkpoints'/f'round-{rounds:03d}.npz',entry['tensor_sha256']),torch=torch,np=np)
        with np.load(P/'prepared'/(view+'-source-standard')/'test.npz',allow_pickle=False) as d:xt,yt=d['x'],d['y']
        values=score(net,xt)
        control_results.append(dict(**entry,test=metrics(yt,values),test_calibrated=metrics(yt,values,entry['threshold'])))
    save(F/'test-results.json',dict(status='final_pretest_update_complete',protocol_sha256=sha(F/'protocol-before-refit.json'),
         fitting_closure_sha256=sha(F/'fitting-closure-before-test.json'),results=results,train_only_controls=control_results,
         primary_weighting='recency-48h',primary_decision='default binary argmax',new_blind_test_claimed=False))
    print(json.dumps(dict(status='final_refit_complete',models=len(results)),indent=2),flush=True)


if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):main()
