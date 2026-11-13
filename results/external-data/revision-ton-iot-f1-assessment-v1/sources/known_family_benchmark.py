"""Separate known-family blocked diagnostic; never a replacement for the temporal test."""
from pathlib import Path
from collections import Counter,defaultdict
import datetime as dt,hashlib,json
import numpy as np
import torch
from sklearn.ensemble import ExtraTreesClassifier,HistGradientBoostingClassifier
from threadpoolctl import threadpool_limits
from flwr.server.strategy.aggregate import aggregate
from fl_forensics.federated_model import build_model,seed_everything,model_to_ndarrays,load_ndarrays
from fl_forensics.preprocessing import FEATURE_NAMES
from fl_forensics.robust_preprocessing import fit_feature_transform,apply_feature_transform
from fl_forensics.ton_iot_retraining import tensor_digest,verify_checkpoint
from fl_forensics.ton_iot_time_bounds import observation_end_upper_bound
from fl_forensics.ton_iot_calibration import metrics

O=Path(__file__).resolve().parent;T=O.parent/'ton-iot-transfer-20261109';K=O/'known-family'
SEEDS=(341593,342593,343593)
def load(path):return json.loads(path.read_text())
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as stream:json.dump(value,stream,indent=2,allow_nan=False);stream.write('\n')
def family(row):
    if row['label']=='benign':return 'benign'
    return min(((-n,name) for name,n in row['source_type_counts'].items() if name!='normal'))[1]
def net(seed):
    seed_everything(seed,torch=torch,np=np)
    return build_model(input_features=25,class_count=2,hidden_layers=[128,64],embedding_size=32,dropout=0.,torch=torch)
def scores(model,x):
    model.eval()
    with torch.no_grad():return torch.softmax(model(torch.from_numpy(x)),dim=1).numpy()[:,1]
def threshold(y,s,families):
    order=np.argsort(s,kind='stable');values=s[order];labels=y[order]
    ends=np.r_[np.flatnonzero(values[1:]!=values[:-1]),len(values)-1]
    fn=np.r_[0,np.cumsum(labels)[ends]];tn=np.r_[0,np.cumsum(1-labels)[ends]]
    tp=int(y.sum())-fn;fp=len(y)-int(y.sum())-tn
    fa=2*tp/np.maximum(1,2*tp+fp+fn);fb=2*tn/np.maximum(1,2*tn+fp+fn)
    eligible=np.ones(len(fn),dtype=bool)
    for name in sorted(set(families)-{'benign'}):
        mask=(families[order]==name).astype(int);miss=np.r_[0,np.cumsum(mask)[ends]]
        eligible &= (mask.sum()-miss)/mask.sum()>=.8
    candidates=np.r_[-1.,values[ends]]
    best=max(np.flatnonzero(eligible),key=lambda i:((fa[i]+fb[i])/2,-int(fp[i]),float(candidates[i])))
    return float(candidates[best])
def quality(y,s,families,t):
    result=metrics(y,s,t);pred=s>t
    result['attack_family_recall']={name:dict(windows=int((families==name).sum()),recall=float(pred[families==name].mean())) for name in sorted(set(families)-{'benign'})}
    result['all_known_family_recall_goal_met']=all(value['recall']>=.8 for value in result['attack_family_recall'].values())
    return result
def local_fit(model,x,y,w,seed):
    seed_everything(seed,torch=torch,np=np);model.train()
    loader=torch.utils.data.DataLoader(torch.utils.data.TensorDataset(torch.from_numpy(x),torch.from_numpy(y),torch.tensor(w,dtype=torch.float32)),
        batch_size=128,shuffle=True,generator=torch.Generator().manual_seed(seed),num_workers=0)
    optimizer=torch.optim.Adam(model.parameters(),lr=.001)
    for _ in range(2):
        for xb,yb,wb in loader:
            optimizer.zero_grad();losses=torch.nn.functional.cross_entropy(model(xb),yb,reduction='none');loss=(losses*wb).sum()/wb.sum()
            if not torch.isfinite(loss):raise ValueError('Nonfinite loss')
            loss.backward();optimizer.step()


def main():
    assert not K.exists();K.mkdir()
    primary=load(T/'windows/occurrence-windows.json');by_family=defaultdict(list)
    for row in primary['rows']:by_family[family(row)].append(row)
    roles={name:[] for name in ('train','validation','test','purged')};support={}
    for name,rows in sorted(by_family.items()):
        rows=sorted(rows,key=lambda r:r['window_start_epoch']);n=len(rows);a=int(n*.6);b=int(n*.8)
        start_val=rows[a]['window_start_epoch'];start_test=rows[b]['window_start_epoch']
        groups=dict(train=[r for r in rows[:a] if observation_end_upper_bound(r)<=start_val-300],
                    validation=[r for r in rows[a:b] if observation_end_upper_bound(r)<=start_test-300],test=rows[b:])
        used={r['window_start_epoch'] for values in groups.values() for r in values}
        groups['purged']=[r for r in rows if r['window_start_epoch'] not in used]
        assert min(len(groups[s]) for s in ('train','validation','test'))>=10
        support[name]={role:len(values) for role,values in groups.items()}
        for role,values in groups.items():roles[role].extend((r['window_start_epoch']//60,name) for r in values)
    for role in roles:roles[role].sort()
    assert len({b for values in roles.values() for b,name in values})==len(primary['rows'])
    protocol=dict(name='ToN-IoT-known-family-blocked-diagnostic-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                  question='Can these features classify traffic when all attack families have training support? This does not test unknown MITM or future-global deployment.',
                  split='Within each dominant source attack family and benign group, ordered first 60% train, next 20% validation, last 20% test; whole windows only.',
                  purge='Within-family window-end + max duration + 1 second must precede next family-role start by 300 seconds.',
                  global_chronology=False,host_independence=False,novel_attack_family_test=False,
                  auxiliary_labels='Source type used only for splitting, training weights, IID allocation and stratified evaluation; IP/date/type never model inputs.',
                  views=['occurrence','exact-projection'],weightings=['binary-balanced','family-balanced'],seeds=list(SEEDS),
                  model='FedAvg 15 clients, [128,64]/embedding32 binary MLP, Adam .001, two local epochs, 30 rounds; log1p and standard scaler fitted only on new train.',
                  family_balance='Half training weight mass to benign, half equally across the nine attack families; every training window retained.',
                  checkpoint='Max validation macro-F1 subject to at least .8 recall in every represented attack family; earliest round on ties. Threshold fitted on validation only.',
                  selection='Mean validation objective across three seeds in the occurrence view; all regimes/seeds/views retained. Central references separate.',
                  limitations='A separate offline known-family diagnostic with global date interleaving and correlated lab traffic; no repair or replacement of the original temporal MITM result.',
                  support=support,roles=roles,input_sha256={v:sha(T/'windows'/(v+'-windows.json')) for v in ('occurrence','exact-projection')},runner_sha256=sha(Path(__file__)))
    save(K/'protocol-before-fitting.json',protocol)
    objects={};entries=[];input_data={}
    for view in ('occurrence','exact-projection'):
        dataset=load(T/'windows'/(view+'-windows.json'));lookup={r['window_start_epoch']//60:r for r in dataset['rows']}
        x={role:np.asarray([lookup[b]['features'] for b,f in roles[role]],dtype=float) for role in ('train','validation','test')}
        f={role:np.asarray([name for b,name in roles[role]]) for role in x};y={role:(f[role]!='benign').astype(np.int64) for role in x}
        spec=fit_feature_transform(train_features=x['train'],feature_names=FEATURE_NAMES,mode='log1p')
        x={role:np.round(apply_feature_transform(features=values,feature_names=FEATURE_NAMES,specification=spec),12).astype(np.float32) for role,values in x.items()}
        input_data[view]=(x,y,f);save(K/(view+'-transform.json'),spec)
        counts=Counter(f['train']);n=len(f['train']);rng=np.random.default_rng(341593);partitions=[[] for _ in range(15)]
        for name in sorted(counts):
            indices=np.flatnonzero(f['train']==name);rng.shuffle(indices)
            for i,index in enumerate(indices):partitions[i%15].append(int(index))
        for weighting in ('binary-balanced','family-balanced'):
            if weighting=='binary-balanced':w=np.asarray([n/(2*int((y['train']==label).sum())) for label in y['train']])
            else:w=np.asarray([n/(2*counts[name]*(1 if name=='benign' else 9)) for name in f['train']])
            for seed in SEEDS:
                identifier=f'{view}-{weighting}-s{seed}';directory=K/identifier;directory.mkdir();model=net(seed);history=[]
                for round_number in range(1,31):
                    base=model_to_ndarrays(model,np=np);updates=[]
                    for client,indices in enumerate(partitions):
                        local=net(seed);load_ndarrays(local,base,torch=torch,np=np);local_fit(local,x['train'][indices],y['train'][indices],w[indices],seed+round_number*10000+client)
                        arrays=model_to_ndarrays(local,np=np);tensor_digest(arrays);updates.append((arrays,len(indices)))
                    arrays=aggregate(updates);digest=tensor_digest(arrays);load_ndarrays(model,arrays,torch=torch,np=np)
                    values=scores(model,x['validation']);t=threshold(y['validation'],values,f['validation']);q=quality(y['validation'],values,f['validation'],t)
                    path=directory/f'round-{round_number:03d}.npz';np.savez_compressed(path,**{f'p{i:02d}':a for i,a in enumerate(arrays)})
                    history.append(dict(round=round_number,threshold=t,validation=q,tensor_sha256=digest,checkpoint_sha256=sha(path)))
                chosen=max(history,key=lambda r:(r['validation']['macro_f1'],-r['round']))
                load_ndarrays(model,verify_checkpoint(directory/f'round-{chosen["round"]:03d}.npz',chosen['tensor_sha256']),torch=torch,np=np)
                save(directory/'history.json',history);objects[identifier]=('torch',model)
                entries.append(dict(id=identifier,view=view,scope='federated',family=weighting,seed=seed,selected_round=chosen['round'],threshold=chosen['threshold'],validation=chosen['validation'],tensor_sha256=chosen['tensor_sha256']))
                print(json.dumps(dict(status='known_family_candidate_closed',id=identifier,validation_macro_f1=chosen['validation']['macro_f1'])),flush=True)
            for kind,reference in [('extra-trees',ExtraTreesClassifier(n_estimators=256,min_samples_leaf=2,max_features=1.,n_jobs=1,random_state=341593)),
                                   ('histogram',HistGradientBoostingClassifier(max_iter=150,learning_rate=.05,max_leaf_nodes=15,l2_regularization=1.,early_stopping=False,random_state=341593))]:
                reference.fit(x['train'],y['train'],sample_weight=w);values=reference.predict_proba(x['validation'])[:,1]
                t=threshold(y['validation'],values,f['validation']);q=quality(y['validation'],values,f['validation'],t)
                identifier=f'central-{kind}-{view}-{weighting}';objects[identifier]=('sklearn',reference)
                entries.append(dict(id=identifier,view=view,scope='centralized-reference',family=kind+'-'+weighting,seed=341593,threshold=t,validation=q))
    selected={}
    for scope in ('federated','centralized-reference'):
        names={e['family'] for e in entries if e['view']=='occurrence' and e['scope']==scope}
        selected[scope]=max(names,key=lambda name:(float(np.mean([e['validation']['macro_f1'] for e in entries if e['view']=='occurrence' and e['scope']==scope and e['family']==name])),name))
    save(K/'closure-before-test.json',dict(protocol_sha256=sha(K/'protocol-before-fitting.json'),entries=entries,selected_families=selected,test_used_for_choices=False))
    results=[]
    for entry in entries:
        x,y,f=input_data[entry['view']];kind,model=objects[entry['id']]
        values=scores(model,x['test']) if kind=='torch' else model.predict_proba(x['test'])[:,1]
        q=quality(y['test'],values,f['test'],entry['threshold'])
        np.savez_compressed(K/(entry['id']+'-test.npz'),actual=y['test'],score=values,family=f['test'])
        results.append(dict(**entry,test=q,selected_family=entry['family']==selected[entry['scope']]))
    save(K/'test-results.json',dict(status='known_family_diagnostic_complete',results=results,selected_families=selected,
         protocol_sha256=sha(K/'protocol-before-fitting.json'),closure_sha256=sha(K/'closure-before-test.json'),
         original_temporal_test_replaced=False,globally_chronological=False,new_blind_test_claimed=False))
    print(json.dumps(dict(status='known_family_complete',selected_families=selected,primary=[(r['id'],r['test']['macro_f1'],r['test']['benign_f1'],r['test']['attack_family_recall']['mitm']) for r in results if r['view']=='occurrence' and r['selected_family']]),indent=2),flush=True)


if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):main()
