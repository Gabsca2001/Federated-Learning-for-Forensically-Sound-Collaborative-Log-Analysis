"""Recompute the closed assessment and replay its selected new trajectory."""
from pathlib import Path
from collections import Counter
import json,hashlib,datetime as dt,importlib.util
import numpy as np
import torch
from sklearn.ensemble import ExtraTreesClassifier,HistGradientBoostingClassifier
from threadpoolctl import threadpool_limits
from flwr.server.strategy.aggregate import aggregate
from fl_forensics.federated_model import model_to_ndarrays,load_ndarrays
from fl_forensics.ton_iot_retraining import tensor_digest,verify_checkpoint
from fl_forensics.ton_iot_traffic_features import derive_features as installed_derive, fit_standard as installed_fit, apply_standard as installed_apply
from fl_forensics.ton_iot_margin import center_validation_plateau as installed_margin
from traffic_features import MODES,derive_features,fit_standard,apply_standard
from threshold_margin import center_validation_plateau
from run_margin import quality
import run_feature_study as runner
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

O=Path(__file__).resolve().parent;D=O/'feature-study';P=O.parent/'ton-iot-f1-study-20261109/known-family'
def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def main():
    protocol=load(D/'protocol-before-fitting.json');closure=load(D/'closure-before-test.json');results=load(D/'results.json')['results']
    assert protocol['runner_sha256']==sha(O/'run_feature_study.py')
    assert protocol['feature_code_sha256']==sha(O/'traffic_features.py')
    assert protocol['margin_code_sha256']==sha(O/'threshold_margin.py')
    assert closure['protocol_sha256']==sha(D/'protocol-before-fitting.json')
    assert load(D/'results.json')['closure_sha256']==sha(D/'closure-before-test.json')
    parent=load(P/'protocol-before-fitting.json');roles=parent['roles'];cache={}
    recomputed=0;central=0
    module=importlib.util.spec_from_file_location('b',O.parent/'ton-iot-f1-study-20261109/known_family_benchmark.py');b=importlib.util.module_from_spec(module);module.loader.exec_module(b)
    for view in protocol['views']:
        path=O.parent/'ton-iot-transfer-20261109/windows'/f'{view}-windows.json';assert sha(path)==parent['input_sha256'][view]
        lookup={r['window_start_epoch']//60:r for r in load(path)['rows']}
        raw={role:np.asarray([lookup[bucket]['features'] for bucket,_ in roles[role]],float) for role in ('train','validation','test')}
        f={role:np.asarray([name for _,name in roles[role]]) for role in raw};y={role:(f[role]!='benign').astype(np.int64) for role in raw}
        for mode in MODES:
            derived={role:derive_features(v,mode)[0] for role,v in raw.items()};spec=fit_standard(derived['train'])
            assert spec=={k:v for k,v in load(D/f'{view}-{mode}-transform.json').items() if k!='names'}
            assert derive_features(raw['train'],mode)[1]==load(D/f'{view}-{mode}-transform.json')['names']
            np.testing.assert_array_equal(installed_derive(raw['train'],mode)[0],derived['train']);assert installed_fit(derived['train'])==spec
            x={role:apply_standard(v,spec) for role,v in derived.items()};np.testing.assert_array_equal(installed_apply(derived['test'],spec),x['test'])
            cache[(view,mode)]=(x,y,f)
    for entry in results:
        if entry['representation']=='original25':continue
        x,y,f=cache[(entry['view'],entry['representation'])]
        val=np.load(D/(entry['id']+'-validation.npz'),allow_pickle=False);test=np.load(D/(entry['id']+'-test.npz'),allow_pickle=False)
        assert np.array_equal(test['actual'],y['test']) and np.array_equal(val['actual'],y['validation'])
        assert np.array_equal(test['family'],f['test']) and np.array_equal(val['family'],f['validation'])
        left=b.threshold(y['validation'],val['score'],f['validation']);margin=center_validation_plateau(val['score'],left)
        assert installed_margin(val['score'],left)==margin
        assert margin['threshold']==entry['threshold']
        assert quality(y['validation'],val['score'],f['validation'],entry['threshold'])==entry['validation']
        assert quality(y['test'],test['score'],f['test'],entry['threshold'])==entry['test']
        if entry['scope']=='federated':
            history=load(D/entry['id']/'history.json');best=max(history,key=lambda h:(h['validation']['macro_f1'],-h['round']))
            assert best['round']==entry['selected_round'] and best['threshold']==entry['threshold']
            arrays=verify_checkpoint(D/entry['id']/'selected.npz',entry['tensor_sha256']);model=runner.net(x['train'].shape[1],entry['seed']);load_ndarrays(model,arrays,torch=torch,np=np)
            np.testing.assert_array_equal(runner.scores(model,x['validation']),val['score']);np.testing.assert_array_equal(runner.scores(model,x['test']),test['score']);recomputed+=1
        else:
            n=len(y['train']);w=np.asarray([n/(2*int((y['train']==label).sum())) for label in y['train']])
            if entry['id'].startswith('central-extra-trees'):model=ExtraTreesClassifier(n_estimators=256,min_samples_leaf=2,max_features=1.,n_jobs=1,random_state=341593)
            else:model=HistGradientBoostingClassifier(max_iter=150,learning_rate=.05,max_leaf_nodes=15,l2_regularization=1.,early_stopping=False,random_state=341593)
            model.fit(x['train'],y['train'],sample_weight=w)
            np.testing.assert_array_equal(model.predict_proba(x['validation'])[:,1],val['score']);np.testing.assert_array_equal(model.predict_proba(x['test'])[:,1],test['score']);central+=1
    means={mode:float(np.mean([e['validation']['macro_f1'] for e in results if e['view']=='occurrence' and e['scope']=='federated' and e['representation']==mode])) for mode in ('original25',*MODES)}
    assert means==closure['validation_means'];options=list(means);selected=max(options,key=lambda mode:(means[mode],-options.index(mode)))
    assert selected==closure['selected_federated_representation']
    # Replay the strongest new representation on validation, even when the parent wins.
    new_mode=max(MODES,key=lambda mode:(means[mode],-list(MODES).index(mode)));seed=341593
    x,y,f=cache[('occurrence',new_mode)];n=len(y['train']);w=np.asarray([n/(2*int((y['train']==label).sum())) for label in y['train']])
    rng=np.random.default_rng(341593);partitions=[[] for _ in range(15)]
    for name in sorted(set(f['train'])):
        ix=np.flatnonzero(f['train']==name);rng.shuffle(ix)
        for i,index in enumerate(ix):partitions[i%15].append(int(index))
    model=runner.net(x['train'].shape[1],seed);history=load(D/f'occurrence-{new_mode}-s{seed}'/'history.json')
    for record in history:
        base=model_to_ndarrays(model,np=np);updates=[]
        for client,indices in enumerate(partitions):
            local=runner.net(x['train'].shape[1],seed);load_ndarrays(local,base,torch=torch,np=np)
            b.local_fit(local,x['train'][indices],y['train'][indices],w[indices],seed+record['round']*10000+client)
            updates.append((model_to_ndarrays(local,np=np),len(indices)))
        arrays=aggregate(updates);assert tensor_digest(arrays)==record['tensor_sha256'];load_ndarrays(model,arrays,torch=torch,np=np)
    # Verify margin rules on the previously closed parent score arrays.
    for entry in load(O/'margin/results.json')['results']:
        v=np.load(O/'margin'/(entry['id']+'-validation.npz'),allow_pickle=False)
        assert center_validation_plateau(v['score'],entry['thresholds']['original'])==entry['margin']
        t=np.load(P/(entry['id']+'-test.npz'),allow_pickle=False)
        for rule,threshold in entry['thresholds'].items():
            assert quality(t['actual'],t['score'],t['family'],threshold)==entry['test'][rule]
    summary=dict(selected_representation=selected,validation_means=means,primary_view_test_means={},per_seed=[],limitations=protocol['test'])
    lookup={r['window_start_epoch']//60:r for r in load(O.parent/'ton-iot-transfer-20261109/windows/occurrence-windows.json')['rows']}
    for mode in options:
        entries=[r for r in results if r['view']=='occurrence' and r['scope']=='federated' and r['representation']==mode]
        summary['primary_view_test_means'][mode]={key:float(np.mean([r['test'][key] for r in entries])) for key in ('macro_f1','benign_f1','attack_f1','attack_recall','false_positive_rate')}
        for e in entries:
            path=(P if mode=='original25' else D)/(e['id']+'-test.npz');a=np.load(path,allow_pickle=False);s=a['score'].astype(np.float64)
            groups={}
            for period in ('early-benign-04-Apr','late-benign-24-to-29-Apr'):
                ix=[i for i,(bucket,name) in enumerate(roles['test']) if name=='benign' and ((lookup[bucket]['capture_id']=='2019-04-04')==(period=='early-benign-04-Apr'))]
                groups[period]=dict(windows=len(ix),false_alerts=int((s[ix]>e['threshold']).sum()),false_positive_rate=float((s[ix]>e['threshold']).mean()))
            summary['per_seed'].append(dict(id=e['id'],representation=mode,seed=e['seed'],selected=e['selected'],test=e['test'],benign_periods=groups))
    save(O/'summary.json',summary)
    save(O/'verification.json',dict(status='verified',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        saved_selected_federated_models_recomputed=recomputed,centralized_models_freshly_refitted=central,all_thirty_new_validation_and_test_metric_sets_recomputed=True,
        source_and_installed_feature_rules_match=True,scalers_refitted_from_training=True,selection_recomputed_from_validation=True,
        replay=dict(id=f'occurrence-{new_mode}-s{seed}',global_tensor_digests_matched=30,local_updates_rerun=450,local_digest_comparison_claimed=False),
        roles_changed=False,blind_holdout_claimed=False))
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False})
    fig,ax=plt.subplots(1,2,figsize=(11,4.5),layout='constrained');labels=['Original 25','Fractions 15','Rates 26','Augmented 33']
    for i,(mode,label) in enumerate(zip(options,labels)):
        mean=summary['primary_view_test_means'][mode]
        ax[0].bar(i-.18,mean['macro_f1'],width=.35,color='#2563eb',label='Macro-F1' if i==0 else None)
        ax[0].bar(i+.18,mean['false_positive_rate'],width=.35,color='#d97706',label='False-positive rate' if i==0 else None)
    ax[0].set(xticks=np.arange(4),xticklabels=labels,ylim=(0,1.05),title='Three-seed test means, unchanged roles');ax[0].tick_params(axis='x',rotation=20);ax[0].legend(fontsize=8)
    for i,mode in enumerate(options):
        entries=[r for r in summary['per_seed'] if r['representation']==mode]
        value=np.mean([r['benign_periods']['late-benign-24-to-29-Apr']['false_positive_rate'] for r in entries])
        ax[1].bar(i,value,color='#0f766e')
    ax[1].set(xticks=np.arange(4),xticklabels=labels,ylim=(0,1.05),ylabel='False-positive rate',title='Later benign traffic only (122 windows)');ax[1].tick_params(axis='x',rotation=20)
    fig.suptitle('Exploratory known-family feature ablations | validation-selected: '+selected,fontsize=11)
    fig.savefig(O/'feature-comparison.png',dpi=180);plt.close(fig)
    print(json.dumps(dict(summary=summary['primary_view_test_means'],selected=selected,verification=load(O/'verification.json')),indent=2),flush=True)
if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):main()
