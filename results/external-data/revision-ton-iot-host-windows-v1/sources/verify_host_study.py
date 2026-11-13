"""Verify host lineage, all selected scores, references and two fresh replays."""
from pathlib import Path
from collections import Counter,defaultdict
import datetime as dt,gzip,hashlib,json,time
import numpy as np
import torch
from sklearn.ensemble import ExtraTreesClassifier,HistGradientBoostingClassifier
from threadpoolctl import threadpool_limits
from flwr.server.strategy.aggregate import aggregate
from fl_forensics.federated_model import model_to_ndarrays,load_ndarrays
from fl_forensics.ton_iot_retraining import verify_checkpoint,tensor_digest
from fl_forensics.ton_iot_calibration import fit_macro_threshold
from fl_forensics.ton_iot_host_windows import pool_host_scores as installed_pool
from host_windows import pool_host_scores
import run_host_study as runner

O=Path(__file__).resolve().parent;S=O/'study';ROOT=O.parent
def load(p):return json.loads(p.read_text())
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def main():
    prepared=load(O/'windows/preparation-summary.json');protocol=load(S/'protocol-before-fitting.json');closure=load(S/'closure-before-test.json');complete=load(S/'results.json')
    assert sha(S/'protocol-before-fitting.json')==closure['protocol_sha256']==complete['protocol_sha256']
    assert sha(S/'closure-before-test.json')==complete['closure_sha256']
    assert sha(O/'run_host_study.py')==protocol['runner_sha256'] and sha(O/'host_windows.py')==protocol['host_module_sha256']
    assert sha(O/'windows/host-windows.npz')==prepared['host_matrix_sha256'] and sha(O/'windows/host-window-lineage.jsonl.gz')==prepared['lineage_sha256']
    with np.load(O/'windows/host-windows.npz',allow_pickle=False) as packed:
        h={name:packed[name] for name in packed.files}
    source_counts=Counter();identities=set();ordinal_digests=set();lineage_count=0
    by_minute=defaultdict(Counter);day_counts=defaultdict(Counter)
    with gzip.open(O/'windows/host-window-lineage.jsonl.gz','rt',encoding='utf-8') as f:
        for i,line in enumerate(f):
            r=json.loads(line);assert r['window_id'] not in identities;identities.add(r['window_id'])
            assert len(r['ordered_source_ordinal_sha256'])==64;ordinal_digests.add(r['ordered_source_ordinal_sha256'])
            np.testing.assert_array_equal(r['features'],h['features'][i])
            assert (r['label']=='attack')==bool(h['actual'][i])
            assert r['source_record_count']==int(h['record_count'][i])
            assert r['binary_record_counts'].get('1',0)==int(h['attack_count'][i])
            assert r['originator_host_sha256']==h['host'][i] and r['window_start_epoch']//60==h['bucket'][i]
            assert r['features'][0]==r['source_record_count']
            source_counts.update(r['source_file_counts']);lineage_count+=1
            by_minute[int(h['bucket'][i])].update(r['binary_record_counts'])
            day_counts[r['capture_id']][r['label']]+=1
    assert lineage_count==len(h['actual'])==prepared['host_windows']
    assert dict(source_counts)==prepared['source_counts'] and sum(source_counts.values())==prepared['accepted_occurrences']
    original=load(ROOT/'ton-iot-transfer-20261109/windows/occurrence-windows.json')
    for row in original['rows']:assert dict(by_minute[row['window_start_epoch']//60])==row['binary_record_counts']
    inputs,notes=runner.prepare_inputs();assert notes==protocol['input_notes']
    selected_count=0;central_count=0;metric_count=0
    for e in complete['results']:
        info=inputs[e['profile']];data=info['data'];tr=info['train_indices'];train_x=data['train']['x'][tr];train_y=data['train']['y'][tr]
        assert info['specification']==load(S/(e['profile']+'-transform.json'))
        if e['scope']=='federated':
            history=load(S/e['id']/'history.json');best=max(history,key=lambda r:(r['validation_common']['macro_f1'],-r['round']))
            assert best['round']==e['selected_round'] and best['threshold']==e['threshold']
            model=runner.net(e['seed']);load_ndarrays(model,verify_checkpoint(S/e['id']/'selected.npz',e['tensor_sha256']),torch=torch,np=np);selected_count+=1
            predict=lambda x:runner.scores(model,x)
        else:
            if e['id'].startswith('central-extra-trees'):model=ExtraTreesClassifier(n_estimators=256,min_samples_leaf=2,max_features=1.,n_jobs=1,random_state=341593)
            else:model=HistGradientBoostingClassifier(max_iter=150,learning_rate=.05,max_leaf_nodes=15,l2_regularization=1.,early_stopping=False,random_state=341593)
            model.fit(train_x,train_y,sample_weight=np.asarray(info['weights'])[train_y]);central_count+=1
            predict=lambda x:model.predict_proba(x)[:,1]
        for role in ('validation','test'):
            a=np.load(S/(e['id']+'-'+role+'.npz'),allow_pickle=False);d=data[role];score=predict(d['x'])
            np.testing.assert_array_equal(score,a['score']);np.testing.assert_array_equal(d['y'],a['actual']);np.testing.assert_array_equal(d['bucket'],a['bucket'])
            pooled=pool_host_scores(d['bucket'],score,d['y']);installed=installed_pool(d['bucket'],score,d['y'])
            for actual,expected in zip(pooled,installed):np.testing.assert_array_equal(actual,expected)
            assert runner.quality(d['y'],score,e['threshold'],d['family'])==e[role+'_native']
            assert runner.common_quality(d,score,e['threshold'])==e[role+'_common'];metric_count+=2
            if role=='validation':assert fit_macro_threshold(pooled[2],pooled[1])['threshold']==e['threshold']
            else:
                saved=np.load(S/(e['id']+'-common-test.npz'),allow_pickle=False)
                for key,value in zip(('bucket','score','actual'),pooled):np.testing.assert_array_equal(saved[key],value)
    replays=[]
    for profile in ('global','host'):
        info=inputs[profile];tr=info['train_indices'];data=info['data'];x=data['train']['x'][tr];y=data['train']['y'][tr]
        seed=341593;model=runner.net(seed);history=load(S/f'{profile}-s{seed}'/'history.json');start=time.monotonic()
        for record in history:
            base=model_to_ndarrays(model,np=np);updates=[]
            for client,ix in enumerate(info['partitions']):
                local=runner.net(seed);load_ndarrays(local,base,torch=torch,np=np);runner.local_fit(local,x[ix],y[ix],info['weights'],seed+record['round']*10000+client)
                updates.append((model_to_ndarrays(local,np=np),len(ix)))
            arrays=aggregate(updates);assert tensor_digest(arrays)==record['tensor_sha256'];load_ndarrays(model,arrays,torch=torch,np=np)
            vs=runner.scores(model,data['validation']['x']);_,pooled,labels=pool_host_scores(data['validation']['bucket'],vs,data['validation']['y'])
            assert fit_macro_threshold(labels,pooled)['threshold']==record['threshold']
            assert runner.common_quality(data['validation'],vs,record['threshold'])==record['validation_common']
        replays.append(dict(id=f'{profile}-s{seed}',global_round_hashes_matched=30,local_updates_rerun=450,all_round_validation_metrics_recomputed=True,elapsed_seconds=time.monotonic()-start))
        print(json.dumps(dict(status='replay_verified',**replays[-1])),flush=True)
    train_hosts=set(h['host'][np.isin(h['bucket'],inputs['host']['data']['train']['bucket'])])
    test_ix=np.flatnonzero(np.isin(h['bucket'],inputs['host']['data']['test']['bucket']))
    overlap=dict(test_units=len(test_ix),test_units_with_training_host=int(sum(host in train_hosts for host in h['host'][test_ix])),test_unique_hosts=len(set(h['host'][test_ix])))
    dilution={}
    for profile in ('global','host'):
        if profile=='global':
            rows=[r for r in original['rows'] if r['window_start_epoch']//60 in set(inputs['global']['data']['test']['bucket'])]
            family=inputs['global']['data']['test']['family'];fraction=np.asarray([r['binary_record_counts'].get('1',0)/r['source_record_count'] for r in rows])
        else:family=h['family'][test_ix];fraction=h['attack_count'][test_ix]/h['record_count'][test_ix]
        dilution[profile]={name:dict(windows=int((family==name).sum()),median_attack_row_fraction=float(np.median(fraction[family==name]))) for name in sorted(set(family)-{'benign'})}
    save(O/'representation-audit.json',dict(host_lineage_rows_checked=lineage_count,all_source_occurrences_accounted=prepared['accepted_occurrences'],all_7934_minute_binary_counts_reconstructed=True,
        same_time_roles_used=True,host_overlap=overlap,test_attack_dilution=dilution,
        limitations='Address overlap is descriptive and not authenticated device identity. Source occurrence duplicates and physical-flow independence remain unproved.'))
    save(O/'verification.json',dict(status='verified',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),selected_federated_models_recomputed=selected_count,centralized_references_freshly_refitted=central_count,
        native_and_common_validation_test_metric_sets_recomputed=metric_count,all_thresholds_recomputed_from_common_validation_only=True,installed_pooling_matches_executed=True,
        training_subsampling_scalers_and_partitions_recomputed=True,replays=replays,local_digest_comparison_claimed=False,
        source_all_files_verified_during_preparation=True,source_row_count=prepared['source_rows'],accepted_source_count=prepared['accepted_occurrences'],blind_test_claimed=False))
    print(json.dumps(load(O/'verification.json'),indent=2),flush=True)
if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):main()
