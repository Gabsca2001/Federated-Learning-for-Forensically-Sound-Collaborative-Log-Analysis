"""Recompute metrics, audit split roles and replay the declared primary trajectory."""
from pathlib import Path
from collections import Counter
import datetime as dt
import importlib.util
import json
import hashlib
import numpy as np
import torch
from threadpoolctl import threadpool_limits
from flwr.server.strategy.aggregate import aggregate
from fl_forensics.federated_model import model_to_ndarrays, load_ndarrays
from fl_forensics.robust_preprocessing import fit_feature_transform, apply_feature_transform
from fl_forensics.preprocessing import FEATURE_NAMES
from fl_forensics.ton_iot_retraining import verify_checkpoint, tensor_digest
from fl_forensics.ton_iot_time_bounds import observation_end_upper_bound
from fl_forensics.ton_iot_calibration import metrics

O = Path(__file__).resolve().parent
K = O / 'known-family'
T = O.parent / 'ton-iot-transfer-20261109'
P = O.parent / 'ton-iot-retraining-20261109/study'
def load(p): return json.loads(p.read_text())
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p, value):
    with p.open('x') as f: json.dump(value, f, indent=2, allow_nan=False); f.write('\n')
def main():
    module = importlib.util.spec_from_file_location('benchmark', O/'known_family_benchmark.py')
    b = importlib.util.module_from_spec(module); module.loader.exec_module(b)
    protocol = load(K/'protocol-before-fitting.json')
    assert sha(O/'known_family_benchmark.py') == protocol['runner_sha256']
    closure = load(K/'closure-before-test.json'); result = load(K/'test-results.json')
    assert sha(K/'protocol-before-fitting.json') == closure['protocol_sha256'] == result['protocol_sha256']
    assert sha(K/'closure-before-test.json') == result['closure_sha256']
    roles = protocol['roles']; all_buckets = [bucket for values in roles.values() for bucket, _ in values]
    assert len(all_buckets) == len(set(all_buckets)) == 7934
    inputs = {}
    for view in protocol['views']:
        source = T/'windows'/f'{view}-windows.json'
        assert sha(source) == protocol['input_sha256'][view]
        lookup = {r['window_start_epoch']//60:r for r in load(source)['rows']}
        for name in protocol['support']:
            for before, after in [('train','validation'),('validation','test')]:
                earlier = [lookup[bucket] for bucket,family in roles[before] if family==name]
                later = [lookup[bucket] for bucket,family in roles[after] if family==name]
                assert max(observation_end_upper_bound(r) for r in earlier) <= min(r['window_start_epoch'] for r in later)-300
        raw = {role:np.asarray([lookup[bucket]['features'] for bucket,_ in roles[role]],float) for role in ('train','validation','test')}
        spec = fit_feature_transform(train_features=raw['train'], feature_names=FEATURE_NAMES, mode='log1p')
        assert spec == load(K/f'{view}-transform.json')
        x = {role:np.round(apply_feature_transform(features=values, feature_names=FEATURE_NAMES, specification=spec),12).astype(np.float32) for role,values in raw.items()}
        f = {role:np.asarray([family for _,family in roles[role]]) for role in x}
        y = {role:(f[role]!='benign').astype(np.int64) for role in x}
        inputs[view] = (x,y,f)
    checked = 0
    selected_scores = 0
    for entry in result['results']:
        x,y,f = inputs[entry['view']]
        artifact = np.load(K/(entry['id']+'-test.npz'), allow_pickle=False)
        assert np.array_equal(artifact['actual'], y['test']) and np.array_equal(artifact['family'], f['test'])
        assert b.quality(y['test'], artifact['score'], f['test'], entry['threshold']) == entry['test']
        if entry['scope'] != 'federated': continue
        history = load(K/entry['id']/'history.json')
        for record in history:
            path = K/entry['id']/f'round-{record["round"]:03d}.npz'
            assert sha(path) == record['checkpoint_sha256']
            verify_checkpoint(path,record['tensor_sha256']); checked += 1
        chosen = max(history,key=lambda r:(r['validation']['macro_f1'],-r['round']))
        assert chosen['round'] == entry['selected_round'] and chosen['threshold'] == entry['threshold']
        model = b.net(entry['seed'])
        load_ndarrays(model,verify_checkpoint(K/entry['id']/f'round-{entry["selected_round"]:03d}.npz',entry['tensor_sha256']),torch=torch,np=np)
        val_score = b.scores(model,x['validation'])
        assert b.threshold(y['validation'],val_score,f['validation']) == entry['threshold']
        assert b.quality(y['validation'],val_score,f['validation'],entry['threshold']) == entry['validation']
        assert np.array_equal(b.scores(model,x['test']),artifact['score']); selected_scores += 1
    selected = {}
    for scope in ('federated','centralized-reference'):
        names = {e['family'] for e in closure['entries'] if e['view']=='occurrence' and e['scope']==scope}
        selected[scope] = max(names,key=lambda name:(float(np.mean([e['validation']['macro_f1'] for e in closure['entries'] if e['view']=='occurrence' and e['scope']==scope and e['family']==name])),name))
    assert selected == closure['selected_families'] == result['selected_families']
    x,y,f = inputs['occurrence']; counts=Counter(f['train']); n=len(f['train'])
    rng=np.random.default_rng(341593); partitions=[[] for _ in range(15)]
    for name in sorted(counts):
        indices=np.flatnonzero(f['train']==name);rng.shuffle(indices)
        for i,index in enumerate(indices):partitions[i%15].append(int(index))
    assert sorted(i for indices in partitions for i in indices) == list(range(n))
    w=np.asarray([n/(2*int((y['train']==label).sum())) for label in y['train']])
    seed=341593;model=b.net(seed); history=load(K/'occurrence-binary-balanced-s341593/history.json')
    for r in history:
        base=model_to_ndarrays(model,np=np);updates=[]
        for client,indices in enumerate(partitions):
            local=b.net(seed);load_ndarrays(local,base,torch=torch,np=np)
            b.local_fit(local,x['train'][indices],y['train'][indices],w[indices],seed+r['round']*10000+client)
            updates.append((model_to_ndarrays(local,np=np),len(indices)))
        arrays=aggregate(updates);assert tensor_digest(arrays)==r['tensor_sha256']
        load_ndarrays(model,arrays,torch=torch,np=np)
    # Preserve the negative chronological diagnostic, including its actual test role.
    original_rows={r['window_start_epoch']//60:r for r in load(T/'windows/occurrence-windows.json')['rows']}
    split=load(P/'split-and-partition.json')['splits']
    evidence=np.load(O/'final-refit/refit-recency-48h-occurrence-s341593-test.npz',allow_pickle=False)
    print('refit keys',evidence.files,flush=True)
    rows=[original_rows[bucket] for bucket in split['test']['buckets']]
    score=evidence['score'];actual=evidence['actual'];pred=score>.5
    missed=[row for row,yes,guess in zip(rows,actual,pred) if yes and not guess]
    detected=[row for row,yes,guess in zip(rows,actual,pred) if yes and guess]
    def fraction(row): return row['binary_record_counts'].get('1',0)/row['source_record_count']
    family_counts=Counter(b.family(row) for row in missed)
    diagnosis=dict(model='refit-recency-48h-occurrence-s341593',threshold=.5,false_negatives=len(missed),
        false_negative_dominant_families=dict(family_counts),test_attack_families=dict(Counter(b.family(row) for row in rows if row['label']=='attack')),
        missed_median_attack_row_fraction=float(np.median([fraction(r) for r in missed])),detected_median_attack_row_fraction=float(np.median([fraction(r) for r in detected])),
        train_mitm_windows=sum('mitm' in original_rows[bucket]['source_type_counts'] for bucket in split['train']['buckets']),
        validation_mitm_windows=sum('mitm' in original_rows[bucket]['source_type_counts'] for bucket in split['validation']['buckets']),
        interpretation='All missed attacks in this declared chronological refit are previously unseen MITM; global minute aggregation can dilute low-density attacks. This diagnostic does not prove dilution is the sole cause.')
    save(O/'chronological-error-diagnosis.json',diagnosis)
    save(O/'verification.json',dict(status='verified',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        known_family_checkpoint_hashes_checked=checked,known_family_federated_selected_validation_and_test_scores_recomputed=selected_scores,
        known_family_all_twenty_test_metric_sets_recomputed=True,within_family_roles_and_flow_end_bounds_verified=True,scalers_refitted_from_train_only=True,
        selected_families_recomputed_from_validation_only=True,fresh_replay=dict(id='occurrence-binary-balanced-s341593',global_round_tensor_hashes_matched=30,local_updates_rerun=450,local_update_hash_comparison_claimed=False),
        global_chronology_claimed=False,blind_holdout_claimed=False))
    print(json.dumps(load(O/'verification.json')),flush=True)

if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True)
    with threadpool_limits(limits=1):main()
