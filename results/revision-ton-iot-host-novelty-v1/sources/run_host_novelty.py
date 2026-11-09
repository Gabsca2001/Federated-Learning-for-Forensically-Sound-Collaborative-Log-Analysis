"""Finite benign-reference novelty study on the fixed chronological host roles."""
from pathlib import Path
import sys,datetime as dt,hashlib,json,time,shutil,platform
import numpy as np
import sklearn
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest
from threadpoolctl import threadpool_limits
from fl_forensics.preprocessing import FEATURE_NAMES
from fl_forensics.robust_preprocessing import fit_feature_transform,apply_feature_transform
from fl_forensics.ton_iot_calibration import metrics
from novelty_rules import calibrate_benign_threshold,anomaly_flags,combine_flags,minute_alert_support

O=Path(__file__).resolve().parent;P=O.parent/'ton-iot-host-20261109';D=O/'study'
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
sys.path.insert(0,str(P))
import run_host_study as parent

DETECTORS=('knn','isolation');BUDGETS=(.01,.05);SEEDS=(341593,342593,343593)
def load(p):return json.loads(p.read_text())
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def score(model,kind,x):
    if kind=='knn':return model.kneighbors(x,return_distance=True)[0].mean(axis=1).astype(np.float64)
    return -model.score_samples(x)
def detector(kind):
    if kind=='knn':return NearestNeighbors(n_neighbors=5,algorithm='brute',n_jobs=1)
    if kind=='isolation':return IsolationForest(n_estimators=256,max_samples=256,contamination='auto',n_jobs=1,random_state=341593)
    raise ValueError('Unknown detector')
def decision_quality(labels,flags,families):
    flags=np.asarray(flags,dtype=bool);q=metrics(labels,flags.astype(float))
    for key in ('auroc','average_precision','threshold'):q.pop(key,None)
    q['decision']='Supplied binary alert; no probability or ranking metric claimed'
    q['attack_family_recall']={name:dict(windows=int((families==name).sum()),detected=int(flags[families==name].sum()),recall=float(flags[families==name].mean())) for name in sorted(set(families)-{'benign'})}
    return q
def evaluate(data,flags):
    support=minute_alert_support(data['bucket'],data['y'],np.asarray(flags,dtype=np.int8))
    np.testing.assert_array_equal(support['bucket'],data['common_bucket']);np.testing.assert_array_equal(support['actual'],data['common_y'].astype(bool))
    localization={}
    for name in sorted(set(data['common_family'])-{'benign'}):
        ix=data['common_family']==name;n=int(ix.sum());any_alert=int(support['any_alert'][ix].sum());attacked=int(support['attacked_host_alert'][ix].sum());benign_only=int(support['benign_host_only_coincidence'][ix].sum())
        localization[name]=dict(attack_minutes=n,any_host_alert_minutes=any_alert,attacked_host_alert_minutes=attacked,benign_host_only_alert_minutes=benign_only,any_host_recall=any_alert/n,attacked_host_supported_recall=attacked/n)
    return dict(native=decision_quality(data['y'],flags,data['family']),common=decision_quality(data['common_y'],support['any_alert'],data['common_family']),localization=localization)
def prepare():
    assert load(P/'verification.json')['status']=='verified'
    inputs,notes=parent.prepare_inputs();frozen=load(P/'study/protocol-before-fitting.json')
    assert notes==frozen['input_notes'];info=inputs['host'];data=info['data']
    pool=info['train_indices'][data['train']['y'][info['train_indices']]==0]
    rng=np.random.default_rng(341593);chosen=np.sort(pool[rng.permutation(len(pool))[:10000]])
    assert not data['train']['y'][chosen].any()
    specification=fit_feature_transform(train_features=data['train']['raw'][chosen],feature_names=FEATURE_NAMES,mode='log1p')
    x={role:np.round(apply_feature_transform(features=d['raw'],feature_names=FEATURE_NAMES,specification=specification),12).astype(np.float32) for role,d in data.items()}
    return data,chosen,specification,x
def main():
    assert not D.exists();assert shutil.disk_usage(O).free>=6*1024**3;D.mkdir()
    data,chosen,specification,x=prepare();baseline_entries=[e for e in load(P/'study/closure-before-test.json')['entries'] if e['scope']=='federated' and e['profile']=='host']
    assert [e['seed'] for e in baseline_entries]==list(SEEDS)
    parent_checks=load(R/'results/revision-ton-iot-host-windows-v1/file-checksums.json')
    base_val={}
    for entry in baseline_entries:
        path=P/'study'/(entry['id']+'-validation.npz');assert sha(path)==parent_checks['study/'+path.name]
        with np.load(path,allow_pickle=False) as saved:
            np.testing.assert_array_equal(saved['actual'],data['validation']['y']);np.testing.assert_array_equal(saved['bucket'],data['validation']['bucket'])
            base_val[entry['id']]=anomaly_flags(saved['score'],entry['threshold'])
    protocol=dict(name='ToN-IoT-chronological-host-benign-novelty-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        question='Can benign-reference novelty improve attacked-host MITM detection without hiding false alerts behind minute coincidence?',
        primary='One-percent empirical native-benign validation budget; compare native macro-F1/class F1/FPR and attacked-host-supported family detection. Keep the same 718-minute compatibility check.',
        secondary='Five-percent empirical benign calibration budget is a predeclared sensitivity, never selected from test results.',
        detectors=dict(knn='Mean Euclidean distance to five training benign neighbors; brute force,one thread',isolation='IsolationForest256,max_samples256,random_state341593,one thread; negative score_samples'),
        budgets=list(BUDGETS),primary_budget=.01,detector_fit='Only the deterministic at-most10000 benign subset of the parent selected training sample. No attacked row used to fit detectors or their scaler.',
        benign_training_indices=chosen.tolist(),benign_training_units=len(chosen),trusted_labels_required=True,
        normalization='Original25 numeric features; log1p and standard scaler fitted only on selected benign training units. Separate from unchanged classifier scaler.',
        calibration='Strict raw anomaly score > order statistic of native benign validation scores; floor(alpha*n) allowed calibration false alerts, indivisible score ties.',
        combination='Original fixed selected classifier flag OR novelty flag on the same host/minute unit; combined FPR is not bounded by the novelty-component budget.',
        selection='At the primary1% budget, choose detector by mean combined native validation macro-F1 over the three fixed parent classifier seeds; ties prefer declared detector order. Keep all methods,budgets,seeds and standalone controls. No test-based promotion or budget choice.',
        scopes='Detectors are centralized numerical diagnostics requiring a trusted benign reference pool, not a federated private implementation, Byzantine-update detector or malicious-intent proof.',
        unchanged_roles='All corrected parent host roles and common minute inventories retained; no MITM fitting/calibration examples; all validation/test units scored.',
        test_reuse='Already examined dates and host/minute targets; exploratory extension, not a fresh blind test or guaranteed future false-positive control.',
        parent_protocol_sha256=sha(P/'study/protocol-before-fitting.json'),parent_closure_sha256=sha(P/'study/closure-before-test.json'),parent_preparation_sha256=sha(P/'windows/preparation-summary.json'),
        parent_publication_index_sha256=sha(R/'results/revision-ton-iot-host-windows-v1/file-checksums.json'),
        baseline_score_hashes={entry['id']:{role:parent_checks['study/'+entry['id']+'-'+role+'.npz'] for role in ('validation','test')} for entry in baseline_entries},
        baseline_models=[dict(id=e['id'],seed=e['seed'],threshold=e['threshold'],tensor_sha256=e['tensor_sha256'],selected_round=e['selected_round']) for e in baseline_entries],
        runner_sha256=sha(Path(__file__)),rule_module_sha256=sha(O/'novelty_rules.py'),source_csv_copies_created=False,
        environment=dict(python=platform.python_version(),numpy=np.__version__,sklearn=sklearn.__version__))
    save(D/'protocol-before-detector-fitting.json',protocol);save(D/'benign-transform.json',specification)
    entries=[];objects={};calibration={};validation_scores={};timings={}
    for base in baseline_entries:
        entries.append(dict(id='classifier-'+str(base['seed']),kind='classifier',detector=None,budget=None,seed=base['seed'],parent_id=base['id'],validation=evaluate(data['validation'],base_val[base['id']])))
    for kind in DETECTORS:
        model=detector(kind);start=time.monotonic();model.fit(x['train'][chosen]);fit_time=time.monotonic()-start
        start=time.monotonic();values=score(model,kind,x['validation']);score_time=time.monotonic()-start
        if not np.isfinite(values).all():raise ValueError('Nonfinite anomaly scores')
        objects[kind]=model;validation_scores[kind]=values;timings[kind]=dict(fit_seconds=fit_time,validation_score_seconds=score_time)
        np.savez_compressed(D/(kind+'-validation.npz'),score=values,actual=data['validation']['y'],bucket=data['validation']['bucket'],family=data['validation']['family'])
        for budget in BUDGETS:
            fitted=calibrate_benign_threshold(values[data['validation']['y']==0],budget);calibration[(kind,budget)]=fitted
            flags=anomaly_flags(values,fitted['threshold']);suffix=f'{int(budget*100):02d}pct'
            entries.append(dict(id=f'{kind}-standalone-{suffix}',kind='standalone',detector=kind,budget=budget,seed=None,parent_id=None,calibration=fitted,validation=evaluate(data['validation'],flags)))
            for base in baseline_entries:
                predicted=combine_flags(base_val[base['id']],flags)
                entries.append(dict(id=f'{kind}-combined-{suffix}-s{base["seed"]}',kind='combined',detector=kind,budget=budget,seed=base['seed'],parent_id=base['id'],calibration=fitted,validation=evaluate(data['validation'],predicted)))
        print(json.dumps(dict(status='detector_closed',detector=kind,benign_fit_units=len(chosen),calibration=[calibration[(kind,b)] for b in BUDGETS],timings=timings[kind])),flush=True)
    val_means={kind:float(np.mean([e['validation']['native']['macro_f1'] for e in entries if e['kind']=='combined' and e['detector']==kind and e['budget']==.01])) for kind in DETECTORS}
    selected=max(DETECTORS,key=lambda kind:(val_means[kind],-DETECTORS.index(kind)))
    save(D/'closure-before-test.json',dict(protocol_sha256=sha(D/'protocol-before-detector-fitting.json'),entries=entries,detector_fit_timings=timings,validation_primary_macro_f1=val_means,selected_primary_detector=selected,test_used_for_choices=False))
    test_scores={};base_test={}
    for base in baseline_entries:
        path=P/'study'/(base['id']+'-test.npz');assert sha(path)==parent_checks['study/'+path.name]
        with np.load(path,allow_pickle=False) as saved:
            np.testing.assert_array_equal(saved['actual'],data['test']['y']);np.testing.assert_array_equal(saved['bucket'],data['test']['bucket'])
            base_test[base['id']]=anomaly_flags(saved['score'],base['threshold'])
    for kind,model in objects.items():
        start=time.monotonic();values=score(model,kind,x['test']);timings[kind]['test_score_seconds']=time.monotonic()-start;test_scores[kind]=values
        np.savez_compressed(D/(kind+'-test.npz'),score=values,actual=data['test']['y'],bucket=data['test']['bucket'],family=data['test']['family'])
    results=[]
    for entry in entries:
        if entry['kind']=='classifier':predicted=base_test[entry['parent_id']]
        else:
            novelty=anomaly_flags(test_scores[entry['detector']],entry['calibration']['threshold'])
            predicted=novelty if entry['kind']=='standalone' else combine_flags(base_test[entry['parent_id']],novelty)
        np.savez_compressed(D/(entry['id']+'-decisions.npz'),predicted=predicted)
        extra={}
        if entry['kind']=='combined':
            new=predicted&~base_test[entry['parent_id']]
            extra=dict(additional_native_true_positives=int((new&(data['test']['y']==1)).sum()),additional_native_false_positives=int((new&(data['test']['y']==0)).sum()),additional_mitm_native_detections=int((new&(data['test']['family']=='mitm')).sum()))
        results.append(dict(**entry,test=evaluate(data['test'],predicted),selected_primary=(entry['kind']=='combined' and entry['budget']==.01 and entry['detector']==selected),**extra))
    save(D/'results.json',dict(status='complete',protocol_sha256=sha(D/'protocol-before-detector-fitting.json'),closure_sha256=sha(D/'closure-before-test.json'),selected_primary_detector=selected,results=results,detector_timings=timings,framework_default_changed=False,new_blind_test_claimed=False))
    report=[dict(id=e['id'],selected=e['selected_primary'],native_macro_f1=e['test']['native']['macro_f1'],native_benign_fpr=e['test']['native']['false_positive_rate'],mitm_native=e['test']['native']['attack_family_recall']['mitm'],common_macro_f1=e['test']['common']['macro_f1'],mitm_supported=e['test']['localization']['mitm']) for e in results]
    print(json.dumps(dict(status='host_novelty_complete',selected_detector=selected,validation_means=val_means,results=report),indent=2),flush=True)
if __name__=='__main__':
    with threadpool_limits(limits=1):main()
