"""Benign-reference novelty probes for the observed unseen-family failure.

The test remains a known exploratory assessment. No MITM test row is used to
fit a detector or its threshold.
"""
from pathlib import Path
import datetime as dt,hashlib,json
from collections import defaultdict
import numpy as np
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from threadpoolctl import threadpool_limits
from fl_forensics.ton_iot_calibration import metrics

O=Path(__file__).resolve().parent;S=O/'study';P=O.parent/'ton-iot-retraining-20261109/study';N=O/'novelty-probe'
def load(path):return json.loads(path.read_text())
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def save(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2,allow_nan=False);stream.write('\n')
def anomaly(model,kind,x):
    if kind=='knn':return model.kneighbors(x,return_distance=True)[0].mean(axis=1)
    if kind=='isolation':return -model.score_samples(x)
    return -model.decision_function(x)


def main():
    assert not N.exists();N.mkdir()
    old=load(S/'selection-and-calibration-closure-before-test.json');keep=load(P/'flow-end-selection-v2/protocol-before-reselection.json')['retained_validation_indices']
    protocol=dict(name='ToN-IoT-benign-reference-novelty-probe-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                  motivation='Previously observed false negatives concentrate in MITM, absent from training and validation. Probe benign-reference novelty without fitting any MITM test record.',
                  detectors=['5-neighbor mean distance','IsolationForest 256 trees /256 samples','OneClassSVM RBF nu=.02 gamma=scale'],
                  feature_views=['all 25 target-log1p inputs','15 protocol/service/state fractions'],
                  fit='Only original training rows with benign label; original training-only preprocessing reused.',
                  threshold='Strict anomaly score > maximum among the 85 corrected benign validation scores: zero empirical novelty false positives on calibration normals.',
                  combination='Validation-selected parent federated classifier OR benign-reference novelty flag.',
                  family_selection='Mean corrected-validation macro-F1 over three parent seeds in the occurrence view; stable lexical tie. All six probes, both views and all seeds reported.',
                  parent_selected_family=old['selected_families']['federated'],
                  scope='Post-test-motivated exploratory open-family probe, not a new blind test or conformal coverage guarantee.',
                  runner_sha256=sha(Path(__file__)),parent_closure_sha256=sha(S/'selection-and-calibration-closure-before-test.json'),test_used_for_fitting=False)
    assert protocol['parent_selected_family']=='fedavg-legacy-source-standard'
    save(N/'protocol-before-fitting.json',protocol)
    fitted={};entries=[];family_values=defaultdict(list)
    for view in ('occurrence','exact-projection'):
        with np.load(P/'prepared'/(view+'-target-log1p')/'train-validation.npz',allow_pickle=False) as d:
            x=d['x_train'];y=d['y_train'];xv=d['x_validation'][keep];yv=d['y_validation'][keep]
        for feature_view,indices in [('full',list(range(25))),('fractions',list(range(10,25)))]:
            normal=x[y==0][:,indices]
            detectors=dict(knn=NearestNeighbors(n_neighbors=5,n_jobs=1),
                           isolation=IsolationForest(n_estimators=256,max_samples=256,contamination='auto',n_jobs=1,random_state=341593),
                           oneclass=OneClassSVM(kernel='rbf',nu=.02,gamma='scale',cache_size=128))
            for kind,model in detectors.items():
                model.fit(normal);values=anomaly(model,kind,xv[:,indices]);threshold=float(values[yv==0].max())
                family=kind+'-'+feature_view;fitted[(view,family)]=(model,kind,indices,threshold)
                for seed in (341593,342593,343593):
                    parent_id=f'legacy-{view}-source-standard-s{seed}';base=next(r for r in old['candidates'] if r['id']==parent_id)
                    with np.load(S/(parent_id+'-validation.npz'),allow_pickle=False) as base_values:
                        assert np.array_equal(yv,base_values['actual']);base_pred=base_values['score']>base['threshold']
                    predicted=base_pred|(values>threshold);quality=metrics(yv,predicted.astype(float))
                    entry=dict(view=view,family=family,seed=seed,parent_id=parent_id,threshold=threshold,
                               validation=quality,novelty_validation_false_positives=int(((values>threshold)&(yv==0)).sum()))
                    entries.append(entry)
                    if view=='occurrence':family_values[family].append(quality['macro_f1'])
    selected=max(family_values,key=lambda family:(float(np.mean(family_values[family])),family))
    save(N/'closure-before-test.json',dict(protocol_sha256=sha(N/'protocol-before-fitting.json'),entries=entries,selected_family=selected,test_used_for_choices=False))
    results=[]
    for entry in entries:
        view=entry['view'];model,kind,indices,threshold=fitted[(view,entry['family'])]
        with np.load(P/'prepared'/(view+'-target-log1p')/'test.npz',allow_pickle=False) as d:x,y=d['x'],d['y']
        values=anomaly(model,kind,x[:,indices])
        with np.load(S/(entry['parent_id']+'-test.npz'),allow_pickle=False) as base_values:
            assert np.array_equal(y,base_values['actual'])
            base=next(r for r in old['candidates'] if r['id']==entry['parent_id']);base_pred=base_values['score']>base['threshold']
        predicted=base_pred|(values>threshold)
        results.append(dict(**entry,test=metrics(y,predicted.astype(float)),novelty_alone=metrics(y,(values>threshold).astype(float)),
                            selected=entry['family']==selected,novelty_new_test_flags=int(((values>threshold)&~base_pred).sum())))
    save(N/'test-results.json',dict(status='novelty_probe_complete',selected_family=selected,results=results,
         protocol_sha256=sha(N/'protocol-before-fitting.json'),closure_sha256=sha(N/'closure-before-test.json'),blind_test_claimed=False))
    print(json.dumps(dict(selected_family=selected,primary_selected=[(r['seed'],r['test']['macro_f1'],r['test']['confusion_matrix']['values']) for r in results if r['view']=='occurrence' and r['selected']]),indent=2),flush=True)


if __name__=='__main__':
    with threadpool_limits(limits=1):main()
