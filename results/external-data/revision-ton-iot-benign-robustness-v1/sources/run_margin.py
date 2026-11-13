"""Evaluate a declared threshold-margin rule on fixed, selected parent models."""
from pathlib import Path
import importlib.util,json,hashlib,datetime as dt
import numpy as np
import torch
from fl_forensics.federated_model import load_ndarrays
from fl_forensics.preprocessing import FEATURE_NAMES
from fl_forensics.robust_preprocessing import apply_feature_transform
from fl_forensics.ton_iot_retraining import verify_checkpoint
from fl_forensics.ton_iot_calibration import metrics
from threshold_margin import center_validation_plateau

O=Path(__file__).resolve().parent
P=O.parent/'ton-iot-f1-study-20261109'
K=P/'known-family'
T=O.parent/'ton-iot-transfer-20261109/windows'
def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def quality(y,s,f,t):
    s=np.asarray(s,dtype=np.float64);q=metrics(y,s,t)
    q['attack_family_recall']={n:dict(windows=int((f==n).sum()),recall=float((s[f==n]>t).mean())) for n in sorted(set(f)-{'benign'})}
    return q
def main():
    D=O/'margin';assert not D.exists();D.mkdir()
    save(D/'protocol-before-validation.json',dict(name='ToN-IoT-validation-plateau-centering-v1',created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        parent_closure_sha256=sha(K/'closure-before-test.json'),
        primary='Center the validation decision gap of the already-selected binary-balanced federated parent checkpoints; no checkpoint or model selection changes.',
        controls=['Original threshold','Fixed threshold 0.5'],
        selection='No test-based selection among these three rules. Midpoint is the declared primary intervention; all views and seeds retained.',
        limitations='Same previously examined known-family test; retrospective exploratory extension, globally interleaved dates, no operational claim.',
        runner_sha256=sha(Path(__file__)),rule_sha256=sha(O/'threshold_margin.py')))
    module=importlib.util.spec_from_file_location('parent',P/'known_family_benchmark.py');b=importlib.util.module_from_spec(module);module.loader.exec_module(b)
    roles=load(K/'protocol-before-fitting.json')['roles'];entries=[];cache={}
    for view in ('occurrence','exact-projection'):
        lookup={r['window_start_epoch']//60:r for r in load(T/f'{view}-windows.json')['rows']}
        spec=load(K/f'{view}-transform.json')
        raw=np.asarray([lookup[bucket]['features'] for bucket,_ in roles['validation']])
        xv=np.round(apply_feature_transform(features=raw,feature_names=FEATURE_NAMES,specification=spec),12).astype(np.float32)
        fv=np.asarray([f for _,f in roles['validation']]);yv=(fv!='benign').astype(int)
        for parent in load(K/'closure-before-test.json')['entries']:
            if parent['scope']!='federated' or parent['family']!='binary-balanced' or parent['view']!=view:continue
            model=b.net(parent['seed']);load_ndarrays(model,verify_checkpoint(K/parent['id']/f'round-{parent["selected_round"]:03d}.npz',parent['tensor_sha256']),torch=torch,np=np)
            vs=b.scores(model,xv).astype(np.float64)
            margin=center_validation_plateau(vs,parent['threshold'])
            candidates={'original':parent['threshold'],'midpoint':margin['threshold'],'fixed-0.5':.5}
            fitted=dict(id=parent['id'],view=view,seed=parent['seed'],margin=margin,
                thresholds=candidates,validation={name:quality(yv,vs,fv,t) for name,t in candidates.items()})
            assert fitted['validation']['original']['confusion_matrix']==fitted['validation']['midpoint']['confusion_matrix']
            entries.append(fitted);cache[parent['id']]=vs
            np.savez_compressed(D/(parent['id']+'-validation.npz'),actual=yv,score=vs,family=fv)
    save(D/'closure-before-scoring.json',dict(protocol_sha256=sha(D/'protocol-before-validation.json'),entries=entries,test_used_for_new_thresholds=False))
    results=[]
    for entry in entries:
        artifact=np.load(K/(entry['id']+'-test.npz'),allow_pickle=False)
        results.append(dict(**entry,test={name:quality(artifact['actual'],artifact['score'],artifact['family'],t) for name,t in entry['thresholds'].items()}))
    save(D/'results.json',dict(status='complete',closure_sha256=sha(D/'closure-before-scoring.json'),results=results,primary='midpoint'))
    print(json.dumps([dict(id=r['id'],gap=r['margin'],test={name:{k:q[k] for k in ('macro_f1','benign_f1','attack_f1','false_positive_rate','attack_recall')} for name,q in r['test'].items()}) for r in results],indent=2),flush=True)
if __name__=='__main__':
    torch.set_num_threads(1);torch.use_deterministic_algorithms(True);main()
