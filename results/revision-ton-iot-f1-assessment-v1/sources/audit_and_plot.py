"""Audit the earlier negative controls and produce explicitly scoped figures."""
from pathlib import Path
from collections import Counter
import json, hashlib, importlib.util
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from fl_forensics.ton_iot_calibration import fit_macro_threshold, metrics
from fl_forensics.ton_iot_retraining import verify_checkpoint
from fl_forensics.robust_preprocessing import apply_feature_transform
from fl_forensics.preprocessing import FEATURE_NAMES
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from threadpoolctl import threadpool_limits

O=Path(__file__).resolve().parent
def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):
    with p.open('x') as f:json.dump(v,f,indent=2,allow_nan=False);f.write('\n')
def main():
    counts={};checkpoint_count=0
    result=load(O/'study/test-results.json')
    for entry in result['results']:
        val=np.load(O/'study'/(entry['id']+'-validation.npz'),allow_pickle=False)
        test=np.load(O/'study'/(entry['id']+'-test.npz'),allow_pickle=False)
        fitted=fit_macro_threshold(val['actual'],val['score'])
        assert fitted['threshold']==entry['threshold']
        assert fitted['validation']==entry['validation']
        assert metrics(test['actual'],test['score'],entry['threshold'])==entry['test']
    counts['calibration_validation_thresholds_and_test_metric_sets']=len(result['results'])
    for parent in ('study','final-refit'):
        for path in (O/parent).glob('*/history.json'):
            for record in load(path):
                checkpoint=path.parent/f'round-{record["round"]:03d}.npz'
                assert sha(checkpoint)==record['checkpoint_sha256']
                verify_checkpoint(checkpoint,record['tensor_sha256']);checkpoint_count+=1
    counts['additional_negative_control_checkpoint_hashes_checked']=checkpoint_count
    for entry in load(O/'final-refit/test-results.json')['results']:
        test=np.load(O/'final-refit'/(entry['id']+'-test.npz'),allow_pickle=False)
        assert metrics(test['actual'],test['score'],.5)==entry['test']
    counts['refit_test_metric_sets']=16
    # Quantify repeated predictor vectors; this is not physical connection identity.
    protocol=load(O/'known-family/protocol-before-fitting.json');repetitions={};classic=0
    for view in protocol['views']:
        data=load(O.parent/'ton-iot-transfer-20261109/windows'/f'{view}-windows.json')
        lookup={r['window_start_epoch']//60:r for r in data['rows']}
        vectors={role:[tuple(lookup[b]['features']) for b,_ in protocol['roles'][role]] for role in ('train','validation','test')}
        earlier=set(vectors['train'])|set(vectors['validation'])
        repetitions[view]=dict(test_vectors_seen_in_train=sum(v in set(vectors['train']) for v in vectors['test']),
                               test_vectors_seen_in_train_or_validation=sum(v in earlier for v in vectors['test']))
        x={role:np.asarray(vectors[role],float) for role in vectors}
        f={role:np.asarray([name for _,name in protocol['roles'][role]]) for role in vectors}
        y={role:(f[role]!='benign').astype(int) for role in vectors}
        spec=load(O/'known-family'/f'{view}-transform.json')
        x={role:np.round(apply_feature_transform(features=v,feature_names=FEATURE_NAMES,specification=spec),12).astype(np.float32) for role,v in x.items()}
        n=len(y['train']);support=Counter(f['train'])
        for entry in load(O/'known-family/test-results.json')['results']:
            if entry['scope']!='centralized-reference' or entry['view']!=view:continue
            if entry['family'].endswith('family-balanced'):w=np.asarray([n/(2*support[name]*(1 if name=='benign' else 9)) for name in f['train']])
            else:w=np.asarray([n/(2*int((y['train']==label).sum())) for label in y['train']])
            if entry['family'].startswith('extra-trees'):model=ExtraTreesClassifier(n_estimators=256,min_samples_leaf=2,max_features=1.,n_jobs=1,random_state=341593)
            else:model=HistGradientBoostingClassifier(max_iter=150,learning_rate=.05,max_leaf_nodes=15,l2_regularization=1.,early_stopping=False,random_state=341593)
            model.fit(x['train'],y['train'],sample_weight=w)
            test=np.load(O/'known-family'/(entry['id']+'-test.npz'),allow_pickle=False)
            assert np.array_equal(model.predict_proba(x['test'])[:,1],test['score']);classic+=1
    counts['known_family_centralized_references_freshly_refitted']=classic
    save(O/'additional-audit.json',dict(status='verified',checks=counts,known_family_exact_predictor_vector_repetitions=repetitions,
         limitation='Identical vectors and physical flow identity differ; same laboratory hosts and globally interleaved family dates prevent a deployment independence claim.'))
    results=load(O/'known-family/test-results.json')['results']
    primary=[r for r in results if r['selected_family'] and r['view']=='occurrence' and r['scope']=='federated']
    summary={k:dict(mean=float(np.mean([r['test'][k] for r in primary])),minimum=float(min(r['test'][k] for r in primary)),maximum=float(max(r['test'][k] for r in primary))) for k in ('macro_f1','benign_f1','attack_f1','attack_recall','false_positive_rate','balanced_accuracy','accuracy')}
    summary.update(protocol='Separate known-family blocked offline benchmark; NOT a replacement for chronological unseen-family evaluation.',
                   split_counts={role:len(protocol['roles'][role]) for role in protocol['roles']},
                   primary_family=load(O/'known-family/test-results.json')['selected_families']['federated'],
                   primary_seed_results=[dict(id=r['id'],selected_round=r['selected_round'],threshold=r['threshold'],test=r['test']) for r in primary])
    save(O/'summary.json',summary)
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False})
    fig,axs=plt.subplots(1,2,figsize=(11,4.5),layout='constrained')
    names=['Macro-F1','Benign F1','Attack F1','False-positive rate'];keys=['macro_f1','benign_f1','attack_f1','false_positive_rate']
    for offset,r in enumerate(primary):axs[0].bar(np.arange(4)+(offset-1)*.24,[r['test'][k] for k in keys],width=.23,label=f'Seed {r["seed"]}')
    axs[0].set(xticks=np.arange(4),xticklabels=names,ylim=(0,1.06),title='Known-family test: all three federated seeds')
    axs[0].tick_params(axis='x',labelrotation=15);axs[0].legend(fontsize=8)
    families=list(primary[0]['test']['attack_family_recall'])
    for r in primary:axs[1].plot(families,[r['test']['attack_family_recall'][name]['recall'] for name in families],marker='o',label=str(r['seed']))
    axs[1].set(ylim=(.7,1.04),ylabel='Recall',title='Family recall (MITM: 21 test windows)');axs[1].tick_params(axis='x',labelrotation=55)
    fig.suptitle('Offline known-family benchmark | within-family time blocks, globally interleaved dates',fontsize=11)
    fig.savefig(O/'known-family-performance.png',dpi=180);plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,4.5),layout='constrained')
    # Each bar retains its own test population; they are not paired interventions.
    phases=[('Calibration',O/'study/test-results.json','selected_family'),('Recent-data refit',O/'final-refit/test-results.json',None),('Novelty probe',O/'novelty-probe/test-results.json','selected')]
    values=[]
    for title,path,key in phases:
        entries=load(path)['results']
        if title=='Recent-data refit':entries=[r for r in entries if r['scope']=='federated' and r['weighting']=='recency-48h' and r['view']=='occurrence']
        else:entries=[r for r in entries if r[key] and r['view']=='occurrence' and (r.get('scope','federated')=='federated')]
        values.append(float(np.mean([r['test']['macro_f1'] for r in entries])))
    ax.bar(['Calibration','Recent-data refit','Novelty probe'],values,color='#0f766e')
    ax.set(ylim=(0,1),ylabel='Test macro-F1',title='Original chronological test: unseen MITM remains unresolved')
    for i,value in enumerate(values):ax.text(i,value+.025,f'{value:.3f}',ha='center')
    fig.savefig(O/'chronological-negative-controls.png',dpi=180);plt.close(fig)
    print(json.dumps(dict(audit=counts,repetitions=repetitions,primary_means={k:v['mean'] for k,v in summary.items() if isinstance(v,dict) and 'mean' in v})),flush=True)
if __name__=='__main__':
    with threadpool_limits(limits=1):main()
