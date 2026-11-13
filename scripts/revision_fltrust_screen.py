"""Small-storage FLTrust transfer on fixed historical Adam endpoint inputs."""
from __future__ import annotations
import os
for k in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ.setdefault(k,'1')
from pathlib import Path
from fractions import Fraction as F
from collections import Counter
import argparse,hashlib,json,time
import numpy as np
from fltrust_screen_aggregation import fltrust_delta,norm_matched_delta
from capped_final_aggregation import project_coefficients
from no_redistribution_aggregation import blend_clipped_deltas
from revision_dba_experiment import save,authenticate,outcomes,model_with_arrays,environment
from revision_study_data import read
from fl_forensics.federated_model import arrays_from_export,dependencies,seed_everything,train_local,export_state
from fl_forensics.secure_round import _model_from_export
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.bounded_aggregation import digest
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded
from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'artifacts/revision-capped-final-v1'
M3=ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1'
DEST=ROOT/'results/admission/revision-fltrust-screen-v1'
MIRROR=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'fltrust-screen-20261107/published')
ROOT_SEEDS=(7110701,7110702,7110703)
ROOT_METHODS=('sgd1','adam10')

def export_digest(v):return hashlib.sha256(derived_json_bytes(v)).hexdigest()
def allocated(p):return sum(f.stat().st_blocks*512 for f in p.rglob('*') if f.is_file()) if p.exists() else 0
def guard():
    s=os.statvfs('/mnt/c');free=s.f_bavail*s.f_frsize;used=allocated(DEST)+allocated(MIRROR)
    if free<8*1024**3 or used>64*1024**2:raise RuntimeError('Fixed host-space or output-budget guard failed')
    return {'host_free_bytes':free,'combined_output_allocated_bytes':used}
def locks():
    paths=[ROOT/'scripts'/n for n in ('fltrust_screen_aggregation.py','revision_fltrust_screen.py','capped_final_aggregation.py',
          'no_redistribution_aggregation.py','revision_dba_experiment.py','revision_study_data.py')]
    paths.append(ROOT/'tests/test_fltrust_screen_aggregation.py')
    return {str(f.relative_to(ROOT)):sha256_file(f) for f in paths}
def check(p):
    assert locks()==p['source_locks'],'New source drift'
    old=read(SOURCE/'protocol-before-training.json')
    assert sha256_file(SOURCE/'protocol-before-training.json')==p['original_protocol_sha256']
    for n,h in old['source_locks'].items():assert sha256_file(ROOT/n)==h,n
    for n,h in p['data_locks'].items():assert sha256_file(Path(n))==h,n
    return old
def choose(rows,n,seed):
    return sorted(rows,key=lambda r:hashlib.sha256(f"{seed}:{r['window_id']}".encode()).hexdigest())[:n]

def prepare():
    assert not DEST.exists(),'Preserve previous study'
    storage=guard();old=read(SOURCE/'protocol-before-training.json');m=read(M3/'manifest.json')
    vpath=Path(old['training']['validation_path']);assert sha256_file(vpath)==old['training']['validation_sha256']
    validation=read(vpath)['rows']['validation'];classes=m['class_names'];pool=[]
    for c in classes:
        candidates=[r for r in validation if r['label']==c];assert len(candidates)>=20
        pool.extend(choose(candidates,10,7110700))
    pool_ids={r['window_id'] for r in pool};assert len(pool_ids)==60
    eval_rows=[r for r in validation if r['window_id'] not in pool_ids]
    root_draws={str(seed):[r['window_id'] for c in classes for r in choose([x for x in pool if x['label']==c],8,seed)] for seed in ROOT_SEEDS}
    training_ids=set();data_locks={str(vpath):sha256_file(vpath),str(M3/'manifest.json'):sha256_file(M3/'manifest.json')}
    for c in m['clients']:
        f=M3/c['dataset_path'];assert sha256_file(f)==c['dataset_sha256'];data_locks[str(f)]=c['dataset_sha256']
        ids={r['window_id'] for r in read(f)['rows']['train']};assert not training_ids&ids;training_ids|=ids
    test_entry=m['server_evaluation_splits']['test'];test_path=M3/test_entry['path']
    assert sha256_file(test_path)==test_entry['sha256'];data_locks[str(test_path)]=test_entry['sha256']
    # Test rows are inspected solely for ID separation, never for model metrics.
    test_ids={r['window_id'] for r in read(test_path)['rows']['test']}
    eval_ids={r['window_id'] for r in eval_rows}
    assert not(pool_ids&training_ids or pool_ids&eval_ids or pool_ids&test_ids or eval_ids&training_ids or eval_ids&test_ids)
    entries=[]
    for task in old['tasks']:
        if task['seed'] not in (6116104,6116105) or task['method'] not in ('robust_bounded','capped_robust'):continue
        f=SOURCE/'cases'/task['name']/'result.json';r=read(f)
        assert r['complete'] and r['completed_rounds']==15
        entries.append({'task':task,'result_sha256':sha256_file(f),'manifest_sha256':r['manifest_sha256']})
    assert len(entries)==16
    p={'profile':'fltrust-fixed-context-transfer-v1','source_locks':locks(),'data_locks':data_locks,
       'original_protocol_sha256':sha256_file(SOURCE/'protocol-before-training.json'),'cases':entries,'rounds':[1,5,10,15],
       'root_pool_ids':sorted(pool_ids),'root_draws':root_draws,'root_seeds':list(ROOT_SEEDS),'root_methods':list(ROOT_METHODS),
       'root_pool_class_counts':dict(Counter(r['label'] for r in pool)),'root_draw_class_count':8,
       'evaluation_ids_sha256':export_digest(sorted(eval_ids)),'evaluation_row_count':len(eval_rows),
       'evaluation_class_counts':dict(Counter(r['label'] for r in eval_rows)),
       'root_training':{'sgd1':{'optimizer':'SGD','steps':1,'batch_size':32,'learning_rate':.001,'class_weighting':'none'},
                        'adam10':{'optimizer':'Adam','epochs':10,'batch_size':128,'learning_rate':.001,'class_weighting':'Original global training-only weights'}},
       'storage_before':storage,'maximum_combined_output_bytes':64*1024**2,'minimum_host_free_bytes':8*1024**3,
       'environment':environment(),'reference':'https://www.ndss-symposium.org/wp-content/uploads/ndss2021_6C-2_24434_paper.pdf',
       'algorithm':'ReLU cosine without sample weights, full-vector norm normalization, global step1. Local endpoint delta sign is local-minus-base; both root and clients use this convention.',
       'adaptation':'Both variants reuse historical ten-epoch Adam client endpoints. SGD1 uses the paper-style one-minibatch root update; Adam10 aligns root training to this project. Neither is a full original FLTrust protocol reproduction.',
       'quorum':'All source admissions have15 trust-assumed eligible clients. Raw FLTrust formula requires positive score sum; positive-score support below runtime quorum10 is separately flagged and cannot establish an operational deployment.',
       'controls':['Reconstructed robust and capped on same inputs','Root-only update','Robust direction rescaled to each FLTrust output norm'],
       'root_assumption':'Correctly labelled, unmodified historical server validation rows; all six classes, not benign-only. This is not newly acquired or independently certified clean data.',
       'separation':'Sixty root-pool rows excluded from all new metrics. Each root is48 rows, eight/class, three overlapping fixed draws. Pool/evaluation disjoint from client training and original test IDs. Test file read for ID check only.',
       'historical_exposure':'The original validation set, including this pool, was already observed and used by historical model selection, indicator scoring and attack queries. This is reused-data exploratory analysis, not an untouched holdout or secret-root defense test.',
       'evaluation':'Only the remaining validation3163 rows; no test inference, no threshold/learning-rate/root selection. Report all draws/methods including undefined and below-quorum outputs.',
       'scope':'64 fixed source contexts,384 root updates,128 baseline outputs plus up to1152 root/FLTrust/norm-control outputs. No new client training or defender-specific adaptive search. No trajectory-security claim.'}
    DEST.mkdir();save(DEST/'protocol-before-root-training.json',p)
    print(json.dumps({'prepared':True,'contexts':64,'root_draws':3,'root_methods':2,'root_pool':60,'evaluation_rows':len(eval_rows),'storage':storage}),flush=True)

def root_update(initial,rows,method,seed,deps,weights):
    torch=deps[1];model=_model_from_export(initial,torch=torch,np=np)
    if method=='adam10':
        train_local(model=model,rows=rows,class_names=initial['class_names'],class_weights=weights,epochs=10,batch_size=128,
                    learning_rate=.001,seed=seed,device_name='cpu',torch=torch,np=np)
        indices=list(range(len(rows)))
    else:
        assert method=='sgd1';seed_everything(seed,torch=torch,np=np);model.train()
        indices=torch.randperm(len(rows),generator=torch.Generator().manual_seed(seed))[:32].tolist()
        features=torch.tensor([rows[i]['features'] for i in indices],dtype=torch.float32)
        labels=torch.tensor([initial['class_names'].index(rows[i]['label']) for i in indices],dtype=torch.long)
        optimizer=torch.optim.SGD(model.parameters(),lr=.001);optimizer.zero_grad()
        loss=torch.nn.functional.cross_entropy(model(features),labels);loss.backward();optimizer.step()
    return export_state(model,architecture=initial['architecture'],class_names=initial['class_names']),indices

def compact(v):
    return {**{k:x for k,x in v.items() if k!='clean'},'clean':{k:v['clean'][k] for k in ('accuracy','macro_f1_all_model_classes','per_class','confusion_matrix')}}
def norm(values):return float(np.linalg.norm(np.concatenate([a.ravel() for a in values])))

def run():
    p=read(DEST/'protocol-before-root-training.json');old=check(p);deps=dependencies()
    deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    original_validation=read(Path(old['training']['validation_path']))['rows']['validation']
    byid={r['window_id']:r for r in original_validation};pool=set(p['root_pool_ids'])
    evaluation=[r for r in original_validation if r['window_id'] not in pool]
    assert len(evaluation)==p['evaluation_row_count'] and export_digest(sorted(r['window_id'] for r in evaluation))==p['evaluation_ids_sha256']
    reference=read(ROOT/old['tensor_references']['non-iid']['path'])
    assert sha256_file(ROOT/old['tensor_references']['non-iid']['path'])==old['tensor_references']['non-iid']['sha256']
    completed=[]
    for entry in p['cases']:
        task=entry['task'];name=task['name'];target=DEST/'cases'/f'{name}.json'
        assert not target.exists(),'Preserve completed output; use a separate explicit recovery'
        source=SOURCE/'cases'/name/'evidence';assert sha256_file(source.parent/'result.json')==entry['result_sha256']
        manifest=authenticate(source,entry['manifest_sha256'])
        part_path=SOURCE/'partitions'/str(task['seed'])/'manifest.json';assert sha256_file(part_path)==old['partitions'][str(task['seed'])]
        partition=read(part_path);counts={x['client_id']:x['train_row_count'] for x in partition['clients']};clients=sorted(counts)
        plan=DistributedBackdoorPlan.model_validate({**old['training']['attack_plan'],'seed':task['seed'],
             'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True))})
        # Conditional ASR remains relative to the pinned original warm start.
        from revision_dba_experiment import predict
        predicted,_=predict(read(Path(old['training']['base_model_path'])),evaluation,deps)
        correct=[a==r['label'] for a,r in zip(predicted,evaluation,strict=True)]
        context_rows=[]
        for number in p['rounds']:
            storage=guard();start=time.perf_counter();folder=source/'rounds'/f'round-{number:03d}'
            initial=read(folder/'base-model.json');rr=read(folder/'round.json');state=read(folder/'gate-state.json')
            assert export_digest(initial)==rr['base_model_sha256']
            base=arrays_from_export(initial,np=np);updates={c:arrays_from_export(read(folder/'updates'/f'{c}.json'),np=np) for c in clients}
            gates={c:state['decisions'][c]['tpm_only']['contributes'] for c in clients}
            assert all(gates.values()) and {c:str(counts[c]) for c in clients}==rr['masses']
            robust,parent=aggregate_robust_bounded(base,updates,masses=rr['masses'],mandatory_gates=gates,limits=reference['limits'],
                  reference_digest=digest(reference),minimum_contributors=old['runtime_admission']['minimum_contributors'],max_iterations=50)
            assert robust is not None
            prior={c:F(v) for c,v in parent['final_coefficients'].items()};cap,_=project_coefficients(prior,cap=F(1,9))
            clipped={c:[np.asarray(t['values']).reshape(t['shape']) for t in parent['final_bounded_derivation']['contributions'][c]['derived_float64_delta']] for c in clients}
            capped=blend_clipped_deltas(base,clipped,cap,gates)
            def measure(params):
                assert all(np.isfinite(a).all() for a in params)
                model=model_with_arrays(initial,params)
                return {'model_sha256':export_digest(model),'validation':compact(outcomes(model,evaluation,plan,correct,deps))}
            baselines={'robust':measure(robust),'capped':measure(capped)}
            selected=robust if task['method']=='robust_bounded' else capped
            assert model_with_arrays(initial,selected)==read(folder/'global-model.json'),'Source checkpoint reconstruction'
            raw={c:[a.astype(float)-b for a,b in zip(updates[c],base,strict=True)] for c in clients}
            robust_delta=[a-b for a,b in zip(robust,base,strict=True)];refs=[]
            for root_seed in p['root_seeds']:
                root_rows=[byid[i] for i in p['root_draws'][str(root_seed)]]
                for method in p['root_methods']:
                    root_weights={c:float(v) for c,v in partition['global_class_weights'].items()}
                    root_model,indices=root_update(initial,root_rows,method,root_seed,deps,root_weights)
                    repeated=False
                    if not completed and not context_rows:
                        again,again_indices=root_update(initial,root_rows,method,root_seed,deps,root_weights)
                        assert again==root_model and again_indices==indices;repeated=True
                    root_arrays=arrays_from_export(root_model,np=np)
                    rd=[a.astype(float)-b for a,b in zip(root_arrays,base,strict=True)]
                    root_only=measure(root_arrays)
                    ref={'root_seed':root_seed,'root_method':method,'root_model_sha256':export_digest(root_model),
                         'root_delta_norm':norm(rd),'executed_root_indices':indices,'root_training_repeated':repeated,'root_only':root_only}
                    try:
                        delta,report=fltrust_delta(raw,rd,gates)
                    except ValueError as exc:
                        ref.update(defined=False,reason=str(exc),fltrust=None,norm_matched_robust=None)
                    else:
                        independent=[sum((raw[c][k]*report['effective_raw_delta_coefficients'][c] for c in clients),np.zeros_like(b)) for k,b in enumerate(base)]
                        for a,b in zip(independent,delta,strict=True):np.testing.assert_allclose(a,b,rtol=1e-12,atol=1e-12)
                        ref.update(defined=True,derivation=report,meets_positive_quorum10=report['positive_contributors']>=10,
                            fltrust=measure([b+d for b,d in zip(base,delta,strict=True)]))
                        if norm(robust_delta)==0 and norm(delta)>0:
                            ref.update(norm_matched_robust=None,matched_robust_reason='Zero robust direction cannot match a positive output norm')
                        else:
                            match,scale=norm_matched_delta(robust_delta,norm(delta))
                            assert abs(norm(match)-norm(delta))<=1e-12*max(1,norm(delta))
                            ref.update(norm_matched_robust=measure([b+d for b,d in zip(base,match,strict=True)]),matched_robust_scale=scale)
                    refs.append(ref)
            pins={str(f.relative_to(source)):sha256_file(f) for f in [folder/'base-model.json',folder/'gate-state.json',folder/'global-model.json',folder/'round.json',*[folder/'updates'/f'{c}.json' for c in clients]]}
            assert all(manifest['core']['artifacts'][n]==h for n,h in pins.items())
            context_rows.append({'case':name,'source_operator':task['method'],'seed':task['seed'],'mode':task['mode'],'round':number,
                 'actually_manipulated_clients':rr['actually_manipulated_clients'],'selected_alpha':rr['selected_alpha'],
                 'input_locks':pins,'baselines':baselines,'references':refs,'source_checkpoint_reproduced':True,
                 'elapsed_seconds':time.perf_counter()-start,'storage_before_context':storage})
            print(json.dumps({'case':name,'round':number,'contexts_completed':len(completed)*4+len(context_rows),'storage':guard()}),flush=True)
        save(target,{'task':task,'rows':context_rows,'source_manifest_sha256':entry['manifest_sha256']});completed.append(name)
    check(p)
    cases=[read(DEST/'cases'/f"{e['task']['name']}.json") for e in p['cases']]
    rows=[r for c in cases for r in c['rows']];refs=[v for r in rows for v in r['references']]
    save(DEST/'completion.json',{'status':'screening_complete','contexts':len(rows),'root_updates':len(refs),
         'root_training_replays':sum(v['root_training_repeated'] for v in refs),'defined_fltrust_outputs':sum(v['defined'] for v in refs),
         'positive_quorum10_outputs':sum(v.get('meets_positive_quorum10',False) for v in refs),
         'client_training_runs':0,'test_inference':False,'test_ids_checked_only':True,'new_TPM_quotes':0,
         'new_defender_specific_attack_search':False,'storage_after':guard()})
    print(json.dumps(read(DEST/'completion.json'),indent=2),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('prepare','run'));args=parser.parse_args()
    if args.phase=='prepare':prepare()
    else:run()
