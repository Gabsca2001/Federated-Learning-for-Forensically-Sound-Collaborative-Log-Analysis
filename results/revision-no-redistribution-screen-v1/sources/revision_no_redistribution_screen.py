"""Small-storage, validation-only interventions on authenticated saved inputs."""
from __future__ import annotations
import os
for key in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ.setdefault(key,'1')
from pathlib import Path
from fractions import Fraction as F
import argparse,hashlib,json,time,shutil
import numpy as np
from no_redistribution_aggregation import coefficient_variants,blend_clipped_deltas
from capped_final_aggregation import project_coefficients
from revision_dba_experiment import save,authenticate,outcomes,predict,model_with_arrays,environment
from revision_study_data import read
from fl_forensics.federated_model import arrays_from_export,dependencies
from fl_forensics.bounded_aggregation import digest,record
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'artifacts/revision-capped-final-v1'
DEST=ROOT/'results/revision-no-redistribution-screen-v1'
MIRROR=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/no-redistribution-20261106/published')
MAX_BYTES=64*1024**2
MIN_FREE=8*1024**3
METHODS=('robust','capped','no_redistribution','matched_step')

def export_digest(value):return hashlib.sha256(derived_json_bytes(value)).hexdigest()

def allocated(p):return sum(f.stat().st_blocks*512 for f in p.rglob('*') if f.is_file()) if p.exists() else 0
def guard():
    s=os.statvfs('/mnt/c');free=s.f_bavail*s.f_frsize
    used=allocated(DEST)+allocated(MIRROR)
    if free<MIN_FREE:raise RuntimeError('Host free space below fixed 8 GiB floor')
    if used>MAX_BYTES:raise RuntimeError('Combined output allocation exceeds fixed 64 MiB budget')
    return {'host_free_bytes':free,'new_output_allocated_bytes':used}

def locks():
    names=('no_redistribution_aggregation.py','revision_no_redistribution_screen.py','capped_final_aggregation.py',
           'revision_dba_experiment.py','revision_study_data.py')
    paths=[ROOT/'scripts'/n for n in names]+[ROOT/'tests/test_no_redistribution_aggregation.py']
    return {str(p.relative_to(ROOT)):sha256_file(p) for p in paths}

def check_protocol(p):
    assert locks()==p['source_locks'],'Research source changed'
    old=read(SOURCE/'protocol-before-training.json')
    assert sha256_file(SOURCE/'protocol-before-training.json')==p['original_protocol_sha256']
    for rel,expected in old['source_locks'].items():assert sha256_file(ROOT/rel)==expected,rel
    assert sha256_file(SOURCE/'training-complete.json')==p['training_closure_sha256']
    assert sha256_file(Path(old['training']['validation_path']))==p['validation_sha256']
    return old

def prepare():
    assert not DEST.exists(),'Preserve previous screen'
    before=guard();old=read(SOURCE/'protocol-before-training.json')
    tasks=[t for t in old['tasks'] if t['seed'] in (6116104,6116105) and t['method'] in ('robust_bounded','capped_robust')]
    assert len(tasks)==16
    cases=[]
    for task in tasks:
        path=SOURCE/'cases'/task['name'];r=read(path/'result.json')
        assert r['complete'] and r['completed_rounds']==15
        assert sha256_file(path/'evidence/manifest.json')==r['manifest_sha256']
        cases.append({'task':task,'manifest_sha256':r['manifest_sha256'],'result_sha256':sha256_file(path/'result.json')})
    p={'profile':'no-redistribution-same-input-screen-v1','source_locks':locks(),
       'original_protocol_sha256':sha256_file(SOURCE/'protocol-before-training.json'),
       'training_closure_sha256':sha256_file(SOURCE/'training-complete.json'),
       'validation_sha256':old['training']['validation_sha256'],'cases':cases,'rounds':list(range(1,16)),
       'methods':list(METHODS),'individual_cut':'1/9','minimum_host_free_bytes':MIN_FREE,'maximum_combined_output_bytes':MAX_BYTES,
       'storage_before':before,'environment':environment(),
       'selection':'Post-hoc diagnostic of both previously identified non-IID failure seeds; both source operators, all clean/distributed/complete-trigger/adaptive histories and all rounds.',
       'contract':'No redistribution: beta_i=min(p_i,1/9), residual=1-sum(beta) retained at current checkpoint. Matched-step control: beta_i=sum(cut)*p_i. Neither is silently renormalized.',
       'bound_scope':'No-redistribution bounds absolute coefficients in the checkpoint-inclusive step, not normalized share within client updates. This is a different contract from the original client-only group ceiling.',
       'input_scope':'Same already selected updates and source parent; no corrected local retraining, no new defender-adaptive search, no fresh TPM appraisal.',
       'evaluation_scope':'Reused validation only; no test inference, no threshold selection, no new training. Conditional one-round effects are not independent defended trajectories.',
       'next_stage':'No automatic full-trajectory promotion. Report all favorable, neutral and unfavorable cases, including slowed-step control.'}
    DEST.mkdir();save(DEST/'protocol-before-inference.json',p)
    print(json.dumps({'prepared_contexts':240,'candidate_outputs':960,'storage':before}),flush=True)

def compact(value):
    return {**{k:v for k,v in value.items() if k!='clean'},'clean':{k:value['clean'][k] for k in ('accuracy','macro_f1_all_model_classes','per_class','confusion_matrix')}}

def process_case(entry,p,old,deps,validation,correct):
    task=entry['task'];name=task['name'];source=SOURCE/'cases'/name/'evidence'
    assert sha256_file(source.parent/'result.json')==entry['result_sha256']
    manifest=authenticate(source,entry['manifest_sha256'])
    reference=read(ROOT/old['tensor_references']['non-iid']['path'])
    assert sha256_file(ROOT/old['tensor_references']['non-iid']['path'])==old['tensor_references']['non-iid']['sha256']
    partition=read(SOURCE/'partitions'/str(task['seed'])/'manifest.json')
    assert sha256_file(SOURCE/'partitions'/str(task['seed'])/'manifest.json')==old['partitions'][str(task['seed'])]
    counts={c['client_id']:c['train_row_count'] for c in partition['clients']}
    plan=DistributedBackdoorPlan.model_validate({**old['training']['attack_plan'],'seed':task['seed'],
         'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True))})
    previous=read(old['training']['base_model_path']);rows=[]
    for n in p['rounds']:
        storage=guard();start=time.perf_counter();folder=source/'rounds'/f'round-{n:03d}'
        initial=read(folder/'base-model.json');rr=read(folder/'round.json');state=read(folder/'gate-state.json')
        assert initial==previous and export_digest(initial)==rr['base_model_sha256']
        clients=sorted(counts);base=arrays_from_export(initial,np=np)
        updates={c:arrays_from_export(read(folder/'updates'/f'{c}.json'),np=np) for c in clients}
        gates={c:state['decisions'][c]['tpm_only']['contributes'] for c in clients}
        assert all(gates.values()) and {c:str(counts[c]) for c in clients}==rr['masses']
        assert len(clients)>=old['runtime_admission']['minimum_contributors']
        robust,parent=aggregate_robust_bounded(base,updates,masses=rr['masses'],mandatory_gates=gates,
             limits=reference['limits'],reference_digest=digest(reference),minimum_contributors=old['runtime_admission']['minimum_contributors'],max_iterations=50)
        assert robust is not None
        prior,cut,matched,residual=coefficient_variants(parent['final_coefficients'])
        cap,_=project_coefficients(prior,cap=F(1,9))
        clipped={}
        for c in clients:
            tensors=parent['final_bounded_derivation']['contributions'][c]['derived_float64_delta']
            clipped[c]=[np.asarray(t['values'],dtype=np.float64).reshape(t['shape']) for t in tensors]
            # Independently reconstruct the fixed per-tensor clipping map.
            for k,(a,b) in enumerate(zip(updates[c],base,strict=True)):
                delta=a.astype(float)-b;norm=np.linalg.norm(delta.ravel())
                independent=delta*min(1.,reference['limits'][k]/norm) if norm else delta
                np.testing.assert_array_equal(clipped[c][k],independent)
        proposals={'robust':prior,'capped':cap,'no_redistribution':cut,'matched_step':matched}
        outputs={};source_model=read(folder/'global-model.json')
        for method,beta in proposals.items():
            params=blend_clipped_deltas(base,clipped,beta,gates)
            # Different summation layout checks the actual unnormalized formula.
            weights=np.array([float(beta[c]) for c in clients])
            for k,a in enumerate(base):
                independent=a+np.tensordot(weights,np.stack([clipped[c][k] for c in clients]),axes=(0,0))
                np.testing.assert_allclose(params[k],independent,rtol=1e-12,atol=1e-12)
            if method=='robust':
                for a,b in zip(params,robust,strict=True):np.testing.assert_array_equal(a,b)
            model=model_with_arrays(initial,params);metrics=outcomes(model,validation,plan,correct,deps)
            is_source=(method=='robust' and task['method']=='robust_bounded') or (method=='capped' and task['method']=='capped_robust')
            if is_source:
                assert model==source_model,'Actual source checkpoint failed reconstruction'
                assert metrics==rr['validation'],'Original validation metrics did not reproduce'
            total=sum(beta.values());attacker=sum(beta[c] for c in task['attackers'])
            outputs[method]={'model_sha256':export_digest(model),'beta':{c:str(beta[c]) for c in clients},
                'retained_checkpoint_weight':str(1-total),'client_step_mass':str(total),
                'maximum_three_absolute_coefficients':str(sum(sorted(beta.values(),reverse=True)[:3])),
                'maximum_three_client_normalized_share':str(sum(sorted(beta.values(),reverse=True)[:3])/total),
                'declared_attacker_absolute_coefficients':str(attacker),
                'declared_attacker_client_normalized_share':str(attacker/total),
                'validation':compact(metrics),'source_checkpoint_reproduced':is_source}
        assert all(cut[c]<=prior[c] for c in clients)
        assert sum(cut.values())==sum(matched.values()) and sum(cut.values())+residual==1
        assert sum(sorted(cut.values(),reverse=True)[:3])<=F(1,3)
        pins={str(f.relative_to(source)):sha256_file(f) for f in [folder/'base-model.json',folder/'gate-state.json',folder/'global-model.json',folder/'round.json',*[folder/'updates'/f'{c}.json' for c in clients]]}
        assert all(manifest['core']['artifacts'][rel]==h for rel,h in pins.items())
        rows.append({'case':name,'source_operator':task['method'],'seed':task['seed'],'mode':task['mode'],'round':n,
            'actually_manipulated_clients':rr['actually_manipulated_clients'],'selected_alpha':rr['selected_alpha'],
            'input_locks':pins,'robust_derivation_digest':parent['derivation_digest'],
            'outputs':outputs,'elapsed_seconds':time.perf_counter()-start,'storage_before_round':storage})
        previous=source_model
        if n%5==0:print(json.dumps({'case':name,'round':n,'storage':guard()}),flush=True)
    assert sha256_file(source/'manifest.json')==entry['manifest_sha256']
    save(DEST/'cases'/f'{name}.json',{'task':task,'rows':rows,'source_manifest_sha256':entry['manifest_sha256']})

def run():
    p=read(DEST/'protocol-before-inference.json');old=check_protocol(p)
    deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
    initial=read(old['training']['base_model_path']);validation=read(old['training']['validation_path'])['rows']['validation']
    labels,_=predict(initial,validation,deps);correct=[a==b['label'] for a,b in zip(labels,validation,strict=True)]
    for entry in p['cases']:
        target=DEST/'cases'/f"{entry['task']['name']}.json"
        if target.exists():
            existing=read(target);assert len(existing['rows'])==15 and existing['source_manifest_sha256']==entry['manifest_sha256'];continue
        process_case(entry,p,old,deps,validation,correct)
    check_protocol(p)
    cases=[read(DEST/'cases'/f"{e['task']['name']}.json") for e in p['cases']]
    record_out={'status':'screening_complete','source_cases':len(cases),'contexts':sum(len(c['rows']) for c in cases),
       'counterfactual_outputs':sum(len(r['outputs']) for c in cases for r in c['rows']),
       'source_checkpoints_and_validation_reproduced':sum(v['source_checkpoint_reproduced'] for c in cases for r in c['rows'] for v in r['outputs'].values()),
       'new_training_runs':0,'new_TPM_quotes':0,'test_inference':False,'defender_adaptive_search_for_new_methods':False,
       'storage_after':guard(),'scope':p['evaluation_scope']}
    save(DEST/'completion.json',record_out)
    print(json.dumps(record_out,indent=2),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('prepare','run'));a=parser.parse_args()
    if a.phase=='prepare':prepare()
    else:run()
