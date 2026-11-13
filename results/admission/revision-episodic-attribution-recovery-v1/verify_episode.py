"""Fresh read-only replay of the frozen V5 assessment and origin interventions."""
import os
for name in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ[name]='1'
from pathlib import Path
import sys,json,multiprocessing
from concurrent.futures import ProcessPoolExecutor,as_completed
from threadpoolctl import threadpool_info
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');sys.path.insert(0,str(R/'scripts'))
import revision_episode_attribution as study
from episodic_attribution_groups import fit_reference,calibrate,detect
from revision_study_data import read
from revision_dba_experiment import save,authenticate
from fl_forensics.canonical import sha256_file
D=study.D;S=D/'source-evidence';E=D/'recovery-evidence'
ENGINES={}

def verify_case(alias):
    p=read(D/'protocol-before-training.json');task=next(t for t in p['tasks'] if t['alias']==alias);seed=task['seed']
    if seed not in ENGINES:ENGINES[seed]=study.Engine(p,write=False)
    engine=ENGINES[seed]
    ref=read(S/'reference.json');cal=read(S/'calibration.json')
    counts=dict(alias=alias,seed=seed,source_rounds=0,recovery_branches=0,recovery_rounds=0,adaptive_queries=0)
    result,model,obs=engine.history(task,[],True)
    assert result==read(S/'histories'/task['alias']/'result.json')
    assert model==read(S/'histories'/task['alias']/'last-checkpoint.json')
    assert detect(obs,ref,cal)==read(S/'selection'/f"{task['alias']}.json")
    counts['source_rounds']+=len(result['journal']);counts['adaptive_queries']+=sum(len(r['queries']) for r in result['journal'])
    print(json.dumps(dict(replayed_source=task['alias'],seed=seed)),flush=True)
    request=read(E/f"{task['alias']}.json")['plan']
    if request['eligible_for_recovery']:
        for removal in request['removals']:
            value,_,_=engine.history(task,removal['removed'],False)
            assert value==read(E/'histories'/task['alias']/f"{removal['key']}.json")
            counts['recovery_branches']+=1;counts['recovery_rounds']+=len(value['journal'])
            counts['adaptive_queries']+=sum(len(r['queries']) for r in value['journal'])
            print(json.dumps(dict(replayed_origin=task['alias'],removed=removal['removed'],seed=seed)),flush=True)
    counts['clean_reference_keys']=[f"{s}:{','.join(removed)}" for s,removed in sorted(engine.clean_cache)]
    study.check(p)
    assert all(x['num_threads']==1 for x in threadpool_info() if x['user_api']=='blas')
    return counts

def main():
    p=read(D/'protocol-before-training.json');study.check(p);assert p==read(S/'protocol.json')
    authenticate(S,read(D/'source-closure.json')['manifest_sha256']);authenticate(E,read(D/'recovery-closure.json')['manifest_sha256'])
    save(D/'verification-definition-before-replay.json',dict(verifier_sha256=sha256_file(Path(__file__)),workers=2,
        scheduling='Two spawned read-only workers over independent cases, all numerical threads1; canonical clean-reference caches make attack family and schedule order-independent.',
        source_manifest_sha256=sha256_file(S/'manifest.json'),recovery_manifest_sha256=sha256_file(E/'manifest.json')))
    engine=study.Engine(p,write=False);frames={}
    for seed in study.FIT+study.CAL:
        role='fit' if seed in study.FIT else 'calibration'
        task=dict(alias=f'{role}-{seed}',seed=seed,mode='clean',family='unrestricted',attackers=['client01','client06','client13'],role=role)
        result,_,obs=engine.history(task,[],True,10);assert result==read(S/'calibration-histories'/f'{seed}.json');frames[seed]=obs
        print(json.dumps(dict(replayed_clean_calibration=seed)),flush=True)
    ref=fit_reference([frames[s] for s in study.FIT]);cal=calibrate([frames[s] for s in study.CAL],ref)
    assert ref==read(S/'reference.json') and cal==read(S/'calibration.json');del frames,engine
    results=[]
    with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn')) as pool:
        futures=[pool.submit(verify_case,task['alias']) for task in p['tasks']]
        for future in as_completed(futures):results.append(future.result())
    planned=read(D/'recovery-plan-before-effects.json')
    assert sum(x['source_rounds'] for x in results)==15*len(p['tasks'])
    assert {x['alias'] for x in results}=={t['alias'] for t in p['tasks']}
    assert sum(x['recovery_branches'] for x in results)==planned['requested_replay_branches']
    study.check(p);authenticate(S,read(D/'source-closure.json')['manifest_sha256']);authenticate(E,read(D/'recovery-closure.json')['manifest_sha256'])
    record=dict(status='v5_histories_selection_and_origin_recovery_replayed',clean_fit_calibration_rounds=50,
        source_rounds=sum(r['source_rounds'] for r in results),recovery_branches=sum(r['recovery_branches'] for r in results),
        recovery_rounds=sum(r['recovery_rounds'] for r in results),adaptive_queries=sum(r['adaptive_queries'] for r in results),
        clean_reference_histories_checked=len({key for r in results for key in r['clean_reference_keys']}),
        software_manifests_authenticated=True,same_implementation_replay=True,new_TPM_quotes=0,test_inference=False,
        default_changed=False,case_verifications=sorted(results,key=lambda r:r['alias']),storage=study.guard())
    save(D/'verification.json',record);print(json.dumps(record,indent=2),flush=True)

if __name__=='__main__':main()
