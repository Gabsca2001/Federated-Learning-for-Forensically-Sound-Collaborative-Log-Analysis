"""Fresh numerical verification, independent read-only workers by allocation.

Each worker preserves the frozen task order within its seed so cached clean
counterfactual identities match the original generation order. Two processes
change scheduling only. PyTorch stays single-threaded; NumPy BLAS pool sizes
are explicitly preserved from the generator's fresh-process import configuration.
"""
from pathlib import Path
import sys,json,multiprocessing
from threadpoolctl import ThreadpoolController,threadpool_info
from concurrent.futures import ProcessPoolExecutor,as_completed
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
sys.path.insert(0,str(R/'scripts'))
import revision_attribution_recovery as study
from revision_study_data import read
from revision_dba_experiment import save,authenticate
from retrospective_anomaly_groups import fit_reference,calibrate,detect
from fl_forensics.canonical import sha256_file
D=study.D;S=D/'source-evidence';E=D/'recovery-evidence'

def verify_seed(seed,blas_settings):
    # Spawn inherits the parent's late environment updates; restore the actual
    # initialized BLAS widths rather than silently changing reduction settings.
    pool_limits=[ThreadpoolController().select(filepath=x['filepath']).limit(limits=x['num_threads']) for x in blas_settings]
    p=read(D/'protocol-before-training.json');engine=study.Engine(p,write=False)
    ref=read(S/'reference.json');cal=read(S/'calibration.json')
    counts=dict(seed=seed,source_rounds=0,recovery_branches=0,recovery_rounds=0,adaptive_queries=0)
    for task in p['tasks']:
        if task['seed']!=seed:continue
        result,model,obs=engine.history(task,[],True)
        assert result==read(S/'histories'/task['alias']/'result.json')
        assert model==read(S/'histories'/task['alias']/'last-checkpoint.json')
        assert detect(obs,ref,cal)==read(S/'selection'/f"{task['alias']}.json")
        counts['source_rounds']+=len(result['journal']);counts['adaptive_queries']+=sum(len(r['queries']) for r in result['journal'])
        print(json.dumps(dict(replayed_source=task['alias'],seed=seed)),flush=True)
        request=read(E/f"{task['alias']}.json")['plan']
        if request['eligible_for_recovery']:
            for removal in request['removals']:
                reconstructed,_,_=engine.history(task,removal['removed'],False)
                assert reconstructed==read(E/'histories'/task['alias']/f"{removal['key']}.json")
                counts['recovery_branches']+=1;counts['recovery_rounds']+=len(reconstructed['journal'])
                counts['adaptive_queries']+=sum(len(r['queries']) for r in reconstructed['journal'])
                print(json.dumps(dict(replayed_origin=task['alias'],removed=removal['removed'],seed=seed)),flush=True)
    counts['clean_reference_histories_checked']=len(engine.clean_cache);study.check(p)
    return counts

def main():
    p=read(D/'protocol-before-training.json');study.check(p)
    authenticate(S,read(D/'source-closure.json')['manifest_sha256']);authenticate(E,read(D/'recovery-closure.json')['manifest_sha256'])
    blas_settings=[x for x in threadpool_info() if x['user_api']=='blas']
    save(D/'verification-definition-before-replay.json',dict(verifier_sha256=sha256_file(Path(__file__)),
        scheduling='Two spawned read-only workers, source task order preserved within each seed; PyTorch single-threaded, NumPy initialized BLAS widths preserved.',
        generator_import_blas_settings=blas_settings,
        source_manifest_sha256=sha256_file(S/'manifest.json'),recovery_manifest_sha256=sha256_file(E/'manifest.json')))
    engine=study.Engine(p,write=False);frames={}
    for seed in study.FIT+study.CAL:
        role='fit' if seed in study.FIT else 'calibration'
        task=dict(alias=f'{role}-{seed}',seed=seed,mode='clean',family='unrestricted',attackers=['client01','client06','client13'],role=role)
        result,_,obs=engine.history(task,[],True,10)
        assert result==read(S/'calibration-histories'/f'{seed}.json');frames[seed]=obs
        print(json.dumps(dict(replayed_clean_calibration=seed)),flush=True)
    ref=fit_reference([frames[s] for s in study.FIT]);cal=calibrate([frames[s] for s in study.CAL],ref)
    assert ref==read(S/'reference.json') and cal==read(S/'calibration.json');del frames,engine
    results=[]
    with ProcessPoolExecutor(max_workers=2,mp_context=multiprocessing.get_context('spawn')) as pool:
        futures=[pool.submit(verify_seed,seed,blas_settings) for seed in study.ASSIGN]
        for future in as_completed(futures):results.append(future.result())
    planned=read(D/'recovery-plan-before-effects.json')
    branches=sum(r['recovery_branches'] for r in results);rounds=sum(r['source_rounds'] for r in results)
    assert branches==planned['requested_replay_branches'] and rounds==15*len(p['tasks'])
    study.check(p);authenticate(S,read(D/'source-closure.json')['manifest_sha256'])
    authenticate(E,read(D/'recovery-closure.json')['manifest_sha256'])
    record=dict(status='fresh_histories_selection_and_origin_recovery_replayed',clean_fit_calibration_rounds=50,
        source_rounds=rounds,recovery_branches=branches,recovery_rounds=sum(r['recovery_rounds'] for r in results),
        adaptive_queries=sum(r['adaptive_queries'] for r in results),
        clean_reference_histories_checked=sum(r['clean_reference_histories_checked'] for r in results),
        software_manifests_authenticated=True,same_implementation_replay=True,new_TPM_quotes=0,test_inference=False,
        default_changed=False,verification_workers=2,workers=sorted(results,key=lambda r:r['seed']),storage=study.guard())
    save(D/'verification.json',record);print(json.dumps(record,indent=2),flush=True)

if __name__=='__main__':main()
