"""Fresh final-beta study plus explicitly known clean continuity cases.

The original generation engine is reused without on-disk modification. A new
numerical operator keeps admission alpha/counts distinct from final beta.
"""
from __future__ import annotations
import argparse,copy,hashlib,json,multiprocessing,time
from concurrent.futures import ProcessPoolExecutor,as_completed
from fractions import Fraction
from pathlib import Path
import revision_gate_trajectories as base
from capped_final_aggregation import aggregate_capped_final
from revision_study_data import read,Generator
from revision_dba_experiment import save,authenticate,environment
from fl_forensics.canonical import sha256_file
from fl_forensics.bounded_aggregation import digest as derivation_digest,record
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded
from fl_forensics.federated_model import arrays_from_export

ROOT=base.ROOT;LAB=ROOT/'artifacts/revision-capped-final-v1'
OLD=ROOT/'artifacts/revision-severe-tail-gate-v1'
ORIGINAL_CONTEXT=base.context;ORIGINAL_STATE=base.gate_state;ORIGINAL_NUMERICAL=base.numerical
METHODS=('tpm_only','robust_bounded','capped_sample','capped_robust')
SPECIAL=METHODS[1:]
RESERVED=[('iid',6116101,['client02','client08','client14']),('iid',6116102,['client03','client07','client12']),
    ('iid',6116103,['client04','client09','client15']),('non-iid',6116104,['client01','client06','client13']),
    ('non-iid',6116105,['client05','client10','client14']),('non-iid',6116106,['client02','client07','client11'])]
KNOWN=[('non-iid',2026110734),('non-iid',2026110735),('non-iid',2026110736)]


def source_locks():
    paths=sorted((ROOT/'src/fl_forensics').glob('*.py'))
    paths += [ROOT/'scripts'/name for name in ('revision_gate_trajectories.py','revision_study_data.py',
        'revision_dba_experiment.py','admission_mass_safety.py','capped_final_aggregation.py','revision_capped_final_study.py')]
    paths += [ROOT/'configs/in-round-admission.yaml',ROOT/'tests/test_capped_final_aggregation.py']
    return {str(p.relative_to(ROOT)):sha256_file(p) for p in paths}


def assert_locks(protocol):
    base.require(source_locks()==protocol['source_locks'],'Frozen capped-profile generation changed')
    for cohort,pin in protocol['tensor_references'].items():
        base.require(sha256_file(ROOT/pin['path'])==pin['sha256'],'Clean tensor reference changed')


def context(protocol,task):
    gen,rows,correct=ORIGINAL_CONTEXT(protocol,task)
    reference=protocol['tensor_references'][task['cohort']]
    gen.tensor_reference=read(ROOT/reference['path']);gen.tensor_reference_sha256=reference['sha256']
    initial=arrays_from_export(gen.initial,np=base.np)
    base.require([int(v.size) for v in initial]==gen.tensor_reference['sizes'],'Tensor reference schema mismatch')
    gen.final_weight_cache={};gen.disable_final_weight_cache=False
    return gen,rows,correct


def gate_state(initial,exports,gen,settings,rows):
    state,arrays=ORIGINAL_STATE(initial,exports,gen,settings,rows)
    for client in gen.clients:
        for method in SPECIAL:
            # This is an aggregation key, not a new hard-admission decision.
            state['decisions'][client][method]=copy.deepcopy(state['decisions'][client]['tpm_only'])
    state['actual_admission_policy']='tpm_only'
    state['operator_scope']='New robust/capped keys share mandatory-trust admission. Original statistical decisions remain diagnostic controls.'
    return state,arrays


def numerical(initial,local_arrays,gen,state,settings,policy):
    if policy not in SPECIAL:return ORIGINAL_NUMERICAL(initial,local_arrays,gen,state,settings,policy)
    masses={c:Fraction(len(gen.rows[c])) if state['decisions'][c]['tpm_only']['contributes'] else Fraction() for c in gen.clients}
    gates={c:state['decisions'][c]['tpm_only']['contributes'] for c in gen.clients}
    fingerprint=hashlib.sha256()
    for array_list in local_arrays:
        for value in array_list:fingerprint.update(value.tobytes())
    key=(base.digest(initial),fingerprint.hexdigest(),policy,tuple(masses.items()))
    cached=not gen.disable_final_weight_cache and key in gen.final_weight_cache
    if cached:model,coefficients,report,elapsed=gen.final_weight_cache[key]
    else:
        started=time.perf_counter();reference=gen.tensor_reference
        initial_arrays=arrays_from_export(initial,np=base.np)
        updates=dict(zip(gen.clients,local_arrays,strict=True))
        common=dict(masses={c:str(v) for c,v in masses.items()},mandatory_gates=gates,
            limits=reference['limits'],reference_digest=derivation_digest(reference),minimum_contributors=settings['minimum_contributors'])
        if policy=='robust_bounded':
            parameters,report=aggregate_robust_bounded(initial_arrays,updates,**common,max_iterations=50)
            coefficients=report.get('final_coefficients') if parameters is not None else None
        else:
            parameters,report=aggregate_capped_final(initial_arrays,updates,**common,
                nominal_counts={c:len(gen.rows[c]) for c in gen.clients},
                proposal='sample' if policy=='capped_sample' else 'robust',minimum_retained_mass=Fraction(4,5),
                maximum_group_size=3,maximum_group_share=Fraction(1,3),max_iterations=50)
            coefficients=report['beta'] if parameters is not None else None
        model=base.model_with_arrays(initial,parameters) if parameters is not None else None
        report=copy.deepcopy(report)
        report['exported_checkpoint_sha256']=base.digest(model) if model is not None else None
        if parameters is not None:
            actual=arrays_from_export(model,np=base.np)
            report['export_rounding_l2_per_tensor']=[float(base.np.linalg.norm(a.astype(float)-b)) for a,b in zip(actual,parameters,strict=True)]
        elapsed=time.perf_counter()-started
        if not gen.disable_final_weight_cache:
            if len(gen.final_weight_cache)>16:gen.final_weight_cache.clear()
            gen.final_weight_cache[key]=(model,coefficients,report,elapsed)
    state['selected_aggregation_operator']=policy;state['selected_aggregation_derivation']=report
    state['timing']['final_operator_seconds']=elapsed
    return model,masses,coefficients


def configure():
    base.LAB=LAB;base.context=context;base.gate_state=gate_state;base.numerical=numerical;base.assert_locks=assert_locks
    # Common-input controls retain the original four decision rules. New
    # operators are compared through their own actually trained histories.
    base.POLICIES=('tpm_only','sequential','gated_composite')


def worker(task):configure();return base.run_case(task)


def run(workers):
    p=read(LAB/'protocol-before-training.json');assert_locks(p)
    if (LAB/'training-complete.json').exists():return read(LAB/'training-complete.json')
    results=[]
    with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
        futures={pool.submit(worker,t):t for t in p['tasks']}
        for future in as_completed(futures):
            task=futures[future]
            try:result=future.result()
            except Exception as exc:
                evidence=LAB/'cases'/task['name']/'evidence'
                error=dict(task=task,complete=False,error=str(exc),exception_type=type(exc).__name__)
                save(evidence/'terminal-exception.json',error)
                if not (evidence/'manifest.json').exists():Generator.close(evidence)
                result={**error,'completed_rounds':len(list(evidence.glob('rounds/round-*/round.json'))),
                        'manifest_sha256':sha256_file(evidence/'manifest.json')}
                if not (evidence.parent/'result.json').exists():save(evidence.parent/'result.json',result)
            results.append(result)
            (LAB/'progress.json').write_text(json.dumps(dict(terminal_cases=len(results),planned_cases=len(p['tasks']),
                complete_cases=sum(r['complete'] for r in results)),sort_keys=True)+'\n')
            print('CASE '+json.dumps(dict(name=task['name'],complete=result['complete'])),flush=True)
    assert_locks(p)
    closed=dict(protocol_sha256=sha256_file(LAB/'protocol-before-training.json'),
        results=sorted(results,key=lambda r:r['task']['name']),test_inference_performed=False)
    save(LAB/'training-complete.json',closed);return closed


def prepare():
    base.require(not LAB.exists(),'Preserve previous capped-final study')
    prior=read(ROOT/'artifacts/revision-gate-trajectories-v1/protocol-before-training.json')
    original=ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1';manifest=read(original/'manifest.json')
    union=[];seen=set()
    for entry in manifest['clients']:
        path=original/entry['dataset_path'];base.require(sha256_file(path)==entry['dataset_sha256'],'Changed training snapshot')
        for row in read(path)['rows']['train']:
            base.require(row['window_id'] not in seen,'Repeated training occurrence');seen.add(row['window_id']);union.append(row)
    LAB.mkdir();(LAB/'partitions').mkdir();partitions={}
    for cohort,seed in KNOWN:
        source=OLD/'partitions'/str(seed)
        expected=read(OLD/'protocol-before-clean-fitting.json')['partitions'][str(seed)]
        base.require(sha256_file(source/'manifest.json')==expected,'Known clean partition changed')
        (LAB/'partitions'/str(seed)).symlink_to(source,target_is_directory=True);partitions[str(seed)]=expected
    for cohort,seed,_ in RESERVED:
        allocation=base._iid_assignments(union,client_count=15,seed=seed,np=base.np) if cohort=='iid' else \
            base._dirichlet_assignments(union,client_count=15,seed=seed,alpha=.3,minimum_rows=32,np=base.np)
        base.require({r['window_id'] for rs in allocation for r in rs}==seen and sum(map(len,allocation))==len(seen),'Partition coverage')
        folder=LAB/'partitions'/str(seed);clients=[]
        for i,rows in enumerate(allocation):
            c=f'client{i+1:02d}';path=folder/'clients'/c/'dataset.json'
            save(path,dict(client_id=c,partition_id=i,class_names=manifest['class_names'],rows={'train':rows}))
            clients.append(dict(client_id=c,partition_id=i,dataset_path=str(path.relative_to(folder)),
                dataset_sha256=sha256_file(path),train_row_count=len(rows)))
        save(folder/'manifest.json',dict(profile='capped-final-training-only-partition-v1',seed=seed,partition_mode=cohort,
            class_names=manifest['class_names'],global_class_weights=manifest['global_class_weights'],clients=clients,
            training_occurrences=len(seen),M3_full_profile_verification_claimed=False))
        partitions[str(seed)]=sha256_file(folder/'manifest.json')
    tasks=[]
    for cohort,seed in KNOWN:
        for method in METHODS:
            tasks.append(dict(name=f'known-{cohort}-s{seed}-{method}-clean',cohort=cohort,seed=seed,
                attackers=['client01','client06','client11'],policy=method,method=method,mode='clean',split='known_clean'))
    for cohort,seed,attackers in RESERVED:
        for method in METHODS:
            for mode in base.MODES:
                tasks.append(dict(name=f'reserved-{cohort}-s{seed}-{method}-{mode}',cohort=cohort,seed=seed,
                    attackers=attackers,policy=method,method=method,mode=mode,split='reserved'))
    refs={}
    for cohort in ('iid','non-iid'):
        path=ROOT/'artifacts/revision-bounded-influence-v1'/f'{cohort}-bounds.json'
        reference=read(path);base.require(reference['reference_update_count']==3675,'Unexpected clean reference bank')
        refs[cohort]=dict(path=str(path.relative_to(ROOT)),sha256=sha256_file(path),updates=3675,
            source='Historical clean normal and generic-state-perturbed updates; fixed99th higher per-tensor norms, no new fitting.')
    p=dict(profile='explicit-capped-final-beta-study-v1',tasks=tasks,horizon=15,attack_rounds=list(range(1,11)),
        clean_continuation_rounds=list(range(11,16)),training=prior['training'],runtime_admission=prior['runtime_admission'],
        partitions=partitions,source_snapshots=prior['source_snapshots'],tensor_references=refs,source_locks=source_locks(),
        methods=METHODS,known_clean=KNOWN,reserved=RESERVED,environment=environment(),
        contract='Admission counts/masses/alpha and retained data are unchanged. Final beta is separately derived after tensor clipping and a sample/finite robust proposal; per-client cap1/9 guarantees every at-most-three share<=1/3. Quorum10 and admission retention>=4/5 remain mandatory; zero gates/masses cannot be resurrected.',
        admission='All four numerical arms use the same mandatory-trust-only admission from the outset. Existing hard-statistical profiles are not edited or retroactively re-admitted. Original statistical decisions are diagnostic. This studies aggregation containment, not a new attacker classifier.',
        measurement='Report actual admission retention AND alpha-to-beta total variation and clean utility. Preserved data counts do not imply preserved sample-weighted objective or an unchanged model.',
        validation='All nine clean known/reserved assignments must complete15 rounds with exact cap/retention checks. Predeclared clean utility: at most .02 macro-F1 loss vs paired raw FedAvg at validation/test rounds10/15. No attack/test selection or automatic promotion. Primary numerical security comparison is capped_robust versus uncapped robust_bounded, paired worst-trigger peak harm; also report capped_sample ablation and raw FedAvg controls, all failures and all peaks/finals.',
        primary_security_guard='Reserved capped_robust cases all complete, every clean utility guard, no greater paired worst-trigger peak harm than uncapped robust in all18 defined comparisons, strict benefit in at least two effective raw-control cases including non-IID. These finite exploratory checks do not prove universal robustness.',
        evaluation='Test only after all108 training cases terminal. Same historical Data24 test has been inspected before: exploratory new seed/partition/identity assignments, not independent data/initializations. Known clean cases are explicit mechanism replications. Adaptive alpha0,.25,.5,1,2,4 queries each actual defender; no clean-utility constraint in attack objective.',
        caching='Generation caches repeated numerical calls on identical base/update/mass/operator inputs within each case. Audit disables this cache. Recorded operator cost is the first full computation, not cache lookup.',
        mandatory_trust='Software research assumption of passed prerequisite trust. No new TPM Quote, client-signature or physical hardware claim.',
        new_TPM_quotes=0,thesis_edited=False)
    save(LAB/'protocol-before-training.json',p)
    (LAB/'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(prepared=True,tasks=len(tasks),protocol_sha256=sha256_file(LAB/'protocol-before-training.json'))))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=('prepare','run','pipeline'))
    parser.add_argument('--workers',type=int,default=3);args=parser.parse_args()
    if args.command=='prepare':prepare()
    else:
        if args.command=='pipeline' and not LAB.exists():prepare()
        run(args.workers)
        if args.command=='pipeline':
            from revision_capped_final_audit import verify
            verify(args.workers)


if __name__=='__main__':main()
