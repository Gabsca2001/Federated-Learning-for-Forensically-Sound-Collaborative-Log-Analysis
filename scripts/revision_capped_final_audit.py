"""Fresh-cache artifact replay, coefficient certificates and closed-test evaluation."""
from __future__ import annotations
import argparse,json,multiprocessing
from concurrent.futures import ProcessPoolExecutor,as_completed
from fractions import Fraction
from pathlib import Path
import revision_capped_final_study as study
import revision_gate_trajectories_audit as legacy
from revision_study_data import read
from revision_dba_experiment import save,authenticate,outcomes,predict,evaluate
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

base=study.base
def same(a,b,label):base.require(a==b,label)


def audit_case(result):
    study.configure();protocol=read(study.LAB/'protocol-before-training.json');study.assert_locks(protocol)
    base.require((study.LAB/'training-complete.json').exists(),'Test before training closure')
    task=result['task'];source=study.LAB/'cases'/task['name']/'evidence';authenticate(source,result['manifest_sha256'])
    gen,validation,correct_validation=study.context(protocol,task);gen.disable_final_weight_cache=True
    settings=base.settings_for(protocol);plan=base.make_plan(protocol,task)
    original=study.ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1'
    same(sha256_file(original/'manifest.json'),protocol['source_snapshots'][str(original/'manifest.json')],'Original manifest pin')
    test_entry=read(original/'manifest.json')['server_evaluation_splits']['test'];path=original/test_entry['path']
    same(sha256_file(path),test_entry['sha256'],'Test pin');test=read(path)['rows']['test']
    ids={r['window_id'] for r in test};train={r['window_id'] for rs in gen.rows.values() for r in rs}
    base.require(len(ids)==len(test) and not(ids & (train|{r['window_id'] for r in validation})),'Split overlap')
    predicted,_=predict(gen.initial,test,gen.deps);correct=[p==r['label'] for p,r in zip(predicted,test,strict=True)]
    rows=[];queries=repeats=certificates=known_reproduced=0;previous=gen.initial
    for number in range(1,result.get('completed_rounds',0)+1):
        folder=source/'rounds'/f'round-{number:03d}';row=read(folder/'round.json');initial=read(folder/'base-model.json')
        same(initial,previous,'Parent chain')
        exports=[read(folder/'updates'/f'{c}.json') for c in gen.clients]
        state,arrays=study.gate_state(initial,exports,gen,settings,validation)
        model,masses,coefficients=study.numerical(initial,arrays,gen,state,settings,task['policy'])
        stored=read(folder/'gate-state.json')
        same({k:v for k,v in state.items() if k!='timing'},{k:v for k,v in stored.items() if k!='timing'},'Full state/derivation replay')
        same(model,read(folder/'global-model.json'),'Actual checkpoint')
        same(base.digest(model),row['global_model_sha256'],'Checkpoint digest')
        same({c:str(v) for c,v in masses.items()},row['masses'],'Admission masses')
        same(coefficients,row['coefficients'],'Actual numerical coefficients')
        same(outcomes(model,validation,plan,correct_validation,gen.deps),row['validation'],'Validation replay')
        if task['method'].startswith('capped_'):
            report=stored['selected_aggregation_derivation'];alpha=report['admission']['alpha'];beta=report['beta']
            same(report['admission']['retained_nominal_mass'],'1','No hard statistical readmission or hidden mass loss')
            same(alpha,{c:str(Fraction(masses[c])/sum(masses.values())) for c in gen.clients},'Admission alpha')
            same(beta,coefficients,'Projected beta')
            base.require(sum(Fraction(v) for v in beta.values())==1,'Unnormalized beta')
            base.require(all(0<=Fraction(v)<=Fraction(1,9) for v in beta.values()),'Individual cap')
            base.require(sum(sorted((Fraction(v) for v in beta.values()),reverse=True)[:3])<=Fraction(1,3),'Group cap')
            certificates+=1
        controls=read(folder/'common-input-comparison.json')
        for policy in (*base.POLICIES,'composite_no_band'):
            alternate,_,co=study.numerical(initial,arrays,gen,state,settings,policy)
            same(dict(defined=alternate is not None,model_sha256=base.digest(alternate) if alternate else None,
                coefficients=co),controls[policy],'Original common-input control')
        same(controls['sequential']['model_sha256'],controls['composite_no_band']['model_sha256'],'No-band negative control')
        active=task['mode']!='clean' and number<=10
        if task['mode']=='adaptive' and active:
            transcript=read(folder/'query-transcript.json');same([q['alpha'] for q in transcript],list(base.ALPHAS),'Adaptive query budget')
            clean=list(exports);poison=list(exports)
            for c in task['attackers']:
                i=gen.clients.index(c);clean[i]=read(folder/'attack-endpoints'/f'{c}-clean.json')
                poison[i]=read(folder/'attack-endpoints'/f'{c}-poison.json')
            ca=[arrays_from_export(e,np=base.np) for e in clean];pa=[arrays_from_export(e,np=base.np) for e in poison]
            ranks=[]
            for query in transcript:
                alpha=query['alpha']
                candidate=[base.model_with_arrays(clean[i],[a+alpha*(b.astype(float)-a) for a,b in zip(ca[i],pa[i],strict=True)])
                    if c in task['attackers'] else clean[i] for i,c in enumerate(gen.clients)]
                rank=legacy.replay_candidate(initial,candidate,gen,settings,validation,plan,correct_validation,task,query)
                queries+=1
                if rank is not None:ranks.append(rank)
            same(max(ranks)[2],row['selected_alpha'],'Chosen adaptive export')
        if number in (1,15):
            actual_plan=plan if active and task['mode']!='adaptive' else None
            actual,_=base.train_one(gen,initial,task['seed'],number,gen.clients[0],actual_plan,distributed=task['mode']!='complete-trigger')
            expected=read(folder/'attack-endpoints'/f'{gen.clients[0]}-clean.json') \
                if active and task['mode']=='adaptive' and gen.clients[0] in task['attackers'] else exports[0]
            same(actual,expected,'Repeated local training');repeats+=1
        if task['split']=='known_clean' and task['method']=='tpm_only':
            old=study.OLD/'evaluation/cases'/f'{task["cohort"]}-s{task["seed"]}-tpm_only-clean/evidence/rounds'/f'round-{number:03d}'/'global-model.json'
            same(model,read(old),'Known original FedAvg trajectory exact reproduction');known_reproduced+=1
        operator=stored.get('selected_aggregation_derivation')
        final=tuple(Fraction(v) for v in coefficients.values())
        original_alpha={c:Fraction(masses[c])/sum(masses.values()) for c in gen.clients}
        rows.append(dict(round=number,statuses=row['statuses'],masses=row['masses'],coefficients=coefficients,
            example_counts={c:len(gen.rows[c]) for c in gen.clients},selected_alpha=row['selected_alpha'],
            actually_manipulated_clients=row['actually_manipulated_clients'],validation_clean=row['validation']['clean'],
            test=outcomes(model,test,plan,correct,gen.deps),
            retained_nominal_mass=str(sum(masses.values())/sum(len(gen.rows[c]) for c in gen.clients)),
            maximum_three_final_share=str(sum(sorted(final,reverse=True)[:3])),
            alpha_beta_total_variation=str(sum(abs(Fraction(coefficients[c])-original_alpha[c]) for c in gen.clients)/2),
            operator_derivation_sha256=base.digest(operator) if operator else None,
            timing={k:v for k,v in row.items() if k.endswith('_seconds')}))
        previous=model
    # No undefined endpoint is replaced by zero. Unexpected terminals remain
    # explicit source exceptions, not certified quorum/attack results.
    study.assert_locks(protocol)
    return dict(task=task,complete=result['complete'],completed_rounds=len(rows),failure=result.get('failure'),
        source_exception=result.get('error'),source_manifest_sha256=result['manifest_sha256'],rows=rows,
        verification=dict(rounds=len(rows),queries=queries,local_repeats=repeats,cap_certificates=certificates,
            known_original_rounds_reproduced=known_reproduced,cache_disabled=True),test_accessed=True)


def verify(workers=3):
    closure=read(study.LAB/'training-complete.json');protocol=read(study.LAB/'protocol-before-training.json')
    study.assert_locks(protocol);same(closure['protocol_sha256'],sha256_file(study.LAB/'protocol-before-training.json'),'Closure pin')
    same(len(closure['results']),len(protocol['tasks']),'Terminal count')
    destination=study.LAB/'verified'
    if (destination/'summary.json').exists():
        saved=read(destination/'summary.json');same(saved['training_closure_sha256'],sha256_file(study.LAB/'training-complete.json'),'Audit closure pin');return saved
    destination.mkdir()
    save(destination/'verification-before-reading.json',dict(verifier_sha256=sha256_file(Path(__file__)),
        training_closure_sha256=sha256_file(study.LAB/'training-complete.json'),test_enabled=True))
    cases=[]
    with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
        futures=[pool.submit(audit_case,r) for r in closure['results']]
        for future in as_completed(futures):
            result=future.result();save(destination/'cases'/f'{result["task"]["name"]}.json',result);cases.append(result)
            print('VERIFIED '+json.dumps(dict(case=result['task']['name'],rounds=result['completed_rounds'])),flush=True)
    saved=dict(status='verified',cases=sorted(cases,key=lambda c:c['task']['name']),test_accessed=True,
        verifier_sha256=sha256_file(Path(__file__)),training_closure_sha256=sha256_file(study.LAB/'training-complete.json'))
    save(destination/'summary.json',saved);return saved


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--workers',type=int,default=3)
    verify(parser.parse_args().workers)
