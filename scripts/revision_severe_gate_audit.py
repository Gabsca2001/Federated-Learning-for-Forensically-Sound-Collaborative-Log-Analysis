"""Saved-update replay; clean stages never open the test split."""
from __future__ import annotations
import argparse
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor,as_completed
from pathlib import Path
import revision_severe_gate_study as study
import revision_gate_trajectories_audit as legacy_audit
from revision_study_data import read
from revision_dba_experiment import authenticate,save,outcomes,predict,evaluate
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

base=study.base


def same(actual,expected,label):base.require(actual==expected,label)


def audit_case(result,phase,test_enabled):
    study.configure(phase);task=result['task']
    if task.get('candidate'):base.POLICIES=(*study.ORIGINAL_POLICIES,'calibrated_gated','calibrated_sequential','calibrated_no_band')
    folder=study.LAB/phase;protocol=read(folder/'protocol-before-training.json');study.assert_locks(protocol)
    source=folder/'cases'/task['name']/'evidence';authenticate(source,result['manifest_sha256'])
    gen,rows,correct=study.context(protocol,task);settings=base.settings_for(protocol);plan=base.make_plan(protocol,task)
    test_rows=test_correct=None
    if test_enabled:
        base.require(phase=='evaluation' and (folder/'training-complete.json').exists(),'Test before evaluation closure')
        same(sha256_file(study.LAB/'selection-decision.json'),protocol['selection_decision_sha256'],'Clean selection pin')
        selection=read(study.LAB/'selection-decision.json')
        base.require(not selection['uses_attack_or_test_outcomes'],'Outcome-contaminated selection')
        if task.get('method')=='severe_gate':
            same(task['candidate'],selection['selected_candidate'],'Selected candidate binding')
        if task.get('method')=='mean_control':same(task['candidate'],'mean_control','Mean control binding')
        original=study.ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1'
        same(sha256_file(original/'manifest.json'),protocol['source_snapshots'][str(original/'manifest.json')],'Evaluation manifest pin')
        test=read(original/'manifest.json')['server_evaluation_splits']['test'];path=original/test['path']
        same(sha256_file(path),test['sha256'],'Test pin')
        test_rows=read(path)['rows']['test']
        ids={r['window_id'] for r in test_rows};train={r['window_id'] for rs in gen.rows.values() for r in rs}
        base.require(len(ids)==len(test_rows) and not(ids & (train|{r['window_id'] for r in rows})),'Split overlap')
        predicted,_=predict(gen.initial,test_rows,gen.deps);test_correct=[a==r['label'] for a,r in zip(predicted,test_rows,strict=True)]
    output=[];queries=repeats=0;previous=gen.initial
    for number in range(1,result.get('completed_rounds',0)+1):
        gen.gate_round=number;target=source/'rounds'/f'round-{number:03d}'
        row=read(target/'round.json');initial=read(target/'base-model.json');same(initial,previous,'Checkpoint chain')
        exports=[read(target/'updates'/f'{c}.json') for c in gen.clients]
        state,arrays=study.gate_state(initial,exports,gen,settings,rows)
        stored=read(target/'gate-state.json')
        same({k:v for k,v in state.items() if k!='timing'},{k:v for k,v in stored.items() if k!='timing'},'Indicator/policy replay')
        model,masses,co=base.numerical(initial,arrays,gen,state,settings,task['policy'])
        same(model,read(target/'global-model.json'),'Flower output replay')
        same(base.digest(model),row['global_model_sha256'],'Checkpoint commitment')
        same({c:str(v) for c,v in masses.items()},row['masses'],'Mass replay');same(co,row['coefficients'],'Coefficient replay')
        same(evaluate(model,rows,gen.deps),row['validation']['clean'],'Clean validation replay')
        controls=read(target/'common-input-comparison.json')
        for policy in (*base.POLICIES,'composite_no_band'):
            alternate,_,coefficients=base.numerical(initial,arrays,gen,state,settings,policy)
            same(dict(defined=alternate is not None,model_sha256=base.digest(alternate) if alternate else None,
                      coefficients=coefficients),controls[policy],'Counterfactual replay')
        if task.get('candidate'):
            same(controls['calibrated_sequential']['model_sha256'],controls['calibrated_no_band']['model_sha256'],
                 'Calibrated numerical negative control')
        active=task['mode']!='clean' and number<=10
        if task['mode']=='adaptive' and active:
            transcript=read(target/'query-transcript.json');same([q['alpha'] for q in transcript],list(base.ALPHAS),'Query budget')
            clean=list(exports);poison=list(exports)
            for c in task['attackers']:
                i=gen.clients.index(c);clean[i]=read(target/'attack-endpoints'/f'{c}-clean.json')
                poison[i]=read(target/'attack-endpoints'/f'{c}-poison.json')
            ca=[arrays_from_export(e,np=base.np) for e in clean];pa=[arrays_from_export(e,np=base.np) for e in poison]
            rankings=[]
            for query in transcript:
                alpha=query['alpha'];candidate=[base.model_with_arrays(clean[i],[a+alpha*(b.astype(float)-a) for a,b in zip(ca[i],pa[i],strict=True)])
                    if c in task['attackers'] else clean[i] for i,c in enumerate(gen.clients)]
                rank=legacy_audit.replay_candidate(initial,candidate,gen,settings,rows,plan,correct,task,query)
                queries+=1
                if rank is not None:rankings.append(rank)
            same(max(rankings)[2],row['selected_alpha'],'Adaptive selection')
        if number in (1,15):
            actual_plan=plan if active and task['mode']!='adaptive' else None
            repeated,_=base.train_one(gen,initial,task['seed'],number,gen.clients[0],actual_plan,distributed=task['mode']!='complete-trigger')
            expected=read(target/'attack-endpoints'/f'{gen.clients[0]}-clean.json') \
                if task['mode']=='adaptive' and active and gen.clients[0] in task['attackers'] else exports[0]
            same(repeated,expected,'Independent local training');repeats+=1
        record=dict(round=number,validation_clean=row['validation']['clean'],statuses=row['statuses'],masses=row['masses'],
                    example_counts={c:len(gen.rows[c]) for c in gen.clients},selected_alpha=row['selected_alpha'],
                    actually_manipulated_clients=row['actually_manipulated_clients'],coefficients=co,
                    timing={k:v for k,v in row.items() if k.endswith('_seconds')})
        if test_enabled:record['test']=outcomes(model,test_rows,plan,test_correct,gen.deps)
        output.append(record);previous=model
    failure_verified=False
    if result.get('failure') and result['failure'].get('classification')=='quorum':
        number=result['failure']['round'];gen.gate_round=number;target=source/'rounds'/f'round-{number:03d}'
        initial=read(target/'base-model.json');same(initial,previous,'Failed base chain')
        if (target/'gate-state.json').exists():
            exports=[read(target/'updates'/f'{c}.json') for c in gen.clients]
            state,arrays=study.gate_state(initial,exports,gen,settings,rows)
            model,_,_=base.numerical(initial,arrays,gen,state,settings,task['policy'])
            same(model,None,'Declared quorum failure');failure_verified=True
        else:
            clean,_=base.train_all(gen,initial,task['seed'],number);poison=list(clean)
            for c in task['attackers']:poison[gen.clients.index(c)]=read(target/'attack-endpoints'/f'{c}-poison.json')
            ca=[arrays_from_export(e,np=base.np) for e in clean];pa=[arrays_from_export(e,np=base.np) for e in poison]
            for q in read(target/'query-transcript.json'):
                alpha=q['alpha'];candidate=[base.model_with_arrays(clean[i],[a+alpha*(b.astype(float)-a) for a,b in zip(ca[i],pa[i],strict=True)])
                    if c in task['attackers'] else clean[i] for i,c in enumerate(gen.clients)]
                same(legacy_audit.replay_candidate(initial,candidate,gen,settings,rows,plan,correct,task,q),None,'Failed query')
                queries+=1
            failure_verified=True
    study.assert_locks(protocol)
    return dict(task=task,complete=result['complete'],completed_rounds=len(output),failure=result.get('failure'),
        source_exception=result.get('error'),source_manifest_sha256=result['manifest_sha256'],rows=output,
        verification=dict(rounds=len(output),queries=queries,local_repeats=repeats,
                          clean_only=not test_enabled,quorum_failure_verified=failure_verified),test_accessed=test_enabled)


def verify_phase(phase,workers=3):
    folder=study.LAB/phase;closure=read(folder/'training-complete.json')
    p=read(folder/'protocol-before-training.json');study.assert_locks(p)
    same(closure['protocol_sha256'],sha256_file(folder/'protocol-before-training.json'),'Closed protocol')
    same(len(closure['results']),len(p['tasks']),'Incomplete phase')
    path=folder/'verified/summary.json'
    if path.exists():
        saved=read(path);same(saved['training_closure_sha256'],sha256_file(folder/'training-complete.json'),'Verification closure pin')
        return saved
    (folder/'verified').mkdir()
    save(folder/'verified/verification-before-reading.json',dict(phase=phase,verifier_sha256=sha256_file(Path(__file__)),
        test_enabled=phase=='evaluation',training_closure_sha256=sha256_file(folder/'training-complete.json')))
    cases=[]
    with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
        futures=[pool.submit(audit_case,r,phase,phase=='evaluation') for r in closure['results']]
        for future in as_completed(futures):
            result=future.result();save(folder/'verified/cases'/f'{result["task"]["name"]}.json',result);cases.append(result)
            print('VERIFIED_CASE '+json.dumps(dict(phase=phase,case=result['task']['name'],rounds=result['completed_rounds'])),flush=True)
    saved=dict(status='verified',training_closure_sha256=sha256_file(folder/'training-complete.json'),
               verifier_sha256=sha256_file(Path(__file__)),test_accessed=phase=='evaluation',cases=sorted(cases,key=lambda r:r['task']['name']))
    save(path,saved);return saved


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=tuple(study.STAGES));parser.add_argument('--workers',type=int,default=3)
    args=parser.parse_args();verify_phase(args.phase,args.workers)
