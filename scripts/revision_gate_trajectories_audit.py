"""Independent saved-artifact replay and post-training evaluation of gate histories."""
from __future__ import annotations
import argparse
import csv
import json
import multiprocessing
import statistics
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import revision_gate_trajectories as study
import numpy as np
from revision_dba_experiment import authenticate, outcomes, predict, save
from revision_study_data import read
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export

ROOT, LAB = study.ROOT, study.LAB


def check_equal(actual, expected, label):
    study.require(actual == expected, label)


def replay_candidate(base, exports, gen, settings, rows, plan, correct, task, item):
    state, arrays = study.gate_state(base,exports,gen,settings,rows)
    model,_,_ = study.numerical(base,arrays,gen,state,settings,task['policy'])
    check_equal(state['decisions'],item['decisions'],'Candidate decision vector differs')
    check_equal({c:study.digest(e) for c,e in zip(gen.clients,exports,strict=True)},
                item['candidate_update_sha256'],'Candidate bytes differ')
    check_equal(model is not None,item['feasible'],'Candidate feasibility differs')
    if model is None:
        check_equal(item['objective'],None,'Undefined candidate was scored')
        return None
    metric = outcomes(model,rows,plan,correct,gen.deps)
    check_equal(study.scalar_asr(metric),item['objective'],'Candidate validation objective differs')
    check_equal(metric['complete_trigger']['asr'],item['full_trigger_asr'],'Candidate full ASR differs')
    check_equal({c:v['asr'] for c,v in metric['component_triggers'].items()},item['component_asr'],
                'Candidate component ASR differs')
    q = sum(not state['decisions'][c][task['policy']]['contributes'] for c in task['attackers'])
    check_equal(q,item['attacker_quarantines'],'Candidate quarantine count differs')
    return (item['objective'],-q,item['alpha'])


def audit_case(result):
    protocol = read(LAB/'protocol-before-training.json')
    study.assert_locks(protocol)
    task = result['task']; evidence = LAB/'cases'/task['name']/'evidence'
    authenticate(evidence,result['manifest_sha256'])
    gen,validation_rows,validation_correct = study.context(protocol,task)
    settings = study.settings_for(protocol); plan = study.make_plan(protocol,task)
    original = ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1'
    study.require(sha256_file(original/'manifest.json') ==
                  protocol['source_snapshots'][str(original/'manifest.json')],
                  'Original evaluation manifest changed after protocol closure')
    manifest = read(original/'manifest.json')
    test_entry = manifest['server_evaluation_splits']['test']
    test_path = original/test_entry['path']
    study.require(sha256_file(test_path)==test_entry['sha256'],'Test commitment differs')
    test_rows = read(test_path)['rows']['test']
    train_ids = {r['window_id'] for rs in gen.rows.values() for r in rs}
    val_ids = {r['window_id'] for r in validation_rows}
    test_ids = {r['window_id'] for r in test_rows}
    study.require(len(test_ids)==len(test_rows) and not (test_ids & (train_ids|val_ids)),
                  'Training/validation/test overlap')
    initial_predictions,_ = predict(gen.initial,test_rows,gen.deps)
    correct = [p==r['label'] for p,r in zip(initial_predictions,test_rows,strict=True)]
    rows, candidate_checks, training_checks, coefficient_rounds = [],0,0,0
    previous = gen.initial
    for number in range(1,result.get('completed_rounds',0)+1):
        target = evidence/'rounds'/f'round-{number:03d}'
        stored = read(target/'round.json')
        base = read(target/'base-model.json')
        check_equal(base,previous,'Successor base differs from previous deployed checkpoint')
        check_equal(study.digest(base),stored['base_model_sha256'],'Base commitment differs')
        exports = [read(target/'updates'/f'{c}.json') for c in gen.clients]
        recomputed,arrays = study.gate_state(base,exports,gen,settings,validation_rows)
        saved_state = read(target/'gate-state.json')
        check_equal({k:v for k,v in recomputed.items() if k!='timing'},
                    {k:v for k,v in saved_state.items() if k!='timing'},'Saved indicator/policy state differs')
        model,masses,coefficients = study.numerical(base,arrays,gen,recomputed,settings,task['policy'])
        check_equal(model,read(target/'global-model.json'),'Deployed numerical checkpoint differs')
        check_equal(study.digest(model),stored['global_model_sha256'],'Checkpoint commitment differs')
        check_equal({c:str(v) for c,v in masses.items()},stored['masses'],'Effective masses differ')
        check_equal(coefficients,stored['coefficients'],'Exact coefficients differ')
        check_equal(outcomes(model,validation_rows,plan,validation_correct,gen.deps),stored['validation'],
                    'Saved validation evaluation differs')
        common = read(target/'common-input-comparison.json')
        for policy in (*study.POLICIES,'composite_no_band'):
            alternate,_,co = study.numerical(base,arrays,gen,recomputed,settings,policy)
            expected = dict(defined=alternate is not None,model_sha256=study.digest(alternate) if alternate else None,
                            coefficients=co)
            check_equal(expected,common[policy],'Common-input control differs')
        check_equal(common['sequential']['model_sha256'],common['composite_no_band']['model_sha256'],
                    'No-band numerical control failed')
        coefficient_rounds += 1
        active = task['mode']!='clean' and number<=10
        if task['mode']=='adaptive' and active:
            transcript = read(target/'query-transcript.json')
            check_equal([t['alpha'] for t in transcript],list(study.ALPHAS),'Adaptive budget/order differs')
            clean = list(exports); poison = list(exports)
            for c in task['attackers']:
                i=gen.clients.index(c)
                clean[i]=read(target/'attack-endpoints'/f'{c}-clean.json')
                poison[i]=read(target/'attack-endpoints'/f'{c}-poison.json')
            ca=[arrays_from_export(e,np=np) for e in clean];pa=[arrays_from_export(e,np=np) for e in poison]
            ranks=[]
            for item in transcript:
                alpha=item['alpha']
                candidate=[study.model_with_arrays(clean[i],[a+alpha*(b.astype(float)-a) for a,b in zip(ca[i],pa[i],strict=True)])
                           if c in task['attackers'] else clean[i] for i,c in enumerate(gen.clients)]
                rank=replay_candidate(base,candidate,gen,settings,validation_rows,plan,validation_correct,task,item)
                candidate_checks += 1
                if rank is not None:ranks.append(rank)
            check_equal(max(ranks)[2],stored['selected_alpha'],'Selected adaptive candidate differs')
            chosen=next(t for t in transcript if t['alpha']==stored['selected_alpha'])
            check_equal(chosen['candidate_update_sha256'],
                        {c:study.digest(e) for c,e in zip(gen.clients,exports,strict=True)},'Deployed adaptive bytes differ')
        if number in (1,15):
            actual_plan = plan if active and task['mode']!='adaptive' else None
            repeated,_ = study.train_one(gen,base,task['seed'],number,gen.clients[0],actual_plan,
                                         distributed=task['mode']!='complete-trigger')
            expected = (read(target/'attack-endpoints'/f'{gen.clients[0]}-clean.json')
                        if task['mode']=='adaptive' and active and gen.clients[0] in task['attackers'] else exports[0])
            check_equal(repeated,expected,'Independent local training repeat differs')
            training_checks += 1
        test_metric=outcomes(model,test_rows,plan,correct,gen.deps)
        counts=Counter(); active_ids=set(stored['actually_manipulated_clients'])
        slot_attackers=set(task['attackers']) if active else set()
        for c,status in stored['statuses'].items():
            group='attacker_slot' if c in slot_attackers else 'benign'
            counts[group+'_total']+=1;counts[group+'_'+status]+=1
            actual_group='actual_manipulated' if c in active_ids else 'currently_unmodified'
            counts[actual_group+'_total']+=1
            counts[actual_group+'_'+status]+=1
        row=dict(round=number,attack_active=active,test=test_metric,**dict(counts))
        row['currently_unmodified_nominal_examples']=sum(len(gen.rows[c]) for c in gen.clients if c not in active_ids)
        row['currently_unmodified_effective_mass']=float(sum((masses[c] for c in gen.clients if c not in active_ids),study.Fraction()))
        row.update({k:stored[k] for k in ('training_seconds','aggregation_seconds','indicator_geometry_seconds',
                                         'validation_inference_seconds','score_and_all_policy_decisions_seconds',
                                         'attack_search_seconds','selected_alpha')})
        if coefficients:
            row['attacker_slot_normalized_share']=float(sum((study.Fraction(coefficients[c]) for c in slot_attackers),study.Fraction()))
        rows.append(row);previous=model
    # A quorum failure has no model; verify its terminal condition where bytes exist.
    failure=result.get('failure')
    failure_verified=False
    if failure and failure.get('classification')=='quorum':
        target=evidence/'rounds'/f'round-{failure["round"]:03d}'
        base=read(target/'base-model.json');check_equal(base,previous,'Failed-round base differs')
        if (target/'gate-state.json').exists():
            exports=[read(target/'updates'/f'{c}.json') for c in gen.clients]
            state,arrays=study.gate_state(base,exports,gen,settings,validation_rows)
            model,_,_=study.numerical(base,arrays,gen,state,settings,task['policy'])
            study.require(model is None,'Declared lost quorum actually aggregates')
            check_equal({k:v for k,v in state.items() if k!='timing'},
                        {k:v for k,v in read(target/'gate-state.json').items() if k!='timing'},'Failed-round gate differs')
            failure_verified=True
        else:
            clean,_=study.train_all(gen,base,task['seed'],failure['round'])
            poison=list(clean)
            for c in task['attackers']:poison[gen.clients.index(c)]=read(target/'attack-endpoints'/f'{c}-poison.json')
            ca=[arrays_from_export(e,np=np) for e in clean];pa=[arrays_from_export(e,np=np) for e in poison]
            transcript=read(target/'query-transcript.json')
            check_equal([t['alpha'] for t in transcript],list(study.ALPHAS),'Failed candidate budget differs')
            for item in transcript:
                alpha=item['alpha']
                exports=[study.model_with_arrays(clean[i],[a+alpha*(b.astype(float)-a) for a,b in zip(ca[i],pa[i],strict=True)])
                         if c in task['attackers'] else clean[i] for i,c in enumerate(gen.clients)]
                check_equal(replay_candidate(base,exports,gen,settings,validation_rows,plan,validation_correct,task,item),
                            None,'Failed adaptive candidate actually aggregates')
                candidate_checks+=1
            failure_verified=True
    study.assert_locks(protocol)
    return dict(task=task,complete=result['complete'],completed_rounds=len(rows),failure=failure,
        source_exception=result.get('error'),failure_condition_verified=failure_verified,
        source_manifest_sha256=result['manifest_sha256'],test_split_sha256=test_entry['sha256'],rows=rows,
        verification=dict(saved_rounds_reconstructed=coefficient_rounds,candidates_reconstructed=candidate_checks,
                          independent_local_training_repeats=training_checks,no_band_controls=coefficient_rounds,
                          all_source_artifact_hashes_and_software_signatures_verified=True,
                          fresh_TPM_appraisal=False))


def evaluate_study(workers, output_root):
    closure=read(LAB/'training-complete.json');protocol=read(LAB/'protocol-before-training.json')
    study.require(len(closure['results'])==len(protocol['tasks'])==72,'Training not terminal for all planned cases')
    study.require(closure['protocol_sha256']==sha256_file(LAB/'protocol-before-training.json'),'Protocol closure changed')
    out=output_root;out.mkdir(exist_ok=False)
    save(out/'evaluation-protocol.json',dict(training_closure_sha256=sha256_file(LAB/'training-complete.json'),
        evaluator_sha256=sha256_file(Path(__file__)),test_access_after_training_closure=True,
        test_policy='All fixed round checkpoints evaluated for predeclared peak/final/attack-window outcomes; no model or threshold selected on test.'))
    results=[]
    with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
        futures={pool.submit(audit_case,result):result for result in closure['results']}
        for future in as_completed(futures):
            result=future.result()  # Failed verification aborts publication; no imputation.
            save(out/'cases'/f'{result["task"]["name"]}.json',result);results.append(result)
            print('AUDITED '+json.dumps(dict(case=result['task']['name'],rounds=result['completed_rounds'])),flush=True)
    save(out/'summary.json',dict(training_closure_sha256=sha256_file(LAB/'training-complete.json'),
                               evaluator_sha256=sha256_file(Path(__file__)),cases=sorted(results,key=lambda r:r['task']['name'])))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers',type=int,default=3)
    parser.add_argument('--output-root',type=Path,default=LAB/'post-training-evaluation-v2')
    args=parser.parse_args();evaluate_study(args.workers,args.output_root)


if __name__=='__main__':main()
