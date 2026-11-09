"""Reserved, prefix-only online interventions with a blind Docker worker."""
from pathlib import Path
from fractions import Fraction
import json
import random

from policy_data import Generator, read, export_observation, current_observation, aggregate_selected
from worker_link import WorkerLink
from revision_dba_experiment import save, authenticate
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.sequential_decision import digest

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-current-evidence-policy-v1'
protocol=read(lab/'protocol-before-new-training.json');frozen=read(lab/'calibration-frozen-before-evaluation.json')
assert sha256_file(lab/'policy-calibration/closure.json')==frozen['policy_closure_sha256']
assert sha256_file(lab/'protocol-before-new-training.json')==frozen['protocol_sha256']
assert sha256_file(repo/'src/fl_forensics/current_evidence_policy.py')==protocol['source_policy_sha256']
assert sha256_file(lab/'worker-code/policy_worker.py')==protocol['worker_sha256']
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
tasks=[]
for cohort,assignments in protocol['reserved_evaluation'].items():
    for index,(seed,attackers) in enumerate(assignments):
        for mode in protocol['modes']:
            for branch in protocol['branches']:
                tasks.append({'cohort':cohort,'seed':seed,'attackers':attackers,'mode':mode,'branch':branch,
                    'attack_rounds':protocol['attack_schedules'][index]})
random.Random(202611031).shuffle(tasks)
for index,task in enumerate(tasks):task['stream']=f'stream-{index:03d}'
execution={'profile':'reserved-online-execution-v1','controller_sha256':sha256_file(Path(__file__)),
    'calibration_frozen_sha256':sha256_file(lab/'calibration-frozen-before-evaluation.json'),
    'tasks':tasks,'worker_receives_task_labels':False,'horizon':15}
if (lab/'reserved-execution-before-training.json').exists():
    assert read(lab/'reserved-execution-before-training.json')==execution
else:save(lab/'reserved-execution-before-training.json',execution)
partitions={'iid':'m3-data24-parquet-iid-local-test-v1','non-iid':'m3-data24-parquet-non-iid'}
generators={};completed=[];worker=WorkerLink(repo,lab,'online')
try:
    assert worker.ready['model_closure_sha256']==protocol['model_closure_sha256']
    for task in tasks:
        episode=lab/'private-episodes'/task['stream']
        if (episode/'manifest.json').exists():
            authenticate(episode,sha256_file(episode/'manifest.json'));completed.append(task['stream']);continue
        cohort=task['cohort']
        if cohort not in generators:generators[cohort]=Generator(repo/'artifacts'/partitions[cohort],cfg)
        gen=generators[cohort];masses={c:len(gen.rows[c]) for c in gen.clients}
        attack_plan=DistributedBackdoorPlan.model_validate({**cfg['attack_plan'],'seed':task['seed'],
            'client_components':{c:[f] for c,f in zip(task['attackers'],(13,17,24),strict=True)},
            'attack_rounds':task['attack_rounds']})
        plan=attack_plan if task['mode']=='distributed' else None
        case={'task':task,'attack_plan_for_simulator_and_evaluation_only':attack_plan.model_dump(mode='json'),
            'partition_sha256':sha256_file(gen.root/'manifest.json'),'initial_model_sha256':cfg['base_model_sha256'],
            'frozen_policy_sha256':sha256_file(lab/'policy-calibration'/f'{cohort}.json'),
            'all_clients_continue_submitting_after_quarantine':True,'fresh_TPM_attestation':False}
        if (episode/'generation-protocol.json').exists():assert read(episode/'generation-protocol.json')==case
        else:save(episode/'generation-protocol.json',case)
        base=gen.initial;previous='0'*64
        for number in range(1,16):
            prefix=episode/'rounds'/f'round-{number:03d}'
            if (prefix/'round.json').exists():
                record=read(prefix/'round.json')
                request,response=worker.request(prefix/'observable',cohort=cohort,op='step',stream=task['stream'],
                    round=number,previous=previous,masses=masses,mandatory_gate={c:True for c in gen.clients})
                assert response['decision']==read(prefix/'worker-response.json')['decision']
                assert record['global_model_sha256']==sha256_file(prefix/'global-model.json')
                previous=response['decision']['decision_digest'];base=read(prefix/'global-model.json')
                continue
            # A partial training round is deliberately not overwritten on resume.
            assert not prefix.exists(),f'incomplete round needs explicit recovery: {prefix}'
            save(prefix/'base-model.json',base)
            ordinary,deltas,exports,training=gen.execute(base,task['seed'],number,plan)
            for client,model,record in zip(gen.clients,exports,training,strict=True):
                save(prefix/'updates'/f'{client}.json',model)
                record['local_model_sha256']=sha256_file(prefix/'updates'/f'{client}.json')
            commitment={'base_model_sha256':sha256_file(prefix/'base-model.json'),
                'local_model_sha256':[r['local_model_sha256'] for r in training]}
            export_observation(prefix/'observable',current_observation(base,deltas,gen.clients,commitment))
            request,response=worker.request(prefix/'observable',cohort=cohort,op='step',stream=task['stream'],
                round=number,previous=previous,masses=masses,mandatory_gate={c:True for c in gen.clients})
            decision=response['decision'];core={k:v for k,v in decision.items() if k!='decision_digest'}
            assert digest(core)==decision['decision_digest'] and decision['previous_decision_digest']==previous
            assert decision['source_observation_sha256']==sha256_file(prefix/'observable/observations.npz')
            excluded=decision['quarantine_current_round'] if task['branch']=='active-current-evidence' else []
            result=aggregate_selected(gen,base,exports,excluded) if excluded else ordinary
            save(prefix/'worker-request.json',request);save(prefix/'worker-response.json',response)
            if result is None:
                save(prefix/'aggregation-failure.json',{'reason':'quorum loss','excluded':excluded,'decision':decision['decision_digest']})
                print(json.dumps({'QUORUM_FAILURE':task['stream'],'round':number}),flush=True)
                break
            selected=[c for c in gen.clients if c not in excluded];total=sum(masses[c] for c in selected)
            weights={c:str(Fraction(masses[c],total)) if c in selected else '0' for c in gen.clients}
            assert task['branch']!='active-current-evidence' or decision['proposal_quorum_satisfied']
            save(prefix/'global-model.json',result)
            save(prefix/'round.json',{'round':number,'clients':gen.clients,'local_training_records':training,
                **commitment,'global_model_sha256':sha256_file(prefix/'global-model.json'),
                'decision_digest':decision['decision_digest'],'applied_exclusions':excluded,
                'actual_aggregation_weights':weights,'all_15_clients_trained':True})
            base=result;previous=decision['decision_digest']
            (lab/'online-progress.json').write_text(json.dumps({'completed_episodes':len(completed),
                'current_stream':task['stream'],'current_round':number,'total_episodes':len(tasks)},sort_keys=True)+'\n')
            print(json.dumps({'stream':task['stream'],'round':number,'quarantines':excluded,
                'supported':decision['supported'],'reviews':len(decision['review_required'])}),flush=True)
        gen.close(episode);completed.append(task['stream'])
    save(lab/'reserved-generation-complete.json',{'episodes':completed,'execution_sha256':sha256_file(lab/'reserved-execution-before-training.json'),
        'episode_manifests':{stream:sha256_file(lab/'private-episodes'/stream/'manifest.json') for stream in completed}})
finally:worker.stop()
print('RESERVED ONLINE STUDY COMPLETE',flush=True)
