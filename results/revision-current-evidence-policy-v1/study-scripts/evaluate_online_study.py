"""Post-study source, causal-prefix, action-cost and numerical validation."""
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
import json
import numpy as np

from study_data import read,get_observation,flat
from revision_dba_experiment import read_pinned,outcomes,predict,model_with_arrays,authenticate,save
from fl_forensics.canonical import sha256_file,sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows
from fl_forensics.federated_model import dependencies,arrays_from_export
from fl_forensics.byzantine import aggregate_deltas,apply_delta,model_delta
from fl_forensics.sequential_decision import digest

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-current-evidence-policy-v1'
execution=read(lab/'reserved-execution-before-training.json');complete=read(lab/'reserved-generation-complete.json')
assert complete['execution_sha256']==sha256_file(lab/'reserved-execution-before-training.json')
frozen=read(lab/'calibration-frozen-before-evaluation.json')
assert sha256_file(lab/'policy-calibration/closure.json')==frozen['policy_closure_sha256']
runtime=read(lab/'online-worker-runtime.json')
assert runtime['HostConfig']['NetworkMode']=='none' and runtime['HostConfig']['ReadonlyRootfs']
assert set(m['Destination'] for m in runtime['Mounts'])=={'/code','/models','/inbox','/policy'}
assert all('/private-' not in m.get('Source','') for m in runtime['Mounts'])
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
deps=dependencies();deps[1].set_num_threads(1)
validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256'])
prediction,_=predict(initial,validation,deps);correct=[p==r['label'] for p,r in zip(prediction,validation,strict=True)]
clients_by_cohort={};source_rows={};masses={};preflight={}
for cohort,directory in [('iid','m3-data24-parquet-iid-local-test-v1'),('non-iid','m3-data24-parquet-non-iid')]:
    partition_root=repo/'artifacts'/directory;partition=read(partition_root/'manifest.json')
    source_rows[cohort]={};masses[cohort]={};ids=[]
    for r in partition['clients']:
        rows=read_pinned(partition_root/r['dataset_path'],r['dataset_sha256'])['rows']['train']
        assert len(rows)==r['train_row_count'];source_rows[cohort][r['client_id']]=rows
        masses[cohort][r['client_id']]=len(rows);ids.extend(x['window_id'] for x in rows)
    clients_by_cohort[cohort]=sorted(source_rows[cohort])
    assert len(ids)==len(set(ids))==7096 and not set(ids)&{r['window_id'] for r in validation}
    preflight[cohort]={'unique_training_windows':len(ids),'validation_overlap':0,
        'manifest_sha256':sha256_file(partition_root/'manifest.json')}

cases=[];trajectories=[];verified_updates=0;verified_aggregates=0;counter=defaultdict(int)
for task in execution['tasks']:
    stream=task['stream'];episode=lab/'private-episodes'/stream
    assert sha256_file(episode/'manifest.json')==complete['episode_manifests'][stream]
    authenticate(episode,complete['episode_manifests'][stream])
    cohort=task['cohort'];clients=clients_by_cohort[cohort];weights=masses[cohort]
    cal=read(lab/'policy-calibration'/f'{cohort}.json');views=('conditioned','state-disabled')
    centers=np.asarray(cal['centers']);scales=np.asarray(cal['scales']);cumulative=np.zeros((15,2));streak=np.zeros((15,2),dtype=int);high_streak=np.zeros(15,dtype=int);previous_quarantine=set()
    plan=DistributedBackdoorPlan.model_validate(read(episode/'generation-protocol.json')['attack_plan_for_simulator_and_evaluation_only'])
    intended=set(task['attackers']) if task['mode']=='distributed' else set()
    metrics=defaultdict(int);latency={c:{'review_rounds':[],'quarantine_rounds':[],'actually_poisoned_rounds':[]} for c in clients}
    previous='0'*64;expected_base=cfg['base_model_sha256'];rounds=[];excluded_ever=set()
    for number in range(1,16):
        prefix=episode/'rounds'/f'round-{number:03d}'
        if not (prefix/'round.json').exists():
            assert (prefix/'aggregation-failure.json').exists();metrics['quorum_failures']+=1;break
        record=read(prefix/'round.json');response=read(prefix/'worker-response.json');request=read(prefix/'worker-request.json')
        decision=response['decision'];core={k:v for k,v in decision.items() if k!='decision_digest'}
        assert digest(core)==decision['decision_digest'] and decision['previous_decision_digest']==previous
        assert decision['calibration_digest']==digest(cal)
        assert decision['source_observation_sha256']==sha256_file(prefix/'observable/observations.npz')==request['observation_sha256']
        assert request['previous']==previous and request['round']==number and request['stream']==stream
        assert set(request)=={'op','request_id','cohort','observation_sha256','stream','round','previous','masses','mandatory_gate'}
        assert all(request['mandatory_gate'].values()) and request['masses']==weights
        assert sha256_file(prefix/'base-model.json')==expected_base==record['base_model_sha256']
        base=read(prefix/'base-model.json');arrays=arrays_from_export(base,np=np)
        locals=[arrays_from_export(read(prefix/'updates'/f'{c}.json'),np=np) for c in clients]
        observation=get_observation(prefix/'observable')
        deltas=[model_delta(arrays,m) for m in locals]
        assert observation['states'].shape[0]==observation['updates'].shape[0]==1
        assert np.array_equal(observation['states'][0],flat(arrays))
        assert np.array_equal(observation['updates'][0],np.stack([flat(d) for d in deltas]))
        active=set()
        for c,tr in zip(clients,record['local_training_records'],strict=True):
            assert tr['client_id']==c and sha256_file(prefix/'updates'/f'{c}.json')==tr['local_model_sha256']
            clean_rows=source_rows[cohort][c];expected_rows=clean_rows
            if task['mode']=='distributed':expected_rows,_=poison_local_rows(rows=clean_rows,plan=plan,client_id=c,round_number=number,distributed=True)
            expected_rows_digest=sha256_bytes(derived_json_bytes(expected_rows))
            assert tr['executed_rows_sha256']==expected_rows_digest
            if expected_rows_digest!=sha256_bytes(derived_json_bytes(clean_rows)):active.add(c);latency[c]['actually_poisoned_rounds'].append(number)
        score=response['scored'];assert len(score['frame_ids'])==1
        supported=all(score['state_distances'][v][0]<=cal['state_support_limits'][v]*(1+1e-12)+1e-12 for v in views)
        assert decision['supported']==supported
        if supported:
            raw=np.stack([score['risk'][v][0] for v in views],axis=1);z=np.maximum(0.,(raw-centers)/scales)
            cumulative=np.maximum(0.,cumulative+z-.5);streak=np.where(z>.5,streak+1,0)
            sq=(cumulative>np.asarray(cal['cumulative_limits']))&(z>.5)&(streak>=2)
            ins=z>np.asarray(cal['instantaneous_limits'])
            warning=(z>np.asarray(cal['review_instantaneous_limits']))|(cumulative>np.asarray(cal['review_cumulative_limits']))
            sequential={c for i,c in enumerate(clients) if sq[i].all()};instant={c for i,c in enumerate(clients) if ins[i].all()}
            high=ins.all(axis=1);high_streak=np.where(high,high_streak+1,0)
            primary={c for i,c in enumerate(clients) if high[i] and high_streak[i]>=2}
            review={c for i,c in enumerate(clients) if c not in primary and
                (warning[i].any() or (sq[i,0]!=sq[i,1]) or c in instant or c in previous_quarantine)}
            metrics['supported_rounds']+=1
        else:
            cumulative[:]=0;streak[:]=0;high_streak[:]=0;primary=set();instant=set();sequential=set();review=set(clients);metrics['unsupported_rounds']+=1
        assert primary==set(decision['quarantine_current_round']) and review==set(decision['review_required'])
        assert instant=={c for c in clients if decision['clients'][c]['instantaneous_proposal']}
        for i,c in enumerate(clients):
            assert np.array_equal(cumulative[i],np.asarray([decision['clients'][c]['cumulative_evidence'][v] for v in views]))
            assert decision['clients'][c]['consecutive_current_high_rounds']==int(high_streak[i])
            assert decision['clients'][c]['current_high_in_both_views']==(c in instant)
            expected_transition=('continued' if c in previous_quarantine else 'entered') if c in primary else (
                'released' if c in previous_quarantine else 'confirmation_pending' if c in instant else 'none')
            assert decision['quarantine_transitions'][c]==expected_transition
            assert decision['clients'][c]['quarantine_transition']==expected_transition
            if expected_transition=='released':metrics['release_client_rounds']+=1
            if c in primary:latency[c]['quarantine_rounds'].append(number)
            if c in review:latency[c]['review_rounds'].append(number)
            if decision['clients'][c]['view_disagreement']:metrics['disagreement_client_rounds']+=1
        for method,selection in [('current',primary),('instantaneous',instant),('sequential',sequential)]:
            metrics[f'{method}_poisoned_update_quarantines']+=len(selection&active)
            metrics[f'{method}_never_attacker_quarantines']+=len(selection-intended)
            clean_scheduled=(selection&intended)-active
            metrics[f'{method}_currently_clean_scheduled_attacker_quarantines']+=len(clean_scheduled)
            if number<min(task['attack_rounds']):metrics[f'{method}_pre_onset_scheduled_attacker_quarantines']+=len(clean_scheduled)
            if number>max(task['attack_rounds']):metrics[f'{method}_after_cessation_attacker_quarantines']+=len(clean_scheduled)
            if min(task['attack_rounds'])<number<max(task['attack_rounds']) and number not in task['attack_rounds']:
                metrics[f'{method}_clean_gap_attacker_quarantines']+=len(clean_scheduled)
            metrics[f'{method}_missed_poisoned_updates']+=len(active-selection)
            metrics[f'{method}_quarantine_client_rounds']+=len(selection)
        metrics['poisoned_update_opportunities']+=len(active)
        metrics['never_attacker_opportunities']+=len(clients)-len(intended)
        metrics['currently_clean_scheduled_attacker_opportunities']+=len(intended-active)
        metrics['review_client_rounds']+=len(review)
        metrics['review_poisoned_client_rounds']+=len(review&active)
        metrics['review_never_attacker_client_rounds']+=len(review-intended)
        metrics['review_currently_clean_scheduled_attacker_client_rounds']+=len((review&intended)-active)
        applied=set(record['applied_exclusions']);expected_excluded=primary if task['branch']=='active-current-evidence' else set()
        assert applied==expected_excluded;excluded_ever|=applied
        selected=[i for i,c in enumerate(clients) if c not in applied]
        assert len(selected)>=8
        actual=model_with_arrays(base,apply_delta(arrays,aggregate_deltas([deltas[i] for i in selected],strategy='fedavg',f=0,weights=[weights[clients[i]] for i in selected])))
        assert derived_json_bytes(actual)==(prefix/'global-model.json').read_bytes()
        mass=sum(weights[clients[i]] for i in selected)
        expected_weights={c:str(Fraction(weights[c],mass)) if c not in applied else '0' for c in clients}
        assert expected_weights==record['actual_aggregation_weights']
        # Evaluation follows the closed decision and cannot feed policy state.
        endpoint=outcomes(actual,validation,plan,correct,deps)
        trajectory={'stream':stream,'round':number,'cohort':cohort,'seed':task['seed'],'mode':task['mode'],'branch':task['branch'],
            'actually_poisoned_clients':sorted(active),'quarantined':sorted(primary),'applied_exclusions':sorted(applied),
            'review_required':sorted(review),'instantaneous_shadow_proposal':sorted(instant),'sequential_shadow_proposal':sorted(sequential),
            'quarantine_transitions':decision['quarantine_transitions'],'supported':supported,
            'outcomes':endpoint}
        trajectories.append(trajectory);rounds.append(trajectory)
        previous_quarantine=set(primary);previous=decision['decision_digest'];expected_base=sha256_file(prefix/'global-model.json')
        assert record['global_model_sha256']==expected_base
        verified_updates+=len(clients);verified_aggregates+=1
    for c,entry in latency.items():
        onset=min(entry['actually_poisoned_rounds']) if entry['actually_poisoned_rounds'] else None
        for role in ('review','quarantine'):
            eligible=[t for t in entry[f'{role}_rounds'] if onset is not None and t>=onset and t in entry['actually_poisoned_rounds']]
            entry[f'first_{role}_delay_from_actual_onset']=min(eligible)-onset if eligible else None
        entry['ever_intended_attacker']=c in intended
        bursts=[]
        for t in entry['actually_poisoned_rounds']:
            if not bursts or t!=bursts[-1][-1]+1:bursts.append([t])
            else:bursts[-1].append(t)
        entry['burst_evaluations']=[{'start':b[0],'end':b[-1],
            'poisoned_updates_quarantined':sum(t in entry['quarantine_rounds'] for t in b),
            'first_quarantine_delay':next((t-b[0] for t in b if t in entry['quarantine_rounds']),None)} for b in bursts]
    cases.append({'task':task,'metrics':dict(metrics),'client_timeline':latency,'applied_exclusions_ever':sorted(excluded_ever),
        'finished_rounds':len(rounds),'final_outcomes':rounds[-1]['outcomes'] if rounds else None,
        'maximum_complete_trigger_ASR':max(r['outcomes']['complete_trigger']['asr'] for r in rounds) if rounds else None,
        'final_decision_digest':previous,'episode_manifest_sha256':sha256_file(episode/'manifest.json')})
    for k,v in metrics.items():counter[k]+=v
    print(json.dumps({'evaluated_stream':stream,'finished_rounds':len(rounds),'current_TP':metrics['current_poisoned_update_quarantines'],
        'never_attacker_FP':metrics['current_never_attacker_quarantines'],'final_ASR':cases[-1]['final_outcomes']['complete_trigger']['asr']}),flush=True)

paired=[]
for cohort in ('iid','non-iid'):
    seeds=sorted({c['task']['seed'] for c in cases if c['task']['cohort']==cohort})
    for seed in seeds:
        for mode in ('clean','distributed'):
            match={c['task']['branch']:c for c in cases if c['task']['cohort']==cohort and c['task']['seed']==seed and c['task']['mode']==mode}
            a=match['shadow-FedAvg'];b=match['active-current-evidence'];equal=[];same_input=[]
            for number in range(1,min(a['finished_rounds'],b['finished_rounds'])+1):
                pa=lab/'private-episodes'/a['task']['stream']/'rounds'/f'round-{number:03d}'
                pb=lab/'private-episodes'/b['task']['stream']/'rounds'/f'round-{number:03d}'
                equal.append((pa/'global-model.json').read_bytes()==(pb/'global-model.json').read_bytes())
                same_input.append((pa/'observable/observations.npz').read_bytes()==(pb/'observable/observations.npz').read_bytes())
                # Every common input must produce the same decision, independent of branch metadata.
                if same_input[-1] and (number==1 or all(same_input)):
                    da=read(pa/'worker-response.json')['decision'];db=read(pb/'worker-response.json')['decision']
                    assert da==db
            paired.append({'cohort':cohort,'seed':seed,'mode':mode,'shadow_stream':a['task']['stream'],'active_stream':b['task']['stream'],
                'checkpoint_equal_by_round':equal,'all_checkpoints_equal':all(equal) and len(equal)==15,
                'first_changed_checkpoint_round':next((i+1 for i,v in enumerate(equal) if not v),None),
                'baseline_final_ASR':a['final_outcomes']['complete_trigger']['asr'],'active_final_ASR':b['final_outcomes']['complete_trigger']['asr'],
                'baseline_peak_ASR':a['maximum_complete_trigger_ASR'],'active_peak_ASR':b['maximum_complete_trigger_ASR'],
                'active_minus_baseline_final_macro_F1':b['final_outcomes']['clean']['macro_f1_all_model_classes']-a['final_outcomes']['clean']['macro_f1_all_model_classes']})
            if mode=='distributed':
                clean_case=next(c for c in cases if c['task']['cohort']==cohort and c['task']['seed']==seed and c['task']['mode']=='clean' and c['task']['branch']=='shadow-FedAvg')
                clean_path=lab/'private-episodes'/clean_case['task']['stream']/'rounds/round-015/global-model.json'
                active_path=lab/'private-episodes'/b['task']['stream']/'rounds'/f'round-{b["finished_rounds"]:03d}'/'global-model.json'
                clean_model=read(clean_path);active_model=read(active_path)
                clean_pred,_=predict(clean_model,validation,deps);active_pred,_=predict(active_model,validation,deps)
                paired[-1].update(clean_reference_final_ASR=clean_case['final_outcomes']['complete_trigger']['asr'],
                    active_vs_clean_final_parameter_L2=float(np.linalg.norm(flat(arrays_from_export(active_model,np=np))-flat(arrays_from_export(clean_model,np=np)))),
                    active_vs_clean_final_checkpoint_equal=active_path.read_bytes()==clean_path.read_bytes(),
                    active_vs_clean_validation_prediction_disagreements=sum(x!=y for x,y in zip(clean_pred,active_pred,strict=True)),
                    validation_prediction_denominator=len(validation),
                    qualification='The all-client clean reference differs in participation after policy actions. Model distance alone cannot attribute a residual wholly to poisoning.')
active=[c for c in cases if c['task']['branch']=='active-current-evidence'];attacked=[c for c in cases if c['task']['mode']=='distributed']
acceptance={'zero_never_attacker_quarantine_proposals':all(c['metrics'].get('current_never_attacker_quarantines',0)==0 for c in cases),
    'zero_after_cessation_clean_source_proposals':all(c['metrics'].get('current_after_cessation_attacker_quarantines',0)==0 for c in cases),
    'at_least_one_poisoned_update_proposed_per_attacked_episode':all(c['metrics'].get('current_poisoned_update_quarantines',0)>0 for c in attacked),
    'no_active_quorum_failure':all(c['finished_rounds']==15 and c['metrics'].get('quorum_failures',0)==0 for c in active)}
assert set(acceptance)==set(read(lab/'protocol-before-new-training.json')['experimental_acceptance'])
result={'profile':'reserved-current-evidence-evaluation-v1','cases':cases,'paired':paired,'totals':dict(counter),
    'predeclared_experimental_acceptance':acceptance,'all_pilot_criteria_pass':all(acceptance.values()),
    'automatic_deployment_validated':False,'semantic_malice_proved':False,'permanent_bans':False,
    'verified_source_updates':verified_updates,'independently_reconstructed_aggregates':verified_aggregates,
    'verified_prefix_decisions':verified_aggregates,'preflight':preflight,
    'qualification':'Counts are correlated client-round opportunities from 24 episodes, not independent Bernoulli trials. Instantaneous and original sequential proposals are shadow comparisons on the same prefixes, not alternative active trajectories. No final test set, future inputs or labels enter the worker. No post-evaluation retuning.'}
save(lab/'post-study-evaluation.json',result);save(lab/'post-study-trajectories.json',{'rows':trajectories})
(out/'online-evaluation.json').write_bytes((lab/'post-study-evaluation.json').read_bytes())
(out/'online-trajectories.json').write_bytes((lab/'post-study-trajectories.json').read_bytes())
print(json.dumps({'acceptance':acceptance,'totals':dict(counter),'verified_updates':verified_updates,'verified_aggregates':verified_aggregates},sort_keys=True),flush=True)
