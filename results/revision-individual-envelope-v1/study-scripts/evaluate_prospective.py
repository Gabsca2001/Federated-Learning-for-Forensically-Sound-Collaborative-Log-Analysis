"""Independent source, action and numerical verification of the frozen study."""
from pathlib import Path
from collections import defaultdict
from fractions import Fraction
import json
import numpy as np
from study_data import read,get_observation,flat
from revision_dba_experiment import save,authenticate,read_pinned,outcomes,predict,model_with_arrays
from fl_forensics.canonical import sha256_file,sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan,poison_local_rows
from fl_forensics.federated_model import dependencies,arrays_from_export
from fl_forensics.byzantine import model_delta,aggregate_deltas,apply_delta
from fl_forensics.sequential_decision import digest

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-geometry-detector-v1'
protocol=read(lab/'protocol-before-new-training.json');execution=read(lab/'reserved-execution-before-training.json')
completion=read(lab/'reserved-generation-complete.json');frozen=read(lab/'calibration-frozen-before-evaluation.json')
assert completion['execution_sha256']==sha256_file(lab/'reserved-execution-before-training.json')
assert frozen['protocol_sha256']==sha256_file(lab/'protocol-before-new-training.json')
assert frozen['envelope_closure_sha256']==sha256_file(lab/'policy-calibration/envelope-closure.json')
assert frozen['policy_closure_sha256']==sha256_file(lab/'policy-calibration/closure.json')
for role in ('fit','online-worker'):
    inspection=read(lab/f'{role}-runtime-inspection.json') if role=='fit' else read(lab/'online-worker-runtime.json')
    assert inspection['HostConfig']['NetworkMode']=='none' and inspection['HostConfig']['ReadonlyRootfs']
    assert not any('/private-episodes' in m.get('Source','') for m in inspection['Mounts'])
for closure in ('closure.json','envelope-closure.json'):
    for name,value in read(lab/'policy-calibration'/closure)['files'].items():assert sha256_file(lab/'policy-calibration'/name)==value
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
deps=dependencies();deps[1].set_num_threads(1)
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256'])
validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
pred,_=predict(initial,validation,deps);correct=[p==r['label'] for p,r in zip(pred,validation,strict=True)]
snapshots={};masses={};preflight={}
for cohort,directory in [('iid','m3-data24-parquet-iid-local-test-v1'),('non-iid','m3-data24-parquet-non-iid')]:
    root=repo/'artifacts'/directory;manifest=read(root/'manifest.json');snapshots[cohort]={};masses[cohort]={};ids=[]
    for record in manifest['clients']:
        rows=read_pinned(root/record['dataset_path'],record['dataset_sha256'])['rows']['train']
        assert len(rows)==record['train_row_count'];snapshots[cohort][record['client_id']]=rows
        masses[cohort][record['client_id']]=len(rows);ids.extend(r['window_id'] for r in rows)
    assert len(ids)==len(set(ids))==7096 and not set(ids)&{r['window_id'] for r in validation}
    preflight[cohort]={'manifest_sha256':sha256_file(root/'manifest.json'),'unique_training_windows':len(ids),'validation_overlap':0}
cases=[];trajectories=[];verified=defaultdict(int)
for task in execution['tasks']:
    episode=lab/'private-episodes'/task['stream'];expected=completion['episode_manifests'][task['stream']]
    assert sha256_file(episode/'manifest.json')==expected;authenticate(episode,expected)
    cohort=task['cohort'];cal=read(lab/'policy-calibration'/f'{cohort}.json');env=read(lab/'policy-calibration'/f'{cohort}-envelope.json')
    plan=DistributedBackdoorPlan.model_validate(read(episode/'generation-protocol.json')['attack_plan_for_simulator_and_evaluation_only'])
    clients=cal['clients'];weights=masses[cohort];C=np.zeros((15,2));streak=np.zeros((15,2),dtype=int)
    base_high_count=np.zeros(15,dtype=int);peak=np.zeros(15);previous_retained=np.zeros(15,dtype=bool)
    previous_base=set();previous_new=set();heads=dict.fromkeys(('prior','envelope'),'0'*64)
    variant='prior' if task['branch']=='active-prior' else 'envelope'
    previous_selected='0'*64;previous_model=cfg['base_model_sha256'];metrics=defaultdict(int);round_results=[]
    timeline={c:{'poisoned_rounds':[],'prior_proposed_rounds':[],'envelope_proposed_rounds':[],'review_rounds':[]} for c in clients}
    intended=set(task['attackers']) if task['mode']=='distributed' else set()
    for t in range(1,16):
        prefix=episode/'rounds'/f'round-{t:03d}'
        if not (prefix/'round.json').exists():
            assert (prefix/'aggregation-failure.json').exists();metrics['quorum_failures']+=1;break
        record=read(prefix/'round.json');response=read(prefix/'worker-response.json');request=read(prefix/'worker-request.json')
        assert set(request)=={'op','request_id','cohort','observation_sha256','stream','round','previous','masses','mandatory_gate','policy_variant'}
        assert request['policy_variant']==variant and request['previous']==previous_selected and request['round']==t
        assert request['masses']==weights and all(request['mandatory_gate'].values())
        assert request['observation_sha256']==sha256_file(prefix/'observable/observations.npz')
        assert sha256_file(prefix/'base-model.json')==record['base_model_sha256']==previous_model
        base=read(prefix/'base-model.json');arrays=arrays_from_export(base,np=np)
        exports=[read(prefix/'updates'/f'{c}.json') for c in clients]
        locals=[arrays_from_export(m,np=np) for m in exports];deltas=[model_delta(arrays,a) for a in locals]
        observed=get_observation(prefix/'observable')
        assert observed['states'].shape[0]==observed['updates'].shape[0]==1
        assert np.array_equal(observed['states'][0],flat(arrays))
        assert np.array_equal(observed['updates'][0],np.stack([flat(d) for d in deltas]))
        active=set()
        for c,tr in zip(clients,record['local_training_records'],strict=True):
            clean=snapshots[cohort][c];rows=clean
            if task['mode']=='distributed':rows,_=poison_local_rows(rows=clean,plan=plan,client_id=c,round_number=t,distributed=True)
            assert tr['client_id']==c and tr['local_model_sha256']==sha256_file(prefix/'updates'/f'{c}.json')
            assert tr['executed_rows_sha256']==sha256_bytes(derived_json_bytes(rows))
            if sha256_bytes(derived_json_bytes(rows))!=sha256_bytes(derived_json_bytes(clean)):active.add(c);timeline[c]['poisoned_rounds'].append(t)
        scored=response['scored'];raw=np.stack([scored['risk'][v][0] for v in ('conditioned','state-disabled')],axis=1)
        supported=all(scored['state_distances'][v][0]<=min(cal['state_support_limits'][v],env['state_support_limits'][v])*(1+1e-12)+1e-12 for v in ('conditioned','state-disabled'))
        if supported:
            z=np.maximum(0.,(raw-np.asarray(cal['centers']))/np.asarray(cal['scales']))
            C=np.maximum(0.,C+z-.5);streak=np.where(z>.5,streak+1,0)
            inst_votes=z>np.asarray(cal['instantaneous_limits']);base_high=inst_votes.all(axis=1)
            base_high_count=np.where(base_high,base_high_count+1,0)
            baseline={c for i,c in enumerate(clients) if base_high[i] and base_high_count[i]>=2}
            sequential_votes=(C>np.asarray(cal['cumulative_limits']))&(z>.5)&(streak>=2)
            warning=(z>np.asarray(cal['review_instantaneous_limits']))|(C>np.asarray(cal['review_cumulative_limits']))
            base_reviews={c for i,c in enumerate(clients) if c not in baseline and
                (base_high[i] or c in previous_base or warning[i].any() or (sequential_votes[i,0]!=sequential_votes[i,1]))}
            excess=(raw-np.asarray(env['tensor_risk_limits'])).min(axis=1);high=excess>0
            peak=np.where(high,np.maximum(peak,excess),0.);retained=high&(excess>=.5*peak)
            envelope_candidates={c for i,c in enumerate(clients) if retained[i] and previous_retained[i]}
            newer=baseline|envelope_candidates
            new_reviews={c for i,c in enumerate(clients) if c not in newer and (high[i] or c in previous_new or c in base_reviews)}
            metrics['supported_rounds']+=1
        else:
            C[:]=0;streak[:]=0;base_high_count[:]=0;peak[:]=0;retained=np.zeros(15,dtype=bool);excess=np.zeros(15)
            baseline=set();envelope_candidates=set();newer=set();base_reviews=set(clients);new_reviews=set(clients)
            metrics['unsupported_rounds']+=1
        expected_selections={'prior':baseline,'envelope':newer};expected_reviews={'prior':base_reviews,'envelope':new_reviews}
        for name,decision in response['comparison_decisions'].items():
            core={k:v for k,v in decision.items() if k!='decision_digest'}
            assert digest(core)==decision['decision_digest'] and decision['previous_decision_digest']==heads[name]
            assert decision['source_observation_sha256']==request['observation_sha256'] and decision['calibration_digest']==digest(cal)
            assert decision['supported']==supported
            assert set(decision['quarantine_current_round'])==expected_selections[name]
            assert set(decision['review_required'])==expected_reviews[name]
            if name=='envelope':
                assert decision['envelope_calibration_digest']==digest(env)
                assert decision['baseline_decision_digest']==response['comparison_decisions']['prior']['decision_digest']
                for i,c in enumerate(clients):
                    r=decision['clients'][c]
                    assert r['client_envelope_episode_peak_excess']==float(peak[i])
                    assert r['client_envelope_current_minimum_excess']==float(excess[i])
                    assert r['client_envelope_non_receding']==bool(retained[i])
                assert set(decision['envelope_quarantine_current_round'])==envelope_candidates
            for i,c in enumerate(clients):
                previous=previous_base if name=='prior' else previous_new
                if c in expected_selections[name]:transition='continued' if c in previous else 'entered'
                elif c in previous:transition='released'
                else:
                    pending=(supported and (base_high_count[i]>0)) if name=='prior' else retained[i]
                    transition='confirmation_pending' if pending else 'none'
                assert decision['quarantine_transitions'][c]==transition
                if transition=='released':metrics[f'{name}_release_client_rounds']+=1
            heads[name]=decision['decision_digest']
        assert response['decision']==response['comparison_decisions'][variant]
        for name,selection in expected_selections.items():
            metrics[f'{name}_poisoned_proposals']+=len(selection&active)
            metrics[f'{name}_never_attacker_proposals']+=len(selection-intended)
            clean_selected=(selection&intended)-active
            metrics[f'{name}_currently_clean_scheduled_proposals']+=len(clean_selected)
            if t>max(task['attack_rounds']):metrics[f'{name}_after_cessation_proposals']+=len(clean_selected)
            if min(task['attack_rounds'])<t<max(task['attack_rounds']) and t not in task['attack_rounds']:
                metrics[f'{name}_clean_gap_proposals']+=len(clean_selected)
            metrics[f'{name}_missed_poisoned_updates']+=len(active-selection)
            metrics[f'{name}_review_client_rounds']+=len(expected_reviews[name])
            for c in selection:timeline[c][f'{name}_proposed_rounds'].append(t)
        for c in new_reviews:timeline[c]['review_rounds'].append(t)
        metrics['poisoned_opportunities']+=len(active);metrics['never_attacker_opportunities']+=15-len(intended)
        selected=expected_selections[variant] if task['branch']!='shadow-FedAvg' else set()
        assert selected==set(record['applied_exclusions'])
        indices=[i for i,c in enumerate(clients) if c not in selected];assert len(indices)>=8
        recomputed=model_with_arrays(base,apply_delta(arrays,aggregate_deltas([deltas[i] for i in indices],strategy='fedavg',f=0,weights=[weights[clients[i]] for i in indices])))
        assert derived_json_bytes(recomputed)==(prefix/'global-model.json').read_bytes()
        total=sum(weights[clients[i]] for i in indices)
        assert record['actual_aggregation_weights']=={c:'0' if c in selected else str(Fraction(weights[c],total)) for c in clients}
        endpoint=outcomes(recomputed,validation,plan,correct,deps)
        row={'stream':task['stream'],'cohort':cohort,'seed':task['seed'],'mode':task['mode'],'branch':task['branch'],'round':t,
            'actually_poisoned_clients':sorted(active),'applied_exclusions':sorted(selected),'prior_proposals':sorted(baseline),
            'envelope_proposals':sorted(newer),'envelope_reviews':sorted(new_reviews),'supported':supported,'outcomes':endpoint}
        trajectories.append(row);round_results.append(row)
        previous_selected=response['decision']['decision_digest'];previous_model=sha256_file(prefix/'global-model.json')
        assert record['global_model_sha256']==previous_model and record['decision_digest']==previous_selected
        previous_base=set(baseline);previous_new=set(newer);previous_retained=retained.copy()
        verified['source_updates']+=15;verified['aggregates']+=1;verified['policy_decisions']+=2
    for c,entry in timeline.items():
        for name in ('prior','envelope'):
            caught=sorted(set(entry['poisoned_rounds'])&set(entry[f'{name}_proposed_rounds']))
            entry[f'{name}_first_poisoned_quarantine_delay']=caught[0]-min(entry['poisoned_rounds']) if caught else None
    case={'task':task,'metrics':dict(metrics),'client_timeline':timeline,'finished_rounds':len(round_results),
        'peak_ASR':max(r['outcomes']['complete_trigger']['asr'] for r in round_results),
        'final_outcomes':round_results[-1]['outcomes'],'episode_manifest_sha256':expected,'final_decision_digest':previous_selected}
    cases.append(case)
    print(json.dumps({'evaluated':task['stream'],'cohort':cohort,'branch':task['branch'],
        'envelope_TP':metrics['envelope_poisoned_proposals'],'envelope_never_FP':metrics['envelope_never_attacker_proposals'],
        'peak_ASR':case['peak_ASR']}),flush=True)

pairs=[]
for cohort in ('iid','non-iid'):
    for seed in sorted({c['task']['seed'] for c in cases if c['task']['cohort']==cohort}):
        for mode in ('clean','distributed'):
            group={c['task']['branch']:c for c in cases if c['task']['cohort']==cohort and c['task']['seed']==seed and c['task']['mode']==mode}
            baseline=group['shadow-FedAvg'];prior=group['active-prior'];new=group['active-envelope']
            equals={name:[] for name in ('prior','envelope')}
            for t in range(1,min(c['finished_rounds'] for c in group.values())+1):
                files={branch:lab/'private-episodes'/c['task']['stream']/'rounds'/f'round-{t:03d}'/'global-model.json' for branch,c in group.items()}
                equals['prior'].append(files['shadow-FedAvg'].read_bytes()==files['active-prior'].read_bytes())
                equals['envelope'].append(files['shadow-FedAvg'].read_bytes()==files['active-envelope'].read_bytes())
            p={'cohort':cohort,'seed':seed,'mode':mode,'streams':{n:c['task']['stream'] for n,c in group.items()},
                'shadow_peak_ASR':baseline['peak_ASR'],'prior_peak_ASR':prior['peak_ASR'],'envelope_peak_ASR':new['peak_ASR'],
                'shadow_final_ASR':baseline['final_outcomes']['complete_trigger']['asr'],
                'prior_final_ASR':prior['final_outcomes']['complete_trigger']['asr'],'envelope_final_ASR':new['final_outcomes']['complete_trigger']['asr'],
                'envelope_minus_prior_final_macro_F1':new['final_outcomes']['clean']['macro_f1_all_model_classes']-prior['final_outcomes']['clean']['macro_f1_all_model_classes'],
                'shadow_checkpoint_equality_by_round':equals,'all_prior_checkpoints_equal_shadow':all(equals['prior']) and len(equals['prior'])==15,
                'all_envelope_checkpoints_equal_shadow':all(equals['envelope']) and len(equals['envelope'])==15}
            if mode=='distributed':
                clean=next(c for c in cases if c['task']['cohort']==cohort and c['task']['seed']==seed and c['task']['mode']=='clean' and c['task']['branch']=='shadow-FedAvg')
                path=lab/'private-episodes'/new['task']['stream']/'rounds'/f'round-{new["finished_rounds"]:03d}'/'global-model.json'
                cleanpath=lab/'private-episodes'/clean['task']['stream']/'rounds/round-015/global-model.json'
                a=read(path);b=read(cleanpath);pa,_=predict(a,validation,deps);pb,_=predict(b,validation,deps)
                p.update(envelope_vs_all_client_clean_parameter_L2=float(np.linalg.norm(flat(arrays_from_export(a,np=np))-flat(arrays_from_export(b,np=np)))),
                    envelope_vs_all_client_clean_prediction_disagreements=sum(x!=y for x,y in zip(pa,pb,strict=True)),
                    validation_prediction_denominator=len(validation),envelope_checkpoint_equal_all_client_clean=path.read_bytes()==cleanpath.read_bytes())
            pairs.append(p)
shadow_non_iid=[c for c in cases if c['task']['cohort']=='non-iid' and c['task']['branch']=='shadow-FedAvg']
attacked_pairs=[p for p in pairs if p['mode']=='distributed'];active_cases=[c for c in cases if c['task']['branch']!='shadow-FedAvg']
acceptance={
    'zero_never_attacker_envelope_proposals':all(c['metrics'].get('envelope_never_attacker_proposals',0)==0 for c in cases),
    'zero_currently_clean_scheduled_attacker_envelope_proposals':all(c['metrics'].get('envelope_currently_clean_scheduled_proposals',0)==0 for c in cases),
    'shadow_non_iid_recall_strictly_above_prior':sum(c['metrics'].get('envelope_poisoned_proposals',0) for c in shadow_non_iid)>sum(c['metrics'].get('prior_poisoned_proposals',0) for c in shadow_non_iid),
    'no_active_quorum_failure':all(c['finished_rounds']==15 and c['metrics'].get('quorum_failures',0)==0 for c in active_cases),
    'active_envelope_peak_ASR_not_worse_than_prior':all(p['envelope_peak_ASR']<=p['prior_peak_ASR']+1e-12 for p in attacked_pairs),
    'active_envelope_final_macro_F1_within_0_02_of_prior':all(p['envelope_minus_prior_final_macro_F1']>=-.02-1e-12 for p in attacked_pairs)}
assert set(acceptance)==set(protocol['experimental_acceptance'])
report={'profile':'individual-envelope-prospective-evaluation-v1','cases':cases,'pairs':pairs,'preflight':preflight,
    'verification_counts':dict(verified),'experimental_acceptance':acceptance,'all_pilot_criteria_pass':all(acceptance.values()),
    'automatic_live_deployment_validated':False,'semantic_malice_proved':False,'final_test_set_used':False,
    'qualification':'Three independently trained histories per seed/mode; no reserved tuning. Classification counts are correlated client-round opportunities. Zero observed errors is not a population false-positive guarantee. Clean-reference distance also reflects changed participation.'}
save(lab/'prospective-evaluation.json',report);save(lab/'prospective-trajectories.json',{'rows':trajectories})
(out/'prospective-evaluation.json').write_bytes((lab/'prospective-evaluation.json').read_bytes())
(out/'prospective-trajectories.json').write_bytes((lab/'prospective-trajectories.json').read_bytes())
print(json.dumps({'acceptance':acceptance,'verification':dict(verified),'pairs':attacked_pairs}),flush=True)
