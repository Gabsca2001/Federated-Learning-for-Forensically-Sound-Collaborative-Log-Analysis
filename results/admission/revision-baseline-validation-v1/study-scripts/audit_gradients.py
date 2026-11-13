"""Replay stored actual-gradient aggregation and diagnose the failed prefix."""
import math
import resource
import time
import numpy as np
from audit_common import *

protocol=read(LAB/'protocol-before-audit-and-benchmark.json');root=REPO/'artifacts/revision-fedgradtrace-live-v1'
deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
rows=[];timings=[];fourth=[];first_gradient_case=None;maximum_relative_diagnostic_error=0.
for case,expected in sorted(protocol['gradient_cases'].items()):
    workspace=root/case;assert sha256_file(workspace/'manifest.json')==expected['manifest_sha256']
    assert sha256_file(workspace/'experiment-authority.public.pem')==expected['public_key_sha256']
    authenticate(workspace,expected['manifest_sha256']);cfg=read(workspace/'protocol-before-training.json')
    partition=read(Path(cfg['partition_workspace'])/'manifest.json');records=sorted(partition['clients'],key=lambda r:r['client_id'])
    counts=[r['train_row_count'] for r in records];clients=[r['client_id'] for r in records];histories={c:[] for c in clients}
    numbers=sorted(int(p.parent.name[-3:]) for p in (workspace/'rounds').glob('*/round.json'))
    endpoints=[]
    for number in range(1,max(numbers)+1):
        prefix=workspace/'rounds'/f'round-{number:03d}';record=read(prefix/'round.json');base=read(prefix/'base-model.json')
        arrays=arrays_from_export(base,np=np);gradients=[]
        for c in clients:
            g=read(prefix/'gradients'/f'{c}.json');assert g['parameter_names']==[p['name'] for p in base['parameters']]
            values=[np.asarray(v,dtype=a.dtype) for v,a in zip(g['values'],arrays,strict=True)]
            gradients.append(values);histories[c].append(np.concatenate([a.astype(np.float64).reshape(-1) for a in values]))
            histories[c]=histories[c][-cfg['gradient_history_length']:]
        def operation():
            if cfg['recurrence']=='gradient_fedavg':
                return [a-cfg['learning_rate']*np.average(np.stack([g[i] for g in gradients]),axis=0,weights=counts) for i,a in enumerate(arrays)],None
            return fedgradtrace_global_gradient(base=arrays,gradients=gradients,gradient_histories=[np.stack(histories[c]) for c in clients],
                client_ids=clients,sample_counts=counts,learning_rate=cfg['learning_rate'],formula=cfg['recurrence'])
        expected_model=read(prefix/'aggregates'/f'{cfg["recurrence"]}.json')
        operation()
        for repeat in range(3):
            wall=time.perf_counter_ns();cpu=time.process_time_ns();result,report=operation()
            cpu=time.process_time_ns()-cpu;wall=time.perf_counter_ns()-wall
            assert derived_json_bytes(model_with_arrays(base,result))==(prefix/'aggregates'/f'{cfg["recurrence"]}.json').read_bytes()
            timings.append({'case':case,'round':number,'method':cfg['recurrence'],'repeat':repeat,'wall_ns':wall,'cpu_ns':cpu})
        comparison=read(prefix/'comparison.json')['comparisons'][cfg['recurrence']]
        if report is not None:
            for key,value in report.items():
                expected_value=comparison['aggregation'][key]
                if key in ('trajectory_frobenius_norms','coefficients','coefficient_sum'):
                    a=np.asarray(value,dtype=float);b=np.asarray(expected_value,dtype=float)
                    assert np.allclose(a,b,rtol=5e-14,atol=1e-15),(case,number,key)
                    maximum_relative_diagnostic_error=max(maximum_relative_diagnostic_error,float(np.max(np.abs(a-b)/np.maximum(np.abs(b),1e-300))))
                else:assert value==expected_value
        endpoints.append({'round':number,'validation':comparison['validation'],
            'coefficient_sum':report['coefficient_sum'] if report else 1.,
            'max_absolute_model_parameter':float(max(np.abs(a).max() for a in arrays_from_export(expected_model,np=np)))})
    rows.append({'case':case,'mode':cfg['attack_mode'],'recurrence':cfg['recurrence'],'completed_rounds':len(numbers),
        'requested_rounds':cfg['rounds'],'poison_fraction':cfg['attack_plan']['poisoned_fraction_decimal'],
        'history_length':cfg['gradient_history_length'],'endpoints':endpoints,
        'failed_execution':read(workspace/'failed-execution.json') if (workspace/'failed-execution.json').exists() else None})
    if case=='clean-gradient_fedavg':first_gradient_case=(workspace,cfg,partition,records)
    if case=='distributed-literal_eq2':
        prefix=workspace/'rounds/round-004';validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
        for path in sorted((prefix/'aggregates').glob('*.json')):
            model=read(path);arrays=arrays_from_export(model,np=np)
            evaluation=evaluate(model,validation,deps)
            fourth.append({'method':path.stem,'model_sha256':sha256_file(path),
                'parameters_all_finite':bool(all(np.isfinite(a).all() for a in arrays)),
                'maximum_absolute_parameter':float(max(np.abs(a).max() for a in arrays)),
                'validation_loss_is_finite':bool(math.isfinite(evaluation['loss'])),
                'validation_loss':evaluation['loss'] if math.isfinite(evaluation['loss']) else str(evaluation['loss']),
                'accuracy':evaluation['accuracy']})
    print(json.dumps({'gradient_case_replayed':case,'completed_rounds':len(numbers)}),flush=True)

# A source-equation counterexample, not a new attack experiment.
base=[np.array([2.],dtype=np.float32)];zeros=[[np.array([0.],dtype=np.float32)] for _ in range(2)]
history=[np.array([[2.],[0.]]) for _ in range(2)]
eq2,r2=fedgradtrace_global_gradient(base=base,gradients=zeros,gradient_histories=history,client_ids=['a','b'],sample_counts=[1,1],learning_rate=.001,formula='literal_eq2')
eq3,r3=fedgradtrace_global_gradient(base=base,gradients=zeros,gradient_histories=history,client_ids=['a','b'],sample_counts=[1,1],learning_rate=.001,formula='literal_eq3')
assert eq2[0].item()==4 and eq3[0].item()==2
counterexample={'current_gradients_zero':True,'nonzero_history_frobenius_norms':[2.,2.],
    'initial_parameter':2.,'literal_eq2_parameter':4.,'literal_eq3_parameter':2.,
    'interpretation':'Literal Eq2 rescales the old model by a generally nonunit coefficient sum; Eq3 does not. This is an algebraic consequence of the printed formulas, not a silently corrected implementation.'}

# Representative collection cost: one complete clean source context, no optimizer steps.
workspace,cfg,partition,source_records=first_gradient_case;base=read(workspace/'rounds/round-001/base-model.json')
weights={c:float(partition['global_class_weights'][c]) for c in base['class_names']}
snapshots=[read_pinned(Path(cfg['partition_workspace'])/r['dataset_path'],r['dataset_sha256'])['rows']['train'] for r in source_records]
collection=[]
for repeat in range(4):
    wall=time.perf_counter_ns();cpu=time.process_time_ns();computed=[full_gradient(base,data,weights,deps)[0] for data in snapshots]
    cpu=time.process_time_ns()-cpu;wall=time.perf_counter_ns()-wall
    for record,values in zip(source_records,computed,strict=True):
        expected=read(workspace/'rounds/round-001/gradients'/f'{record["client_id"]}.json')['values']
        assert all(np.array_equal(a,np.asarray(b,dtype=a.dtype)) for a,b in zip(values,expected,strict=True))
    if repeat:collection.append({'repeat':repeat-1,'wall_ns':wall,'cpu_ns':cpu})
result={'profile':'actual-gradient-replay-and-formula-audit-v1','cases':rows,'completed_rounds':sum(r['completed_rounds'] for r in rows),
    'replayed_gradient_aggregates':sum(r['completed_rounds'] for r in rows),'server_aggregation_timing_samples':timings,
    'failed_round_4_evaluation_diagnosis':fourth,'formula_counterexample':counterexample,
    'representative_gradient_collection':{'source':'clean-gradient_fedavg/round-001','clients':15,'records':sum(map(len,snapshots)),
        'timings':collection,'warmup_calls':15,'timed_gradient_evaluations':45,'total_new_gradient_evaluations':60,
        'optimizer_steps':0,'process_peak_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'qualification':'Sequential client collection in a shared common runtime. Data loading/import excluded. Memory peak includes the preceding source audit, so it is not attributed to gradient collection alone.'},
    'maximum_relative_diagnostic_error':maximum_relative_diagnostic_error,
    'diagnostic_tolerance':{'relative':5e-14,'absolute':1e-15,'model_bytes_comparison':'strict, no tolerance'},
    'native_client_detection_metric_available':False,'full_FedXLog_reproduced':False,'same_protocol_as_Adam_DBA':False,
    'new_client_training_calls':0,'fresh_TPM_attestation':False}
save(LAB/'gradient-audit.json',result);(OUT/'gradient-audit.json').write_bytes((LAB/'gradient-audit.json').read_bytes())
print('GRADIENT AUDIT COMPLETE',json.dumps({'rounds':result['completed_rounds'],'failed_round':fourth,'counterexample':counterexample}),flush=True)
