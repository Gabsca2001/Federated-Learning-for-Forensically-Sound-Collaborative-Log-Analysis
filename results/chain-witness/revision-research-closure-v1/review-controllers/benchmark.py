"""Sequential single-thread operation costs on fixed verified inputs."""
from pathlib import Path
import json
import resource
import sys
import time

import numpy as np

OUT=Path(__file__).parent
sys.path[:0]=[str(OUT),str(OUT.parent/'state-conditioned-detector-20261103')]
from gradient_study import operation,read
from study_data import Generator
from revision_dba_experiment import save,model_with_arrays
from fl_forensics.bounded_aggregation import aggregate_bounded,digest
from fl_forensics.canonical import sha256_file
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.literature_baselines import flame_aggregate,weidetect_aggregate
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.robust_bounded_aggregation import aggregate_robust_bounded
from fl_forensics.round_derivation import implementation_sha256

REPO=Path.cwd();ROOT=REPO/'artifacts/revision-research-closure-v1'
assert read(ROOT/'native-gradient-replay.json')['status']=='verified'
assert read(ROOT/'robust-replay.json')['status']=='verified'
assert read(ROOT/'shared-gradient-replay.json')['status']=='verified'
assert not (ROOT/'sequential-benchmark.json').exists()
cfg=read(REPO/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
samples=[]

def time_operation(fn,expected,scope,method,context):
    warm=fn();assert derived_json_bytes(warm)==derived_json_bytes(expected)
    for repeat in range(5):
        wall=time.perf_counter_ns();cpu=time.process_time_ns();value=fn()
        cpu=time.process_time_ns()-cpu;wall=time.perf_counter_ns()-wall
        assert derived_json_bytes(value)==derived_json_bytes(expected)
        samples.append({'scope':scope,'method':method,'context':context,'repeat':repeat,
                        'wall_ns':wall,'process_cpu_ns':cpu})

native=ROOT/'native-gradients-evaluation'
for case in read(native/'results.json')['cases']:
    task=case['task'];workspace=native/task['name']
    gen=Generator(REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid'),cfg)
    counts=[len(gen.rows[c]) for c in gen.clients]
    for number in sorted({1,len(case['rounds'])}):
        if number==0:continue
        history=[[] for _ in gen.clients];gradients=None
        for n in range(max(1,number-2),number+1):
            p=workspace/'rounds'/f'round-{n:03d}';frame=read(p/'round.json');base=read(p/'base-model.json')
            arrays=arrays_from_export(base,np=np)
            with np.load(p/'gradient-endpoints.npz',allow_pickle=False) as z:
                clean=[[z[f'clean_{i}_{j}'].copy() for j in range(len(arrays))] for i in range(15)]
                gradients=[[np.asarray(a+frame['selected_alpha']*(z[f'poison_{c}_{j}'].astype(float)-a),dtype=a.dtype)
                            for j,a in enumerate(g)] if frame['attack_active'] and c in task['attackers'] else g
                           for c,g in zip(gen.clients,clean,strict=True)]
            for h,g in zip(history,gradients,strict=True):h.append(np.concatenate([a.astype(float).ravel() for a in g]))
        expected=read(p/'global-model.json')
        fn=lambda:operation(base,gradients,history,counts,gen.clients,task['method'])[0]
        time_operation(fn,expected,'native_server_recurrence_and_export',task['method'],f'{task["name"]}/R{number}')

shared=ROOT/'shared-gradient-baselines-v2'
for source in read(native/'results.json')['cases']:
    task=source['task']
    if task['method']!='gradient_fedavg':continue
    gen=Generator(REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid'),cfg)
    for number in (1,15):
        prefix=native/task['name']/'rounds'/f'round-{number:03d}'
        p=shared/task['name']/f'round-{number:03d}'
        frame=read(prefix/'round.json');base=read(prefix/'base-model.json');arrays=arrays_from_export(base,np=np)
        with np.load(prefix/'gradient-endpoints.npz',allow_pickle=False) as z:
            gs=[]
            for i,c in enumerate(gen.clients):
                g=[z[f'clean_{i}_{j}'].copy() for j in range(len(arrays))]
                if frame['attack_active'] and c in task['attackers']:
                    g=[np.asarray(a+frame['selected_alpha']*(z[f'poison_{c}_{j}'].astype(float)-a),dtype=a.dtype) for j,a in enumerate(g)]
                gs.append(g)
        models=[[b.astype(float)-.001*g.astype(float) for b,g in zip(arrays,gradient,strict=True)] for gradient in gs]
        inputs=read(p/'common-inputs.json');masses=[r['mass'] for r in inputs['composite_decisions']]
        for method in ('flame','weidetect','gated_composite'):
            def fn():
                if method=='flame':
                    values,_=flame_aggregate(base=arrays,models=models,client_ids=gen.clients,noise_factor=.01,seed=task['seed']+number)
                elif method=='weidetect':
                    values,_=weidetect_aggregate(models=models,client_ids=gen.clients,validation_f1=inputs['auxiliary_f1'],keep_count=12,seed=task['seed']+number)
                else:
                    values=[sum(m*local[j] for m,local in zip(masses,models,strict=True))/sum(masses) for j in range(len(arrays))]
                return model_with_arrays(base,values)
            time_operation(fn,read(p/f'{method}-model.json'),'cached_shared_kernel_and_export',method,f'{task["name"]}/R{number}')

robust=ROOT/'robust-evaluation'
for case in read(robust/'results.json')['cases']:
    if case['task']['mode']!='clean':continue
    task=case['task'];workspace=robust/'cases'/case['name']
    gen=Generator(REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid'),cfg)
    reference=read(REPO/'artifacts/revision-bounded-influence-v1'/f'{task["cohort"]}-bounds.json')
    for number in (1,10,15):
        p=workspace/'rounds'/f'round-{number:03d}';base=read(p/'base-model.json');arrays=arrays_from_export(base,np=np)
        updates={c:arrays_from_export(read(p/'updates'/f'{c}.json'),np=np) for c in gen.clients}
        excluded=set(read(p/'decision.json')['quarantine_current_round'])
        args=dict(masses={c:0 if c in excluded else len(gen.rows[c]) for c in gen.clients},mandatory_gates=dict.fromkeys(gen.clients,True),
                  limits=reference['limits'],reference_digest=digest(reference),minimum_contributors=8)
        for name,op in [('bounded_mean',aggregate_bounded),('robust_bounded',aggregate_robust_bounded)]:
            fn=lambda: model_with_arrays(base,op(arrays,updates,**args)[0])
            expected=fn()
            time_operation(fn,expected,'cached_admitted_transform_and_export',name,f'{case["name"]}/R{number}')

summaries=[]
for scope,method in sorted({(s['scope'],s['method']) for s in samples}):
    subset=[s for s in samples if s['scope']==scope and s['method']==method]
    wall=np.asarray([s['wall_ns']/1e6 for s in subset]);cpu=np.asarray([s['process_cpu_ns']/1e6 for s in subset])
    summaries.append({'scope':scope,'method':method,'calls':len(subset),'contexts':len({s['context'] for s in subset}),
                      'median_wall_ms':float(np.median(wall)),'p95_wall_ms':float(np.quantile(wall,.95)),
                      'median_process_cpu_ms':float(np.median(cpu))})
record={'profile':'sequential-cached-operation-cost-v1','source':implementation_sha256(),'summaries':summaries,'samples':samples,
        'process_peak_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'scope':'One warm-up per context, five timed repetitions, one Python process and one numerical thread. Input loading, training, attack optimization, detector fitting/scoring, fresh TPM operations and output-equivalence checks are outside timers. RSS includes all common libraries and loaded contexts, not incremental defense memory. Background host activity is not excluded. These are operation costs, not total federated-round latency.'}
save(ROOT/'sequential-benchmark.json',record);(OUT/'sequential-benchmark.json').write_bytes((ROOT/'sequential-benchmark.json').read_bytes())
print(json.dumps(summaries),flush=True)
