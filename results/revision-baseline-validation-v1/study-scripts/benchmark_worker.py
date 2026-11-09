"""One fresh common application process per timing scope/method."""
import json
import os
import random
import resource
import sys
import time
import numpy as np
from audit_common import *

method=sys.argv[1];scope=sys.argv[2]
deps=dependencies();deps[1].set_num_threads(1);deps[1].use_deterministic_algorithms(True)
protocol=read(LAB/'protocol-before-audit-and-benchmark.json')
contexts=[(case,n) for case in sorted(protocol['source_cases']) for n in range(1,16) if scope=='kernel' or n in (1,10,15)]
random.Random(20261103).shuffle(contexts)
validation,auxiliary=validation_inputs(read(ROOT/'clean-s341593/protocol-before-training.json'))
timings=[];load_start=list(os.getloadavg());began=time.time()
for index,(case,number) in enumerate(contexts):
    d=load_case(case,number);source=d['comparison']['comparisons'][method]
    expected=arrays_from_export(read(d['prefix']/'aggregates'/f'{method}.json'),np=np) if source['status']=='aggregated' else None
    def operation():
        return (kernel(method,d),None) if scope=='kernel' else full_defense(method,d,deps,validation,auxiliary)
    if index==0:operation()
    for repeat in range(3):
        wall=time.perf_counter_ns();cpu=time.process_time_ns()
        actual,meta=operation()
        cpu=time.process_time_ns()-cpu;wall=time.perf_counter_ns()-wall
        if expected is None:assert actual is None
        else:assert all(np.array_equal(a,b) for a,b in zip(actual,expected,strict=True)),(method,scope,case,number)
        if scope=='full' and method=='weidetect':assert meta==source['aggregation']['validation_f1']
        if scope=='full' and method=='gated_composite':
            assert meta['masses']==[r['mass'] for r in d['calibration']['decisions']]
            assert meta['status']==[r['decision']['status'] for r in d['calibration']['decisions']]
        timings.append({'case':case,'round':number,'repeat':repeat,'wall_ns':wall,'cpu_ns':cpu})
    if index%15==14:print(json.dumps({'benchmark':method,'scope':scope,'contexts':index+1}),flush=True)
    del d,expected,actual,meta
result={'method':method,'scope':scope,'contexts':len(contexts),'repetitions_per_context':3,'warmup_calls':1,
    'samples':timings,'process_peak_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    'loadavg_start':load_start,'loadavg_end':list(os.getloadavg()),'elapsed_process_seconds':time.time()-began,
    'threads':{'torch':deps[1].get_num_threads(),'OPENBLAS_NUM_THREADS':os.environ.get('OPENBLAS_NUM_THREADS')},
    'qualification':'RSS is a process high-water mark including the shared application runtime, loaded inputs and retained allocations. Loading, import and result evaluation are excluded from call timers.'}
try:
    from threadpoolctl import threadpool_info
    result['threadpools']=threadpool_info()
except ImportError:result['threadpools']='not available'
save(LAB/'benchmark'/f'{scope}-{method}.json',result)
print(json.dumps({'finished':method,'scope':scope,'median_wall_ms':float(np.median([r['wall_ns'] for r in timings]))/1e6,
    'process_peak_RSS_KiB':result['process_peak_RSS_KiB']}),flush=True)
