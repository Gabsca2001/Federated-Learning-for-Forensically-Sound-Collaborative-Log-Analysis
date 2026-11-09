"""Sequential performance runs; no competing audit/training workers."""
import os
import random
import subprocess
import sys
import numpy as np
from audit_common import *

jobs=[(m,'kernel') for m in METHODS]+[(m,'full') for m in ('weidetect','gated_composite')]
random.Random(20261103).shuffle(jobs)
save(LAB/'benchmark-run-plan.json',{'profile':'sequential-benchmark-run-plan-v1','jobs':jobs,
    'worker_sha256':sha256_file(OUT/'benchmark_worker.py'),'helper_sha256':sha256_file(OUT/'audit_common.py'),
    'randomization_seed':20261103,'benchmark_processes_run_concurrently':False,
    'protocol_sha256':sha256_file(LAB/'protocol-before-audit-and-benchmark.json')})
env={**os.environ,'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1','MKL_NUM_THREADS':'1','NUMEXPR_NUM_THREADS':'1'}
for method,scope in jobs:
    subprocess.run([sys.executable,str(OUT/'benchmark_worker.py'),method,scope],env=env,check=True)
summary=[]
for method,scope in jobs:
    data=read(LAB/'benchmark'/f'{scope}-{method}.json');wall=np.asarray([r['wall_ns']/1e6 for r in data['samples']]);cpu=np.asarray([r['cpu_ns']/1e6 for r in data['samples']])
    summary.append({'method':method,'scope':scope,'contexts':data['contexts'],'timed_calls':len(wall),
        'median_wall_ms':float(np.median(wall)),'p95_wall_ms':float(np.quantile(wall,.95)),
        'min_wall_ms':float(wall.min()),'max_wall_ms':float(wall.max()),'median_cpu_ms':float(np.median(cpu)),
        'process_peak_RSS_MiB':data['process_peak_RSS_KiB']/1024,
        'input_and_output_validation_passed':True})
save(LAB/'benchmark-summary.json',{'profile':'measured-baseline-costs-v1','rows':summary,
    'training_and_TPM_included':False,'wall_and_CPU_are_measured':True,'memory_is_process_peak_not_incremental':True,
    'qualification':'Each aggregation row uses all 135 shared contexts; full-defense rows use 27 stratified contexts. Repeat samples and client-round contexts are dependent, not independent performance trials.'})
(OUT/'benchmark-summary.json').write_bytes((LAB/'benchmark-summary.json').read_bytes())
print('ALL BASELINE BENCHMARKS COMPLETE',flush=True)
