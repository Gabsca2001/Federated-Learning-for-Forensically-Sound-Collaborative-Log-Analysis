import os
import subprocess
import sys
from audit_common import *
save(LAB/'envelope-benchmark-plan.json',{'profile':'secondary-stateful-cost-plan-v1','cohorts':['iid','non-iid'],
    'contexts_per_cohort':90,'repetitions':3,'worker_sha256':sha256_file(OUT/'benchmark_envelope.py'),
    'source_protocol_sha256':sha256_file(LAB/'secondary-protocol-before-comparison.json'),
    'no_concurrent_benchmark_or_analysis_workers':True,
    'qualification':'Additional fixed cost scope for the latest policy. Predictor inference, decision logic and selected-contributor aggregation; model loading amortized. Not a claim about complete live wall-clock cost.'})
env={**os.environ,'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1','MKL_NUM_THREADS':'1'}
for cohort in ('iid','non-iid'):
    subprocess.run([sys.executable,str(OUT/'benchmark_envelope.py'),cohort],env=env,check=True)
summary={'rows':[read(LAB/'benchmark'/f'envelope-full-{c}.json') for c in ('iid','non-iid')]}
save(LAB/'envelope-benchmark-summary.json',summary);(OUT/'envelope-benchmark-summary.json').write_bytes((LAB/'envelope-benchmark-summary.json').read_bytes())
