from pathlib import Path
import json
p=Path(__file__).parent
def read(n): return json.loads((p/n).read_bytes())
d=read('consolidated-results.json')
print('ENDPOINTS')
for r in d['fixed_test_endpoint_summary']:
    if r['mode']!='clean': print(r['mode'],r['round'],r['method'],*[round(r[k]*100,4) for k in ('accuracy_mean','macro_f1_mean','ASR_mean','ASR_sample_std')],r['component_ASR_means'])
print('CLEAN EXCLUSIONS')
for r in d['operational_selection_summary']:
    if r['mode']=='clean' and r['selection_metric_available']: print(r['method'],r['phase'],r['clean_excluded'],r['clean_update_opportunities'],r['clean_downweighted'])
print('DIAGNOSTICS',d['adapter_diagnostics'])
g=read('gradient-audit.json')
for k,v in g.items():
    if k not in ('cases','server_aggregation_timing_samples'): print('GRAD',k,v)
for r in g['cases']:
    print('GRAD CASE',str(r)[:1600])
e=read('envelope-benchmark-summary.json')
for r in e['rows']:print('ENVELOPE',{k:v for k,v in r.items() if k not in ('samples','contexts_detail','input_cases')})
t=read('secondary-test-results.json')['rows']
print('SECONDARY SCHEMA',str(t[0])[:2500])
