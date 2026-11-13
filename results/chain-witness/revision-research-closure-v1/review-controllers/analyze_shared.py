"""Summarize conditional comparisons without inventing defender trajectories."""
from pathlib import Path
import collections
import json

out=Path(__file__).parent; root=Path.cwd()/'artifacts/revision-research-closure-v1'
data=json.loads((out/'shared-gradient-results.json').read_bytes())
replay=json.loads((root/'shared-gradient-replay.json').read_bytes())
assert replay['status']=='verified'
groups=collections.defaultdict(list)
for frame in data['records']:
    for item in frame['outputs']:
        groups[frame['task']['cohort'],frame['task']['mode'],item['method']].append((frame,item))
rows=[]
for (cohort,mode,method),items in sorted(groups.items()):
    metric=[v['metrics'] for _,v in items]
    active=[(f,v) for f,v in items if v['current_manipulated_count']]
    clean=[(f,v) for f,v in items if not v['current_manipulated_count']]
    worst=lambda m:max([m['complete_trigger']['asr']]+[x['asr'] for x in m['component_triggers'].values()])
    rows.append({'cohort':cohort,'mode':mode,'method':method,'contexts':len(items),
      'clean_accuracy_min':min(m['clean']['accuracy'] for m in metric),
      'clean_macro_F1_min':min(m['clean']['macro_f1_all_model_classes'] for m in metric),
      'clean_macro_F1_max':max(m['clean']['macro_f1_all_model_classes'] for m in metric),
      'peak_conditional_full_ASR':max(m['complete_trigger']['asr'] for m in metric),
      'peak_conditional_worst_ASR':max(map(worst,metric)),
      'R15_full_ASR':[v['metrics']['complete_trigger']['asr'] for f,v in items if f['round']==15],
      'manipulated_denominator':sum(v['current_manipulated_count'] for _,v in active),
      'manipulated_excluded':sum(v['manipulated_excluded'] or 0 for _,v in active) if items[0][1]['native_client_detection_metric'] else None,
      'unmodified_denominator':sum(15-v['current_manipulated_count'] for _,v in items),
      'unmodified_excluded':sum(v['currently_unmodified_excluded'] or 0 for _,v in items) if items[0][1]['native_client_detection_metric'] else None,
      'degenerate_WeiDetect_fits':sum('degenerate' in str(v['report'].get('fit_status','')) for _,v in items)})
summary={'counts':data['counts'],'verification':replay,'rows':rows,
  'scope':'Conditional current-round outputs on common gradient-FedAvg histories; no independently evolving defender trajectories, no defender-adaptive optimization, no new test fold or TPM attestation. Honest derivatives and malicious gradient-forgery exports are distinguished. A zero exclusion count for non-classifiers is undefined, not perfect detection. WeiDetect neutral-CDF tied rankings are declared extensions, not successful fitted distributions.'}
for p in (out/'SHARED_GRADIENT_SUMMARY.json',root/'SHARED_GRADIENT_SUMMARY.json'):
    p.write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(rows),flush=True)
