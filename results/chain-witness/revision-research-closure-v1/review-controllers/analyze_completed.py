"""Summarize completed comparisons without pooling failed or incompatible protocols."""
from pathlib import Path
import json

OUT=Path(__file__).parent;ROOT=Path.cwd()/'artifacts/revision-research-closure-v1'
def read(p):return json.loads(Path(p).read_bytes())
def dump(name,data):
    for dest in [ROOT/name,OUT/name]:dest.write_text(json.dumps(data,indent=2)+'\n')

native=read(ROOT/'native-gradients-evaluation/results.json')
verification=read(ROOT/'native-gradient-replay.json')
assert verification['status']=='verified'
cases=native['cases'];clean={(c['task']['cohort'],c['task']['method']):c for c in cases if c['task']['mode']=='clean'}
summary=[]
for case in cases:
    task=case['task'];rows=case['rounds'];reference=clean[task['cohort'],'gradient_fedavg']['rounds']
    full=lambda r:r['metrics']['complete_trigger']['asr']
    f1=lambda r:r['metrics']['clean']['macro_f1_all_model_classes']
    effective=any(r['worst_trigger_asr']-reference[i]['worst_trigger_asr']>=.20 and f1(reference[i])-f1(r)<=.05
                  for i,r in enumerate(rows)) if task['mode']!='clean' else None
    summary.append({'task':task,'completed_rounds':len(rows),'terminal_failure':case['terminal_failure'],
                    'peak_full_ASR':max(map(full,rows),default=None),
                    'peak_worst_ASR':max((r['worst_trigger_asr'] for r in rows),default=None),
                    'final_full_ASR':full(rows[-1]) if len(rows)==15 else None,
                    'final_worst_ASR':rows[-1]['worst_trigger_asr'] if len(rows)==15 else None,
                    'final_macro_F1':f1(rows[-1]) if len(rows)==15 else None,
                    'observed_max_clean_F1_loss':max((f1(reference[i])-f1(r) for i,r in enumerate(rows)),default=None),
                    'selective_attack_effective':effective,
                    'search_failed_rounds':[r['round'] for r in rows if r.get('selective_search_failed')]})
dump('NATIVE_GRADIENT_SUMMARY.json',{'planned_cases':len(cases),'complete_trajectories':sum(len(c['rounds'])==15 for c in cases),
    'numerical_failure_cases':sum(c['terminal_failure'] is not None for c in cases),'counts':native['counts'],
    'verification':verification,'cases':summary,
    'scope':'One full honest gradient/current global base. Explicit malicious gradient-forgery exports. Separate from the ten-epoch honest-Adam DBA benchmark; no full FedXLog reproduction or malicious-client classifier.'})

membership=read(ROOT/'groups/membership-evaluation.json')['cases']
interventions=read(ROOT/'groups/interventions/results.json')
replay=read(ROOT/'group-replay.json');assert replay['status']=='verified'
aggregate=[]
for method in ('v2','v3'):
    attacked=[x for x in membership if x['mode']=='distributed' and x['method']==method]
    unmodified=[x for x in membership if x['mode']=='clean' and x['method']==method]
    aggregate.append({'method':method,'attacked_cases':len(attacked),
        'selected_TP':sum(x['TP'] for x in attacked),'selected_FP':sum(x['FP'] for x in attacked),
        'selected_FN':sum(x['FN'] for x in attacked),
        'clean_cases_with_a_candidate':sum(bool(x['selected_group']) for x in unmodified),
        'clean_cases':len(unmodified),'clean_selected_members':sum(x['FP'] for x in unmodified),
        'candidate_pool_TP':sum(x['pool_TP'] for x in attacked),'candidate_pool_FP':sum(x['pool_FP'] for x in attacked)})
effects=[]
for case in interventions['cases']:
    source=case['source_R10']['complete_trigger']['asr']
    for entry in case['interventions']:
        if not any(role.endswith('-joint') for role in entry['roles']):continue
        item={'alias':case['alias'],'task':case['task'],'removed':entry['removed'],'roles':entry['roles'],
              'source_R10_full_ASR':source,'removed_R10_full_ASR':entry['R10']['complete_trigger']['asr'],
              'final_full_ASR':entry.get('continuation',[{}])[-1].get('validation',{}).get('complete_trigger',{}).get('asr')}
        individual=[x for x in case['interventions'] if len(x['removed'])==1 and x['removed'][0] in entry['removed']]
        item['individual_R10_full_ASR']={x['removed'][0]:x['R10']['complete_trigger']['asr'] for x in individual}
        controls=[x['R10']['complete_trigger']['asr'] for x in case['interventions'] if len(x['removed'])==len(entry['removed']) and any(r.endswith('benign-control') for r in x['roles'])]
        item['benign_control_R10_ASR_range']=[min(controls),max(controls)] if controls else None
        effects.append(item)
dump('GROUP_SUMMARY.json',{'membership':aggregate,'individual_cases':membership,'joint_effects':effects,
    'counts':interventions['counts'],'verification':replay,
    'decision':'Do not promote V3 as uniformly superior or authorize automatic exclusion. It increases selected true members from8to9/18 but also selected false members from3to6; both flag one of six new clean histories.'})
print(json.dumps({'native_cases':len(cases),'native_terminal_failures':sum(c['terminal_failure'] is not None for c in cases),
                  'group_membership':aggregate,'joint_effects':effects}),flush=True)
