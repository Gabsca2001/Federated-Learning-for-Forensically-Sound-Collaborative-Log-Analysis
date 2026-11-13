"""Check declared search fallbacks and actual manipulated-export denominators."""
from pathlib import Path
import json
import numpy as np
from fl_forensics.preprocessing import derived_json_bytes

repo=Path.cwd();out=Path(__file__).parent;root=repo/'artifacts/revision-research-closure-v1'
read=lambda p:json.loads(Path(p).read_bytes())
native=root/'native-gradients-evaluation';data=read(native/'results.json')
clean={c['task']['cohort']:c for c in data['cases'] if c['task']['method']=='gradient_fedavg' and c['task']['mode']=='clean'}
violations=[];fallbacks=[];endpoint_trainings=0
for case in data['cases']:
    task=case['task'];workspace=native/task['name']
    for p in workspace.glob('rounds/round-*/forged-gradient-training-records.json'):
        endpoint_trainings+=len(read(p))
    for frame in case['rounds']:
        if not frame['attack_active']:continue
        ref=clean[task['cohort']]['rounds'][frame['round']-1]
        loss=ref['metrics']['clean']['macro_f1_all_model_classes']-frame['metrics']['clean']['macro_f1_all_model_classes']
        if frame['selective_search_failed']:fallbacks.append({'case':task['name'],'round':frame['round'],'alpha':frame['selected_alpha']})
        if frame['selected_alpha']!=0 and loss>.05+1e-12:violations.append({'case':task['name'],'round':frame['round'],'loss':loss})
assert not violations,violations
assert all(x['alpha']==0 for x in fallbacks)
assert endpoint_trainings==2955,endpoint_trainings
robust=root/'robust-evaluation';mismatches=[];checked=0
for case in read(robust/'results.json')['cases']:
    for frame in case['rounds']:
        p=robust/'cases'/case['name']/'rounds'/f'round-{frame["round"]:03d}'
        if case['task']['mode']!='adaptive' or frame['round']>10:continue
        actual={c for c in frame['client_ids'] if (p/'updates'/f'{c}.json').read_bytes()!=(p/'endpoints/clean'/f'{c}.json').read_bytes()} if 'client_ids' in frame else {c for c in case['task']['attackers'] if (p/'updates'/f'{c}.json').read_bytes()!=(p/'endpoints/clean'/f'{c}.json').read_bytes()}
        claimed=set(frame['actual_manipulated_clients']);checked+=len(claimed)
        if actual!=claimed:mismatches.append({'case':case['name'],'round':frame['round'],'actual':sorted(actual),'claimed':sorted(claimed)})
assert not mismatches,mismatches
record={'status':'verified','native_selected_nonzero_search_guard_violations':violations,
 'native_explicit_zero_fallbacks':fallbacks,'native_actual_extra_Adam_endpoint_trainings':endpoint_trainings,
 'robust_claimed_manipulations_checked_against_saved_clean_exports':checked,
 'robust_export_denominator_mismatches':mismatches,
 'scope':'Saved creator artifacts and full numerical replay together establish the actual finite recipe. No silent retuning of historical search logic.'}
for p in (root/'attack-contract-audit.json',out/'attack-contract-audit.json'):p.write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k!='native_explicit_zero_fallbacks'}),flush=True)
