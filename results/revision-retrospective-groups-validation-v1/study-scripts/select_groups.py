"""Selection consumes only the public observable index and clean role labels."""
from itertools import combinations
from group_common import *
from fl_forensics.group_calibration_v2 import fit_group_reference,calibrate_group_threshold,detect_conditioned_groups

index=read(LAB/'observable-index.json')['cases']
protocol=read(LAB/'protocol-before-selection.json')
for n in ('group_common.py','select_groups.py'):assert sha256_file(OUT/n)==protocol['code_sha256'][n]
inputs={r['alias']:load_observable(LAB/'observable-inputs'/r['alias']) for r in index}
results=[]
for cohort in ('iid','non-iid'):
    fit=[inputs[r['alias']] for r in index if r['role']=='fit' and r['cohort']==cohort]
    cal=[inputs[r['alias']] for r in index if r['role']=='calibration' and r['cohort']==cohort]
    reference=fit_group_reference(fit);calibration=calibrate_group_threshold(cal,reference)
    assert derived_json_bytes(reference)==derived_json_bytes(fit_group_reference(fit))
    assert derived_json_bytes(calibration)==derived_json_bytes(calibrate_group_threshold(cal,reference))
    save(LAB/'selections'/cohort/'reference.json',reference);save(LAB/'selections'/cohort/'calibration.json',calibration)
    for item in index:
        if item['role']!='evaluation' or item['cohort']!=cohort:continue
        alias=item['alias'];result=detect_conditioned_groups(inputs[alias],reference,calibration)
        assert derived_json_bytes(result)==derived_json_bytes(detect_conditioned_groups(inputs[alias],reference,calibration))
        scores={tuple(p['clients']):p['conditioned_score'] for p in result['pairs']}
        ranked=sorted(result['candidate_groups'],key=lambda g:(-min(scores[tuple(p)] for p in combinations(sorted(g),2)),tuple(g)))
        feasible=[g for g in ranked if 15-len(g)>=8]
        result['ranked_candidate_groups']=ranked;result['selected_feasible_group']=feasible[0] if feasible else []
        meta=read(LAB/'observable-inputs'/alias/'metadata.json')
        envelope=sorted({c for group in meta['frozen_envelope_quarantines_by_round'] for c in group})
        result['secondary_envelope_prefix_set']=envelope
        result['secondary_is_pairwise_collusion_detector']=False
        result['selection_uses_rounds']=list(range(1,11))
        save(LAB/'selections'/f'{alias}.json',result)
        results.append({'alias':alias,'cohort':cohort,'candidate_groups':ranked,'primary_selected':result['selected_feasible_group'],
            'envelope_prefix_set':envelope,'sha256':sha256_file(LAB/'selections'/f'{alias}.json')})
save(LAB/'selection-closure-before-labels.json',{'profile':'closed-observable-group-selection-v1','cases':results,
    'observable_index_sha256':sha256_file(LAB/'observable-index.json'),
    'calibration_files':{p.relative_to(LAB).as_posix():sha256_file(p) for p in (LAB/'selections').glob('*/*.json')},
    'selection_received_identity_truth_or_ASR':False,'production_policy_changed':False})
print('SELECTIONS CLOSED BEFORE LABEL EVALUATION',len(results),flush=True)
