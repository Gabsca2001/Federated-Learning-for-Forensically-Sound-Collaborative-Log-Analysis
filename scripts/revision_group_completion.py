"""New campaign assignments, clean-only group selection and held-out evaluation."""
from pathlib import Path
import json
import random
import sys

import numpy as np

OUT=Path(__file__).parent

from revision_study_data import Generator
from revision_group_observables import load_observable,materialize_observable
from revision_dba_experiment import save,outcomes,predict
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.group_calibration_v2 import fit_group_reference,calibrate_group_threshold,detect_conditioned_groups
from fl_forensics.group_calibration_v3 import calibrate_tree_groups,detect_tree_groups
from fl_forensics.round_derivation import implementation_sha256

REPO=Path.cwd()
import argparse
parser=argparse.ArgumentParser();parser.add_argument('--output-root',type=Path)
args=parser.parse_args()
ROOT=args.output_root or REPO/'artifacts/revision-research-closure-v1/groups'
assert not ROOT.exists()
cfg=json.loads((REPO/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json').read_bytes())
assignments=[('iid',2026110431,['client03','client07','client12']),
             ('iid',2026110432,['client01','client08','client14']),
             ('iid',2026110433,['client04','client09','client15']),
             ('non-iid',2026110434,['client02','client08','client13']),
             ('non-iid',2026110435,['client04','client07','client15']),
             ('non-iid',2026110436,['client01','client06','client12'])]
tasks=[dict(cohort=c,seed=s,attackers=a,mode=m) for c,s,a in assignments for m in ('clean','distributed')]
random.Random(2026110440).shuffle(tasks)
protocol={'profile':'heldout-tree-group-evaluation-v1','tasks':tasks,'horizon':15,'selection_rounds':list(range(1,11)),
          'source':implementation_sha256(),'controller_sha256':sha256_file(Path(__file__)),
          'rule':'V2 strict clique versus V3 mean maximum-spanning-tree score for sizes2/3, calibrated per family on the same existing clean fit/calibration histories; triples preferred for investigative recall. No attack ASR or identity truth enters selection.',
          'interventions':'At R10 individual/joint frozen reaggregation and hash-random/mass-matched benign controls; corrected-base continuation for attack-effective selected cases. Selection closes before labels/effects.',
          'scope':'New seeds/attacker identities under the existing IID/non-IID Data24 partitions; not an independent dataset, physical-TPM trial or proof of collusion.'}
save(ROOT/'protocol-before-training.json',protocol)
(ROOT/'controller.py').write_bytes(Path(__file__).read_bytes())
observable_index=[]
truth=[]
for index,task in enumerate(tasks):
    alias=f'case-{index:03d}'
    case=ROOT/'cases'/alias
    root=REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid')
    gen=Generator(root,cfg)
    base=gen.initial
    plan=DistributedBackdoorPlan.model_validate({**cfg['attack_plan'],'seed':task['seed'],
        'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True))})
    rows=json.loads(Path(cfg['validation_path']).read_bytes())['rows']['validation']
    pred,_=predict(base,rows,gen.deps);correct=[p==r['label'] for p,r in zip(pred,rows,strict=True)]
    record=[]
    for number in range(1,16):
        p=case/'rounds'/f'round-{number:03d}'
        save(p/'base-model.json',base)
        result,_,exports,training=gen.execute(base,task['seed'],number,plan if task['mode']=='distributed' else None)
        for c,e in zip(gen.clients,exports,strict=True):save(p/'updates'/f'{c}.json',e)
        save(p/'global-model.json',result)
        metric=outcomes(result,rows,plan,correct,gen.deps)
        frame={'round':number,'clients':gen.clients,'training':training,'validation':metric}
        save(p/'round.json',frame);record.append(frame);base=result
        print(json.dumps({'case':alias,'cohort':task['cohort'],'round':number,'ASR':metric['complete_trigger']['asr']}),flush=True)
    gen.close(case)
    pins=materialize_observable(case,ROOT/'observable-inputs'/alias,gen.deps,rows)
    observable_index.append({'alias':alias,'cohort':task['cohort'],**pins})
    truth.append({'alias':alias,'task':task,'rounds':record,'manifest_sha256':sha256_file(case/'manifest.json')})
    (ROOT/'progress.json').write_text(json.dumps({'generated_cases':len(truth),'planned_cases':len(tasks)})+'\n')
save(ROOT/'observable-index.json',{'cases':observable_index})

# Only the observable index and clean role bindings enter the selector.
old=REPO/'artifacts/revision-retrospective-group-validation-v1'
clean_index=json.loads((old/'observable-index.json').read_bytes())['cases']
selected=[]
for cohort in ('iid','non-iid'):
    fitting=[load_observable(old/'observable-inputs'/x['alias']) for x in clean_index if x['cohort']==cohort and x['role']=='fit']
    calibration=[load_observable(old/'observable-inputs'/x['alias']) for x in clean_index if x['cohort']==cohort and x['role']=='calibration']
    reference=fit_group_reference(fitting)
    c2=calibrate_group_threshold(calibration,reference)
    c3=calibrate_tree_groups(calibration,reference)
    save(ROOT/'selection'/cohort/'reference.json',reference)
    save(ROOT/'selection'/cohort/'v2-calibration.json',c2)
    save(ROOT/'selection'/cohort/'v3-calibration.json',c3)
    for item in observable_index:
        if item['cohort']!=cohort:continue
        observation=load_observable(ROOT/'observable-inputs'/item['alias'])
        v2=detect_conditioned_groups(observation,reference,c2)
        scores={tuple(p['clients']):p['conditioned_score'] for p in v2['pairs']}
        from itertools import combinations
        ranked=sorted(v2['candidate_groups'],key=lambda g:(-min(scores[tuple(p)] for p in combinations(sorted(g),2)),tuple(g)))
        feasible=[g for g in ranked if 15-len(g)>=8]
        v2['selected_group']=feasible[0] if feasible else []
        v3=detect_tree_groups(observation,reference,c3)
        assert v3==detect_tree_groups(observation,reference,c3)
        save(ROOT/'selection'/f'{item["alias"]}-v2.json',v2)
        save(ROOT/'selection'/f'{item["alias"]}-v3.json',v3)
        selected.append({'alias':item['alias'],'cohort':cohort,'v2':v2['selected_group'],'v3':v3['selected_group'],
                         'v2_candidate_groups':v2['candidate_groups'],
                         'v3_candidate_groups':[g['clients'] for g in v3['candidate_groups']]})
save(ROOT/'selection-closure-before-labels.json',{'cases':selected,'labels_or_ASR_read_by_selector':False})
save(ROOT/'evaluation-truth.json',{'cases':truth})
evaluation=[]
for item in selected:
    true=next(t for t in truth if t['alias']==item['alias'])
    attackers=set(true['task']['attackers']) if true['task']['mode']=='distributed' else set()
    for method in ('v2','v3'):
        group=set(item[method]);pool=set(c for g in item[method+'_candidate_groups'] for c in g)
        evaluation.append({'alias':item['alias'],'cohort':item['cohort'],'mode':true['task']['mode'],'method':method,
                           'selected_group':sorted(group),'TP':len(group&attackers),'FP':len(group-attackers),'FN':len(attackers-group),
                           'pool_TP':len(pool&attackers),'pool_FP':len(pool-attackers),'pool_FN':len(attackers-pool),
                           'R10_ASR':true['rounds'][9]['validation']['complete_trigger']['asr']})
save(ROOT/'membership-evaluation.json',{'cases':evaluation})
print('GROUP GENERATION AND BLIND SELECTION FINISHED',json.dumps(evaluation),flush=True)
