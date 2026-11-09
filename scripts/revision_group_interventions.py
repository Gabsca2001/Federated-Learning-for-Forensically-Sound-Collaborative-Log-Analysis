"""Individual/joint removals, preselected benign controls and corrected-base futures."""
from pathlib import Path
from itertools import combinations
import hashlib
import json
import sys

import numpy as np

OUT=Path(__file__).parent

from revision_study_data import Generator
from revision_policy_data import aggregate_selected
from revision_dba_experiment import save,outcomes,predict,authenticate
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256

import argparse
parser=argparse.ArgumentParser();parser.add_argument('--source-root',type=Path)
args=parser.parse_args()
REPO=Path.cwd();ROOT=args.source_root or REPO/'artifacts/revision-research-closure-v1/groups'
DEST=ROOT/'interventions'
assert not DEST.exists()

def read(p):return json.loads(Path(p).read_bytes())
def key(group):return hashlib.sha256(derived_json_bytes(sorted(group))).hexdigest()[:16]

closed=read(ROOT/'selection-closure-before-labels.json')
truth=read(ROOT/'evaluation-truth.json')['cases']
cfg=read(REPO/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
save(DEST/'protocol-before-effects.json',{
    'source':implementation_sha256(),'controller_sha256':sha256_file(Path(__file__)),
    'selection_sha256':sha256_file(ROOT/'selection-closure-before-labels.json'),
    'direct':'R10 fixed inputs, original FedAvg sample masses, each member and joint set removed.',
    'controls':'Five SHA256-ranked never-attacker sets of equal cardinality plus the closest original sample-mass benign set; effects not inspected before selection.',
    'continuation':'For source full-trigger validation ASR>=.20, union of selected individual/joint removals, one mass-matched benign control per method and no-removal branch. Reaggregate R10 then train fresh R11-15 from each corrected base. Replay all local training at R11/R15.',
    'scope':'Known Data24 replay. Late correction does not certify a clean past, unlearning or malicious intent.'})
results=[];totals={'direct_outputs':0,'continuation_branches':0,'training_calls':0,'training_repeats':0}
for item in closed['cases']:
    source=next(t for t in truth if t['alias']==item['alias'])
    task=source['task'];workspace=ROOT/'cases'/item['alias']
    authenticate(workspace,source['manifest_sha256'])
    gen=Generator(REPO/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid'),cfg)
    rows=read(cfg['validation_path'])['rows']['validation']
    original_pred,_=predict(gen.initial,rows,gen.deps)
    correct=[p==r['label'] for p,r in zip(original_pred,rows,strict=True)]
    plan=DistributedBackdoorPlan.model_validate({**cfg['attack_plan'],'seed':task['seed'],
        'client_components':dict(zip(task['attackers'],[[13],[17],[24]],strict=True))})
    p=workspace/'rounds/round-010';base=read(p/'base-model.json')
    exports=[read(p/'updates'/f'{c}.json') for c in gen.clients]
    reconstructed=aggregate_selected(gen,base,exports,[])
    assert derived_json_bytes(reconstructed)==(p/'global-model.json').read_bytes()
    source_metric=outcomes(reconstructed,rows,plan,correct,gen.deps)
    attackers=set(task['attackers']) if task['mode']=='distributed' else set()
    benign=sorted(set(gen.clients)-attackers)
    requested={():{'roles':['no-removal']}}
    for method in ('v2','v3'):
        group=sorted(item[method])
        if not group:continue
        for subset in [group,*[[c] for c in group]]:
            entry=requested.setdefault(tuple(subset),{'roles':[]});entry['roles'].append(method+('-joint' if subset==group else '-individual'))
        selected_mass=sum(len(gen.rows[c]) for c in group)
        controls=list(combinations(benign,len(group)))
        random_controls=sorted(controls,key=lambda g:key(g))[:5]
        mass_control=min(controls,key=lambda g:(abs(sum(len(gen.rows[c]) for c in g)-selected_mass),key(g)))
        for subset in set(random_controls+[mass_control]):
            entry=requested.setdefault(tuple(subset),{'roles':[]});entry['roles'].append(method+'-benign-control')
        requested[tuple(mass_control)]['roles'].append(method+'-mass-matched-control')
    save(DEST/item['alias']/'controls-before-effects.json',{'groups':[{'removed':list(g),**meta} for g,meta in requested.items()]})
    output=[]
    for removed,meta in requested.items():
        model=aggregate_selected(gen,base,exports,list(removed))
        assert model is not None
        repeated=aggregate_selected(gen,base,exports,list(removed));assert repeated==model
        metric=outcomes(model,rows,plan,correct,gen.deps)
        target=DEST/item['alias']/key(removed)
        save(target/'R10-model.json',model)
        effect={'removed':list(removed),'roles':meta['roles'],'R10':metric,
                'removed_sample_mass':sum(len(gen.rows[c]) for c in removed)}
        totals['direct_outputs']+=1
        eligible=source_metric['complete_trigger']['asr']>=.20 and (
            not removed or any(r.endswith(('-joint','-individual','-mass-matched-control')) for r in meta['roles']))
        if eligible:
            trajectory=[];state=model
            for number in range(11,16):
                prefix=target/'rounds'/f'round-{number:03d}'
                save(prefix/'base-model.json',state)
                _,_,local,training=gen.execute(state,task['seed'],number)
                totals['training_calls']+=15
                if number in (11,15):
                    _,_,repeat,_=gen.execute(state,task['seed'],number)
                    assert repeat==local;totals['training_repeats']+=15
                for c,e in zip(gen.clients,local,strict=True):save(prefix/'updates'/f'{c}.json',e)
                state=aggregate_selected(gen,state,local,list(removed))
                save(prefix/'global-model.json',state)
                metric=outcomes(state,rows,plan,correct,gen.deps)
                if not removed:
                    assert derived_json_bytes(state)==(workspace/'rounds'/f'round-{number:03d}'/'global-model.json').read_bytes()
                frame={'round':number,'removed':list(removed),'training':training,'validation':metric}
                save(prefix/'round.json',frame);trajectory.append(frame)
            effect['continuation']=trajectory
            totals['continuation_branches']+=1
        save(target/'effect.json',effect);output.append(effect)
    results.append({'alias':item['alias'],'task':task,'source_R10':source_metric,'interventions':output})
    (DEST/'progress.json').write_text(json.dumps({'completed_cases':len(results),'total_cases':len(closed['cases']),'counts':totals})+'\n')
    print(json.dumps({'intervention_case':item['alias'],'counts':totals}),flush=True)
save(DEST/'results.json',{'cases':results,'counts':totals})
Generator.close(DEST)
print('GROUP INTERVENTIONS FINISHED',json.dumps(totals),flush=True)
