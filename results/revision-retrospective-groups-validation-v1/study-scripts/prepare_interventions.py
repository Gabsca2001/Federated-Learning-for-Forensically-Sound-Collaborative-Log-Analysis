"""Close all removal choices before evaluating any intervention effect."""
from itertools import combinations
import random
from group_common import *

selection=read(LAB/'selection-closure-before-labels.json');private=read(LAB/'private-alias-map.json')
for row in selection['cases']:assert sha256_file(LAB/'selections'/f"{row['alias']}.json")==row['sha256']
partitions={'iid':'m3-data24-parquet-iid-local-test-v1','non-iid':'m3-data24-parquet-non-iid'}
cases=[];jobs=[]
for row in selection['cases']:
    alias=row['alias'];item=private[alias];task=item['task'];cohort=task['cohort']
    records=read(REPO/'artifacts'/partitions[cohort]/'manifest.json')['clients'];mass={r['client_id']:r['train_row_count'] for r in records}
    clients=sorted(mass);truth=sorted(task['attackers']) if task['mode']=='distributed' else []
    complete=read(LAB/'selections'/f'{alias}.json');pool=sorted({c for g in row['candidate_groups'] for c in g})
    methods=[];direct={};continuation={}
    def removal(group,role,train=False,clean_reference=False):
        group=sorted(group);k=key(group)
        direct.setdefault(k,{'removed':group,'roles':[]})['roles'].append(role)
        if train and task['mode']=='distributed':
            mode='unmodified' if clean_reference else 'original-script'
            name=mode+'-'+k
            continuation.setdefault(name,{'branch':name,'removed':group,'data_mode':mode,'roles':[]})['roles'].append(role)
        return k
    removal([],'no-intervention',train=True)
    for name,group in [('pair-v2',row['primary_selected']),('envelope-prefix-set',row['envelope_prefix_set'])]:
        group=sorted(group);eligible=bool(group) and len(clients)-len(group)>=8
        result={'method':name,'selected':group,'eligible':eligible,'tp':len(set(group)&set(truth)),
            'fp':len(set(group)-set(truth)),'fn':len(set(truth)-set(group)),
            'selection_is_pairwise_group':name=='pair-v2','exact_experimental_membership':set(group)==set(truth) if truth else None}
        if eligible:
            removal(group,name+':joint',train=True)
            removal(group,name+':same-start-unmodified-reference',train=True,clean_reference=True)
            individual=[removal([c],name+':individual:'+c,train=True) for c in group]
            benign=sorted(set(clients)-set(truth))
            possible=[list(g) for g in combinations(benign,len(group)) if list(g)!=group]
            selected_mass=sum(mass[c] for c in group)
            closest=min(possible,key=lambda g:(abs(sum(mass[c] for c in g)-selected_mass),tuple(g))) if possible else None
            seed=int(sha256_bytes(derived_json_bytes({'alias':alias,'group':group,'purpose':'benign-controls-v1'}))[:16],16)
            sampled=random.Random(seed).sample(possible,min(20,len(possible)))
            controls={key(g):g for g in sampled}
            if closest is not None:controls[key(closest)]=closest
            for g in controls.values():removal(g,name+':benign-direct')
            replay_controls=[]
            for role,g in [('closest-mass',closest),('hash-random-first',sampled[0] if sampled else None)]:
                if g is not None:removal(g,name+':benign-continuation:'+role,train=True);replay_controls.append({'role':role,'removed':g})
            result.update({'joint_key':key(group),'individual_keys':individual,'direct_benign_controls':list(controls.values()),
                'continuation_benign_controls':replay_controls,'selected_original_sample_mass':selected_mass,
                'selected_original_mass_fraction':selected_mass/sum(mass.values()),'control_sampling_seed':seed})
        methods.append(result)
    cases.append({'alias':alias,'source':item['source'],'source_manifest_sha256':item['manifest_sha256'],'task':task,
        'client_masses':mass,'truth_for_evaluation_only':truth,'candidate_groups':row['candidate_groups'],
        'primary_pool':{'clients':pool,'tp':len(set(pool)&set(truth)),'fp':len(set(pool)-set(truth)),
            'fn':len(set(truth)-set(pool))},'methods':methods,'direct_removals':list(direct.values())})
    for branch in continuation.values():jobs.append({'alias':alias,'cohort':cohort,'source':item['source'],'task':task,**branch})
protocol={'profile':'group-interventions-fixed-before-effects-v1','selection_closure_sha256':sha256_file(LAB/'selection-closure-before-labels.json'),
    'cases':cases,'jobs':jobs,'code_sha256':{n:sha256_file(OUT/n) for n in ('group_common.py','prepare_interventions.py','run_interventions.py')},
    'control_detail':'Uniform benign subsets except the identical selected subset; overlaps with benign false members are allowed and retained. Closest mass uses only original sample counts, never outcomes. Missing controls are explicit.',
    'source_histories_previously_evaluated':True,'thesis_changed':False,'production_code_changed':False}
save(LAB/'interventions-protocol-before-computation.json',protocol)
save(OUT/'selection-summary.json',{'cases':[{'alias':c['alias'],'task':c['task'],'primary_pool':c['primary_pool'],
    'candidate_groups':c['candidate_groups'],'methods':[{k:v for k,v in m.items() if k in ('method','selected','eligible','tp','fp','fn','exact_experimental_membership','selected_original_mass_fraction')} for m in c['methods']]} for c in cases]})
print('INTERVENTIONS FROZEN',json.dumps({'cases':len(cases),'direct_removals':sum(len(c['direct_removals']) for c in cases),
    'continuation_branches':len(jobs),'new_continuation_training_calls':sum((6 if j['data_mode']=='unmodified' else 5)*(15-len(j['removed'])) for j in jobs)}),flush=True)
