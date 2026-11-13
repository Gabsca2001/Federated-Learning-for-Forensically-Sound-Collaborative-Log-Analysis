"""Secondary frozen-update interventions for every predeclared predictor view."""
from pathlib import Path
from itertools import combinations
from fractions import Fraction
import numpy as np
from study_data import read
from revision_dba_experiment import save,read_pinned,outcomes,predict,model_with_arrays
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan
from fl_forensics.federated_model import dependencies,arrays_from_export
from fl_forensics.byzantine import model_delta,aggregate_deltas,apply_delta

repo=Path.cwd();lab=repo/'artifacts/revision-state-conditioned-heldout-v1';out=Path(__file__).parent
evaluation=read(lab/'post-selection-evaluation.json')
save(lab/'secondary-effect-protocol-before-computation.json',{'profile':'dual-view-selected-set-direct-effects-v1',
    'evaluation_sha256':sha256_file(lab/'post-selection-evaluation.json'),
    'selection_closure_sha256':sha256_file(lab/'selections/selection-closure.json'),
    'scope':'Secondary evaluation after classification outcomes. All three predeclared methods, every attacked case, no set pruning by ground truth.',
    'interventions':'Round-10 frozen FedAvg removal of complete flagged set, each member individually, up to 20 benign size-matched controls chosen without looking at effects.',
    'control_seed':'case seed + 1000 * group size; without replacement from lexicographically ordered benign combinations',
    'quorum':8,'future_training_performed':False,'collusion_intent_proved':False,
    'controller_sha256':sha256_file(Path(__file__))})
cfg=read(repo/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
validation=read_pinned(cfg['validation_path'],cfg['validation_sha256'])['rows']['validation']
initial=read_pinned(cfg['base_model_path'],cfg['base_model_sha256'])
deps=dependencies();deps[1].set_num_threads(1)
predicted,_=predict(initial,validation,deps);correct=[p==r['label'] for p,r in zip(predicted,validation,strict=True)]
results=[];cache={}
for case in evaluation['rows']:
    if case['mode']!='distributed':continue
    source=lab/'private-generation/heldout'/case['source_case_id'];last=source/'rounds/round-010'
    partition=read(repo/'artifacts'/('m3-data24-parquet-iid-local-test-v1' if case['cohort']=='iid' else 'm3-data24-parquet-non-iid')/'manifest.json')
    counts={r['client_id']:r['train_row_count'] for r in partition['clients']};clients=sorted(counts)
    plan=DistributedBackdoorPlan.model_validate(read(source/'generation-protocol.json')['attack_plan_for_generation_and_evaluation_only'])
    base=read(last/'base-model.json');arrays=arrays_from_export(base,np=np)
    local={c:arrays_from_export(read(last/'updates'/f'{c}.json'),np=np) for c in clients}
    original=read(last/'global-model.json');original_arrays=arrays_from_export(original,np=np)
    original_outcomes=outcomes(original,validation,plan,correct,deps)
    def remove(group):
        key=(case['source_case_id'],tuple(sorted(group)))
        if key in cache:return cache[key]
        selected=sorted(set(clients)-set(group))
        if len(selected)<8:return {'status':'quorum-insufficient','model_available':False}
        model=model_with_arrays(base,apply_delta(arrays,aggregate_deltas([model_delta(arrays,local[c]) for c in selected],strategy='fedavg',f=0,weights=[counts[c] for c in selected])))
        result=outcomes(model,validation,plan,correct,deps)
        difference=sum(float(np.square(a.astype(np.float64)-b.astype(np.float64)).sum()) for a,b in zip(original_arrays,arrays_from_export(model,np=np),strict=True))**.5
        value={'status':'aggregated','ASR':result['complete_trigger']['asr'],
            'ASR_reduction':original_outcomes['complete_trigger']['asr']-result['complete_trigger']['asr'],
            'clean_macro_f1':result['clean']['macro_f1_all_model_classes'],'clean_accuracy':result['clean']['accuracy'],
            'model_l2_change':difference}
        cache[key]=value;return value
    group=case['flagged_clients']
    if not group:
        results.append({k:case[k] for k in ('cohort','seed','method','source_case_id')}|{'status':'no-candidate'});continue
    joint=remove(group)
    if joint['status']!='aggregated':
        results.append({k:case[k] for k in ('cohort','seed','method','source_case_id')}|{'selected_clients':group,**joint});continue
    singles=[{'client':c,**remove([c])} for c in group]
    benign=sorted(set(clients)-set(case['active_poisoning_clients']))
    combinations_list=list(combinations(benign,len(group)))
    rng=np.random.default_rng(case['seed']+1000*len(group))
    indexes=sorted(rng.choice(len(combinations_list),min(20,len(combinations_list)),replace=False)) if combinations_list else []
    controls=[{'group':list(combinations_list[i]),**remove(combinations_list[i])} for i in indexes]
    beta=Fraction(sum(counts[c] for c in group),sum(counts.values()))
    results.append({k:case[k] for k in ('cohort','seed','method','source_case_id')}|{
        'status':'evaluated','selected_clients':group,'ground_truth_overlap_for_evaluation_only':sorted(set(group)&set(case['active_poisoning_clients'])),
        'original_ASR':original_outcomes['complete_trigger']['asr'],'original_clean_macro_f1':original_outcomes['clean']['macro_f1_all_model_classes'],
        'joint':joint,'individuals':singles,'benign_size_matched_controls':controls,
        'joint_reduction_beyond_largest_individual':joint['ASR_reduction']-max(s['ASR_reduction'] for s in singles),
        'benign_controls_at_least_as_effective':sum(c['ASR_reduction']>=joint['ASR_reduction'] for c in controls),
        'removed_weight':{'numerator':str(beta.numerator),'denominator':str(beta.denominator)},
        'original_fixed_population_Delta_L1':{'numerator':str((2*beta).numerator),'denominator':str((2*beta).denominator)},
        'original_J':1,'interpretation':'Conditional round-local effect under frozen stored updates. Neither every selected member malice nor complete history repair is established.'})
save(lab/'secondary-selected-effects.json',{'profile':'dual-view-selected-set-direct-effects-v1','rows':results,
    'unique_reaggregations':len(cache),'new_local_training_calls':0,'future_training_performed':False})
(out/'secondary-selected-effects.json').write_bytes((lab/'secondary-selected-effects.json').read_bytes())
for r in results:
    if r['method']=='fusion':print({k:r[k] for k in ('cohort','seed','selected_clients','original_ASR','joint','joint_reduction_beyond_largest_individual') if k in r},flush=True)
