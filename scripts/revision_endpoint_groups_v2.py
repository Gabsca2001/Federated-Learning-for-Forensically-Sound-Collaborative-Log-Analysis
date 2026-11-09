"""Clean-calibrated retrospective groups on immutable effective endpoint DBA histories.

Research software only. Selection precedes truth-based evaluation and effects.
Late R10 correction is distinct from removal of the complete poisoned history.
"""
from pathlib import Path
import os
from collections import Counter
import argparse, json, os
import numpy as np
import revision_coherent_endpoint_dba as source
from coherent_gradient_protocol import (digest,array_record,delta_digest,make_context,
    update_record,assess_round,verify_round)
from endpoint_attack_selection import poisoned_endpoint
from endpoint_group_protocol import select_groups,removal_plan,remove_and_aggregate,group_key
from endpoint_group_allocation_guard import allocation_identity,require_unique_allocations
from revision_study_data import read,Generator
from revision_dba_experiment import save,authenticate,evaluate,outcomes,predict,model_with_arrays
from fl_forensics.byzantine import update_indicators
from fl_forensics.retrospective_groups import pair_descriptors
from fl_forensics.group_calibration_v2 import fit_group_reference,calibrate_group_threshold
from fl_forensics.group_calibration_v3 import calibrate_tree_groups
from fl_forensics.federated_partitioning import _dirichlet_assignments
from fl_forensics.federated_model import arrays_from_export,dependencies
from fl_forensics.canonical import sha256_file
from fl_forensics.round_derivation import implementation_sha256

R=source.R;B=source.D;D=R/'results/revision-endpoint-retrospective-groups-v2'
O=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'endpoint-groups-20261107')
FIT=[6117001,6118001];CAL=[6119001,6120001,6121001]


def guard():
    s=os.statvfs('/mnt/c');free=s.f_bavail*s.f_frsize
    used=source.allocated(D)+source.allocated(O/'published')
    if free<8*1024**3 or used>64*1024**2:raise RuntimeError('Fixed storage guard failed')
    return dict(host_free_bytes=free,new_allocated_bytes=used)


def locks():
    files=[R/'scripts'/n for n in ('revision_endpoint_groups_v2.py','endpoint_group_protocol.py','endpoint_group_allocation_guard.py',
        'revision_coherent_endpoint_dba.py','endpoint_attack_selection.py','coherent_gradient_protocol.py')]
    files+=[R/'src/fl_forensics'/n for n in ('retrospective_groups.py','group_calibration_v2.py','group_calibration_v3.py','federated_partitioning.py')]
    files+=[R/'tests/test_endpoint_group_protocol.py',R/'tests/test_endpoint_group_allocation_guard.py']
    return {str(p.relative_to(R)):sha256_file(p) for p in files}


def check(p):
    assert locks()==p['source_locks']
    q=read(B/'protocol-before-training.json');pp,op,old=source.check(q)
    assert sha256_file(B/'protocol-before-training.json')==p['source_protocol_sha256']
    assert sha256_file(B/'file-checksums.json')==p['source_publication_index_sha256']
    assert all(sha256_file(B/n)==h for n,h in read(B/'file-checksums.json').items())
    assert sha256_file(R/'artifacts/revision-capped-final-v1/partitions/6116106/manifest.json')==p['clean_pool_manifest_sha256']
    assert implementation_sha256()==p['core_implementation_sha256']
    return q,pp,op,old


def prepare():
    assert not D.exists();storage=guard();q=read(B/'protocol-before-training.json');source.check(q)
    cases=[]
    for seed in (6116104,6116105):
        for mode in ('clean','distributed','complete-trigger'):
            task=next(t for t in q['tasks'] if t['seed']==seed and t['mode']==mode and t['method']=='coherent_fedavg')
            cases.append(dict(alias=f'case-{len(cases):02d}',task=task))
    template=read(Path(source.check(q)[0]['initial_model_path']))
    original_rows,_,_=source.pilot.data_source.seed_data(6116106,template['class_names'])
    union=sorted([r for rs in original_rows.values() for r in rs],key=lambda r:r['window_id'])
    allocation_records={}
    for seed in FIT+CAL:
        allocations=_dirichlet_assignments(union,client_count=15,seed=seed,alpha=.3,minimum_rows=32,np=np)
        rows={f'client{i+1:02d}':rs for i,rs in enumerate(allocations)}
        allocation_records[str(seed)]=allocation_identity(rows)
    for seed in (6116104,6116105):
        rows,_,_=source.pilot.data_source.seed_data(seed,template['class_names'])
        allocation_records[str(seed)]=allocation_identity(rows)
    require_unique_allocations(allocation_records)
    p=dict(profile='endpoint-retrospective-late-removal-v2',source_locks=locks(),
        source_protocol_sha256=sha256_file(B/'protocol-before-training.json'),
        source_publication_index_sha256=sha256_file(B/'file-checksums.json'),
        core_implementation_sha256=implementation_sha256(),
        clean_pool_manifest_sha256=sha256_file(R/'artifacts/revision-capped-final-v1/partitions/6116106/manifest.json'),
        fit_allocation_seeds=FIT,calibration_allocation_seeds=CAL,cases=cases,allocation_preflight=allocation_records,
        previous_blocked_attempt_protocol_sha256=sha256_file(R/'results/revision-endpoint-retrospective-groups-v1/protocol-before-observation.json'),
        allocation_guard='Seed intervals are separated by1000 to avoid overlapping retry ranges; actual membership uniqueness, population equality and fit/calibration/evaluation separation are checked before training. The failed adjacent-seed v1 attempt is preserved.',
        allocation='Five new in-memory Dirichlet alpha=.3 allocations, minimum32 rows/client,15 clients, from the same pinned7096 training occurrences. No new dataset copies; allocation digests and counts retained. Disjoint campaign allocations, not disjoint populations or independent-data validation.',
        clean_training='Ten coherent full-batch gradient rounds, eta.001, same initial checkpoint and common pooled loss as the source. Fit2 clean allocations, calibrate3 separate clean allocations, evaluate2 separate source clean allocations plus4 effective raw attacked histories.',
        observables='Rounds1-10 only. Raw exported submission deltas, median-centered cosine, per-tensor deviation profile and temporal indicators. Validation impact uses the same3163 root-disjoint reused validation rows. Attacker IDs, attack modes, ASR and future rounds do not enter select_groups.',
        selection='Unmodified existing V2 pair-conditioned maximal-clique and V3 tree-connected pair/triple rules. Clean-only empirical maximum thresholds; strict exceedance. V2 chooses feasible clique with largest weakest pair score, then lexical order; V3 existing triples-first ranking, minimum10 survivors. Report empty groups and all false members/misses; no automatic exclusion authorization.',
        source_reconstruction='Recompute all selected client vectors and checkpoints at actual parents for all15 source rounds and compare input digests, complete round events, checkpoint hashes and metrics. Previously verified adaptive query grids remain immutable; this study does not claim a new replay of unselected source queries.',
        interventions='At R10 fixed actual source parent and selected submission vectors, omit each selected member and the joint group. Reaggregate raw FedAvg with renormalized surviving sample counts. Include no-removal and a separately labelled known-attacker oracle diagnostic.',
        controls='After group selection closes and before effects, choose five SHA256-ranked equal-size never-attacker sets and the closest sample-mass benign set; ties by digest. Preserve both cardinality and mass difference. These descriptive controls are not randomized inferential p-values.',
        future='From each R10 corrected checkpoint, recompute R11-15 gradients at every corrected parent with the same fixed removed set omitted from aggregation. Only no-removal, group joint, each individual and one closest-mass benign control per method/oracle receive continuation. Attack source has no active poisoning in R11-15. No-removal must reproduce all five source checkpoint hashes.',
        interpretation='Late intervention cannot erase R1-9 contamination or certify exact unlearning. Groups are compatible with coordinated updates, not proof of intention. Raw effective controls, not the already contained defended histories, are the investigation subjects.',
        scope='Exploratory reused Data24/warm start, two attack assignments and finite endpoint family. Newly recalibrated existing selectors, not a claim of held-out method selection across all prior research. No test inference, TPM quotes, client signatures, deployment/default or thesis changes.',
        maximum_combined_output_bytes=64*1024**2,minimum_host_free_bytes=8*1024**3,storage_before=storage)
    D.mkdir();save(D/'protocol-before-observation.json',p)
    print(json.dumps(dict(prepared=True,clean_fit=2,clean_calibration=3,source_cases=6,storage=storage)),flush=True)


class Engine:
    def __init__(self,p):
        self.p=p;self.q,self.pp,self.op,self.old=check(p);self.deps=dependencies()
        self.deps[1].set_num_threads(1);self.deps[1].use_deterministic_algorithms(True)
        self.initial=read(Path(self.pp['initial_model_path']));self.weights=self.q['loss_contract']['client_effective_class_weights']
        rows=read(Path(self.old['training']['validation_path']))['rows']['validation'];pool=set(self.q['root_ids'])
        self.evaluation=[r for r in rows if r['window_id'] not in pool];assert len(self.evaluation)==3163
        pred,_=predict(self.initial,self.evaluation,self.deps)
        self.correct=[x==r['label'] for x,r in zip(pred,self.evaluation,strict=True)]
        source_rows,_,_=source.pilot.data_source.seed_data(6116106,self.initial['class_names'])
        self.union=sorted([r for rs in source_rows.values() for r in rs],key=lambda r:r['window_id'])
        assert len(self.union)==len({r['window_id'] for r in self.union})==7096
        self.rows_cache={};self.protocol_sha=sha256_file(D/'protocol-before-observation.json')

    def training_rows(self,seed):
        if seed not in self.rows_cache:
            if seed in FIT+CAL:
                allocation=_dirichlet_assignments(self.union,client_count=15,seed=seed,alpha=.3,minimum_rows=32,np=np)
                rows={f'client{i+1:02d}':v for i,v in enumerate(allocation)}
            else:rows,_,_=source.pilot.data_source.seed_data(seed,self.initial['class_names'])
            assert len({r['window_id'] for rs in rows.values() for r in rs})==7096
            assert sum(map(len,rows.values()))==7096
            assert allocation_identity(rows)==self.p['allocation_preflight'][str(seed)]
            self.rows_cache[seed]=rows
        return self.rows_cache[seed]

    def allocation_record(self,rows):
        return {c:dict(count=len(rs),ordered_ids_sha256=digest([r['window_id'] for r in rs])) for c,rs in rows.items()}

    def context(self,model,number,alias):
        base=arrays_from_export(model,np=np)
        return make_context(parent_model_sha256=source.pilot.old_study.export_digest(model),
            base_tensor_digest=digest(array_record([a.astype(float) for a in base])),round_number=number,
            attempt_id=f'{alias}-r{number:03d}',protocol_sha256=self.protocol_sha,
            loss_contract_sha256=self.q['loss_contract_sha256'],roster=[f'client{i:02d}' for i in range(1,16)],method='coherent_fedavg')

    def observe_frame(self,model,updates,number):
        clients=sorted(updates);deltas=[updates[c]['delta'] for c in clients];base=arrays_from_export(model,np=np)
        indicators=update_indicators(deltas,client_ids=clients)
        base_f1=evaluate(model,self.evaluation,self.deps)['macro_f1_all_model_classes']
        for c,item in zip(clients,indicators,strict=True):
            endpoint=model_with_arrays(model,[a+d for a,d in zip(base,updates[c]['delta'],strict=True)])
            item['validation_impact']=base_f1-evaluate(endpoint,self.evaluation,self.deps)['macro_f1_all_model_classes']
        return dict(round_number=number,client_ids=clients,deltas=deltas,indicators=indicators)

    def clean_observation(self,seed):
        rows=self.training_rows(seed);model=self.initial;frames=[];journal=[]
        for number in range(1,11):
            guard();context=self.context(model,number,f'clean-{seed}');base=arrays_from_export(model,np=np)
            updates={c:update_record(c,context,source.pilot.gradient_step(model,rs,self.weights,self.deps)[0],len(rs),True) for c,rs in rows.items()}
            frame=self.observe_frame(model,updates,number);params,event=assess_round(base,updates,None,context)
            verify_round(base,updates,None,context,event);assert event['decision']=='commit'
            model=model_with_arrays(model,params);frames.append(frame)
            journal.append(dict(round=number,parent_sha256=context['parent_model_sha256'],
                input_delta_digests=event['input_delta_digests'],checkpoint_sha256=source.pilot.old_study.export_digest(model)))
        return frames,dict(seed=seed,allocation=self.allocation_record(rows),journal=journal,pairs=pair_descriptors(frames))

    def source_observation(self,entry,write_inputs):
        task=entry['task'];alias=entry['alias'];model=self.initial;rows=self.training_rows(task['seed']);clients=sorted(rows)
        original=read(B/'evidence/histories'/task['name']/'result.json');plan=source.plan_for(task)
        frames=[];journal=[]
        for oldrow in original['journal']:
            guard();number=oldrow['round'];base=arrays_from_export(model,np=np);context=oldrow['event']['context']
            assert context['parent_model_sha256']==source.pilot.old_study.export_digest(model)
            active=task['mode']!='clean' and number<=10;alpha=oldrow['selected_alpha'];updates={}
            for c in clients:
                clean,_=source.pilot.gradient_step(model,rows[c],self.weights,self.deps)
                delta=clean
                if active and c in task['attackers']:
                    changed,_=source.poison_local_rows(rows=rows[c],plan=plan,client_id=c,round_number=number,distributed=task['mode']!='complete-trigger')
                    endpoint=poisoned_endpoint(model,changed,self.weights,task['seed']+number*10000+int(c[6:])-1,self.deps)
                    poisoned=[a.astype(float)-b for a,b in zip(arrays_from_export(endpoint,np=np),base,strict=True)]
                    delta=clean if alpha==0 else poisoned if alpha==1 else [a+alpha*(b-a) for a,b in zip(clean,poisoned,strict=True)]
                updates[c]=update_record(c,context,delta,len(rows[c]),True)
            params,event=assess_round(base,updates,None,context);assert event==oldrow['event']
            verify_round(base,updates,None,context,event);assert params is not None
            if number<=10:frames.append(self.observe_frame(model,updates,number))
            if number==10:
                meta=dict(context=context,shapes=[list(a.shape) for a in base],clients=clients,
                    facts={c:{k:v for k,v in u.items() if k!='delta'} for c,u in updates.items()},
                    original_event=event,source_checkpoint_sha256=oldrow['exported_checkpoint_sha256'])
                target=D/'selection-evidence/inputs'/alias
                if write_inputs:
                    target.mkdir(parents=True)
                    np.savez_compressed(target/'r10-inputs.npz',base=np.concatenate([a.ravel() for a in base]),
                        deltas=np.stack([np.concatenate([a.ravel() for a in updates[c]['delta']]) for c in clients]))
                    meta['arrays_sha256']=sha256_file(target/'r10-inputs.npz');save(target/'metadata.json',meta)
                else:
                    expected=read(target/'metadata.json');assert {k:v for k,v in expected.items() if k!='arrays_sha256'}==meta
                    assert sha256_file(target/'r10-inputs.npz')==expected['arrays_sha256']
                    b,u,_=self.load_inputs(alias)
                    for a,z in zip(base,b,strict=True):np.testing.assert_array_equal(a,z)
                    for c in clients:
                        for a,z in zip(updates[c]['delta'],u[c]['delta'],strict=True):np.testing.assert_array_equal(a,z)
            model=model_with_arrays(model,params)
            assert source.pilot.old_study.export_digest(model)==oldrow['exported_checkpoint_sha256']
            metric=source.compact(outcomes(model,self.evaluation,plan,self.correct,self.deps));assert metric==oldrow['validation']
            journal.append(dict(round=number,checkpoint_sha256=oldrow['exported_checkpoint_sha256'],input_delta_digests=event['input_delta_digests']))
        return frames,dict(alias=alias,rounds_reconstructed=len(journal),journal=journal,pairs=pair_descriptors(frames),
            source_result_sha256=sha256_file(B/'evidence/histories'/task['name']/'result.json'))

    def load_inputs(self,alias):
        root=D/'selection-evidence/inputs'/alias;meta=read(root/'metadata.json')
        assert sha256_file(root/'r10-inputs.npz')==meta['arrays_sha256']
        shapes=meta['shapes'];cuts=np.cumsum([0]+[int(np.prod(s)) for s in shapes])
        def unpack(x):return [x[cuts[i]:cuts[i+1]].reshape(s).copy() for i,s in enumerate(shapes)]
        with np.load(root/'r10-inputs.npz',allow_pickle=False) as z:
            base=unpack(z['base']);updates={c:{**meta['facts'][c],'delta':unpack(z['deltas'][i])} for i,c in enumerate(meta['clients'])}
        for c in updates:assert delta_digest(updates[c]['delta'])==updates[c]['delta_digest']
        params,event=assess_round(base,updates,None,meta['context']);assert event==meta['original_event']
        assert source.pilot.old_study.export_digest(model_with_arrays(self.initial,params))==meta['source_checkpoint_sha256']
        return base,updates,meta

    def effects(self,entry,plan):
        alias=entry['alias'];task=entry['task'];base,updates,meta=self.load_inputs(alias)
        attack_plan=source.plan_for(task);rows=self.training_rows(task['seed']);original=read(B/'evidence/histories'/task['name']/'result.json')
        outputs=[]
        for request in plan['removals']:
            guard();removed=request['removed'];params,event=remove_and_aggregate(base,updates,meta['context'],removed)
            assert params is not None;model=model_with_arrays(self.initial,params)
            direct=source.compact(outcomes(model,self.evaluation,attack_plan,self.correct,self.deps))
            item=dict(**request,direct=dict(event=event,model_sha256=source.pilot.old_study.export_digest(model),metrics=direct),continuation=[])
            should_continue=not removed or any(role.endswith(('-joint','-individual','-mass-matched-control')) for role in request['roles'])
            if should_continue:
                for number in range(11,16):
                    context=self.context(model,number,alias+'-remove-'+request['key'])
                    current=arrays_from_export(model,np=np)
                    fresh={c:update_record(c,context,source.pilot.gradient_step(model,rs,self.weights,self.deps)[0],len(rs),True)
                        for c,rs in rows.items() if c not in removed}
                    params,future=assess_round(current,fresh,None,context)
                    verify_round(current,fresh,None,context,future);assert params is not None
                    model=model_with_arrays(model,params);checkpoint=source.pilot.old_study.export_digest(model)
                    metric=source.compact(outcomes(model,self.evaluation,attack_plan,self.correct,self.deps))
                    if not removed:
                        oldrow=original['journal'][number-1];assert checkpoint==oldrow['exported_checkpoint_sha256'] and metric==oldrow['validation']
                    item['continuation'].append(dict(round=number,event=future,model_sha256=checkpoint,metrics=metric))
                model_values=arrays_from_export(model,np=np)
                clean_name=f"s{task['seed']}-coherent_fedavg-clean"
                clean=arrays_from_export(read(B/'evidence/histories'/clean_name/'last-committed-checkpoint.json'),np=np)
                item['final_parameter_l2_to_full_roster_clean']=float(np.linalg.norm(np.concatenate([(a.astype(float)-b).ravel() for a,b in zip(model_values,clean,strict=True)])))
            outputs.append(item)
        return dict(alias=alias,interventions=outputs,source_R10=original['journal'][9]['validation'],
            source_R15=original['journal'][14]['validation'],plan=plan)


def observe():
    p=read(D/'protocol-before-observation.json');engine=Engine(p);E=D/'selection-evidence';assert not E.exists()
    save(E/'protocol.json',p);clean={}
    for seed in FIT+CAL:
        frames,record=engine.clean_observation(seed);clean[seed]=frames
        save(E/'clean'/f'{seed}.json',record);print(json.dumps(dict(clean_observation=seed)),flush=True)
    reference=fit_group_reference([clean[s] for s in FIT])
    c2=calibrate_group_threshold([clean[s] for s in CAL],reference)
    c3=calibrate_tree_groups([clean[s] for s in CAL],reference)
    for name,v in [('reference',reference),('v2-calibration',c2),('v3-calibration',c3)]:save(E/'calibration'/f'{name}.json',v)
    del clean
    selected=[]
    for entry in p['cases']:
        frames,record=engine.source_observation(entry,True);v=select_groups(frames,reference,c2,c3)
        save(E/'observations'/f"{entry['alias']}.json",record);save(E/'selection'/f"{entry['alias']}.json",v)
        selected.append(dict(alias=entry['alias'],v2=v['v2']['selected_group'],v3=v['v3']['selected_group']))
        print(json.dumps(dict(alias=entry['alias'],v2=v['v2']['selected_group'],v3=v['v3']['selected_group'])),flush=True)
    save(E/'selection-closure-before-evaluation.json',dict(cases=selected,selector_receives_attack_labels=False,
        future_frames_used=False,group_effects_used=False,not_process_isolated_blinding=True))
    check(p);Generator.close(E);save(D/'selection-closure.json',dict(manifest_sha256=sha256_file(E/'manifest.json')))


def plan_effects():
    p=read(D/'protocol-before-observation.json');engine=Engine(p);E=D/'selection-evidence'
    authenticate(E,read(D/'selection-closure.json')['manifest_sha256']);closed=read(E/'selection-closure-before-evaluation.json')
    plans=[];membership=[]
    for entry in p['cases']:
        selected=next(s for s in closed['cases'] if s['alias']==entry['alias']);task=entry['task']
        truth=task['attackers'] if task['mode']!='clean' else []
        rows=engine.training_rows(task['seed']);clients=sorted(rows);counts={c:len(v) for c,v in rows.items()}
        plans.append(dict(alias=entry['alias'],plan=removal_plan(selected,clients,counts,truth)))
        for method in ('v2','v3'):
            group=set(selected[method]);v=read(E/'selection'/f"{entry['alias']}.json")[method]
            candidates=v['candidate_groups'];pool=set(c for g in candidates for c in (g['clients'] if isinstance(g,dict) else g))
            membership.append(dict(alias=entry['alias'],seed=task['seed'],mode=task['mode'],method=method,
                selected_group=sorted(group),TP=len(group&set(truth)),FP=len(group-set(truth)),FN=len(set(truth)-group),
                pool_TP=len(pool&set(truth)),pool_FP=len(pool-set(truth)),pool_FN=len(set(truth)-pool)))
    save(D/'plans-before-effects.json',dict(selection_manifest_sha256=sha256_file(E/'manifest.json'),plans=plans))
    save(D/'membership-evaluation.json',dict(cases=membership,selection_already_closed=True))


def effects():
    p=read(D/'protocol-before-observation.json');engine=Engine(p);planned=read(D/'plans-before-effects.json')
    authenticate(D/'selection-evidence',planned['selection_manifest_sha256'])
    E=D/'effects-evidence';assert not E.exists();save(E/'plans-before-effects.json',planned)
    for entry in p['cases']:
        plan=next(x['plan'] for x in planned['plans'] if x['alias']==entry['alias'])
        result=engine.effects(entry,plan);save(E/f"{entry['alias']}.json",result)
        print(json.dumps(dict(alias=entry['alias'],direct_outputs=len(result['interventions']),
            continued_branches=sum(bool(i['continuation']) for i in result['interventions']))),flush=True)
    check(p);Generator.close(E);save(D/'effects-closure.json',dict(manifest_sha256=sha256_file(E/'manifest.json')))


def verify():
    p=read(D/'protocol-before-observation.json');engine=Engine(p);E=D/'selection-evidence'
    authenticate(E,read(D/'selection-closure.json')['manifest_sha256'])
    authenticate(D/'effects-evidence',read(D/'effects-closure.json')['manifest_sha256'])
    clean={}
    for seed in FIT+CAL:
        frames,record=engine.clean_observation(seed);assert record==read(E/'clean'/f'{seed}.json');clean[seed]=frames
        print(json.dumps(dict(replayed_clean=seed)),flush=True)
    reference=fit_group_reference([clean[s] for s in FIT]);assert reference==read(E/'calibration/reference.json')
    c2=calibrate_group_threshold([clean[s] for s in CAL],reference);assert c2==read(E/'calibration/v2-calibration.json')
    c3=calibrate_tree_groups([clean[s] for s in CAL],reference);assert c3==read(E/'calibration/v3-calibration.json');del clean
    direct=branches=rounds=0
    planned=read(D/'plans-before-effects.json')
    for entry in p['cases']:
        frames,record=engine.source_observation(entry,False);assert record==read(E/'observations'/f"{entry['alias']}.json")
        selected=select_groups(frames,reference,c2,c3);assert selected==read(E/'selection'/f"{entry['alias']}.json")
        task=entry['task'];truth=task['attackers'] if task['mode']!='clean' else []
        rows=engine.training_rows(task['seed']);counts={c:len(v) for c,v in rows.items()}
        plan=removal_plan({m:selected[m]['selected_group'] for m in ('v2','v3')},sorted(rows),counts,truth)
        assert plan==next(x['plan'] for x in planned['plans'] if x['alias']==entry['alias'])
        effect=engine.effects(entry,plan);assert effect==read(D/'effects-evidence'/f"{entry['alias']}.json")
        direct+=len(effect['interventions']);branches+=sum(bool(i['continuation']) for i in effect['interventions'])
        rounds+=sum(len(i['continuation']) for i in effect['interventions'])
        print(json.dumps(dict(replayed_case=entry['alias'],direct_outputs=direct,continuation_rounds=rounds)),flush=True)
    check(p)
    save(D/'verification.json',dict(status='observations_selection_and_interventions_fully_replayed',
        clean_calibration_histories=5,clean_calibration_rounds=50,source_histories=6,selected_source_rounds_reconstructed=90,
        direct_outputs=direct,continuation_branches=branches,continuation_rounds=rounds,
        source_adaptive_queries_reexecuted=False,selection_manifest_authenticated=True,effects_manifest_authenticated=True,
        same_implementation_replay=True,new_TPM_quotes=0,test_inference=False,default_changed=False,storage=guard()))
    print(json.dumps(read(D/'verification.json'),indent=2),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('prepare','observe','plan','effects','verify'));args=parser.parse_args()
    {'prepare':prepare,'observe':observe,'plan':plan_effects,'effects':effects,'verify':verify}[args.phase]()
