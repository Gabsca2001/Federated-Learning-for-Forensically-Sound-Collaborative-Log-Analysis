"""Frozen V4 attribution assessment and fresh-parent recovery from pre-attack W0.

Software research only. No operational exclusion, physical TPM or new dataset.
"""
from pathlib import Path
import os
import argparse,os,json
import numpy as np
import revision_endpoint_groups_v2 as prior
from endpoint_group_allocation_guard import allocation_identity,require_unique_allocations
from endpoint_group_protocol import group_key
from endpoint_recovery_protocol import forged_delta
from retrospective_anomaly_groups import fit_reference,calibrate,detect
from endpoint_attack_selection import FACTORS,select_endpoint_query,poisoned_endpoint
from coherent_gradient_protocol import (digest,array_record,make_context,update_record,assess_round,verify_round)
from coherent_dba_selection import worst_asr,poison_commitment
from revision_study_data import read,Generator
from revision_dba_experiment import save,authenticate,outcomes,evaluate,model_with_arrays
from fl_forensics.federated_partitioning import _dirichlet_assignments
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.canonical import sha256_file

R=prior.R;D=R/'results/admission/revision-attribution-origin-recovery-v1'
O=(Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'attribution-recovery-20261107')
ASSIGN={6122001:['client02','client08','client15'],6123001:['client03','client07','client11']}
FIT=prior.FIT;CAL=prior.CAL

def guard():
    s=os.statvfs('/mnt/c');free=s.f_bavail*s.f_frsize
    used=prior.source.allocated(D)+prior.source.allocated(O/'published')
    if free<8*1024**3 or used>64*1024**2:raise RuntimeError('Fixed storage budget/floor failed')
    return dict(host_free_bytes=free,new_allocated_bytes=used)

def locks():
    names=['revision_attribution_recovery.py','retrospective_anomaly_groups.py','endpoint_recovery_protocol.py']
    paths=[R/'scripts'/n for n in names]+[R/'tests/test_retrospective_anomaly_groups.py']
    return {str(p.relative_to(R)):sha256_file(p) for p in paths}

def check(p):
    assert locks()==p['source_locks'];previous=read(prior.D/'protocol-before-observation.json');prior.check(previous)
    assert sha256_file(prior.D/'file-checksums.json')==p['prior_publication_index_sha256']
    assert all(sha256_file(prior.D/n)==h for n,h in read(prior.D/'file-checksums.json').items())
    return previous

def prepare():
    assert not D.exists();storage=guard();previous=read(prior.D/'protocol-before-observation.json')
    engine=prior.Engine(previous);allocations={}
    for seed in FIT+CAL+list(ASSIGN):
        arrays=_dirichlet_assignments(engine.union,client_count=15,seed=seed,alpha=.3,minimum_rows=32,np=np)
        allocations[str(seed)]=allocation_identity({f'client{i+1:02d}':rs for i,rs in enumerate(arrays)})
    for seed in (6116104,6116105):allocations[str(seed)]=previous['allocation_preflight'][str(seed)]
    require_unique_allocations(allocations)
    tasks=[]
    for seed,attackers in ASSIGN.items():
        tasks.append(dict(alias=f'case-{len(tasks):02d}',seed=seed,attackers=attackers,mode='clean',family='unrestricted',role='assessment'))
        for family in ('unrestricted','relative-radius'):
            for mode in ('distributed','complete-trigger'):
                tasks.append(dict(alias=f'case-{len(tasks):02d}',seed=seed,attackers=attackers,mode=mode,family=family,role='assessment'))
    p=dict(profile='attribution-origin-recovery-v1',source_locks=locks(),
        prior_publication_index_sha256=sha256_file(prior.D/'file-checksums.json'),
        fit_seeds=FIT,calibration_seeds=CAL,assessment_assignments=ASSIGN,tasks=tasks,allocation_preflight=allocations,
        selector='V4: pooled clean log1p(relative norm) and positive validation-impact standardized increases; median of ten per-round maximum channel scores gives individual persistence. Fit2/calibrate3 clean campaigns; strict campaign-max threshold. Anomalous-client pairs require coactivity fraction strictly above max(.3,all clean calibration pair fractions). Maximal cliques, largest feasible then weakest persistent score then lexical order. Tensor pair descriptors are separate evidence. No known group size, labels, ASR or future rounds select groups.',
        calibration='Reuse five clean-only allocation roles from the failed V2/V3 transfer, freshly reconstruct their observations. New rule is developed after that failure; assessment uses two actual new allocations and attacker rosters frozen before new outcomes. Same reused Data24 population, initial model and validation, not independent-data confirmation.',
        training='Same full-batch float64 eval-mode coherent honest gradient, eta.001 and globally normalized weighted loss. Raw count-weighted FedAvg, minimum10 contributors; all prerequisite trust gates assumed passed in software.',
        attacks='Three fixed identities,ceil(.5*n_i) hashed poisoned rows each,features13/17/24 set12,target benign,rounds1-10,unmodified continuation11-15. Distributed assigns one feature each; complete-trigger assigns all3. Same row budgets, different feature-edit budgets. Malicious endpoints use10 Adam epochs, batch128,lr.001 at every actual parent.',
        families='Unrestricted: clean_delta+alpha*(poisoned_endpoint_delta-clean_delta). Relative-radius: clean_delta+alpha*||clean_delta||*unit(poisoned_endpoint_delta-clean_delta); each submitted norm <=(1+alpha)||clean_delta||,max5 times own clean norm. This is a restricted less-conspicuous family, not arbitrary stealth optimization.',
        adaptive_queries=list(FACTORS),adaptive_selection='Six queries at each actual parent/operator; among defined candidates losing at most.05 macro-F1 to own same-round same-removed-roster CLEAN history, maximize worst(full,3 single components) ASR then alpha. Privileged reused-validation/matched-clean oracle. No feasible candidate uses explicit unmodified alpha0; no zero ASR for undefined models.',
        effectiveness='At least.20 paired worst-trigger ASR increase with<=.05 F1 loss at the SAME round versus own clean control. Ineffective controls and membership misses stay reported.',
        recovery='Selection closes before labels/effects. Full-origin replays for effective source attacks and clean false-group cases only. Start from the preserved pre-attack W0 and retrain ALL15 rounds after each group/individual omission. Remaining attackers retrain poisoned endpoints and rerun the same six adaptive queries at every corrected parent duringR1-10. No stale original updates or original alphas are replayed.',
        controls='Include selected group joint/individual, separately labelled oracle group joint/individual, one hash-ranked and one closest-mass never-attacker group of equal size per method. Deduplicate sets; no-removal reproduces source history. Compare to a freshly trained clean history with the SAME omitted roster. Maximum48 requested replay branches; stop explicitly if exceeded, never trim by observed effects.',
        interpretation='V4 flags concurrent abnormal updates, not proven collusion or permanent exclusion. Exact matching to same-roster clean counterfactual is conditional on a clean W0, correct attribution and complete removal of active attackers, deterministic training/data and declared protocol. W0 authenticity does not itself establish cleanliness.',
        scope='Exploratory numerical research. Two fresh allocations reuse7096 rows and3163 root-disjoint validation rows; no test inference or independent dataset. No TPM/client signatures, new defaults or thesis edits. Previous failed selectors/late recovery and containment results remain unchanged.',
        maximum_combined_output_bytes=64*1024**2,minimum_host_free_bytes=8*1024**3,maximum_recovery_branches=48,storage_before=storage)
    D.mkdir();save(D/'protocol-before-training.json',p)
    print(json.dumps(dict(prepared_histories=len(tasks),assessment_allocations=2,all_nine_memberships_unique=True,storage=storage)),flush=True)

class Engine(prior.Engine):
    def __init__(self,p,*,write):
        self.v4=p;self.write=write;super().__init__(check(p));self.protocol_sha=sha256_file(D/'protocol-before-training.json')
        self.clean_cache={};self.clean_root=D/'source-evidence/clean-controls'

    def training_rows(self,seed):
        if seed not in self.rows_cache:
            alloc=_dirichlet_assignments(self.union,client_count=15,seed=seed,alpha=.3,minimum_rows=32,np=np)
            rows={f'client{i+1:02d}':rs for i,rs in enumerate(alloc)}
            assert allocation_identity(rows)==self.v4['allocation_preflight'][str(seed)]
            self.rows_cache[seed]=rows
        return self.rows_cache[seed]

    def metric(self,model,task):
        if task['role'] in ('fit','calibration'):
            v=evaluate(model,self.evaluation,self.deps);return {'clean':{k:v[k] for k in ('accuracy','macro_f1_all_model_classes','confusion_matrix')}}
        v=outcomes(model,self.evaluation,prior.source.plan_for(task),self.correct,self.deps)
        v['clean']={k:v['clean'][k] for k in ('accuracy','macro_f1_all_model_classes','confusion_matrix')}
        return v

    def clean(self,task,removed):
        key=(task['seed'],tuple(removed))
        if key not in self.clean_cache:
            clean_task={**task,'alias':f"clean-s{task['seed']}-omit-{group_key(removed)}",'mode':'clean','role':'clean-reference'}
            result,model,_=self.history(clean_task,removed,False,15)
            name=f"s{task['seed']}-{group_key(removed)}.json"
            existing=[root/name for root in (D/'source-evidence/clean-controls',D/'recovery-evidence/clean-controls') if (root/name).exists()]
            if existing:assert len(existing)==1 and result==read(existing[0])
            elif self.write:save(self.clean_root/name,result)
            else:raise AssertionError('missing clean counterfactual reference')
            self.clean_cache[key]=(result,model)
        return self.clean_cache[key]

    def history(self,task,removed,observe,horizon=15):
        guard();rows=self.training_rows(task['seed']);removed=sorted(removed)
        if len(set(removed))!=len(removed) or not set(removed)<=set(rows):raise ValueError('invalid omitted roster')
        clients=sorted(set(rows)-set(removed));assert len(clients)>=10
        control,clean_model=self.clean(task,removed) if task['mode']!='clean' else (None,None)
        model=self.initial;journal=[];frames=[];plan=prior.source.plan_for(task)
        for number in range(1,horizon+1):
            guard();base=arrays_from_export(model,np=np)
            ctx=self.context(model,number,task['alias']+'-omit-'+group_key(removed))
            clean={c:prior.source.pilot.gradient_step(model,rows[c],self.weights,self.deps)[0] for c in clients}
            poisoned={};poisoning={};active=task['mode']!='clean' and number<=10
            for c in clients:
                if active and c in task['attackers']:
                    changed,record=prior.source.poison_local_rows(rows=rows[c],plan=plan,client_id=c,round_number=number,distributed=task['mode']!='complete-trigger')
                    endpoint=poisoned_endpoint(model,changed,self.weights,task['seed']+number*10000+int(c[6:])-1,self.deps)
                    poisoned[c]=[a.astype(float)-b for a,b in zip(arrays_from_export(endpoint,np=np),base,strict=True)]
                    poisoning[c]=poison_commitment(record)
            def attempt(alpha):
                deltas={};proofs={}
                for c in clients:
                    if c in poisoned:deltas[c],proofs[c]=forged_delta(clean[c],poisoned[c],alpha,task['family'])
                    else:deltas[c]=clean[c]
                updates={c:update_record(c,ctx,deltas[c],len(rows[c]),True) for c in clients}
                params,event=assess_round(base,updates,None,ctx)
                candidate=model_with_arrays(model,params) if params is not None else None
                return candidate,event,updates,proofs
            queries=[];selection=None
            if poisoned:
                for alpha in FACTORS:
                    candidate,event,_,_=attempt(alpha);m=self.metric(candidate,task) if candidate is not None else None
                    queries.append(dict(alpha=alpha,defined=candidate is not None,metrics=m,
                        candidate_model_sha256=prior.source.pilot.old_study.export_digest(candidate) if candidate else None))
                alpha,selection=select_endpoint_query(queries,control['journal'][number-1]['metrics']['clean']['macro_f1_all_model_classes'])
            else:alpha=0.
            candidate,event,updates,proofs=attempt(alpha)
            verify_round(base,updates,None,ctx,event);assert candidate is not None and event['decision']=='commit'
            if observe and number<=10:frames.append(self.observe_frame(model,updates,number))
            metric=self.metric(candidate,task);checkpoint=prior.source.pilot.old_study.export_digest(candidate)
            journal.append(dict(round=number,event=event,selected_alpha=alpha,selection=selection,queries=queries,
                poisoning=poisoning,relative_radius_proofs=proofs,model_sha256=checkpoint,metrics=metric))
            model=candidate
        actual=arrays_from_export(model,np=np);initial=arrays_from_export(self.initial,np=np)
        def distance(other):return float(np.linalg.norm(np.concatenate([(a.astype(float)-b).ravel() for a,b in zip(actual,other,strict=True)])))
        own_clean_distance=distance(arrays_from_export(clean_model,np=np)) if clean_model is not None else 0.
        if task['mode']!='clean' and not (set(task['attackers'])-set(removed)):
            assert all(a['model_sha256']==b['model_sha256'] and a['metrics']==b['metrics'] for a,b in zip(journal,control['journal'],strict=True))
        result=dict(task=task,removed=removed,complete=len(journal)==horizon,journal=journal,
            final_model_sha256=prior.source.pilot.old_study.export_digest(model),
            final_parameter_l2_to_same_roster_clean=own_clean_distance,final_parameter_l2_to_initial=distance(initial),
            new_TPM_quotes=0,test_inference=False)
        return result,model,frames

def calibrate_phase():
    p=read(D/'protocol-before-training.json');engine=Engine(p,write=True);E=D/'source-evidence'
    assert not E.exists();save(E/'protocol.json',p);frames={}
    for seed in FIT+CAL:
        role='fit' if seed in FIT else 'calibration'
        task=dict(alias=f'{role}-{seed}',seed=seed,mode='clean',family='unrestricted',attackers=['client01','client06','client13'],role=role)
        result,_,obs=engine.history(task,[],True,10);frames[seed]=obs;save(E/'calibration-histories'/f'{seed}.json',result)
        print(json.dumps(dict(clean_role=role,seed=seed)),flush=True)
    ref=fit_reference([frames[s] for s in FIT]);cal=calibrate([frames[s] for s in CAL],ref)
    save(E/'reference.json',ref);save(E/'calibration.json',cal)
    save(D/'calibration-closure-before-assessment.json',dict(reference_sha256=sha256_file(E/'reference.json'),calibration_sha256=sha256_file(E/'calibration.json')))
    check(p)

def assess():
    p=read(D/'protocol-before-training.json');engine=Engine(p,write=True);E=D/'source-evidence'
    closure=read(D/'calibration-closure-before-assessment.json')
    assert sha256_file(E/'reference.json')==closure['reference_sha256'] and sha256_file(E/'calibration.json')==closure['calibration_sha256']
    ref=read(E/'reference.json');cal=read(E/'calibration.json');selected=[]
    for task in p['tasks']:
        result,model,obs=engine.history(task,[],True);selection=detect(obs,ref,cal)
        save(E/'histories'/task['alias']/'result.json',result);save(E/'histories'/task['alias']/'last-checkpoint.json',model)
        save(E/'selection'/f"{task['alias']}.json",selection)
        selected.append(dict(alias=task['alias'],individual_anomalies=selection['individual_anomalies'],selected_group=selection['selected_group']))
        print(json.dumps(dict(alias=task['alias'],selected_group=selection['selected_group'])),flush=True)
    save(E/'selection-before-membership-and-effects.json',dict(cases=selected,labels_read_by_detector=False,
        attack_outcomes_read_by_detector=False,future_frames_read_by_detector=False,not_process_isolated_blinding=True))
    check(p);Generator.close(E);save(D/'source-closure.json',dict(manifest_sha256=sha256_file(E/'manifest.json')))

def plan():
    from itertools import combinations
    p=read(D/'protocol-before-training.json');engine=Engine(p,write=False);E=D/'source-evidence'
    authenticate(E,read(D/'source-closure.json')['manifest_sha256']);closed=read(E/'selection-before-membership-and-effects.json')
    membership=[];plans=[];total=0
    for task in p['tasks']:
        result=read(E/'histories'/task['alias']/'result.json');selection=next(c for c in closed['cases'] if c['alias']==task['alias'])
        truth=set(task['attackers']) if task['mode']!='clean' else set();group=set(selection['selected_group'])
        anomalies=set(selection['individual_anomalies']);control=engine.clean(task,[])[0]
        effective=[a['round'] for a,b in zip(result['journal'],control['journal'],strict=True)
            if worst_asr(a['metrics'])-worst_asr(b['metrics'])>=.20 and
            b['metrics']['clean']['macro_f1_all_model_classes']-a['metrics']['clean']['macro_f1_all_model_classes']<=.05]
        membership.append(dict(alias=task['alias'],seed=task['seed'],mode=task['mode'],family=task['family'],selected_group=sorted(group),
            TP=len(group&truth),FP=len(group-truth),FN=len(truth-group),individual_TP=len(anomalies&truth),
            individual_FP=len(anomalies-truth),individual_FN=len(truth-anomalies),effective_rounds=effective))
        requested={():['no-removal']};comparisons=[]
        eligible=bool(effective) if task['mode']!='clean' else bool(group)
        if eligible:
            groups=[('v4',sorted(group))]
            if truth:groups.append(('oracle-diagnostic',sorted(truth)))
            rows=engine.training_rows(task['seed']);counts={c:len(rs) for c,rs in rows.items()};benign=sorted(set(rows)-truth)
            for method,g in groups:
                if not g:continue
                requested.setdefault(tuple(g),[]).append(method+'-joint')
                for c in g:requested.setdefault((c,),[]).append(method+'-individual')
                controls=list(combinations(benign,len(g)));mass=sum(counts[c] for c in g)
                matched=min(controls,key=lambda x:(abs(sum(counts[c] for c in x)-mass),group_key(x)))
                hashed=min(controls,key=group_key)
                for x,role in [(matched,method+'-mass-matched-benign'),(hashed,method+'-hash-benign')]:requested.setdefault(x,[]).append(role)
                comparisons.append(dict(method=method,group=g,mass_matched_control=list(matched),hash_control=list(hashed),
                    group_sample_count=mass,control_sample_count=sum(counts[c] for c in matched)))
        removals=[dict(removed=list(g),roles=roles,key=group_key(g)) for g,roles in sorted(requested.items())]
        if eligible:total+=len(removals)
        plans.append(dict(alias=task['alias'],eligible_for_recovery=eligible,removals=removals,comparisons=comparisons))
    assert total<=p['maximum_recovery_branches'],'Explicit branch budget exceeded; no case trimming allowed'
    save(D/'membership-evaluation.json',dict(cases=membership))
    save(D/'recovery-plan-before-effects.json',dict(plans=plans,requested_replay_branches=total,
        source_manifest_sha256=sha256_file(E/'manifest.json'),selection_sha256=sha256_file(E/'selection-before-membership-and-effects.json')))
    print(json.dumps(dict(recovery_branches=total,membership=membership),indent=2),flush=True)

def recovery():
    p=read(D/'protocol-before-training.json');engine=Engine(p,write=True);E=D/'recovery-evidence';assert not E.exists()
    planned=read(D/'recovery-plan-before-effects.json');authenticate(D/'source-evidence',planned['source_manifest_sha256'])
    save(E/'plan.json',planned);engine.clean_root=E/'clean-controls'
    for task in p['tasks']:
        request=next(x for x in planned['plans'] if x['alias']==task['alias']);records=[]
        if request['eligible_for_recovery']:
            for removal in request['removals']:
                result,_,_=engine.history(task,removal['removed'],False)
                if not removal['removed']:assert result==read(D/'source-evidence/histories'/task['alias']/'result.json')
                save(E/'histories'/task['alias']/f"{removal['key']}.json",result)
                records.append(dict(**removal,final_model_sha256=result['final_model_sha256']))
                print(json.dumps(dict(recovery=task['alias'],removed=removal['removed'],rounds=15)),flush=True)
        save(E/f"{task['alias']}.json",dict(task=task,plan=request,records=records))
    check(p);Generator.close(E);save(D/'recovery-closure.json',dict(manifest_sha256=sha256_file(E/'manifest.json')))

def verify():
    p=read(D/'protocol-before-training.json');engine=Engine(p,write=False);S=D/'source-evidence';E=D/'recovery-evidence'
    authenticate(S,read(D/'source-closure.json')['manifest_sha256']);authenticate(E,read(D/'recovery-closure.json')['manifest_sha256'])
    frames={}
    for seed in FIT+CAL:
        role='fit' if seed in FIT else 'calibration';task=dict(alias=f'{role}-{seed}',seed=seed,mode='clean',family='unrestricted',attackers=['client01','client06','client13'],role=role)
        result,_,obs=engine.history(task,[],True,10);assert result==read(S/'calibration-histories'/f'{seed}.json');frames[seed]=obs
    ref=fit_reference([frames[s] for s in FIT]);cal=calibrate([frames[s] for s in CAL],ref)
    assert ref==read(S/'reference.json') and cal==read(S/'calibration.json');del frames
    queries=branches=source_rounds=recovery_rounds=0
    for task in p['tasks']:
        result,model,obs=engine.history(task,[],True);assert result==read(S/'histories'/task['alias']/'result.json')
        assert model==read(S/'histories'/task['alias']/'last-checkpoint.json')
        assert detect(obs,ref,cal)==read(S/'selection'/f"{task['alias']}.json")
        source_rounds+=len(result['journal']);queries+=sum(len(r['queries']) for r in result['journal'])
        print(json.dumps(dict(replayed_source=task['alias'])),flush=True)
        request=read(E/f"{task['alias']}.json")['plan']
        if request['eligible_for_recovery']:
            for removal in request['removals']:
                reconstructed,_,_=engine.history(task,removal['removed'],False)
                assert reconstructed==read(E/'histories'/task['alias']/f"{removal['key']}.json")
                branches+=1;recovery_rounds+=len(reconstructed['journal']);queries+=sum(len(r['queries']) for r in reconstructed['journal'])
            print(json.dumps(dict(replayed_origin_recovery=task['alias'],branches=branches)),flush=True)
    check(p);save(D/'verification.json',dict(status='fresh_histories_selection_and_origin_recovery_replayed',
        clean_fit_calibration_rounds=50,source_rounds=source_rounds,recovery_branches=branches,recovery_rounds=recovery_rounds,
        adaptive_queries=queries,clean_reference_histories_checked=len(engine.clean_cache),
        software_manifests_authenticated=True,same_implementation_replay=True,new_TPM_quotes=0,test_inference=False,default_changed=False,storage=guard()))
    print(json.dumps(read(D/'verification.json'),indent=2),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('prepare','calibrate','assess','plan','recovery','verify'));args=parser.parse_args()
    {'prepare':prepare,'calibrate':calibrate_phase,'assess':assess,'plan':plan,'recovery':recovery,'verify':verify}[args.phase]()
