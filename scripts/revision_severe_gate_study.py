"""Severe-tail structural gate revision with independently reserved evaluation.

The retained v1 generation engine is reused through explicit process-local
adapters. Its on-disk code, source profiles and prior evidence are never edited.
No new TPM appraisal is claimed; prerequisite validity is a research assumption.
"""
from __future__ import annotations
import argparse
import copy
import json
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor,as_completed
from pathlib import Path
from statistics import median
import revision_gate_trajectories as base  # Establish numeric environment first.
import severe_gate_calibration as cal
import clean_gate_calibration as legacy_cal
from revision_study_data import read,Generator
from revision_dba_experiment import save,authenticate,environment
from fl_forensics.canonical import sha256_file
from fl_forensics.composite_admission import decide_admission_policies

ROOT=base.ROOT
LAB=ROOT/'artifacts/revision-severe-tail-gate-v1'
ORIGINAL_CONTEXT=base.context
ORIGINAL_STATE=base.gate_state
ORIGINAL_TRAIN_ALL=base.train_all
ORIGINAL_POLICIES=('tpm_only','sequential','gated_composite')
STAGES={
    'fit': [('iid',2026110701),('iid',2026110702),('iid',2026110703),('iid',2026110704),
            ('non-iid',2026110705),('non-iid',2026110706),('non-iid',2026110707),('non-iid',2026110708)],
    'calibration': [('iid',2026110711),('iid',2026110712),('iid',2026110713),('iid',2026110714),
                    ('non-iid',2026110715),('non-iid',2026110716),('non-iid',2026110717),('non-iid',2026110718)],
    'selection': [('iid',2026110721),('iid',2026110722),('iid',2026110723),
                  ('non-iid',2026110724),('non-iid',2026110725),('non-iid',2026110726)],
    'evaluation': [('iid',2026110731),('iid',2026110732),('iid',2026110733),
                   ('non-iid',2026110734),('non-iid',2026110735),('non-iid',2026110736)],
}
ATTACKERS=[['client02','client09','client14'],['client04','client07','client12'],['client01','client08','client15'],
           ['client03','client06','client13'],['client02','client10','client15'],['client04','client08','client11']]



def source_locks():
    paths=sorted((ROOT/'src/fl_forensics').glob('*.py'))
    paths += [ROOT/'scripts'/name for name in ('revision_gate_trajectories.py','revision_study_data.py',
        'revision_dba_experiment.py','clean_gate_calibration.py','severe_gate_calibration.py','revision_severe_gate_study.py')]
    paths += [ROOT/'configs/in-round-admission.yaml']
    return {str(p.relative_to(ROOT)):sha256_file(p) for p in paths}


def assert_locks(protocol):
    base.require(source_locks()==protocol['source_locks'],'Locked calibration/generation source changed')
    for candidate,expected in protocol.get('calibration_models',{}).items():
        base.require(sha256_file(LAB/'models'/f'{candidate}.json')==expected,'Bound calibration model changed')


def context(protocol,task):
    gen,rows,correct=ORIGINAL_CONTEXT(protocol,task)
    gen.gate_cohort=task['cohort'];gen.gate_round=None
    candidate=task.get('candidate')
    gen.gate_calibration=None;gen.gate_calibration_sha256=None
    if candidate:
        path=LAB/'models'/f'{candidate}.json'
        expected=protocol['calibration_models'][candidate]
        base.require(sha256_file(path)==expected,'Candidate pin mismatch')
        gen.gate_calibration=read(path);gen.gate_calibration_sha256=expected
    return gen,rows,correct


def train_all(gen,initial,seed,number,plan=None,distributed=True):
    gen.gate_round=number
    return ORIGINAL_TRAIN_ALL(gen,initial,seed,number,plan,distributed)


def gate_state(initial,exports,gen,settings,rows):
    state,arrays=ORIGINAL_STATE(initial,exports,gen,settings,rows)
    model=gen.gate_calibration
    if model is None:return state,arrays
    started=time.perf_counter()
    number=gen.gate_round;cal.stage(number)  # Never infer round from model contents.
    sizes={c:len(gen.rows[c]) for c in gen.clients};middle=median(sizes.values())
    state['calibration_model_sha256']=gen.gate_calibration_sha256
    state['calibration_stage']=cal.stage(number)
    state['calibrated_scores']={};state['reference_profiles']={}
    limits=model['thresholds'][gen.gate_cohort]
    for raw in state['indicators']:
        client=raw['client_id'];indicator={name:raw[name] for name in cal.NAMES}
        signal,profile=cal.score(model,gen.gate_cohort,number,sizes[client],middle,indicator,client)
        kwargs=dict(trust=base.TRUST,statistics=signal,
            statistical_threshold=limits['statistical_threshold'],composite_threshold=limits['composite_threshold'],
            trust_weight=.5)
        decisions={d.policy:d for d in decide_admission_policies(**kwargs,
            composite_downweight_threshold=limits['composite_downweight_threshold'])}
        state['decisions'][client]['calibrated_gated']=decisions['gated_composite'].model_dump(mode='json')
        state['decisions'][client]['calibrated_sequential']=decisions['sequential'].model_dump(mode='json')
        no_band=next(d for d in decide_admission_policies(**kwargs,
            composite_downweight_threshold=limits['composite_threshold']) if d.policy=='gated_composite')
        state['decisions'][client]['calibrated_no_band']=no_band.model_dump(mode='json')
        base.require(no_band.status==decisions['sequential'].status,'Calibrated no-band control differs')
        base.require(decisions['gated_composite'].contributes==decisions['sequential'].contributes,
                     'Calibrated no-warning support differs')
        state['calibrated_scores'][client]=signal.model_dump(mode='json')
        state['reference_profiles'][client]=profile
    if model['profile']=='noncompensatory-log-tail-gate-v1':
        state['tail_fusion']='maximum of uncapped normalized log severities'
        state['severe_tail_details']={}
        for raw in state['indicators']:
            c=raw['client_id']
            detail=cal.diagnostics(model,gen.gate_cohort,number,sizes[c],middle,{n:raw[n] for n in cal.NAMES})
            detail['quarantine_alarm_indicators']=[n for n,v in detail['components'].items()
                if cal.bounded(v['normalized_severity'])>limits['statistical_threshold']]
            if detail['quarantine_alarm_indicators']:
                base.require(state['decisions'][c]['calibrated_gated']['status']=='statistically_quarantined',
                             'A severe component alarm was compensated')
            state['severe_tail_details'][c]=detail
    state['timing']['clean_calibration_seconds']=time.perf_counter()-started
    return state,arrays


def configure(phase):
    base.LAB=LAB/phase
    base.context=context;base.train_all=train_all;base.gate_state=gate_state;base.assert_locks=assert_locks
    base.POLICIES=ORIGINAL_POLICIES


def worker(task,phase):
    configure(phase)
    if task.get('candidate'):base.POLICIES=(*ORIGINAL_POLICIES,'calibrated_gated','calibrated_sequential','calibrated_no_band')
    return base.run_case(task)


def make_tasks(phase):
    tasks=[]
    if phase=='evaluation':
        choice=read(LAB/'selection-decision.json');base.require(choice['selected_candidate'] is not None,'No clean-qualified severe gate')
        for i,(cohort,seed) in enumerate(STAGES[phase]):
            for method in ('tpm_only','gated_composite','mean_control','severe_gate'):
                for mode in base.MODES:
                    candidate=(choice['selected_candidate'] if method=='severe_gate' else
                               'mean_control' if method=='mean_control' else None)
                    policy='calibrated_gated' if candidate else method
                    tasks.append(dict(name=f'{cohort}-s{seed}-{method}-{mode}',cohort=cohort,seed=seed,
                        attackers=ATTACKERS[i],policy=policy,mode=mode,candidate=candidate,method=method))
    else:
        for cohort,seed in STAGES[phase]:
            for candidate in ([None,*cal.CANDIDATES] if phase=='selection' else [None]):
                tasks.append(dict(name=f'{cohort}-s{seed}-{candidate or "tpm_only"}-clean',cohort=cohort,seed=seed,
                    attackers=['client01','client06','client11'],policy='calibrated_gated' if candidate else 'tpm_only',
                    mode='clean',candidate=candidate,method=candidate or 'tpm_only'))
    return tasks


def phase_protocol(phase):
    path=LAB/phase/'protocol-before-training.json'
    if path.exists():
        p=read(path);assert_locks(p);return p
    root=read(LAB/'protocol-before-clean-fitting.json');assert_locks(root)
    folder=path.parent;folder.mkdir()
    (folder/'partitions').symlink_to(LAB/'partitions',target_is_directory=True)
    models={c:sha256_file(LAB/'models'/f'{c}.json') for c in (*cal.CANDIDATES,'mean_control') if (LAB/'models'/f'{c}.json').exists()}
    p={**root,'phase':phase,'tasks':make_tasks(phase),'calibration_models':models,
       'selection_decision_sha256':sha256_file(LAB/'selection-decision.json') if phase=='evaluation' else None}
    save(path,p);return p


def run_phase(phase,workers):
    protocol=phase_protocol(phase);folder=LAB/phase
    if (folder/'training-complete.json').exists():
        closed=read(folder/'training-complete.json')
        for result in closed['results']:authenticate(folder/'cases'/result['task']['name']/'evidence',result['manifest_sha256'])
        return closed
    results=[]
    with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
        futures={pool.submit(worker,t,phase):t for t in protocol['tasks']}
        for future in as_completed(futures):
            task=futures[future]
            try:result=future.result()
            except Exception as exc:
                case=folder/'cases'/task['name'];evidence=case/'evidence'
                error=dict(task=task,complete=False,error=str(exc),exception_type=type(exc).__name__)
                save(evidence/'terminal-exception.json',error)
                if not (evidence/'manifest.json').exists():Generator.close(evidence)
                result={**error,'completed_rounds':len(list(evidence.glob('rounds/round-*/round.json'))),
                        'manifest_sha256':sha256_file(evidence/'manifest.json')}
                if not (case/'result.json').exists():save(case/'result.json',result)
            results.append(result)
            (folder/'progress.json').write_text(json.dumps(dict(terminal_cases=len(results),planned_cases=len(protocol['tasks']),
                complete_cases=sum(r['complete'] for r in results)),sort_keys=True)+'\n')
            print('PHASE_CASE '+json.dumps(dict(phase=phase,task=task['name'],complete=result['complete'])),flush=True)
    assert_locks(protocol)
    closed=dict(protocol_sha256=sha256_file(folder/'protocol-before-training.json'),
                results=sorted(results,key=lambda r:r['task']['name']),test_inference_performed=False)
    save(folder/'training-complete.json',closed);return closed


def clean_records(phase):
    closed=read(LAB/phase/'training-complete.json');records=[];pins={}
    for result in closed['results']:
        task=result['task'];base.require(result['complete'] and task['mode']=='clean' and task['policy']=='tpm_only',
                                        'Fitting requires complete clean TPM-only histories')
        root=LAB/phase/'cases'/task['name']/'evidence';authenticate(root,result['manifest_sha256'])
        pins[task['name']]=result['manifest_sha256']
        part=read(LAB/'partitions'/str(task['seed'])/'manifest.json')
        sizes={r['client_id']:r['train_row_count'] for r in part['clients']};middle=median(sizes.values())
        for number in range(1,16):
            state=read(root/'rounds'/f'round-{number:03d}'/'gate-state.json')
            for raw in state['indicators']:
                records.append(dict(cohort=task['cohort'],round=number,examples=sizes[raw['client_id']],
                    cohort_median=middle,indicators={name:raw[name] for name in cal.NAMES}))
    return records,pins


def derive_models():
    root=read(LAB/'protocol-before-clean-fitting.json');assert_locks(root)
    for phase in ('fit','calibration'):
        receipt=read(LAB/phase/'verified/summary.json')
        base.require(receipt['status']=='verified' and not receipt['test_accessed'],'Unverified or test-observed clean fitting phase')
    fitting,fit_pins=clean_records('fit');calibration,cal_pins=clean_records('calibration')
    for candidate in cal.CANDIDATES:
        model=cal.fit_thresholds(cal.fit_references(fitting,candidate),calibration)
        model['source_clean_manifests']=dict(fit=fit_pins,calibration=cal_pins)
        model['fit_observations']=len(fitting);model['threshold_observations']=len(calibration)
        path=LAB/'models'/f'{candidate}.json'
        if path.exists():base.require(read(path)==model,'Existing fitted model differs')
        else:save(path,model)
        print('CALIBRATED '+json.dumps(dict(candidate=candidate,thresholds=model['thresholds'])),flush=True)
    mean=legacy_cal.fit_thresholds(legacy_cal.fit_references(fitting,'conditioned_conservative'),calibration)
    mean['candidate']='mean_control';mean['source_clean_manifests']=dict(fit=fit_pins,calibration=cal_pins)
    mean['fit_observations']=len(fitting);mean['threshold_observations']=len(calibration)
    mean['control_semantics']='Same fresh clean data, original capped average and conservative quantiles; never selectable as the proposed severe gate.'
    path=LAB/'models/mean_control.json'
    if path.exists():base.require(read(path)==mean,'Existing mean control differs')
    else:save(path,mean)



def choose():
    root=read(LAB/'protocol-before-clean-fitting.json');assert_locks(root)
    receipt=read(LAB/'selection/verified/summary.json')
    base.require(receipt['status']=='verified' and not receipt['test_accessed'],'Unverified or test-observed selection')
    closed=read(LAB/'selection/training-complete.json');by={(r['task']['seed'],r['task']['candidate']):r for r in closed['results']}
    choices=[]
    for candidate in cal.CANDIDATES:
        details=[];model=read(LAB/'models'/f'{candidate}.json')
        for cohort,seed in STAGES['selection']:
            result=by[(seed,candidate)];control=by[(seed,None)]
            complete=result['complete'] and control['complete'];summaries=[];losses=[]
            if complete:
                part=read(LAB/'partitions'/str(seed)/'manifest.json');sizes={r['client_id']:r['train_row_count'] for r in part['clients']}
                for number in range(1,16):
                    path=LAB/'selection/cases'/result['task']['name']/'evidence/rounds'/f'round-{number:03d}'/'round.json'
                    row=read(path);summaries.append(dict(statuses=row['statuses'],masses=row['masses'],example_counts=sizes))
                    if number in (10,15):
                        other=read(LAB/'selection/cases'/control['task']['name']/'evidence/rounds'/f'round-{number:03d}'/'round.json')
                        losses.append(other['validation']['clean']['macro_f1_all_model_classes']-row['validation']['clean']['macro_f1_all_model_classes'])
                budget=cal.budget_summary(summaries)
            else:budget=None
            ok=complete and budget['quarantine_rate']<=.05 and budget['downweight_rate']<=.15 and budget['nominal_mass_retention']>=.90 \
                and budget['minimum_round_mass_retention']>=.80 and max(losses)<=.02 and model['thresholds'][cohort]['nonempty_quarantine_region']
            details.append(dict(cohort=cohort,seed=seed,complete=complete,budget=budget,validation_losses=losses,qualified=bool(ok)))
        qualified=all(r['qualified'] for r in details)
        choices.append(dict(candidate=candidate,qualified=qualified,details=details,
            worst_validation_loss=max((v for r in details for v in r['validation_losses']),default=None),
            minimum_mass_retention=min((r['budget']['nominal_mass_retention'] for r in details if r['budget']),default=None)))
    feasible=[c for c in choices if c['qualified']]
    ranking=sorted(feasible,key=lambda c:(c['worst_validation_loss'],-c['minimum_mass_retention'],list(cal.CANDIDATES).index(c['candidate'])))
    decision=dict(selected_candidate=ranking[0]['candidate'] if ranking else None,candidates=choices,
                  uses_attack_or_test_outcomes=False,selection_source_sha256=sha256_file(LAB/'selection/training-complete.json'))
    save(LAB/'selection-decision.json',decision)
    print('CLEAN_SELECTION '+json.dumps(decision),flush=True);return decision


def prepare():
    base.require(not LAB.exists(),'Preserve existing calibration study')
    prior=read(ROOT/'artifacts/revision-gate-trajectories-v1/protocol-before-training.json')
    source=ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1';manifest=read(source/'manifest.json')
    union=[];seen=set()
    for record in manifest['clients']:
        path=source/record['dataset_path'];base.require(sha256_file(path)==record['dataset_sha256'],'Changed source snapshot')
        for row in read(path)['rows']['train']:
            base.require(row['window_id'] not in seen,'Duplicate training occurrence');seen.add(row['window_id']);union.append(row)
    LAB.mkdir();partitions={}
    for cohort,seed in [v for rows in STAGES.values() for v in rows]:
        allocation=(base._iid_assignments(union,client_count=15,seed=seed,np=base.np) if cohort=='iid' else
            base._dirichlet_assignments(union,client_count=15,seed=seed,alpha=.3,minimum_rows=32,np=base.np))
        base.require({r['window_id'] for rs in allocation for r in rs}==seen and sum(map(len,allocation))==len(seen),'Allocation coverage failed')
        folder=LAB/'partitions'/str(seed);clients=[]
        for i,rows in enumerate(allocation):
            client=f'client{i+1:02d}';path=folder/'clients'/client/'dataset.json'
            save(path,dict(client_id=client,partition_id=i,class_names=manifest['class_names'],rows={'train':rows}))
            clients.append(dict(client_id=client,partition_id=i,dataset_path=str(path.relative_to(folder)),
                                dataset_sha256=sha256_file(path),train_row_count=len(rows)))
        save(folder/'manifest.json',dict(profile='clean-gate-training-only-allocation-v1',seed=seed,partition_mode=cohort,
            class_names=manifest['class_names'],global_class_weights=manifest['global_class_weights'],clients=clients,
            training_occurrences=len(seen),M3_full_profile_verification_claimed=False))
        partitions[str(seed)]=sha256_file(folder/'manifest.json')
    protocol=dict(profile='noncompensatory-severe-tail-gate-study-v1',stages=STAGES,candidates=cal.CANDIDATES,
        training=prior['training'],runtime_admission=prior['runtime_admission'],partitions=partitions,
        source_snapshots=prior['source_snapshots'],source_locks=source_locks(),environment=environment(),
        clean_budgets=dict(maximum_quarantine_rate=.05,maximum_downweight_rate=.15,minimum_nominal_mass_retention=.90,
            minimum_round_mass_retention=.80,maximum_fixed_endpoint_validation_f1_loss=.02),
        selection='All six clean selection assignments must meet every budget and retain a nonempty quarantine region. Minimize worst validation F1 loss, then maximize minimum mass retained, then declared candidate order. No attack/test selection.',
        fitting='Eight clean FedAvg histories fit conditioned references, eight other histories calibrate per-indicator uncapped log-tail normalization and the maximum tail. Every empirical cutoff uses max(count,mass weighted quantiles). No exchangeability guarantee. Eighteen clean selection campaigns precede the reserved study.',
        independence='Disjoint seed/partition assignments by stage on the same Data24 global training rows and fixed clean warm start. Not independent data or initialization. The previously inspected test split remains exploratory.',
        admission='The raw five server-visible indicators, trust veto, factor0.5, minimum10 and Flower FedAvg are retained. New statistical fusion is the maximum of uncapped adverse log severities normalized by clean per-indicator tails. Its bounded monotone display score enters the original hard-veto decision API. Per-indicator diagnostics replace the original additive-component schema for this profile. Unsupported cohort/round fails.',
        evaluation_plan='Six new reserved assignments, four arms (TPM-only, original composite, matched fresh-data capped-average control, selected severe-tail gate). Clean/distributed/full-trigger/adaptive conditions yield96 planned histories of15 rounds (10 attack,5 continuation). Same six-query adaptive budget and trigger/row edits. Test only after every training case is terminal.',
        promotion='Proposed severe gate: every reserved clean budget, <=.02 test F1 loss at rounds10/15, all24 proposed histories complete, no higher paired worst-trigger peak harm than matched mean control, and strict benefit in at least two effective-control cases including a non-IID case. Also report every original-composite comparison and failure; undefined comparisons cannot establish equivalence or universal superiority. No automatic production promotion or permanent identity exclusion.',
        stage_diagnostics='Existing clean runner emits trigger diagnostics for parity; fitting/selection use an allowlisted clean-indicator/budget/F1 interface only. All attacks are absent from fit/calibration/selection.',
        mandatory_trust='Assumed passed in software research. No fresh TPM Quotes, no per-client hardware-signature claim.',
        new_TPM_Quotes=0)
    save(LAB/'protocol-before-clean-fitting.json',protocol)
    (LAB/'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print('PREPARED '+json.dumps(dict(protocol_sha256=sha256_file(LAB/'protocol-before-clean-fitting.json'))),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('prepare','fit','calibration','derive','selection','choose','evaluation','pipeline'))
    parser.add_argument('--workers',type=int,default=3);args=parser.parse_args()
    if args.command=='prepare':prepare()
    elif args.command=='derive':derive_models()
    elif args.command=='choose':choose()
    elif args.command=='pipeline':
        from revision_severe_gate_audit import verify_phase
        if not LAB.exists():prepare()
        run_phase('fit',args.workers);verify_phase('fit',args.workers)
        run_phase('calibration',args.workers);verify_phase('calibration',args.workers);derive_models()
        run_phase('selection',args.workers);verify_phase('selection',args.workers)
        decision=read(LAB/'selection-decision.json') if (LAB/'selection-decision.json').exists() else choose()
        if decision['selected_candidate'] is not None:
            run_phase('evaluation',args.workers);verify_phase('evaluation',args.workers)
    else:run_phase(args.command,args.workers)


if __name__=='__main__':main()
