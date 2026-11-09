"""Locked, independently trained gate comparison; software research profile.

No fresh TPM attestation is claimed. Mandatory prerequisites are assumed passed.
All gates use the unchanged original risk calibration and the live Flower FedAvg
operator. Attacker identities enter only training, attack selection and evaluation.
Test inference is a separate phase after all training cases have terminal records.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import os
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
import multiprocessing

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
import numpy as np
import yaml

from revision_study_data import Generator, read
from revision_dba_experiment import save, model_with_arrays, evaluate, outcomes, predict, environment, authenticate
from fl_forensics.byzantine import model_delta, update_indicators
from fl_forensics.canonical import sha256_file
from fl_forensics.composite_admission import decide_admission_policies, score_statistical_indicators
from fl_forensics.composite_admission_models import IndicatorReference, TrustSignal
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan, poison_local_rows
from fl_forensics.federated_model import arrays_from_export, train_local, export_state, fedavg
from fl_forensics.federated_partitioning import _iid_assignments, _dirichlet_assignments
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.secure_round import _model_from_export

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'artifacts/revision-gate-trajectories-v1'
POLICIES = ('tpm_only', 'sequential', 'gated_composite')
MODES = ('clean', 'distributed', 'complete-trigger', 'adaptive')
ALPHAS = (0., .25, .5, 1., 2., 4.)
ASSIGNMENTS = [
    ('iid', 2026110601, ['client03', 'client08', 'client13']),
    ('iid', 2026110602, ['client02', 'client07', 'client15']),
    ('iid', 2026110603, ['client01', 'client09', 'client12']),
    ('non-iid', 2026110604, ['client02', 'client08', 'client14']),
    ('non-iid', 2026110605, ['client04', 'client06', 'client15']),
    ('non-iid', 2026110606, ['client03', 'client07', 'client12']),
]
TRUST = TrustSignal(raw_status='software-research-assumed-passed', admissible=True, risk=0,
                    evaluated_checks=[], failed_checks=[],
                    reasons=['Research assumption, not a fresh TPM appraisal.'])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(derived_json_bytes(value)).hexdigest()


def locks():
    paths = [ROOT/'scripts/revision_gate_trajectories.py', ROOT/'scripts/revision_study_data.py',
             ROOT/'scripts/revision_dba_experiment.py', ROOT/'configs/in-round-admission.yaml']
    paths += sorted((ROOT/'src/fl_forensics').glob('*.py'))
    return {str(p.relative_to(ROOT)):sha256_file(p) for p in paths}


def assert_locks(protocol):
    require(locks() == protocol['source_locks'], 'Source or policy changed during locked experiment')


def scalar_asr(metric):
    return max([metric['complete_trigger']['asr'], *[v['asr'] for v in metric['component_triggers'].values()]])


def train_one(gen, base, seed, number, client, plan=None, distributed=True):
    rows = gen.rows[client]
    poisoning = None
    if plan is not None:
        rows, poisoning = poison_local_rows(rows=rows, plan=plan, client_id=client,
                                            round_number=number, distributed=distributed)
    local_seed = seed+number*10000+int(gen.records[client]['partition_id'])
    model = _model_from_export(base, torch=gen.torch, np=np)
    train_local(model=model, rows=rows, class_names=base['class_names'], class_weights=gen.weights,
                epochs=gen.cfg['local_epochs'], batch_size=gen.cfg['batch_size'],
                learning_rate=gen.cfg['learning_rate'], seed=local_seed, device_name='cpu',
                torch=gen.torch, np=np)
    exported = export_state(model, architecture=base['architecture'], class_names=base['class_names'])
    return exported, dict(client_id=client, seed=local_seed,
                          snapshot_sha256=gen.records[client]['dataset_sha256'],
                          executed_rows_sha256=digest(rows), local_model_sha256=digest(exported),
                          poisoning=poisoning)


def train_all(gen, base, seed, number, plan=None, distributed=True):
    pairs = [train_one(gen, base, seed, number, c, plan, distributed) for c in gen.clients]
    return [p[0] for p in pairs], [p[1] for p in pairs]


def gate_state(base, exports, gen, settings, rows):
    started = time.perf_counter()
    values = arrays_from_export(base, np=np)
    local = [arrays_from_export(e, np=np) for e in exports]
    deltas = [model_delta(values, e) for e in local]
    indicators = update_indicators(deltas, client_ids=gen.clients)
    geometry = time.perf_counter()-started
    started = time.perf_counter()
    base_f1 = evaluate(base, rows, gen.deps)['macro_f1_all_model_classes']
    for indicator, export in zip(indicators, exports, strict=True):
        indicator['validation_impact'] = base_f1-evaluate(export, rows, gen.deps)['macro_f1_all_model_classes']
    inference = time.perf_counter()-started
    started = time.perf_counter()
    calibration = settings['calibration']
    references = {name:IndicatorReference(name=name, **v) for name, v in calibration['indicator_references'].items()}
    scores = score_statistical_indicators(indicators, references=references,
                 weights=calibration['indicator_weights'], z_cap=settings['robust_z_cap'])
    limits = calibration['thresholds']
    decisions, no_band = {}, {}
    for client in gen.clients:
        kwargs = dict(trust=TRUST, statistics=scores[client],
                      statistical_threshold=limits['statistical_threshold'],
                      composite_threshold=limits['composite_threshold'],
                      trust_weight=limits['trust_weight'])
        decisions[client] = {d.policy:d.model_dump(mode='json') for d in decide_admission_policies(
             **kwargs, composite_downweight_threshold=limits['composite_downweight_threshold'])}
        no_band[client] = next(d for d in decide_admission_policies(**kwargs,
             composite_downweight_threshold=limits['composite_threshold']) if d.policy == 'gated_composite')
        decisions[client]['composite_no_band'] = no_band[client].model_dump(mode='json')
        require(decisions[client]['sequential']['contributes'] == decisions[client]['gated_composite']['contributes'],
                'Expected no-warning support equivalence failed')
        require(no_band[client].status == decisions[client]['sequential']['status'], 'No-band control differs')
    scoring = time.perf_counter()-started
    return dict(indicators=indicators, scores={c:v.model_dump(mode='json') for c,v in scores.items()},
                decisions=decisions, timing=dict(indicator_geometry_seconds=geometry,
                validation_inference_seconds=inference, score_and_all_policy_decisions_seconds=scoring)), local


def numerical(base, local_arrays, gen, state, settings, policy):
    rho = Fraction(str(settings['accepted_downweight_factor']))
    factors = {c:(rho if state['decisions'][c][policy]['status'] == 'accepted_downweighted' else
                  Fraction(int(state['decisions'][c][policy]['contributes']))) for c in gen.clients}
    masses = {c:len(gen.rows[c])*factors[c] for c in gen.clients}
    selected = [(arrays, float(masses[c])) for c, arrays in zip(gen.clients, local_arrays, strict=True) if masses[c]>0]
    if len(selected)<settings['minimum_contributors']:
        return None, masses, None
    total = sum(masses.values(), Fraction())
    model = model_with_arrays(base, fedavg(selected, aggregate=gen.deps[4]))
    return model, masses, {c:str(masses[c]/total) for c in gen.clients}


def settings_for(protocol):
    cfg = yaml.safe_load((ROOT/'configs/in-round-admission.yaml').read_bytes())['runtime_admission']
    require(cfg == protocol['runtime_admission'], 'Runtime configuration drift')
    return cfg


def make_plan(protocol, task):
    return DistributedBackdoorPlan.model_validate({**protocol['training']['attack_plan'],
        'seed':task['seed'], 'client_components':dict(zip(task['attackers'], [[13],[17],[24]], strict=True)),
        'attack_rounds':list(range(1,11))})


def context(protocol, task):
    cfg = protocol['training']
    root = LAB/'partitions'/str(task['seed'])
    require(sha256_file(root/'manifest.json') == protocol['partitions'][str(task['seed'])], 'Partition changed')
    gen = Generator(root, cfg)
    require(sha256_file(Path(cfg['validation_path'])) == cfg['validation_sha256'], 'Validation changed')
    rows = read(cfg['validation_path'])['rows']['validation']
    require(not ({r['window_id'] for r in rows} & {r['window_id'] for rs in gen.rows.values() for r in rs}),
            'Training/validation overlap')
    predictions, _ = predict(gen.initial, rows, gen.deps)
    correct = [p==r['label'] for p,r in zip(predictions,rows,strict=True)]
    return gen, rows, correct


def run_case(task):
    protocol = read(LAB/'protocol-before-training.json')
    assert_locks(protocol)
    case = LAB/'cases'/task['name']
    result_path = case/'result.json'
    if result_path.is_file():
        result = read(result_path)
        authenticate(case/'evidence', result['manifest_sha256'])
        return result
    require(not case.exists(), f'Partial case preserved; explicit recovery required: {case}')
    case.mkdir(parents=True)
    evidence = case/'evidence'
    save(evidence/'task.json', task)
    gen, rows, correct = context(protocol, task)
    settings = settings_for(protocol)
    plan = make_plan(protocol, task)
    base = gen.initial
    records, failure = [], None
    for number in range(1,16):
        target = evidence/'rounds'/f'round-{number:03d}'
        save(target/'base-model.json', base)
        active = task['mode'] != 'clean' and number<=10
        start = time.perf_counter()
        clean, training = train_all(gen, base, task['seed'], number,
                   plan if active and task['mode']!='adaptive' else None,
                   distributed=task['mode']!='complete-trigger')
        training_seconds = time.perf_counter()-start
        repeated_training = 0
        if number in (1,15):
            repeated, _ = train_one(gen, base, task['seed'], number, gen.clients[0],
                    plan if active and task['mode']!='adaptive' else None,
                    distributed=task['mode']!='complete-trigger')
            require(repeated == clean[0], 'Local training not deterministic')
            repeated_training = 1
        start_search = time.perf_counter()
        transcript = []
        chosen_alpha = None
        if active and task['mode']=='adaptive':
            poison = list(clean)
            poisoned_training = []
            for c in task['attackers']:
                i = gen.clients.index(c)
                poison[i], tr = train_one(gen, base, task['seed'], number, c, plan, True)
                poisoned_training.append(tr)
                save(target/'attack-endpoints'/f'{c}-clean.json', clean[i])
                save(target/'attack-endpoints'/f'{c}-poison.json', poison[i])
            ca = [arrays_from_export(e,np=np) for e in clean]
            pa = [arrays_from_export(e,np=np) for e in poison]
            best = None
            for alpha in ALPHAS:
                candidate = [model_with_arrays(clean[i], [a+alpha*(b.astype(float)-a) for a,b in zip(ca[i],pa[i],strict=True)])
                             if c in task['attackers'] else clean[i] for i,c in enumerate(gen.clients)]
                state, arrays = gate_state(base, candidate, gen, settings, rows)
                model, masses, coefficients = numerical(base, arrays, gen, state, settings, task['policy'])
                metric = outcomes(model, rows, plan, correct, gen.deps) if model is not None else None
                q = sum(not state['decisions'][c][task['policy']]['contributes'] for c in task['attackers'])
                objective = scalar_asr(metric) if metric is not None else None
                transcript.append(dict(alpha=alpha, feasible=model is not None, objective=objective,
                    attacker_quarantines=q, decisions=state['decisions'],
                    candidate_update_sha256={c:digest(e) for c,e in zip(gen.clients,candidate,strict=True)},
                    full_trigger_asr=metric['complete_trigger']['asr'] if metric else None,
                    component_asr={c:v['asr'] for c,v in metric['component_triggers'].items()} if metric else None))
                if model is not None:
                    rank = (objective, -q, alpha)
                    if best is None or rank > best[0]:
                        best = (rank, alpha, candidate, state, arrays, model, masses, coefficients)
            save(target/'query-transcript.json', transcript)
            if best is None:
                failure = dict(round=number, reason='all adaptive candidates lose quorum', classification='quorum')
                save(target/'failure.json', failure)
                break
            _, chosen_alpha, exports, state, arrays, model, masses, coefficients = best
            training += poisoned_training
        else:
            exports = clean
            state, arrays = gate_state(base, exports, gen, settings, rows)
            model, masses, coefficients = numerical(base, arrays, gen, state, settings, task['policy'])
        search_seconds = time.perf_counter()-start_search if active and task['mode']=='adaptive' else None
        if model is None:
            save(target/'gate-state.json', state)
            for c,e in zip(gen.clients,exports,strict=True): save(target/'updates'/f'{c}.json',e)
            failure = dict(round=number, reason='minimum ten contributors not reached', classification='quorum')
            save(target/'failure.json', failure)
            break
        for c,e in zip(gen.clients,exports,strict=True): save(target/'updates'/f'{c}.json',e)
        save(target/'gate-state.json', state)
        # Timing fields are observations, not deterministic verification targets.
        start = time.perf_counter()
        repeated_model, repeated_masses, repeated_coefficients = numerical(base, arrays, gen, state, settings, task['policy'])
        aggregation_seconds = time.perf_counter()-start
        require(model == repeated_model and masses == repeated_masses and coefficients == repeated_coefficients,
                'Numerical reconstruction mismatch')
        counterfactual = {}
        for policy in (*POLICIES, 'composite_no_band'):
            alternate, _, coeff = numerical(base, arrays, gen, state, settings, policy)
            counterfactual[policy] = dict(defined=alternate is not None,
                model_sha256=digest(alternate) if alternate else None, coefficients=coeff)
        require(counterfactual['sequential']['defined'] == counterfactual['gated_composite']['defined'], 'Support/quorum mismatch')
        require(counterfactual['sequential']['model_sha256'] == counterfactual['composite_no_band']['model_sha256'],
                'No-band numerical negative control differs')
        save(target/'common-input-comparison.json', counterfactual)
        save(target/'global-model.json', model)
        metric = outcomes(model, rows, plan, correct, gen.deps)
        manipulated = task['attackers'] if active and (task['mode']!='adaptive' or chosen_alpha!=0) else []
        decisions = {c:state['decisions'][c][task['policy']]['status'] for c in gen.clients}
        row = dict(round=number, attack_active=active, selected_alpha=chosen_alpha,
            actually_manipulated_clients=manipulated, statuses=decisions,
            masses={c:str(v) for c,v in masses.items()}, coefficients=coefficients,
            base_model_sha256=digest(base), global_model_sha256=digest(model), training=training,
            local_repeat_checks=repeated_training, validation=metric,
            training_seconds=training_seconds, attack_search_seconds=search_seconds,
            aggregation_seconds=aggregation_seconds, **state['timing'])
        save(target/'round.json', row)
        records.append(row)
        base = model
        print(json.dumps(dict(case=task['name'], round=number,
              validation_full_asr=metric['complete_trigger']['asr'],
              quarantined=sum(v.endswith('quarantined') for v in decisions.values())),sort_keys=True),flush=True)
    assert_locks(protocol)
    save(evidence/'summary.json', dict(task=task, completed_rounds=len(records), failure=failure,
                                      complete=len(records)==15, new_TPM_Quotes=0))
    gen.close(evidence)
    result = dict(task=task, complete=len(records)==15, completed_rounds=len(records),
                  failure=failure, manifest_sha256=sha256_file(evidence/'manifest.json'))
    save(result_path, result)
    return result


def prepare():
    require(not LAB.exists(), 'Preserve existing study; use run/evaluate/verify commands')
    LAB.mkdir(parents=True)
    cfg = read(ROOT/'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
    source_root = ROOT/'artifacts/m3-data24-parquet-iid-local-test-v1'
    manifest = read(source_root/'manifest.json')
    union, seen, source_pins = [], set(), {}
    for record in manifest['clients']:
        path = source_root/record['dataset_path']
        require(sha256_file(path)==record['dataset_sha256'], 'Source snapshot pin mismatch')
        source_pins[str(path.relative_to(ROOT))] = sha256_file(path)
        snapshot = read(path)
        for row in snapshot['rows']['train']:
            require(row['window_id'] not in seen, 'Duplicate source training occurrence')
            seen.add(row['window_id']); union.append(row)
    source_pins[str(source_root/'manifest.json')] = sha256_file(source_root/'manifest.json')
    settings = yaml.safe_load((ROOT/'configs/in-round-admission.yaml').read_bytes())['runtime_admission']
    partitions = {}
    for cohort, seed, attackers in ASSIGNMENTS:
        allocation = (_iid_assignments(union,client_count=15,seed=seed,np=np) if cohort=='iid' else
            _dirichlet_assignments(union,client_count=15,seed=seed,alpha=.3,minimum_rows=32,np=np))
        require({r['window_id'] for rs in allocation for r in rs} == seen and
                sum(map(len,allocation)) == len(seen), 'Training allocation coverage mismatch')
        folder = LAB/'partitions'/str(seed)
        clients = []
        for i, rows in enumerate(allocation):
            client = f'client{i+1:02d}'
            path = folder/'clients'/client/'dataset.json'
            save(path,dict(client_id=client,partition_id=i,class_names=manifest['class_names'],rows={'train':rows}))
            clients.append(dict(client_id=client,partition_id=i,dataset_path=str(path.relative_to(folder)),
                                dataset_sha256=sha256_file(path),train_row_count=len(rows)))
        save(folder/'manifest.json',dict(profile='training-only-research-repartition-v1',seed=seed,
            partition_mode=cohort,dirichlet_alpha=.3 if cohort=='non-iid' else None,
            class_names=manifest['class_names'],global_class_weights=manifest['global_class_weights'],
            clients=clients,training_occurrences=len(seen),source_snapshot_pins=source_pins,
            local_test_rows_included=False,M3_full_profile_verification_claimed=False))
        partitions[str(seed)] = sha256_file(folder/'manifest.json')
    tasks = [dict(name=f'{cohort}-s{seed}-{policy}-{mode}', cohort=cohort, seed=seed,
                  attackers=attackers, policy=policy, mode=mode)
             for cohort,seed,attackers in ASSIGNMENTS for policy in POLICIES for mode in MODES]
    protocol = dict(profile='independent-original-gate-trajectories-v1',tasks=tasks,horizon=15,
        attack_rounds=list(range(1,11)),clean_continuation_rounds=list(range(11,16)),
        training=cfg,runtime_admission=settings,partitions=partitions,source_snapshots=source_pins,
        source_locks=locks(),environment=environment(),
        preflight_seed_excluded=2026110600,calibration_refitting=False,threshold_selection=False,
        numerical_backend='Unchanged Flower full-model weighted FedAvg, ordered clients and float masses, as in live in-round admission.',
        trust='All mandatory prerequisites assumed passed, trust risk zero. Software research, no fresh TPM attestation or client signature claim.',
        partition_scope='Six fresh training-only allocations from the same original Data24 global training rows; three IID and three label-Dirichlet alpha=.3. Same initial trained model. Not an independent dataset or random initialization study.',
        attack='Feature-space replacement of 50% hash-selected local training rows, benign target, trigger features13/17/24 at12. Distributed and complete-trigger variants use the same selected rows but different feature-edit budgets.',
        adaptive=dict(alphas=list(ALPHAS),query_budget_per_active_round=len(ALPHAS),
            information='Privileged white-box current clean/poisoned local endpoints and validation oracle. Every defender optimized independently; no test oracle.',
            objective='Maximize worst ASR across full and three component validation triggers after the actual gate and FedAvg; tie: fewer quarantined attacker slots, then larger alpha. Shared alpha for three clients.',
            zero_alpha='Recorded as no actual manipulated exports, not a successfully detected attack.'),
        endpoints='Fixed rounds10 and15, full-horizon peak ASR and attack-window mean ASR. No best-test checkpoint selection.',
        evaluation='Validation during training/search. Test evaluated only after all72 cases have terminal signed evidence; no parameters or models changed after test. Test split was used in earlier work: exploratory reused holdout, not untouched confirmation.',
        costs='Measure training, geometry, validation inference, decisions, aggregation, adaptive search. Offline trust appraisal cost unavailable. Statistical work retained for TPM-only for compatibility with current live wrapper; legacy TPM-only is not timed here.',
        claims='Report every planned case, failures and ineffective controls. Missing/quorum failure is never ASR zero. Seed/partition assignment is the repetition unit, not rounds/clients. No automatic permanent client exclusion claim.',
        effective_control='TPM-only attacked control: at least one test endpoint with >=.20 increase in worst-trigger ASR over its paired clean at the same round and <=.05 loss in clean macro-F1. Report other cases as inconclusive for mitigation.',
        guardrail='Report clean-policy macro-F1 loss relative to paired TPM-only; no promotion if maximum fixed-endpoint loss exceeds.02, if a new gate failure occurs, or if paired peak harm worsens. Even passing all guardrails is exploratory, not universal safety.',
        verification='Independent saved-update score/policy/Flower reconstruction for every completed round; exact no-band/Sequential negative control; repeat one local training at rounds1and15 per case; repeat every candidate decision and objective transcript. Re-evaluate fixed test metrics after training closes.',
        new_TPM_Quotes=0)
    save(LAB/'protocol-before-training.json', protocol)
    (LAB/'controller-frozen.py').write_bytes(Path(__file__).read_bytes())
    print(json.dumps(dict(prepared_cases=len(tasks),protocol_sha256=sha256_file(LAB/'protocol-before-training.json'))),flush=True)


def run(workers):
    protocol = read(LAB/'protocol-before-training.json'); assert_locks(protocol)
    tasks = protocol['tasks']; results = []
    with ProcessPoolExecutor(max_workers=workers,mp_context=multiprocessing.get_context('spawn')) as pool:
        futures = {pool.submit(run_case,task):task for task in tasks}
        for future in as_completed(futures):
            task = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                # Infrastructure/numerical failures remain explicit terminal outcomes.
                error = dict(task=task, complete=False, exception_type=type(exc).__name__, error=str(exc))
                path = LAB/'exceptions'/f'{task["name"]}.json'
                if not path.exists(): save(path,error)
                case = LAB/'cases'/task['name']; evidence = case/'evidence'
                save(evidence/'terminal-exception.json',error)
                if not (evidence/'manifest.json').exists(): Generator.close(evidence)
                completed = len(list(evidence.glob('rounds/round-*/round.json')))
                result = {**error,'completed_rounds':completed,
                          'manifest_sha256':sha256_file(evidence/'manifest.json')}
                if not (case/'result.json').exists(): save(case/'result.json',result)
            results.append(result)
            (LAB/'progress.json').write_text(json.dumps(dict(terminal_cases=len(results),planned_cases=len(tasks),
                complete_cases=sum(r.get('complete',False) for r in results),
                failed_cases=sum(not r.get('complete',False) for r in results)),sort_keys=True)+'\n')
            print('CASE_TERMINAL '+json.dumps({k:v for k,v in result.items() if k not in ('manifest_sha256',)}),flush=True)
    assert_locks(protocol)
    save(LAB/'training-complete.json',dict(protocol_sha256=sha256_file(LAB/'protocol-before-training.json'),
        results=sorted(results,key=lambda r:r['task']['name']),test_inference_performed=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('prepare','run'))
    parser.add_argument('--workers',type=int,default=3)
    args = parser.parse_args()
    prepare() if args.phase=='prepare' else run(args.workers)


if __name__=='__main__': main()
