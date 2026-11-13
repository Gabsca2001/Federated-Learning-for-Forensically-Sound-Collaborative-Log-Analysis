"""Matched native-gradient histories; literal failures are terminal outcomes."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import sys
import time

import numpy as np

OUT = Path(__file__).parent
sys.path[:0] = [str(OUT.parent / 'state-conditioned-detector-20261103')]
from study_data import Generator
from revision_dba_experiment import save, full_gradient, model_with_arrays, outcomes, predict
from fl_forensics.canonical import sha256_file
from fl_forensics.distributed_backdoor import DistributedBackdoorPlan, poison_local_rows
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.literature_baselines import fedgradtrace_global_gradient
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256

REPO = Path.cwd()
ROOT = REPO / 'artifacts/revision-research-closure-v1'
ALPHAS = [0., .25, .5, 1., 2., 4., 16., 64., 128., 256.]
METHODS = ['gradient_fedavg', 'literal_eq2', 'literal_eq3', 'normalized_eq2_adaptation']

def read(p):
    return json.loads(Path(p).read_bytes())

def worst(metric):
    return max([metric['complete_trigger']['asr'],
                *[v['asr'] for v in metric['component_triggers'].values()]])

def operation(base, gradients, histories, counts, clients, method):
    arrays = arrays_from_export(base, np=np)
    if method == 'gradient_fedavg':
        result = [a - .001 * np.average(np.stack([g[i] for g in gradients]), axis=0, weights=counts)
                  for i, a in enumerate(arrays)]
        report = {'coefficients': (np.asarray(counts)/sum(counts)).tolist(), 'coefficient_sum': 1.}
    elif method == 'normalized_eq2_adaptation':
        norms = np.asarray([np.linalg.norm(np.stack(h), 'fro') for h in histories])
        masses = np.asarray(counts) * norms
        if masses.sum() <= 0:
            raise ValueError('zero normalized-Eq2 denominator')
        weights = masses / masses.sum()
        result = [a - .001 * sum(w*g[i] for w, g in zip(weights, gradients, strict=True))
                  for i, a in enumerate(arrays)]
        report = {'coefficients': weights.tolist(), 'coefficient_sum': float(weights.sum()),
                  'interpretation': 'Explicit normalized sample-times-trajectory ablation; not literal Eq2.'}
    else:
        result, report = fedgradtrace_global_gradient(
            base=arrays, gradients=gradients, gradient_histories=[np.stack(h) for h in histories],
            client_ids=clients, sample_counts=counts, learning_rate=.001, formula=method)
    model = model_with_arrays(base, result)
    if not all(np.isfinite(a).all() for a in arrays_from_export(model, np=np)):
        raise ValueError('nonfinite gradient aggregate')
    return model, report

def run_case(task, root, counts_global):
    case = root / task['name']
    assert not case.exists()
    cfg = read(REPO / 'artifacts/revision-dba-three-seed-v1/distributed-s341593/protocol-before-training.json')
    partition = REPO / 'artifacts' / ('m3-data24-parquet-iid-local-test-v1' if task['cohort']=='iid' else 'm3-data24-parquet-non-iid')
    gen = Generator(partition, cfg)
    rows = read(cfg['validation_path'])['rows']['validation']
    pred, _ = predict(gen.initial, rows, gen.deps)
    correct = [p==r['label'] for p, r in zip(pred, rows, strict=True)]
    plan = DistributedBackdoorPlan.model_validate({**cfg['attack_plan'], 'seed': task['seed'],
        'client_components': dict(zip(task['attackers'], [[13],[17],[24]], strict=True))})
    save(case / 'task.json', task)
    base = gen.initial
    history = [[] for _ in gen.clients]
    counts = [len(gen.rows[c]) for c in gen.clients]
    records = []
    failure = None
    for number in range(1, 16):
        prefix = case / 'rounds' / f'round-{number:03d}'
        save(prefix / 'base-model.json', base)
        clean, poisoned, poison_metadata = [], {}, {}
        active = task['mode']=='adaptive-gradient' and number <= 10
        started = time.perf_counter_ns()
        for c in gen.clients:
            grad, _ = full_gradient(base, gen.rows[c], gen.weights, gen.deps)
            clean.append(grad)
            counts_global['full_gradient_evaluations'] += 1
            if active and c in task['attackers']:
                altered, meta = poison_local_rows(rows=gen.rows[c], plan=plan, client_id=c,
                                                 round_number=number, distributed=True)
                poisoned[c], _ = full_gradient(base, altered, gen.weights, gen.deps)
                poison_metadata[c] = meta
                counts_global['full_gradient_evaluations'] += 1
        collection_ns = time.perf_counter_ns()-started
        packed = {f'clean_{i}_{j}': a for i,g in enumerate(clean) for j,a in enumerate(g)}
        packed.update({f'poison_{c}_{j}':a for c,g in poisoned.items() for j,a in enumerate(g)})
        np.savez_compressed(prefix/'gradient-endpoints.npz', **packed)
        save(prefix/'poisoning-evaluation-only.json', poison_metadata)
        candidates, transcript = [], []
        for alpha in ALPHAS if active else [0.]:
            gradients = [[np.asarray(a + alpha*(b.astype(np.float64)-a), dtype=a.dtype)
                          for a,b in zip(g,poisoned[c],strict=True)] if c in poisoned else g
                         for c,g in zip(gen.clients,clean,strict=True)]
            next_history = [(h+[np.concatenate([a.astype(np.float64).ravel() for a in g])])[-3:]
                            for h,g in zip(history,gradients,strict=True)]
            try:
                model, report = operation(base, gradients, next_history, counts, gen.clients, task['method'])
                metric = outcomes(model, rows, plan, correct, gen.deps)
                if not np.isfinite(metric['clean']['loss']):
                    raise ValueError('nonfinite validation loss')
                item = {'alpha':alpha,'valid':True,'metrics':metric,'coefficient_sum':report['coefficient_sum']}
                candidates.append((worst(metric), alpha, model, report, metric, gradients, next_history))
            except (ValueError, ArithmeticError, RuntimeError) as error:
                item = {'alpha':alpha,'valid':False,'error_type':type(error).__name__,'error':str(error)}
            transcript.append(item)
            if active:
                counts_global['queries'] += 1
        save(prefix/'queries.json', transcript)
        if not candidates:
            failure = {'round':number,'reason':'No finite candidate under the literal declared recurrence.',
                       'queries_sha256':sha256_file(prefix/'queries.json')}
            save(prefix/'terminal-failure.json',failure)
            break
        search_failed = False
        if active and root.name != 'native-gradients-development':
            ref_path = root / f"{task['cohort']}-gradient_fedavg-clean/rounds/round-{number:03d}/round.json"
            ref_f1 = read(ref_path)['metrics']['clean']['macro_f1_all_model_classes']
            allowed = [x for x in candidates if x[4]['clean']['macro_f1_all_model_classes'] >= ref_f1-.05]
            if not allowed:
                allowed = [x for x in candidates if x[1]==0.]
                search_failed = True
            candidates = allowed or candidates
        _, alpha, model, report, metric, gradients, next_history = max(candidates,key=lambda x:(x[0],x[1]))
        # Independently repeat the selected server operation, with all timings scoped.
        timings = []
        for repeat in range(3):
            start = time.perf_counter_ns()
            repeated, repeated_report = operation(base, gradients, next_history, counts, gen.clients, task['method'])
            elapsed = time.perf_counter_ns()-start
            assert derived_json_bytes(repeated)==derived_json_bytes(model)
            assert repeated_report==report
            timings.append(elapsed)
        if number in (1,15):
            for c, g in zip(gen.clients, clean, strict=True):
                repeat, _ = full_gradient(base, gen.rows[c],gen.weights,gen.deps)
                assert all(np.array_equal(a,b) for a,b in zip(g,repeat,strict=True))
                counts_global['gradient_repeats'] += 1
        save(prefix/'global-model.json',model)
        save(prefix/'aggregation.json',report)
        record = {'round':number,'selected_alpha':alpha,'attack_active':active,'selective_search_failed':search_failed,
                  'metrics':metric,'worst_trigger_asr':worst(metric),'collection_ns':collection_ns,
                  'server_export_and_aggregation_ns':timings,'native_client_detection_metric_available':False,
                  'gradient_endpoints_sha256':sha256_file(prefix/'gradient-endpoints.npz')}
        save(prefix/'round.json',record)
        records.append(record)
        history, base = next_history, model
        counts_global['rounds'] += 1
        print(json.dumps({'case':task['name'],'round':number,'alpha':alpha,
                          'ASR':worst(metric),'F1':metric['clean']['macro_f1_all_model_classes']}),flush=True)
    gen.close(case)
    result = {'task':task,'completed_rounds':len(records),'complete_trajectory':len(records)==15,
              'terminal_failure':failure,'rounds':records,'manifest_sha256':sha256_file(case/'manifest.json')}
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--phase', choices=['development','development-v2','evaluation'], required=True)
    args = ap.parse_args()
    root = ROOT / ('native-gradients-' + args.phase)
    assert not root.exists()
    if args.phase.startswith('development'):
        assignments = [('non-iid',512593,['client03','client08','client14'])]
        methods = ['gradient_fedavg']
    else:
        assignments = [('iid',2026110421,['client02','client07','client12']),
                       ('iid',2026110422,['client03','client08','client15']),
                       ('iid',2026110423,['client01','client09','client14']),
                       ('non-iid',2026110424,['client02','client06','client13']),
                       ('non-iid',2026110425,['client04','client09','client15']),
                       ('non-iid',2026110426,['client03','client07','client11'])]
        methods = METHODS
    tasks=[]
    for cohort in ('iid','non-iid'):
        if not any(a[0]==cohort for a in assignments):
            continue
        for method in methods:
            c,s,a = next(x for x in assignments if x[0]==cohort)
            tasks.append(dict(name=f'{cohort}-{method}-clean',cohort=c,seed=s,attackers=a,method=method,mode='clean'))
    for c,s,a in assignments:
        for method in methods:
            tasks.append(dict(name=f'{c}-{s}-{method}-attack',cohort=c,seed=s,attackers=a,method=method,mode='adaptive-gradient'))
    protocol = {'profile':'matched-native-gradient-completion-v1','phase':args.phase,'tasks':tasks,
                'source':implementation_sha256(),'controller_sha256':sha256_file(Path(__file__)),
                'eta':.001,'rounds':15,'attack_rounds':list(range(1,11)), 'history_length':3,
                'poison_fraction':.5,'trigger_features':[13,17,24],'trigger_value':12,'alpha_candidates':ALPHAS,
                'attack':'Real clean/50%-DBA-poisoned full-snapshot gradients at current base, with scaled attacker gradient exports. Ten queries/attack round maximize worst full/component validation ASR then scale. Honest gradients are unmodified. No Adam deltas substitute for gradients.',
                'information':'Shared Data24 partitions and validation oracle; no test access or fresh TPM Quote.',
                'independence':'Clean gradients are deterministic and seed-independent; one shared clean reference per cohort/method, not three independent clean replications.',
                'success_rule':'All cases reported, including finite-loss failures. Mitigation requires attack-effective gradient-FedAvg control, paired utility and ASR comparison. Failed tails have no ASR. Larger trajectory norms do not become downweight factors by changing the literal formula.',
                'normalized_variant':'Separate explicitly normalized sample-times-norm ablation, not a claimed literal Eq2 correction.'}
    protocol['attack_utility_guard'] = 'For development-v2 and evaluation, select only candidates within .05 clean macro-F1 of the same-round unmodified gradient-FedAvg reference; if none exists retain alpha0 as an explicit search failure, not a successful stealth attack.'
    save(root/'protocol-before-execution.json',protocol)
    (root/'controller.py').write_bytes(Path(__file__).read_bytes())
    totals = dict(full_gradient_evaluations=0,gradient_repeats=0,queries=0,rounds=0)
    results=[]
    for task in tasks:
        results.append(run_case(task,root,totals))
        (root/'progress.json').write_text(json.dumps({'finished_cases':len(results),'total_cases':len(tasks),'counts':totals})+'\n')
    save(root/'results.json',{'protocol_sha256':sha256_file(root/'protocol-before-execution.json'),
                             'cases':results,'counts':totals})
    print('NATIVE GRADIENT STUDY FINISHED',json.dumps(totals),flush=True)

if __name__=='__main__':
    main()
