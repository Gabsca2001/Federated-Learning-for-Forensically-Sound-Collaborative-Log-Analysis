"""Publish only a closed, independently replayed capped-final study."""
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
import os
import csv
import hashlib
import json
import math
import shutil
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'artifacts/revision-capped-final-v1'
DEST = ROOT / 'results/gates-probes/revision-capped-final-v1'
OUT = (Path(os.environ["FL_FORENSICS_OUTPUT_ROOT"]) / 'capped-final-20261106')
PIN = '13cb93e46e48eb4481a79979399a27f80b0d8b2e6a1c46fdcbe13844e78f8ddc'
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src')]
import revision_capped_final_study as study
from revision_dba_experiment import authenticate, predict
from fl_forensics.federated_model import dependencies

METHODS = ('tpm_only', 'robust_bounded', 'capped_sample', 'capped_robust')
MODES = ('distributed', 'complete-trigger', 'adaptive')
SPLITS = ('validation', 'test')

def read(path):
    return json.loads(Path(path).read_text())

def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')

def table(path, rows):
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def avg(values):
    values = [value for value in values if value is not None]
    return statistics.mean(values) if values else None

def maximum(values):
    values = [value for value in values if value is not None]
    return max(values) if values else None

def rate(item):
    denominator = item['non_target_denominator']
    result = Fraction(item['target_predictions'], denominator) if denominator else None
    assert (float(result) if result is not None else None) == item['asr']
    return result

def trigger_items(metric):
    return [('complete_trigger', metric['complete_trigger']),
        *[(f'component:{client}', value) for client, value in sorted(metric['component_triggers'].items())]]

def worst(metric):
    return maximum([rate(value) for _, value in trigger_items(metric)])

def f1(metric):
    return metric['clean']['macro_f1_all_model_classes']

def pct(value):
    return 'undefined' if value is None else f'{100 * float(value):.2f}'

def main():
    assert sha(LAB / 'protocol-before-training.json') == PIN
    protocol = read(LAB / 'protocol-before-training.json')
    study.assert_locks(protocol)
    training = read(LAB / 'training-complete.json')
    audit = read(LAB / 'verified/summary.json')
    header = read(LAB / 'verified/verification-before-reading.json')
    assert audit['status'] == 'verified' and audit['test_accessed']
    assert audit['training_closure_sha256'] == sha(LAB / 'training-complete.json')
    assert header['training_closure_sha256'] == audit['training_closure_sha256']
    assert header['verifier_sha256'] == audit['verifier_sha256'] == sha(ROOT / 'scripts/revision_capped_final_audit.py')
    assert training['protocol_sha256'] == PIN and not training['test_inference_performed']
    assert len(audit['cases']) == len(training['results']) == len(protocol['tasks']) == 108
    expected = {task['name']: task for task in protocol['tasks']}
    assert set(expected) == {case['task']['name'] for case in audit['cases']}
    assert not DEST.exists(), 'Preserve any earlier published release'
    staging = ROOT / 'results' / f'.capped-final-publication-{time.time_ns()}'
    assert staging.resolve().is_relative_to(ROOT / 'results')
    staging.mkdir()
    cases = {}
    for case in audit['cases']:
        task = case['task']
        assert task == expected[task['name']]
        result = read(LAB / 'cases' / task['name'] / 'result.json')
        assert case['source_manifest_sha256'] == result['manifest_sha256']
        authenticate(LAB / 'cases' / task['name'] / 'evidence', result['manifest_sha256'])
        assert case['verification']['cache_disabled']
        assert case['completed_rounds'] == len(case['rows'])
        cases[(task['seed'], task['method'], task['mode'])] = case
    assert len(cases) == 108
    case_rows, round_rows, triggers, cost_rows = [], [], [], []
    series = {}
    for case in audit['cases']:
        task = case['task']; name = task['name']; method = task['method']
        common = {key: task[key] for key in ('name', 'split', 'cohort', 'seed', 'method', 'mode')}
        row_index = {row['round']: row for row in case['rows']}
        case_metrics = {split: {} for split in SPLITS}
        all_counts = []
        all_retention = []
        all_shares = []
        all_tv = []
        all_no_resurrection = []
        costs = []
        for row in case['rows']:
            number = row['round']
            original = read(LAB / 'cases' / name / 'evidence/rounds' / f'round-{number:03d}' / 'round.json')
            metrics = {'validation': original['validation'], 'test': row['test']}
            assert metrics['validation']['clean'] == row['validation_clean']
            coefficients = {client: Fraction(value) for client, value in row['coefficients'].items()}
            masses = {client: Fraction(value) for client, value in row['masses'].items()}
            nominal = sum(row['example_counts'].values())
            retained = sum(masses.values()) / nominal
            share = sum(sorted(coefficients.values(), reverse=True)[:3])
            tv = sum(abs(coefficients[client] - masses[client] / sum(masses.values())) for client in masses) / 2
            contributors = sum(value > 0 for value in coefficients.values())
            no_resurrection = all(coefficients[client] == 0 for client in masses if masses[client] == 0)
            assert sum(coefficients.values()) == 1 and min(coefficients.values()) >= 0
            assert str(retained) == row['retained_nominal_mass']
            assert str(share) == row['maximum_three_final_share']
            assert str(tv) == row['alpha_beta_total_variation']
            capped_ok = sum(coefficients.values()) == 1 and contributors >= 10 and share <= Fraction(1, 3) and retained >= Fraction(4, 5) and no_resurrection
            if method.startswith('capped_'):
                assert all(value <= Fraction(1, 9) for value in coefficients.values()) and capped_ok
            all_counts.append(contributors); all_retention.append(retained)
            all_shares.append(share); all_tv.append(tv); all_no_resurrection.append(no_resurrection)
            timing = row['timing']
            cold_operator = timing['aggregation_seconds'] if method == 'tpm_only' else timing['final_operator_seconds']
            assert cold_operator is not None and cold_operator >= 0
            costs.append(cold_operator)
            entry = {**common, 'round': number, 'contributors': contributors,
                'retained_nominal_mass_fraction': str(retained), 'retained_nominal_mass': float(retained),
                'top_three_beta_fraction': str(share), 'top_three_beta': float(share),
                'alpha_beta_tv_fraction': str(tv), 'alpha_beta_tv': float(tv),
                'zero_mass_not_resurrected': no_resurrection, 'capped_operator_checks_pass': capped_ok if method.startswith('capped_') else None,
                'selected_attack_alpha': row['selected_alpha'], 'manipulated_updates': len(row['actually_manipulated_clients']),
                'quarantined_updates': sum(value.endswith('quarantined') for value in row['statuses'].values()),
                'downweighted_updates': sum(value == 'accepted_downweighted' for value in row['statuses'].values()),
                'cold_operator_seconds': cold_operator, **timing}
            for split, metric in metrics.items():
                case_metrics[split][number] = metric
                entry.update({f'{split}_clean_macro_f1': f1(metric), f'{split}_clean_accuracy': metric['clean']['accuracy'],
                    f'{split}_full_asr': metric['complete_trigger']['asr'],
                    f'{split}_worst_trigger_asr': float(worst(metric)) if worst(metric) is not None else None})
                for trigger, value in trigger_items(metric):
                    rate(value)
                    triggers.append({**common, 'round': number, 'evaluation_split': split, 'trigger': trigger, **value})
            round_rows.append(entry)
        for split in SPLITS:
            series[(task['seed'], method, task['mode'], split)] = case_metrics[split]
        result_row = {**common, 'complete': case['complete'], 'completed_rounds': case['completed_rounds'],
            'failure': json.dumps(case.get('failure')), 'source_exception': case.get('source_exception'),
            'minimum_contributors': min(all_counts, default=None),
            'minimum_retained_nominal_mass': float(min(all_retention)) if all_retention else None,
            'maximum_three_beta_share': float(max(all_shares)) if all_shares else None,
            'maximum_alpha_beta_tv': float(max(all_tv)) if all_tv else None,
            'zero_mass_not_resurrected': all(all_no_resurrection),
            'source_manifest_sha256': case['source_manifest_sha256']}
        for split in SPLITS:
            data = case_metrics[split]
            result_row.update({
                f'{split}_peak_full_asr': max((item['complete_trigger']['asr'] for item in data.values()), default=None) if case['complete'] else None,
                f'{split}_observed_prefix_peak_full_asr': max((item['complete_trigger']['asr'] for item in data.values()), default=None),
                f'{split}_peak_worst_asr': float(max(worst(item) for item in data.values())) if case['complete'] else None,
                f'{split}_final_full_asr': data.get(15, {}).get('complete_trigger', {}).get('asr'),
                f'{split}_final_worst_asr': float(worst(data[15])) if 15 in data else None,
                f'{split}_macro_f1_round10': f1(data[10]) if 10 in data else None,
                f'{split}_final_macro_f1': f1(data[15]) if 15 in data else None,
                f'{split}_final_accuracy': data[15]['clean']['accuracy'] if 15 in data else None})
            if data:
                peak_full = max(item['complete_trigger']['asr'] for item in data.values())
                peak_worst = max(worst(item) for item in data.values())
                result_row[f'{split}_first_observed_peak_full_round'] = min(number for number, item in data.items() if item['complete_trigger']['asr'] == peak_full)
                result_row[f'{split}_first_observed_peak_worst_round'] = min(number for number, item in data.items() if worst(item) == peak_worst)
        case_rows.append(result_row)
        cost_rows.append({**common, 'observed_rounds': len(costs), 'cold_operator_seconds_mean': avg(costs),
            'cold_operator_seconds_total': sum(costs),
            'training_seconds_total': sum(row['timing']['training_seconds'] for row in case['rows']),
            'attack_search_seconds_total': sum(row['timing'].get('attack_search_seconds') or 0 for row in case['rows']),
            'timing_context': 'two-worker shared CPU host; historical retained-case observations included; nested timings not additive'})
    clean_guards = []
    for task in protocol['tasks']:
        if task['mode'] != 'clean' or task['method'] == 'tpm_only':
            continue
        method = task['method']; seed = task['seed']
        case = cases[(seed, method, 'clean')]; control = cases[(seed, 'tpm_only', 'clean')]
        for split in SPLITS:
            for number in (10, 15):
                model = series[(seed, method, 'clean', split)].get(number)
                raw = series[(seed, 'tpm_only', 'clean', split)].get(number)
                defined = model is not None and raw is not None
                loss = f1(raw) - f1(model) if defined else None
                clean_guards.append({key: task[key] for key in ('split', 'cohort', 'seed', 'method')} | {
                    'evaluation_split': split, 'round': number, 'defined': defined,
                    'complete_histories': case['complete'] and control['complete'],
                    'macro_f1_loss_vs_tpm': loss, 'maximum_allowed_loss': .02,
                    'qualified': bool(defined and case['complete'] and control['complete'] and loss <= .02)})
    effects, attacked_utility = [], []
    for task in protocol['tasks']:
        if task['mode'] == 'clean':
            continue
        seed, method, mode = task['seed'], task['method'], task['mode']
        attacked = cases[(seed, method, mode)]; clean = cases[(seed, method, 'clean')]
        for split in SPLITS:
            am, cm = series[(seed, method, mode, split)], series[(seed, method, 'clean', split)]
            paired = [(number, worst(am[number]) - worst(cm[number]), f1(cm[number]) - f1(am[number]))
                for number in sorted(am.keys() & cm.keys())]
            for number, harm, loss in paired:
                attacked_utility.append({key: task[key] for key in ('cohort', 'seed', 'method', 'mode')} | {
                    'evaluation_split': split, 'round': number, 'clean_control_macro_f1': f1(cm[number]),
                    'attacked_model_macro_f1': f1(am[number]), 'macro_f1_loss_under_attack': loss,
                    'paired_worst_trigger_asr_increase': float(harm)})
            peak = max((item[1] for item in paired), default=None)
            effects.append({key: task[key] for key in ('cohort', 'seed', 'method', 'mode')} | {
                'evaluation_split': split, 'complete_histories': attacked['complete'] and clean['complete'],
                'paired_rounds': len(paired), 'peak_paired_harm_fraction': str(peak) if peak is not None else None,
                'peak_paired_harm': float(peak) if peak is not None else None,
                'maximum_clean_macro_f1_loss_under_attack': max((item[2] for item in paired), default=None),
                'final_clean_macro_f1_loss_under_attack': f1(cm[15]) - f1(am[15]) if 15 in am and 15 in cm else None,
                'effective_control': any(harm >= Fraction(1, 5) and loss <= .05 for _, harm, loss in paired)})
    effect_map = {(row['seed'], row['method'], row['mode'], row['evaluation_split']): row for row in effects}
    comparisons = []
    for cohort, seed, _attackers in study.RESERVED:
        for mode in MODES:
            for split in SPLITS:
                proposed, baseline, raw = (effect_map[(seed, method, mode, split)] for method in ('capped_robust', 'robust_bounded', 'tpm_only'))
                defined = proposed['complete_histories'] and baseline['complete_histories'] and proposed['paired_rounds'] == baseline['paired_rounds'] == 15
                p = Fraction(proposed['peak_paired_harm_fraction']) if proposed['peak_paired_harm_fraction'] is not None else None
                b = Fraction(baseline['peak_paired_harm_fraction']) if baseline['peak_paired_harm_fraction'] is not None else None
                comparisons.append({'cohort': cohort, 'seed': seed, 'mode': mode, 'evaluation_split': split,
                    'defined': defined, 'capped_robust_harm': float(p) if p is not None else None,
                    'robust_bounded_harm': float(b) if b is not None else None,
                    'effective_raw_control': raw['complete_histories'] and raw['effective_control'],
                    'worse_than_robust': bool(defined and p > b),
                    'strict_benefit_in_effective_control': bool(defined and raw['complete_histories'] and raw['effective_control'] and p < b)})
    aggregates = []
    groups = defaultdict(list)
    for row in case_rows:
        groups[(row['split'], row['cohort'], row['method'], row['mode'])].append(row)
    for key, group in sorted(groups.items()):
        for split in SPLITS:
            for metric in ('peak_full_asr', 'peak_worst_asr', 'final_full_asr', 'final_macro_f1', 'final_accuracy'):
                values = [row[f'{split}_{metric}'] for row in group if row[f'{split}_{metric}'] is not None]
                aggregates.append(dict(zip(('stage', 'cohort', 'method', 'mode'), key, strict=True)) | {
                    'evaluation_split': split, 'metric': metric, 'planned_cases': len(group),
                    'defined_cases': len(values), 'mean': avg(values),
                    'sample_sd': statistics.stdev(values) if len(values) > 1 else None,
                    'minimum': min(values, default=None), 'maximum': max(values, default=None)})
    # Fixed-endpoint model differences complement ASR and clean utility.
    deps = dependencies(); deps[1].set_num_threads(1)
    deps[1].use_deterministic_algorithms(True)
    test_entry = read(ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1/manifest.json')['server_evaluation_splits']['test']
    test_path = ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1' / test_entry['path']
    assert sha(test_path) == test_entry['sha256']
    test = read(test_path)['rows']['test']
    model_cache, prediction_cache = {}, {}
    def exported(case, number):
        path = LAB / 'cases' / case['task']['name'] / 'evidence/rounds' / f'round-{number:03d}' / 'global-model.json'
        if path not in model_cache:
            model_cache[path] = read(path)
        return path, model_cache[path]
    def predicted(path, model):
        if path not in prediction_cache:
            prediction_cache[path] = predict(model, test, deps)[0]
        return prediction_cache[path]
    residuals = []
    for task in protocol['tasks']:
        if task['mode'] == 'clean':
            continue
        attacked = cases[(task['seed'], task['method'], task['mode'])]
        clean = cases[(task['seed'], task['method'], 'clean')]
        for number in (10, 15):
            available = number in {r['round'] for r in attacked['rows']} and number in {r['round'] for r in clean['rows']}
            entry = {key: task[key] for key in ('cohort', 'seed', 'method', 'mode')} | {'round': number, 'defined': available}
            if available:
                ap, a = exported(attacked, number); cp, c = exported(clean, number)
                assert [(p['name'], p['shape'], p['dtype']) for p in a['parameters']] == [(p['name'], p['shape'], p['dtype']) for p in c['parameters']]
                squared = sum(float(deps[0].sum((deps[0].asarray(x['values'], dtype=float) - deps[0].asarray(y['values'], dtype=float)) ** 2))
                              for x, y in zip(a['parameters'], c['parameters'], strict=True))
                mismatch = sum(x != y for x, y in zip(predicted(ap, a), predicted(cp, c), strict=True))
                entry.update(parameter_l2=math.sqrt(squared), identical_parameter_payload=a == c,
                    untriggered_prediction_mismatches=mismatch, untriggered_examples=len(test),
                    untriggered_prediction_disagreement=mismatch / len(test))
            residuals.append(entry)
    guard_splits = {}
    for split in SPLITS:
        rows = [row for row in comparisons if row['evaluation_split'] == split]
        benefits = [row for row in rows if row['strict_benefit_in_effective_control']]
        clean = [row for row in clean_guards if row['evaluation_split'] == split]
        guard_splits[split] = {'defined_comparisons': sum(row['defined'] for row in rows),
            'worse_comparisons': sum(row['worse_than_robust'] for row in rows),
            'strict_effective_control_benefits': len(benefits),
            'non_iid_effective_control_benefits': sum(row['cohort'] == 'non-iid' for row in benefits),
            'clean_utility_checks': len(clean), 'clean_utility_failures': sum(not row['qualified'] for row in clean),
            'clean_utility_failures_by_method': {method: sum(not row['qualified'] for row in clean if row['method'] == method) for method in METHODS[1:]},
            'capped_robust_own_clean_utility_guard_pass': all(row['qualified'] for row in clean if row['method'] == 'capped_robust'),
            'security_guard_pass': all(row['defined'] and not row['worse_than_robust'] for row in rows) and len(benefits) >= 2 and any(row['cohort'] == 'non-iid' for row in benefits),
            'clean_utility_guard_pass': all(row['qualified'] for row in clean)}
    capped_rounds = [row for row in round_rows if row['method'].startswith('capped_')]
    structural_pass = all(case['complete'] for case in audit['cases'] if case['task']['mode'] == 'clean') and all(row['capped_operator_checks_pass'] for row in capped_rounds)
    totals = {key: sum(case['verification'][key] for case in audit['cases'])
              for key in ('rounds', 'queries', 'local_repeats', 'cap_certificates', 'known_original_rounds_reproduced')}
    summary = {'profile': protocol['profile'], 'protocol_sha256': PIN,
        'training_closure_sha256': sha(LAB / 'training-complete.json'),
        'numerical_audit_sha256': sha(LAB / 'verified/summary.json'),
        'publication_contract_sha256': sha(LAB / 'publication-contract-before-test.json'),
        'verifier_sha256': audit['verifier_sha256'], 'planned_cases': 108,
        'complete_cases': sum(case['complete'] for case in audit['cases']), 'audit_totals': totals,
        'completed_by_method': {method: sum(case['complete'] for case in audit['cases'] if case['task']['method'] == method) for method in METHODS},
        'structural_guard_pass': structural_pass, 'guards': guard_splits,
        'combined_predeclared_guards_pass': structural_pass and all(value['security_guard_pass'] and value['clean_utility_guard_pass'] for value in guard_splits.values()),
        'default_policy_changed': False, 'actual_admission_policy': 'tpm_only', 'fresh_TPM_quotes': 0,
        'test_split_sha256': sha(test_path), 'independent_dataset': False,
        'scope': 'Exploratory assigned histories on reused Data24; no universal robustness, malicious-client identification or automatic production promotion'}
    for filename, values in (('cases.csv', case_rows), ('rounds.csv', round_rows), ('triggers.csv', triggers),
            ('costs.csv', cost_rows), ('clean-utility.csv', clean_guards), ('paired-effects.csv', effects),
            ('security-comparisons.csv', comparisons), ('aggregate.csv', aggregates), ('residuals.csv', residuals),
            ('attacked-clean-utility.csv', attacked_utility)):
        table(staging / filename, values)
    write(staging / 'summary.json', summary)
    write(staging / 'effective-settings.json', {
        'local_epochs': protocol['training']['local_epochs'],
        'batch_size': protocol['training']['batch_size'],
        'learning_rate': protocol['training']['learning_rate'],
        'horizon': protocol['horizon'],
        'effective_minimum_contributors': protocol['runtime_admission']['minimum_contributors'],
        'inherited_training_helper_minimum_contributors': protocol['training']['minimum_contributors'],
        'quorum_precedence': 'The active controller/operators use runtime_admission.minimum_contributors (10), not the inherited helper field (8).',
        'attack_plan_template': protocol['training']['attack_plan'],
        'actual_assignments_and_attackers': protocol['reserved'],
        'adaptive_alpha_budget': [0, .25, .5, 1, 2, 4], 'device': 'cpu',
        'actual_admission': 'tpm_only with prerequisite trust assumed passed in software'})
    shutil.copyfile(LAB / 'protocol-before-training.json', staging / 'protocol-before-training.json')
    shutil.copyfile(LAB / 'publication-contract-before-test.json', staging / 'publication-contract-before-test.json')
    shutil.copyfile(ROOT / 'docs/admission-gates/CAPPED_FINAL_AGGREGATION.md', staging / 'CAP_PROJECTION_MODEL.md')
    if (OUT / 'GATE_DEFAULTS.md').exists():
        shutil.copyfile(OUT / 'GATE_DEFAULTS.md', staging / 'GATE_DEFAULTS.md')
    plot(staging, round_rows, clean_guards, comparisons)
    lines = ['# Explicit capped-final aggregation: completed exploratory campaign', '',
        f'Completed **{summary["complete_cases"]}/108** planned histories. The independent numerical audit reconstructed **{totals["rounds"]} rounds**, '
        f'**{totals["queries"]} adaptive candidate evaluations**, **{totals["cap_certificates"]} capped coefficient certificates** '
        f'and **{totals["known_original_rounds_reproduced"]} historical FedAvg checkpoints**.', '',
        f'Combined predeclared research guards passed: **{summary["combined_predeclared_guards_pass"]}**. '
        f'Structural continuity/coefficient checks passed: **{structural_pass}**.', '',
        '| Evaluation | Clean utility failures | Worse paired security comparisons | Strict benefits in effective raw controls | Non-IID benefits | Security guard |',
        '| --- | ---: | ---: | ---: | ---: | --- |']
    for split, value in guard_splits.items():
        lines.append(f'| {split} | {value["clean_utility_failures"]}/{value["clean_utility_checks"]} | {value["worse_comparisons"]}/{value["defined_comparisons"]} | {value["strict_effective_control_benefits"]} | {value["non_iid_effective_control_benefits"]} | {value["security_guard_pass"]} |')
    lines += ['', '## Design and interpretation', '',
        'The four arms use mandatory-trust-only admission: raw FedAvg, robust bounded aggregation, capped sample weights and capped robust weights. '
        'The capped operators retain the original admitted counts and alpha, but derive a distinct final beta after tensor clipping. '
        'Each coefficient is at most 1/9, hence any three clients have final share at most 1/3. '
        'Admission retention is not preservation of sample-proportional influence; alpha/beta total variation is reported.', '',
        'Three previously problematic non-IID assignments provide 12 known clean mechanism replications. '
        'Six separately declared IID/non-IID assignments provide 96 clean/distributed/full-trigger/adaptive histories. '
        'All histories have a 15-round horizon, attacks in rounds 1–10 and unmodified continuation in rounds 11–15. '
        'The test split was used in previous work; new assignments are exploratory and do not supply an independent dataset.', '',
        'The DBA controls three identities and deterministically selects ceil(0.50*N_i) of each local dataset for triggering and assignment of the benign target label, '
        'including rows already labelled benign (which are triggered without a label flip). It '
        'sets standardized feature coordinates 13, 17 and 24 to 12. The distributed variant gives each client one component; '
        'the complete-trigger variant gives each attacking client the full trigger. These are feature-space experiments; '
        'realizability as raw network traffic is not established. The adaptive variant queries alpha={0,.25,.5,1,2,4} '
        'against each actual defender, optimizing validation worst-trigger ASR without a clean-utility constraint. '
        'Alpha zero is an unmodified export, and values above one amplify the poisoned direction.', '',
        'The adaptive search uses an experimental defender-aware validation oracle. This does not establish that a deployed attacker has access to the server validation labels or such a live API.', '',
        'Effective local training uses ten Adam epochs, batch size 128 and learning rate 0.001 on CPU. '
        'The actual quorum is ten, read from runtime_admission; the inherited training-helper field of eight is not the active quorum. '
        'All methods share the pinned historical warm start and scaler; effective-settings.json records field precedence.', '',
        'Paired harm is the maximum over fixed rounds of attacked worst full/component-trigger ASR minus the same method’s own clean worst-trigger ASR at that round. '
        'The historical effective-control rule requires at least 20 percentage points paired ASR increase with at most 5 points clean F1 loss at the same endpoint. '
        'Undefined results remain undefined. Full-trigger zero and final zero do not establish prevention across trigger components or over the whole history.', '',
        '## Reserved attack outcomes', '',
        'Cells below show cohort mean **peak / final full-trigger test ASR (%)**, with all three assignments contributing when complete. '
        'Per-assignment worst-trigger outcomes and paired effects remain in the CSV files.', '',
        '| Cohort | Attack | TPM-only FedAvg | Robust bounded | Capped sample | Capped robust |', '| --- | --- | --- | --- | --- | --- |']
    for cohort in ('iid', 'non-iid'):
        for mode in MODES:
            cells = []
            for method in METHODS:
                selected = [row for row in case_rows if row['split'] == 'reserved' and row['cohort'] == cohort and row['mode'] == mode and row['method'] == method]
                peak_values = [row['test_peak_full_asr'] for row in selected if row['test_peak_full_asr'] is not None]
                final_values = [row['test_final_full_asr'] for row in selected if row['test_final_full_asr'] is not None]
                support = '' if len(peak_values) == len(final_values) == 3 else f' (n={len(peak_values)}/{len(final_values)})'
                cells.append(pct(avg(peak_values)) + ' / ' + pct(avg(final_values)) + support)
            lines.append('| ' + ' | '.join([cohort, mode, *cells]) + ' |')
    residual_nonzero = sum(row.get('parameter_l2', 0) > 0 for row in residuals if row['defined'])
    lines += ['', '## Residual differences and measured cost', '',
        f'At the fixed round-10/15 endpoints, **{residual_nonzero}/{sum(row["defined"] for row in residuals)}** defined own-method attacked/clean comparisons '
        'have nonzero parameter distance. The table also records untriggered test prediction differences. '
        'These differences alone do not establish harmful remaining poisoning, and zero ASR alone does not establish restoration.', '',
        'attacked-clean-utility.csv also retains the untriggered-data macro-F1 loss of each attacked model against its own clean control at every fixed round. '
        'This exposes defenses that lower ASR while degrading normal classification. The predeclared clean-branch utility guards remain separately identified; no new attacked-utility threshold was fitted.', '',
        'The timing table retains actual observed training, attack-search and operator times. '
        'For special operators the first uncached computation is measured by final_operator_seconds; '
        'the repeated aggregation_seconds call may be a cache lookup. Raw FedAvg has no such cache and uses its actual repeated aggregation time. '
        'Search, geometry and operator timings overlap and must not be added as disjoint components. '
        'Jobs used two concurrent CPU workers; retained historical cases keep their original timings. These are measured shared-host costs, not isolated latency benchmarks.', '',
        '## Defaults, trust and scope', '',
        'The standard in-round admission configuration still selects gated_composite when explicitly bound to M5. '
        'The unified witnessed profile selects tpm_only. The present study also uses tpm_only as common admission, '
        'with prerequisite trust assumed passed in software. It creates no fresh TPM quote and does not measure a new physical-TPM campaign. '
        'The old severe statistical gate can still defer upstream; the new operator does not override zero admission or trust vetoes. '
        'No default was changed and no automatic permanent client exclusion was validated.', '',
        'A coefficient/norm bound is not an ASR guarantee. Clean utility, attack effectiveness and continuity are reported independently. '
        'An effective live deployment would additionally require a source-bound measured runtime for the selected operator. '
        'The thesis and ToN-IoT evaluation were left unchanged by this campaign.', '',
        'Trajectory curves show the mean over three reserved assignments, with min–max shading; a curve stops when all three observations are no longer available. '
        'This descriptive range is not a confidence interval; per-assignment tables retain outliers.', '',
        '## Evidence', '',
        '- Frozen protocol and pre-test reporting contract are copied alongside the results.',
        '- Complete source evidence: artifacts/revision-capped-final-v1/cases/.',
        '- Training closure: artifacts/revision-capped-final-v1/training-complete.json.',
        '- Cache-disabled numerical audit: artifacts/revision-capped-final-v1/verified/summary.json.',
        '- Operational interruptions remain preserved; resource failures were not counted as attack or defense outcomes.',
        '- cases.csv, rounds.csv, triggers.csv, costs.csv, clean-utility.csv, attacked-clean-utility.csv, paired-effects.csv, security-comparisons.csv, aggregate.csv and residuals.csv retain every planned case.']
    (staging / 'REPORT.md').write_text('\n'.join(lines) + '\n')
    shutil.copyfile(Path(__file__), staging / 'report_capped_final.py')
    checker = Path(__file__).with_name('check_capped_final_publication.py')
    shutil.copyfile(checker, staging / checker.name)
    import subprocess
    subprocess.run([sys.executable, str(checker), str(staging)], cwd=ROOT, check=True)
    files = {path.name: sha(path) for path in staging.iterdir() if path.is_file()}
    write(staging / 'publication-manifest.json', {'profile': 'capped-final-publication-sha256-v1',
        'files': files, 'protocol_sha256': PIN, 'training_closure_sha256': summary['training_closure_sha256'],
        'numerical_audit_sha256': summary['numerical_audit_sha256'], 'signature_claimed': False})
    assert staging.resolve().is_relative_to(ROOT / 'results') and not DEST.exists()
    staging.rename(DEST)
    print(json.dumps({'published': str(DEST), **summary}, indent=2))

def plot(folder, rounds, utility, comparisons):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    colors = dict(zip(METHODS, ('#277da1', '#f8961e', '#9b5de5', '#159a78'), strict=True))
    labels = {'tpm_only': 'TPM-only FedAvg', 'robust_bounded': 'Robust bounded', 'capped_sample': 'Capped sample', 'capped_robust': 'Capped robust'}
    for metric, filename, title in (('test_full_asr', 'full-trigger-trajectories', 'Full-trigger test ASR'),
            ('test_worst_trigger_asr', 'worst-trigger-trajectories', 'Worst full/component-trigger test ASR')):
        fig, axes = plt.subplots(2, 3, figsize=(13, 7), sharex=True, sharey=True, constrained_layout=True)
        for i, cohort in enumerate(('iid', 'non-iid')):
            for j, mode in enumerate(MODES):
                ax = axes[i, j]
                for method in METHODS:
                    xs, means, lows, highs = [], [], [], []
                    for number in range(1, 16):
                        values = [row[metric] * 100 for row in rounds if row['split'] == 'reserved' and row['cohort'] == cohort
                            and row['mode'] == mode and row['method'] == method and row['round'] == number]
                        if len(values) == 3:
                            xs.append(number); means.append(statistics.mean(values)); lows.append(min(values)); highs.append(max(values))
                    ax.plot(xs, means, label=labels[method], color=colors[method], linewidth=1.8)
                    ax.fill_between(xs, lows, highs, color=colors[method], alpha=.10)
                ax.axvline(10.5, color='#777777', linestyle=':', linewidth=1)
                ax.set_title(f'{cohort.upper()} / {mode}'); ax.set_ylim(-2, 102); ax.grid(alpha=.2)
                if i == 1: ax.set_xlabel('Round')
                if j == 0: ax.set_ylabel(title + ' (%)')
        handles, names = axes[0, 0].get_legend_handles_labels()
        fig.legend(handles, names, loc='outside upper center', ncol=4)
        for extension in ('png', 'pdf'): fig.savefig(folder / f'{filename}.{extension}', dpi=180)
        plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(12, 8), sharey=True, constrained_layout=True)
    assignments = sorted({(row['split'], row['cohort'], row['seed']) for row in utility})
    for ax, split in zip(axes, SPLITS, strict=True):
        for method in METHODS[1:]:
            for number, marker, offset in ((10, 'o', -.10), (15, '^', .10)):
                data = [row for row in utility if row['evaluation_split'] == split and row['method'] == method and row['round'] == number and row['defined']]
                ax.scatter([100 * row['macro_f1_loss_vs_tpm'] for row in data],
                    [assignments.index((row['split'], row['cohort'], row['seed'])) + offset for row in data],
                    color=colors[method], marker=marker, s=35, label=f'{labels[method]}, round {number}')
        ax.axvline(2, color='#c0392b', linestyle='--', label='2-point loss limit')
        ax.axvline(0, color='#777777', linewidth=.7); ax.grid(axis='x', alpha=.2)
        ax.set_title(split.capitalize()); ax.set_xlabel('Clean macro-F1 loss versus paired FedAvg (percentage points)')
    axes[0].set_yticks(range(len(assignments)), [f'{stage}: {cohort}, {seed}' for stage, cohort, seed in assignments])
    handles, names = axes[0].get_legend_handles_labels()
    fig.legend(handles, names, loc='outside upper center', ncol=2, fontsize=8)
    for extension in ('png', 'pdf'): fig.savefig(folder / f'clean-utility.{extension}', dpi=180)
    plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(11, 5), constrained_layout=True)
    mode_colors = dict(zip(MODES, ('#277da1', '#9b5de5', '#f8961e'), strict=True))
    points = [100 * row[key] for row in comparisons if row['defined'] for key in ('robust_bounded_harm', 'capped_robust_harm')]
    low, high = min(-5, min(points, default=0) - 5), max(5, max(points, default=0) + 5)
    for ax, split in zip(axes, SPLITS, strict=True):
        for cohort, marker in (('iid', 'o'), ('non-iid', 's')):
            for mode in MODES:
                selected = [row for row in comparisons if row['evaluation_split'] == split and row['cohort'] == cohort and row['mode'] == mode and row['defined']]
                ax.scatter([row['robust_bounded_harm'] * 100 for row in selected], [row['capped_robust_harm'] * 100 for row in selected],
                    color=mode_colors[mode], marker=marker, label=f'{cohort}, {mode}', s=45)
        ax.plot([low, high], [low, high], color='#777777', linestyle='--', linewidth=1)
        ax.set_xlim(low, high); ax.set_ylim(low, high); ax.set_aspect('equal', adjustable='box'); ax.grid(alpha=.2)
        ax.set_title(split.capitalize()); ax.set_xlabel('Robust bounded paired peak harm (points)')
        ax.set_ylabel('Capped robust paired peak harm (points)')
    handles, names = axes[0].get_legend_handles_labels()
    fig.legend(handles, names, loc='outside upper center', ncol=3, fontsize=8)
    for extension in ('png', 'pdf'): fig.savefig(folder / f'paired-security-comparison.{extension}', dpi=180)
    plt.close(fig)

if __name__ == '__main__':
    main()
