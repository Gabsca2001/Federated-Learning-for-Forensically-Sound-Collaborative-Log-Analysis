"""Independently cross-check published tables against retained replay receipts."""
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
import csv
import hashlib
import json
import math
import statistics
import sys

ROOT = Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
LAB = ROOT / 'artifacts/revision-capped-final-v1'
folder = Path(sys.argv[1])
assert folder.resolve().is_relative_to(ROOT / 'results')

def read(path):
    return json.loads(Path(path).read_text())

def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def rows(name):
    with (folder / name).open(newline='') as handle:
        return list(csv.DictReader(handle))

def number(value):
    return float(value) if value not in ('', None) else None

def boolean(value):
    assert value in ('True', 'False')
    return value == 'True'

def equal(actual, expected):
    if actual is None or expected is None:
        assert actual is expected, (actual, expected)
    else:
        assert math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-14), (actual, expected)

summary = read(folder / 'summary.json')
protocol = read(folder / 'protocol-before-training.json')
assert sha(folder / 'protocol-before-training.json') == summary['protocol_sha256'] == sha(LAB / 'protocol-before-training.json')
assert sha(LAB / 'training-complete.json') == summary['training_closure_sha256']
assert sha(LAB / 'verified/summary.json') == summary['numerical_audit_sha256']
assert sha(folder / 'publication-contract-before-test.json') == summary['publication_contract_sha256']
for relative, digest in protocol['source_locks'].items():
    assert sha(ROOT / relative) == digest
audit = read(LAB / 'verified/summary.json')
assert audit['status'] == 'verified' and audit['verifier_sha256'] == summary['verifier_sha256']
case_source = {case['task']['name']: case for case in audit['cases']}
assert len(case_source) == summary['planned_cases'] == 108
case_rows = rows('cases.csv')
assert len(case_rows) == len({row['name'] for row in case_rows}) == 108
case_table = {row['name']: row for row in case_rows}
assert set(case_table) == set(case_source)
round_table = rows('rounds.csv')
rounds = {(row['name'], int(row['round'])): row for row in round_table}
expected_rounds = {(name, row['round']) for name, case in case_source.items() for row in case['rows']}
assert len(rounds) == len(round_table) == len(expected_rounds)
assert set(rounds) == expected_rounds
lookup = {(case['task']['seed'], case['task']['method'], case['task']['mode']): name for name, case in case_source.items()}
for name, case in case_source.items():
    published = case_table[name]
    assert boolean(published['complete']) == case['complete']
    assert int(published['completed_rounds']) == len(case['rows'])
    assert published['source_manifest_sha256'] == case['source_manifest_sha256']
    for item in case['rows']:
        row = rounds[(name, item['round'])]
        beta = {client: Fraction(value) for client, value in item['coefficients'].items()}
        masses = {client: Fraction(value) for client, value in item['masses'].items()}
        share = sum(sorted(beta.values(), reverse=True)[:3])
        retention = sum(masses.values()) / sum(item['example_counts'].values())
        tv = sum(abs(beta[client] - masses[client] / sum(masses.values())) for client in masses) / 2
        assert Fraction(row['top_three_beta_fraction']) == share
        assert Fraction(row['retained_nominal_mass_fraction']) == retention
        assert Fraction(row['alpha_beta_tv_fraction']) == tv
        assert sum(beta.values()) == 1 and all(beta[client] == 0 for client in masses if masses[client] == 0)
        if case['task']['method'].startswith('capped_'):
            assert share <= Fraction(1, 3) and max(beta.values()) <= Fraction(1, 9)
            assert sum(value > 0 for value in beta.values()) >= 10 and retention >= Fraction(4, 5)
        equal(number(row['test_full_asr']), item['test']['complete_trigger']['asr'])
        equal(number(row['test_clean_macro_f1']), item['test']['clean']['macro_f1_all_model_classes'])
        equal(number(row['validation_clean_macro_f1']), item['validation_clean']['macro_f1_all_model_classes'])
        timing = item['timing']
        expected_cost = timing['aggregation_seconds'] if case['task']['method'] == 'tpm_only' else timing['final_operator_seconds']
        equal(number(row['cold_operator_seconds']), expected_cost)
    for split in ('validation', 'test'):
        observed = [row for row in round_table if row['name'] == name]
        peak = max(number(row[f'{split}_full_asr']) for row in observed) if case['complete'] else None
        equal(number(published[f'{split}_peak_full_asr']), peak)
        endpoint = rounds.get((name, 15))
        equal(number(published[f'{split}_final_full_asr']), number(endpoint[f'{split}_full_asr']) if endpoint else None)
triggers = rows('triggers.csv')
trigger_groups = defaultdict(list)
assert len(triggers) == 8 * len(rounds)
for row in triggers:
    count, denominator = int(row['target_predictions']), int(row['non_target_denominator'])
    assert 0 <= count <= denominator
    fraction = Fraction(count, denominator) if denominator else None
    equal(number(row['asr']), float(fraction) if fraction is not None else None)
    trigger_groups[(row['name'], int(row['round']), row['evaluation_split'])].append(fraction)
assert all(len(values) == 4 for values in trigger_groups.values())
for (name, round_number, split), values in trigger_groups.items():
    equal(number(rounds[(name, round_number)][f'{split}_worst_trigger_asr']), float(max(values)))
utility = rows('clean-utility.csv')
assert len(utility) == 108
for row in utility:
    seed, round_number = int(row['seed']), int(row['round'])
    name = lookup[(seed, row['method'], 'clean')]
    control = lookup[(seed, 'tpm_only', 'clean')]
    metric = row['evaluation_split'] + '_clean_macro_f1'
    a, c = rounds.get((name, round_number)), rounds.get((control, round_number))
    loss = number(c[metric]) - number(a[metric]) if a and c else None
    equal(number(row['macro_f1_loss_vs_tpm']), loss)
    assert boolean(row['qualified']) == bool(a and c and boolean(case_table[name]['complete']) and boolean(case_table[control]['complete']) and loss <= .02)
effects = rows('paired-effects.csv')
assert len(effects) == 144
effect_map = {}
for row in effects:
    seed, method, mode, split = int(row['seed']), row['method'], row['mode'], row['evaluation_split']
    name = lookup[(seed, method, mode)]; clean = lookup[(seed, method, 'clean')]
    pairs = []
    for round_number in range(1, 16):
        if (name, round_number) in rounds and (clean, round_number) in rounds:
            harm = max(trigger_groups[(name, round_number, split)]) - max(trigger_groups[(clean, round_number, split)])
            loss = number(rounds[(clean, round_number)][split + '_clean_macro_f1']) - number(rounds[(name, round_number)][split + '_clean_macro_f1'])
            pairs.append((harm, loss))
    peak = max((value for value, _ in pairs), default=None)
    assert (Fraction(row['peak_paired_harm_fraction']) if row['peak_paired_harm_fraction'] else None) == peak
    assert boolean(row['effective_control']) == any(harm >= Fraction(1, 5) and loss <= .05 for harm, loss in pairs)
    effect_map[(seed, method, mode, split)] = (peak, boolean(row['complete_histories']), boolean(row['effective_control']))
comparison_rows = rows('security-comparisons.csv')
assert len(comparison_rows) == 36
for row in comparison_rows:
    seed, mode, split = int(row['seed']), row['mode'], row['evaluation_split']
    p, pc, _ = effect_map[(seed, 'capped_robust', mode, split)]
    b, bc, _ = effect_map[(seed, 'robust_bounded', mode, split)]
    _, rc, effective = effect_map[(seed, 'tpm_only', mode, split)]
    defined = pc and bc
    assert boolean(row['defined']) == defined
    assert boolean(row['worse_than_robust']) == bool(defined and p > b)
    assert boolean(row['strict_benefit_in_effective_control']) == bool(defined and rc and effective and p < b)
    equal(number(row['capped_robust_harm']), float(p) if p is not None else None)
    equal(number(row['robust_bounded_harm']), float(b) if b is not None else None)
for split in ('validation', 'test'):
    data = [row for row in comparison_rows if row['evaluation_split'] == split]
    benefits = [row for row in data if boolean(row['strict_benefit_in_effective_control'])]
    guards = summary['guards'][split]
    assert guards['defined_comparisons'] == sum(boolean(row['defined']) for row in data)
    assert guards['worse_comparisons'] == sum(boolean(row['worse_than_robust']) for row in data)
    assert guards['strict_effective_control_benefits'] == len(benefits)
    assert guards['non_iid_effective_control_benefits'] == sum(row['cohort'] == 'non-iid' for row in benefits)
    assert guards['clean_utility_failures'] == sum(not boolean(row['qualified']) for row in utility if row['evaluation_split'] == split)
    for method, count in guards['clean_utility_failures_by_method'].items():
        assert count == sum(not boolean(row['qualified']) for row in utility if row['evaluation_split'] == split and row['method'] == method)
    assert guards['capped_robust_own_clean_utility_guard_pass'] == all(boolean(row['qualified']) for row in utility if row['evaluation_split'] == split and row['method'] == 'capped_robust')
    assert len(data) == 18
    assert guards['security_guard_pass'] == bool(all(boolean(row['defined']) and not boolean(row['worse_than_robust']) for row in data) and len(benefits) >= 2 and any(row['cohort'] == 'non-iid' for row in benefits))
    assert guards['clean_utility_guard_pass'] == all(boolean(row['qualified']) for row in utility if row['evaluation_split'] == split)
for row in rows('attacked-clean-utility.csv'):
    seed, round_number, split = int(row['seed']), int(row['round']), row['evaluation_split']
    name = lookup[(seed, row['method'], row['mode'])]; clean = lookup[(seed, row['method'], 'clean')]
    loss = number(rounds[(clean, round_number)][split + '_clean_macro_f1']) - number(rounds[(name, round_number)][split + '_clean_macro_f1'])
    equal(number(row['macro_f1_loss_under_attack']), loss)
for row in rows('aggregate.csv'):
    field = row['evaluation_split'] + '_' + row['metric']
    selected = [number(case[field]) for case in case_rows if case['split'] == row['stage'] and case['cohort'] == row['cohort'] and case['method'] == row['method'] and case['mode'] == row['mode'] and case[field] != '']
    assert int(row['defined_cases']) == len(selected)
    equal(number(row['mean']), statistics.mean(selected) if selected else None)
    equal(number(row['sample_sd']), statistics.stdev(selected) if len(selected) > 1 else None)
for row in rows('costs.csv'):
    source = [item for item in round_table if item['name'] == row['name']]
    equal(number(row['cold_operator_seconds_total']), sum(number(item['cold_operator_seconds']) for item in source))
    equal(number(row['cold_operator_seconds_mean']), statistics.mean(number(item['cold_operator_seconds']) for item in source) if source else None)
    equal(number(row['training_seconds_total']), sum(number(item['training_seconds']) for item in source))
assert sum(case['complete'] for case in audit['cases']) == summary['complete_cases']
expected_structural = all(case['complete'] for case in audit['cases'] if case['task']['mode'] == 'clean')
for case in audit['cases']:
    if case['task']['method'].startswith('capped_'):
        for row in case['rows']:
            beta = [Fraction(value) for value in row['coefficients'].values()]
            expected_structural &= sum(beta) == 1 and min(beta) >= 0 and sum(value > 0 for value in beta) >= 10 and sum(sorted(beta, reverse=True)[:3]) <= Fraction(1, 3) and Fraction(row['retained_nominal_mass']) >= Fraction(4, 5)
assert summary['structural_guard_pass'] == expected_structural
for key, value in summary['audit_totals'].items():
    assert value == sum(case['verification'][key] for case in audit['cases'])
assert not summary['default_policy_changed'] and summary['actual_admission_policy'] == 'tpm_only' and summary['fresh_TPM_quotes'] == 0
assert summary['combined_predeclared_guards_pass'] == bool(summary['structural_guard_pass'] and all(item['security_guard_pass'] and item['clean_utility_guard_pass'] for item in summary['guards'].values()))

# Independently rerun the new fixed-endpoint prediction-difference measurements.
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'src')]
from revision_dba_experiment import predict
from fl_forensics.federated_model import dependencies
deps = dependencies(); deps[1].set_num_threads(1); deps[1].use_deterministic_algorithms(True)
manifest = read(ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1/manifest.json')
entry = manifest['server_evaluation_splits']['test']
test_path = ROOT / 'artifacts/m3-data24-parquet-iid-local-test-v1' / entry['path']
assert sha(test_path) == entry['sha256'] == summary['test_split_sha256']
test = read(test_path)['rows']['test']
model_cache, prediction_cache = {}, {}
def get_model(name, round_number):
    key = (name, round_number)
    if key not in model_cache:
        model_cache[key] = read(LAB / 'cases' / name / 'evidence/rounds' / f'round-{round_number:03d}' / 'global-model.json')
    return model_cache[key]
def get_prediction(name, round_number):
    key = (name, round_number)
    if key not in prediction_cache:
        prediction_cache[key] = predict(get_model(name, round_number), test, deps)[0]
    return prediction_cache[key]
residuals = rows('residuals.csv')
assert len(residuals) == 144
for row in residuals:
    if not boolean(row['defined']):
        continue
    seed, round_number = int(row['seed']), int(row['round'])
    name = lookup[(seed, row['method'], row['mode'])]; clean = lookup[(seed, row['method'], 'clean')]
    a, c = get_model(name, round_number), get_model(clean, round_number)
    squared = 0.0
    for x, y in zip(a['parameters'], c['parameters'], strict=True):
        assert x['name'] == y['name'] and x['shape'] == y['shape']
        delta = deps[0].asarray(x['values'], dtype=float) - deps[0].asarray(y['values'], dtype=float)
        squared += float(deps[0].sum(delta * delta))
    equal(number(row['parameter_l2']), math.sqrt(squared))
    assert boolean(row['identical_parameter_payload']) == (a == c)
    differences = sum(x != y for x, y in zip(get_prediction(name, round_number), get_prediction(clean, round_number), strict=True))
    assert int(row['untriggered_prediction_mismatches']) == differences
    assert int(row['untriggered_examples']) == len(test)
    equal(number(row['untriggered_prediction_disagreement']), differences / len(test))
for name in ('full-trigger-trajectories', 'worst-trigger-trajectories', 'clean-utility', 'paired-security-comparison'):
    for extension in ('png', 'pdf'):
        assert (folder / f'{name}.{extension}').stat().st_size > 1000
receipt = {'status': 'verified_publication_against_numerical_audit', 'cases': len(case_rows),
    'rounds': len(rounds), 'trigger_rows': len(triggers), 'utility_checks': len(utility),
    'security_comparisons': len(comparison_rows), 'residual_checks': len(residuals),
    'protocol_sha256': summary['protocol_sha256'], 'numerical_audit_sha256': summary['numerical_audit_sha256'],
    'fresh_process_residual_predictions_recomputed': True, 'source_locks_verified': True}
receipt_path = folder / 'publication-verification.json'
if receipt_path.exists():
    assert read(receipt_path) == receipt, 'Do not overwrite a different retained receipt'
else:
    with receipt_path.open('x') as handle:
        handle.write(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
