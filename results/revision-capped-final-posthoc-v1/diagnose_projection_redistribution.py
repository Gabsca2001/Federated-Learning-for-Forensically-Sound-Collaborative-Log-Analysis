"""Post-hoc coefficient diagnostic; no new training, test inference or retuning."""
from fractions import Fraction
from pathlib import Path
import csv
import hashlib
import json

ROOT = Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
LAB = ROOT / 'artifacts/revision-capped-final-v1'
PUB = ROOT / 'results/revision-capped-final-v1'
OUT = Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1/output/capped-final-20261106')
DEST = PUB.parent / 'revision-capped-final-posthoc-v1'
assert not DEST.exists()
DEST.mkdir()
protocol = json.loads((LAB / 'protocol-before-training.json').read_text())
items = []
for task in protocol['tasks']:
    if task['method'] != 'capped_robust' or task['mode'] == 'clean':
        continue
    for number in range(1, 16):
        folder = LAB / 'cases' / task['name'] / 'evidence/rounds' / f'round-{number:03d}'
        state_path = folder / 'gate-state.json'
        state = json.loads(state_path.read_text())
        row = json.loads((folder / 'round.json').read_text())
        report = state['selected_aggregation_derivation']
        p = {client: Fraction(value) for client, value in report['projection']['normalized_proposal'].items()}
        beta = {client: Fraction(value) for client, value in report['beta'].items()}
        before = sum(p[client] for client in task['attackers'])
        after = sum(beta[client] for client in task['attackers'])
        largest = max(sorted(p), key=p.get)
        assert sum(p.values()) == sum(beta.values()) == 1 and after <= Fraction(1, 3)
        items.append({key: task[key] for key in ('name', 'cohort', 'seed', 'mode')} | {
            'round': number, 'attack_window': number <= 10,
            'actually_manipulated_updates': len(row['actually_manipulated_clients']),
            'proposal_attacker_identity_share_fraction': str(before),
            'final_attacker_identity_share_fraction': str(after),
            'proposal_attacker_identity_share': float(before), 'final_attacker_identity_share': float(after),
            'share_increase_fraction': str(after - before), 'share_increase': float(after - before),
            'largest_proposal_identity': largest, 'largest_proposal_identity_is_declared_attacker': largest in task['attackers'],
            'source_gate_state_sha256': hashlib.sha256(state_path.read_bytes()).hexdigest()})
active = [row for row in items if row['attack_window'] and row['actually_manipulated_updates'] > 0]
increased = [row for row in active if Fraction(row['share_increase_fraction']) > 0]
record = {'profile': 'posthoc-capped-coefficient-redistribution-v1',
    'selection': 'All eighteen reserved attacked capped_robust histories, all15 rounds; post-hoc diagnostic after the complete frozen evaluation',
    'rows': len(items), 'actually_manipulated_active_rounds': len(active),
    'active_rounds_with_increased_attacker_identity_coefficient_share': len(increased),
    'largest_increase_example': max(increased, key=lambda row: Fraction(row['share_increase_fraction'])) if increased else None,
    'interpretation': 'Upper-capping a large robust coefficient redistributes positive weight to unsaturated clients. This can increase the coefficient share of admitted attacker identities despite the one-third group ceiling. It does not resurrect a zero proposal or a quarantined mass.',
    'scope': 'Shares apply to clipped updates on each recorded capped-history input. This is not an ASR counterfactual, not a retrained uncapped history, not an attribution of every outcome, and not a fitted threshold.',
    'new_training_or_test_inference': False, 'primary_protocol_or_published_results_changed': False}
with (DEST / 'coefficient-redistribution.csv').open('w', newline='') as handle:
    writer = csv.DictWriter(handle, fieldnames=list(items[0]))
    writer.writeheader(); writer.writerows(items)
(DEST / 'diagnosis.json').write_text(json.dumps(record, indent=2) + '\n')
(OUT / 'projection-diagnosis.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
