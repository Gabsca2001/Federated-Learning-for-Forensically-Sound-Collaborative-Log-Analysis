"""Diagnose the new rule on explicitly reused development trajectories."""
from collections import defaultdict
from pathlib import Path
import json
from fl_forensics.current_evidence_policy import CurrentEvidencePolicy
from fl_forensics.canonical import sha256_file
from revision_dba_experiment import save

repo=Path.cwd();out=Path(__file__).parent;old=repo/'artifacts/revision-sequential-round-policy-v1'
lab=repo/'artifacts/revision-current-evidence-policy-v1'
tasks=json.loads((old/'reserved-execution-before-training.json').read_bytes())['tasks'];rows=[];totals=defaultdict(int)
for task in tasks:
    cal=json.loads((lab/'policy-calibration'/f'{task["cohort"]}.json').read_bytes());p=CurrentEvidencePolicy(cal)
    metrics=defaultdict(int);intended=set(task['attackers']) if task['mode']=='distributed' else set()
    for number in range(1,16):
        prefix=old/'private-episodes'/task['stream']/'rounds'/f'round-{number:03d}'
        request=json.loads((prefix/'worker-request.json').read_bytes());response=json.loads((prefix/'worker-response.json').read_bytes())
        d=p.step(number,{v:r[0] for v,r in response['scored']['risk'].items()},context_supported=response['decision']['supported'],
            mandatory_gate=request['mandatory_gate'],masses=request['masses'],expected_previous_digest=p.head,
            source_observation_sha256=request['observation_sha256'])
        selected=set(d['quarantine_current_round']);active=intended if number in task['attack_rounds'] else set()
        metrics['poisoned_proposals']+=len(selected&active);metrics['never_attacker_proposals']+=len(selected-intended)
        if number>max(task['attack_rounds']):metrics['after_cessation_proposals']+=len(selected&intended)
        metrics['review_client_rounds']+=len(d['review_required'])
    rows.append({'task':task,'metrics':dict(metrics)})
    for k,v in metrics.items():totals[k]+=v
save(lab/'development-replay.json',{'profile':'reused-development-prefix-replay-v1','rows':rows,'totals':dict(totals),
    'source_previous_completion_sha256':sha256_file(out.parent/'sequential-policy-20261103/completion-closure.json'),
    'qualification':'Same old observations, not new active trajectories, not held-out validation. No threshold revision or candidate selection based on the reserved study.'})
(out/'development-replay.json').write_bytes((lab/'development-replay.json').read_bytes())
print(json.dumps(dict(totals)))
