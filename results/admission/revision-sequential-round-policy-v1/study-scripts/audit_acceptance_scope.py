"""Apply the conservative full-scope reading of the frozen acceptance rule.

The first evaluator restricted its false-quarantine check to actual active
actions. The frozen wording did not restrict that condition to active branches.
Keep that result, but count shadow proposals too in the authoritative audit.
No model, action, training run, threshold or primary measurement is changed.
"""
from pathlib import Path
import copy
import json
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-sequential-round-policy-v1'
original=json.loads((lab/'post-study-evaluation.json').read_bytes());cases=original['cases']
active=[c for c in cases if c['task']['branch']=='active-sequential']
attacked=[c for c in cases if c['task']['mode']=='distributed']
strict={'zero_never_attacker_quarantines':all(c['metrics'].get('sequential_never_attacker_quarantines',0)==0 for c in cases),
    'at_least_one_poisoned_update_quarantined_per_attacked_episode':all(c['metrics'].get('sequential_poisoned_update_quarantines',0)>0 for c in attacked),
    'no_active_quorum_failure':all(c['finished_rounds']==15 and c['metrics'].get('quorum_failures',0)==0 for c in active)}
audit={'profile':'conservative-frozen-acceptance-scope-audit-v1',
    'original_evaluation_sha256':sha256_file(lab/'post-study-evaluation.json'),
    'protocol_sha256':sha256_file(lab/'protocol-before-new-training.json'),
    'original_active_only_operational_checks':original['predeclared_experimental_acceptance'],
    'authoritative_predeclared_experimental_acceptance':strict,'all_pilot_criteria_pass':all(strict.values()),
    'scope_correction':'The original evaluator restricted the zero-false-quarantine check to active branches. The frozen criterion did not explicitly restrict it. Count all shadow proposals conservatively; preserve the active-only measurements separately.',
    'shadow_never_attacker_quarantine_proposals':sum(c['metrics'].get('sequential_never_attacker_quarantines',0) for c in cases if c['task']['branch']=='shadow-FedAvg'),
    'active_never_attacker_actual_quarantines':sum(c['metrics'].get('sequential_never_attacker_quarantines',0) for c in active),
    'thresholds_or_decisions_changed':False}
save(lab/'acceptance-scope-audit.json',audit)
revised=copy.deepcopy(original);revised['profile']='reserved-online-policy-evaluation-v2'
revised['active_branch_operational_checks']=original['predeclared_experimental_acceptance']
revised['predeclared_experimental_acceptance']=strict;revised['all_pilot_criteria_pass']=all(strict.values())
revised['acceptance_scope_audit_sha256']=sha256_file(lab/'acceptance-scope-audit.json')
revised['superseded_evaluation_sha256']=sha256_file(lab/'post-study-evaluation.json')
revised['acceptance_scope_qualification']=audit['scope_correction']
save(lab/'post-study-evaluation-v2.json',revised)
(out/'online-evaluation.json').write_bytes((lab/'post-study-evaluation-v2.json').read_bytes())
(out/'acceptance-scope-audit.json').write_bytes((lab/'acceptance-scope-audit.json').read_bytes())
print(json.dumps(audit,sort_keys=True))
