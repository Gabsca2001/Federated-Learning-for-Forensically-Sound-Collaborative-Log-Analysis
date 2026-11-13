"""Freeze current-evidence study and reuse unchanged clean score thresholds."""
from pathlib import Path
import json
import shutil
from revision_dba_experiment import save
from fl_forensics.canonical import sha256_file

repo=Path.cwd();out=Path(__file__).parent;prior=out.parent/'sequential-policy-20261103'
lab=repo/'artifacts/revision-current-evidence-policy-v1';assert not lab.exists();lab.mkdir()
previous='3b2fff3ad94aea6a4c6dd723115a7598e886d5078176d8afc059dea5df371057'
assert sha256_file(prior/'completion-closure.json')==previous
closure=json.loads((prior/'completion-closure.json').read_bytes())
for name,value in closure['core']['artifacts'].items():assert sha256_file(prior/name)==value
old=repo/'artifacts/revision-sequential-round-policy-v1'
for name in ('policy_data.py','worker_link.py','policy_worker.py','run_online_study.py'):
    text=(prior/name).read_text()
    if name=='worker_link.py':text=text.replace('revision-sequential-{role}','revision-current-evidence-{role}')
    if name=='policy_worker.py':
        text=text.replace('from fl_forensics.sequential_decision import SequentialRoundPolicy','from fl_forensics.current_evidence_policy import CurrentEvidencePolicy')
        text=text.replace('SequentialRoundPolicy(calibration,','CurrentEvidencePolicy(calibration,')
    if name=='run_online_study.py':
        text=text.replace('revision-sequential-round-policy-v1','revision-current-evidence-policy-v1')
        text=text.replace('src/fl_forensics/sequential_decision.py','src/fl_forensics/current_evidence_policy.py')
        text=text.replace('active-sequential','active-current-evidence').replace('random.Random(20261103)','random.Random(202611031)')
    (out/name).write_text(text)
code=lab/'worker-code/fl_forensics';code.mkdir(parents=True)
(code/'__init__.py').write_text('"""Isolated observable-only current-evidence decision worker."""\n')
for name in ('state_conditioned_audit.py','sequential_decision.py','current_evidence_policy.py'):
    shutil.copy(repo/'src/fl_forensics'/name,code/name)
shutil.copy(out/'policy_worker.py',lab/'worker-code/policy_worker.py')
shutil.copytree(old/'policy-calibration',lab/'policy-calibration');(lab/'inbox').mkdir()
assignments=[['client03','client06','client11'],['client04','client07','client13'],['client02','client10','client14']]
protocol={'profile':'confirmed-current-evidence-study-v1','previous_completion_sha256':previous,
    'source_policy_sha256':sha256_file(repo/'src/fl_forensics/current_evidence_policy.py'),
    'unchanged_evidence_module_sha256':sha256_file(repo/'src/fl_forensics/sequential_decision.py'),
    'worker_sha256':sha256_file(out/'policy_worker.py'),'controller_sha256':sha256_file(out/'run_online_study.py'),
    'generator_sha256':sha256_file(out/'policy_data.py'),
    'model_closure_sha256':sha256_file(repo/'artifacts/revision-state-conditioned-heldout-v1/models/model-closure.json'),
    'unchanged_policy_calibration_closure_sha256':sha256_file(lab/'policy-calibration/closure.json'),
    'decision':'Entry requires two consecutive supported rounds where both current standardized view risks strictly exceed their original instantaneous clean-calibrated limits. Continue only while the same dual current-high condition holds. Release immediately otherwise, retain history for review, reset entry confirmation on every gap. Cumulative evidence never authorizes quarantine.',
    'threshold_change':False,'horizon':15,'modes':['clean','distributed'],
    'branches':['shadow-FedAvg','active-current-evidence'],
    'reserved_evaluation':{'iid':list(zip((481593,482593,483593),assignments)),
        'non-iid':list(zip((491593,492593,493593),assignments))},
    'attack_schedules':[list(range(1,8)),list(range(4,11)),[3,4,5,9,10,11]],
    'experimental_acceptance':{
        'zero_never_attacker_quarantine_proposals':'Across ALL shadow and active episodes; count client-round proposals even when not applied.',
        'zero_after_cessation_clean_source_proposals':'Across ALL episodes after final scheduled attack round. Also report clean gaps between bursts separately.',
        'at_least_one_poisoned_update_proposed_per_attacked_episode':'Across all 12 attacked shadow/active episodes; weak screening criterion, not full recovery or complete identification.',
        'no_active_quorum_failure':'All active episodes finish with the fixed minimum of 8 positive contributors.'},
    'comparators':'Original instantaneous and cumulative-sequential proposals on the exact same observed prefixes; neither has a separate active trajectory in this study.',
    'development_scope':'The previous 24 episodes are development data. Their risks may diagnose/design the new rule, but do not validate it. Freeze this protocol before new reserved training; no tuning on new outcomes.',
    'raw_data_boundary':'Only simulator/evaluator access original rows and attack plans. Docker worker sees code, frozen observable models/thresholds and current-request inbox; no raw client rows, labels, branch names or future files.',
    'all_clients_resubmit_each_round':True,'semantic_malice_proved':False,'automatic_live_deployment':False,'fresh_TPM_attestation':False}
save(lab/'protocol-before-new-training.json',protocol)
save(lab/'calibration-frozen-before-evaluation.json',{'policy_closure_sha256':sha256_file(lab/'policy-calibration/closure.json'),
    'protocol_sha256':sha256_file(lab/'protocol-before-new-training.json'),'reused_thresholds_unchanged':True})
print('CURRENT-EVIDENCE PROTOCOL FROZEN',sha256_file(lab/'protocol-before-new-training.json'))
