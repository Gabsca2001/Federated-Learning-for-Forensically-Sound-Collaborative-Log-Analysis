"""Seal the new current-evidence policy evidence without rewriting history."""
from pathlib import Path
import json
import shutil
import zipfile
import xml.etree.ElementTree as ET

from fl_forensics.canonical import sha256_file,digest_object
from fl_forensics.crypto import SoftwareECDSASigner,load_public_key,verify_digest_signature
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.storage import write_once

repo=Path.cwd();project=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1')
out=project/'output/current-evidence-policy-20261103';previous=project/'output/sequential-policy-20261103'
lab=repo/'artifacts/revision-current-evidence-policy-v1'
def read(p):return json.loads(p.read_bytes())
assert sha256_file(previous/'completion-closure.json')=='3b2fff3ad94aea6a4c6dd723115a7598e886d5078176d8afc059dea5df371057'
for name,value in read(previous/'completion-closure.json')['core']['artifacts'].items():assert sha256_file(previous/name)==value
before=read(project/'output/formal-review-20261103/before-context.json')
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/n)==v for n,v in before['thesis_sources'].items())
with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as archive:
    old_sources={n:archive.read(n) for n in archive.namelist() if n.startswith('src/fl_forensics/') and n.endswith('.py')}
for name,value in old_sources.items():assert (repo/name).read_bytes()==value,name
current={p.relative_to(repo).as_posix() for p in (repo/'src/fl_forensics').glob('*.py')}
assert current-set(old_sources)=={'src/fl_forensics/current_evidence_policy.py'}
protocol=read(lab/'protocol-before-new-training.json')
assert sha256_file(repo/'src/fl_forensics/current_evidence_policy.py')==protocol['source_policy_sha256']
assert sha256_file(repo/'src/fl_forensics/sequential_decision.py')==protocol['unchanged_evidence_module_sha256']
assert sha256_file(lab/'policy-calibration/closure.json')==protocol['unchanged_policy_calibration_closure_sha256']
for name,digest in read(lab/'policy-calibration/closure.json')['files'].items():assert sha256_file(lab/'policy-calibration'/name)==digest
assert sha256_file(out/'policy_worker.py')==protocol['worker_sha256']
assert sha256_file(out/'policy_data.py')==protocol['generator_sha256']
assert sha256_file(out/'run_online_study.py')==protocol['controller_sha256']==read(lab/'reserved-execution-before-training.json')['controller_sha256']
for name in ('state_conditioned_audit.py','sequential_decision.py','current_evidence_policy.py'):
    assert (repo/'src/fl_forensics'/name).read_bytes()==(lab/'worker-code/fl_forensics'/name).read_bytes()
assert (repo/'src/fl_forensics/current_evidence_policy.py').read_bytes()==(out/'current_evidence_policy.py').read_bytes()
assert (repo/'tests/test_current_evidence_policy.py').read_bytes()==(out/'test_current_evidence_policy.py').read_bytes()
suite=ET.parse(out/'full-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='604' and all(suite.attrib[k]=='0' for k in ('errors','failures','skipped'))
evaluation=read(lab/'post-study-evaluation.json')
assert set(evaluation['predeclared_experimental_acceptance'])==set(protocol['experimental_acceptance'])
assert len(evaluation['cases'])==24 and evaluation['verified_source_updates']==5400 and evaluation['independently_reconstructed_aggregates']==360
for episode,digest in read(lab/'reserved-generation-complete.json')['episode_manifests'].items():
    assert sha256_file(lab/'private-episodes'/episode/'manifest.json')==digest
assert read(lab/'engine-shutdown.json')['owned_engine_stopped']
binding={'profile':'current-evidence-policy-study-artifact-closure-v1',
    'files':{p.relative_to(lab).as_posix():sha256_file(p) for p in lab.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='study-artifact-closure.json'}}
write_once(lab/'study-artifact-closure.json',derived_json_bytes(binding));write_once(out/'study-artifact-closure.json',derived_json_bytes(binding))
for name in ('protocol-before-new-training.json','calibration-frozen-before-evaluation.json','reserved-execution-before-training.json','online-worker-runtime.json','engine-shutdown.json'):
    shutil.copy(lab/name,out/name)
shutil.copy(lab/'policy-calibration/closure.json',out/'unchanged-policy-calibration-closure.json')
checks={'status':'verified','current_implementation_sha256':implementation_sha256(),'unchanged_prior_package_files':len(old_sources),
    'added_package_file_sha256':sha256_file(repo/'src/fl_forensics/current_evidence_policy.py'),
    'tests':{k:suite.attrib[k] for k in ('tests','errors','failures','skipped','time')},
    'source_updates_verified':5400,'prefix_decisions_verified':360,'aggregates_reconstructed':360,
    'new_calibration_training_calls':0,'total_new_local_training_calls':5400,'new_autoregressive_rounds':360,
    'thesis_sources_unchanged':len(before['thesis_sources']),'git_index_unchanged':True,'prior_signed_completion_preserved':True,
    'artifact_root':str(lab),'artifact_closure_sha256':sha256_file(lab/'study-artifact-closure.json'),
    'qualifications':{'pilot_acceptance':evaluation['predeclared_experimental_acceptance'],'all_pilot_criteria_pass':evaluation['all_pilot_criteria_pass'],
        'current_evidence_required_for_all_quarantines':True,'cumulative_history_can_authorize_quarantine':False,
        'raw_rows_or_attack_labels_accessible_to_worker':False,'future_observations_accessible_to_worker':False,
        'automatic_live_deployment_validated':False,'semantic_malice_or_collusion_proved':False,
        'permanent_bans_implemented':False,'fresh_TPM_attestation_performed':False,'final_test_set_used':False,
        'historical_poisoning_automatically_repaired':False,'thresholds_changed':False,'reserved_outcomes_used_for_tuning':False}}
(out/'integrity-and-qualification.json').write_text(json.dumps(checks,indent=2,sort_keys=True)+'\n')
with zipfile.ZipFile(out/'source-and-study-scripts.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for p in sorted((repo/'src/fl_forensics').glob('*.py')):archive.write(p,p.relative_to(repo).as_posix())
    for p in sorted(out.glob('*.py')):archive.write(p,'study-scripts/'+p.name)
    with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as older:
        for name in ('study_data.py','revision_dba_experiment.py'):
            archive.writestr('study-scripts/'+name,older.read('study-scripts/'+name))
    archive.write(repo/'tests/test_current_evidence_policy.py','tests/test_current_evidence_policy.py')
with zipfile.ZipFile(out/'source-and-study-scripts.zip') as archive:assert archive.testzip() is None
result=repo/'results/revision-current-evidence-policy-v1';result.mkdir(exist_ok=False)
shutil.copy(out/'CURRENT_EVIDENCE_POLICY.md',result/'README.md')
for p in out.iterdir():
    if p.is_file() and p.suffix in ('.json','.xml','.png','.pdf'):shutil.copy(p,result/p.name)
scripts=result/'study-scripts';scripts.mkdir()
for p in out.glob('*.py'):shutil.copy(p,scripts/p.name)
status=repo/'docs/STATUS.md'
note='''> Current-evidence quarantine follow-up, 2026-11-03: entry now requires two
> consecutive supported dual-view high observations; continuation requires current
> high evidence, and statistical release is immediate when that evidence ceases.
> Cumulative evidence is review-only. Models and thresholds are unchanged. New
> reserved cases include cessation and interrupted attacks. All 604 tests pass.
> The module remains experimental; no live deployment or semantic-malice claim.
> See [complete frozen results and limitations](../results/revision-current-evidence-policy-v1/README.md).

'''
status.write_text(note+status.read_text())
for name in ('SUPERVISOR_REQUIREMENTS_AUDIT.md','FORMAL_MODEL_THEOREMS.md'):
    p=repo/'docs'/name;p.write_text(p.read_text()+'''

## Current-evidence confirmation and statistical release (2026-11-03)

The added `current_evidence_policy` module keeps the previous evidence engine
unchanged and separates its cumulative review evidence from quarantine authority.
For supported gate-compatible current high evidence H, the action is
Q(i,t) = H(i,t) AND H(i,t-1). Hence quarantine is a subset of current high
candidates; a stale cumulative score cannot authorize or prolong it. Failure of
current high evidence releases statistical quarantine immediately. Release does
not override mandatory rejection, prove benign intent or erase prior provenance.
New entry after a gap requires new confirmation. Fixed-calibration deterministic
prefix invariance, strict round order, trusted predecessor and exact-observation
bindings are preserved. Classification accuracy is an empirical question.

The new fixed-protocol study includes changed attackers, short attacks, cessation
and a clean gap between bursts, with shadow proposals counted as well as actual
active actions. The thresholds remain unchanged. All 604 tests pass. This remains
an experimental adapter: no fresh TPM attestation, live admission integration,
permanent ban or automatic repair of earlier checkpoints is claimed. See
[the complete reserved evaluation](../results/revision-current-evidence-policy-v1/README.md).
''')
authority=repo/'artifacts/revision-current-evidence-completion-v1';signer=SoftwareECDSASigner.generate()
write_once(authority/'analyst.private.pem',signer.private_pem());write_once(out/'analyst.public.pem',signer.public_pem())
core={'profile':'current-evidence-policy-analyst-completion-v1','date':'2026-11-03',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),
    'current_implementation_sha256':checks['current_implementation_sha256'],'qualifications':checks['qualifications'],
    'artifact_roots':{str(lab):checks['artifact_closure_sha256']},
    'artifacts':{p.name:sha256_file(p) for p in out.iterdir() if p.is_file() and p.name not in ('completion-closure.json','completion-closure.sha256')},
    'authority_role':'Local software analyst, not an independent receipt witness or TPM client'}
digest=digest_object(core);signed={'core':core,'core_digest':digest,
    'signature':{'key_id':signer.key_id,'value_b64':signer.sign_digest(digest),'trust_level':'software-development'}}
write_once(out/'completion-closure.json',derived_json_bytes(signed))
assert verify_digest_signature(load_public_key(signer.public_pem()),digest,signed['signature']['value_b64'])
for name,value in core['artifacts'].items():assert sha256_file(out/name)==value
(out/'completion-closure.sha256').write_text(sha256_file(out/'completion-closure.json')+'\n')
for name in ('completion-closure.json','completion-closure.sha256','analyst.public.pem'):shutil.copy(out/name,result/name)
print(json.dumps(checks,sort_keys=True));print('SIGNED COMPLETION',sha256_file(out/'completion-closure.json'))
