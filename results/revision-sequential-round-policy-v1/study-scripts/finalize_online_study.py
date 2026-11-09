"""Seal experimental evidence while preserving previous releases and the thesis."""
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
out=project/'output/sequential-policy-20261103';previous=project/'output/state-conditioned-detector-20261103'
lab=repo/'artifacts/revision-sequential-round-policy-v1'
def read(p):return json.loads(p.read_bytes())
assert sha256_file(previous/'completion-closure.json')=='12cc602c1bfa5fa8cf52e866def2df4f0cdf52c5123cdf68b002b407bb6f50f1'
for name,value in read(previous/'completion-closure.json')['core']['artifacts'].items():assert sha256_file(previous/name)==value
before=read(project/'output/formal-review-20261103/before-context.json')
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/n)==v for n,v in before['thesis_sources'].items())
with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as archive:
    old_sources={n:archive.read(n) for n in archive.namelist() if n.startswith('src/fl_forensics/') and n.endswith('.py')}
for name,value in old_sources.items():assert (repo/name).read_bytes()==value,name
current={p.relative_to(repo).as_posix() for p in (repo/'src/fl_forensics').glob('*.py')}
assert current-set(old_sources)=={'src/fl_forensics/sequential_decision.py'}
protocol=read(lab/'protocol-before-new-training.json')
assert sha256_file(repo/'src/fl_forensics/sequential_decision.py')==protocol['source_policy_sha256']
assert sha256_file(out/'policy_worker.py')==protocol['worker_sha256']
assert sha256_file(out/'policy_data.py')==protocol['generator_sha256']
assert sha256_file(out/'run_online_study.py')==read(lab/'reserved-execution-before-training.json')['controller_sha256']
assert (repo/'src/fl_forensics/sequential_decision.py').read_bytes()==(out/'sequential_decision.py').read_bytes()
assert (repo/'tests/test_sequential_decision.py').read_bytes()==(out/'test_sequential_decision.py').read_bytes()
suite=ET.parse(out/'full-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='590' and all(suite.attrib[k]=='0' for k in ('errors','failures','skipped'))
evaluation=read(lab/'post-study-evaluation-v2.json')
assert evaluation['acceptance_scope_audit_sha256']==sha256_file(lab/'acceptance-scope-audit.json')
assert len(evaluation['cases'])==24 and evaluation['verified_source_updates']==5400 and evaluation['independently_reconstructed_aggregates']==360
for episode,digest in read(lab/'reserved-generation-complete.json')['episode_manifests'].items():
    assert sha256_file(lab/'private-episodes'/episode/'manifest.json')==digest
for cohort,seeds in protocol['new_clean_calibration'].items():
    for seed in seeds:
        episode=lab/'private-calibration'/cohort/f'cal-{seed}'
        assert len(list((episode/'rounds').glob('round-*/round.json')))==15
        from revision_dba_experiment import authenticate
        authenticate(episode,sha256_file(episode/'manifest.json'))
binding={'profile':'sequential-policy-study-artifact-closure-v1',
    'files':{p.relative_to(lab).as_posix():sha256_file(p) for p in lab.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='study-artifact-closure.json'}}
write_once(lab/'study-artifact-closure.json',derived_json_bytes(binding))
write_once(out/'study-artifact-closure.json',derived_json_bytes(binding))
for relative in ('protocol-before-new-training.json','calibration-frozen-before-evaluation.json','reserved-execution-before-training.json',
    'online-worker-runtime.json','calibration-worker-runtime.json','cutoff-runtime-inspection.json'):
    shutil.copy(lab/relative,out/relative)
shutil.copy(lab/'policy-calibration/closure.json',out/'policy-calibration-closure.json')
checks={'status':'verified','current_implementation_sha256':implementation_sha256(),'unchanged_prior_package_files':len(old_sources),
    'added_package_file_sha256':sha256_file(repo/'src/fl_forensics/sequential_decision.py'),
    'tests':{k:suite.attrib[k] for k in ('tests','errors','failures','skipped','time')},
    'source_updates_verified':5400,'prefix_decisions_verified':360,'aggregates_reconstructed':360,
    'new_clean_calibration_local_training_calls':1350,'new_reserved_evaluation_local_training_calls':5400,
    'total_new_local_training_calls':6750,'new_autoregressive_rounds':450,
    'thesis_sources_unchanged':len(before['thesis_sources']),'git_index_unchanged':True,'prior_signed_completion_preserved':True,
    'artifact_root':str(lab),'artifact_closure_sha256':sha256_file(lab/'study-artifact-closure.json'),
    'qualifications':{'pilot_acceptance':evaluation['predeclared_experimental_acceptance'],'all_pilot_criteria_pass':evaluation['all_pilot_criteria_pass'],
        'raw_rows_or_attack_labels_accessible_to_worker':False,'future_observations_accessible_to_worker':False,
        'automatic_live_deployment_validated':False,'semantic_malice_or_collusion_proved':False,
        'permanent_bans_implemented':False,'fresh_TPM_attestation_performed':False,'final_test_set_used':False,
        'historical_poisoning_automatically_repaired':False,'thresholds_retuned_on_reserved_cases':False}}
(out/'integrity-and-qualification.json').write_text(json.dumps(checks,indent=2,sort_keys=True)+'\n')
with zipfile.ZipFile(out/'source-and-study-scripts.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for p in sorted((repo/'src/fl_forensics').glob('*.py')):archive.write(p,p.relative_to(repo).as_posix())
    for p in sorted(out.glob('*.py')):archive.write(p,'study-scripts/'+p.name)
    archive.write(previous/'study_data.py','study-scripts/study_data.py')
    archive.write(repo/'scripts/revision_dba_experiment.py','study-scripts/revision_dba_experiment.py')
    archive.write(repo/'tests/test_sequential_decision.py','tests/test_sequential_decision.py')
with zipfile.ZipFile(out/'source-and-study-scripts.zip') as archive:assert archive.testzip() is None
result=repo/'results/revision-sequential-round-policy-v1';result.mkdir(exist_ok=False)
shutil.copy(out/'SEQUENTIAL_ROUND_POLICY.md',result/'README.md')
for p in out.iterdir():
    if p.is_file() and p.suffix in ('.json','.xml','.png','.pdf'):shutil.copy(p,result/p.name)
scripts=result/'study-scripts';scripts.mkdir()
for p in out.glob('*.py'):shutil.copy(p,scripts/p.name)
note='''> Sequential current-round policy study, 2026-11-03: a new isolated worker
> retains single-view review items and accumulates only past/current evidence.
> Temporary quarantines are evaluated on 24 reserved 15-round episodes with frozen
> clean-only thresholds, shifted attack onset/cessation and active/shadow branches.
> All 590 tests pass. Statistical actions do not establish malicious intent, repair
> earlier checkpoints or qualify the policy for live deployment. See
> [the complete frozen results](../results/revision-sequential-round-policy-v1/README.md).

'''
status=repo/'docs/STATUS.md';status.write_text(note+status.read_text())
for name in ('SUPERVISOR_REQUIREMENTS_AUDIT.md','FORMAL_MODEL_THEOREMS.md'):
    p=repo/'docs'/name;p.write_text(p.read_text()+'''

## Prefix-only, round-scoped policy follow-up (2026-11-03)

The experimental `sequential_decision` module separates review from temporary
quarantine. Both score views remain visible. Cumulative evidence uses a fixed
clean-calibrated recurrence and strict round/predecessor bindings. For fixed
calibration and an identical observation/gate/mass prefix, induction on the
deterministic recurrence gives identical prefix decisions regardless of future
inputs. This is a causal-input property, not a theorem about classification
accuracy. The two views are correlated and do not provide independent votes.

Mandatory rejection always gives zero effective mass. Statistical evidence cannot
override it. A changed eligible population invalidates the fixed-cohort detector
and causes review/abstention. Quorum failure never re-admits excluded updates.
Current-round quarantine is neither a permanent ban nor a semantic malice label.
Hash chaining assumes a trusted expected predecessor; the local analyst closure
is not an independent witness, a trusted timestamp or a fresh TPM attestation.
The experimental worker is not wired into live admission and does not validate
invalid-payload handling by the production path.

The 24 reserved episodes, action costs, latency, coverage, ASR trajectories and
clean utility are reported in [the frozen online study](../results/revision-sequential-round-policy-v1/README.md).
It does not replace the approved retrospective candidate-group scope or historical
replay. No automatic repair of previously affected checkpoints is claimed.
''')
authority=repo/'artifacts/revision-sequential-policy-completion-v1';signer=SoftwareECDSASigner.generate()
write_once(authority/'analyst.private.pem',signer.private_pem());write_once(out/'analyst.public.pem',signer.public_pem())
core={'profile':'sequential-round-policy-analyst-completion-v1','date':'2026-11-03',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),
    'current_implementation_sha256':checks['current_implementation_sha256'],'qualifications':checks['qualifications'],
    'artifact_roots':{str(lab):checks['artifact_closure_sha256']},
    'artifacts':{p.name:sha256_file(p) for p in out.iterdir() if p.is_file() and p.name not in ('completion-closure.json','completion-closure.sha256')},
    'authority_role':'Local software analyst; not an independent witness or a fresh TPM client'}
digest=digest_object(core);signed={'core':core,'core_digest':digest,
    'signature':{'key_id':signer.key_id,'value_b64':signer.sign_digest(digest),'trust_level':'software-development'}}
write_once(out/'completion-closure.json',derived_json_bytes(signed))
assert verify_digest_signature(load_public_key(signer.public_pem()),digest,signed['signature']['value_b64'])
for name,value in core['artifacts'].items():assert sha256_file(out/name)==value
(out/'completion-closure.sha256').write_text(sha256_file(out/'completion-closure.json')+'\n')
for name in ('completion-closure.json','completion-closure.sha256','analyst.public.pem'):shutil.copy(out/name,result/name)
print(json.dumps(checks,sort_keys=True));print('SIGNED COMPLETION',sha256_file(out/'completion-closure.json'))
