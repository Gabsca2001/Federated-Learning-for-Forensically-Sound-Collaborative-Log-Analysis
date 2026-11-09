"""Seal the complete investigation, including rejected alternatives and limits."""
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
out=project/'output/geometry-detector-20261103';previous=project/'output/current-evidence-policy-20261103'
lab=repo/'artifacts/revision-geometry-detector-v1'
def read(p):return json.loads(p.read_bytes())
assert sha256_file(previous/'completion-closure.json')=='4ef209ad006da39251ddb6ef6cf2abbe9bd0e945e2797e23202a162301faf1e2'
for name,value in read(previous/'completion-closure.json')['core']['artifacts'].items():assert sha256_file(previous/name)==value
before=read(project/'output/formal-review-20261103/before-context.json')
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/name)==value for name,value in before['thesis_sources'].items())
with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as archive:
    old_sources={n:archive.read(n) for n in archive.namelist() if n.startswith('src/fl_forensics/') and n.endswith('.py')}
for name,value in old_sources.items():assert (repo/name).read_bytes()==value,name
current={p.relative_to(repo).as_posix() for p in (repo/'src/fl_forensics').glob('*.py')}
added={'src/fl_forensics/client_envelope_policy.py','src/fl_forensics/residual_geometry.py'}
assert current-set(old_sources)==added
protocol=read(lab/'protocol-before-new-training.json')
assert sha256_file(repo/'src/fl_forensics/client_envelope_policy.py')==protocol['source_policy_sha256']
assert sha256_file(repo/'src/fl_forensics/residual_geometry.py')==protocol['source_geometry_sha256']
assert sha256_file(out/'policy_worker.py')==protocol['worker_sha256']
assert sha256_file(out/'run_online_study.py')==protocol['controller_sha256']
assert sha256_file(out/'policy_data.py')==protocol['generator_sha256']
for name in ('client_envelope_policy.py','residual_geometry.py'):
    assert (repo/'src/fl_forensics'/name).read_bytes()==(out/name).read_bytes()
for name in ('test_client_envelope_policy.py','test_residual_geometry.py'):
    assert (repo/'tests'/name).read_bytes()==(out/name).read_bytes()
for name in ('state_conditioned_audit.py','sequential_decision.py','current_evidence_policy.py','client_envelope_policy.py'):
    assert (repo/'src/fl_forensics'/name).read_bytes()==(lab/'worker-code/fl_forensics'/name).read_bytes()
suite=ET.parse(out/'full-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='631' and all(suite.attrib[k]=='0' for k in ('errors','failures','skipped'))
evaluation=read(lab/'prospective-evaluation.json');assert len(evaluation['cases'])==36
assert set(evaluation['experimental_acceptance'])==set(protocol['experimental_acceptance'])
assert read(lab/'engine-shutdown.json')['owned_engine_stopped']
for name,digest in read(lab/'reserved-generation-complete.json')['episode_manifests'].items():
    assert sha256_file(lab/'private-episodes'/name/'manifest.json')==digest
training_calls=len(list((lab/'private-episodes').glob('*/rounds/*/updates/*.json')))
completed_rounds=len(list((lab/'private-episodes').glob('*/rounds/*/round.json')))
assert completed_rounds==evaluation['verification_counts']['aggregates']
assert evaluation['verification_counts']['policy_decisions']==2*completed_rounds
assert evaluation['verification_counts']['source_updates']==15*completed_rounds
binding={'profile':'individual-envelope-study-artifact-closure-v1',
    'files':{p.relative_to(lab).as_posix():sha256_file(p) for p in lab.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='study-artifact-closure.json'}}
write_once(lab/'study-artifact-closure.json',derived_json_bytes(binding));write_once(out/'study-artifact-closure.json',derived_json_bytes(binding))
for name in ('protocol-before-new-training.json','calibration-frozen-before-evaluation.json','reserved-execution-before-training.json',
    'development-protocol-before-fit.json','retreat-development-protocol-before-scoring.json','fit-runtime-inspection.json','online-worker-runtime.json','engine-shutdown.json'):
    shutil.copy(lab/name,out/name)
shutil.copy(lab/'policy-calibration/envelope-closure.json',out/'envelope-fit-closure.json')
checks={'status':'verified','current_implementation_sha256':implementation_sha256(),'unchanged_prior_package_files':len(old_sources),
    'added_package_files':{n:sha256_file(repo/n) for n in sorted(added)},
    'tests':{k:suite.attrib[k] for k in ('tests','errors','failures','skipped','time')},
    'verification_counts':evaluation['verification_counts'],'new_local_training_calls':training_calls,'new_completed_FL_rounds':completed_rounds,
    'thesis_sources_unchanged':len(before['thesis_sources']),'git_index_unchanged':True,'previous_signed_completion_preserved':True,
    'artifact_root':str(lab),'artifact_closure_sha256':sha256_file(lab/'study-artifact-closure.json'),
    'qualifications':{'experimental_acceptance':evaluation['experimental_acceptance'],'all_pilot_criteria_pass':evaluation['all_pilot_criteria_pass'],
        'raw_rows_or_attack_labels_accessible_to_detector':False,'future_frames_accessible_to_detector':False,
        'three_independently_trained_trajectories':True,'geometry_only_filter_rejected':True,
        'reserved_outcomes_used_for_tuning':False,'automatic_live_deployment_validated':False,'semantic_malice_proved':False,
        'permanent_bans':False,'fresh_TPM_attestation':False,'historical_checkpoints_automatically_repaired':False,'final_test_set_used':False}}
(out/'integrity-and-qualification.json').write_text(json.dumps(checks,sort_keys=True,indent=2)+'\n')
with zipfile.ZipFile(out/'source-and-study-scripts.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for p in sorted((repo/'src/fl_forensics').glob('*.py')):archive.write(p,p.relative_to(repo).as_posix())
    for p in sorted(out.glob('*.py')):archive.write(p,'study-scripts/'+p.name)
    with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as old:
        for name in ('study_data.py','revision_dba_experiment.py'):archive.writestr('study-scripts/'+name,old.read('study-scripts/'+name))
    for name in ('test_client_envelope_policy.py','test_residual_geometry.py'):archive.write(repo/'tests'/name,'tests/'+name)
with zipfile.ZipFile(out/'source-and-study-scripts.zip') as archive:assert archive.testzip() is None
result=repo/'results/revision-individual-envelope-v1';result.mkdir(exist_ok=False)
shutil.copy(out/'INDIVIDUAL_ENVELOPE_STUDY.md',result/'README.md')
for p in out.iterdir():
    if p.is_file() and p.suffix in ('.json','.xml','.png','.pdf'):shutil.copy(p,result/p.name)
scripts=result/'study-scripts';scripts.mkdir()
for p in out.glob('*.py'):shutil.copy(p,scripts/p.name)
status=repo/'docs/STATUS.md'
note='''> Individual clean envelope follow-up, 2026-11-03: tensor-row/column geometry
> was investigated and rejected for automatic filtering because of development
> false proposals. The selected policy supplements confirmed current evidence
> with client-specific clean envelopes and releases a receding additional channel.
> A new frozen 36-episode study executes no intervention, prior policy and new
> policy as independent training histories, with 12 attack rounds per episode.
> All 631 tests pass. See [complete outcomes and limitations](../results/revision-individual-envelope-v1/README.md).

'''
status.write_text(note+status.read_text())
for name in ('SUPERVISOR_REQUIREMENTS_AUDIT.md','FORMAL_MODEL_THEOREMS.md'):
    p=repo/'docs'/name;p.write_text(p.read_text()+'''

## Individual clean envelope and evidence retreat (2026-11-03)

The added empirical policy separates client-specific departures from a global
worst-client cutoff. Its additional channel uses positive current minimum excess
over a fixed per-client/view clean envelope, a peak within the uninterrupted
positive episode, and two consecutive observations retaining at least half that
peak. The peak can suppress an action; it cannot authorize one without current
evidence. The final union requires either a confirmed prior current channel or
the confirmed additional channel. Neither a stored peak nor cumulative review
score alone can quarantine an update. Gate rejection remains non-compensable,
unsupported contexts break confirmation, and failed quorum cannot restore
excluded mass. Statistical release is not a semantic benign label.

Geometry-only filtering was rejected empirically rather than silently promoted.
Method selection uses only declared historical development observations. The
new frozen persistent-attack comparison trains all three active/control
histories and counts shadow proposals as well as actual exclusions. All 631
tests pass. Finite empirical accuracy, population false-positive guarantees,
semantic malice and historical clean-state recovery remain separate claims.
No new TPM attestation, live deployment or permanent ban is introduced. See
[the full prospective results](../results/revision-individual-envelope-v1/README.md).
''')
authority=repo/'artifacts/revision-individual-envelope-completion-v1';signer=SoftwareECDSASigner.generate()
write_once(authority/'analyst.private.pem',signer.private_pem());write_once(out/'analyst.public.pem',signer.public_pem())
core={'profile':'individual-envelope-analyst-completion-v1','date':'2026-11-03',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),
    'current_implementation_sha256':checks['current_implementation_sha256'],'qualifications':checks['qualifications'],
    'artifact_roots':{str(lab):checks['artifact_closure_sha256']},
    'artifacts':{p.name:sha256_file(p) for p in out.iterdir() if p.is_file() and p.name not in ('completion-closure.json','completion-closure.sha256')},
    'authority_role':'Local software analyst; not an independent witness or TPM client'}
d=digest_object(core);signed={'core':core,'core_digest':d,
    'signature':{'key_id':signer.key_id,'value_b64':signer.sign_digest(d),'trust_level':'software-development'}}
write_once(out/'completion-closure.json',derived_json_bytes(signed))
assert verify_digest_signature(load_public_key(signer.public_pem()),d,signed['signature']['value_b64'])
for name,value in core['artifacts'].items():assert sha256_file(out/name)==value
(out/'completion-closure.sha256').write_text(sha256_file(out/'completion-closure.json')+'\n')
for name in ('completion-closure.json','completion-closure.sha256','analyst.public.pem'):shutil.copy(out/name,result/name)
print(json.dumps(checks,sort_keys=True));print('SIGNED COMPLETION',sha256_file(out/'completion-closure.json'))
