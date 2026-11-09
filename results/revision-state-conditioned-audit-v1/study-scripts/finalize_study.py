"""Seal source, protocols, blinded analysis and replay evidence; preserve history."""
import json
from pathlib import Path
import shutil
import zipfile
import xml.etree.ElementTree as ET

from fl_forensics.canonical import sha256_file,digest_object
from fl_forensics.crypto import SoftwareECDSASigner,load_public_key,verify_digest_signature
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.storage import write_once

repo=Path.cwd();project=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1')
out=project/'output/state-conditioned-detector-20261103';previous=project/'output/residual-poisoning-20261103'
lab=repo/'artifacts/revision-state-conditioned-heldout-v1';development=repo/'artifacts/revision-state-conditioned-development-v1'


def read(path):return json.loads(path.read_bytes())
def closure_files(root):
    return {p.relative_to(root).as_posix():sha256_file(p) for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='study-artifact-closure.json'}


assert sha256_file(previous/'completion-closure.json')=='969aa8687d4ace295254696c86bb416edc4308c3ddfc0f14572455dac6317eff'
older=read(previous/'completion-closure.json')
for name,digest in older['core']['artifacts'].items():assert sha256_file(previous/name)==digest
before=read(project/'output/formal-review-20261103/before-context.json')
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/name)==digest for name,digest in before['thesis_sources'].items())
with zipfile.ZipFile(previous/'source-and-case-scripts.zip') as archive:
    sources={n:archive.read(n) for n in archive.namelist() if n.startswith('src/fl_forensics/') and n.endswith('.py')}
for name,data in sources.items():assert (repo/name).read_bytes()==data,name
current={p.relative_to(repo).as_posix() for p in (repo/'src/fl_forensics').glob('*.py')}
added=current-set(sources)
assert added=={'src/fl_forensics/state_conditioned_audit.py','src/fl_forensics/state_conditioned_fusion.py'}
protocol=read(lab/'frozen-protocol-before-new-training.json')
for name,digest in protocol['algorithms'].items():
    assert sha256_file(repo/'src/fl_forensics'/name)==digest
    assert sha256_file(lab/'detector-code/fl_forensics'/name)==digest
assert sha256_file(out/'study_data.py')==protocol['generator_sha256']
suite=ET.parse(out/'full-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='578' and all(suite.attrib[k]=='0' for k in ('errors','failures','skipped'))
evaluation=read(lab/'post-selection-evaluation.json')
replay=read(lab/'full-selected-replay/evaluation.json')
assert replay['new_local_training_calls']==1550 and replay['new_aggregation_rounds']==130
exact=sum(c['matched_clean_comparison']['commitment_trajectories_equal'] for c in replay['cases'])
assert exact==5 and len(replay['cases'])==6
for relative,digest in read(lab/'full-selected-replay/closure.json')['files'].items():assert sha256_file(lab/'full-selected-replay'/relative)==digest
for root,name in ((development,'development'),(lab,'heldout')):
    binding={'profile':'state-audit-artifact-closure-v1','scope':name,'files':closure_files(root)}
    write_once(root/'study-artifact-closure.json',derived_json_bytes(binding))
    write_once(out/f'{name}-artifact-closure.json',derived_json_bytes(binding))

important={
    'frozen-protocol-before-new-training.json':lab/'frozen-protocol-before-new-training.json',
    'model-closure.json':lab/'models/model-closure.json',
    'selection-closure.json':lab/'selections/selection-closure.json',
    'fit-runtime-inspection.json':lab/'fit-runtime-inspection.json',
    'infer-runtime-inspection.json':lab/'infer-runtime-inspection.json',
    'matched-state-control-protocol-before-generation.json':lab/'matched-state-control-protocol-before-generation.json',
    'full-history-protocol-before-training.json':lab/'full-selected-replay/protocol-before-training.json',
    'full-history-artifact-closure.json':lab/'full-selected-replay/closure.json',
    'fit-input-closure.json':lab/'fit-input-closure.json',
    'blinded-evaluation-input-closure.json':lab/'blinded-evaluation-input-closure.json'}
for name,path in important.items():shutil.copy(path,out/name)
checks={'status':'verified','current_implementation_sha256':implementation_sha256(),
    'prior_package_files_unchanged':len(sources),'added_package_files':{n:sha256_file(repo/n) for n in sorted(added)},
    'old_signed_completion_preserved':True,'git_index_unchanged':True,'thesis_source_files_unchanged':len(before['thesis_sources']),
    'tests':{k:suite.attrib[k] for k in ('tests','errors','failures','skipped','time')},
    'new_local_training_calls':6710,'new_autoregressive_aggregation_rounds':310,'conditional_clean_contexts':164,
    'artifact_roots':{str(root):sha256_file(root/'study-artifact-closure.json') for root in (development,lab)},
    'qualification':{'detector_fit_calibration_and_inference_without_original_client_rows':True,
        'heldout_models_frozen_before_case_generation':True,'heldout_attacker_assignments_changed':True,
        'IID_and_non_IID_evaluated_with_separate_clean_references':True,
        'all_methods_retained_no_posthoc_cohort_winner_selection':True,
        'primary_true_poisoning_client_occurrences':17,'primary_false_client_occurrences_in_attacked_cases':3,
        'primary_missed_poisoning_client_occurrences':1,'matched_clean_replay_equal_cases':5,'replayed_attacked_cases':6,
        'automatic_live_exclusion_validated':False,'complete_update_only_colluding_group_identification_validated':False,
        'intentional_collusion_proved':False,'fresh_TPM_attestation_performed':False,'final_test_used':False}}
(out/'integrity-and-qualification.json').write_text(json.dumps(checks,sort_keys=True,indent=2)+'\n')
with zipfile.ZipFile(out/'source-and-study-scripts.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted((repo/'src/fl_forensics').glob('*.py')):archive.write(path,path.relative_to(repo).as_posix())
    for path in sorted(out.glob('*.py')):archive.write(path,'study-scripts/'+path.name)
    archive.write(repo/'tests/test_state_conditioned_audit.py','tests/test_state_conditioned_audit.py')
with zipfile.ZipFile(out/'source-and-study-scripts.zip') as archive:assert archive.testzip() is None

result=repo/'results/revision-state-conditioned-audit-v1';result.mkdir(exist_ok=False)
shutil.copy(out/'STATE_CONDITIONED_AUDIT.md',result/'README.md')
for path in out.glob('*.json'):shutil.copy(path,result/path.name)
for name in ('full-tests.xml','heldout-detection-results.png','heldout-detection-results.pdf'):shutil.copy(out/name,result/name)
scripts=result/'study-scripts';scripts.mkdir()
for path in out.glob('*.py'):shutil.copy(path,scripts/path.name)
note='''> State-conditioned audit, 2026-11-03: new client-update predictors explicitly
> condition on incoming checkpoints. Blinded Docker fitting/calibration/inference
> uses only exported models, without client datasets or attack identities. New IID
> and non-IID evaluations change attacker assignments. Results expose a precision/
> recall trade-off; frozen primary fusion has 17 true, 3 false and 1 missed client
> occurrence. Exact selected-history replays match 5/6 clean references. The missed
> non-IID contribution leaves ASR 12.7874%. All views and disagreements are retained;
> automatic exclusion is not validated. Full suite: 578 tests. See
> [protocol, controls and qualifications](../results/revision-state-conditioned-audit-v1/README.md).

'''
status=repo/'docs/STATUS.md';status.write_text(note+status.read_text())
for name in ('SUPERVISOR_REQUIREMENTS_AUDIT.md','FORMAL_MODEL_THEOREMS.md'):
    p=repo/'docs'/name
    p.write_text(p.read_text()+'''

## Incoming-state consistency follow-up (2026-11-03)

The new observable-only audit separates a local update departure from a benign
response to an already affected global checkpoint. It remains statistical evidence,
not semantic truth or a gate override. Frozen evaluation covers changed attacker
identities in IID and non-IID data; ordinary and matched-state clean controls;
all predeclared predictor views; direct effects and complete selected-history
retraining. Primary fusion misses one high-weight non-IID client and has false
candidates, so it is not promoted to automatic exclusion. Exact clean-reference
history equality does not establish that every excluded client was malicious.

See [the frozen study](../results/revision-state-conditioned-audit-v1/README.md) for
all counts, the file-access boundary, calibrations, trade-offs and unresolved scope.
''')

authority=repo/'artifacts/revision-state-audit-completion-v1';signer=SoftwareECDSASigner.generate()
write_once(authority/'analyst.private.pem',signer.private_pem());write_once(out/'analyst.public.pem',signer.public_pem())
core={'profile':'state-conditioned-audit-analyst-completion-v1','date':'2026-11-03',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),
    'current_implementation_sha256':implementation_sha256(),'qualification':checks['qualification'],
    'artifact_roots':checks['artifact_roots'],
    'artifacts':{p.name:sha256_file(p) for p in out.iterdir() if p.is_file() and p.name not in ('completion-closure.json','completion-closure.sha256')},
    'authority_role':'Local software analyst, not an independent witness or fresh TPM client'}
digest=digest_object(core);signed={'core':core,'core_digest':digest,
    'signature':{'key_id':signer.key_id,'value_b64':signer.sign_digest(digest),'trust_level':'software-development'}}
write_once(out/'completion-closure.json',derived_json_bytes(signed))
assert verify_digest_signature(load_public_key(signer.public_pem()),digest,signed['signature']['value_b64'])
for name,digest in core['artifacts'].items():assert sha256_file(out/name)==digest
(out/'completion-closure.sha256').write_text(sha256_file(out/'completion-closure.json')+'\n')
for name in ('completion-closure.json','completion-closure.sha256','analyst.public.pem'):shutil.copy(out/name,result/name)
print(json.dumps(checks,indent=2))
print('SIGNED COMPLETION',sha256_file(out/'completion-closure.json'))
