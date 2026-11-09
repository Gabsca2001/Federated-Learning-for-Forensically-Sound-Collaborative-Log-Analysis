"""Close new analyst evidence without changing any historical case or thesis."""
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

repo=Path.cwd()
project=Path('/mnt/c/Users/scama/.codex/.chatgpt-projects/g-p-6a58cde903388191b9f85ecd023562c1')
out=project/'output/residual-poisoning-20261103'
previous=project/'output/effective-influence-20261103'


def read(path): return json.loads(path.read_bytes())


assert sha256_file(previous/'completion-closure.json')=='9803d5b46fcca8dcededad8255a3d4e9360adb088c189e9e6327ad91cc0c10fa'
old=read(previous/'completion-closure.json')
for name,digest in old['core']['artifacts'].items(): assert sha256_file(previous/name)==digest
before=read(project/'output/formal-review-20261103/before-context.json')
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/name)==digest for name,digest in before['thesis_sources'].items())
with zipfile.ZipFile(previous/'analyst-source-release.zip') as archive:
    old_sources={name:archive.read(name) for name in archive.namelist() if name.startswith('src/fl_forensics/') and name.endswith('.py')}
for name,data in old_sources.items(): assert (repo/name).read_bytes()==data,name
current={p.relative_to(repo).as_posix() for p in (repo/'src/fl_forensics').glob('*.py')}
added=current-set(old_sources)
assert added=={'src/fl_forensics/group_calibration_v2.py','src/fl_forensics/remediation_validation.py'},added
suite=ET.parse(out/'full-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='561' and all(suite.attrib[k]=='0' for k in ('failures','errors','skipped'))
labs=('revision-clean-reconstruction-v1','revision-conditioned-groups-v2-fixed-serialization',
    'revision-selected-group-remediation-v2','revision-same-base-execution-audit-v1',
    'revision-forensic-selected-remediation-v1')
closures={}
for name in labs:
    lab=repo/'artifacts'/name
    closure=read(lab/'closure.json')
    for relative,digest in closure['artifacts'].items():
        assert sha256_file(lab/relative)==digest,(name,relative)
    closures[name]={'path':str(lab),'closure_sha256':sha256_file(lab/'closure.json'),'artifact_count':len(closure['artifacts'])}
    (out/(name+'-closure.json')).write_bytes((lab/'closure.json').read_bytes())
audit=read(out/'same-base-execution-audit-evaluation.json')
assert all(c['exact_experimental_membership_recovered'] for c in audit['cases'])
forensic=read(out/'forensic-selected-remediation-evaluation.json')
assert forensic['actual_new_local_training_calls']==720
assert all(c['matched_clean_comparison']['commitment_trajectories_equal'] for c in forensic['cases'] if c['status']=='evaluated')
ordinary=read(out/'selected-group-remediation-evaluation.json')
assert ordinary['actual_new_local_training_calls']==780
assert all(not c['matched_clean_comparison']['commitment_trajectories_equal'] for c in ordinary['cases'] if c['status']=='evaluated')
checks={'status':'verified','current_implementation_sha256':implementation_sha256(),
    'previous_package_files_unchanged':len(old_sources),'added_package_files':{n:sha256_file(repo/n) for n in sorted(added)},
    'git_index_unchanged':True,'thesis_source_files_unchanged':len(before['thesis_sources']),
    'prior_signed_case_unchanged':True,'tests':{k:suite.attrib[k] for k in ('tests','errors','failures','skipped','time')},
    'new_local_training_calls':5010,'new_aggregated_rounds':300,'artifact_closures':closures,
    'qualifications':{'matched_clean_reconstruction_verified':True,'update_only_pilot_evaluated':True,
        'update_only_full_group_recovery_validated':False,'update_only_automatic_exclusion_validated':False,
        'privileged_same_base_execution_deviations_match_experimental_membership':True,
        'privileged_selected_group_clean_reference_replay_verified':True,
        'privileged_profile_requires_original_unmodified_client_snapshots':True,
        'intentional_collusion_proved':False,'fresh_TPM_attestation_performed':False,
        'independent_timestamp_verified':False}}
(out/'integrity-and-qualification.json').write_text(json.dumps(checks,indent=2,sort_keys=True)+'\n')

# Preserve current code and exact case scripts. Case scripts contain their fixed
# historical paths; they are reproducibility material, not general live controls.
with zipfile.ZipFile(out/'source-and-case-scripts.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for p in sorted((repo/'src/fl_forensics').glob('*.py')):
        archive.write(p,p.relative_to(repo).as_posix())
    for p in sorted(out.glob('*.py')):
        archive.write(p,'case-scripts/'+p.name)
    for name in ('tests/test_group_calibration_v2.py','tests/test_remediation_validation.py'):
        archive.write(repo/name,name)
with zipfile.ZipFile(out/'source-and-case-scripts.zip') as archive:
    assert archive.testzip() is None

result=repo/'results/revision-clean-reconstruction-and-groups-v1'
result.mkdir(exist_ok=False)
shutil.copy(out/'CLEAN_RECONSTRUCTION_AND_GROUPS.md',result/'README.md')
for p in out.glob('*.json'): shutil.copy(p,result/p.name)
shutil.copy(out/'full-tests.xml',result/'full-tests.xml')
scripts=result/'case-scripts';scripts.mkdir()
for p in out.glob('*.py'): shutil.copy(p,scripts/p.name)
for name in ('STATUS.md','FORMAL_MODEL_THEOREMS.md','SUPERVISOR_REQUIREMENTS_AUDIT.md'):
    p=repo/'docs'/name
    note='''

## Clean reconstruction and group-analysis follow-up (2026-11-03)

An exact-history comparison API now separates ASR zero from matched clean-reference
equivalence. Ninety reconstructed checkpoints match the intended clean references;
the previous partial removal remains non-equivalent. A pair-conditioned group
pilot uses disjoint clean fitting/calibration and new evaluation training seeds.
Its candidate pool still has false clients and missed membership and is not
validated for automatic exclusion.

A separately qualified same-base execution audit, requiring original unmodified
client snapshots, identifies every experimental execution deviation in the six
evaluation campaigns. Its selected full-history removals match clean references
exactly. This privileged result is not generalized to update-only FL. The full
suite passes 561 tests; the step includes 5,010 local training calls and 300 new
aggregation rounds, all software/analyst evidence. Existing attested evidence and
the thesis remain preserved.

See [profiles, results and remaining scope](../results/revision-clean-reconstruction-and-groups-v1/README.md).
'''
    p.write_text(p.read_text()+note)

signer=SoftwareECDSASigner.generate()
authority=repo/'artifacts/revision-residual-poisoning-completion-v1'
write_once(authority/'analyst.private.pem',signer.private_pem())
write_once(out/'analyst.public.pem',signer.public_pem())
core={'profile':'analyst-clean-reconstruction-and-groups-completion-v1',
    'current_implementation_sha256':implementation_sha256(),
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),
    'qualifications':checks['qualifications'],'artifact_closures':closures,
    'artifacts':{p.name:sha256_file(p) for p in out.iterdir() if p.is_file() and p.name not in ('completion-closure.json','completion-closure.sha256')},
    'authority_role':'Local analyst software signature, not an independent witness or fresh TPM client'}
digest=digest_object(core)
closure={'core':core,'core_digest':digest,'signature':{'key_id':signer.key_id,'value_b64':signer.sign_digest(digest),'trust_level':'software-development'}}
write_once(out/'completion-closure.json',derived_json_bytes(closure))
assert verify_digest_signature(load_public_key(signer.public_pem()),digest,closure['signature']['value_b64'])
for name,digest in core['artifacts'].items(): assert sha256_file(out/name)==digest
(out/'completion-closure.sha256').write_text(sha256_file(out/'completion-closure.json')+'\n')
for name in ('completion-closure.json','completion-closure.sha256','analyst.public.pem'):
    shutil.copy(out/name,result/name)
print(json.dumps(checks,indent=2))
print('Completion SHA256',sha256_file(out/'completion-closure.json'))
