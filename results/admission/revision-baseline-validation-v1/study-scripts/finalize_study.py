"""Check frozen source anchors and seal the baseline audit without changing algorithms."""
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
from revision_dba_experiment import authenticate

repo=Path.cwd();out=Path(__file__).parent;project=out.parent.parent
lab=repo/'artifacts/revision-baseline-closure-v1'
previous=project/'output/geometry-detector-20261103'
def read(p):return json.loads(p.read_bytes())
def signed_completion(folder,expected):
    assert sha256_file(folder/'completion-closure.json')==expected
    signed=read(folder/'completion-closure.json');core=signed['core']
    assert digest_object(core)==signed['core_digest']
    assert verify_digest_signature(load_public_key((folder/'analyst.public.pem').read_bytes()),signed['core_digest'],signed['signature']['value_b64'])
    for name,value in core['artifacts'].items():assert sha256_file(folder/name)==value,name
    return core

old=signed_completion(previous,'17346b960336a5881a063c0026bfc9bc0241c2f16ae258a63e5632eb83680690')
with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as archive:
    old_sources={n:archive.read(n) for n in archive.namelist() if n.startswith('src/fl_forensics/') and n.endswith('.py')}
current={p.relative_to(repo).as_posix() for p in (repo/'src/fl_forensics').glob('*.py')}
assert current==set(old_sources) and len(current)==114
for name,value in old_sources.items():assert (repo/name).read_bytes()==value,name
assert implementation_sha256()=='c1f236869b9cb410cde0d0311c545c54a69dd1a5fc95d2828174c2925cfa7d7b'
suite=ET.parse(previous/'full-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='631' and all(suite.attrib[k]=='0' for k in ('errors','failures','skipped'))
before=read(project/'output/formal-review-20261103/before-context.json')
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/name)==value for name,value in before['thesis_sources'].items())

protocol=read(lab/'protocol-before-audit-and-benchmark.json')
for name,value in protocol['source_files'].items():assert sha256_file(repo/name)==value,name
root=repo/'artifacts/revision-dba-three-seed-v1'
assert sha256_file(root/'fixed-endpoint-test.json')==protocol['fixed_test_report_sha256']
anchors={}
for case,expected in protocol['source_cases'].items():
    workspace=root/case
    assert sha256_file(root/'reports'/f'{case}.json')==expected['report_sha256']
    assert sha256_file(workspace/'experiment-authority.public.pem')==expected['public_key_sha256']
    authenticate(workspace,expected['manifest_sha256']);anchors[str(workspace)]=expected['manifest_sha256']
for case,expected in protocol['gradient_cases'].items():
    workspace=repo/'artifacts/revision-fedgradtrace-live-v1'/case
    assert sha256_file(workspace/'experiment-authority.public.pem')==expected['public_key_sha256']
    authenticate(workspace,expected['manifest_sha256']);anchors[str(workspace)]=expected['manifest_sha256']

secondary=read(lab/'secondary-protocol-before-comparison.json')
groot=repo/'artifacts/revision-geometry-detector-v1';gclosure=groot/'study-artifact-closure.json'
assert sha256_file(gclosure)==secondary['source_closure_sha256']=='608ed58b2bb8f47ba2ec4c7610a9504ebd3320788c5247f6eb391fbb798b702f'
assert old['artifact_roots'][str(groot)]==sha256_file(gclosure)
gf=read(gclosure)['files'];source_execution=read(groot/'reserved-execution-before-training.json')
assert sha256_file(groot/'reserved-execution-before-training.json')==gf['reserved-execution-before-training.json']
assert secondary['cases']==[t for t in source_execution['tasks'] if t['branch']=='shadow-FedAvg']
assert len(secondary['cases'])==12
for task in secondary['cases']:
    rel=f"private-episodes/{task['stream']}";workspace=groot/rel;expected=gf[f'{rel}/manifest.json']
    authenticate(workspace,expected);anchors[str(workspace)]=expected
    generation=read(workspace/'generation-protocol.json');assert generation['task']==task
    assert generation['fresh_TPM_attestation'] is False
    for number in range(1,16):
        p=workspace/'rounds'/f'round-{number:03d}';record=read(p/'round.json')
        assert not record['applied_exclusions'] and record['all_15_clients_trained']
        assert record['base_model_sha256']==sha256_file(p/'base-model.json')
        assert record['global_model_sha256']==sha256_file(p/'global-model.json')
        assert record['local_model_sha256']==[sha256_file(p/'updates'/f'{c}.json') for c in record['clients']]
        if number>1:assert (p/'base-model.json').read_bytes()==(workspace/'rounds'/f'round-{number-1:03d}'/'global-model.json').read_bytes()
seqout=project/'output/sequential-policy-20261103'
seq=signed_completion(seqout,'3b2fff3ad94aea6a4c6dd723115a7598e886d5078176d8afc059dea5df371057')
sroot=repo/'artifacts/revision-sequential-round-policy-v1';sclosure=sroot/'study-artifact-closure.json'
assert sha256_file(sclosure)=='9f4a6809b6543fd3f58782a085b3fc40c041c19d039cf4fb64659b7fd0188e07'
assert seq['artifact_roots'][str(sroot)]==sha256_file(sclosure)
sf=read(sclosure)['files']
for cohort,relative in secondary['historical_clean_references'].items():
    workspace=repo/relative;rel=workspace.relative_to(sroot).as_posix();expected=sf[f'{rel}/manifest.json']
    authenticate(workspace,expected);anchors[str(workspace)]=expected
    assert read(lab/'secondary-reference-index.json')[cohort]['manifest_sha256']==expected

original=read(out/'consolidated-results.json');gradient=read(out/'gradient-audit.json')
assert original['verification']=={'recomputed_aggregates':1080,'recomputed_test_endpoints':144,'source_rounds':135,'source_updates':2025}
assert gradient['completed_rounds']==gradient['replayed_gradient_aggregates']==53
assert len(gradient['server_aggregation_timing_samples'])==159
assert gradient['representative_gradient_collection']['total_new_gradient_evaluations']==60
assert gradient['representative_gradient_collection']['optimizer_steps']==0
assert read(out/'secondary-comparison.json')['counts']=={'conditional_model_outputs':900,'source_contexts':180}
assert len(read(out/'secondary-test-results.json')['rows'])==120
assert len(read(out/'secondary-test-summary.json')['summary'])==40
assert len(read(lab/'secondary-round-results.json')['rows'])==900
plan=read(lab/'benchmark-run-plan.json')
assert sha256_file(out/'audit_common.py')==plan['helper_sha256']
assert sha256_file(out/'benchmark_worker.py')==plan['worker_sha256']
assert sha256_file(lab/'protocol-before-audit-and-benchmark.json')==plan['protocol_sha256']
benches=read(out/'benchmark-summary.json')['rows']
assert sum(r['timed_calls'] for r in benches if r['scope']=='kernel')==3240
assert sum(r['timed_calls'] for r in benches if r['scope']=='full')==162
for row in benches:
    full=read(lab/'benchmark'/f"{row['scope']}-{row['method']}.json")
    assert len(full['samples'])==row['timed_calls']
envplan=read(lab/'envelope-benchmark-plan.json')
assert sha256_file(out/'benchmark_envelope.py')==envplan['worker_sha256']
assert sha256_file(lab/'secondary-protocol-before-comparison.json')==envplan['source_protocol_sha256']
env=read(out/'envelope-benchmark-summary.json')['rows']
assert len(env)==2 and sum(len(r['samples']) for r in env)==540 and sum(r['contexts'] for r in env)==180

# Duplicate the protocol next to the report before binding this new release.
for name in ('protocol-before-audit-and-benchmark.json','secondary-protocol-before-comparison.json',
    'benchmark-run-plan.json','envelope-benchmark-plan.json','gradient-replay-numeric-policy.json','secondary-reference-index.json'):
    shutil.copy(lab/name,out/name)
checks={'profile':'baseline-dba-final-integrity-v1','status':'verified',
    'current_implementation_sha256':implementation_sha256(),'unchanged_package_files':114,
    'previous_test_result':{'tests':631,'new_full_suite_run':False,'source_unchanged':True},
    'new_numerical_validation':original['verification'],
    'gradient_aggregate_replays':53,'new_gradient_evaluations':60,'new_optimizer_steps':0,
    'secondary_contexts':180,'secondary_conditional_models':900,'secondary_test_endpoints':120,
    'timed_operations':{'original_kernel':3240,'original_full_scoring':162,'gradient_server':159,'individual_envelope':540},
    'authenticated_source_cases':anchors,'parent_closures':{str(gclosure):sha256_file(gclosure),str(sclosure):sha256_file(sclosure)},
    'thesis_sources_unchanged':len(before['thesis_sources']),'git_index_unchanged':True,
    'previous_signed_completions_preserved':True,
    'qualifications':{'production_code_changed':False,'new_client_training_calls':0,'fresh_TPM_attestation':False,
        'ToN_IoT_included':False,'full_FedXLog_reproduced':False,'native_FedGradTrace_detector_metrics':False,
        'conditional_outputs_are_closed_loop_defense_trajectories':False,
        'different_clean_reference_information_budgets':True,'secondary_analysis_of_previously_evaluated_cases':True,
        'test_fold_pristine_or_external':False,'all_methods_remediate_all_attacks':False,
        'automatic_live_deployment_validated':False,'semantic_malice_proved':False,
        'group_discovery_validated_by_this_step':False,'thesis_changed':False}}
(out/'integrity-and-qualification.json').write_text(json.dumps(checks,sort_keys=True,indent=2)+'\n')
binding={'profile':'baseline-dba-study-artifact-closure-v1','files':{
    p.relative_to(lab).as_posix():sha256_file(p) for p in lab.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='study-artifact-closure.json'}}
write_once(lab/'study-artifact-closure.json',derived_json_bytes(binding))
write_once(out/'study-artifact-closure.json',derived_json_bytes(binding))
with zipfile.ZipFile(out/'source-and-study-scripts.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for p in sorted((repo/'src/fl_forensics').glob('*.py')):archive.write(p,p.relative_to(repo).as_posix())
    for p in sorted(out.glob('*.py')):archive.write(p,'study-scripts/'+p.name)
    archive.write(repo/'scripts/revision_dba_experiment.py','study-scripts/revision_dba_experiment.py')
with zipfile.ZipFile(out/'source-and-study-scripts.zip') as archive:assert archive.testzip() is None

result=repo/'results/revision-baseline-validation-v1';result.mkdir(exist_ok=False)
shutil.copy(out/'BASELINE_DBA_VALIDATION.md',result/'README.md')
for p in out.iterdir():
    if p.is_file() and p.suffix in ('.json','.png','.pdf','.md','.zip'):shutil.copy(p,result/p.name)
scripts=result/'study-scripts';scripts.mkdir()
for p in out.glob('*.py'):shutil.copy(p,scripts/p.name)
note='''> Baseline/DBA validation closure, 2026-11-03: all 1,080 original aggregate
> exports and 144 fixed test endpoints are reproduced; costs now distinguish
> cached aggregation from complete scoring. A secondary 180-context check uses
> separate historical clean references and retains old-composite clean exclusions
> (15/675 IID, 16/675 non-IID). Complete-trigger residual ASR and the interrupted
> literal FedGradTrace Eq. (2) execution remain explicit negative outcomes.
> Source code is unchanged; no new training, TPM or ToN-IoT campaign, or thesis edit.
> See [validated comparisons, costs and limits](../results/revision-baseline-validation-v1/README.md).

'''
status=repo/'docs/STATUS.md';status.write_text(note+status.read_text())
audit=repo/'docs/SUPERVISOR_REQUIREMENTS_AUDIT.md'
audit.write_text(note+audit.read_text()+'''

## Baseline/DBA evidence and measured cost (2026-11-03)

Step 1 consolidates the retained common-update comparisons, independently
replays 1,080 aggregate model exports and 144 test endpoints, and reports
full/component ASR, clean accuracy, macro-F1, operational exclusions,
downweights and measured wall/CPU/process-memory scopes. Cached WeiDetect F1
and composite masses are not counted as complete scoring. Current envelope
inference/policy/aggregation cost is measured in a separate stateful scope.

The original old-composite clean exclusion result was in-sample. A secondary
180-context IID/non-IID check using fixed separate historical clean references
exposes 15/675 and 16/675 clean exclusions, respectively. Its 900 conditional
outputs and 120 fixed test evaluations preserve inherited-state contamination
and all component outcomes. Unequal clean-reference information requirements
prevent a universal equal-information superiority claim.

FedGradTrace remains a qualified MLP adaptation of two distinct printed
recurrences, not a full FedXLog replication or a malicious-client classifier.
All 53 completed native-gradient exports replay exactly. The unstable Eq. (2)
fourth round and protocol differences are preserved; zero ASR in the attacked
gradient FedAvg control prevents attributing Eq. (3)'s zero ASR to mitigation.

This closes consolidation/measurement for the declared protocols; it does not
claim that every attack was remediated or every baseline reproduced end to end.
Selected-group individual/joint removal and benign controls are next, followed
by final formal correspondence, adaptive/live-TPM policy work and thesis writing.
ToN-IoT remains explicitly deferred. No production code or thesis source changed.
''')

authority=repo/'artifacts/revision-baseline-validation-completion-v1';signer=SoftwareECDSASigner.generate()
write_once(authority/'analyst.private.pem',signer.private_pem());write_once(out/'analyst.public.pem',signer.public_pem())
core={'profile':'baseline-dba-analyst-completion-v1','date':'2026-11-03',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),
    'current_implementation_sha256':implementation_sha256(),
    'artifact_roots':{str(lab):sha256_file(lab/'study-artifact-closure.json')},
    'maintained_document_sha256':{p.relative_to(repo).as_posix():sha256_file(p) for p in (status,audit)},
    'qualifications':checks['qualifications'],
    'artifacts':{p.name:sha256_file(p) for p in out.iterdir() if p.is_file() and p.name not in ('completion-closure.json','completion-closure.sha256')},
    'authority_role':'Local software analyst; not an independent witness or TPM client'}
d=digest_object(core);signed={'core':core,'core_digest':d,
    'signature':{'key_id':signer.key_id,'value_b64':signer.sign_digest(d),'trust_level':'software-development'}}
write_once(out/'completion-closure.json',derived_json_bytes(signed))
assert verify_digest_signature(load_public_key(signer.public_pem()),d,signed['signature']['value_b64'])
for name,value in core['artifacts'].items():assert sha256_file(out/name)==value
(out/'completion-closure.sha256').write_text(sha256_file(out/'completion-closure.json')+'\n')
for name in ('completion-closure.json','completion-closure.sha256','analyst.public.pem'):shutil.copy(out/name,result/name)
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/name)==value for name,value in before['thesis_sources'].items())
print(json.dumps(checks,sort_keys=True));print('SIGNED COMPLETION',sha256_file(out/'completion-closure.json'))
