"""Bind group selections, every intervention and the unchanged implementation."""
import shutil
import zipfile
import xml.etree.ElementTree as ET
from group_common import *
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.crypto import SoftwareECDSASigner,load_public_key,verify_digest_signature
from fl_forensics.storage import write_once

previous=PROJECT/'output/baseline-dba-closure-20261103'
assert sha256_file(previous/'completion-closure.json')=='6ecb9bf6d30527cc55c61b9a5bfc60dce315bf10df244937068b3864091efa69'
old=read(previous/'completion-closure.json');assert digest_object(old['core'])==old['core_digest']
assert verify_digest_signature(load_public_key((previous/'analyst.public.pem').read_bytes()),old['core_digest'],old['signature']['value_b64'])
for name,value in old['core']['artifacts'].items():assert sha256_file(previous/name)==value
with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as archive:
    package={n:archive.read(n) for n in archive.namelist() if n.startswith('src/fl_forensics/') and n.endswith('.py')}
assert len(package)==114 and set(package)=={p.relative_to(REPO).as_posix() for p in (REPO/'src/fl_forensics').glob('*.py')}
for name,value in package.items():assert (REPO/name).read_bytes()==value
assert implementation_sha256()==old['core']['current_implementation_sha256']
before=read(PROJECT/'output/formal-review-20261103/before-context.json')
assert sha256_file(REPO/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/name)==value for name,value in before['thesis_sources'].items())
protocol=read(LAB/'protocol-before-selection.json');intervention=read(LAB/'interventions-protocol-before-computation.json')
for stage in (protocol,intervention):
    for name,value in stage['code_sha256'].items():assert sha256_file(OUT/name)==value
for name,value in protocol['source_closures'].items():assert sha256_file(REPO/name)==value
assert sha256_file(LAB/'selection-closure-before-labels.json')==intervention['selection_closure_sha256']
selection=read(LAB/'selection-closure-before-labels.json')
assert len(selection['cases'])==12
for case in selection['cases']:assert sha256_file(LAB/'selections'/f"{case['alias']}.json")==case['sha256']
for name,value in selection['calibration_files'].items():assert sha256_file(LAB/name)==value
assert sha256_file(LAB/'observable-index.json')==selection['observable_index_sha256']
index=read(LAB/'observable-index.json')['cases'];assert len(index)==24
for row in index:
    p=LAB/'observable-inputs'/row['alias'];assert sha256_file(p/'metadata.json')==row['metadata_sha256']
    assert sha256_file(p/'arrays.npz')==row['arrays_sha256']
    assert read(p/'metadata.json')['frames']==10 and not read(p/'metadata.json')['future_rounds_included']
private=read(LAB/'private-alias-map.json');pins=read(LAB/'private-source-pins.json')
for name,pin in pins.items():
    w=REPO/name
    if name.startswith('artifacts/revision-dba-three-seed-v1/'):
        expected=read(previous/'protocol-before-audit-and-benchmark.json')['source_cases'][w.name]['manifest_sha256']
    else:
        closure=next(REPO/n for n in protocol['source_closures'] if w.is_relative_to((REPO/n).parent))
        expected=read(closure)['files'][w.relative_to(closure.parent).as_posix()+'/manifest.json']
    assert pin['manifest_sha256']==expected;authenticate(w,expected)
# Rebuild every exported prefix delta and validate every source commitment.
for row in index:
    meta=read(LAB/'observable-inputs'/row['alias']/'metadata.json');source=REPO/private[row['alias']]['source']
    with np.load(LAB/'observable-inputs'/row['alias']/'arrays.npz',allow_pickle=False) as z:packed=z['deltas']
    for n,commitment in enumerate(meta['source_commitments'],1):
        p=source/'rounds'/f'round-{n:03d}';base=arrays_from_export(read(p/'base-model.json'),np=np)
        assert sha256_file(p/'base-model.json')==commitment['base']
        for i,c in enumerate(meta['clients']):
            assert sha256_file(p/'updates'/f'{c}.json')==commitment['updates'][i]
            delta=model_delta(base,arrays_from_export(read(p/'updates'/f'{c}.json'),np=np))
            assert np.array_equal(packed[n-1,i],np.concatenate([a.astype(np.float64).reshape(-1) for a in delta]))

result=read(LAB/'continuation-results.json');evaluated=read(LAB/'verified-effect-summary.json');v=evaluated['verification']
assert len(result['branches'])==len(intervention['jobs'])==72
assert result['new_local_training_calls']==v['new_local_input_commitments']==4860
assert result['new_aggregated_training_rounds']==372
assert v['branch_model_reaggregations']==432 and v['direct_model_reaggregations']==293
assert v['direct_outcome_recomputations']==293 and v['final_validation_endpoints_recomputed']==72
assert v['source_prefix_input_commitments']==1800 and v['reference_comparisons']==12
assert v['new_no_intervention_local_outputs_matched']==450 and v['new_no_intervention_models_matched']==30
assert v['test_endpoints_recomputed']==len(read(LAB/'test-endpoints.json')['endpoints'])
assert len({(b['alias'],b['branch']) for b in result['branches']})==72
for b in result['branches']:authenticate(LAB/b['path'],b['manifest_sha256'])
rewind=read(LAB/'full-rewind/result.json');rewind_check=read(LAB/'full-rewind/verification.json')
rewind_protocol=read(LAB/'full-rewind/protocol-before-training.json')
assert sha256_file(OUT/'rewind_hard_case.py')==rewind_protocol['script_sha256']
assert rewind_protocol['triggering_effect_summary_sha256']==sha256_file(LAB/'verified-effect-summary.json')
assert rewind['new_local_training_calls']==810 and rewind['new_genuinely_trained_rounds']==60
assert rewind_check['counts']['aggregate_exports_recomputed']==60 and rewind_check['counts']['input_commitments_checked']==810
assert rewind_check['counts']['source_or_clean_reference_local_matches']==450
assert rewind_check['counts']['source_or_clean_reference_checkpoint_matches']==30
assert rewind_check['selected_full_history_reference_equal']
assert rewind_check['all_client_unmodified_exact_original_clean_history']
for b in rewind['branches']:authenticate(LAB/b['path'],b['manifest_sha256'])
suite=ET.parse(OUT/'targeted-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='31' and all(suite.attrib[k]=='0' for k in ('errors','failures','skipped'))
all_selections={c['alias']:read(LAB/'selections'/f"{c['alias']}.json") for c in selection['cases']}
save(OUT/'all-selections.json',all_selections)
for name in ('protocol-before-selection.json','interventions-protocol-before-computation.json','selection-closure-before-labels.json',
    'observable-index.json','private-source-pins.json','private-alias-map.json'):
    shutil.copy(LAB/name,OUT/name)
save(OUT/'frozen-cohort-calibrations.json',{cohort:{name:read(LAB/'selections'/cohort/f'{name}.json') for name in ('reference','calibration')} for cohort in ('iid','non-iid')})
attacked=[r for r in evaluated['cases'] if r['mode']=='distributed']
env=[r for r in attacked if r['method']=='envelope-prefix-set']
checks={'profile':'retrospective-group-validation-final-v1','status':'verified',
    'current_implementation_sha256':implementation_sha256(),'unchanged_package_files':114,
    'new_relevant_tests':{'tests':31,'errors':0,'failures':0,'skipped':0},'previous_full_suite':{'tests':631,'rerun_now':False},
    'new_local_training_calls':5670,'new_genuinely_trained_aggregation_rounds':432,'continuation_branches':72,
    'main_continuation_training_calls':4860,'main_continuation_training_rounds':372,
    'post_hoc_full_rewind':{'training_calls':810,'training_rounds':60,'branches':4,'verification':rewind_check['counts']},
    'verification':v,'source_campaigns_authenticated':len(pins),'exported_prefix_deltas_verified':24*10*15,
    'thesis_sources_unchanged':len(before['thesis_sources']),'git_index_unchanged':True,'previous_signed_completion_preserved':True,
    'qualifications':{'secondary_analysis_of_previously_evaluated_histories':True,'fresh_prospective_population':False,
        'priority_V2_exact_three_client_memberships':sum(r['exact_experimental_membership'] for r in attacked if r['method']=='pair-v2'),
        'envelope_prefix_exact_three_client_memberships':sum(r['exact_experimental_membership'] for r in env),
        'envelope_sets_are_pairwise_collusion_detector':False,
        'same_start_unmodified_reference_does_not_reconstruct_W9':True,
        'envelope_joint_R15_nonzero_ASR_cases':sum(r['continuation']['joint_R15_ASR']>0 for r in env),
        'bounded_full_rewind_is_post_hoc_mechanistic_followup':True,
        'bounded_full_rewind_selected_complete_reference_equality':True,
        'all_client_full_reconstruction_requires_privileged_unmodified_snapshots':True,
        'intentional_collusion_proved':False,'automatic_live_exclusion_validated':False,
        'fresh_TPM_attestation':False,'ToN_IoT_included':False,'production_code_changed':False,'thesis_changed':False}}
save(OUT/'integrity-and-qualification.json',checks)
binding={'profile':'retrospective-group-study-artifact-closure-v1','files':{p.relative_to(LAB).as_posix():sha256_file(p)
    for p in LAB.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='study-artifact-closure.json'}}
write_once(LAB/'study-artifact-closure.json',derived_json_bytes(binding));write_once(OUT/'study-artifact-closure.json',derived_json_bytes(binding))
with zipfile.ZipFile(OUT/'source-and-study-scripts.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for p in sorted((REPO/'src/fl_forensics').glob('*.py')):archive.write(p,p.relative_to(REPO).as_posix())
    for p in sorted(OUT.glob('*.py')):archive.write(p,'study-scripts/'+p.name)
    archive.write(REPO/'scripts/revision_dba_experiment.py','study-scripts/revision_dba_experiment.py')
with zipfile.ZipFile(OUT/'source-and-study-scripts.zip') as archive:assert archive.testzip() is None

destination=REPO/'results/revision-retrospective-groups-validation-v1';destination.mkdir(exist_ok=False)
shutil.copy(OUT/'RETROSPECTIVE_GROUP_VALIDATION.md',destination/'README.md')
for p in OUT.iterdir():
    if p.is_file() and p.suffix in ('.json','.png','.pdf','.csv','.md','.xml','.zip'):shutil.copy(p,destination/p.name)
(destination/'study-scripts').mkdir()
for p in OUT.glob('*.py'):shutil.copy(p,destination/'study-scripts'/p.name)
note='''> Retrospective group validation, 2026-11-03: frozen V2 and an explicitly
> separate envelope-prefix anomaly set are tested on changed identities and
> separately calibrated IID/non-IID cohorts. V2 priority groups miss one attacker
> in all six cases; wider pools retain benign false members. The secondary sets
> recover all three experimental identities but do not prove collusion.
> Main and hard-case follow-up studies add 293 direct removals, 72 continuation
> branches and four full rewinds: 5,670 local calls and 432 genuinely trained rounds.
> Same-start unmodified-tail equality does not reconstruct the inherited W9;
> the post-hoc W0 hard-case replay supports bounded reference reconstruction.
> All 31 relevant tests pass; production algorithms and thesis sources are unchanged.
> See [full outcomes and remaining limits](../results/revision-retrospective-groups-validation-v1/README.md).

'''
status=REPO/'docs/STATUS.md';status.write_text(note+status.read_text())
audit=REPO/'docs/SUPERVISOR_REQUIREMENTS_AUDIT.md';audit.write_text(note+audit.read_text()+'''

## Retrospective selected sets and causal tails (2026-11-03)

The requested individual/joint/benign comparisons are extended to changed
attacker identities and separately referenced IID/non-IID cohorts. This is a
secondary analysis of existing histories. Selection closes on rounds 1–10
before truth or ASR is used; full V2 candidate pools and selection mistakes
remain visible. The envelope-prefix collection is separately labelled as an
anomaly-selected set, not a pairwise collusion classifier.

Direct R10 reaggregations are followed by genuine R11–15 local retraining from
each corrected branch checkpoint. Remaining scripted poisoning is retained.
Benign controls match set size and additionally include closest original sample
mass; their ranks are descriptive rather than p-values. The no-intervention
tails reproduce 450 local outputs and 30 newly trained checkpoints exactly.

For each selected set, same-W9 unmodified-data reference tails check the complete
future execution. That reference can inherit an already poisoned checkpoint;
its equality does not establish a globally clean pre-intervention history.
All-client clean-history differences also reflect changed participation.
The report preserves residual ASR, false pool members, missed membership,
individual effects, benign controls and complete/component test outcomes.

After observing the largest late-removal residual, a separate recorded post-hoc
follow-up replays that same frozen selected set from W0 through all 15 rounds.
It does not retune discovery. Four full histories add 810 local calls and 60
trained rounds: original source reproduction, selected-set exclusion, matched
unmodified reference and all-client unmodified reconstruction. All source/clean
reference payloads match, while complete selected-history equality concerns
the reduced population. The all-client reconstruction requires the original
unmodified snapshots and declared starting-state/environment assumptions.

This strengthens the accepted retrospective claim of compatibility with
coordinated behaviour. It does not prove malicious intent, complete update-only
collusion identification or automatic live exclusion. No new TPM or ToN-IoT
campaign and no thesis edit is introduced. Final formal correspondence,
adaptive/live policy qualification and thesis integration remain separate steps.
''')

authority=REPO/'artifacts/revision-retrospective-group-validation-completion-v1';signer=SoftwareECDSASigner.generate()
write_once(authority/'analyst.private.pem',signer.private_pem());write_once(OUT/'analyst.public.pem',signer.public_pem())
core={'profile':'retrospective-group-validation-analyst-completion-v1','date':'2026-11-03',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),'current_implementation_sha256':implementation_sha256(),
    'artifact_roots':{str(LAB):sha256_file(LAB/'study-artifact-closure.json')},
    'maintained_document_sha256':{p.relative_to(REPO).as_posix():sha256_file(p) for p in (status,audit)},
    'qualifications':checks['qualifications'],
    'artifacts':{p.name:sha256_file(p) for p in OUT.iterdir() if p.is_file() and p.name not in ('completion-closure.json','completion-closure.sha256')},
    'authority_role':'Local software analyst; not independent witness, trusted time or TPM attestation'}
d=digest_object(core);signed={'core':core,'core_digest':d,'signature':{'key_id':signer.key_id,'value_b64':signer.sign_digest(d),'trust_level':'software-development'}}
write_once(OUT/'completion-closure.json',derived_json_bytes(signed))
assert verify_digest_signature(load_public_key(signer.public_pem()),d,signed['signature']['value_b64'])
for name,value in core['artifacts'].items():assert sha256_file(OUT/name)==value
(OUT/'completion-closure.sha256').write_text(sha256_file(OUT/'completion-closure.json')+'\n')
for name in ('completion-closure.json','completion-closure.sha256','analyst.public.pem'):shutil.copy(OUT/name,destination/name)
assert sha256_file(REPO/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/name)==value for name,value in before['thesis_sources'].items())
print('GROUP VALIDATION SIGNED COMPLETION',sha256_file(OUT/'completion-closure.json'),json.dumps(checks),flush=True)
