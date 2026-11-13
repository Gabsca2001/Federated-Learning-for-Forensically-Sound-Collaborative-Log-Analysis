"""Seal the corrected release and final conditional-proof correspondence."""
from pathlib import Path
import ast
import difflib
import json
import re
import shutil
import zipfile
import xml.etree.ElementTree as ET
from fl_forensics.canonical import sha256_file,digest_object
from fl_forensics.crypto import SoftwareECDSASigner,load_public_key,verify_digest_signature
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.storage import write_once

repo=Path.cwd();out=Path(__file__).parent;project=out.parent.parent;lab=repo/'artifacts/revision-formal-correspondence-v2'
def read(p):return json.loads(p.read_bytes())
def save(p,v):write_once(p,derived_json_bytes(v))
before=read(out/'before-review.json');revision=read(out/'source-correction.json')
assert implementation_sha256()==revision['after_implementation_sha256']=='3a5165d525b0d69079f6f5bf83ef939f46a269568907724913d3575010cf3073'
assert set(revision['source_changes'])=={'src/fl_forensics/round_derivation.py','src/fl_forensics/campaign_derivation.py','tests/test_campaign_derivation.py'}
changed=[]
for n,h in before['sources'].items():
    assert sha256_file(lab/'current-source/fl_forensics'/Path(n).name)==h
    actual=sha256_file(repo/n)
    if actual!=h:changed.append(n);assert actual==revision['source_changes'][n]['after_sha256']
    assert sha256_file(lab/'corrected-source/fl_forensics'/Path(n).name)==actual
assert set(changed)=={'src/fl_forensics/round_derivation.py','src/fl_forensics/campaign_derivation.py'}
assert len(before['sources'])==len(list((repo/'src/fl_forensics').glob('*.py')))==114
for n,item in revision['source_changes'].items():
    assert sha256_file(out/'pre-fix'/n)==item['before_sha256'] and sha256_file(repo/n)==item['after_sha256']
for n,h in before['historical_case']['package_files'].items():assert sha256_file(lab/'historical-runtime'/Path(n).relative_to('src'))==h
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/n)==h for n,h in before['thesis_sources'].items())
for ref in before['original_references'].values():
    if ref['available']:assert sha256_file(Path(ref['source_path']))==ref['sha256']
previous=project/'output/group-validation-20261103';old=read(previous/'completion-closure.json')
assert sha256_file(previous/'completion-closure.json')==before['previous_completion_sha256']=='be3c2d61597d7bc32ace3c90dfdc41d6bf4a755b8e39d2efcaeaa6d9570dcd02'
assert digest_object(old['core'])==old['core_digest']
assert verify_digest_signature(load_public_key((previous/'analyst.public.pem').read_bytes()),old['core_digest'],old['signature']['value_b64'])
for n,h in old['core']['artifacts'].items():assert sha256_file(previous/n)==h
matrix=read(out/'property-code-evidence-matrix.json');assert matrix['implementation_sha256']==implementation_sha256()
assert len(matrix['properties'])==15
for row in matrix['properties']:
    for item in row['implementation']+row['verifiers']:
        assert sha256_file(repo/item['path'])==item['source_sha256']
        tree=ast.parse((repo/item['path']).read_text());parts=item['function'].split('.')
        node=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.name==parts[0])
        if len(parts)==2:node=next(n for n in node.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==parts[1])
        assert node.lineno==item['line'] and node.end_lineno==item['end_line']
    for n,h in row['test_source_sha256'].items():assert sha256_file(repo/'tests'/n)==h
for item in matrix['evidence'].values():assert sha256_file(Path(item['path']))==item['sha256']
suite=ET.parse(out/'full-tests.xml').getroot().find('testsuite')
assert suite.attrib['tests']=='633' and all(suite.attrib[k]=='0' for k in ('failures','errors','skipped'))
assert 'All checks passed!' in (out/'ruff.log').read_text()
targeted=ET.parse(out/'occurrence-regression-tests.xml').getroot().find('testsuite')
assert targeted.attrib['tests']=='27' and all(targeted.attrib[k]=='0' for k in ('failures','errors','skipped'))
assert ET.parse(out/'pre-fix/full-tests.xml').getroot().find('testsuite').attrib['tests']=='631'
current=read(out/'current-obligation-checks.json');historic=read(out/'obligation-checks.json')
assert current['implementation_sha256']==implementation_sha256() and current['status']=='passed'
assert historic['implementation_sha256']==before['historical_case']['implementation_sha256'] and historic['status']=='passed'
assert historic['shortest_typed_witnesses_verified']==4135
probe=read(out/'replayed-bundle-probe-reproduced.json')
assert probe['implementation_sha256']==before['implementation_sha256'] and probe['source_rounds_full_verified']
assert not probe['graph_created'] and probe['error']=='cycle in campaign graph'
borrowed_before=read(out/'borrowed-bundle-probe-before.json');borrowed_after=read(out/'borrowed-bundle-probe-after.json')
assert borrowed_before['implementation_sha256']==before['implementation_sha256'] and borrowed_before['rejected_origin_reaches_numeric_or_scoring_nodes']
assert borrowed_after['implementation_sha256']==implementation_sha256() and not borrowed_after['rejected_origin_reaches_numeric_or_scoring_nodes']
survey=read(out/'historical-occurrence-scope.json')
assert survey['submission_occurrences']==survey['distinct_bundle_origin_nodes']==296 and not survey['nodes_shared_by_distinct_submissions']

destination=repo/'results/revision-final-formal-correspondence-v2';destination.mkdir(exist_ok=False)
note='''> Final formal correspondence, 2026-11-03: a concrete graph-identity defect was
> found and corrected. Replayed/borrowed identical bundle bytes now have distinct
> submission-occurrence nodes, preserving their content commitments. Two negative
> regression cases pass; the full corrected-release suite passes 633 tests.
> The 15-property matrix binds assumptions, real function lines/hashes, verifiers
> and evidence. Historical releases and their signed graphs remain preserved.
> See [the final review](../results/revision-final-formal-correspondence-v2/README.md)
> and [current profiles](FORMAL_PROFILE_CORRESPONDENCE.md).

'''
for n in ('STATUS.md','FORMAL_MODEL_REVIEW.md','SUPERVISOR_REQUIREMENTS_AUDIT.md'):
    p=repo/'docs'/n;p.write_text(note+p.read_text())
p=repo/'docs/SUPERVISOR_REQUIREMENTS_AUDIT.md'
p.write_text(p.read_text()+'''

## Final conditional-proof/code/evidence correspondence (2026-11-03)

The original proposal and both supplied exchanges are pinned read-only sources.
The final matrix covers the accepted core and distinguishes newer empirical
adapters. The review corrected content-based aliasing of distinct submissions:
cross-round rejected replay could create a cycle, and same-round borrowed bytes
could inherit another client's numerical/scoring descendants. Node identity now
uses submission ID; the node's content SHA remains the bundle byte hash.

The corrected release passes 633 tests and the current finite obligations.
The earlier 631-pass run and old-source counterexamples remain preserved. The
historical 104-file release independently rechecks its 4,135 typed witnesses;
the old attested graph has 296 distinct origins for 296 submissions and does not
contain the newly identified alias condition. Its 20 live round instances are
four five-round branches, not one 20-step trajectory. No new TPM or training
campaign is added by this review.

Receipt coverage still depends on supplied retained client evidence, record
coverage on named committed source profiles, and review rollback detection on
externally retained heads. The newer empirical adapters emit proposed masses:
unsupported abstention can retain eligible mass and quorum, so it is not the
original full live-admission/scoring theorem. Exact history comparison requires
caller authentication and seed/optimizer-contract checks. Statistical success,
semantic truth, independent deadline/delivery, all-product completeness and a
physical TPM are not inferred.

The thesis handoff carries these bounds, model-index translation, all empirical
negative outcomes and the need for an accurate assistance disclosure. Adaptive
and live-TPM policy validation remain separate; ToN-IoT stays deferred. The
actual thesis and Git index are unchanged.
''')
docs=['FORMAL_MODEL_THEOREMS.md','FORMAL_PROFILE_CORRESPONDENCE.md','FORMAL_MODEL_REVIEW.md','STATUS.md','SUPERVISOR_REQUIREMENTS_AUDIT.md']
changes=[]
for n in docs:
    source=repo/'docs'/n;final=out/'final-docs/docs'/n;final.parent.mkdir(parents=True,exist_ok=True);shutil.copy(source,final)
    prior=out/'before/docs'/n
    changes.extend(difflib.unified_diff(prior.read_text().splitlines(keepends=True) if prior.exists() else [],source.read_text().splitlines(keepends=True),fromfile='a/docs/'+n,tofile='b/docs/'+n))
(out/'documentation.patch').write_text(''.join(changes))
checks={'profile':'final-formal-correspondence-integrity-v2','status':'verified','before_implementation_sha256':before['implementation_sha256'],
    'current_implementation_sha256':implementation_sha256(),'package_files':114,'unchanged_package_files':112,
    'changed_package_files':changed,'changed_test_files':['tests/test_campaign_derivation.py'],
    'tests':{k:suite.attrib[k] for k in ('tests','errors','failures','skipped','time')},'targeted_regressions':27,
    'property_count':15,'current_finite_checks':current['counts'],'historical_graph_witnesses_checked':4135,
    'before_source_and_counterexamples_preserved':True,'historical_signature_and_source_releases_preserved':True,
    'old_attested_case_submission_aliases':0,'thesis_source_files_unchanged':len(before['thesis_sources']),'git_index_unchanged':True,
    'qualifications':{'manual_conditional_proofs':True,'proof_assistant_certified':False,'new_corpus_training_calls':0,
        'fresh_TPM_attestation':False,'ToN_IoT_included':False,'independent_deadline_or_delivery_verified':False,
        'global_artifact_completeness':False,'semantic_truth_proved':False,'automatic_live_policy_validated':False,
        'numerical_training_or_aggregation_algorithms_changed':False,'graph_occurrence_identity_corrected':True,'thesis_changed':False}}
save(out/'integrity-and-qualification.json',checks)
binding={'profile':'final-formal-review-artifact-closure-v2','files':{p.relative_to(lab).as_posix():sha256_file(p) for p in lab.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name!='study-artifact-closure.json'}}
save(lab/'study-artifact-closure.json',binding);save(out/'study-artifact-closure.json',binding)
with zipfile.ZipFile(out/'source-and-review-scripts.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for p in sorted((repo/'src/fl_forensics').glob('*.py')):archive.write(p,p.relative_to(repo).as_posix())
    for n in ('current-source','historical-runtime'):
        for p in sorted((lab/n/'fl_forensics').glob('*.py')):archive.write(p,n+'/fl_forensics/'+p.name)
    archive.write(repo/'tests/test_campaign_derivation.py','tests/test_campaign_derivation.py')
    for p in out.glob('*.py'):archive.write(p,'review-scripts/'+p.name)
    for p in (out/'pre-fix').rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:archive.write(p,'pre-fix/'+p.relative_to(out/'pre-fix').as_posix())
    for folder in ('before','final-docs'):
        for p in (out/folder).rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts:archive.write(p,folder+'/'+p.relative_to(out/folder).as_posix())
with zipfile.ZipFile(out/'source-and-review-scripts.zip') as archive:assert archive.testzip() is None
shutil.copy(out/'FORMAL_CORRESPONDENCE_CLOSURE.md',destination/'README.md')
for p in out.iterdir():
    if p.is_file() and p.suffix in ('.json','.md','.xml','.log','.zip','.patch'):shutil.copy(p,destination/p.name)
(destination/'review-scripts').mkdir()
for p in out.glob('*.py'):shutil.copy(p,destination/'review-scripts'/p.name)
for n in docs:
    source=repo/'docs'/n
    for href in re.findall(r'\]\(([^)]+\.md)\)',source.read_text()):
        if not href.startswith(('http:','https:')):assert (source.parent/href).exists(),(n,href)
authority=repo/'artifacts/revision-final-formal-correspondence-authority-v2';signer=SoftwareECDSASigner.generate()
write_once(authority/'analyst.private.pem',signer.private_pem());write_once(out/'analyst.public.pem',signer.public_pem())
core={'profile':'final-formal-correspondence-analyst-completion-v2','date':'2026-11-03',
    'previous_completion_sha256':sha256_file(previous/'completion-closure.json'),'current_implementation_sha256':implementation_sha256(),
    'source_correction_sha256':sha256_file(out/'source-correction.json'),'artifact_roots':{str(lab):sha256_file(lab/'study-artifact-closure.json')},
    'maintained_documents':{n:sha256_file(repo/'docs'/n) for n in docs},'qualifications':checks['qualifications'],
    'artifacts':{p.relative_to(out).as_posix():sha256_file(p) for p in out.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.name not in ('completion-closure.json','completion-closure.sha256')},
    'authority_role':'Local software analyst; manual conditional proofs, not independent mathematical certification, witness time or TPM attestation'}
d=digest_object(core);signed={'core':core,'core_digest':d,'signature':{'key_id':signer.key_id,'value_b64':signer.sign_digest(d),'trust_level':'software-development'}}
save(out/'completion-closure.json',signed)
assert verify_digest_signature(load_public_key(signer.public_pem()),d,signed['signature']['value_b64'])
for n,h in core['artifacts'].items():assert sha256_file(out/n)==h
(out/'completion-closure.sha256').write_text(sha256_file(out/'completion-closure.json')+'\n')
for n in ('completion-closure.json','completion-closure.sha256','analyst.public.pem'):shutil.copy(out/n,destination/n)
assert sha256_file(repo/'.git/index')==before['git_index_sha256']
assert all(sha256_file(Path(before['thesis_root'])/n)==h for n,h in before['thesis_sources'].items())
print('FINAL FORMAL REVIEW SEALED',sha256_file(out/'completion-closure.json'),json.dumps(checks),flush=True)
