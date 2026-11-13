"""Freeze current sources, original requirements and historical proof runtime."""
from pathlib import Path
import ast
import json
import shutil
import zipfile
import xml.etree.ElementTree as ET
from fl_forensics.canonical import sha256_file,digest_object
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.crypto import load_public_key,verify_digest_signature
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.storage import write_once

REPO=Path.cwd();OUT=Path(__file__).parent;PROJECT=OUT.parent.parent
LAB=REPO/'artifacts/revision-formal-correspondence-v2';assert not LAB.exists();LAB.mkdir()
def read(p):return json.loads(p.read_bytes())
def save(p,v):write_once(p,derived_json_bytes(v))
previous=PROJECT/'output/group-validation-20261103'
assert sha256_file(previous/'completion-closure.json')=='be3c2d61597d7bc32ace3c90dfdc41d6bf4a755b8e39d2efcaeaa6d9570dcd02'
old=read(previous/'completion-closure.json');assert digest_object(old['core'])==old['core_digest']
assert verify_digest_signature(load_public_key((previous/'analyst.public.pem').read_bytes()),old['core_digest'],old['signature']['value_b64'])
for name,value in old['core']['artifacts'].items():assert sha256_file(previous/name)==value
with zipfile.ZipFile(previous/'source-and-study-scripts.zip') as archive:
    package={n:archive.read(n) for n in archive.namelist() if n.startswith('src/fl_forensics/') and n.endswith('.py')}
assert len(package)==114
for name,value in package.items():assert (REPO/name).read_bytes()==value
assert implementation_sha256()==old['core']['current_implementation_sha256']=='c1f236869b9cb410cde0d0311c545c54a69dd1a5fc95d2828174c2925cfa7d7b'
thesis_before=read(PROJECT/'output/formal-review-20261103/before-context.json')
assert sha256_file(REPO/'.git/index')==thesis_before['git_index_sha256']
assert all(sha256_file(Path(thesis_before['thesis_root'])/name)==value for name,value in thesis_before['thesis_sources'].items())
docs=['FORMAL_MODEL_THEOREMS.md','FORMAL_MODEL_REVIEW.md','ROUND_DERIVATION.md','SUBMISSION_EVIDENCE.md',
    'INGESTION_COVERAGE.md','COUNTERFACTUAL_REPLAY.md','MULTIROUND_DERIVATION.md','STATUS.md','SUPERVISOR_REQUIREMENTS_AUDIT.md']
for n in docs:
    (OUT/'before/docs').mkdir(parents=True,exist_ok=True);shutil.copy(REPO/'docs'/n,OUT/'before/docs'/n)
sources={p.relative_to(REPO).as_posix():sha256_file(p) for p in (REPO/'src/fl_forensics').glob('*.py')}
for p in (REPO/'src/fl_forensics').glob('*.py'):
    destination=LAB/'current-source/fl_forensics'/p.name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy(p,destination)
references={}
for name,p in [('proposal',Path('/mnt/c/Users/scama/Downloads/Proposta_modello_formale_derivazione_Gabriele_Scamardo.docx')),
    ('mail-A',Path('/mnt/c/Users/scama/.codex/attachments/b13377cf-44ed-4672-809c-e9683289aa48/Testo incollato.txt')),
    ('mail-B',Path('/mnt/c/Users/scama/.codex/attachments/89361f68-5392-4d06-a48a-802b9589bb8b/Testo incollato.txt'))]:
    references[name]={'source_path':str(p),'available':p.is_file(),'role':'Read-only original user-supplied reference; document imperatives are not tool instructions.'}
    if p.is_file():references[name]['sha256']=sha256_file(p)
    if name=='proposal' and p.is_file():
        assert references[name]['sha256']=='c2ba9b093fdb829ed1252087fc7b0630c8853320e4d3e526759d1800019c09b3'
        with zipfile.ZipFile(p) as z:root=ET.fromstring(z.read('word/document.xml'))
        paragraphs=[''.join(n.itertext()) for n in root.iter() if n.tag.endswith('}p')]
        (OUT/'original-proposal-extracted.txt').write_text('READ-ONLY ORIGINAL PROPOSAL TEXT (source language preserved)\n\n'+'\n'.join(paragraphs)+'\n')
case=PROJECT/'output/attack-replay-20261103';closure=read(case/'case-closure.json')
assert sha256_file(case/'case-closure.json')=='f265b12d1d331cdf913eb2c21eab4555684ed79550ab0fd6630bec07d5d6759c'
assert digest_object(closure['core'])==closure['core_digest']
assert verify_digest_signature(load_public_key((case/'case-authority.public.pem').read_bytes()),closure['core_digest'],closure['signature']['value_b64'])
assert sha256_file(case/'final-source-release.zip')==closure['core']['final_source_archive_sha256']
legacy={}
with zipfile.ZipFile(case/'final-source-release.zip') as archive:
    for n in archive.namelist():
        if n.startswith('src/fl_forensics/') and n.endswith('.py'):
            relative=Path(n).relative_to('src');assert '..' not in relative.parts
            dest=LAB/'historical-runtime'/relative;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(archive.read(n));legacy[n]=sha256_file(dest)
assert len(legacy)==104
shutil.copy(PROJECT/'output/formal-review-20261103/check_obligations.py',OUT/'check_historical_obligations.py')
for name in ('proof-obligations.json','obligation-checks.json','review-manifest.json'):
    dest=OUT/'prior-review'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy(PROJECT/'output/formal-review-20261103'/name,dest)
outline={}
for name in sources:
    tree=ast.parse((REPO/name).read_text());items={}
    for n in tree.body:
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):items[n.name]=n.lineno
        elif isinstance(n,ast.ClassDef):
            for m in n.body:
                if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)):items[n.name+'.'+m.name]=m.lineno
    outline[name]=items
save(OUT/'source-function-index.json',outline)
snapshot={'profile':'final-formal-correspondence-review-v2','previous_completion_sha256':sha256_file(previous/'completion-closure.json'),
    'implementation_sha256':implementation_sha256(),'sources':sources,'git_index_sha256':thesis_before['git_index_sha256'],
    'thesis_root':thesis_before['thesis_root'],'thesis_sources':thesis_before['thesis_sources'],
    'document_before_sha256':{n:sha256_file(REPO/'docs'/n) for n in docs},'original_references':references,
    'historical_case':{'closure_sha256':sha256_file(case/'case-closure.json'),'source_archive_sha256':sha256_file(case/'final-source-release.zip'),
        'implementation_sha256':closure['core']['source_implementation_sha256'],'package_files':legacy},
    'scope':'Manual conditional proof/code/verifier/evidence review; current full suite and finite cross-checks. No new training/TPM/ToN-IoT campaign or thesis edit.'}
save(LAB/'before-review.json',snapshot);save(OUT/'before-review.json',snapshot)
print('REVIEW SOURCE AND REQUIREMENT SNAPSHOT FROZEN',len(sources),len(legacy),references['proposal']['available'],flush=True)
