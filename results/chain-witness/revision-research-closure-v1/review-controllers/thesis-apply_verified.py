"""Apply only reviewed source changes, guarding the user's actual manuscript bytes."""
from pathlib import Path
import difflib
import hashlib
import json
import shutil

out=Path(__file__).parent;stage=out/'candidate'
manifest=json.loads((out/'original-manifest.json').read_bytes());root=Path(manifest['root'])
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
for rel,expected in manifest['files'].items():
    assert sha(root/rel)==expected,('Manuscript changed during revision; preserve user edits',rel)
inspection=json.loads((out/'pdf-inspection.json').read_bytes())
assert not inspection['pages_with_question_marks'] and not inspection['repeated_long_source_paragraphs']
log=(stage/'thesis.log').read_text(errors='replace')
assert 'There were undefined references' not in log
assert 'Citation ' not in log or 'undefined' not in log
assert 'Overfull ' not in log
assert json.loads((out.parent/'live-runtime-verification.json').read_bytes())['status']=='verified'
assert (out/'visual-review.json').exists()
target_pdf=root/'thesis_revision_20261104_v4.pdf';assert not target_pdf.exists()
changes=[];patch=[]
for p in sorted(stage.rglob('*')):
    if not p.is_file():continue
    rel=p.relative_to(stage)
    if p.suffix not in ('.tex','.bib','.sty','.cls') and rel.parts[0]!='images':continue
    if rel.as_posix() in manifest['files'] and sha(p)==manifest['files'][rel.as_posix()]:continue
    target=root/rel
    if rel.as_posix() not in manifest['files']:assert not target.exists(),('New-name collision',str(target))
    if p.suffix in ('.tex','.bib','.sty','.cls'):
        before=(out/'before'/rel).read_text(encoding='utf-8-sig').splitlines(keepends=True) if (out/'before'/rel).exists() else []
        after=p.read_text(encoding='utf-8-sig').splitlines(keepends=True)
        patch.extend(difflib.unified_diff(before,after,fromfile='before/'+rel.as_posix(),tofile='after/'+rel.as_posix()))
    target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
    assert sha(target)==sha(p)
    changes.append({'file':rel.as_posix(),'before_sha256':manifest['files'].get(rel.as_posix()),'after_sha256':sha(target)})
shutil.copy2(stage/'thesis.pdf',target_pdf)
record={'status':'applied','actual_root':str(root),'pdf':str(target_pdf),'pdf_sha256':sha(target_pdf),
 'pages':inspection['pages'],'changed_files':changes,'original_pdfs_preserved':manifest['pdfs'],
 'notes':'Actual Download manuscript sources changed; generated build intermediates are retained in the reviewed staging directory. Earlier PDFs and the original source backup are preserved. No submission/publication occurred.'}
(out/'applied-changes.json').write_text(json.dumps(record,indent=2)+'\n')
(out/'thesis-changes.patch').write_text(''.join(patch),encoding='utf-8')
print(json.dumps({'status':'applied','files':len(changes),'pages':inspection['pages'],'pdf':str(target_pdf)}))
