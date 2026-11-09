"""Stage the current manuscript without altering reference material or evidence."""
from pathlib import Path
import hashlib
import json
import shutil

OUT = Path(__file__).parent
ROOT = Path('C:/Users/scama/Downloads/materiale tesi/materiale tesi/Thesis_s')
STAGE = OUT / 'candidate'
BEFORE = OUT / 'before'
assert not STAGE.exists() and not BEFORE.exists()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

files = {}
for path in sorted(ROOT.rglob('*')):
    if not path.is_file():
        continue
    rel = path.relative_to(ROOT)
    if '.vscode' in rel.parts:
        continue
    if path.suffix.lower() in ('.tex', '.bib', '.sty', '.cls') or rel.parts[0] == 'images':
        dest = STAGE / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        files[rel.as_posix()] = sha(path)
        if path.suffix.lower() in ('.tex', '.bib', '.sty', '.cls'):
            backup = BEFORE / rel
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, backup)

record = {'root': str(ROOT), 'files': files,
          'pdfs': {p.name: sha(p) for p in ROOT.glob('*.pdf')}}
(OUT / 'original-manifest.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'staged_files': len(files), 'original_pdfs': len(record['pdfs'])}))
