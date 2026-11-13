"""Capture the original source state and inspect public dataset metadata."""
from pathlib import Path
import hashlib
import json
import subprocess
import urllib.request
import zipfile

ROOT = Path.cwd()
OUT = Path(__file__).parent
LAB = ROOT / 'artifacts/revision-research-closure-v1'
LAB.mkdir(exist_ok=False)

def h(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

source = {p.as_posix(): h(p) for top in ('src', 'scripts', 'tests', 'configs')
          for p in sorted(Path(top).rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
(LAB / 'original-source-files.json').write_text(json.dumps(source, indent=2) + '\n')
(LAB / 'git-status-before.txt').write_bytes(subprocess.check_output(['git', 'status', '--porcelain=v1', '-b']))
with zipfile.ZipFile(LAB / 'source-before.zip', 'x', zipfile.ZIP_DEFLATED) as z:
    for name in source:
        z.write(name, name)
print(json.dumps({'source_files_preserved': len(source), 'source_archive_sha256': h(LAB / 'source-before.zip')}), flush=True)

urls = {
    'zenodo-metadata': 'https://zenodo.org/api/records/19367312',
    'hf-catalog': 'https://huggingface.co/api/datasets?search=ton_iot&limit=20',
}
for name, url in urls.items():
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'Academic dataset compatibility study'})
        with urllib.request.urlopen(request, timeout=35) as r:
            body = r.read()
        (LAB / f'{name}.json').write_bytes(body)
        data = json.loads(body)
        if name == 'zenodo-metadata':
            summary = [{'key': f['key'], 'size': f['size'], 'links': f['links']} for f in data['files']]
        else:
            summary = [x['id'] for x in data]
        print(json.dumps({'source': name, 'summary': summary}), flush=True)
    except Exception as e:
        (LAB / f'{name}-access-error.json').write_text(json.dumps({'url': url, 'error': str(e)}) + '\n')
        print(json.dumps({'source': name, 'error': str(e)}), flush=True)
