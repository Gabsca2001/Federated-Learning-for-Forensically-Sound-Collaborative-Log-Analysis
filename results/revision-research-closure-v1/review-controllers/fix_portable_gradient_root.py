"""Keep the portable attack contract independent of the output directory name."""
from pathlib import Path
import ast
import hashlib
import json

repo=Path.cwd();out=Path(__file__).parent;p=repo/'scripts/revision_native_gradient_study.py'
s=p.read_text()
old="if active and (root.name.endswith('development-v3') or root.name.endswith('evaluation')):"
assert s.count(old)==1
s=s.replace(old,'if active:')
old="if active and root.name != 'native-gradients-development':"
assert s.count(old)==1;s=s.replace(old,'if active:')
ast.parse(s);p.write_text(s)
assert 'root.name' not in s
record=json.loads((out/'portable-entrypoints-final.json').read_bytes())
for entry in record:
    if entry['path']==p.relative_to(repo).as_posix():entry['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
(out/'portable-entrypoints-final.json').write_text(json.dumps(record,indent=2)+'\n')
print('Portable gradient contract no longer depends on the destination basename; historical creator unchanged.')
