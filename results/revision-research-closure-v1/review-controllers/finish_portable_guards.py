"""Fail a future portable search if even its explicit zero fallback is invalid."""
from pathlib import Path
import ast
import hashlib
import json

repo=Path.cwd();out=Path(__file__).parent;p=repo/'scripts/revision_native_gradient_study.py'
s=p.read_text();old='            candidates = allowed or candidates'
assert s.count(old)==1
s=s.replace(old,"""            if not allowed:
                failure = {'round':number,'reason':'No utility-admissible candidate and no finite zero-factor fallback.',
                           'queries_sha256':sha256_file(prefix/'queries.json')}
                save(prefix/'terminal-failure.json',failure)
                break
            candidates = allowed""")
ast.parse(s);p.write_text(s)
record=json.loads((out/'portable-entrypoints-final.json').read_bytes())
for entry in record:
    if entry['path']==p.relative_to(repo).as_posix():entry['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
(out/'portable-entrypoints-final.json').write_text(json.dumps(record,indent=2)+'\n')
print('Future portable search enforces its fallback contract; retained creator outcomes satisfy the declared guard.')
