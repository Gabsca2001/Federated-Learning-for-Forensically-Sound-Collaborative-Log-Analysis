"""Check the preserved attested case for the newly discovered alias condition."""
from pathlib import Path
import ast
import json
import shutil
from collections import Counter
from fl_forensics.canonical import sha256_file
from fl_forensics.preprocessing import derived_json_bytes

repo=Path.cwd();out=Path(__file__).parent;case=out.parent/'attack-replay-20261103'
closure=json.loads((case/'case-closure.json').read_bytes())
assert sha256_file(case/'case-closure.json')=='f265b12d1d331cdf913eb2c21eab4555684ed79550ab0fd6630bec07d5d6759c'
assert sha256_file(case/'graph-manifest.json')==closure['core']['graph_manifest_sha256']
graph=json.loads((case/'graph-manifest.json').read_bytes())['core']
origins=[(sid,node) for r in graph['rounds'] for sid,node in r['submissions'].items()]
counts=Counter(node for sid,node in origins)
result={'profile':'historical-submission-content-alias-survey-v1','source_graph_sha256':closure['core']['graph_manifest_sha256'],
    'submission_occurrences':len(origins),'distinct_bundle_origin_nodes':len(counts),
    'nodes_shared_by_distinct_submissions':{n:c for n,c in counts.items() if c>1},
    'scope':'The retained attested case only; not an exhaustive survey of every historical artifact.'}
assert len({sid for sid,node in origins})==len(origins)
assert not result['nodes_shared_by_distinct_submissions']
(out/'historical-occurrence-scope.json').write_bytes(derived_json_bytes(result))
if (out/'pre-fix/source-function-index.json').exists():
    assert sha256_file(out/'pre-fix/source-function-index.json')==sha256_file(out/'source-function-index.json')
else:shutil.copy(out/'source-function-index.json',out/'pre-fix/source-function-index.json')
index={}
for p in (repo/'src/fl_forensics').glob('*.py'):
    items={}
    for n in ast.parse(p.read_text()).body:
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):items[n.name]=n.lineno
        elif isinstance(n,ast.ClassDef):
            for m in n.body:
                if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)):items[n.name+'.'+m.name]=m.lineno
    index[p.relative_to(repo).as_posix()]=items
(out/'corrected-source-function-index.json').write_bytes(derived_json_bytes(index))
print('HISTORICAL CASE OCCURRENCE SURVEY',json.dumps(result),flush=True)
