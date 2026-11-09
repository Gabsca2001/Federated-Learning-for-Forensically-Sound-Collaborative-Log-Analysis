"""Refresh source bindings without rewriting historical proof or experiment identities."""
from pathlib import Path
import ast
import copy
import hashlib
import json
import zipfile

from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.canonical import sha256_file

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-research-closure-v1'
oldpath=repo/'results/revision-final-formal-correspondence-v2/property-code-evidence-matrix.json'
old=json.loads(oldpath.read_bytes());rows=copy.deepcopy(old['properties'])
def node_for(path,name):
    tree=ast.parse(path.read_text());nodes={}
    def visit(node,prefix=''):
        for item in ast.iter_child_nodes(node):
            if isinstance(item,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
                key=prefix+item.name;nodes[key]=item;visit(item,key+'.')
    visit(tree);return nodes[name]
def bind(path,name,previous=None):
    p=repo/path;n=node_for(p,name);h=hashlib.sha256(ast.dump(n,include_attributes=False).encode()).hexdigest()
    return {'path':path,'function':name,'line':n.lineno,'end_line':n.end_lineno,
      'source_sha256':sha256_file(p),'function_AST_sha256':h,
      'local_AST_equal_to_previous_matrix':h==previous['function_AST_sha256'] if previous else None}
changed=[]
for row in rows:
    row['historical_evidence_ids']=row.pop('evidence_ids',[])
    row['previous_test_source_sha256']=row.get('test_source_sha256',{})
    row['test_source_sha256']={n:sha256_file(repo/'tests'/n) for n in row['previous_test_source_sha256']}
    row['evidence_ids']=['current-suite']
    for key in ('implementation','verifiers'):
        if key not in row:continue
        current=[]
        for item in row[key]:
            entry=bind(item['path'],item['function'],item)
            if not entry['local_AST_equal_to_previous_matrix']:changed.append({'property':row['id'],'role':key,**entry})
            current.append(entry)
        row[key]=current
new=[('ROBUST','Finite deterministic convex combination of clipped deltas; alpha and beta remain distinct.',
      'Fixed base/limits/admitted masses, representable finite arithmetic, declared smoothing/iteration cap and export. Frozen-final-beta removal bound requires survivor quorum; no dynamic reweighting/ASR theorem.',
      [('src/fl_forensics/robust_bounded_aggregation.py','aggregate_robust_bounded')],
      [('src/fl_forensics/robust_bounded_aggregation.py','verify_robust_bounded')]),
     ('LIVE-ROBUST','Actual runtime matches the separately named robust transformation and binds original bundles, derived report and graph.',
      'Full receipt/admission/Quote reconstruction, named opt-in profile, bounds/reference identity, original signed inputs and measured release. Software TPMs on one host; no external time/delivery guarantee.',
      [('src/fl_forensics/live_bounded_aggregation.py','backend'),('src/fl_forensics/live_bounded_aggregation.py','materialize')],
      [('src/fl_forensics/in_round_admission.py','verify_in_round_secure_round')]),
     ('GROUP-V3','Separately clean-calibrated pair/triple investigation hypotheses with measured false/missed members.',
      'Fixed observable inputs, disjoint fit/calibration/evaluation roles. No universal recovery, intent, significance or automatic-exclusion guarantee.',
      [('src/fl_forensics/group_calibration_v3.py','detect_tree_groups')],
      [('src/fl_forensics/group_calibration_v3.py','detect_tree_groups')])]
for ident,claim,boundary,impl,verifiers in new:
    rows.append({'id':ident,'claim':claim,'boundaries':boundary,
      'implementation':[bind(*x) for x in impl],'verifiers':[bind(*x) for x in verifiers]})
for row in rows[-3:]:
    row['evidence_ids']=['current-suite','robust-replay' if row['id']!='GROUP-V3' else 'group-replay']
    row['test_source_sha256']={n:sha256_file(repo/'tests'/n) for n in ('test_research_extensions.py','test_live_robust.py')}
with zipfile.ZipFile(lab/'source-before.zip') as z:
    names=z.namelist()
    prefix=next(n[:n.index('src/fl_forensics/')] for n in names if 'src/fl_forensics/' in n)
    oldfiles={n[len(prefix):]:hashlib.sha256(z.read(n)).hexdigest() for n in names if n.startswith(prefix+'src/fl_forensics/') and n.endswith('.py')}
    module_changes=[p.relative_to(repo).as_posix() for p in sorted((repo/'src/fl_forensics').glob('*.py'))
                    if oldfiles.get(p.relative_to(repo).as_posix())!=sha256_file(p)]
record={'profile':'incremental-property-code-evidence-correspondence-20261104',
 'implementation_sha256':implementation_sha256(),'previous_matrix_sha256':sha256_file(oldpath),
 'previous_119_source':'4b58e1590179dbaa37c8e9760b94bd57549db6c3a228e95f00ee2def26012bbb',
 'changed_package_modules_since_119':module_changes,'changed_function_bindings_since_114_matrix':changed,
 'properties':rows,'historical_evidence':old['evidence'],
 'incremental_review':'Only two new numerical/selection modules and three profile-routing/schema modules differ from the preceding 119-module source. Reviewed finite reweighting, distinct input/final coefficients, opt-in profile selection, reference/mode validation, actual backend/report agreement, graph binding and historical-label preservation. Earlier AST differences from the 114-file matrix belong to the separately documented envelope/bounded integrations; they are flagged rather than declared identical.',
 'proof_scope':'Manual conditional arguments; source/AST binding is not proof of transitive equivalence or independent verification. Original FedAvg proof remains scoped to untransformed FedAvg. Bounded and robust transformations have explicit separate convexity/frozen-weight arguments and runtime replay evidence.',
 'evidence':{n.removesuffix('.json') if n!='full-tests-live-release.log' else 'current-suite':{'path':str(lab/n),'sha256':sha256_file(lab/n)} for n in ('native-gradient-replay.json','group-replay.json','shared-gradient-replay.json','robust-replay.json','sequential-benchmark.json','full-tests-live-release.log')}}
for p in (lab/'current-property-bindings.json',out/'current-property-bindings.json'):
    p.write_text(json.dumps(record,indent=2)+'\n')
def ref(item):return f"`{item['path']}:{item['line']}` (`{item['function']}`)"
text=['# Current property/source/verifier correspondence','',
      f"Source: `{implementation_sha256()}`. Historical proof/evidence identities remain in the JSON ledger; this refresh does not re-sign or relabel their releases.",'',
      '| Property | Claim and hypothesis boundary | Implementation | Verifier | Current evidence |',
      '|---|---|---|---|---|']
for row in rows:
    claim=row.get('statement',row.get('claim',''))+' '+row.get('assumptions','')+' '+row['boundaries']
    text.append('| '+row['id']+' | '+claim.replace('|','\\|')+' | '+'; '.join(map(ref,row['implementation']))+' | '+'; '.join(map(ref,row['verifiers']))+' | '+', '.join(row['evidence_ids'])+' |')
text.extend(['',record['proof_scope'],'',record['incremental_review'],''])
for p in (lab/'current-property-bindings.md',out/'current-property-bindings.md'):p.write_text('\n'.join(text))
print(json.dumps({'properties':len(rows),'changed_modules':module_changes,'changed_historical_function_bindings':len(changed)}))
