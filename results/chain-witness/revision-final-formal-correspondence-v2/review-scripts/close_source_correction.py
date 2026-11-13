"""Finish the regression fixture and record the precise corrected release."""
from pathlib import Path
import json
import difflib
import shutil
from fl_forensics.canonical import sha256_file
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.preprocessing import derived_json_bytes

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-formal-correspondence-v2'
record=json.loads((out/'source-correction.json').read_bytes())
p=repo/'tests/test_campaign_derivation.py';text=p.read_text()
assert text.count('from unittest.mock import patch\n')==1
text=text.replace('from unittest.mock import patch\n','')
text=text.replace('''    def _assert_separate_bundle_origins(self, case, accepted_case):
        self.assertEqual(case._verify()["status"], "verified")''','''    def _assert_separate_bundle_origins(self, case, accepted_case):
        self.assertEqual(accepted_case._verify()["status"], "verified")
        self.assertEqual(case._verify()["status"], "verified")''')
p.write_text(text)
diff=[]
for name,item in record['source_changes'].items():
    item['after_sha256']=sha256_file(repo/name)
    diff.extend(difflib.unified_diff((out/'pre-fix'/name).read_text().splitlines(keepends=True),(repo/name).read_text().splitlines(keepends=True),fromfile='a/'+name,tofile='b/'+name))
record['after_implementation_sha256']=implementation_sha256()
(out/'source-correction.json').write_bytes(derived_json_bytes(record));(out/'submission-occurrence-fix.patch').write_text(''.join(diff))
for p in (repo/'src/fl_forensics').glob('*.py'):
    dest=lab/'corrected-source/fl_forensics'/p.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy(p,dest)
print('CORRECTED SOURCE SNAPSHOT',record['after_implementation_sha256'],flush=True)
