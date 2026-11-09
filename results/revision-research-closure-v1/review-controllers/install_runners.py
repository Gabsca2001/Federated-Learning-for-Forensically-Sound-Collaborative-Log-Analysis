"""Install reviewable WSL-native study entry points and their shared helpers."""
from pathlib import Path
import hashlib
import json

out=Path(__file__).parent
repo=Path.cwd()
dest=repo/'scripts'
records=[]

def install(name,text):
    p=dest/name
    assert not p.exists(),p
    p.write_text(text)
    records.append({'path':p.relative_to(repo).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})

s=(out.parent/'state-conditioned-detector-20261103/study_data.py').read_text()
install('revision_study_data.py',s)
s=(out.parent/'geometry-detector-20261103/policy_data.py').read_text().replace('from study_data import','from revision_study_data import')
install('revision_policy_data.py',s)
s=(out.parent/'group-validation-20261103/group_common.py').read_text()
start=s.index('def read(')
header='''"""Observable-only group input construction and pinned array loading."""
from pathlib import Path
import json
import numpy as np
from revision_dba_experiment import save,evaluate
from fl_forensics.canonical import sha256_file,sha256_bytes
from fl_forensics.preprocessing import derived_json_bytes
from fl_forensics.federated_model import arrays_from_export
from fl_forensics.byzantine import model_delta,update_indicators

'''
install('revision_group_observables.py',header+s[start:])
s=(out.parent/'bounded-influence-20261104/common.py').read_text()
s=s.replace("sys.path[:0]=[str(out.parent/'state-conditioned-detector-20261103'),str(out.parent/'geometry-detector-20261103')]",'')
s=s.replace('from policy_data import','from revision_policy_data import')
install('revision_containment_common.py',s)

for original,name in [('gradient_study.py','revision_native_gradient_study.py'),
                      ('group_study.py','revision_group_completion.py'),
                      ('group_interventions.py','revision_group_interventions.py'),
                      ('robust_study.py','revision_robust_containment_study.py')]:
    s=(out/original).read_text()
    s=s.replace("sys.path[:0] = [str(OUT.parent / 'state-conditioned-detector-20261103')]",'')
    s=s.replace("sys.path[:0]=[str(OUT.parent/'state-conditioned-detector-20261103'),str(OUT.parent/'group-validation-20261103')]",'')
    s=s.replace("sys.path[:0]=[str(OUT.parent/'state-conditioned-detector-20261103'),str(OUT.parent/'geometry-detector-20261103')]",'')
    s=s.replace("sys.path.insert(0,str(out.parent/'bounded-influence-20261104'))",'')
    s=s.replace('from study_data import','from revision_study_data import')
    s=s.replace('from policy_data import','from revision_policy_data import')
    s=s.replace('from group_common import','from revision_group_observables import')
    s=s.replace('import common as shared','import revision_containment_common as shared')
    s=s.replace('from common import','from revision_containment_common import')
    s=s.replace("out.parent/'bounded-influence-20261104/common.py'", "out/'revision_containment_common.py'")
    install(name,s)

(out/'installed-wsl-runners.json').write_text(json.dumps({'files':records,
 'note':'Portable original-WSL entry points remove dependence on Windows output helper locations. Already running studies retain their frozen original creator-controller bytes; no historical run is relabelled as produced by these imports.'},indent=2)+'\n')
print(json.dumps({'installed_WSL_scripts':len(records)}))
