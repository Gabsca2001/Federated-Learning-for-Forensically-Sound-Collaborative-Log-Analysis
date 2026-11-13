"""Close the publication only after report and figure inspection."""
import os
for name in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):os.environ[name]='1'
from pathlib import Path
import sys,json,shutil,hashlib
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');sys.path.insert(0,str(R/'scripts'))
import revision_episode_attribution as study
from revision_study_data import read
from revision_dba_experiment import save,authenticate
O=Path(__file__).parent;D=study.D
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()

p=read(D/'protocol-before-training.json');study.check(p)
assert read(D/'summary.json')['status']=='verified_v5_separated_episode_assessment'
assert sha(O/'analyze_episode.py')==read(D/'report-before-accounting.json')['reporter_sha256']
assert sha(O/'verify_episode.py')==read(D/'verification-definition-before-replay.json')['verifier_sha256']
layout=read(D/'figure-layout-review.json');interpretation=read(D/'group-interpretation.json')
assert layout['source_summary_sha256']==interpretation['source_summary_sha256']==sha(D/'summary.json')
assert layout['reviewed_figure_sha256']==sha(D/'episode-origin-recovery.png')
assert layout['layout_script_sha256']==sha(O/'refine_figures.py')
assert interpretation['source_branch_table_sha256']==sha(D/'origin-branches.csv')
assert interpretation['interpreter_sha256']==sha(O/'interpret_episode.py')
authenticate(D/'source-evidence',read(D/'source-closure.json')['manifest_sha256'])
authenticate(D/'recovery-evidence',read(D/'recovery-closure.json')['manifest_sha256'])
assert not (D/'file-checksums.json').exists() and not (O/'published').exists()
for name in ('build_study.py','resume_assessment.py','verify_episode.py','analyze_episode.py','publish_episode.py','refine_figures.py','interpret_episode.py',
             'tests.log','calibration.log','assessment.log','resume.log','plan.log','recovery.log','verify.log','analysis.log','figure-review.log','interpretation.log'):
    shutil.copy2(O/name,D/name)
sources=D/'sources';sources.mkdir()
for name in ('revision_episode_attribution.py','episodic_attribution_groups.py'):
    shutil.copy2(R/'scripts'/name,sources/name)
shutil.copy2(R/'tests/test_episodic_attribution_groups.py',sources/'test_episodic_attribution_groups.py')
save(D/'source-integrity.json',dict(measured_core_sha256=study.prior.implementation_sha256(),
    predecessor_publications_unchanged=True,diagnostic_publication_unchanged=True,defaults_changed=False,
    thesis_changed=False,numerical_protocol_changed_on_resume=False))
pins={str(f.relative_to(D)):sha(f) for f in D.rglob('*') if f.is_file()}
save(D/'file-checksums.json',pins);shutil.copytree(D,O/'published')
assert all(sha(O/'published'/n)==h for n,h in pins.items())
assert sha(D/'file-checksums.json')==sha(O/'published/file-checksums.json')
save(O/'final-storage-check.json',dict(status='verified_and_mirrored',**study.guard()))
print(json.dumps(read(O/'final-storage-check.json'),indent=2))
