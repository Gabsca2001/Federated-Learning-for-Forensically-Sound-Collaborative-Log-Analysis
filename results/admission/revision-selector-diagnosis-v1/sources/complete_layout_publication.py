"""Preserve the write-once pre-layout index, then close the final presentation."""
from pathlib import Path
import sys,json,shutil,hashlib
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;sys.path.insert(0,str(R/'scripts'))
import revision_selector_diagnosis as study
from revision_study_data import read
from revision_dba_experiment import save,authenticate
D=study.D;M=O/'published'
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
record=read(D/'layout-finalization.json')
assert sha(D/'file-checksums.json')==record['initial_publication_index_sha256']
assert sha(D/'false-client-channels.png')==record['final_plot_sha256']
assert sha(O/'layout-review/initial-false-client-channels.png')==record['initial_plot_sha256']
authenticate(D/'evidence',read(D/'closure.json')['manifest_sha256'])
for base in (D,M):
    archive=base/'layout-review';archive.mkdir()
    source=base/'file-checksums.json';dest=archive/'initial-file-checksums.json'
    assert source.resolve().is_relative_to(base.resolve()) and dest.resolve().is_relative_to(base.resolve())
    source.rename(dest)
    shutil.copy2(O/'layout-review/initial-false-client-channels.png',archive/'initial-false-client-channels.png')
shutil.copy2(__file__,D/'sources/complete_layout_publication.py')
save(D/'publication-finalization.json',dict(layout_only=True,numerical_evidence_changed=False,
    finalizer_sha256=sha(Path(__file__)),initial_index_preserved='layout-review/initial-file-checksums.json',
    prior_renderer_sha256=sha(O/'finalize_layout.py'),evidence_manifest_sha256=sha(D/'evidence/manifest.json')))
shutil.copy2(D/'sources/complete_layout_publication.py',M/'sources/complete_layout_publication.py')
shutil.copy2(D/'publication-finalization.json',M/'publication-finalization.json')
pins={str(f.relative_to(D)):sha(f) for f in D.rglob('*') if f.is_file()}
save(D/'file-checksums.json',pins);shutil.copy2(D/'file-checksums.json',M/'file-checksums.json')
assert all(sha(D/n)==h and sha(M/n)==h for n,h in pins.items())
study.check(read(D/'protocol-before-diagnosis.json'))
(O/'final-storage-check.json').write_text(json.dumps(dict(status='verified_and_mirrored_after_visual_QA',**study.guard()))+'\n')
print('Final presentation verified; original numerical evidence and initial index preserved.')
