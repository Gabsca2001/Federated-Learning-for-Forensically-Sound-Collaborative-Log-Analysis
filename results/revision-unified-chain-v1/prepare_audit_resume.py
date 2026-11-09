"""Retain completed checks and correct the harness's report artifact locator."""
from pathlib import Path
OUT=Path(__file__).parent
original=(OUT/'audit_final.py').read_text()
header=original[:original.index("assert load_json(LAB/'unified-validation.json')")]
verification=original[original.index('def verify_archive('):original.index('relocated=verify_archive(')]
tail=original[original.index('# Audit actual signer chains/CRLs'):]
middle=r'''
assert implementation_sha256()=='8d7efa28b62a47d306a12958d66b3081d6527518f25641545cc81456640d2e64'
assert DEST.is_dir()
public=LAB/'public-chain'
scratch=LAB/'audit-scratch'
mutants=LAB/'audit-mutants'
recovery=DEST/'recovery'
pins=load_json(recovery/'retained-pins.json')
assert sha256_file(recovery/'recovery.tar')==pins['archive_sha256']
relocated=load_json(DEST/'relocated-offline-verification.json')
assert relocated['status']=='verified_unified_recovery'
assert load_json(DEST/'wrong-closure-pin-rejected.json')['status']=='invalid'
m7=load_json(DEST/'actual-M7-negative-controls.json')
assert m7['actual_witness_M7_checkpoint_verified'] and all(x['rejected'] for x in m7['negatives'].values())
def docker(arguments):
    return subprocess.run(['docker',*arguments],text=True,capture_output=True,check=False)
inspected=docker(['image','inspect',IMAGE])
assert inspected.returncode==0
image=json.loads(inspected.stdout)[0]
bindings=load_json(DEST/'measured-runtime-bindings.json')
assert image['Id']==bindings['image_id']
for relative,digest in bindings['measured_files'].items():assert sha256_file(REPO/relative)==digest
'''
mutation=r'''
bad=mutants/'modified-recovery.tar'
assert bad.resolve().is_relative_to(mutants.resolve())
assert sha256_file(bad)==pins['archive_sha256']
with tarfile.open(bad,'r:') as archive:
    member=archive.getmember('payload/products/report/investigation-report.json')
    offset=member.offset_data+min(100,member.size-1)
with bad.open('r+b') as handle:
    handle.seek(offset);old=handle.read(1);handle.seek(offset);handle.write(b'X' if old!=b'X' else b'Y')
verify_archive(bad,pins['closure_sha256'],'actual-report-payload-mutation-rejected',False)
assert sha256_file(recovery/'recovery.tar')==pins['archive_sha256']
'''
target=OUT/'complete_audit_resume.py'
assert not target.exists()
target.write_text(header+middle+'\n'+verification+mutation+'\n'+tail)
print(str(target))
