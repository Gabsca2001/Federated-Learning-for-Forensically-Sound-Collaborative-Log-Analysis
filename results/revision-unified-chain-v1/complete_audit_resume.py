"""Real-data negatives, exact source/measurement bindings and relocated recovery."""
from pathlib import Path
from datetime import UTC,datetime
import base64,json,os,shutil,subprocess,tarfile,zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fl_forensics.canonical import sha256_file
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.storage import load_json,write_json_once
from fl_forensics.timestamp_anchor import _extract_certificates
from fl_forensics.witness_models import WitnessSnapshot,TimestampEvidence

OUT=Path(__file__).parent
REPO=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
LAB=REPO/'artifacts/revision-unified-chain-20261105-v2'
DEST=REPO/'results/revision-unified-chain-v1'
IMAGE='revision-unified-chain:20261105-v2'
uid=f'{os.getuid()}:{os.getgid()}'

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

def verify_archive(path,pin,name,valid):
    args=['run','--rm','--network','none','--read-only','--cap-drop','ALL','--user',uid,
        '--env','TMPDIR=/scratch','--tmpfs','/tmp:rw,size=256m','-v',str(path)+':/recovery.tar:ro',
        '-v',str(scratch)+':/scratch',IMAGE,'-m','fl_forensics','m8-unified-verify','--archive','/recovery.tar',
        '--expected-closure-sha256',pin]
    p=docker(args)
    assert (p.returncode==0)==valid,(name,p.stdout,p.stderr)
    report=json.loads(p.stdout)
    write_json_once(DEST/(name+'.json'),report)
    write_json_once(DEST/(name+'-command.json'),{'arguments':['docker',*args]})
    return report


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

# Audit actual signer chains/CRLs for every new witness token and final M8 token.
authenticated=OUT.parent/'witness-external-20261105/sectigo-authenticated'
root=x509.load_pem_x509_certificate((authenticated/'tsa-trust-store.pem').read_bytes())
assert root.fingerprint(hashes.SHA256()).hex()=='f871f8976b4068d700d5f281084b4a29eaf4b8f35743330ba062fab46f58c2ed'
crls=[x509.load_der_x509_crl((authenticated/name).read_bytes()) for name in ('signer.crl','issuer.crl')]
snapshot=WitnessSnapshot.model_validate(load_json(public/'witness/snapshot.json'))
tokens=[e.timestamp for e in snapshot.registrations]+[snapshot.closure.timestamp,TimestampEvidence.model_validate(load_json(recovery/'timestamp.json'))]
now=datetime.now(UTC);signers=set()
for evidence in tokens:
    certificates=x509.load_pem_x509_certificates(_extract_certificates(base64.b64decode(evidence.response_b64)))
    leaf=next(c for c in certificates if not c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    intermediate=next(c for c in certificates if c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    for cert,issuer in ((leaf,intermediate),(intermediate,root)):
        cert.verify_directly_issued_by(issuer)
        assert cert.not_valid_before_utc<=now<=cert.not_valid_after_utc
        crl=next(c for c in crls if c.issuer==issuer.subject)
        assert crl.is_signature_valid(issuer.public_key()) and crl.last_update_utc<=now<=crl.next_update_utc
        assert crl.get_revoked_certificate_by_serial_number(cert.serial_number) is None
    signers.add(leaf.fingerprint(hashes.SHA256()).hex())
assert len(tokens)==17
authority=DEST/'external-authority';authority.mkdir()
for name in ('root.crt','tsa-trust-store.pem','signer.crl','issuer.crl','crls.pem'):
    shutil.copyfile(authenticated/name,authority/name)
write_json_once(authority/'current-chain-audit.json',{'token_count':17,'signer_certificate_sha256':sorted(signers),
    'signature_and_deadline_checks':'full witness/M7/system/M8 verifiers','CRL_check_as_of':now.isoformat(),
    'future_revocation_or_archival_validation_guarantee':False})

for name in ('integration-reports','integration-logs'):
    shutil.copytree(LAB/name,DEST/name)
for name in ('unified-validation.json','protocol.json','source-manifest.json','runtime-image.json'):
    shutil.copyfile(LAB/name,DEST/name)
shutil.copyfile(OUT/'SYSTEM_MODEL.md',DEST/'SYSTEM_MODEL.md')
shutil.copyfile(OUT/'full-tests-final.txt',DEST/'full-tests.txt')
shutil.copyfile(OUT/'focused-tests-final.txt',DEST/'focused-tests.txt')
source=REPO/'artifacts/revision-unified-build-20261105-v2'
with zipfile.ZipFile(DEST/'executed-source-release.zip','w',zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(source.rglob('*')):
        if path.is_file():archive.write(path,path.relative_to(source).as_posix())
    for name in ('revision_unified_products_v2.py','revision_unified_products_v2_retry.py'):
        archive.write(REPO/'scripts'/name,'executed-publishers/'+name)
result={'status':'verified_unified_model_and_representative_chain','profile':'unified-witnessed-fedavg-v1',
    'implementation_sha256':implementation_sha256(),'core_modules':130,'image_id':image['Id'],
    'full_tests_passed':773,'existing_dependency_warnings':2,'new_tests':21,'focused_tests_passed':35,
    'rounds':1,'clients':15,'newly_TPM_signed_submissions':15,'new_external_TSA_tokens_in_final_case':17,
    'M7_cases':2,'all_four_M7_product_types_created_and_recomputed':True,'M7_actual_negative_controls_rejected':3,
    'M8_verified_stages':relocated['verified_stages'],'archive_bytes':(recovery/'recovery.tar').stat().st_size,
    'archive_sha256':pins['archive_sha256'],'closure_sha256':pins['closure_sha256'],
    'relocated_offline_reconstruction':True,'original_source_workspaces_or_private_keys_mounted_for_recovery':False,
    'actual_TAR_report_payload_mutation_rejected':True,'full_measured_source_matches_image_and_host':True,
    'administrative_independence_demonstrated':False,'source_record_coverage_replayed':False,
    'attack_resistance_evaluated':False,'global_artifact_completeness_verified':False,
    'publisher_TPM_measured':False,'thesis_edited':False,
    'preliminary_v1_M5_pilot':'Separate preserved e9171187 release; not counted as final full-chain case.',
    'preserved_runtime_interruption':'Docker bridge endpoint creation failed before M8 ran; resumed with host networking for final TSA only. No WSL restart or old server reset.'}
write_json_once(DEST/'validation.json',result)
write_json_once(OUT/'validation.json',result)
print(json.dumps(result,indent=2))
