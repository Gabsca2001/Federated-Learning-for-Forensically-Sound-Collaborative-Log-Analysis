"""Finish public-artifact audit, signature-only forgery and actual TLS probes."""
from pathlib import Path
from datetime import UTC,datetime,timedelta
import json,os,re,shutil,subprocess,time

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from fl_forensics.canonical import sha256_file
from fl_forensics.secure_round import _coordinator_signer
from fl_forensics.storage import load_json,write_json_once
from fl_forensics.submission_evidence import _signature
from fl_forensics.submission_evidence_models import SubmissionReceipt

OUT=Path(__file__).parent
REPO=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
LAB=REPO/'artifacts/revision-witness-operations-20261105-v1'
PUBLIC=REPO/'results/revision-witness-operations-v1'
ORIGINAL=REPO/'artifacts/revision-external-tsa-20261105-v2'
IMAGE='revision-witness-round:20261105-v2'
uid=f'{os.getuid()}:{os.getgid()}'
NAME='witness-operations-tls-20261105-v1'
snapshot=load_json(ORIGINAL/'public-witness/snapshot.json')
coordinator=_coordinator_signer(ORIGINAL/'cases/external-sectigo/round',create=False,coordinator_workspace=ORIGINAL/'coordinator')
forged=json.loads(json.dumps(snapshot['registrations'][0]['receipt']))
forged['signature']=_signature(coordinator,forged['core_digest'],'swtpm').model_dump(mode='json')
SubmissionReceipt.model_validate(forged)
assert {k:v for k,v in forged.items() if k!='signature'}=={k:v for k,v in snapshot['registrations'][0]['receipt'].items() if k!='signature'}
probes=LAB/'public-probes'
if not (probes/'signature-only-forgery.json').exists():
    write_json_once(probes/'signature-only-forgery.json',forged)
else:
    retained=load_json(probes/'signature-only-forgery.json')
    assert retained['core']==forged['core'] and retained['signature']['key_id']==forged['signature']['key_id']

def command(arguments,expected=0):
    p=subprocess.run(['docker',*arguments],text=True,capture_output=True)
    assert p.returncode==expected,(arguments,p.stdout,p.stderr)
    return p.stdout

image=json.loads(command(['image','inspect',IMAGE]))[0]
entrypoint=image['Config']['Entrypoint']
# Deliberately local development TLS certificates; no trusted public issuance
# or independent ownership is implied by their use here.
tls=LAB/'development-tls-v2';tls.mkdir(mode=0o700)
now=datetime.now(UTC)
ca_key=ec.generate_private_key(ec.SECP256R1())
ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Witness operations local test CA')])
ca=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(ca_key,hashes.SHA256())
key=ec.generate_private_key(ec.SECP256R1())
leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(ca_key,hashes.SHA256())
for name,data in [('ca.pem',ca.public_bytes(serialization.Encoding.PEM)),('server.pem',leaf.public_bytes(serialization.Encoding.PEM)),('server-private.pem',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))]:
    fd=os.open(tls/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as handle:handle.write(data)
insecure=json.loads(command(['run','--rm','--network','none','--read-only','--cap-drop','ALL','--user',uid,IMAGE,
    '-m','fl_forensics','witness-serve','--state','/deliberately-not-mounted','--host','0.0.0.0'],expected=1))
assert any('require TLS' in error for error in insecure['errors'])
write_json_once(PUBLIC/'remote-plaintext-listener-rejected.json',insecure)
probe=r'''
import json,socket,ssl,urllib.request,urllib.error
from pathlib import Path
ctx=ssl.create_default_context(cafile='/tls/ca.pem')
url='https://localhost:9443'
with urllib.request.urlopen(url+'/snapshot',context=ctx,timeout=10) as r:
    actual=json.load(r)
assert actual==json.loads(Path('/probes/expected-snapshot.json').read_text())
bad=json.loads(Path('/probes/signature-only-forgery.json').read_text())
try:
    urllib.request.urlopen(urllib.request.Request(url+'/receipts',data=json.dumps(bad).encode(),headers={'Content-Type':'application/json'}),context=ctx,timeout=10)
except urllib.error.HTTPError as e:
    assert e.code==409
    error=json.load(e)
    assert error['error']=='invalid authenticated client receipt'
else:raise AssertionError('coordinator signature accepted as client signature')
rejected=[]
for label,context,hostname in [('wrong-hostname',ctx,'wrong.invalid'),('untrusted-CA',ssl.create_default_context(),'localhost')]:
    try:
        with socket.create_connection(('127.0.0.1',9443),timeout=10) as sock:
            with context.wrap_socket(sock,server_hostname=hostname):pass
    except ssl.SSLCertVerificationError:rejected.append(label)
    else:raise AssertionError('invalid TLS peer accepted')
assert len(rejected)==2
print(json.dumps({'trusted_development_TLS_snapshot_verified':True,'snapshot_identical':True,'signature_only_coordinator_forgery_rejected':True,'rejected_TLS_peers':rejected,'network_mode':'none','development_certificate_only':True}))
'''
created=False
try:
    command(['run','-d','--name',NAME,'--network','none','--read-only','--cap-drop','ALL','--user',uid,
        '--security-opt','no-new-privileges','--tmpfs','/tmp:rw,size=64m',
        '-v',str(LAB/'service-state')+':/state:rw','-v',str(tls)+':/tls:ro','-v',str(probes)+':/probes:ro',IMAGE,
        '-u','-m','fl_forensics','witness-serve','--state','/state','--host','0.0.0.0','--port','9443',
        '--tls-cert','/tls/server.pem','--tls-private-key','/tls/server-private.pem'])
    created=True
    result=None
    for _ in range(80):
        p=subprocess.run(['docker','exec','--user',uid,NAME,*entrypoint,'-c',probe],text=True,capture_output=True)
        if p.returncode==0:
            result=json.loads(p.stdout);break
        time.sleep(.2)
    assert result is not None,p.stdout+p.stderr
    write_json_once(PUBLIC/'live-TLS-and-signature-only-forgery.json',result)
finally:
    if created:command(['stop',NAME])

# The preliminary controller's literal substring scan matched its own Python
# assertion, not PEM material. Preserve that failed run and use anchored PEM
# block recognition before declaring this audit complete.
pattern=re.compile(rb'^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----\s*$',re.MULTILINE)
private_blocks=[p.relative_to(PUBLIC).as_posix() for p in PUBLIC.rglob('*') if p.is_file() and pattern.search(p.read_bytes())]
assert not private_blocks,private_blocks
final=dict(load_json(OUT/'validation.json'),
    status='verified_operational_handover',
    signature_only_coordinator_forgery_rejected=True,
    development_TLS_round_trip_verified=True,
    wrong_TLS_hostname_and_untrusted_CA_rejected=True,
    nonloopback_plaintext_listener_rejected=True,
    actual_private_PEM_blocks_in_public_artifacts=False,
    initial_controller_exit='1: literal secret-marker scan matched its own retained source; operational checks had completed. This final anchored PEM-block audit and additional TLS/signature-only checks complete validation.',
    production_TLS_identity_or_administration_demonstrated=False,
    executing_operator_tool_is_TPM_measured=False)
write_json_once(OUT/'validation-final.json',final)
write_json_once(PUBLIC/'validation-final.json',final)
shutil.copyfile(__file__,PUBLIC/'executed-final-audit.py')
print(json.dumps(final,indent=2))
