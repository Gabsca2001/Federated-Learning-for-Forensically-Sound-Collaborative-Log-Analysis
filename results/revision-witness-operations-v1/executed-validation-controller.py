"""Actual process/permission/recovery checks over preserved external TSA evidence."""
from pathlib import Path
import json, os, shutil, sqlite3, subprocess, sys, time

from fl_forensics.canonical import digest_object,sha256_file
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.round_derivation import implementation_sha256
from fl_forensics.secure_round import _coordinator_signer
from fl_forensics.storage import load_json,write_json_once
from fl_forensics.submission_evidence import _signature
from fl_forensics.submission_witness_cli import open_store

OUT=Path(__file__).parent
REPO=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
ORIGINAL=REPO/'artifacts/revision-external-tsa-20261105-v2'
SOURCE=ORIGINAL/'private-witness'
LAB=REPO/'artifacts/revision-witness-operations-20261105-v1'
PUBLIC=REPO/'results/revision-witness-operations-v1'
TOOL=REPO/'scripts/witness_operator.py'
IMAGE='revision-witness-round:20261105-v2'
NAME='witness-operations-20261105-v1'
assert not LAB.exists() and not PUBLIC.exists()
LAB.mkdir(mode=0o700)
PUBLIC.mkdir(parents=True)
pins=load_json(ORIGINAL/'public-witness/external-pins.json')
snapshot=load_json(ORIGINAL/'public-witness/snapshot.json')
identity=implementation_sha256()
assert identity==load_json(ORIGINAL/'source-manifest.json')['implementation_sha256']
before={p.relative_to(SOURCE).as_posix():sha256_file(p) for p in SOURCE.rglob('*') if p.is_file()}
common=['--expected-policy-digest',pins['policy_digest'],'--expected-closure-digest',pins['closure_digest']]
for p in sorted((ORIGINAL/'public-witness').glob('*-ack.json')):common+=['--acknowledgement',str(p)]

def operation(name,command,state,output=None,expect=True,overrides=None):
    arguments=[sys.executable,str(TOOL),command,'--state',str(state),*(common if overrides is None else overrides)]
    if output is not None:arguments+=['--output',str(output)]
    p=subprocess.run(arguments,capture_output=True,text=True)
    report=json.loads(p.stdout)
    assert (p.returncode==0)==expect,(name,report,p.stderr)
    write_json_once(PUBLIC/(name+'.json'),report)
    return report

def clone(name):
    target=LAB/name
    shutil.copytree(SOURCE,target)
    return target

operation('source-check','check',SOURCE)
operation('backup','backup',SOURCE,LAB/'sealed-backup')
operation('restore','restore',LAB/'sealed-backup',LAB/'restored')
restored=open_store(LAB/'restored').snapshot().model_dump(mode='json')
assert restored==snapshot
negative={}
missing=clone('missing-journal');(missing/'registrations.sqlite3').unlink()
negative['missing-journal']=operation('missing-journal','check',missing,expect=False)
assert not (missing/'registrations.sqlite3').exists()
wrong=common.copy();wrong[1]='0'*64
negative['wrong-policy-pin']=operation('wrong-policy-pin','check',SOURCE,expect=False,overrides=wrong)
wrong=common.copy();wrong[3]='0'*64
negative['wrong-closure-pin']=operation('wrong-closure-pin','check',SOURCE,expect=False,overrides=wrong)
truncated=clone('truncated-history')
with sqlite3.connect(truncated/'registrations.sqlite3') as db:
    db.execute('DROP TRIGGER registrations_delete')
    db.execute('DELETE FROM registrations WHERE sequence=(SELECT MAX(sequence) FROM registrations)')
negative['truncated-history']=operation('truncated-history','check',truncated,expect=False)
unsealed=clone('unsealed')
with sqlite3.connect(unsealed/'registrations.sqlite3') as db:
    db.execute('DROP TRIGGER closure_delete');db.execute('DELETE FROM closure')
negative['unsealed-state']=operation('unsealed-state','backup',unsealed,LAB/'must-not-back-up-open-state',expect=False)
assert not (LAB/'must-not-back-up-open-state').exists()
wrongkey=clone('wrong-private-key');(wrongkey/'witness-private.pem').write_bytes(SoftwareECDSASigner.generate().private_pem())
negative['wrong-private-key']=operation('wrong-private-key','check',wrongkey,expect=False)
unsafe=clone('unsafe-permissions');(unsafe/'witness-private.pem').chmod(0o644)
negative['unsafe-permissions']=operation('unsafe-permissions','check',unsafe,expect=False)
symlink=clone('symlink-state');(symlink/'client-keys/0.pem').unlink();(symlink/'client-keys/0.pem').symlink_to(symlink/'witness-public.pem')
negative['symlink']=operation('symlink','check',symlink,expect=False)
altered=LAB/'altered-backup';shutil.copytree(LAB/'sealed-backup',altered)
(altered/'unexpected.txt').write_text('unmanifested content')
negative['backup-manifest']=operation('backup-manifest','restore',altered,LAB/'must-not-restore-altered',expect=False)
assert not (LAB/'must-not-restore-altered').exists()
existing=LAB/'existing-destination';existing.mkdir(mode=0o700);(existing/'sentinel').write_text('preserve me')
negative['existing-destination']=operation('existing-destination','restore',LAB/'sealed-backup',existing,expect=False)
assert (existing/'sentinel').read_text()=='preserve me'

# Service and recovery probes never mount the original witness store.
service=LAB/'service-state';shutil.copytree(LAB/'restored',service)
probes=LAB/'public-probes';probes.mkdir()
forged=json.loads(json.dumps(snapshot['registrations'][0]['receipt']))
forged['core']['submitted_at']='2026-11-05T01:49:30Z'
forged['core_digest']=digest_object(forged['core'])
coordinator=_coordinator_signer(ORIGINAL/'cases/external-sectigo/round',create=False,coordinator_workspace=ORIGINAL/'coordinator')
forged['signature']=_signature(coordinator,forged['core_digest'],'swtpm').model_dump(mode='json')
write_json_once(probes/'coordinator-forgery.json',forged)
shutil.copyfile(ORIGINAL/'public-witness/snapshot.json',probes/'expected-snapshot.json')

def docker(arguments,expect=True):
    p=subprocess.run(['docker',*arguments],text=True,capture_output=True)
    assert (p.returncode==0)==expect,(arguments,p.stdout,p.stderr)
    return p.stdout

image=json.loads(docker(['image','inspect',IMAGE]))[0]
entrypoint=image['Config']['Entrypoint']
assert len(entrypoint)==1 and 'python' in entrypoint[0]
uid=f'{os.getuid()}:{os.getgid()}'
request_code=r'''
import json,sys,urllib.request,urllib.error
from pathlib import Path
url=sys.argv[1]
def request(path,value=None):
    req=urllib.request.Request(url+path,data=None if value is None else json.dumps(value).encode(),headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=10) as r:return r.status,json.load(r)
    except urllib.error.HTTPError as e:return e.code,json.load(e)
status,snapshot=request('/snapshot')
expected=json.loads(Path('/probes/expected-snapshot.json').read_text())
assert status==200 and snapshot==expected
receipt=expected['registrations'][0]['receipt']
status,ack=request('/receipts',receipt)
assert status==200 and ack==expected['registrations'][0]
checks={}
for path in ('/close','/reset','/init'):
    code,_=request(path,{})
    assert code==404
    checks['POST '+path]=code
for path in ('/witness-private.pem','/registrations.sqlite3','/settings.json'):
    code,_=request(path)
    assert code==404
    checks['GET '+path]=code
code,_=request('/receipts',json.loads(Path('/probes/coordinator-forgery.json').read_text()))
assert code==409
print(json.dumps({'snapshot_unchanged':True,'duplicate_acknowledgement_identical':True,'coordinator_signed_forgery_rejected':True,'restricted_HTTP_routes':checks,'external_network_available':False}))
'''
permission_code=r'''
import os,json
checks={}
for name in ('witness-private.pem','registrations.sqlite3'):
    for label,flag in (('read',os.O_RDONLY),('write',os.O_WRONLY)):
        try:
            fd=os.open('/state/'+name,flag)
        except PermissionError as e:
            checks[name+':'+label]={'denied':True,'errno':e.errno}
        else:
            os.close(fd)
            raise AssertionError('coordinator OS identity accessed private witness material')
print(json.dumps({'effective_uid':os.getuid(),'checks':checks,'simulation_only':True,'administrative_independence_demonstrated':False}))
'''
permissions=json.loads(docker(['run','--rm','--network','none','--read-only','--cap-drop','ALL','--user','65534:65534',
    '-v',str(service)+':/state:rw',IMAGE,'-c',permission_code]))
write_json_once(PUBLIC/'unprivileged-coordinator-access.json',permissions)
created=False

def wait_ready():
    for _ in range(100):
        lines=docker(['logs',NAME]).splitlines()
        events=[]
        for line in lines:
            try:
                event=json.loads(line)
            except json.JSONDecodeError:continue
            if event.get('status')=='listening':events.append(event)
        if events:
            port=events[-1]['address'][1]
            p=subprocess.run(['docker','exec','--user',uid,NAME,*entrypoint,'-c',request_code,f'http://127.0.0.1:{port}'],text=True,capture_output=True)
            if p.returncode==0:return json.loads(p.stdout)
        time.sleep(.2)
    raise RuntimeError('witness did not pass service probe after restart')

try:
    container=docker(['run','-d','--name',NAME,'--network','none','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--user',uid,'--tmpfs','/tmp:rw,size=64m',
        '-v',str(service)+':/state:rw','-v',str(probes)+':/probes:ro',IMAGE,
        '-u','-m','fl_forensics','witness-serve','--state','/state','--port','0']).strip()
    created=True
    initial=wait_ready();write_json_once(PUBLIC/'service-before-crash.json',initial)
    docker(['kill','--signal','KILL',NAME])
    stopped=json.loads(docker(['inspect',NAME]))[0]
    assert stopped['State']['ExitCode']==137
    docker(['start',NAME])
    restarted=wait_ready();write_json_once(PUBLIC/'service-after-crash.json',restarted)
    closed=json.loads(docker(['exec','--user',uid,NAME,*entrypoint,'-m','fl_forensics','witness-close',
        '--state','/state','--output','/tmp/reclosed-snapshot.json']))
    assert closed['closure_digest']==pins['closure_digest']
    write_json_once(PUBLIC/'idempotent-close-after-crash.json',closed)
finally:
    if created:docker(['stop',NAME])
operation('service-after-shutdown','check',service)
after={p.relative_to(SOURCE).as_posix():sha256_file(p) for p in SOURCE.rglob('*') if p.is_file()}
assert before==after
assert implementation_sha256()==identity
result={'status':'verified','external_TSA_evidence_reused_without_new_requests':True,
    'registered_receipts':15,'timestamp_tokens_in_unchanged_snapshot':16,'backup_restore_snapshot_identical':True,
    'forced_process_exit_code':137,'service_restart_verified':True,'idempotent_ack_and_closure_after_restart':True,
    'coordinator_signed_forgery_rejected':True,'restricted_HTTP_routes':6,'unprivileged_file_access_checks_denied':4,
    'negative_recovery_cases_rejected':len(negative),'missing_journal_not_silently_recreated':True,
    'historical_private_state_unchanged':True,'core_implementation_unchanged':True,'implementation_sha256':identity,
    'executed_core_image_id':image['Id'],'new_operator_tool_sha256':sha256_file(TOOL),
    'witness_admin_independence_demonstrated':False,'privilege_probe_scope':'Local Linux UID 65534 without capabilities; host/Docker administrator remains capable of bypassing it.',
    'backup_scope':'Sealed SQLite state only; no open-round backup or crash during an in-flight commit was tested.',
    'thesis_edited':False,'private_backup_directory':str(LAB/'sealed-backup')}
write_json_once(PUBLIC/'validation.json',result)
write_json_once(OUT/'validation.json',result)
shutil.copyfile(TOOL,PUBLIC/'witness_operator.py')
shutil.copyfile(__file__,PUBLIC/'executed-validation-controller.py')
assert not any(b'PRIVATE KEY-----' in p.read_bytes() for p in PUBLIC.rglob('*') if p.is_file())
write_json_once(PUBLIC/'artifact-index.json',{'files':{p.relative_to(PUBLIC).as_posix():sha256_file(p) for p in PUBLIC.rglob('*') if p.is_file()}})
print(json.dumps(result,indent=2))
