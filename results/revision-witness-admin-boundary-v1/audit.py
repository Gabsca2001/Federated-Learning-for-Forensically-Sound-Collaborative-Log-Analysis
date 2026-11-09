"""Read-only administrative-boundary audit; never print private key material."""
from pathlib import Path
from datetime import UTC,datetime
import json,os,sqlite3,stat
from fl_forensics.canonical import sha256_file
from fl_forensics.crypto import SoftwareECDSASigner
from fl_forensics.storage import load_json,write_json_once

OUT=Path(__file__).parent
REPO=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
CASE=REPO/'artifacts/revision-external-tsa-20261105-v2'
WITNESS=CASE/'private-witness'
COORDINATOR=CASE/'coordinator/authority/round-coordinator.private.pem'
policy=load_json(WITNESS/'policy.json')
paths=[COORDINATOR,WITNESS/'witness-private.pem',WITNESS/'registrations.sqlite3']
before={str(p):sha256_file(p) for p in paths}
read_checks={}
for role,path,expected in [
    ('coordinator',COORDINATOR,policy['core']['coordinator_key_id']),
    ('witness',WITNESS/'witness-private.pem',policy['core']['witness_key_id']),
]:
    signer=SoftwareECDSASigner.load(path)
    assert signer.key_id==expected
    info=path.stat()
    read_checks[role]={'private_key_read_verified_by_matching_public_key_id':True,
        'public_key_id':signer.key_id,'owner_uid':info.st_uid,'mode':oct(stat.S_IMODE(info.st_mode))}
with sqlite3.connect((WITNESS/'registrations.sqlite3').resolve().as_uri()+'?mode=ro&immutable=1',uri=True) as db:
    count=db.execute('SELECT COUNT(*) FROM registrations').fetchone()[0]
    assert count==15
arguments=load_json(CASE/'logs/admission-command.json')['arguments']
mounts=[arguments[i+1] for i,v in enumerate(arguments[:-1]) if v=='-v']
assert not any(m.split(':',1)[0]==str(WITNESS) for m in mounts)
assert before=={str(p):sha256_file(p) for p in paths}
result={
    'status':'administrative_separation_requirement_not_met_in_local_configuration',
    'audit_time_utc':datetime.now(UTC).isoformat(),
    'auditing_effective_uid':os.geteuid(),
    'same_current_operator_can_read_both_actual_private_keys':True,
    'private_key_checks':read_checks,
    'same_current_operator_can_read_actual_witness_journal':True,
    'witness_journal_current_operator_write_access_reported_by_OS':os.access(WITNESS/'registrations.sqlite3',os.W_OK),
    'journal_registered_receipts':count,
    'coordinator_application_private_witness_mount_present':False,
    'runtime_isolation_and_administrative_separation_are_distinct':True,
    'signed_artifacts_and_database_bytes_unchanged':True,
    'private_key_material_in_output':False,
    'external_TSA_technical_adoption_already_verified':True,
    'new_cryptographic_or_TSA_operations_requested':False,
    'witness_administrative_independence_demonstrated':False,
    'user_reported_distinct_operator_resource':False,
    'required_external_change':'A genuinely distinct trusted operator must control witness credentials/key/journal/backups and independently distribute policy/final-head references.',
    'thesis_edited':False,
}
write_json_once(OUT/'administrative-boundary.json',result)
print(json.dumps(result,indent=2))
