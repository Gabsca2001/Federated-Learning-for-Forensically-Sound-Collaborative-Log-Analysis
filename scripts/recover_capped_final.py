"""Preserve orphaned attempts before resuming the unchanged frozen protocol."""
import hashlib,json,os
from pathlib import Path
import revision_capped_final_study as study
from revision_dba_experiment import authenticate,save
from revision_study_data import read

lab=study.LAB.resolve();cases=(lab/'cases').resolve();archive=(lab/'interrupted-attempts/attempt-1').resolve()
assert archive.is_relative_to(lab) and not archive.exists()
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
    try:args=(proc/'cmdline').read_bytes().decode(errors='replace').split('\0')
    except (OSError,ProcessLookupError):continue
    assert not any(a=='scripts/revision_capped_final_study.py' or a.endswith('/revision_capped_final_study.py') for a in args),'Study process still live'
study.assert_locks(read(lab/'protocol-before-training.json'))
completed=[];partial=[];failures={}
for path in sorted(cases.iterdir()):
    if (path/'result.json').exists():
        try:
            result=read(path/'result.json');authenticate(path/'evidence',result['manifest_sha256']);completed.append(path.name)
        except Exception as exc:
            partial.append(path);failures[path.name]=dict(kind='unverifiable_closed_attempt',error_type=type(exc).__name__,error=str(exc))
    else:
        partial.append(path);failures[path.name]=dict(kind='unclosed_interrupted_attempt')
archive.mkdir(parents=True)
records=[]
for path in partial:
    source=path.resolve();target=(archive/path.name).resolve()
    assert source.is_relative_to(cases) and target.is_relative_to(archive) and not target.exists()
    pins={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
    source.rename(target)
    records.append(dict(case=path.name,partial_files=pins,relocated_to=str(target.relative_to(lab)),
        counted_as_completed=False,interruption_status=failures[path.name]))
log=study.ROOT/'revision-capped-final-v1.log';data=log.read_bytes()
summary=dict(profile='preserved-interrupted-capped-final-attempt-v1',completed_authenticated=completed,
    partial_attempts=records,original_log_sha256=hashlib.sha256(data).hexdigest(),original_log_null_bytes=data.count(bytes([0])),
    source_protocol_unchanged=True,training_method_unchanged=True,new_worker_count=2,
    interruption_cause='Process and prior WSL session were absent when checked; no cause established. No WSL restart requested by this controller.')
save(archive/'recovery.json',summary)
print(json.dumps(dict(authenticated_complete=len(completed),preserved_partial=len(partial)),indent=2))
