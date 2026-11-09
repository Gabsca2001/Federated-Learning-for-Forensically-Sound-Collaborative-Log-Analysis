"""Durable one-case jobs for a host with interrupted WSL sessions."""
import argparse,fcntl,hashlib,json,os,time
from pathlib import Path
import revision_capped_final_study as study
from revision_capped_final_audit import audit_case
from revision_study_data import read,Generator
from revision_dba_experiment import save,authenticate
from fl_forensics.canonical import sha256_file

LAB=study.LAB


def preserve(path,reason):
    root=LAB.resolve();source=path.resolve()
    assert source.is_relative_to(root) and source!=root
    target=(root/'interrupted-attempts'/f'durable-{time.time_ns()}'/path.name).resolve()
    assert target.is_relative_to(root/'interrupted-attempts') and not target.exists()
    target.parent.mkdir(parents=True)
    pins={str(p.relative_to(source)):sha256_file(p) for p in source.rglob('*') if p.is_file()} if source.is_dir() else {source.name:sha256_file(source)}
    source.rename(target)
    save(target.parent/'preservation.json',dict(reason=reason,relocated_to=str(target.relative_to(root)),files=pins,
        counted_as_completed=False,method_or_protocol_changed=False))
    os.sync()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=('train','close_training','audit','close_audit'))
    parser.add_argument('index',type=int,nargs='?',default=0);args=parser.parse_args()
    p=read(LAB/'protocol-before-training.json');study.assert_locks(p)
    if args.phase=='train':
        task=p['tasks'][args.index];case=LAB/'cases'/task['name'];result_path=case/'result.json'
        result=None
        if result_path.exists():
            try:
                result=read(result_path);authenticate(case/'evidence',result['manifest_sha256'])
            except Exception as exc:preserve(case,'Closed attempt did not authenticate: '+type(exc).__name__);result=None
        elif case.exists():preserve(case,'Interrupted unclosed attempt; same fixed task repeated')
        if result is None:
            try:result=study.worker(task)
            except Exception as exc:
                evidence=case/'evidence';error=dict(task=task,complete=False,error=str(exc),exception_type=type(exc).__name__)
                save(evidence/'terminal-exception.json',error)
                if not (evidence/'manifest.json').exists():Generator.close(evidence)
                result={**error,'completed_rounds':len(list(evidence.glob('rounds/round-*/round.json'))),
                        'manifest_sha256':sha256_file(evidence/'manifest.json')}
                if not result_path.exists():save(result_path,result)
        os.sync();authenticate(case/'evidence',result['manifest_sha256'])
        existing=[read(x) for x in (LAB/'cases').glob('*/result.json')]
        (LAB/'progress.json').write_text(json.dumps(dict(terminal_cases=len(existing),planned_cases=len(p['tasks']),
            complete_cases=sum(r['complete'] for r in existing)),sort_keys=True)+'\n')
        os.sync();print(json.dumps(dict(durable_case=task['name'],complete=result['complete'])),flush=True)
    elif args.phase=='close_training':
        results=[]
        for task in p['tasks']:
            result=read(LAB/'cases'/task['name']/'result.json')
            authenticate(LAB/'cases'/task['name']/'evidence',result['manifest_sha256']);results.append(result)
        value=dict(protocol_sha256=sha256_file(LAB/'protocol-before-training.json'),
            results=sorted(results,key=lambda r:r['task']['name']),test_inference_performed=False)
        path=LAB/'training-complete.json'
        if path.exists():assert read(path)==value
        else:save(path,value)
        os.sync();print('TRAINING_CLOSED',flush=True)
    else:
        closure=read(LAB/'training-complete.json');destination=LAB/'verified';destination.mkdir(exist_ok=True)
        verifier=study.ROOT/'scripts/revision_capped_final_audit.py'
        before=dict(verifier_sha256=sha256_file(verifier),training_closure_sha256=sha256_file(LAB/'training-complete.json'),test_enabled=True)
        header=destination/'verification-before-reading.json'
        if header.exists():assert read(header)==before
        else:save(header,before);os.sync()
        if args.phase=='audit':
            result=closure['results'][args.index];target=destination/'cases'/f'{result["task"]["name"]}.json'
            lock_path=destination/'locks'/f'{result["task"]["name"]}.lock'
            lock_path.parent.mkdir(exist_ok=True)
            with lock_path.open('a') as audit_lock:
                fcntl.flock(audit_lock.fileno(),fcntl.LOCK_EX)
                if target.exists():
                    try:
                        existing=read(target);assert existing['source_manifest_sha256']==result['manifest_sha256']
                    except Exception:preserve(target,'Interrupted verification output');existing=None
                else:existing=None
                if existing is None:save(target,audit_case(result))
            os.sync();print('VERIFIED '+result['task']['name'],flush=True)
        else:
            cases=[read(destination/'cases'/f'{r["task"]["name"]}.json') for r in closure['results']]
            assert len(cases)==len(p['tasks'])
            result=dict(status='verified',cases=sorted(cases,key=lambda c:c['task']['name']),test_accessed=True,
                verifier_sha256=sha256_file(verifier),training_closure_sha256=sha256_file(LAB/'training-complete.json'))
            target=destination/'summary.json'
            if target.exists():assert read(target)==result
            else:save(target,result)
            os.sync();print('AUDIT_CLOSED',flush=True)


if __name__=='__main__':main()
