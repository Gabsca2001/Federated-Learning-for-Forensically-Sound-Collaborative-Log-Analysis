"""Execute four prespecified paired replicas using the existing M4/M5 tools."""
import fcntl, hashlib, json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LOCK=ROOT/'configs/m6-adaptive-multiseed-v1.lock.json'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p): return json.loads(p.read_text())
def check_lock():
    lock=read(LOCK)
    for path,digest in lock['files'].items():
        if sha(ROOT/path)!=digest: raise ValueError('Locked input changed: '+path)
    return lock

def main():
    guard=(ROOT/'m6-adaptive-multiseed-v1.process-lock').open('a')
    fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
    lock=check_lock()
    receipt=ROOT/'artifacts/m6-adaptive-multiseed-v1-invocation-recovery2.json'
    with receipt.open('x') as stream:
        json.dump({'reason':'Pass an absolute runner path through the numerical wrapper; previous failure before pair lock or training','lock_sha256':sha(LOCK),'recovery_code_sha256':sha(Path(__file__))},stream,indent=2)
    empty_pair=ROOT/'artifacts/m6-adaptive-paired-s342593-v1'
    if empty_pair.exists():
        if any(empty_pair.iterdir()): raise ValueError('Pair is not empty; preserve and investigate')
        empty_pair.rmdir()  # Empty directory only; never recursive.
    env=os.environ.copy(); env['PATH']=str(ROOT/'.venv/bin')+os.pathsep+env['PATH']
    def run(args):
        print(' '.join(map(str,args)),flush=True)
        subprocess.run(list(map(str,args)),cwd=ROOT,env=env,check=True)
    # All destinations must be fresh before any provisioning or training.
    for path in lock['plans']:
        p=read(ROOT/path); tag=p['trust_tag']; ns='flforensics_'+tag.replace('-','_')
        for target in [ROOT/'artifacts'/p['experiment_id'],ROOT/'artifacts'/(tag+'-trust'),ROOT/'artifacts'/(tag+'-nodes')]:
            if target.exists() and not (p['seed']==342593 and target in [ROOT/'artifacts'/(tag+'-trust'),ROOT/'artifacts'/(tag+'-nodes')]): raise FileExistsError(target)
        for kind,args in [('container',['-a']),('volume',[])]:
            found=subprocess.check_output(['docker',kind,'ls',*args,'-q','--filter','label=com.docker.compose.project='+ns],text=True)
            if found.strip() and p['seed']!=342593: raise ValueError('Existing Docker namespace '+ns)
        run(['fl-forensics','m3-verify-partitions','--workspace',p['partition'],'--dataset-workspace','artifacts/m2-data24-parquet'])
    for path in lock['plans']:
        check_lock(); p=read(ROOT/path); tag=p['trust_tag']; ns='flforensics_'+tag.replace('-','_')
        trust=ROOT/'artifacts'/(tag+'-trust'); nodes=ROOT/'artifacts'/(tag+'-nodes')
        env.update(COMPOSE_PROJECT_NAME=ns,M4_TRUST_WORKSPACE=str(trust),M4_NODE_ROOT=str(nodes),M4_UID=str(os.getuid()),M4_GID=str(os.getgid()))
        for image in [p['runtime_image_id'],p['m4_runtime_image_id']]:
            got=subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],text=True).strip()
            if got!=image: raise ValueError('Runtime image unavailable')
        for service in [*[f'client{i:02d}' for i in range(1,16)],*[f'tpm{i:02d}' for i in range(1,16)],'verifier']:
            run(['docker','tag',p['m4_runtime_image_id'],ns+'-'+service+':latest'])
        print('STARTING PAIRED SEED '+str(p['seed']),flush=True)
        if p['seed']==342593:
            for i in range(1,16):
                state=json.loads(subprocess.check_output(['docker','inspect',ns+f'-tpm{i:02d}-1'],text=True))[0]['State']
                if not state['Running']: raise ValueError('Provisioned TPM stopped; do not restart')
        else:
            run(['fl-forensics','m4-init','--workspace',trust,'--project-root',ROOT])
            run([sys.executable,'scripts/run_m4_swtpm.py','provision','--skip-build','--trust-workspace',trust,'--node-root',nodes])
            run(['fl-forensics','m4-enroll','--workspace',trust,'--node-root',nodes])
            run(['fl-forensics','m4-mtls-test','--workspace',trust,'--node-root',nodes])
        check_lock()
        run([sys.executable,'scripts/m6_numeric_runtime.py','script',str(ROOT/'scripts/run_m6_adaptive_paired_seed.py'),path])
        complete=read(ROOT/'artifacts'/p['experiment_id']/'complete.json')
        if complete['status']!='verified' or complete['rounds_per_arm']!=30: raise ValueError('Pair incomplete')
        print('VERIFIED PAIRED SEED '+str(p['seed']),flush=True)
    with (ROOT/'artifacts/m6-adaptive-multiseed-v1-complete.json').open('x') as stream:
        json.dump({'status':'verified','new_seeds':lock['new_seeds'],'lock_sha256':sha(LOCK)},stream,indent=2)
    print('ADAPTIVE MULTISEED EXTENSION VERIFIED',flush=True)
if __name__=='__main__': main()