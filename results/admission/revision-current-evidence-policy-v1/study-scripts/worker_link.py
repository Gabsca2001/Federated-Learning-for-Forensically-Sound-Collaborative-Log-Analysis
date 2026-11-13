"""Host transport to a task-owned observable-only decision worker."""
import json
import os
from pathlib import Path
import shutil
import subprocess


class WorkerLink:
    def __init__(self,repo,lab,role):
        self.lab=Path(lab);self.number=0
        self.env={**os.environ,'DOCKER_HOST':'unix:///run/revision-dba-engine.sock','DOCKER_CONFIG':'/tmp/revision-dba-docker-config'}
        self.name=f'revision-current-evidence-{role}-20261103'
        modelroot=Path(repo)/'artifacts/revision-state-conditioned-heldout-v1/models'
        image='sha256:c763483709fabee912591d8b2cd95f06733f381602723244f281bdcb76d0d575'
        args=['docker','create','-i','--name',self.name,'--network','none','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
            '--tmpfs','/tmp:rw,size=1g','-e','PYTHONPATH=/code','-e','PYTHONDONTWRITEBYTECODE=1',
            '-e','OPENBLAS_NUM_THREADS=1','-e','OMP_NUM_THREADS=1',
            '-v',f'{self.lab/"worker-code"}:/code:ro','-v',f'{modelroot}:/models:ro',
            '-v',f'{self.lab/"inbox"}:/inbox:ro','-v',f'{self.lab/"policy-calibration"}:/policy:ro',
            image,'/code/policy_worker.py']
        self.container=subprocess.check_output(args,env=self.env,text=True).strip()
        inspection=json.loads(subprocess.check_output(['docker','inspect',self.container],env=self.env))[0]
        assert inspection['HostConfig']['NetworkMode']=='none' and inspection['HostConfig']['ReadonlyRootfs']
        assert not any('/private-' in m.get('Source','') for m in inspection['Mounts'])
        (self.lab/f'{role}-worker-runtime.json').write_text(json.dumps(inspection,indent=2,sort_keys=True)+'\n')
        self.log=(self.lab/f'{role}-worker-stderr.txt').open('w')
        self.process=subprocess.Popen(['docker','start','-ai',self.container],env=self.env,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,bufsize=1)
        self.ready=json.loads(self.process.stdout.readline());assert self.ready['ready']
        (self.lab/f'{role}-worker-ready.json').write_text(json.dumps(self.ready,indent=2,sort_keys=True)+'\n')

    def request(self,path,*,cohort,op='score',**extra):
        path=Path(path);target=self.lab/'inbox/current';target.mkdir(exist_ok=True)
        for name in ('metadata.json','observations.npz'):shutil.copyfile(path/name,target/name)
        meta=json.loads((target/'metadata.json').read_bytes())
        self.number+=1
        request={'op':op,'request_id':f'request-{self.number:06d}','cohort':cohort,
            'observation_sha256':meta['observations_sha256'],**extra}
        self.process.stdin.write(json.dumps(request,sort_keys=True)+'\n');self.process.stdin.flush()
        line=self.process.stdout.readline()
        if not line:raise RuntimeError('worker stopped; inspect its stderr log')
        response=json.loads(line)
        if 'error' in response:raise RuntimeError(response['error'])
        if response['request_id']!=request['request_id']:raise RuntimeError('worker response binding mismatch')
        return request,response

    def stop(self):
        if self.process.poll() is None:
            self.process.stdin.write('{"op":"stop"}\n');self.process.stdin.flush()
            line=self.process.stdout.readline()
            assert line and json.loads(line)['stopped']
            self.process.stdin.close()
        code=self.process.wait(timeout=30)
        state=json.loads(subprocess.check_output(['docker','inspect',self.container],env=self.env))[0]['State']
        subprocess.run(['docker','rm',self.container],env=self.env,check=True,capture_output=True)
        self.log.close()
        assert code==0 and state['ExitCode']==0,(code,state)
