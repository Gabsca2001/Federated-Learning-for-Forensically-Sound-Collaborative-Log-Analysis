"""Stop only the idle Docker daemon created for this experiment family."""
from pathlib import Path
import json
import os
import signal
import subprocess
import time

repo=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
runtime=repo/'artifacts/revision-dba-isolated-runtime-v1';pid=int((runtime/'engine.pid').read_text())
cmdline=Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0',b' ').decode()
assert cmdline.startswith('/usr/bin/dockerd ')
for required in ('unix:///run/revision-dba-engine.sock','--containerd-namespace revision-dba-v1',str(runtime/'data')):assert required in cmdline
env={**os.environ,'DOCKER_HOST':'unix:///run/revision-dba-engine.sock','DOCKER_CONFIG':'/tmp/revision-dba-docker-config'}
running=subprocess.check_output(['docker','ps','-q'],env=env,text=True).strip();assert not running
os.kill(pid,signal.SIGTERM)
for _ in range(100):
    if not Path(f'/proc/{pid}/cmdline').exists():break
    if not Path(f'/proc/{pid}/cmdline').read_bytes():break
    time.sleep(.1)
else:raise RuntimeError('owned idle engine did not stop')
result={'profile':'task-owned-engine-shutdown-v1','owned_pid':pid,'running_containers_before_stop':[],
    'verified_owned_socket':'unix:///run/revision-dba-engine.sock','owned_engine_stopped':True,
    'other_docker_daemons_not_signalled':True}
target=repo/'artifacts/revision-geometry-detector-v1/engine-shutdown.json'
assert not target.exists();target.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result))
