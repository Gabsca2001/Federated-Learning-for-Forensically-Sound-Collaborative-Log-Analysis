from pathlib import Path
import json,subprocess,os
root=Path(__file__).resolve().parents[1]
log=root/'m6-adaptive-multiseed-v1-recovery2.log'
receipt=root/'artifacts/m6-adaptive-multiseed-v1-recovery2-process.json'
if receipt.exists(): raise FileExistsError(receipt)
with log.open('xb') as stream:
    child=subprocess.Popen([str(root/'.venv/bin/python'),'-u',str(root/'scripts/recover_m6_adaptive_multiseed_invocation_v2.py')],cwd=root,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True,env={**os.environ,'PYTHONUNBUFFERED':'1'})
with receipt.open('x') as f:json.dump({'pid':child.pid,'log':str(log),'status':'launched_not_yet_verified'},f)
print(json.dumps({'pid':child.pid,'log':str(log)}))