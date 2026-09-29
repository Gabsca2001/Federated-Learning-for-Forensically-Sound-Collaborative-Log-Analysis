"""Start the checked recovery independently of the interactive tool session."""
import json,os,subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
for process in Path("/proc").iterdir():
    if not process.name.isdigit() or int(process.name)==os.getpid():continue
    try:args=(process/"cmdline").read_bytes().decode(errors="replace").split("\0")
    except (OSError,PermissionError):continue
    if any(Path(arg).name in {"run_m6_adaptive_paired_v4.py","resume_m6_adaptive_paired_v4.py"} for arg in args if arg):
        raise RuntimeError("Another campaign process is still running: "+process.name)
script=root/"scripts/resume_m6_adaptive_paired_v4.py"
compile(script.read_text(),str(script),"exec")
log=root/"m6-adaptive-paired-s341593-v4-resume.log"
with log.open("xb") as stream:
    child=subprocess.Popen([str(root/".venv/bin/python"),"-u",str(script)],cwd=root,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
receipt={"pid":child.pid,"log":str(log),"status":"launched_not_yet_verified"}
with (root/"artifacts/m6-adaptive-paired-s341593-v4/resume-process.json").open("x") as out:json.dump(receipt,out,indent=2)
print(json.dumps(receipt),flush=True)