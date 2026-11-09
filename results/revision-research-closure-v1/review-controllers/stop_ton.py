"""Stop only this task's ToN-IoT acquisition after the user defers it."""
from pathlib import Path
import json
import os
import signal

target = str(Path(__file__).with_name('ton_sources.py'))
stopped = []
for p in Path('/proc').iterdir():
    if not p.name.isdigit():
        continue
    try:
        args = (p/'cmdline').read_bytes().split(b'\0')
        if target.encode() in args:
            os.kill(int(p.name), signal.SIGTERM)
            stopped.append(int(p.name))
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
out = Path(__file__).parent
record = {'reason':'User explicitly deferred ToN-IoT; no compatibility/training work continues.',
          'stopped_acquisition_pids':stopped}
(out/'ton-deferred.json').write_text(json.dumps(record,indent=2)+'\n')
p=out/'WORK_PLAN.md'
s=p.read_text().replace('The request reopens ToN-IoT.',
                       'The user subsequently explicitly deferred ToN-IoT again; do not continue that work.')
s+='\n- User steering: ToN-IoT deferred again; no local dataset exists. Task-owned acquisition stopped; partial files retained without a dataset-validation claim.\n'
p.write_text(s)
print(json.dumps(record))
