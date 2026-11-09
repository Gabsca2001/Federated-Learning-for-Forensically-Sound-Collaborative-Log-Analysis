import json
from pathlib import Path
p=Path('artifacts/revision-geometry-detector-v1/private-episodes/stream-001/rounds/round-001/round.json')
r=json.loads(p.read_bytes());print(list(r))
for k,v in r.items():
    if 'poison' in k or 'attack' in k: print(k,str(v)[:3500])
g=Path('artifacts/revision-geometry-detector-v1/private-episodes/stream-001')
print('ROOT',[(p.name) for p in g.iterdir()])
