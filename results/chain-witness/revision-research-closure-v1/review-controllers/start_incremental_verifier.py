"""Allow verification of each closed case while later reserved cases still run."""
from pathlib import Path

out=Path(__file__).parent;p=out/'verify_robust.py';s=p.read_text()
assert "results=read(lab/'results.json')" in s
s=s.replace("results=read(lab/'results.json')",'''import time
def closed_cases():
    observed={}
    for index,task in enumerate(protocol['tasks']):
        name=f"case-{index:02d}-{task['cohort']}-{task['strategy']}-{task['mode']}"
        manifest=lab/'cases'/name/'manifest.json'
        while True:
            try:
                read(manifest)
                break
            except (FileNotFoundError,json.JSONDecodeError):
                time.sleep(1)
        observed[name]=sha256_file(manifest)
        yield {'name':name,'task':task,'manifest_sha256':observed[name]}
    while not (lab/'results.json').exists():time.sleep(1)
    final=read(lab/'results.json')
    assert len(final['cases'])==len(observed)
    assert all(observed[c['name']]==c['manifest_sha256'] for c in final['cases'])
''')
s=s.replace("for case in results['cases']:","for case in closed_cases():")
p.write_text(s)
print('Verifier consumes only closed case manifests and reconciles them with the final creator result.')
