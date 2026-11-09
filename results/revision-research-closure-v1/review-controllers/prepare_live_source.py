"""After offline closure, add a separately named attested robust profile."""
from pathlib import Path
import hashlib
import json
import zipfile

from fl_forensics.round_derivation import implementation_sha256

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-research-closure-v1'
assert (lab/'robust-replay.json').exists(),'Close frozen offline verification before changing source.'
assert json.loads((lab/'robust-replay.json').read_bytes())['status']=='verified'
assert json.loads((lab/'shared-gradient-replay.json').read_bytes())['status']=='verified'
assert json.loads((lab/'sequential-benchmark.json').read_bytes())['source']=='b6533003dc83d5baab2033e5b89d522bdf720629b1051049cbeec3cff0b34b6b'
assert implementation_sha256()=='b6533003dc83d5baab2033e5b89d522bdf720629b1051049cbeec3cff0b34b6b'
assert not (lab/'offline-source-before-live.zip').exists()
with zipfile.ZipFile(lab/'offline-source-before-live.zip','x',zipfile.ZIP_DEFLATED) as archive:
    for top in ('src','scripts','tests','configs'):
        for p in sorted((repo/top).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:
                archive.write(p,p.relative_to(repo))
before={}
def change(name,old,new):
    p=repo/name;s=p.read_text();assert s.count(old)==1,(name,old[:60])
    before.setdefault(name,s)
    p.write_text(s.replace(old,new))

change('src/fl_forensics/live_envelope.py',
       '(PROFILE, "live-client-envelope-bounded-v1")',
       '(PROFILE, "live-client-envelope-bounded-v1", "live-client-envelope-robust-bounded-v1")')
change('src/fl_forensics/live_envelope.py',
       '{"bounds.json"} if value["profile"] == "live-client-envelope-bounded-v1" else set()',
       '{"bounds.json"} if value["profile"] in ("live-client-envelope-bounded-v1", "live-client-envelope-robust-bounded-v1") else set()')
change('src/fl_forensics/live_bounded_aggregation.py',
       'PROFILE = "live-client-envelope-bounded-v1"',
       'PROFILE = "live-client-envelope-bounded-v1"\nROBUST_PROFILE = "live-client-envelope-robust-bounded-v1"')
change('src/fl_forensics/live_bounded_aggregation.py','        == PROFILE','        in (PROFILE, ROBUST_PROFILE)')
change('src/fl_forensics/live_bounded_aggregation.py','\ndef reference(workspace):', '''
def robust_enabled(workspace):
    path = Path(workspace) / "public/in-round-admission.yaml"
    return path.exists() and load_yaml(path)[0].get("runtime_admission", {}).get("observable_policy", {}).get("profile") == ROBUST_PROFILE


def _operator(workspace):
    if robust_enabled(workspace):
        from .robust_bounded_aggregation import aggregate_robust_bounded
        return aggregate_robust_bounded
    return aggregate_bounded


def reference(workspace):''')
change('src/fl_forensics/live_bounded_aggregation.py','model, _ = aggregate_bounded(', 'model, _ = _operator(workspace)(')
change('src/fl_forensics/live_bounded_aggregation.py','parameters, report = aggregate_bounded(', 'parameters, report = _operator(workspace)(')
change('src/fl_forensics/live_bounded_aggregation.py',
       '"transformation": "float64 per-tensor capped original deltas, then weighted sum, final checkpoint dtype cast",',
       '"transformation": ("float64 tensor-capped deltas, finite smoothed geometric-median convex reweighting, final checkpoint dtype cast" if robust_enabled(workspace) else "float64 per-tensor capped original deltas, then weighted sum, final checkpoint dtype cast"),')
change('src/fl_forensics/live_bounded_aggregation.py',
       '''    return (
        "BoundedDelta-FedAvg-observable-envelope"''',
       '''    if robust_enabled(workspace):
        return "RobustBoundedDelta-GeometricMedian-observable-envelope"
    return (
        "BoundedDelta-FedAvg-observable-envelope"''')
change('src/fl_forensics/live_bounded_aggregation.py','"profile": PROFILE,',
       '"profile": ROBUST_PROFILE if robust_enabled(workspace) else PROFILE,')
change('src/fl_forensics/in_round_admission_models.py',
       '        "BoundedDelta-FedAvg-observable-envelope",',
       '        "BoundedDelta-FedAvg-observable-envelope",\n        "RobustBoundedDelta-GeometricMedian-observable-envelope",')

for name,text in before.items():
    p=lab/'before-live-source'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
(out/'live-source-update.json').write_text(json.dumps({'before_source':'b6533003dc83d5baab2033e5b89d522bdf720629b1051049cbeec3cff0b34b6b',
    'after_source':implementation_sha256(),'changed_files':list(before),
    'default_profile_changed':False,'old_profile_serialized_descriptions_retained':True},indent=2)+'\n')
print('SEPARATE LIVE ROBUST PROFILE',implementation_sha256())
