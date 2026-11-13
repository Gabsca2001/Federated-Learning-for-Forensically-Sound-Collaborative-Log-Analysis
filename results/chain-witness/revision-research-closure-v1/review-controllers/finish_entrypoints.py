"""Make original-WSL research entry points reserve explicit fresh destinations."""
from pathlib import Path
import hashlib
import json

repo=Path.cwd();out=Path(__file__).parent;records=[]
def update(name,changes):
    p=repo/'scripts'/name;s=p.read_text()
    before=s
    for old,new in changes:
        assert s.count(old)==1,(name,old[:80]);s=s.replace(old,new)
    backup=repo/'artifacts/revision-research-closure-v1/before-entrypoint-cleanup'/name
    backup.parent.mkdir(parents=True,exist_ok=True);assert not backup.exists();backup.write_text(before)
    p.write_text(s);records.append({'path':p.relative_to(repo).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})

update('revision_native_gradient_study.py',[
 ("choices=['development','development-v2','development-v3','evaluation']","choices=['development-v3','evaluation']"),
 ('    args = ap.parse_args()',"    ap.add_argument('--output-root',type=Path,help='Fresh artifact directory; existing evidence is never overwritten.')\n    args = ap.parse_args()"),
 ("    root = ROOT / ('native-gradients-' + args.phase)","    root = args.output_root or ROOT / ('native-gradients-' + args.phase)"),
 ('For development-v2 and evaluation, select only candidates','For development-v3 and evaluation, select only candidates')])
update('revision_robust_containment_study.py',[
 ("phase=parser.parse_args().phase\nrepo=Path.cwd();lab=repo/'artifacts/revision-research-closure-v1'/('robust-'+phase)","parser.add_argument('--output-root',type=Path,help='Fresh artifact directory; existing evidence is never overwritten.')\nargs=parser.parse_args();phase=args.phase\nrepo=Path.cwd();lab=args.output_root or repo/'artifacts/revision-research-closure-v1'/('robust-'+phase)"),
 ("(out/f'robust-{phase}-protocol.json').write_bytes((lab/'protocol-before-training.json').read_bytes())","# The reserved protocol remains inside the selected evidence directory."),
 ("(out/f'robust-{phase}-results.json').write_bytes((lab/'results.json').read_bytes())","# Results remain inside the selected evidence directory.")])
update('revision_group_completion.py',[("ROOT=REPO/'artifacts/revision-research-closure-v1/groups'","import argparse\nparser=argparse.ArgumentParser();parser.add_argument('--output-root',type=Path)\nargs=parser.parse_args()\nROOT=args.output_root or REPO/'artifacts/revision-research-closure-v1/groups'")])
update('revision_group_interventions.py',[("REPO=Path.cwd();ROOT=REPO/'artifacts/revision-research-closure-v1/groups'","import argparse\nparser=argparse.ArgumentParser();parser.add_argument('--source-root',type=Path)\nargs=parser.parse_args()\nREPO=Path.cwd();ROOT=args.source_root or REPO/'artifacts/revision-research-closure-v1/groups'")])
s=(out/'shared_gradient_baselines.py').read_text()
s=s.replace("OUT=Path(__file__).parent;sys.path[:0]=[str(OUT),str(OUT.parent/'state-conditioned-detector-20261103')]","OUT=Path(__file__).parent")
s=s.replace('from gradient_study import','from revision_native_gradient_study import').replace('from study_data import','from revision_study_data import')
s=s.replace("DEST=ROOT/'shared-gradient-baselines-v2';assert not DEST.exists()", "import argparse\nparser=argparse.ArgumentParser();parser.add_argument('--source-root',type=Path);parser.add_argument('--output-root',type=Path)\nargs=parser.parse_args()\nSOURCE=args.source_root or SOURCE\nDEST=args.output_root or ROOT/'shared-gradient-baselines-v2';assert not DEST.exists()")
s=s.replace("(OUT/'shared-gradient-results.json').write_bytes((DEST/'results.json').read_bytes())","# Results remain in the reserved comparison directory.")
p=repo/'scripts/revision_shared_gradient_baselines.py';assert not p.exists();p.write_text(s)
records.append({'path':p.relative_to(repo).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
(out/'portable-entrypoints-final.json').write_text(json.dumps(records,indent=2)+'\n')
print('Original WSL entry points ready; frozen historical controllers retained.')
