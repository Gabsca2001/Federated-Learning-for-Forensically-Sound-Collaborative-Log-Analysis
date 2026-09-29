from pathlib import Path
import subprocess,json,re,hashlib,sys
ROOT=Path(__file__).resolve().parents[1]
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True).splitlines()
paths=sorted(set((git('ls-files') if '--all' in sys.argv else git('diff','--name-only','HEAD'))+git('ls-files','--others','--exclude-standard')))
files=[ROOT/p for p in paths if (ROOT/p).is_file()]
issues=[];broken=[]
for p in files:
    if p.stat().st_size>50_000_000:issues.append([str(p.relative_to(ROOT)),'large file'])
    if p.suffix.lower() in {'.pem','.key','.p12','.pfx'}:issues.append([str(p.relative_to(ROOT)),'key/certificate container'])
    if p.suffix in {'.json','.md','.yaml','.yml','.csv','.toml','.txt','.py','.sh'}:
        text=p.read_text(errors='replace')
        if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',text):issues.append([str(p.relative_to(ROOT)),'private key marker'])
        if re.search(r'(?<![A-Za-z0-9])(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-proj-[A-Za-z0-9_-]{30,})',text):issues.append([str(p.relative_to(ROOT)),'credential-like token'])
    if p.suffix.lower()=='.md':
        text=p.read_text()
        for target in re.findall(r'\]\(([^)]+)\)',text):
            target=target.split('#')[0].strip('<>')
            if not target or '://' in target or target.startswith('mailto:'):continue
            if not (p.parent/target).exists():broken.append([str(p.relative_to(ROOT)),target])
lock=json.loads((ROOT/'configs/m6-adaptive-multiseed-v1.lock.json').read_text())
lock_errors=[p for p,d in lock['files'].items() if hashlib.sha256((ROOT/p).read_bytes()).hexdigest()!=d]
print(json.dumps({'candidate_file_count':len(files),'total_bytes':sum(p.stat().st_size for p in files),'potential_sensitive_or_large_files':issues,'broken_readme_links':broken,'active_lock_mismatches':lock_errors,'new_result_directories':sorted({p.parts[1] for p in map(Path,paths) if p.parts[0]=='results' and len(p.parts)>2})},indent=2))