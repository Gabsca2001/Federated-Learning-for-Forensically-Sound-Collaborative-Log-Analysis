"""Preserve current source, verification, environment and maintained status in original WSL."""
from pathlib import Path
import importlib.metadata
import json
import platform
import shutil
import subprocess
import zipfile

from fl_forensics.canonical import sha256_file
from fl_forensics.round_derivation import implementation_sha256

repo=Path.cwd();out=Path(__file__).parent;lab=repo/'artifacts/revision-research-closure-v1'
read=lambda p:json.loads(Path(p).read_bytes())
assert '686 passed' in (lab/'full-tests-live-release.log').read_text()
live=read(lab/'live-runtime-verification.json');assert live['status']=='verified'
assert implementation_sha256()==live['source']=='1bfb5a16525f1c1427b5de09d4445bf309c7fd458172314abe1020d031aef81b'
assert read(out/'thesis_revision/applied-changes.json')['status']=='applied'
dest=repo/'results/revision-research-closure-v1';assert not dest.exists();dest.mkdir()
files=['NATIVE_GRADIENT_SUMMARY.json','GROUP_SUMMARY.json','ROBUST_SUMMARY.json','SHARED_GRADIENT_SUMMARY.json',
 'native-gradient-replay.json','group-replay.json','robust-replay.json','shared-gradient-replay.json',
 'sequential-benchmark.json','live-runtime-verification.json','current-property-bindings.json','current-property-bindings.md',
 'full-tests.log','full-tests-live-release.log','live-profile-tests.log','formal-binding.log','attack-contract-audit.json','portable-entrypoint-verification.json','owned-engine-stop.json']
for name in files:shutil.copy2(lab/name,dest/name)
for name in ('robust-profile-verification.json','fixed-endpoint-evaluation.json'):
    shutil.copy2(lab/'live-robust-tpm-v1/reports'/name,dest/name)
for name in ('live-source-update.json','portable-entrypoints-final.json'):
    shutil.copy2(out/name,dest/name)
thesis=dest/'thesis';thesis.mkdir()
for name in ('applied-changes.json','visual-review.json','pdf-inspection.json','thesis-changes.patch'):
    shutil.copy2(out/'thesis_revision'/name,thesis/name)
shutil.copy2(out/'RESEARCH_CLOSURE.md',dest/'README.md')
with (dest/'README.md').open('a') as f:
    f.write('\n\n## Final implementation and live mechanism closure\n\n')
    f.write(f"The offline 121-module source is `b6533003dc83d5baab2033e5b89d522bdf720629b1051049cbeec3cff0b34b6b`; its replay uses that release. The separately measured live source is `{implementation_sha256()}`. The previous 119-module source, the offline source and the current source are retained separately. Full current suite: **686 passed**, two existing Typer deprecation warnings. No default profile is changed.\n\n")
    f.write(f"The fresh three-branch/five-round runtime case has {live['fresh_quote_executions']} distinct software-TPM Quote executions and {live['fresh_local_training_submissions']} newly trained signed submissions. All fifteen rounds reconstruct originals, derived reports, checkpoints and graph bindings; ten robust rounds provide {live['fixed_final_beta_removal_certificates']} frozen-final-beta removal certificates and reject {live['coefficient_mutations_rejected']} coefficient mutations. The emulators share one host and do not provide physical-TPM protection. Full case details are retained under `artifacts/revision-research-closure-v1/live-robust-tpm-v1`.\n\n")
    f.write('Fixed live validation endpoints, separated by branch:\n\n```json\n'+json.dumps(live['endpoint_totals'],indent=2)+'\n```\n\n')
    f.write('These short runtime histories establish integration mechanics; an ineffective attacked control cannot establish mitigation. The longer reserved offline histories supply the reported positive and negative robustness outcomes.\n\n')
    f.write('The current 18-property source/verifier ledger is `current-property-bindings.json` and its readable table is `current-property-bindings.md`. It binds actual current function lines and hashes, retains old proof/evidence identities, flags ten changed bindings relative to the older 114-module matrix, and separately reviews the five changed package modules relative to the preceding 119-module source. AST equality is not transitive execution equivalence or proof-assistant certification.\n')
    f.write('\nPortable research entry points accept fresh destinations and preserve one-shot evidence guards. A targeted real-input smoke confirms identical original gradient endpoints under a custom destination; an injected invalid-zero case closes without fabricating an out-of-guard result. These portability-only changes do not rewrite the archived creators or the already frozen runtime image; the runtime runner and measured package remain bound to that image.\n')
    f.write('\nThe actual Download thesis sources are updated, compiled and visually checked. The `thesis/` handoff binds changed source files, a guarded patch and the separate v4 PDF hash. Original PDFs and the complete source backup remain preserved; no submission has occurred.\n')
env={'python':platform.python_version(),'platform':platform.platform(),
     'packages':{d.metadata['Name']:d.version for d in importlib.metadata.distributions() if d.metadata['Name']},
     'numerical_threads':1,'image_id':live['image_id']}
(dest/'environment.json').write_text(json.dumps(env,indent=2,sort_keys=True)+'\n')
(dest/'git-status.txt').write_bytes(subprocess.check_output(['git','status','--short']))
with zipfile.ZipFile(dest/'current-source.zip','x',zipfile.ZIP_DEFLATED) as z:
    for top in ('src','scripts','configs','tests'):
        for p in sorted((repo/top).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:z.write(p,p.relative_to(repo))
    for name in ('AGENTS.md','pyproject.toml','uv.lock','Dockerfile.revision-live-robust'):
        if (repo/name).exists():z.write(repo/name,name)
helpers=dest/'review-controllers';helpers.mkdir()
for p in sorted(out.glob('*.py')):shutil.copy2(p,helpers/p.name)
for p in sorted((out/'thesis_revision').glob('*.py')):
    shutil.copy2(p,helpers/('thesis-'+p.name))

docs=repo/'docs';backups=lab/'maintained-documents-before-final';backups.mkdir()
for name in ('STATUS.md','FORMAL_PROFILE_CORRESPONDENCE.md','SUPERVISOR_REQUIREMENTS_AUDIT_20261104.md'):
    shutil.copy2(docs/name,backups/name)
banner=('## Reserved research consolidation — 4 November 2026\n\n'
 'The current original-WSL source includes the separately named robust profile and passes **686 tests**. Native-gradient failures are reproduced terminal outcomes, the common-input comparison has 840 reconstructed outputs, the new group rule is not uniformly better, and robust weighting retains a 75.72% reserved peak. ToN-IoT remains explicitly deferred. See [the complete current report](../results/revision-research-closure-v1/README.md) and [the current 18-property bindings](../results/revision-research-closure-v1/current-property-bindings.md). Earlier entries below retain their historical release and experiment scope.\n\n')
for name in ('STATUS.md','FORMAL_PROFILE_CORRESPONDENCE.md'):
    p=docs/name;p.write_text(banner+p.read_text())
p=docs/'SUPERVISOR_REQUIREMENTS_AUDIT_20261104.md';s=p.read_text()
s=s.replace('New Chapter 1 assistance account. No detector-percentage evasion or claim that an AI score establishes authorship.',
 'The manuscript follows the user\'s subsequent writing preference and contains no assistance declaration. Historical correspondence remains preserved; no solely-human authorship claim is added.')
p.write_text(banner+s)
(docs/'RESEARCH_CONSOLIDATION_20261104.md').write_text((dest/'README.md').read_text())
record={'status':'verified-scoped-research-closure','source':implementation_sha256(),
 'offline_source':'b6533003dc83d5baab2033e5b89d522bdf720629b1051049cbeec3cff0b34b6b',
 'suite_passed':686,'ToN_IoT':'explicitly-deferred-by-user','default_profile_changed':False,
 'scientific_limits':['Residual robust peak ASR','False and missed group members','No automatic semantic exclusion guarantee','No external witness/trusted deadline','No full FedXLog replication','No independent dataset'],
 'files':{p.relative_to(dest).as_posix():sha256_file(p) for p in sorted(dest.rglob('*')) if p.is_file()},
 'artifact_roots':['artifacts/revision-research-closure-v1','artifacts/revision-research-closure-v1/live-robust-tpm-v1']}
for p in (dest/'completion-closure.json',out/'completion-closure.json'):
    p.write_text(json.dumps(record,indent=2)+'\n')
(dest/'completion-closure.sha256').write_text(sha256_file(dest/'completion-closure.json')+'  completion-closure.json\n')
print(json.dumps({'source':record['source'],'files':len(record['files']),'full_suite':686,'closure_sha256':sha256_file(dest/'completion-closure.json')}),flush=True)
