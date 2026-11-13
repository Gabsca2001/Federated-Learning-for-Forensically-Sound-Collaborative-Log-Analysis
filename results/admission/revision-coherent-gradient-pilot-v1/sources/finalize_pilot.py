from pathlib import Path
import sys,json,hashlib,shutil,os,csv
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis');O=Path(__file__).parent
P=R/'results/revision-coherent-gradient-pilot-v1';Q=R/'results/revision-coherent-gradient-recovery-v1'
def read(p):return json.loads(p.read_bytes())
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def save(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def allocated(p):return sum(f.stat().st_blocks*512 for f in p.rglob('*') if f.is_file())
sys.path.insert(0,str(R/'scripts'))
import revision_coherent_gradient_pilot as pilot
import revision_coherent_gradient_recovery as recovery
pp=read(P/'protocol-before-clean-training.json');op,old=pilot.check(pp)
qp=read(Q/'protocol-before-recovery.json');recovery.check(qp)
v=read(P/'verification.json');rv=read(Q/'verification.json')
assert v['status']=='verified_clean_pilot' and rv['all_recovery_branches_qualify']
assert v['complete_fltrust_histories']==4 and v['paused_histories']==2
from fl_forensics.round_derivation import implementation_sha256
assert implementation_sha256()=='8d7efa28b62a47d306a12958d66b3081d6527518f25641545cc81456640d2e64'
pub=R/'results/revision-capped-final-v1'
assert all(sha(pub/n)==h for n,h in read(pub/'publication-manifest.json')['files'].items())
rows=[];maximum_loss=0.
for task in pp['tasks']:
    primary=read(P/'evidence/histories'/task['name']/'result.json')
    if task['method']!='coherent_fltrust':continue
    check=next(c for c in v['fltrust_qualification'] if c['history']==task['name'])
    row={'history':task['name'],'primary_complete':primary['complete'],'primary_committed_rounds':primary['committed_rounds'],
        'primary_last_positive_contributors':primary['journal'][-1]['event']['positive_contributors'],
        'linked_recovery_used':not primary['complete'],'eventual_committed_rounds':primary['committed_rounds'],
        'linked_recovery_first_positive_contributors':None,'round10_f1_loss':None,'round15_f1_loss':None}
    if not primary['complete']:
        check=next(c for c in rv['branches'] if c['history']==task['name'])
        recovered=read(Q/'evidence/histories'/task['name']/'result.json')
        assert recovered['recovery_proof']['retained_parent_model_sha256']==primary['state']['parent_model_sha256']
        assert recovered['recovery_proof']['retained_committed_round']==primary['committed_rounds']
        assert len(recovered['recovery_proof']['additional_root_ids'])==12
        row['eventual_committed_rounds']=check['committed_rounds']
        row['linked_recovery_first_positive_contributors']=check['first_recovery_positive_contributors']
    assert check['qualified']
    for endpoint in check['endpoints']:
        assert endpoint['defined'] and endpoint['passes']
        row[f"round{endpoint['round']}_f1_loss"]=endpoint['f1_loss'];maximum_loss=max(maximum_loss,endpoint['f1_loss'])
    rows.append(row)
with (P/'clean-outcomes.csv').open('x',newline='') as h:
    w=csv.DictWriter(h,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
save(P/'source-integrity.json',{'implementation_sha256':implementation_sha256(),'original_generation_pins_verified':len(old['source_locks']),
    'original_publication_unchanged':True,'original_primary_result_rewritten':False,'operational_defaults_changed':False})
save(P/'linked-result-summary.json',{'primary_fltrust_complete':4,'primary_fltrust_paused':2,'linked_recovery_branches_complete':2,
    'eventual_completed_fltrust_histories_with_explicit_links':6,'committed_rounds_per_completed_history':15,
    'maximum_fixed_endpoint_clean_f1_loss_points':maximum_loss*100,'root_expansion':{'old_rows':48,'new_rows':60,'additional_rows':12,'maximum_expansions':1},
    'original_primary_all_guards_pass':False,'linked_recovery_qualifies':True,'interpretation':'Clean availability and utility only; post-hoc linked recovery on both failures, not six independent confirmations or original six-of-six primary success.',
    'new_attack_evaluation':False,'fresh_TPM_attestation':False,'production_gradient_adapter_validated':False})
table='\n'.join(f"| {r['history']} | {'15' if r['primary_complete'] else 'paused at0'} | {'48' if r['primary_complete'] else '60, linked expansion'} | {100*r['round10_f1_loss']:.4f} | {100*r['round15_f1_loss']:.4f} |" for r in rows)
text=f'''# Coherent gradient protocol and explicit availability recovery

This is an opt-in research profile, separate from the original Adam/FedAvg
campaigns and the measured M2–M8 core. It changes neither production defaults
nor historical formulas/evidence. No thesis edits, ToN-IoT acquisition or witness
administration work occurs here.

## What changed

Both client and server compute one float64 full-batch gradient at the current
checkpoint, in evaluation mode with dropout disabled, with descent step.001.
Every committed round recomputes all inputs on its NEW parent. The profile does
not relabel multi-epoch Adam endpoints as gradients.

Original class weights w_c are divided by the fixed preprocessing-population
mean weight mu. Client loss is the arithmetic mean of (w_y/mu)*cross_entropy,
without client-local weight-sum normalization. Sample-count-weighted client
gradients therefore match the pooled weighted objective on the sampled client
population. Root importance weights use the same normalized population class
mass divided by root sampling frequency. This matches the marginal objective,
not necessarily within-class feature distributions.

Trusted aggregate population counts/weights are explicit preprocessing metadata.
The experiment controller trains on original client rows; the server operator
receives deltas, counts and supplied mandatory-gate facts. No operational access
to private per-client raw rows or exact oracle gradient is assumed.

Contexts bind parent model and actual base tensors, loss contract, protocol
version, roster, round/attempt and root dataset version. Updates/root deltas bind
to that context and their content digests. Wrong parent/context, changed content,
schema errors and mandatory-veto resurrection are rejected. These checks do not
obtain fresh TPM evidence or authenticate caller-supplied trust facts.

## No-quorum behavior

The minimum remains TEN positive-coefficient contributors. When unavailable,
the numerical attempt returns no new checkpoint, retains the parent and the
committed-round number, and enters PAUSED. The pause is a visible decision,
not a completed round, zero-ASR endpoint or silently repaired quorum. Identical
automatic retries are rejected. Undefined root/alignment also pauses.

## Fresh clean pilot

Two previously studied non-IID assignments have two separately trained coherent
FedAvg baselines and six FLTrust histories (three overlapping48-row root draws).
The same pinned warm start and disjoint3163-row validation subset are reused.
The horizon is15 committed rounds, not training from scratch or independent-data
validation. No attack or test inference is performed.

Both FedAvg baselines complete15 rounds. FOUR of six initial FLTrust histories
complete15 rounds with actual parameter changes and pass the two-point clean F1
guard at rounds10/15. TWO pause before their first commit. The primary result
remains four complete and two paused; its all-history guard remains FALSE.

## Explicit linked recovery

A separate protocol was fixed after the pauses. Both failed histories receive
all twelve remaining rows from the previously reserved60-row root pool. All
sixty were already excluded from evaluation. No metric rows, attack labels,
candidate subset search or external data acquisition are used. Each source root
is a strict subset of the expanded root; source/loss contracts and old references
remain anchored.

The linked branch retains the original parent and committed-round number,
declares a new policy/reference and obtains fresh context bindings. Initial
client delta digests reproduce the original paused inputs exactly; the extra
reference evidence changes the server's assessment. Mandatory vetoes and quorum
are unchanged. Only one expansion is permitted; no remaining evidence means
another pause rather than blind progress.

BOTH linked branches reach15 committed rounds. The first resumed supports are
10 and12 positive contributors. Their F1 losses versus matched coherent FedAvg
are0.0000 points at rounds10 and15. This is availability recovery, not removal of
poisoning from a contaminated checkpoint. Data were clean in these experiments.

| Initial history | Initial commits | Final root evidence | F1 loss R10 (points) | F1 loss R15 (points) |
| --- | ---: | --- | ---: | ---: |
{table}

The largest fixed-endpoint loss across four direct and two linked completions
is {maximum_loss*100:.4f} F1 points. F1 equality does not imply identical parameters.
These linked results do not rewrite the original two failures or establish six
independent successes of one prospectively tested fallback policy. Recovery was
a clean-only, post-hoc engineering follow-up. It requires additional trustworthy
reference rows; such rows are not guaranteed in an operational deployment.

## Verification and remaining boundary

All primary and linked histories replay exactly from pinned original data,
including every gradient digest, context, state transition, checkpoint, clean
metric and pause. Scientific manifests authenticate preserved evidence with
software experiment keys. They explicitly claim no fresh TPM attestation or
client signatures. Twenty-seven focused tests pass:14 context/pause/common-loss
tests, five expansion tests and eight FLTrust numerical tests. A first analytic
test used exact equality for a floating-point sum; its2e-16 tolerance correction
and original failure log were preserved BEFORE protocol preparation. Scientific
thresholds and quorum did not change.

The existing130-module core identity,138 original generation pins and original
publication checksums remain unchanged. This research controller is not a new
TPM-attested M5 gradient adapter. It needs dedicated integration and security
validation before operational adoption.

The result supports clean continuity for the four direct histories and two
specific linked recoveries. It establishes no DBA resistance, defender-adaptive
attack resistance, independence from root poisoning, cold-start convergence,
unlearning or universal non-IID availability. The next security evaluation would
need a separately fixed effective attacked baseline and defended trajectories
under this new gradient/availability contract; historical Adam ASRs cannot be
transferred to it. No new attack campaign is included in this clean-only result.

Only journals, hashes, scalar metrics and final committed checkpoints are stored;
client tensors and datasets are not duplicated. Both result folders plus Windows
mirrors remain under64 MiB with an8 GiB host-free floor. Original inputs remain
necessary to reproduce the experiment; this is not a standalone recovery archive.
'''
(P/'README.md').write_text(text)
(Q/'README.md').write_text('''# Linked clean root-expansion recovery

This separate protocol links to both original clean paused states. It expands
each48-row reference to the complete60-row pool already excluded from metrics,
adds exactly12 rows and preserves parent, loss contract and committed-round count.
No quorum is lowered. Only one expansion is allowed; no identical-evidence retry.

Both branches reach15 committed rounds and pass clean F1 guards at10/15, with
zero F1 loss versus matched coherent FedAvg. The full trajectories and recovery
proofs replay. Original four-of-six primary completion remains unchanged. This
tests clean training availability, not decontamination or attack resistance.
See the primary README, verification.json, protocols and signed evidence.
''')
for dest,names in ((P,('tests.log','tests-first.log','run.log','verify.log')),(Q,('recovery-tests.log','recovery-run.log','recovery-verify.log'))):
    for n in names:shutil.copy2(O/n,dest/n)
for dest,names in ((P,('coherent_gradient_protocol.py','revision_coherent_gradient_pilot.py','test_coherent_gradient_protocol.py')),
                   (Q,('coherent_gradient_recovery.py','revision_coherent_gradient_recovery.py','test_coherent_gradient_recovery.py'))):
    src=dest/'sources';src.mkdir()
    for n in names:
        f=R/('tests' if n.startswith('test_') else 'scripts')/n;shutil.copy2(f,src/n)
shutil.copy2(__file__,P/'sources/finalize_pilot.py')
for source,mirror in ((P,O/'published'),(Q,O/'recovery')):
    assert not mirror.exists();shutil.copytree(source,mirror)
    hashes={str(f.relative_to(source)):sha(f) for f in source.rglob('*') if f.is_file()}
    save(source/'file-checksums.json',hashes);shutil.copy2(source/'file-checksums.json',mirror/'file-checksums.json')
    assert all(sha(mirror/n)==h for n,h in hashes.items())
used=sum(allocated(x) for x in (P,Q,O/'published',O/'recovery'));fs=os.statvfs('/mnt/c');free=fs.f_bavail*fs.f_frsize
assert used<64*1024**2 and free>=8*1024**3
out={'status':'completed_replayed_and_mirrored','combined_result_allocated_bytes':used,'host_free_bytes':free,
    'primary_clean_completions':4,'primary_clean_pauses':2,'successful_linked_recoveries':2,
    'maximum_fixed_endpoint_f1_loss_points':maximum_loss*100,'quorum':10,'new_attack_inference':False,
    'original_core_and_defaults_unchanged':True}
(O/'final-storage-check.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
