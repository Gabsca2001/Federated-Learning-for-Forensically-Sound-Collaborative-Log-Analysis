from pathlib import Path
import json,hashlib,shutil,sys,os
R=Path('/home/gio/projects/Federated-Learning-for-Forensically-Sound-Collaborative-Log-Analysis')
O=Path(__file__).parent;D=R/'results/revision-no-redistribution-screen-v1';M=O/'published'
def read(p):return json.loads(p.read_bytes())
def sha(p):
    with p.open('rb') as h:return hashlib.file_digest(h,'sha256').hexdigest()
def allocated(p):return sum(f.stat().st_blocks*512 for f in p.rglob('*') if f.is_file())
def save(p,v):
    assert not p.exists(),p
    p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
summary=read(D/'summary.json');p=read(D/'protocol-before-inference.json')
old=read(R/'artifacts/revision-capped-final-v1/protocol-before-training.json')
assert all(sha(R/name)==h for name,h in old['source_locks'].items())
assert all(sha(R/name)==h for name,h in p['source_locks'].items())
publication=R/'results/revision-capped-final-v1'
assert all(sha(publication/name)==h for name,h in read(publication/'publication-manifest.json')['files'].items())
sys.path.insert(0,str(R/'src'))
from fl_forensics.round_derivation import implementation_sha256
assert implementation_sha256()=='8d7efa28b62a47d306a12958d66b3081d6527518f25641545cc81456640d2e64'
save(D/'source-integrity.json',{'original_generation_source_locks_verified':len(old['source_locks']),
    'screen_source_locks_verified':len(p['source_locks']),'original_publication_checksums_unchanged':True,
    'implementation_sha256':implementation_sha256(),'current_defaults_changed':False})
save(D/'focused-tests.json',{'command':'python -m pytest tests/test_no_redistribution_aggregation.py tests/test_capped_final_aggregation.py -q',
    'observed_result':'19 passed in 0.29s','new_tests':8,'existing_comparison_tests':11,
    'timing':'Executed before candidate inference. Subsequent runner-only path/hash fixes did not change the tested operator or test sources.',
    'operator_sha256':sha(R/'scripts/no_redistribution_aggregation.py'),
    'new_tests_sha256':sha(R/'tests/test_no_redistribution_aggregation.py')})
text='''# No-redistribution aggregation: completed small-storage screening

The hypothesis was tested on the two previously identified non-IID failure
seeds, 6116104 and 6116105. Both original robust and capped-robust parent
histories were included, with clean, distributed, full-trigger and adaptive
branches and all fifteen saved rounds. This yields 240 contexts, including
232 distinct seed/base/update input sets. Repeated contexts are not independent
replications. All 960 one-step outputs use validation only. No local training,
new test inference, new defender-specific adaptive search or TPM Quote occurred.

## Operator and contract

For the same fixed clipped deltas and normalized robust proposal p, the candidate
uses beta_i=min(p_i,1/9) and retains weight 1-sum(beta) at the source checkpoint.
It never redistributes discarded coefficient mass to another client. The
matched-step control instead uses beta_i=sum(cut)*p_i, which is simply a scalar
reduction of the original robust step. It matches total client coefficient mass,
not the actual update vector norm. Original robust and water-filled capped
operators are retained as additional controls.

The candidate's at-most-three absolute coefficient sum is at most 1/3 in the
step including the retained checkpoint. Its share after normalizing only client
coefficients can exceed 1/3. It does not preserve the older client-only group
budget contract. Admission counts and original zero/veto rules are not restored
or silently changed. Retaining an already contaminated checkpoint does not
remove its historical influence. No formal model or operational default changed.

## Observed security comparisons

The table describes 120 contexts with actually manipulated current updates.
Worst-trigger ASR is the maximum over the full trigger and the three individual
component triggers. Counts compare the candidate to each control on the SAME
parent and current inputs. They are not counts of independent campaigns.

| Control | Candidate lower ASR | Candidate higher ASR | Equal ASR |
| --- | ---: | ---: | ---: |
| Original robust | 2 | 32 | 86 |
| Water-filled capped | 47 | 0 | 73 |
| Scalar matched-step robust | 1 | 32 | 87 |

The candidate avoids some unfavorable capped redistributions, but does not
outperform simply shrinking the robust step. It cannot be promoted as a new
validated defense on this evidence. The inherited adaptive exports were chosen
against their ORIGINAL source defender, not adaptively against this candidate.

## Clean utility and mechanism

All sixty clean contexts are retained. Relative to robust, the candidate's
maximum one-step clean macro-F1 loss is 0.4103 percentage points; relative to
matched-step robust it is 0.3971 points. Relative to water-filled capped, sixteen
contexts lose more than two points and the worst difference is 20.4902 points.
The inherited two-point budget is a descriptive check here, not new independent
confirmation or a threshold fitted to these results.

For example, source seed 6116104, robust-clean round 5 starts with macro-F1
0.66124. On that SAME parent and updates, water-filled capped reaches 0.88708,
while the no-redistribution candidate reaches 0.68218. Thus the 20.49-point
difference is a missed improvement relative to the capped alternative, not a
20.49-point deterioration from the starting checkpoint. Capping and
redistributing can help normal classification even though it can hurt security.
Removing redistribution alone does not resolve the security/utility tradeoff.

Maxima across these frozen contexts must not be called defended trajectory
peaks, and round-15 one-step results must not be called newly trained endpoints.
Every alternative starts from a source trajectory; its changed output is never
fed into the next saved local-training round. A full retraining experiment would
be required for trajectory or recovery conclusions. No large new campaign is
justified for this candidate by the current comparison.

## Verification and storage

Nineteen focused tests passed: eight for the new numerical helper and eleven
for the existing capped control. Generation reconstructed all 240 actual source
checkpoints and their original validation metrics, checked the clipping map
against original updates and checked an alternate summation layout. A separate
record checker rehashed 4,560 input references, checked exact coefficient
equations, recomputed metric arithmetic from confusion/count records and
rejected hidden renormalization, changed trigger ASR and changed clean F1.
This is not an independent implementation of neural-network inference.

All 138 original generation-source pins, the original publication checksums and
the measured 130-module core identity remain unchanged. The two initial
controller interruptions were preserved. Path-type and export-hash binding
corrections changed no formula, cap, task or selection rule; no candidate
results were produced before those corrections.

Only summaries, coefficients, metrics and input hashes are written. Original
datasets, updates and checkpoints are referenced in place. A fixed 64 MiB
combined output budget and 8 GiB host-free floor were checked throughout.
The original inputs remain necessary for reconstruction; this is not a
self-contained recovery archive. Final footprint and host free space are
recorded separately. No old scientific results were removed during this probe.

The next distinct hypothesis is whether a representative clean server reference
improves the direction of aggregation. It would require a separately named
protocol and disjoint training/calibration/evaluation roles; it is not already
validated by this screen.
'''
assert summary['comparisons_on_actually_manipulated_rounds']['matched_step']['higher_worst_trigger_asr']==32
assert summary['comparisons_on_actually_manipulated_rounds']['capped']['lower_worst_trigger_asr']==47
assert abs(summary['clean_context_checks']['capped']['worst_clean_f1_loss_points']-20.490215513454444)<1e-9
(D/'README.md').write_text(text)
sources=D/'sources';sources.mkdir()
for source in (R/'scripts/no_redistribution_aggregation.py',R/'scripts/revision_no_redistribution_screen.py',R/'tests/test_no_redistribution_aggregation.py'):
    shutil.copy2(source,sources/source.name)
for name in ('run.log','run-corrected.log','run-export-corrected.log'):
    shutil.copy2(O/name,D/name)
shutil.copy2(__file__,D/Path(__file__).name)
assert not M.exists()
shutil.copytree(D,M)
manifest={str(f.relative_to(D)):sha(f) for f in D.rglob('*') if f.is_file()}
save(D/'file-checksums.json',manifest);shutil.copy2(D/'file-checksums.json',M/'file-checksums.json')
assert all(sha(M/name)==h for name,h in manifest.items())
host=os.statvfs('/mnt/c');free=host.f_bavail*host.f_frsize
size=allocated(D)+allocated(M)
assert size<64*1024**2 and free>=8*1024**3
result={'status':'completed_and_mirrored','linux_result_allocated_bytes':allocated(D),
    'windows_result_copy_allocated_bytes':allocated(M),'combined_result_allocated_bytes':size,
    'host_free_bytes':free,'budget_bytes':64*1024**2,'minimum_host_free_bytes':8*1024**3,
    'files_verified_in_windows_copy':len(manifest),'new_training_runs':0,'no_new_large_campaign_started':True}
(O/'final-storage-check.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
