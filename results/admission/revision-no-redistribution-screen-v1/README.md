# No-redistribution aggregation: completed small-storage screening

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
