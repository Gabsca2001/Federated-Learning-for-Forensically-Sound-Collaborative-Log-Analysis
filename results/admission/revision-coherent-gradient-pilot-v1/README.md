# Coherent gradient protocol and explicit availability recovery

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
| s6116104-coherent-fltrust-root7110701 | 15 | 48 | -0.0354 | -0.0354 |
| s6116104-coherent-fltrust-root7110702 | 15 | 48 | 0.0302 | 0.0302 |
| s6116104-coherent-fltrust-root7110703 | paused at0 | 60, linked expansion | 0.0000 | 0.0000 |
| s6116105-coherent-fltrust-root7110701 | paused at0 | 60, linked expansion | 0.0000 | 0.0000 |
| s6116105-coherent-fltrust-root7110702 | 15 | 48 | 0.0151 | 0.0151 |
| s6116105-coherent-fltrust-root7110703 | 15 | 48 | 0.0000 | 1.1221 |

The largest fixed-endpoint loss across four direct and two linked completions
is 1.1221 F1 points. F1 equality does not imply identical parameters.
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
