# Retrospective group validation: selection and causal continuation

Date: 2026-11-03. Step 2, after baseline/DBA consolidation. Documentation is English.

## Findings and supported interpretation

The unchanged pair-conditioned V2 method is now evaluated on both IID and
non-IID histories with changed experimental attacker assignments. Its highest
ranked feasible group contains **two of three attackers in all six attacked
cases**. No priority group contains a benign client, but every one misses an
attacker. The complete candidate pool contains **15 true,
16 false and 3 missed client occurrences**.
All maximal cliques are retained; priority-group precision does not erase those
false candidates. No exact three-client clique is recovered.

The [post-selection true-pair diagnosis](PAIR_MEMBERSHIP_DIAGNOSIS.md) records
the three relevant edge scores in every attacked case. It explains which
frozen similarity requirements prevent complete clique recovery, without
lowering thresholds or inserting a missed member using identity truth.

A separately labelled secondary set, the union of frozen individual-envelope
quarantines through round 10, contains all three experimental attackers in each
case (18/18 client occurrences, zero false members). This is an anomaly-selected
set, **not a new pairwise collusion detector**. Both methods return no candidates
on the six ordinary clean histories. These are descriptive results on a small,
previously evaluated population; no general false-positive guarantee or malicious
intent follows.

The intervention study executes **293 direct removals**, **72 continuation branches**,
**4860 new local training calls** and **372 genuinely trained aggregation rounds**.
It separates immediate reaggregation from new local responses to the corrected
checkpoint. It also separates an unmodified future from a globally clean past.
The later, explicitly post-hoc hard-case rewind adds four full 15-round histories,
810 local training calls and 60 trained rounds. The **total for this step is
5,670 new local training calls and 432 genuinely trained aggregation rounds**.

Nonzero R15 ASR after joint envelope-set removal, if any: **non-iid 512593: 1.68%**.
The detailed tables below, including residual effects and adverse controls,
determine the conclusion; membership accuracy is not substituted for remediation.

## Frozen methods, source population and evidence boundary

This is a **secondary analysis of existing source trajectories**, not a fresh
untouched prospective evaluation. The group algorithm and its scale floor .05
are unchanged. All references, selection horizons, ranking/control rules and
interventions are recorded before their respective output computations.
No threshold is lowered to capture an observed missed client.

Each cohort uses three clean fitting histories and three disjoint clean
calibration histories. IID fitting uses original seeds 341593/342593/343593;
non-IID fitting uses 411593/412593/413593. Clean threshold calibration uses
451593/452593/453593 for IID and 454593/455593/456593 for non-IID. Only rounds
1–10 enter the fixed-horizon group reference and calibration. Thresholds are
9.23770954 (IID) and 6.44185855 (non-IID), each the maximum
clean campaign score with strict exceedance. Campaigns/pairs are dependent;
105 pairs per history are not 105 independent false-alarm trials.

Evaluation uses twelve shadow-FedAvg histories from the earlier frozen persistent
attack study: clean/distributed × three seeds × two cohorts. Each has 15 rounds
and 15 clients. IID seeds are 501593/502593/503593, non-IID
511593/512593/513593, with assignments shown below. The known Data24 partitions,
trigger features and ten-epoch local Adam protocol are retained. Both data
distributions have separate clean references; this is not transfer of an IID
reference to an uncalibrated cohort or an independent-dataset result.

The envelope comparator retains two previously fitted clean response predictors
and individual clean envelopes, including the earlier controlled clean-state
perturbation banks. V2 uses the pair-reference/calibration histories declared
here. Their clean-reference information budgets and objectives differ, so the
membership comparison is not an equal-information superiority claim.

Only deltas, tensor shapes, server-validation indicators, cohort/clean-role
bindings and frozen prefix decisions enter the selector. Neutral aliases hide
evaluation mode and attacker assignments in its input index. No private client
rows, ASR, identity truth or rounds 11–15 enter selection. Selection outputs
close before the evaluator reads truth or creates benign controls. This is a
verified data-flow separation; no new OS/Docker isolation or TPM attestation
is claimed. The evaluator/retrainer later accesses committed private snapshots
to execute the declared experimental interventions and unmodified references.

V2 ranks maximal cliques by the weakest conditioned edge, breaking ties by
client tuple. It selects the first clique retaining eight contributors. All
other and oversized candidates remain visible; no candidate is pruned using
truth. Empty selections remain empty. The secondary envelope set uses only
past/current R1–10 quarantines; its fixed-set removal is an investigative
counterfactual, not the original online release/confirmation policy.

## Selection results

TP/FP/FN refer to current experimental local poisoning membership. A benign
response to an inherited poisoned checkpoint is not labelled an intentional
poisoning act. Executed-row commitments and seeds are checked against the
declared simulator inputs for every evaluation prefix.

| Partition / seed | V2 pool TP / FP / FN | Priority V2 group | V2 TP / FP / FN | Envelope set | Envelope TP / FP / FN |
| --- | --- | --- | --- | --- | --- |
| iid / 501593 | 2 / 0 / 1 | 06/13 | 2 / 0 / 1 | 02/06/13 | 3 / 0 / 0 |
| iid / 502593 | 3 / 3 / 0 | 08/14 | 2 / 0 / 1 | 03/08/14 | 3 / 0 / 0 |
| iid / 503593 | 2 / 0 / 1 | 01/15 | 2 / 0 / 1 | 01/09/15 | 3 / 0 / 0 |
| non-iid / 511593 | 2 / 2 / 1 | 02/13 | 2 / 0 / 1 | 02/06/13 | 3 / 0 / 0 |
| non-iid / 512593 | 3 / 4 / 0 | 03/08 | 2 / 0 / 1 | 03/08/14 | 3 / 0 / 0 |
| non-iid / 513593 | 3 / 7 / 0 | 01/09 | 2 / 0 / 1 | 01/09/15 | 3 / 0 / 0 |


All six clean histories return no groups/secondary sets. False members in the
attacked V2 pools remain explicitly recorded in
[the selection summary](selection-summary.json). A top pair can be precise and
still incomplete. The envelope set's exact experimental membership does not
provide independent evidence of pairwise cooperation or malicious intent.

## Direct round-10 interventions

Each selected set is removed jointly and each selected client individually,
using exactly the same stored incoming checkpoint/local outputs. Weights of
remaining clients are renormalized; at least eight contributors are required.
No survivor admission rescoring is mixed into this effect. All 293 removal
outputs and their validation outcomes are recomputed from bound inputs in a
separate verification pass.

Up to twenty uniformly sampled benign subsets of equal size and the benign
subset closest in original sample mass are fixed before effects are inspected.
Truth is used only to identify benign controls. The identical selected subset
is excluded; overlaps with false benign members are allowed. The closest-mass
control is not chosen by ASR. Joint-minus-best-individual means
`ASR(best individual removal) - ASR(joint removal)`, in percentage points.
It is a descriptive contrast, not a theorem of statistical interaction.

| Partition / seed | Method | Source R10 ASR (%) | Joint R10 ASR (%) | Joint beyond best individual (pp) | Benign controls ≥ joint / total |
| --- | --- | --- | --- | --- | --- |
| iid / 501593 | Envelope prefix set | 49.07 | 0.00 | 27.31 | 0/21 |
| iid / 501593 | Pair V2 | 49.07 | 0.00 | 35.61 | 0/21 |
| iid / 502593 | Envelope prefix set | 17.50 | 0.00 | 0.34 | 0/21 |
| iid / 502593 | Pair V2 | 17.50 | 0.00 | 0.34 | 0/21 |
| iid / 503593 | Envelope prefix set | 0.06 | 0.00 | 0.00 | 0/21 |
| iid / 503593 | Pair V2 | 0.06 | 0.00 | 0.00 | 0/21 |
| non-iid / 511593 | Envelope prefix set | 0.00 | 0.00 | 0.00 | 21/21 |
| non-iid / 511593 | Pair V2 | 0.00 | 0.00 | 0.00 | 20/20 |
| non-iid / 512593 | Envelope prefix set | 97.59 | 49.30 | 42.62 | 0/21 |
| non-iid / 512593 | Pair V2 | 97.59 | 93.33 | 0.06 | 0/21 |
| non-iid / 513593 | Envelope prefix set | 0.00 | 0.00 | 0.00 | 19/21 |
| non-iid / 513593 | Pair V2 | 0.00 | 0.00 | 0.00 | 20/21 |


Control ranks include ties and are **not p-values**. If source ASR is zero,
zero joint ASR gives no demonstrated attack-success reduction. Such cases are
retained. More removed clients/sample mass, nonlinear inference and benign data
heterogeneity can affect these contrasts; observed joint improvement alone
does not prove collusion.

### Sample-mass controls

Equal client counts can remove very different aggregation weights under non-IID
data. These mass differences are therefore reported rather than hidden:

| Partition / seed | Method | Selected mass removed (%) | Closest benign set | Benign mass removed (%) | Mass difference (pp) |
| --- | --- | --- | --- | --- | --- |
| iid / 501593 | Envelope prefix set | 20.00 | 03/04/05 | 20.00 | 0.00 |
| iid / 501593 | Pair V2 | 13.33 | 03/04 | 13.33 | 0.00 |
| iid / 502593 | Envelope prefix set | 20.00 | 02/04/05 | 20.00 | 0.00 |
| iid / 502593 | Pair V2 | 13.33 | 02/04 | 13.33 | 0.00 |
| iid / 503593 | Envelope prefix set | 20.01 | 02/03/04 | 20.00 | -0.01 |
| iid / 503593 | Pair V2 | 13.35 | 02/03 | 13.33 | -0.01 |
| non-iid / 511593 | Envelope prefix set | 4.13 | 01/03/09 | 8.50 | 4.37 |
| non-iid / 511593 | Pair V2 | 1.76 | 03/09 | 4.88 | 3.11 |
| non-iid / 512593 | Envelope prefix set | 35.58 | 07/11/15 | 33.78 | -1.80 |
| non-iid / 512593 | Pair V2 | 11.80 | 04/10 | 11.75 | -0.04 |
| non-iid / 513593 | Envelope prefix set | 15.71 | 05/11/12 | 15.63 | -0.08 |
| non-iid / 513593 | Pair V2 | 7.23 | 05/12 | 7.53 | 0.30 |


## New training after the corrected checkpoint

Membership is fixed from R1–10. At R10 each original-script branch starts from
the direct corrected aggregate. For R11–15 all remaining clients train again
from that branch's actual global checkpoint, with source seeds, fresh Adam,
same data and original remaining-attack schedules. No historical future update
is reused. The two benign continuation controls are closest-mass and the first
hash-random subset; direct results contain the larger control pool.

No-intervention continuation reproduces all **450 local outputs** and **30 new
global checkpoints** of the six source tails byte-for-byte. Its six R10 starting
checkpoints are also exact copies. The source reproduction distinguishes an
intervention effect from a changed training implementation.

| Partition / seed | Method | Source R15 ASR (%) | Joint R15 ASR (%) | Individual R15 ASRs (%) | Benign R15 ASRs (%) | Joint beyond best individual (pp) |
| --- | --- | --- | --- | --- | --- | --- |
| iid / 501593 | Envelope prefix set | 0.00 | 0.00 | 0.00, 0.00, 0.00 | 0.00, 0.00 | 0.00 |
| iid / 501593 | Pair V2 | 0.00 | 0.00 | 0.00, 0.00 | 0.00, 0.00 | 0.00 |
| iid / 502593 | Envelope prefix set | 50.93 | 0.00 | 30.90, 30.85, 15.76 | 83.45, 88.11 | 15.76 |
| iid / 502593 | Pair V2 | 50.93 | 0.00 | 30.85, 15.76 | 72.74, 71.12 | 15.76 |
| iid / 503593 | Envelope prefix set | 55.47 | 0.00 | 30.17, 33.88, 14.64 | 86.32, 89.51 | 14.64 |
| iid / 503593 | Pair V2 | 55.47 | 0.00 | 30.17, 14.64 | 73.42, 72.57 | 14.64 |
| non-iid / 511593 | Envelope prefix set | 0.00 | 0.00 | 0.00, 0.00, 0.00 | 0.00, 0.00 | 0.00 |
| non-iid / 511593 | Pair V2 | 0.00 | 0.00 | 0.00, 0.00 | 0.00, 0.00 | 0.00 |
| non-iid / 512593 | Envelope prefix set | 99.94 | 1.68 | 99.94, 98.32, 92.48 | 100.00, 100.00 | 90.80 |
| non-iid / 512593 | Pair V2 | 99.94 | 98.21 | 99.94, 98.32 | 100.00, 100.00 | 0.11 |
| non-iid / 513593 | Envelope prefix set | 15.31 | 0.00 | 1.40, 7.40, 0.00 | 31.91, 99.21 | 0.00 |
| non-iid / 513593 | Pair V2 | 15.31 | 0.00 | 1.40, 7.40 | 18.28, 30.68 | 1.40 |


Positive joint-minus-best-individual contrasts strengthen the descriptive
coordinated-effect hypothesis under these inputs. Zero/negative contrasts,
equally effective benign controls, unsuccessful source attacks and residual ASR
must remain visible. These are finite investigator interventions, not a rule
authorizing permanent bans.

## What exact reference equality means here

For each selected joint set, an independent branch starts from the same actual
incoming **W9**, uses the same remaining clients and seeds, and executes only
unmodified snapshots from R10 through R15. This reference has extra privileged
input evidence. Its incoming W9 can already contain poisoning. Equality to
this reference proves equality of that declared future execution; it does
**not** reconstruct a hypothetical globally clean history before W9.

Complete tail equality (inputs, local outputs and globals at every round) holds
in 0/6 V2 selections and 6/6 envelope selections.
The all-client clean history is a separate diagnostic with different participation.
Its model distance includes both poisoning history and the removal intervention,
so it cannot alone attribute residual differences to poisoning.

| Partition / seed | Method | Exact same-start unmodified tail? | Reference R15 ASR (%) | Distance to reference (L2) | Distance to all-client clean history (L2) | Clean-history prediction differences / 3223 |
| --- | --- | --- | --- | --- | --- | --- |
| iid / 501593 | Envelope prefix set | Yes | 0.00 | 0.00000 | 4.33613 | 12 |
| iid / 501593 | Pair V2 | No | 0.00 | 0.61671 | 4.49255 | 17 |
| iid / 502593 | Envelope prefix set | Yes | 0.00 | 0.00000 | 2.70224 | 6 |
| iid / 502593 | Pair V2 | No | 0.00 | 0.92728 | 3.18271 | 9 |
| iid / 503593 | Envelope prefix set | Yes | 0.00 | 0.00000 | 3.10721 | 11 |
| iid / 503593 | Pair V2 | No | 0.00 | 0.85400 | 3.36485 | 17 |
| non-iid / 511593 | Envelope prefix set | Yes | 0.00 | 0.00000 | 1.01280 | 2 |
| non-iid / 511593 | Pair V2 | No | 0.00 | 0.23454 | 0.99210 | 1 |
| non-iid / 512593 | Envelope prefix set | Yes | 1.68 | 0.00000 | 4.90746 | 29 |
| non-iid / 512593 | Pair V2 | No | 3.31 | 2.54548 | 5.62170 | 32 |
| non-iid / 513593 | Envelope prefix set | Yes | 0.00 | 0.00000 | 2.33710 | 13 |
| non-iid / 513593 | Pair V2 | No | 0.00 | 1.07607 | 2.75366 | 9 |


The reference ASR can itself be nonzero when the starting checkpoint is already
affected. Conversely, ASR zero with unequal model/input histories is not proof
of clean-state recovery. These checks preserve precisely the separation between
structural exposure, numerical effect and semantic interpretation requested in
the supervisor correspondence.

## Complete rewind of the residual hard case

After the primary verification exposed residual ASR, an additional protocol
selected the **largest observed envelope-set R15 residual**, breaking ties by
alias: non-iid seed 512593. This is a labelled, post-hoc
mechanistic follow-up, not another independent discovery-validation case.
Its group membership and detector thresholds are unchanged. Four full 15-round
histories were specified before this additional training:

1. Reproduce the original all-client scripted attack from W0.
2. Exclude the same already selected set from R1–15, retraining every remaining
   client at every round under the original script.
3. Independently train an unmodified reference with those same exclusions.
4. Reconstruct the all-client unmodified history, using the original snapshots.

This adds 810 local calls and 60 newly trained aggregation rounds. All 60
aggregate exports and 810 input commitments are rechecked. The original-source
and all-client clean-reference arms match **450 stored local outputs and
30 checkpoints** byte-for-byte. The selected-exclusion arm and its matched
unmodified reference have complete 15-round equality:
**Yes**.

| Intervention | R15 validation ASR (%) | R15 test ASR (%) | R15 test accuracy (%) | R15 test macro-F1 (%) |
| --- | --- | --- | --- | --- |
| Late R10 selected-set removal | 1.68 | 1.54 | 96.35 | 95.98 |
| Original scripted attack, all clients | 99.94 | 99.91 | 96.37 | 94.45 |
| W0 replay excluding the selected set | 0.00 | 0.00 | 96.33 | 95.96 |
| W0 matched unmodified reference, same exclusions | 0.00 | 0.00 | 96.33 | 95.96 |
| W0 privileged unmodified replay, all clients | 0.00 | 0.00 | 96.07 | 94.50 |


The W0 exclusion replay concerns the reduced population, not the original
all-client clean model. The all-client unmodified replay is a different,
privileged intervention: it matches the original all-client clean history
exactly, but requires access to the correct original snapshots, seeds, code,
starting checkpoint and deterministic environment. Snapshot commitment alone
does not establish that its contents were semantically clean.

The comparison demonstrates why the starting point matters in this controlled
case. Excluding every selected attacker late can leave inherited behavior;
replaying from before the scripted poisoning removes that measured residual
under the declared reference assumptions. No actual production history is
rewritten and no universal recovery guarantee is inferred. See
[the frozen follow-up protocol](full-rewind-protocol-before-training.json)
and [full-rewind verification](full-rewind-verification.json).

## Test endpoints, checks and retained limitations

The existing 4,937-row isolated test fold is evaluated at R10/R15 for selected
sets, individuals, continuation benign controls and no intervention; unmodified
references also have R15 endpoints. It has been used in previous studies and is
not claimed as a pristine external holdout. No candidate or threshold is chosen
using these outcomes. [Selected test endpoint table](TEST_SELECTED_ENDPOINTS.md)
and [all endpoint records](test-endpoints.json) retain full/component ASR,
accuracy, macro-F1 and untriggered target rates with explicit denominators.

Verification counts:

- 1800 source-prefix local-input/seed commitments checked.
- 293 direct model exports and their complete validation outcomes recomputed.
- 432 branch recurrence/model exports recomputed, including R10 stored-output steps.
- 4860 newly executed local-input commitments checked.
- 450 no-intervention local outputs and 30 new checkpoints matched exactly.
- 72 final validation endpoints and 138 test endpoints recomputed.
- 12 full same-start unmodified-reference comparisons.

The separate hard-case rewind adds 60 verified aggregates, 810 input commitments,
four final validation/test endpoint pairs and the complete reference comparisons
above. Its existing-test-fold results are not used to retune the detector.

The relevant **31 tests pass**, with two existing Typer deprecation warnings.
Production source is unchanged across all 114 package files; the prior 631-pass
full-suite result remains applicable and is not represented as a fresh full run.
No detector algorithm, automatic policy, attestation protocol or thesis source
is changed. No ToN-IoT acquisition or new TPM campaign is performed.

New source selections/replays are signed and hash-bound as local software analyst
evidence, not independent witness registration or trusted time. Previous signed
campaigns and completion records remain preserved. The source archive, input
index, private source pins, selection closure, pre-intervention plan, full pools,
controls and every branch manifest are retained for review.

The study strengthens the agreed **retrospective** analysis across identities
and data distributions. It does not establish complete update-only collusion
discovery: V2 still misses a member in every priority group and flags benign
members in its wider pools. The successful anomaly-selected sets support
additional review/interventions, not semantic verdicts. Live automatic quarantine,
adaptive peak suppression, final formal correspondence and thesis integration
remain separate work. ToN-IoT remains deferred.

Figures: [all validation tails](continuation-asr.png),
[selection errors](group-selection-errors.png),
[direct versus subsequent joint effects](joint-effect-contrasts.png),
[late correction versus complete rewind](full-rewind-hard-case.png).
Each has a PDF export. [Compact numerical effects](effect-summary.csv).
