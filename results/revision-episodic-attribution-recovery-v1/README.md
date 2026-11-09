# V5: separate utility risk and repeated actor-anomaly episodes

This completed study implements the correction proposed after the frozen V4
diagnosis. V5 does not let macro-F1 utility risk create an actor anomaly or group
edge. Identity evidence uses repeated magnitude excess; groups require temporal
coexceedance on that SAME mechanism. Utility risk and tensor descriptors remain
visible as separate investigative evidence. No operational policy changes.

## Common-input V4/V5 assessment

Both methods observe the exact same fourteen source histories on two new actual
allocation memberships and different scheduled adversarial rosters. They share
the same two clean fitting and three clean calibration histories. The V4 rule is
unchanged and recalibrated on those same clean observations, rather than comparing
methods on different attacks or hiding the previous failures.

| Method | Family | Schedule | Effective raw controls | Selected group TP/FP/FN | Individual TP/FP/FN |
| --- | --- | --- | ---: | ---: | ---: |
| v4 | unrestricted | persistent | 3/4 | 10/5/2 | 10/5/2 |
| v4 | unrestricted | intermittent | 3/4 | 10/3/2 | 10/5/2 |
| v4 | relative-radius | persistent | 0/4 | 4/0/8 | 6/0/6 |
| v5 | unrestricted | persistent | 3/4 | 9/0/3 | 9/0/3 |
| v5 | unrestricted | intermittent | 3/4 | 9/0/3 | 9/0/3 |
| v5 | relative-radius | persistent | 0/4 | 4/0/8 | 6/0/6 |

Across all 36 scheduled adversarial client-history roles, V4 selects
24 true and 8 benign memberships while missing
12; V5 selects 22 true and 0 benign
memberships while missing 14. This is an observed precision/recall
trade-off, not uniform dominance. Separate utility risks are not hidden:
separated-client-signals.csv preserves them alongside both actor assessments.
classwise-utility.csv reconstructs per-class TP, FP, FN, support and F1 from every
source/replay confusion matrix, together with the same-excluded-roster clean
comparison. This retains the rare-class impact instead of hiding it in accuracy.
The original full-roster clean comparison is also exported, so the utility cost
of omitting clients is not cancelled by choosing an already-excluded reference.

Memberships count client-history entries, not independent persons. The same three
scheduled identities recur across each allocation's variants. Actual modified
rounds and threshold-exceedance rounds remain available; a scheduled attacker can
export an honest alpha0 update. Ineffective raw controls remain reported and
cannot establish resistance or recovery success.

| Method | Clean histories with selected group | False clean group members | False clean individual flags |
| --- | ---: | ---: | ---: |
| v4 | 0/2 | 0 | 0 |
| v5 | 0/2 | 0 | 0 |

## New source histories

| Case | Allocation | Variant | Family | Schedule | Peak worst ASR | Effective raw control | V5 selected group |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| case-00 | 6124001 | clean | unrestricted | persistent | 0.00% | no | none |
| case-01 | 6124001 | distributed | unrestricted | persistent | 0.00% | no | none |
| case-02 | 6124001 | complete-trigger | unrestricted | persistent | 90.02% | yes | client01, client09, client14 |
| case-03 | 6124001 | distributed | relative-radius | persistent | 0.00% | no | client01, client14 |
| case-04 | 6124001 | complete-trigger | relative-radius | persistent | 0.00% | no | client01, client14 |
| case-05 | 6124001 | distributed | unrestricted | intermittent | 0.00% | no | none |
| case-06 | 6124001 | complete-trigger | unrestricted | intermittent | 86.50% | yes | client01, client09, client14 |
| case-07 | 6125001 | clean | unrestricted | persistent | 0.00% | no | none |
| case-08 | 6125001 | distributed | unrestricted | persistent | 34.45% | yes | client04, client08, client12 |
| case-09 | 6125001 | complete-trigger | unrestricted | persistent | 99.54% | yes | client04, client08, client12 |
| case-10 | 6125001 | distributed | relative-radius | persistent | 0.00% | no | none |
| case-11 | 6125001 | complete-trigger | relative-radius | persistent | 0.00% | no | none |
| case-12 | 6125001 | distributed | unrestricted | intermittent | 27.52% | yes | client04, client08, client12 |
| case-13 | 6125001 | complete-trigger | unrestricted | intermittent | 99.54% | yes | client04, client08, client12 |

Raw source training remains count-weighted FedAvg; retrospective V5 does not
block its updates. Those ASRs measure the attack under the source protocol, not
online mitigation by V5. Full and each individual trigger are measured; worst
ASR is their maximum. Trigger composition necessity is not established.

## Episode rule and separate utility output

V5 uses the THIRD-largest standardized log1p(relative norm) over ten rounds as
each client's episode statistic. Its strict clean-calibrated threshold is
5.222720920, obtained as the maximum of the calibration campaign/client statistics.
This is a new statistic with its own calibration, not V4's median threshold
reused or lowered after consulting attacker identities. Pair edges require more
than 2 common exceedance rounds and both
individual episode flags. No known group size is forced; a selected clique must
leave ten contributors. One or two, staggered, small or norm-constrained adverse
submissions can escape this contract. Genuine benign large updates may qualify.

The unchanged macro-F1 channel has a separate utility-risk output at threshold
5.222250143. A benign contribution can really harm a
rare class and still not justify a malicious-identity hypothesis. V5 retains that
risk rather than erasing it from evaluation. Coactivity on unlike channels no
longer makes a V5 group. Shared magnitude/time behavior still does not prove
intentional collusion or authorize automatic permanent exclusion.

Continuous validation loss and model-state-aware utility calibration remain
separate proposed extensions, not new validated inputs of V5. The earlier
diagnosis already showed why replacing macro-F1 with loss alone cannot establish
malicious identity: some honest updates also increase validation loss.

## Full-origin replay of selected and oracle-known groups

On effective raw controls, V5 selected groups have zero final full/component ASR
in 6/6 comparisons;
6/6 match EVERY
checkpoint of their same-excluded-roster clean reference. Oracle-labelled roles
are separate diagnostics; when a selected group equals the oracle, the shared
numerical branch is not an independent replication.

| Case | Group role | Original final worst ASR | Origin joint-removal ASR | Closest-mass benign-removal ASR | Every checkpoint equals same-roster clean |
| --- | --- | ---: | ---: | ---: | --- |
| case-02 | v5 | 88.63% | 0.00% | 91.40% | yes |
| case-02 | oracle-diagnostic | 88.63% | 0.00% | 91.40% | yes |
| case-06 | v5 | 84.82% | 0.00% | 90.94% | yes |
| case-06 | oracle-diagnostic | 84.82% | 0.00% | 90.94% | yes |
| case-08 | v5 | 34.45% | 0.00% | 27.52% | yes |
| case-08 | oracle-diagnostic | 34.45% | 0.00% | 27.52% | yes |
| case-09 | v5 | 99.42% | 0.00% | 98.90% | yes |
| case-09 | oracle-diagnostic | 99.42% | 0.00% | 98.90% | yes |
| case-12 | v5 | 27.52% | 0.00% | 22.39% | yes |
| case-12 | oracle-diagnostic | 27.52% | 0.00% | 22.39% | yes |
| case-13 | v5 | 99.54% | 0.00% | 98.73% | yes |
| case-13 | oracle-diagnostic | 99.54% | 0.00% | 98.73% | yes |

All fifteen rounds are retrained from preserved pre-attack W0. Surviving attackers
relearn endpoints and requery each corrected parent on their DECLARED active
dates, including the intermittent schedule. Historical vectors and original
alphas are never reused at changed parents. No-removal reproduces the source.
Individual, joint, closest-mass and hash-ranked benign removals remain reported.
Some single removals may reach zero ASR too; joint zero alone cannot demonstrate
synergy, composition necessity or intentional coordination.
The offline runner retains client rows and deterministic training; live-client
availability and cooperation for such replay are not established by this study.

Exact clean matching assumes clean W0, correct attribution, complete removal of
active attackers and the frozen deterministic training/data contract. The clean
reference omits the SAME clients during the replay interval; earlier benign
influence already in W0 remains in both. This is conditional restoration to the
client-exclusion counterfactual, not selective erasure of only poisoned rows or
restoration to the original full-roster model. Nonzero parameter residuals and
utility losses are retained even when all tested ASRs are zero.
origin-branches.csv and classwise-utility.csv retain utility loss to BOTH clean
references. Equality to the same-excluded-roster reference does not by itself
establish harmless removal relative to ordinary training with all clients.

| V5 selected replay | Final clean accuracy | Final macro-F1 | F1 loss to full-roster clean (percentage points) |
| --- | ---: | ---: | ---: |
| case-02 | 96.65% | 93.60% | +0.0302 |
| case-06 | 96.65% | 93.60% | +0.0302 |
| case-08 | 96.71% | 93.63% | +0.0000 |
| case-09 | 96.71% | 93.63% | +0.0000 |
| case-12 | 96.71% | 93.63% | +0.0000 |
| case-13 | 96.71% | 93.63% | +0.0000 |

Negative loss denotes an improvement. Per-class changes and worst intermediate
utility loss remain in the CSVs; final utility alone is not the entire trajectory.

## Protocol, interruption and verification

Schedules and cases were frozen before new assessment outcomes. Persistent
attacks are active in R1-10; intermittent attacks in [1,2,4,7,10]; R11-15 are
unmodified continuation. Per-active-round poisoned-row budgets match between
distributed/full variants; feature-edit and total row-round budgets differ across
variant/schedule. All adversaries use the restricted six-factor poisoned-Adam
endpoint families and privileged validation/same-roster-clean feedback. They
optimize raw ASR with a five-point F1 guard, not unrestricted evasion of V5.
The relative-radius family bounds submitted norm by five times its own honest
gradient norm; ineffective controls do not validate stealth resistance.

The external run stopped after twelve completed source cases without a recorded
numerical exception. Only the two missing cases were resumed. The completed
files were hashed before resumption and checked unchanged before closure; full
fresh replay then checked ALL cases and branches. The cause of the interruption
is unknown. No incomplete case was silently overwritten or counted complete.

40 focused tests pass, including eight new episode, channel-separation, limited-
support, overlap and quorum cases. Fresh deterministic replay covers 50 clean
fit/calibration rounds, 210 source rounds and
630 origin-replay rounds in
42 branches, including
2220 adaptive queries and
14 clean references. Separate
accounting reconstructs 3320 metric sets, validates 2220 candidate
queries and 370 parent-specific selections, schedules, budgets,
sample-weight coefficients, episode scores, utility
outputs, group support and 120 relative-radius bounds.
Replay uses the same numerical implementation; it is not independent classifier
reimplementation. Numerical threads are fixed at one for both compared methods.

Both new allocations reuse the same 7096 Data24 training rows, W0 and 3163 reused
root-disjoint validation rows (1733 non-target ASR rows). All eleven relevant
allocation memberships were checked distinct; this does not make them independent
datasets or establish population error rates. The five clean roles are reused
development resources. Old V4 diagnosis, failed selectors/late recovery and all
predecessor publications remain intact. Experimental manifests use software
research keys; there is no fresh TPM Quote, physical-TPM validation, client
signature, new policy default, independent dataset or thesis edit.
