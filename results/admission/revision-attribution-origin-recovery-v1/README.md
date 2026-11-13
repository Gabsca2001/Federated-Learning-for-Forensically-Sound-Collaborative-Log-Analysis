# V4 retrospective attribution and full-origin recovery

The completed frozen study distinguishes individual anomaly, coincident group
activity and actual corrected-parent recovery. It does not authorize automatic
exclusion. The existing V2/V3 failures, late-R10 failures and preventive numerical
containment results remain unchanged, with separate evidence and interpretation.

## New assessment results

- unrestricted: 3/4 effective raw controls; group memberships TP=5,FP=0,FN=7; individual memberships TP=11,FP=9,FN=1.
- relative-radius: 0/4 effective raw controls; group memberships TP=2,FP=2,FN=10; individual memberships TP=2,FP=2,FN=10.

The two fresh clean histories yield selected groups in
0/2 cases, with
0 false group members and
0 individually flagged benign clients.
Membership counts repeat three scheduled adversarial identities across variants;
they are not independent persons. Actual altered export counts and alpha0 active
rounds are retained. A scheduled attacker may export an unmodified alpha0 update.

| Allocation | Family | Variant | Effective raw attack | Peak worst ASR | Selected group | TP/FP/FN |
| --- | --- | --- | --- | ---: | --- | --- |
| 6122001 | unrestricted | clean | no | 0.00% | none | 0/0/0 |
| 6122001 | unrestricted | distributed | yes | 61.92% | client02, client08, client15 | 3/0/0 |
| 6122001 | unrestricted | complete-trigger | yes | 43.10% | client02, client08 | 2/0/1 |
| 6122001 | relative-radius | distributed | no | 0.00% | none | 0/0/3 |
| 6122001 | relative-radius | complete-trigger | no | 0.00% | none | 0/0/3 |
| 6123001 | unrestricted | clean | no | 0.00% | none | 0/0/0 |
| 6123001 | unrestricted | distributed | no | 0.00% | none | 0/0/3 |
| 6123001 | unrestricted | complete-trigger | yes | 98.62% | none | 0/0/3 |
| 6123001 | relative-radius | distributed | no | 0.00% | client06, client07 | 1/1/2 |
| 6123001 | relative-radius | complete-trigger | no | 0.00% | client06, client07 | 1/1/2 |

Ineffective relative-radius controls remain included. Low ASR in those cases is
not evidence of resistance or a successful recovered model. A small constrained
attack may still be identified as anomalous or may escape attribution; neither
outcome validates a general stealth-adversary guarantee.

## Recovery from before the first attack round

For effective raw controls, selected-group recovery reaches zero measured full
and individual-trigger ASR in
2/2
selected-group comparisons; 1/2
match every checkpoint of the independently executed same-excluded-roster clean
counterfactual. Oracle-known groups remain a separate diagnostic, even when they
coincide with the detector output; deduplicated numerical branches are not
independent replications of these two roles.

| Allocation | Variant | Group role | Original final worst ASR | Origin joint-removal ASR | Matched benign-removal ASR | All checkpoints equal same-roster clean |
| --- | --- | --- | ---: | ---: | ---: | --- |
| 6122001 | distributed | v4 | 61.86% | 0.00% | 79.63% | yes |
| 6122001 | distributed | oracle-diagnostic | 61.86% | 0.00% | 79.63% | yes |
| 6122001 | complete-trigger | v4 | 42.70% | 0.00% | 46.91% | no |
| 6122001 | complete-trigger | oracle-diagnostic | 42.70% | 0.00% | 48.24% | yes |
| 6123001 | complete-trigger | oracle-diagnostic | 98.50% | 0.00% | 99.88% | yes |

Every replay starts at the preserved W0 before R1. Each surviving honest client
recomputes its gradient at the actual corrected parent. Every surviving attacker
relearns its poisoned Adam endpoint and reruns all six adaptive queries at that
parent in R1-10; R11-15 use the declared unmodified continuation. No historical
client tensor or original selected alpha is reused as a future update.
No-removal branches reproduce the complete new source histories. Individual,
joint, hash-ranked benign and closest-mass benign removals are all retained.
There is one hash and one closest-mass control per group role, not a calibrated
distribution of intervention effects or an inferential p-value.
Some individual removals also reach zero final ASR. Joint-removal zero alone
therefore cannot prove that all members were necessary, that the full trigger
requires all components, or that the group intentionally colluded. Read the
retained individual effects and same-roster parameter residuals together.

The clean comparison excludes exactly the same clients during R1-15 and retrains
from the same W0. Earlier benign influence already in W0 remains in both models.
The comparison accounts for omitted benign as well as poisoned replay-period
contributions. Equality
with that reference is conditional exact reproduction under this deterministic
simulation, not certified unlearning of only poisoned rows, restoration of the
original full-roster model or proof that a real deployment's W0 is clean.
Correct attribution, clean W0 and complete removal of all active attackers are
essential assumptions. Authenticity of a checkpoint alone does not prove its
semantic cleanliness. Missing/false members stay visible in membership results.

### Residual effect despite zero ASR

- Allocation 6122001 / complete-trigger: zero final worst-trigger ASR, but final parameter L2 distance 0.09104722 to the same-roster clean model.

Because this comparison holds the omitted roster, initial checkpoint, honest
data and training rule fixed, the remaining difference isolates the declared
adversarial submissions within this deterministic protocol. It is not a claim
that the residual is harmful on untested inputs or a general certified-unlearning
measure. It does demonstrate why zero tested ASR cannot establish exact recovery.

## Why this differs from V2/V3 and late correction

V4 fits a pooled clean reference for log1p(relative norm) and validation impact,
with robust scales and fixed floors. A client's median ten-round maximum channel
increase is its persistent anomaly score. The individual threshold is the maximum
clean calibration campaign/client persistence. Two anomalous clients form a
candidate edge only when their threshold exceedances coincide in a fraction of
rounds strictly above the larger of .3 and all clean calibration pair fractions.
Maximal cliques yield investigative groups; no expected attacker count is forced.
Tensor direction/profile/correlation descriptors are retained as separate evidence.
Common benign causes can create concurrent anomalies. This is not proof of
intentional collusion and is not itself an admission policy.
coordination-evidence.csv exposes all105 pairs per history, including coactivity
and the three tensor/temporal descriptors. Scheduled adversary annotations there
are post-selection evaluation labels, never inputs to the selector.

An empty selected group can mean that every candidate is too large to omit while
retaining ten contributors. source-cases.csv distinguishes this from no candidate
evidence and retains candidate-pool membership errors. No oversized group is
silently truncated to the known attacker count. Benign clients flagged inside an
attacked history remain false members even when both clean control histories are
unflagged. A ten-round median can also miss an intermittent attacker; actual
alpha0 exports and per-round scores remain available for that diagnosis.

V2/V3 looked for increases over client-pair similarity references and missed the
earlier effective endpoint attacks while flagging both earlier clean histories.
The current method is explicitly developed after that finding. Its assessment
uses two new allocations and new adversarial rosters frozen before outcomes,
with actual membership uniqueness checked across all nine relevant allocations.
The five clean fitting/calibration roles are reused development resources, not
new independent clean validation. All allocations reuse the same 7096 training
rows, W0 and 3163 validation rows (1733 non-target ASR rows), so no independent
dataset or statistically guaranteed false-positive rate is established.

paired-method-comparison.json also applies the frozen predecessor rules to exactly
the same new pair observations as V4. It is a post-hoc common-input comparison,
not a separately preregistered experiment. The descriptor adapter reproduces all
six original V2/V3 selected groups before use; thresholds remain unchanged.
Comparing different allocations alone would not isolate the rule's effect.

| Method on identical new observations | Clean histories with selected group | Unrestricted memberships TP/FP/FN | Relative-radius memberships TP/FP/FN |
| --- | ---: | ---: | ---: |
| v2 | 1/2 | 0/4/12 | 0/4/12 |
| v3 | 2/2 | 0/6/12 | 0/12/12 |
| v4 | 0/2 | 5/0/7 | 2/2/10 |

Late R10 removal in the previous study retained R1-9 contamination. This study
instead rebuilds the entire affected history from W0. Those are different
interventions; origin recovery does not retroactively turn the earlier late
correction failure into a success.

## Attacker and remaining limits

Unrestricted Byzantine vectors interpolate/extrapolate a poisoned 10-epoch Adam
endpoint from an honest one-step coherent delta. Relative-radius vectors instead
limit the perturbation to alpha times the client's own clean delta norm, with
submitted norm at most five times that norm. Both use factors 0/.125/.5/1/2/4 and
a privileged reused-validation/same-roster-clean oracle. Defined candidates must
retain F1 within five points of that control; selection maximizes worst full or
three single-component ASR, then alpha. Attacks optimize the raw FedAvg model,
not an unrestricted evasion objective against the retrospective V4 selector.
No data-only honest-training, raw-traffic trigger realizability, cold-start or
long-horizon guarantee follows. Full-trigger composition necessity is not proven.

## Verification and storage

74 focused tests pass, including eight new persistence/coactivity, leakage and
whole-vector relative-radius tests. Full fresh replay checks 50 fit/calibration
rounds, 150 source rounds and 360 origin-recovery
rounds across 24 branches, including 1740
adaptive queries. Separate arithmetic checks reconstruct2555 metric
sets, sample-mass coefficients, poisoned-row budgets, utility-constrained query
selections and120 relative-radius bounds. Replay uses the same
numerical implementation; it is not independent classifier reimplementation.

Experimental manifests use software research authorities, not TPM/client keys.
All predecessor publication indexes and the 130-module measured core remain
unchanged. No test inference, operational default, thesis text, ToN-IoT acquisition
or independent witness deployment changes. Metadata and final source checkpoints
are retained without dataset copies, under the 64 MiB combined output ceiling and
8 GiB host free-space floor.
