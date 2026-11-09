# Learned Byzantine endpoint DBA: completed quantitative comparison

All12 histories complete15 rounds: four clean mechanism replications and eight
attacked histories. Full replay reconstructs180 rounds and480 adaptive queries;
no candidate or selected trajectory pauses. All four raw attacked histories
meet the fixed selective-attack effectiveness criterion. All four defended
attacked histories have ZERO observed full/component ASR at every committed
round, including unmodified continuation. This is a positive containment result
for the stated family and horizon, not a universal security guarantee.

## Explicitly stronger adversary

Honest clients retain one coherent gradient step. Malicious clients instead
train a poisoned endpoint with10 Adam epochs,batch128,lr.001 at each current
parent. They submit clean_delta+alpha*(endpoint_minus_parent-clean_delta),
querying0/.125/.5/1/2/4 against each actual defender. Every attacked mode is
defender-adaptive. These are forged Byzantine vectors constructed from DBA/full
poisoned datasets, NOT honest SGD gradients or pure data-only attested training.
The extra attacker training and different factor grid define a NEW protocol;
this is not an isolated causal ablation of epochs alone.

The separate four-context warm-parent feasibility probe preceded this protocol.
It found full-trigger controls effective; initial distributed controls were not.
Both modes and both assignments were retained. All24 probe query models/metrics
are reproduced by the raw first rounds here and the full fresh replay. This is
attack development on reused validation, not an independent confirmation set.

## Full trajectories

| Seed | Attack | Raw effective | Raw observed peak worst ASR | Defended rounds | Defended observed peak worst ASR | Defended R15 worst ASR | Interpretation |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 6116104 | distributed | yes | 35.43% | 15/15 | 0.00% | 0.00% | effective_control_comparison |
| 6116104 | complete-trigger | yes | 94.40% | 15/15 | 0.00% | 0.00% | effective_control_comparison |
| 6116105 | distributed | yes | 100.00% | 15/15 | 0.00% | 0.00% | effective_control_comparison |
| 6116105 | complete-trigger | yes | 100.00% | 15/15 | 0.00% | 0.00% | effective_control_comparison |

The largest observed attacked-versus-own-clean defended F1 loss is
0.0000 points. All four defended final parameter vectors differ
from their own clean controls (4/4 nonidentical); zero
ASR therefore does not establish exact restoration or certified unlearning.
See submission-observations.json for actual manipulated exports and distances.
No malicious identity classification or permanent exclusion is inferred.

## Trigger composition required by the correspondence

Raw R15 results distinguish full trigger from the strongest individual component:

| Seed | Poisoned training variant | Full trigger ASR R15 | Strongest single ASR R15 |
| --- | --- | ---: | ---: |
| 6116104 | distributed | 17.48% | 33.47% |
| 6116104 | complete-trigger | 94.35% | 18.87% |
| 6116105 | distributed | 100.00% | 100.00% |
| 6116105 | complete-trigger | 100.00% | 91.58% |

Construction uses disjoint assigned components for the distributed variant.
The complete trigger need not outperform each component in every assignment.
These measurements test compositional behavior; they do not prove collusion
or replace retrospective individual/joint group removal. Full per-component
values at rounds10/15 are in trigger-composition.json.


ASR is calculated on the1733 non-target validation rows. Worst-trigger ASR is
the maximum over the full trigger and the three individual components, not
every possible subset. Fixed-endpoint F1 uses the3163 root-disjoint validation
rows. Data and historical validation have been observed before; this is an
exploratory two-assignment study, not independent-data confirmation.

The complete trusted60-row root is active from round1, representing the ready
post-expansion profile. No further reserved root exists. Failed quorum pauses
without a new checkpoint or retry; a held parent is not an R15 endpoint. All15
mandatory trust facts are software assumptions. No fresh TPM quote, client
signature, production M5 gradient adapter or attested execution of the attack
optimizer is claimed. These studies do not change the measured core/defaults.

All committed rounds retrain on their actual current parent. Three attackers,
50% hash-ranked poisoned rows each, rounds1-10 and unmodified continuation11-15
are fixed. Distributed clients learn one assigned component; full-trigger
clients learn all three. Row selections match but feature-edit budgets differ.
Features13/17/24 are set to12 in standardized space and selected labels become
benign. Realizability in raw network logs is not demonstrated.

The attacker has a privileged reused-validation and matched-clean oracle. Only
defined candidates within five F1 points of own clean control are ranked, by
worst ASR and then largest alpha. Alpha0 is explicitly unmodified. A candidate
that pauses has no new-checkpoint ASR and is not ranked as zero. This optimizes
a restricted targeted backdoor family, not every Byzantine or DoS strategy.

The raw effectiveness criterion requires at least20 points of paired worst-ASR
increase and at most5 points of own-clean F1 loss at the SAME committed round.
All ineffective controls and pauses remain included. Zero ASR without an
effective control does not establish defense success.


## Limits and verification

The rule combines a clean reference, magnitude normalization and cosine weights.
This two-arm comparison does not isolate which component caused mitigation.
Norm-only ablations and broader adaptive attacks would require a new protocol.
No1/3 three-client influence ceiling or80% sample-mass retention guarantee is
inherited from earlier capped experiments. Scores are convex weights on
normalized deltas, not sample masses or necessarily convex coefficients on
original raw deltas. Cold-start convergence and longer horizons are untested.

Thirty focused tests pass (three endpoint-selection tests, five original-query
and poison-budget tests,14 coherent-context tests and eight FLTrust numerical
tests). Full training/query replay uses the same implementation; separate
accounting recomputes F1/ASR from counts and verifies row-budget matching and
adaptive selections. The classifier is not independently reimplemented.
Experimental manifests have software research authority keys, not TPM identity.

The inherited timing field client_clean_and_poison_gradients_seconds includes
malicious Adam endpoint training in THIS study. Context wall times are measured
on the shared machine and are not isolated operator/TPM latency benchmarks.

The original one-step campaign remains negative/inconclusive for security and
retains its three availability failures. Those failures and the new positive
restricted-family result must be reported together. Code/data paths remain
required for reconstruction; model/client tensor histories were not copied.
