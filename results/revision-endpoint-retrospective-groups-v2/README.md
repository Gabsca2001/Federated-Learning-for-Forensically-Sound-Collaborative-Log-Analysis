# Retrospective groups on effective learned-endpoint DBA histories

Both selectors miss the attacker groups in all four attacked histories and select false groups in both clean histories. This is a failed transfer of the existing retrospective selection rules to these new endpoint histories; it does not validate automatic identification or exclusion.

This completed study applies the existing V2/V3 retrospective selectors to the
four effective raw FedAvg endpoint attacks, plus two source clean controls.
It is separate from automatic containment by FLTrust or norm-only normalization.
All selection and intervention outputs were freshly reconstructed and checked.

## Candidate membership

- v2: attacked histories TP=0, FP=0, FN=12; clean selected groups in 2/2 histories.
- v3: attacked histories TP=0, FP=0, FN=12; clean selected groups in 2/2 histories.

Counts are memberships across four histories, not independent client persons.
Both attack variants reuse each of two data assignments and attacker rosters.
False members and missed attackers remain explicit; an empty selection is not
replaced by the known attacker set. The separately labelled oracle diagnostic
cannot be presented as detector output or used to tune thresholds.

| Seed | Source | Method | Selected group | TP | FP | FN |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 6116104 | clean | v2 | client03, client04 | 0 | 2 | 0 |
| 6116104 | clean | v3 | client03, client04 | 0 | 2 | 0 |
| 6116104 | distributed | v2 | none | 0 | 0 | 3 |
| 6116104 | distributed | v3 | none | 0 | 0 | 3 |
| 6116104 | complete-trigger | v2 | none | 0 | 0 | 3 |
| 6116104 | complete-trigger | v3 | none | 0 | 0 | 3 |
| 6116105 | clean | v2 | client05, client12 | 0 | 2 | 0 |
| 6116105 | clean | v3 | client05, client12, client13 | 0 | 3 | 0 |
| 6116105 | distributed | v2 | none | 0 | 0 | 3 |
| 6116105 | distributed | v3 | none | 0 | 0 | 3 |
| 6116105 | complete-trigger | v2 | none | 0 | 0 | 3 |
| 6116105 | complete-trigger | v3 | none | 0 | 0 | 3 |

## Direct and future interventions

R10 holds the actual source parent and surviving exported vectors fixed.
R15 follows five genuinely recomputed coherent-gradient rounds at the corrected
parents, keeping the same removed identities omitted from aggregation. Active
poisoning already ends at R10 in the declared source protocol. Every no-removal
branch reproduces all five original continuation checkpoints exactly.

| Seed | Source | Group method | Stage | Original full ASR | Joint-removal full ASR | Joint minus best individual reduction (points) |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 6116104 | distributed | oracle-diagnostic | R10 | 17.48% | 17.37% | 0.06 |
| 6116104 | distributed | oracle-diagnostic | R15 | 17.48% | 17.43% | 0.06 |
| 6116104 | complete-trigger | oracle-diagnostic | R10 | 94.40% | 93.71% | 0.06 |
| 6116104 | complete-trigger | oracle-diagnostic | R15 | 94.35% | 93.77% | 0.23 |
| 6116105 | distributed | oracle-diagnostic | R10 | 100.00% | 100.00% | 0.00 |
| 6116105 | distributed | oracle-diagnostic | R15 | 100.00% | 100.00% | 0.00 |
| 6116105 | complete-trigger | oracle-diagnostic | R10 | 100.00% | 100.00% | 0.00 |
| 6116105 | complete-trigger | oracle-diagnostic | R15 | 100.00% | 100.00% | 0.00 |

The complete comparison includes all individual removals, full and three
individual triggers, clean F1, five hash-ranked equal-size benign controls and
one closest sample-mass control. Direct R10 benign-control distributions are
descriptive, not p-values. Only the closest-mass benign control receives future
training for each method; do not call that a distribution of R15 controls.
The full-versus-worst-trigger differences and sample-mass mismatch are retained
in comparisons.csv/summary.json. Cardinality matching does not ensure exact
sample-mass equality in non-IID data. Joint-versus-individual differences do not
alone establish a synergistic or intentional coordinated attack.

## Scope of the causal interpretation

R10 begins after nine potentially poisoned rounds. Removing an identified group
at R10 cannot retroactively clean that starting checkpoint. Residual ASR after
joint removal is a real limitation of late correction, not evidence that the
omitted current updates were reused. Conversely, zero ASR does not establish
exact parameter restoration. Parameter distance to the original full-roster clean
reference is descriptive: it also includes changed roster and lost benign data,
so it is not an isolated measure of residual poisoning.

The separate selection-diagnostics.json retains the actual frozen pair threshold,
largest observed pair score, labelled attacker-pair scores and R10 malicious
update norm ratios. The rule looks for increased pairwise similarity; it does
not directly threshold absolute update magnitude. Large updates therefore need
not produce a candidate group. Clean non-IID distribution changes can instead
exceed the pair reference. These observed score failures require a separately
designed validation protocol before changing the selector, not lowering the
threshold after consulting attacker identities.

The attacker's original R10 factor and other submissions remain fixed during
direct removal. This is a conditional intervention on retained evidence, not a
new attack that adapts to exclusion. R11-15 are the already-declared unmodified
continuation. No claim is made about removing a group from the first attack round
or replaying an adversary that continually adapts after discovery.

## Clean calibration and duplicate-allocation finding

Two fresh clean allocation histories fit the reference; three separate clean
allocations calibrate empirical maxima. All seven actual memberships (five
fit/calibration and two source evaluation assignments) were checked distinct
before training. They reuse the same7096 training occurrences, initial model
and3163 root-disjoint validation rows; they are not independent datasets or
population samples. Three calibration histories cannot establish a population
false-positive guarantee. The V2/V3 algorithms are unchanged; recalibration is
necessary because historical Adam endpoint references do not match the new
coherent-gradient honest protocol.

The initial v1 attempt stopped before selection/effects because adjacent nominal
seeds converged to duplicate allocations through the historical generator's
seed+attempt retry. It is preserved, not counted as a completed calibration.
The separate allocation audit also finds historical seeds6116105/6116106 have
identical memberships; their different attacker identities/training seeds do
not make them distinct data distributions. The two actual source assignments
6116104/6116105 used here are distinct. No historical evidence was rewritten.

## Verification and preservation

66 focused tests passed, including ten new control/allocation guard tests and
existing retrospective, counterfactual and actual-retraining checks.
Fresh replay covers50 fit/calibration rounds,90 selected source rounds,
69 direct outputs and170
corrected-parent continuation rounds in34
branches. Separate arithmetic accounting reconstructs239 metric sets.
It is same-implementation numerical replay, not independent classifier code.
The previously verified unselected adaptive source queries were not rerun here.
Source publication checksums, all original generation pins and the130-module
core digest remain unchanged. The new evidence uses software research authority
signatures, not client signatures or TPM evidence. No test inference, thesis
change, operational default change or independent-data claim is introduced.
