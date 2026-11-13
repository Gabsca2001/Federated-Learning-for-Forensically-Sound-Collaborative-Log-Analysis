# Admission gates: mechanisms, supported claims and discriminating validation

Review date: 2026-11-05. This is a manual mathematical analysis with finite
program checks and a replay of retained decision signals. It changes neither the
deployed policies nor the thesis. Original experiments remain preserved.

## 1. What is being compared

The original policies share one statistical signal. Sequential does not mean the
new temporal/sequential detector in `sequential_decision.py`; here it means the
original trust-then-statistics admission rule in `composite_admission.py`.

Keep four different operations separate:

1. Protocol validation: identity, signatures, context, bindings, structure and
   required trust checks are validated by the live M5 wrapper.
2. Admission: a policy chooses accept, downweight or quarantine.
3. Numerical aggregation: original weighted FedAvg, bounded aggregation and
   robust bounded aggregation are different numerical profiles.
4. Semantic investigation: a retained or rejected contribution is not thereby
   proved benign or malicious; retrospective group analysis remains separate.

The `statistics_only` primitive is an isolated diagnostic ablation. It is not an
available live primary policy bypassing M5 validation. Its trust-failure
counterexamples must not be described as a bypass of the deployed M5 wrapper.

Let H be the common mandatory protocol prerequisite, G the effective trust gate,
s in [0,1] the statistical risk and r in [0,1] the trust risk. For a scored input,
let lambda be the trust weight, d the downweight threshold, q the quarantine
threshold, tau the sequential statistical threshold, and 0 < rho < 1 the nominal
downweight factor. The primitive policies use:

    TPM-only factor:    G
    Sequential factor:  G * 1[s <= tau]
    Composite risk:     R = lambda*r + (1-lambda)*s
    Composite factor:   0,      if G = 0 or R > q
                        rho,    if G = 1 and d < R <= q
                        1,      if G = 1 and R <= d.

H must already pass. An unscored input receives zero mass in the live wrapper.
Effective mass is m_i = n_i*f_i. A normalized transition exists only if the
minimum positive-contributor count is met and M = sum_i m_i > 0; then
alpha_i = m_i/M. An unavailable transition is undefined, not an all-zero model.

## 2. Conditional mechanism results

### Hard trust non-compensation

For the integrated policies G = 0 implies f = 0 and therefore m = 0, regardless
of s. On a successful aggregate alpha = 0 as well. This follows directly from
the first branch of the policy and the mass definition. Statistical normality
cannot compensate for a mandatory trust failure. The claim says nothing about
whether an authenticated client's numerical objective is benign.

### Equivalent contributor sets under the deployed no-warning configuration

For lambda < 1 and fixed r, the composite retains a contribution exactly when

    G = 1 and s <= (q - lambda*r)/(1-lambda).

For r = 0 and q = (1-lambda)*tau, its contributor set equals Sequential's. The
proof is division of the risk inequality by the positive number 1-lambda.
It does not assert equal assigned masses or equal trained models.

The retained configurations have:

    lambda = 0.5
    tau = 0.8183094063145846
    q = 0.4091547031572923 = tau/2
    d = 0.2748970485340289
    rho = 0.5.

Consequently, when trust passes without warning, both policies quarantine above
statistical risk 0.8183094063145846. The composite additionally downweights above
statistical risk 0.5497940970680578. It is not an additional independent detector
on that slice of the state space. Different live quarantine counts can arise
because earlier weight differences change subsequent models, updates and scores.

This is an ideal-arithmetic argument. For this actual binary-exact halving,
finite checks also cover the deployed threshold and its adjacent floating values.
Arbitrary floating-point parameterizations must be checked at their own bounds.

### Warnings are a distinct, currently unobserved comparison axis

For admissible r = 0.25 with the same parameters, the effective statistical
quarantine threshold becomes 0.5683094063145846; full-weight acceptance ends at
0.2997940970680578. Sequential ignores this graded r once G passes. The policies
can therefore differ on the same warned input. No such admissible warning was
observed among the 12,600 decisions in this audit. Synthetic warning cases
check branches, not real-world prevalence or predictive value of warnings.

When lambda = 1, statistics disappear from R; the division above is invalid.
Changing lambda while proportionally rescaling thresholds, with r = 0, does not
introduce a new information source. A claimed benefit from changing lambda alone
must distinguish threshold movement from genuinely additional trust evidence.

### Compensation inside the statistical average

The statistical score is s = sum_j w_j*c_j, where the five component risks are
bounded in [0,1] and their normalized weights are all 0.2. If any c_j = 0, then
s <= 0.8 < tau. Thus no-warning Sequential and Composite cannot statistically
quarantine that input, even if the other four components saturate at 1. The
composite can still downweight it. Positive values of every component are
necessary, but not sufficient, for quarantine under these particular settings.

This is a property of the averaging rule and threshold. It does not violate
hard trust non-compensation: G = 0 still causes zero mass. A zero
`validation_impact` component means no adverse deviation from the clean
reference for that indicator; it does not prove unchanged accuracy or benignity.
The replay does not establish that making a component zero causes attack
success. It identifies a detection limitation and concrete retained examples.

### Downweighting is not a universal normalized-influence guarantee

Compare policies on the same surviving set with fixed example counts. Let p be
the original attacker mass share and let f_M and f_B denote the example-weighted
average factors among attackers and benign contributors. After reweighting:

    p' = p*f_M / (p*f_M + (1-p)*f_B).

For 0 < p < 1 and positive average factors, p' < p exactly when f_M < f_B.
Equal reductions leave the share unchanged; stronger benign reductions increase
it. This follows by cross-multiplication of positive denominators. Zero-group
or zero-mass cases need their explicit boundary treatment.

Even halving only one of 15 equal masses changes its coefficient from 1/15 to
1/29, a ratio of 15/29, not 1/2. A normalized coefficient is participation, not
semantic trust or demonstrated predictive damage. No ASR guarantee or useful
tensor-norm-independent model-displacement bound follows from rho alone.
Numerical clipping/robust aggregation has separate assumptions and validation.

## 3. What the retained evidence now supports

The source-bound [audit report](../../results/gates-probes/revision-gate-mechanism-audit-v1/README.md)
rechecks 12,600 decisions from 28 campaigns and 840 rounds, including coordinator
signatures, contract/checkpoint/decision hash bindings, normalization of stored
indicator values, four-policy vectors and deployed effective masses. It does not
re-appraise Quotes or extract indicators again from model tensors.

The replay finds no contributor-set difference between Sequential and Composite
on any of those same-signal inputs. On four retained adaptive gated trajectories,
Composite quarantines 11/240 active attacker submissions, downweights 124 and
fully accepts 105. Of the 240, 135 have a zero component and are all retained.

In the 80 attack-active rounds, the composite's normalized attacker share is
lower than hypothetical Sequential in 61 rounds, higher in 17 and equal in two.
These are local fixed-signal comparisons on already trained gated histories.
They do not describe a separately trained Sequential defender or an attack
optimized against Sequential, and they do not measure ASR changes.

The earlier five-seed live comparison still has uncertain predictive differences.
Its higher benign quarantine count for Composite cannot be explained as a
different same-input quarantine threshold under the observed no-warning state.
The later live downweight-threshold sensitivity also reduced benign intervention
without demonstrating improved predictive performance. Neither result should be
discarded or used to tune the already inspected test set again.

## 4. A discriminating next experiment

The useful question is whether graded admission improves the utility/containment
tradeoff enough to justify its additional benign interventions. Calling the
composite universally best is not the study objective.

Use the following predeclared, staged protocol. It is a protocol proposal, not a
record of a newly executed training campaign or an external validation result.

1. **Same-input mechanism stage.** Preserve a common base, all local update bytes,
   shared prerequisite results and calibration. Compare original Sequential and
   Composite, including the latter with d = q (no downweight band, leaving the
   live factor schema valid). Under r = 0 and matched thresholds, the no-band
   variant is a negative control and must match Sequential. Measure contributor
   sets, per-client factors, exact normalized attacker share, availability and
   direct checkpoint effects. Recomputing scores after removing clients is a
   different intervention and must be reported separately.
2. **Independent live trajectories.** Run TPM-only, Sequential and original
   Composite from common initial models with paired clean/attacked branches.
   Each policy must drive its own subsequent local training. Hold the numerical
   aggregation backend fixed to FedAvg; add bounded/robust aggregation only in
   a separately labelled factorial experiment. Otherwise its benefit cannot be
   attributed to the gate.
3. **Attack validity and fairness.** Include a fixed-signature-valid attack and
   the established distributed/full-trigger DBA cases under IID and non-IID
   assignments. For adaptive attacks, optimize against each evaluated defender
   with the same declared information and query/poisoning budgets. Preserve
   ineffective attacks and training failures. An ineffective attacked control
   supports integration, not mitigation efficacy.
4. **Outcomes before execution.** Report final ASR, peak ASR, mean ASR over the
   fixed attack window, component/full triggers, clean macro-F1/accuracy,
   benign quarantine/downweight rates, active-attacker retained mass and round
   failures. Fix a post-attack endpoint; validation-selected checkpoints are
   secondary, so a pre-attack selected model cannot be mistaken for recovery.
5. **Computational cost.** Measure trust checking, indicator extraction,
   validation inference, admission and aggregation separately. The in-round
   wrapper currently computes statistical state even for its TPM-only option;
   a different legacy TPM-only path cannot be compared as if all overhead were
   identical. The small decision-function runtime is not total policy cost.
6. **Calibration and claims.** Freeze parameters using clean development data,
   define an acceptable benign intervention/utility budget before inspecting new
   outcomes, and retain all planned seeds. Treat the seed as the repetition
   unit, not the number of client/round decisions. New seeds on the already
   inspected Data24 test set remain exploratory within one dataset. ToN-IoT is
   deferred as requested. Lack of superiority is not statistical equivalence;
   an equivalence claim would require a justified margin and adequate precision.

Admissible warnings and genuine mandatory trust failures need their own tests.
Controlled synthetic failures must remain labelled as such; a genuine failed
measurement tests enforcement but does not validate the predictive usefulness of
the statistical score. Current warning risk 0.25 is configured, not an estimated
probability of malicious behavior.

If stronger detection is desired, evaluate an explicitly new candidate (for
example, independently calibrated severe-indicator vetoes or a temporal rule).
Do not silently lower thresholds, use attacker identities in calibration, or
present a candidate tuned on these results as independent confirmation. A
permanent automatic exclusion rule requires additional evidence beyond this
round-local gate study.
