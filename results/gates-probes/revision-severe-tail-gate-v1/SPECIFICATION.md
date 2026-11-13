# Severe-tail statistical admission: research specification

This document describes the separate `noncompensatory-log-tail-gate-v1`
research profile. It does not replace the existing formal derivation model or
change a production admission default. The frozen numerical study is
`revision-severe-tail-gate-v1`; its result and rejection criteria are reported
separately. Statistical quarantine concerns an update in a particular round,
not a permanent finding about a client's identity.

## Evidence, trust and numerical influence

The update's recorded lineage, prerequisite trust result and actual numerical
coefficient remain separate objects. Let `G_i` be the existing mandatory trust
predicate, `n_i` the bound example count and `m_i` the admission mass factor.
The original hard veto is preserved: `G_i=0` implies `m_i=0`, independently of
the statistical score. A statistical score does not provide a new TPM Quote or
turn an untrusted update into an admissible one.

The study assumes trust passes and uses the existing full-model Flower FedAvg:

    a_i = n_i m_i / sum_k(n_k m_k),       W_next = sum_i a_i W_i.

At least ten contributing clients are required. If the denominator or quorum
is invalid, the round has no checkpoint. Such a failure is reported as an
availability failure; its missing ASR is undefined, not zero.

The five server-visible indicators are relative update norm, cosine similarity
to the coordinate median, coordinate-median distance, MAD score and validation
impact. Low cosine similarity is adverse; high values are adverse for the
other indicators. Their numerical definitions and the original training engine
are retained.

## Conditioned clean references

For component `j`, let `mu_j` and `MAD_j` be the clean reference median and
median absolute deviation selected by declared cohort, campaign phase and
relative example-count bucket. Phases are rounds 1–5, 6–10 and 11–15. Counts
below half the cohort median are small; counts above 1.5 times it are large;
the remaining counts are middle. Reference groups require 30 clean
observations, with the declared phase/cohort fallback retained. Unsupported
cohorts or rounds fail explicitly.

For observed component `x_ij`, define:

    s_j = max(1.4826 MAD_j, 10^-9 max(1, abs(mu_j)))
    d_ij = max(0, x_ij - mu_j)           for a high-adverse component,
    d_ij = max(0, mu_j - x_ij)           for a low-adverse component,
    l_ij = log(1 + d_ij / s_j).

The logarithm has no former robust-z cap. Its implementation uses a stable
logarithmic calculation for large finite deviations. Invalid numerical inputs
are rejected rather than silently accepted.

Let `L_j` be the maximum of 1, the empirical count-weighted 95th percentile and
the nominal-example-mass-weighted 95th percentile of `l_j` on the separate
clean calibration histories. Define:

    z_ij = l_ij / L_j,     M_i = max_j z_ij,     S_i = M_i / (1 + M_i).

`S_i` is a bounded monotone display score. It is not a probability of
maliciousness. Full per-component diagnostics are retained separately from
the original additive-component schema, which would misdescribe a maximum.

## Actions and the exact non-compensation claim

Let `q` and `d` be the selected cohort's empirical maximum-severity quarantine
and downweight cutoffs, with `d<=q`. In the no-warning, passed-trust setting of
this study, the unchanged decision API produces:

    m_i = 0       if M_i > q,
    m_i = 1/2     if d < M_i <= q,
    m_i = 1       if M_i <= d.

The API receives statistical threshold `q/(1+q)`, composite threshold
`q/(2(1+q))`, downweight threshold `d/(2(1+d))` and trust weight one half.
Equality at a threshold does not trigger the stricter action.

For any component `j`, `z_ij>q` implies `M_i>=z_ij>q`. Strict monotonicity of
`M/(1+M)` preserves this ordering. Therefore a component exceeding the
operational quarantine threshold forces quarantine regardless of the other
four components. This is the component non-compensation property. It is
distinct from, and compatible with, the mandatory trust-veto property.

This implication does not prove that every poisoned update exceeds `q`, that
every outlier is malicious, or that harmful combinations of individually
ordinary updates will be detected. Numerical execution, the clean-reference
assumption and the bound metadata remain material premises.

## Empirical calibration and retained mass

Each joint cutoff is the larger of count- and nominal-mass-weighted empirical
quantiles. The candidates are `Q=.975,D=.90` and `Q=.99,D=.95`. With strict
threshold crossing, their recorded calibration populations have count and mass
tail fractions bounded by `1-Q` and `1-D`, respectively.

If `r_Q` is the quarantined nominal mass fraction and `r_D` the total nominal
mass fraction above the downweight cutoff, retained nominal mass is:

    R = 1 - r_Q - (r_D - r_Q)/2.

Consequently the empirical calibration bound is:

    R >= 1 - [(1-Q) + (Q-D)/2].

This is an arithmetic statement about the recorded calibration population.
Clients and rounds are dependent; no exchangeability or future false-positive
guarantee is inferred. In particular, a pooled calibration bound does not
guarantee a later per-round minimum. That minimum is checked separately.

## What the experiment can establish

Clean fitting, calibration, clean selection and attack evaluation reserve
different seed/partition assignments on the same Data24 training examples and
fixed clean warm checkpoint. The historical test set has been inspected in
earlier research, so evaluation remains exploratory. There is no independent
dataset or initialization claim.

Selection uses clean indicators, clean mass budgets and fixed-endpoint clean
validation F1 only. The matched capped-average control is fitted on the same
fresh clean histories and cannot be selected as the proposed gate. The
comparison evaluates the combined saturation, normalization and maximum-fusion
revision; it does not isolate the causal contribution of every subcomponent.

Reserved branches train independently under TPM-only, original composite,
matched average control and severe-tail admission. Each has clean,
distributed-trigger, complete-trigger and six-query defender-adaptive
conditions. Clean continuation is included. Peak and final full/component ASR,
clean utility, actual manipulated-update interventions, unmodified-update
interventions, nominal mass, availability and cost are all reported.

The predeclared research criteria require complete proposed histories, every
reserved clean budget, no worse paired peak harm than the matched average and
strict benefits in at least two effective-control cases including non-IID.
Passing these criteria would support this bounded experiment. It would not
automatically enable the profile in the live pipeline, justify permanent
identity exclusion, or establish robustness to arbitrary adaptive attackers.
Fresh TPM/profile binding and a separately assessed deployment integration
remain distinct work.
