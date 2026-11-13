# Explicit final coefficients: model and conditional guarantees

The profile `capped-final-bounded-aggregation-v1` solves the identified
coefficient/mass conflict by introducing a separately recorded final numerical
operator. It does not claim that the incompatible original FedAvg requirements
have become compatible. Original admission decisions, signed inputs, formulas
and historical profiles remain unchanged.

## Admission and actual numerical coefficients

For an authenticated complete eligible roster, let n_i>0 be bound example counts
and m_i be the original effective admission masses after mandatory gates and
any declared hard statistical quarantine. A zero gate or zero admitted mass
remains zero. Define:

    N = sum_i n_i,    M = sum_i m_i,
    R_admit = M/N,    alpha_i = m_i/M.

Admission requires at least ten positive masses and R_admit>=4/5. This preserves
the existing lower mass condition; projection does not repair an upstream
mass deficit. In particular, applying it after an existing hard gate that
excludes a large benign client can still defer the round.

The new numerical study uses the same mandatory-trust-only admission for all
four arms from the start. The hard statistical profiles remain separate.
They are not overridden after a quarantine. This is aggregation containment,
not a newly validated malicious-client classifier or a new TPM appraisal.

## Bounded transformations and coefficient proposals

At fixed parent W, for tensor l and local model U_i define:

    d_i,l = U_i,l - W_l,
    lambda_i,l = min(1, C_l / ||d_i,l||), with lambda=1 for zero norm,
    v_i,l = lambda_i,l * d_i,l.

The per-tensor positive C_l values are the fixed historical clean-reference
99th percentiles, with the original source commitments retained. No attack
outcome is used for a new cap fit.

The sample proposal is p_i=alpha_i. The robust proposal is the existing finite
smoothed geometric-median procedure's final normalized coefficient vector,
calculated from these bounded deltas and original masses. Finite iteration and
convergence metadata are retained. Its output is a proposal, not a claim of
an exact global optimum or guaranteed identification of poisoned updates.

## Exact final projection

For group budget gamma=1/3 and group size k=3, choose c=gamma/k=1/9. Construct

    beta_i = min(c, z*p_i),    sum_i beta_i=1,

with beta_i=0 whenever p_i=0. A rational water-filling algorithm fixes saturated
coordinates at c and rescales the remaining coordinates. All weights and cap
certificates are exact fractions. The projection preserves relative proportions
among coordinates that remain unsaturated. It is also the unique minimizer of
KL(beta||p) on the capped simplex restricted to positive proposal support; no
claim about the predictive training objective follows from that fact.

The final operator, before checkpoint-dtype export, is:

    W_next,l = W_l + sum_i beta_i*v_i,l.

The record includes original masses/alpha, proposal, projection, beta,
alpha-to-beta total variation, clipping derivation, pre-export commitment,
exported checkpoint commitment and measured export-rounding errors. Actual
checkpoint reconstruction uses beta. It must never silently substitute alpha
or claim the original untransformed FedAvg identity for this operator.

## Feasibility and quarantine preservation

For q positive proposal entries, a capped simplex exists iff q*c>=1. With
q>=10 and c=1/9, the feasible set is nonempty. The sample proposal is positive
exactly on admitted support; the supported finite robust execution must retain
sufficient positive support. Infeasible or invalid numerical support fails
explicitly rather than inventing contributions.

Any subset S of at most three clients satisfies:

    sum_(i in S) beta_i <= |S|/9 <= 1/3.

This stronger per-coordinate cap is sufficient for the group requirement; it
is not the least restrictive possible top-three constraint. Zero proposal mass
stays zero, so a quarantined contribution cannot be resurrected to fill the
simplex. A hard upstream mass/quorum failure still produces no checkpoint.

The previous incompatibility assumed final coefficients alpha_i=m_i/M and
0<=m_i<=n_i. Here the admission mass remains constrained, but final beta is an
explicit transformed operator. Consequently R_admit=1 and a three-client cap
can coexist without discarding local training examples. This does NOT preserve
their previous sample-proportional numerical importance. Alpha/beta total
variation and paired clean macro-F1 must disclose that objective change.

## Conditional norm interpretation

Nonnegative normalized beta and ||v_i,l||<=C_l imply
||sum_i beta_i*v_i,l||<=C_l in real arithmetic. A group of at most three has
direct coefficient mass at most gamma. The familiar fixed-coefficient removal
vector bound is 2*A*C_l with removed mass A<=gamma, provided its stated frozen
base, clipping and survivor-coefficient premises hold. It is an analytical
comparison, not a newly authorized checkpoint: survivor quorum/caps may fail.
Reprojecting, recomputing robust weights or retraining changes those premises.
Actual exported checkpoint comparisons additionally require rounding allowances.

Neither coefficient nor norm caps prove low ASR, benign intent, perfect
collusion detection, clean-state recovery or physical-TPM protection. Existing
authenticated context/receipt/root assumptions remain necessary for live use.

## Validation contract

Three known problematic non-IID partitions run all four clean arms for all
15 rounds, as explicit mechanism replications. Six new IID/non-IID
seed/partition/attacker assignments run clean, distributed-trigger,
complete-trigger and defender-adaptive branches for all four arms. This gives
108 planned histories: 12 known and 96 reserved. Attacks run rounds 1–10,
followed by five unmodified continuations. The same ten-epoch local Adam,
feature triggers and six-query adaptive budget are retained.

The methods are raw mandatory-trust FedAvg, uncapped robust bounded aggregation,
capped sample proposal and capped robust proposal. The primary numerical
comparison isolates projection by comparing capped robust with uncapped robust.
Sample proposal is a separately declared ablation. No winner or new threshold
is selected from attack/test outcomes. Test inference starts only after every
training case is terminal. Numerical replay disables generation caching.

Continuity/cap validity, clean utility and attack efficacy are separate results.
The historical Data24 test was previously observed; these are exploratory new
assignments, not an independent dataset or new initialization. The thesis is
frozen and live production defaults are unchanged.


## Completed validation

The campaign of 108 histories and the numerical/publication checks are complete.
Structural continuity and the coefficient ceiling hold; both capped methods pass
the clean-utility checks. Capped robust nevertheless has greater paired attack
harm in 6 of 18 reserved comparisons and reaches 99.94% peak and 97.80% final
full-trigger test ASR in the worst case. It does not qualify as a defense against
poisoning to use by default. See [measured results and limits](CAPPED_FINAL_RESULTS.md).
The equations above are unchanged; a coefficient/norm constraint does not imply low ASR.
