# Exploratory check of the group-coefficient constraint

The completed capped campaign is unchanged. This separate post-hoc calculation
uses its 270 recorded robust proposals, not new local training or prediction
evaluation. It changes no operational default, admission gate or published result.

The implemented individual ceiling of 1/9 is sufficient to bound every group
of three by 1/3, but it is stricter than the group condition itself. For example,
a normalized proposal with one coefficient 0.7 and fourteen equal others admits
a group-constrained solution with dominant coefficient 2/9 and fourteen others
1/18. An individual ceiling of 1/9 unnecessarily changes that distribution more.
This algebraic observation says nothing about which identity is malicious.

The exploratory solver minimizes KL divergence from the normalized robust
proposal subject to every three-coordinate sum being at most 1/3. It receives
no attacker identities or outcome metrics. Original zero support is preserved.
Conversion to exact fractions and, when necessary, mixing with the uniform
distribution on the original positive support ensures exact feasibility. The
repair is not a certificate of exact optimality. Analytic checks cover the
dominant example, an unchanged feasible proposal, the unique nine-client
uniform solution and an infeasible eight-client support.

All 270 exported candidates are exactly feasible, but only 212 passed the
numerical convergence, tangent linear-program gap and no-worse-objective checks.
The remaining 58 must not be presented as qualified projection optima. Of the
180 active attack-window rows, 139 passed these checks. Within those 139 rows:

| Change relative to the implemented individual-ceiling projection | Rows |
| --- | ---: |
| Lower coefficient share for the declared attacker identities | 25 |
| Higher coefficient share for those identities | 24 |
| Unchanged share within 1e-9 | 90 |

Both projections increased the declared attacker identities' share relative to
the robust proposal in 49 of these 139 qualified active rows. Attacker labels
are used only to describe the result after projection. Counts over all 270
candidates in summary.json include unqualified numerical solutions; use
qualified-active-summary.json for this restricted comparison. The two subsets
are not separate attack campaigns and must not be pooled as independent trials.

The weaker mathematical restriction reduces unnecessary distortion in some
cases, but this check provides no consistent directional improvement in attacker
coefficient share. That share also omits update direction, clipping, trigger
behavior and later training. No ASR, clean-utility or causal defense improvement
has been established. A coefficient budget alone cannot establish that a
backdoor is absent. Promoting this candidate, or launching another large campaign
on the strength of a feasible budget alone, is not justified by these results.

The next security experiment should first isolate the mechanism on a small
paired trajectory, retain the uncapped robust control, and require both clean
utility and trigger/partial-trigger resistance. Any choice made using the
completed campaign is exploratory; confirmation needs a newly fixed protocol
and separate evaluation. The current campaign remains negative evidence about
the security of the individual-ceiling operator.

Input hashes, exact candidate coefficients, numerical qualification and all
failures are retained alongside this note. No source-generation locks changed.
