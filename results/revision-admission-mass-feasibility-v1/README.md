# Why the proposed mass floor and group cap conflict

This is a conditional algebraic necessary-condition proof, with exact certificates on six pinned clean partitions. It is not an attack-success experiment or a new fitted threshold. The guard and all earlier evidence remain unchanged.

Let authenticated nominal counts be n_i>0, N=sum(n_i), effective masses satisfy 0<=m_i<=n_i, and M=sum(m_i). The policy requires M>=r*N. For any fixed subset S with at most k identities and nominal share c=sum_S(n_i)/N, the outside mass is at most (1-c)*N. Thus

    sum_S(m_i)/M >= max(0, 1-(1-c)*N/M) >= max(0, 1-(1-c)/r).

If every at-most-k subset must have coefficient mass at most gamma, a necessary condition is

    c <= 1-r*(1-gamma).

The condition applies to the subset with largest nominal counts even if it is no longer the largest subset after downweighting. If it fails, no admissible continuous choice of m_i can satisfy both constraints; the original discrete factors 0,1/2,1 cannot do so either. With r=4/5, gamma=1/3 and k=3, the threshold is 7/15. Equivalently any feasible retained mass fraction must be <=(1-c)/(1-gamma).

| Cohort | Seed | Top-three nominal share (%) | Unavoidable subset share at 80% retention (%) | Maximum retention with 1/3 cap (%) | Incompatible |
|---|---:|---:|---:|---:|---|
| iid | 2026110731 | 20.011 | 0.014 | 100.000 | False |
| iid | 2026110732 | 20.011 | 0.014 | 100.000 | False |
| iid | 2026110733 | 20.011 | 0.014 | 100.000 | False |
| non-iid | 2026110734 | 55.158 | 43.947 | 67.263 | True |
| non-iid | 2026110735 | 54.608 | 43.260 | 68.088 | True |
| non-iid | 2026110736 | 54.228 | 42.785 | 68.658 | True |

All three non-IID nominal top-three shares exceed 7/15, so under the current sample-weighted-mass contract the two policy requirements are incompatible. A different statistical alarm threshold cannot fix this incompatibility. The guard correctly defers instead of silently violating one of the requirements.
This does not disprove every influence cap. A separately declared final reweighting beta can redistribute coefficients while retaining original admission masses for accounting. It is then a different operator: final beta, transformation dependencies and verification must be explicit, as for the existing bounded/robust profiles. Alternatively the retention/influence goals, eligible support or data allocation must change. No such alternative is selected or validated here, and none of these mathematical bounds guarantees low ASR.
