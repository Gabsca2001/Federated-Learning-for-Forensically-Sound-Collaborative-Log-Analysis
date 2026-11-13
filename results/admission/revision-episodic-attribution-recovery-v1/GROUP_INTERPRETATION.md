# What the individual/joint controls support

These are derived comparisons of the completed V5 assessment, not additional
training runs or a policy change. All six effective raw cases remain included.

In 4/6 selected-group comparisons, full-origin joint removal reaches
zero final worst-trigger ASR and is strictly better than every single-member
removal. Closest-mass benign group removal leaves a nonzero ASR in all six.
Surviving attackers retrain and readapt at corrected parents in every branch.

| Case | Best individual-removal ASR | Worst individual-removal ASR | Joint-removal ASR | Closest-mass benign-removal ASR |
| --- | ---: | ---: | ---: | ---: |
| case-02 | 0.00% | 100.00% | 0.00% | 91.40% |
| case-06 | 0.00% | 99.94% | 0.00% | 90.94% |
| case-08 | 16.91% | 100.00% | 0.00% | 27.52% |
| case-09 | 92.90% | 99.94% | 0.00% | 98.90% |
| case-12 | 16.04% | 78.02% | 0.00% | 22.39% |
| case-13 | 91.92% | 99.88% | 0.00% | 98.73% |

This supports a group-level counterfactual effect under the declared attack and
training protocol. It does not establish statistical significance, superadditive
synergy, necessity of distributed trigger composition or intentional collusion.
In the other 2 cases, a single removal also reaches zero: the full group
is not necessary for that final ASR criterion. The original source graph and
the numerical counterfactual remain different kinds of evidence.

## Zero ASR and model restoration remain distinct

All selected joint removals match every same-excluded-roster clean checkpoint.
For the single removals that reach zero ASR, the parameter comparison is:

| Case | Removed client | Final L2 to same-roster clean | Every checkpoint equals same-roster clean |
| --- | --- | ---: | --- |
| case-02 | client09 | 0.0596475583 | no |
| case-06 | client09 | 0.0596475583 | no |

The comparison does not restore the original full-roster model or selectively
erase only poisoned rows. The main report retains full-roster utility loss and
per-class outcomes, including rare-class support, for that reason.

## Meaning for the professor's agreed retrospective analysis

The experiment now includes groups selected without attacker labels, individual
and joint omissions, two benign group controls, and full retraining of subsequent
rounds. Oracle-known groups are explicitly diagnostic and share a numerical
branch when they equal the selected group. These results support the qualified
description "groups compatible with coordinated behavior" in these cases.
They do not authorize general automatic exclusion: V5 still misses scheduled
roles, and ineffective norm-limited attacks do not test successful evasion.
