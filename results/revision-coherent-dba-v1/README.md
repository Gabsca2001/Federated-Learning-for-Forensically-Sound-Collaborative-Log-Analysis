# One-step coherent DBA: negative controls and availability failures

The frozen16-history study and its full replay contain198 committed rounds,
three pauses and240 adaptive queries (20 blocked). Four clean histories
reproduce known checkpoints. All six raw attacked controls have zero ASR and
fail the declared effectiveness criterion. Three defended attacked histories
pause, and three complete; no backdoor-resistance conclusion is supported by
these ineffective controls. Availability failures are genuine observed results.

Pure distributed/full branches train the same one-step gradient on poisoned
data. The adaptive distributed branch additionally interpolates/extrapolates
clean/poisoned gradient deltas at factors0/1/4/16/64/256. Such scaling is an
explicit Byzantine model-update extension, not data-only attested training.

| Seed | Attack | Raw effective | Raw observed peak worst ASR | Defended rounds | Defended observed peak worst ASR | Defended R15 worst ASR | Interpretation |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 6116104 | distributed | no | 0.00% | 15/15 | 0.00% | 0.00% | ineffective_control_inconclusive |
| 6116104 | complete-trigger | no | 0.00% | 0/15 | undefined | undefined | availability_failure |
| 6116104 | adaptive-distributed | no | 0.00% | 15/15 | 0.00% | 0.00% | ineffective_control_inconclusive |
| 6116105 | distributed | no | 0.00% | 0/15 | undefined | undefined | availability_failure |
| 6116105 | complete-trigger | no | 0.00% | 3/15 | 0.00% | undefined | availability_failure |
| 6116105 | adaptive-distributed | no | 0.00% | 15/15 | 0.00% | 0.00% | ineffective_control_inconclusive |

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

Evidence is preserved separately from the later endpoint attack development.
No failure was removed or relabelled after observing stronger attacks. Query
and full-trajectory replay uses the same numerical implementation; arithmetic
counts are checked separately. Per-case prefixes/held-parent ASR are in CSVs,
not substituted for missing R15 endpoints.
