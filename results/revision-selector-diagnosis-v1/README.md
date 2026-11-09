# Diagnosis of the frozen V4 selector

The principal observed failure is a semantic conflation: a contribution that
reduces global validation macro-F1 is treated as evidence about an abnormal
client and then combined with other anomaly channels into a group. The measured
macro-F1 drop is real. It does not establish that the submitting identity is an
attacker. V4 and all thresholds remain unchanged in this diagnostic study.

## Main findings

All 11 false-positive client-history entries have validation-channel
median above the frozen threshold and norm-channel median below it. All remain
flagged when all submitted vectors are honest gradients at the SAME original
parent, and none is flagged at the matched clean-history parent. This isolates
the inherited model state as sufficient for these false signals under the
declared simulator controls; current malicious peer vectors are not required.

| Case | Benign client | Combined median | Norm median | Validation median | All-honest same-parent median | Clean-parent median |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| case-06 | client02 | 6.199 | 1.107 | 6.199 | 6.199 | 3.451 |
| case-06 | client06 | 6.284 | 2.623 | 6.284 | 6.284 | 5.154 |
| case-06 | client08 | 5.875 | 0.962 | 5.875 | 5.875 | 3.459 |
| case-06 | client12 | 6.065 | 0.356 | 6.065 | 6.065 | 3.134 |
| case-06 | client13 | 5.477 | 0.049 | 5.477 | 5.477 | 2.601 |
| case-07 | client02 | 6.911 | 1.015 | 6.911 | 6.911 | 3.451 |
| case-07 | client06 | 6.996 | 2.500 | 6.996 | 6.996 | 5.154 |
| case-07 | client08 | 5.543 | 0.867 | 5.543 | 5.543 | 3.459 |
| case-07 | client12 | 6.288 | 0.264 | 6.288 | 6.288 | 3.134 |
| case-08 | client06 | 8.279 | 2.007 | 8.279 | 8.279 | 5.154 |
| case-09 | client06 | 8.044 | 2.008 | 8.044 | 8.044 | 5.154 |

The frozen standardized threshold is 5.222250143. A validation-channel exceedance
corresponds to a macro-F1 drop greater than
2.611125 points. Norm-channel exceedance
requires a submitted norm greater than 8.883628 times
the current peer median. These are decoded existing thresholds, not new cutoffs.

## Why a benign gradient can trigger the validation alarm

There are 89 flagged client-round observations among the 110
rounds inspected for the falsely flagged identities. All 89 are
validation-dominated, and all 89 reduce their own declared common
local training loss. The float64 common weighted validation loss decreases in
63/89 and increases in
26/89. Local descent does
not ensure global utility, and a continuous validation loss is not universally
safe either. The loss figures are diagnostic, not a replacement rule.

The exfiltration class has only 10 evaluation examples. Its F1
falls in 89/89 flagged observations and accounts
for 94.09% of the summed negative
per-class F1 changes in those observations. Its number of true positives stays
unchanged in 89/89; false-positive predictions
into that class increase in 89/89.
Classwise F1, confusion matrices, accuracy and both objective changes are retained.
These repeated observations are correlated and do not constitute independent
statistical samples. Rare-class utility must remain visible; calling its decline
a risk is appropriate, equating it with malicious identity is not justified.

## The intermittent attacker is suppressed by the median

In case-02, client15 actually exports modified vectors in rounds
[1, 2, 4, 7, 10]. Its threshold exceedances occur in exactly
[1, 2, 4, 7, 10]. The fifth and sixth ordered scores are
0.000000000 and 9.073961305; their average
is 4.536980653, below 5.222250143. The ten-round median therefore
discards a five-round attack. No hash, enrollment or reconstruction error is
needed to explain the miss. A new episode statistic would require clean-only
recalibration, including any multiple-window search; the current threshold cannot
simply be reused after changing the aggregation statistic.

## Large and mixed-channel groups

candidate-group-channel-evidence.csv exposes each group's member channels and
survivor count. In the heavily altered histories, norm-anomalous adversaries and
validation-risk benign clients can become one coactive clique. Too-large groups
are not feasible under the ten-contributor rule. The limit is not silently
lowered or the group arbitrarily cut to the known attacker count.
The relative-radius cases also produce mixed-channel pairs: a benign validation
risk and an adversarial magnitude anomaly can coincide in time without a common
anomaly mechanism. Temporal coincidence across unlike risk channels is not proof
of coordinated malicious submissions. Per-tensor similarities remain in the
sealed decisions for later investigation; no new tensor threshold was chosen.

## Controls, verification and limits

All ten source R1-10 prefixes were reconstructed: 100 selected round events,
all 1500 submitted-vector digests, checkpoint digests and complete V4 decisions
match the prior authenticated publication. Unselected adaptive queries and
R11-15 were already verified previously and were not rerun here. Alpha0 poisoned
endpoint fitting was skipped where it cannot affect the exported honest vector.
The two matched clean prefixes are shared controls, not ten independent clean
campaigns. Eight attacked cases provide 80 common-parent all-honest contexts.
Those shadow windows follow the original parent sequence and are NOT a newly
trained all-honest trajectory or a deployable server capability.

17 focused tests pass, including five new channel/median, interval and rare-class
accounting tests. Separate scalar and confusion-matrix accounting checks all
4500 channel rows across three profiles, client medians, paired class effects,
loss differences and invariant benign vectors/validation impacts. The simulator
uses original unpoisoned private client rows for the honest controls; real server
access to those rows is not assumed. Same implementation and reused Data24
validation apply. Original artifacts, measured core, V4 rule, thresholds,
operational defaults and thesis are unchanged. There is no new attack campaign,
independent dataset, test inference, TPM Quote or permanent exclusion.

See CORRECTION_SPECIFICATION.md for the evidence-based next implementation step.
