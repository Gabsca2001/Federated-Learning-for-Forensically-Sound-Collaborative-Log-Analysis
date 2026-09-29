# M6 active-policy paired pilot — 2026-09-25

Four separate 30-round trajectories completed and passed the M5 campaign verifier:
seed 341593, CPU, same IID partition, fixed clean calibration, four workers and
attestation refresh interval three. Each campaign contains 450 contribution decisions.
The deployed policy is bound in the signed contract and checkpoint; sequential is
an actual aggregation policy here, not merely a shadow decision on gated updates.

| Condition | Policy | Selected round | Test macro-F1 | Safe quarantines | Safe downweights |
|---|---|---:|---:|---:|---:|
| Clean | gated_composite | 25 | 0.9354670337 | 6 | 75 |
| Clean | sequential | 11 | 0.9225672285 | 4 | 0 |
| Disagreement | gated_composite | 11 | 0.9245538256 | 2 | 24 |
| Disagreement | sequential | 11 | 0.9224306785 | 2 | 0 |

Both attacked trajectories quarantined all 90 declared-unsafe contributions: 30
statistical and 60 controlled trust failures. The trust failures are counterfactual
policy inputs; these are not 60 genuinely failed TPM Quotes. Safe denominators are
450 in clean and 360 in disagreement. Checkpoints were selected on validation.

Gated-minus-sequential test macro-F1 is +0.0128998051 clean and +0.0021231471
under disagreement. This single-seed result does not establish general superiority
or statistical significance. Gated intervenes more often on clean contributions.
The one-round smoke also showed tiny numerical differences between otherwise
matching clean runs (maximum parameter difference 7.45e-9); bitwise cross-run
identity is not claimed.

[summary.json](summary.json) contains exact metrics, admission counts, relative source
paths and source digests. It is a sanitized derived snapshot, not a substitute for
the signed workspaces or full independent campaign verifier. Raw logs, datasets,
private TPM material and full artifacts remain local and are excluded from Git.

The remaining four paired seeds are in progress; no five-seed estimate is published
here. See [protocol and recovery](../../docs/M6_POLICY_PILOT.md).

## Follow-up completed

The [five-seed comparison](../m6-active-policy-multiseed-v1/README.md) is now complete.
This page retains the historical one-seed pilot; use the full comparison for conclusions.
