# Protocol: confirmation of the two-view Data24 system on UNSW-NB15 session S0 (v1)

Written 2026-11-10 before any prediction of view B, the MAX rule or temporal persistence on
UNSW-NB15 session S0. SHA-256 in `protocol.sha256`; the script refuses to run otherwise.

## System (frozen from exploratory runs on Data22, ToN-IoT and UNSW-NB15 session S1)

Two FedAvg binary classifiers trained **only on Data24** (train+validation, 30 rounds, 2
local epochs, Adam 1e-3, batch 128, class-balanced loss, final round):
- view A: `[clip(z, ±20), log1p|z|]`; view B: `log1p|z|` sorted in descending order;
  z = standardization by the network's own benign baseline after log1p on the ten
  count/volume/duration features.
- Each logit margin is converted to its rank against the target baseline; fused score =
  max of the two ranks (ties broken by 1e-6 × max of baseline-standardized margins).
- Temporal persistence: trailing median over the last 5 units of the same source host,
  restarting after a gap > 10 minutes.
- Label-free decision: alert above the 99th percentile of the smoothed fused score on the
  baseline. Seeds 0–4, evaluated per seed (no seed averaging).

Reference: NOV = Mahalanobis to the baseline (cov + 1e-6·I) with the same persistence and
threshold rule. Also reported: view A alone with persistence (strong-alert tier).

## Data

UNSW-NB15 source-host × minute units, session S0. Baseline: 2015-01-22 20:00–22:00 UTC
(label-free). Primary test: S0 units starting before 14:00 UTC (attack period, benign and
attack units in the same minutes). Secondary: all S0 units outside the baseline.
Already seen on S0: view A without persistence and NOV without persistence
(`results/revision-unsw-s0-confirmation-v1`). Never seen on S0: view B, MAX, persistence.

## Criteria (primary test, mean over five seeds)

**Confirmed** if all hold: (1) system BA ≥ 0.90 and FPR ≤ 0.10; (2) system BA − NOV BA ≥
−0.02; (3) at least four of five seeds with BA ≥ 0.85; (4) view A with persistence: recall
at 1% test FPR ≥ 0.60. **Not confirmed** if system BA < 0.80 or system BA − NOV BA < −0.10.
**Partial** otherwise.

## Limits declared in advance

Same testbed and four attacker hosts as S1; synthetic attacks; Argus state mapping;
baseline later than the test period; one dataset (Data22 and ToN-IoT have no untouched
data left, so their figures remain exploratory).
