# Protocol: confirmation of Data24 → UNSW-NB15 transfer on the untouched January session (v1)

Written 2026-11-10 before any prediction of this configuration on UNSW-NB15 session S0.
SHA-256 in `protocol.sha256`; the script refuses to run if it differs.

## Hypothesis (from exploratory runs on session S1, 2015-02-18)

A FedAvg classifier trained **only on Data24**, with input `[clip(z, ±20), log1p|z|]` where z
is standardization by the target's own benign baseline (after log1p on the ten
count/volume/duration features), detects UNSW-NB15 attacks at low false-positive rates
without any UNSW-NB15 label, and does so much better than baseline-relative novelty
(exploratory S1: recall 0.80 vs 0.003 at 1% test FPR).

## Frozen configuration

Exactly `explore_deviation_fl.py` representation `both`, arm `D24`: 50→128→64→32 encoder +
binary head, FedAvg with Data24 train+validation as the single client, 30 rounds, 2 local
epochs, Adam 1e-3, batch 128, class-balanced loss; score = logit margin. Seeds 0–4 (0–2 were
used in exploration, 3–4 are new). NOV = Mahalanobis to the baseline (cov + 1e-6·I).
SUM = sum of baseline-relative ranks of CLF and NOV.

## Data (UNSW-NB15 source-host × minute units, session S0 = 2015-01-22/23)

- **Baseline (label-free):** S0 units with start in [20:00, 22:00) UTC on 2015-01-22. This
  interval was never used before (earlier studies used 14:00–16:00). It follows the test
  period in time, which is declared as a limit; standardization uses only this interval.
- **Primary test:** S0 units with start before 14:00 UTC on 2015-01-22 (the attack period;
  benign and attack units share the same minutes).
- **Secondary test:** all S0 units outside the baseline interval.

S0 attack units have never been scored by any Data24-trained model in earlier studies.

## Metrics and criteria (primary test, mean over five seeds)

Recall at test FPR 1% (primary), 0.1% and 5%; AUROC; label-free decision at the 99th
baseline percentile (BA, FPR, recall).

- **Confirmed** if CLF recall at 1% FPR ≥ 0.50 **and** CLF − NOV recall at 1% FPR ≥ 0.20
  **and** at least four of five seeds individually reach recall ≥ 0.40 at 1% FPR.
- **Not confirmed** if CLF recall at 1% FPR < 0.30.
- **Partial** otherwise.

## Limits declared in advance

Same four attacker hosts as S1 (same testbed), synthetic attacks, Argus state mapping,
baseline later than the test period, one dataset: confirmation concerns UNSW-NB15 only.
