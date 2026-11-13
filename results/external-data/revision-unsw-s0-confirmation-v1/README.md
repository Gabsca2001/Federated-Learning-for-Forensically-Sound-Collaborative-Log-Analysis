# Confirmed: Data24-trained federated classifier transfers to UNSW-NB15 without local labels

`protocol.md` (SHA-256 `3fd2aa35…`) froze the configuration and criteria before any
prediction on UNSW-NB15 session S0 (2015-01-22/23), whose attack units had never been scored
by a Data24-trained model. The hypothesis came from exploratory runs on session S1
(`scripts/explore_deviation_fl.py`, `explore_fusion.py`).

## Configuration

FedAvg classifier trained **only on Data24** (30 rounds, binary head). Input for every
network: `[clip(z, ±20), log1p|z|]`, where z standardizes the log-transformed features by the
network's own benign baseline. The magnitude channel makes the model usable where the
direction of a feature's deviation differs between networks. Score = logit margin.
UNSW-NB15 baseline (label-free): S0 20:00–22:00 UTC, 1,960 units, never used before.
NOV = Mahalanobis to the baseline; SUM = sum of baseline-relative ranks of CLF and NOV.

## Results – primary test (S0 attack period: 2,801 units, 469 attack, same minutes)

| Method | Recall @ FPR 0.1% | @ 1% | @ 5% | AUROC | Label-free decision (BA / FPR / recall) |
| --- | ---: | ---: | ---: | ---: | --- |
| NOV (local novelty) | 0.000 | 0.000 | 0.343 | 0.944 | 0.920 / 0.066 / 0.906 |
| **CLF (Data24 classifier)** | **0.608** | **0.762** | 0.810 | 0.855 | 0.875 / 0.009 / 0.759 |
| SUM (fusion) | 0.669 | 0.796 | 0.826 | 0.915 | 0.893 / 0.023 / 0.810 |

CLF recall at 1% FPR per seed (0–4): 0.755, 0.772, 0.746, 0.753, 0.783.
Secondary test (all S0 outside the baseline, 11,206 units): CLF 0.757 at 1% FPR, NOV 0.064.

**Verdict under the predeclared criteria: `confirmed`** (CLF ≥ 0.50 at 1% FPR; CLF − NOV ≥
0.20; 5/5 seeds ≥ 0.40). Exploratory S1 figures (0.80 at 1% FPR, 0.61 at 0.1%) are
reproduced on S0 (0.76, 0.61).

## Reading

- With no UNSW-NB15 label, the Data24 federated classifier finds about three quarters of
  attack units at 1% false positives and 61% at 0.1%. Local novelty detection has a higher
  AUROC but no usable low-false-positive operating point (its top-scored units are benign).
- The two are complementary: novelty reaches 91% recall at 6.6% FPR; fusion adds 3–6 points
  of recall to the classifier at low FPR.
- Earlier failures of the same Data24 model on UNSW-NB15 (BA 0.56–0.58) used signed inputs
  scaled by Data24 or by the baseline; the baseline-relative magnitude channel is what
  makes the transfer work.

## Limits

One target dataset: on Data22 and ToN-IoT the same classifier ranks attacks inversely
(AUROC 0.05 and 0.19), consistent with their different attack profiles, so the transfer
holds where attack behaviour resembles Data24's. S0 and S1 share the same four attacker
hosts and testbed; attacks are synthetic; Argus states mapped to Zeek; the baseline follows
the test period in time; numerical FedAvg without the secure pipeline; no significance test.

```bash
.venv/bin/python scripts/unsw_s0_confirmation.py   # refuses if protocol digest differs
```
