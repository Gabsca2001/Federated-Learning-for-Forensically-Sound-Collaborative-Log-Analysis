# Protocol: label-free benign-baseline adaptation of the frozen Data24 model (v1)

Written 2026-11-10 before computing any prediction for the configurations below.
Its SHA-256 is stored in `protocol.sha256`; the script refuses to run if it differs.
This file is not edited after results are seen.

## Question

Can the frozen Data24 checkpoint become usable on a different network **without
retraining and without attack labels**, using only a short period of traffic that the
receiving organization treats as normal? Two hypotheses, motivated by earlier evidence:

- **H-A (scale):** the failure is driven by network-specific feature scale (99.97% of
  Data22 rows and 99.95% of ToN-IoT windows exceed |z| > 5 under the Data24 scaler).
  Re-estimating the standardization on the target baseline should restore decisions.
- **H-B (threshold):** ranking information survives transfer (ToN-IoT AUROC 0.89 with the
  unchanged scaler) while the argmax decision rule does not. A threshold set on the
  target baseline should restore usable alerting.

## Fixed inputs

- Model: frozen Data24 round-11 checkpoint, SHA-256
  `39075d9cbf7c45248c475ae3ddfb66f0e032d55cc210eba2a9e97c19e3d594e5`; Data24 training
  scaler from the same transfer workspace. No parameter is changed.
- Data22: `artifacts/revision-data22-external-v1/dataset.json` (10,128 windows).
- ToN-IoT: occurrence windows of the frozen-transfer workspace (7,934 windows).

## Baseline / test split (by capture date, declared before any prediction)

| Dataset | Baseline (assumed normal; labels not used) | Test (everything else) |
| --- | --- | --- |
| Data22 | 2022-01-09 … 2022-01-12 | 2022-01-13 … 2022-02-11 |
| ToN-IoT | 2019-04-02 … 2019-04-03 | 2019-04-04 … 2019-04-29 |

The baseline dates are the earliest capture dates and contain only benign windows in the
released labels; this is recorded as a check, not used to tune anything. In both datasets
attack windows occur only on later dates, so the test necessarily mixes later benign
captures with attack days (capture-schedule confound, reported as a limit).

## Configurations (all evaluated, all reported)

Score: `s = 1 - P(benign)` from the unchanged six-class softmax.

| ID | Standardization | Decision |
| --- | --- | --- |
| C0 | Data24 training scaler | argmax six-class, collapsed to benign/attack (reference) |
| A | mean/std re-estimated on target baseline windows | argmax six-class, collapsed |
| B1 | Data24 training scaler | attack if `s` > 99th percentile of `s` on baseline |
| B5 | Data24 training scaler | attack if `s` > 95th percentile of `s` on baseline |
| AB1 | baseline-refit standardization | attack if `s` > 99th baseline percentile |
| AB5 | baseline-refit standardization | attack if `s` > 95th baseline percentile |

Baseline standard deviations below 1e-9 are replaced by the Data24 training scale for
that feature (recorded per feature). Primary threshold budget: 1% (B1, AB1); 5% is the
predeclared sensitivity.

## Metrics (test windows only)

Binary balanced accuracy, false-positive rate, attack recall, attack precision, binary
macro-F1, AUROC of `s`, confusion matrix. Data22 also reports reconnaissance recall in
the six-class output for A (shared-label view). Baseline FPR is reported only as a
calibration check.

## Criteria (per dataset, per configuration)

- **Improvement:** balanced accuracy ≥ 0.70 **and** FPR ≤ 0.30.
- **Negative:** balanced accuracy < 0.60.
- **Inconclusive:** otherwise.

A configuration supports **label-free generalization** only if it meets the improvement
criterion on **both** Data22 and ToN-IoT. Success on one dataset only is reported as
dataset-specific. Primary configurations for the overall conclusion: A and AB1.

## Limits declared in advance

Single frozen checkpoint; correlated windows (no significance testing); baseline assumed
normal by the receiving organization; later benign captures may differ from the baseline
(observed earlier on ToN-IoT); Data22 has only 110 attack windows.
